"""Rule sharing: offer lifecycle and the per-account o5 clause registry.

An account registers at most one clause per target stream, either by accepting
an offered rule or by declaring one itself. The registry is committed to the
state hash; each clause is evaluated on its own, for its owner only.

`canonicalize_clause_v1` and `clause_body_v1` are consensus-frozen: they fix the
canonical clause text that the registry root commits to. They are pure and do
not call into tau_native, so a tau-lang upgrade cannot change historical roots.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

import tau_defs
from consensus.clause_registry import ClausePlan, ClauseRegistry
from consensus.serialization import (
    compute_offer_id,
    compute_rule_offer_book_root,
)

# --- Transaction type names -------------------------------------------------

TX_TYPE_RULE_OFFER = "rule_offer"
TX_TYPE_RULE_OFFER_ACCEPT = "rule_offer_accept"
TX_TYPE_RULE_OFFER_REJECT = "rule_offer_reject"

RULE_OFFER_TX_TYPES = frozenset({
    TX_TYPE_RULE_OFFER,
    TX_TYPE_RULE_OFFER_ACCEPT,
    TX_TYPE_RULE_OFFER_REJECT,
})

# --- Frozen consensus bounds ------------------------------------------------
#
# Deliberately module constants, NOT config: a per-node value would let two
# honest nodes disagree on whether a transaction is admissible, which forks.

MAX_OFFER_RULE_BYTES = 8192
MAX_PENDING_OFFERS_PER_RECIPIENT = 32
MAX_PENDING_OFFERS_PER_OFFERER = 16
MAX_OFFER_WINDOW_BLOCKS = 100_000
# Bound the build cost of one clause.
MAX_CLAUSE_COMPARISONS = 32
MAX_CLAUSE_DEPTH = 32
# Output streams an offered clause may target. o5 is the user-policy stream:
# 1 = allow, 0 = block, absent = allow.
ALLOWED_TARGET_STREAMS: Dict[int, Dict[str, Any]] = {
    tau_defs.USER_POLICY_STREAM_INDEX: {"width": 24},
}


# Streams a clause may never write: consensus-owned verdicts and fees, plus the
# rule/ack channel. Kept as a frozen tuple so admission and apply screen the
# same set.
FORBIDDEN_CLAUSE_OUTPUT_STREAMS = (0, 1, 2, 3, 4, 6, 7, 8, 9)

# i12 is the node-injected sender public key.
SENDER_STREAM = "i12"


class RuleOfferShapeError(ValueError):
    """An offered rule does not have a shape the node can safely register."""


# --- Frozen text canonicalization ------------------------------------------

_ALWAYS_UNIT_RE = re.compile(r"^always\s*\((?P<body>.*)\)\s*\.$", re.DOTALL)
_TEMPORAL_RE = re.compile(r"\b(?:always|sometimes)\b")
_OUTPUT_WRITE_RE = re.compile(r"\bo(\d+)\s*\[")
_DIRECTIVE_RE = re.compile(r"^\s*(?:#\s*tau\b|tau\s)")


def strip_clause_comments(text: str) -> str:
    """Drop '#' comments while preserving '#b'/'#x' bitvector literals.

    A local copy of the same logic as consensus.admission._strip_tau_comments,
    kept local on purpose: this one feeds the state-hash preimage and must
    never drift with an unrelated edit to the admission screens.
    """
    out: List[str] = []
    for line in (text or "").splitlines():
        i = 0
        while i < len(line):
            ch = line[i]
            if ch != "#":
                out.append(ch)
                i += 1
                continue
            nxt = line[i + 1].lower() if i + 1 < len(line) else ""
            if nxt in ("b", "x"):  # literal, not a comment
                out.append(ch)
                i += 1
                continue
            break  # comment marker -> drop the rest of this line
        out.append("\n")
    return "".join(out)


def canonicalize_clause_v1(rule_text: str) -> str:
    """CONSENSUS-FROZEN. Normalize offered rule text to a single flat unit.

    Strips comments and `tau `/`#tau ` directive lines, collapses to one line,
    and ensures exactly one trailing period. Pure function of its input.
    """
    if not isinstance(rule_text, str):
        raise RuleOfferShapeError("rule text must be a string")

    lines = []
    for line in strip_clause_comments(rule_text).splitlines():
        if _DIRECTIVE_RE.match(line):
            continue
        stripped = line.strip()
        if stripped:
            lines.append(stripped)
    flat = " ".join(lines)
    flat = re.sub(r"\s+", " ", flat).strip()
    if not flat:
        raise RuleOfferShapeError("rule text is empty after canonicalization")
    flat = flat.rstrip(".").rstrip()
    if not flat:
        raise RuleOfferShapeError("rule text is empty after canonicalization")
    return flat + " ."


def _parens_balanced(text: str) -> bool:
    depth = 0
    for ch in text:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return False
    return depth == 0


_COMPARISON_RE = re.compile(r"!=|<=|>=|(?<![-<])>|<(?!-)|=")


def clause_comparison_count(body: str) -> int:
    """Comparison operators in the comment-stripped body, each counted once."""
    return len(_COMPARISON_RE.findall(strip_clause_comments(body)))


def clause_paren_depth(body: str) -> int:
    """Deepest parenthesis nesting in the comment-stripped body."""
    depth = deepest = 0
    for ch in strip_clause_comments(body):
        if ch == "(":
            depth += 1
            deepest = max(deepest, depth)
        elif ch == ")":
            depth = max(depth - 1, 0)
    return deepest


def screen_clause_structure(body: str) -> Optional[str]:
    """None when the body is within the comparison and nesting limits."""
    comparisons = clause_comparison_count(body)
    if comparisons > MAX_CLAUSE_COMPARISONS:
        return (
            f"clause has {comparisons} comparisons; the limit is "
            f"{MAX_CLAUSE_COMPARISONS}"
        )
    depth = clause_paren_depth(body)
    if depth > MAX_CLAUSE_DEPTH:
        return (
            f"clause nests parentheses {depth} deep; the limit is "
            f"{MAX_CLAUSE_DEPTH}"
        )
    return None


def clause_output_streams(body: str) -> List[int]:
    """Output stream indices the body writes, comment-stripped, deduplicated."""
    scrubbed = strip_clause_comments(body)
    seen: List[int] = []
    for match in _OUTPUT_WRITE_RE.finditer(scrubbed):
        idx = int(match.group(1))
        if idx not in seen:
            seen.append(idx)
    return sorted(seen)


def clause_body_v1(rule_text: str) -> str:
    """CONSENSUS-FROZEN. Extract the body of a single `always` unit.

    Rejects anything that is not exactly one unit. The balanced-paren check
    is load-bearing, not cosmetic: `_ALWAYS_UNIT_RE` uses a greedy `.*`, so
    "always (a). always (b)." matches with body "a). always (b" -- accepting it
    would smuggle a second unit into one clause.
    """
    unit = canonicalize_clause_v1(rule_text)
    match = _ALWAYS_UNIT_RE.match(unit)
    if not match:
        raise RuleOfferShapeError(
            "rule must be exactly one `always ( ... ).` unit"
        )
    body = match.group("body").strip()
    if not body:
        raise RuleOfferShapeError("rule body is empty")
    if not _parens_balanced(body):
        raise RuleOfferShapeError(
            "unbalanced parentheses (or more than one rule unit)"
        )
    if _TEMPORAL_RE.search(body):
        raise RuleOfferShapeError(
            "nested temporal operator (always/sometimes) is not allowed"
        )
    if re.search(rf"\b{SENDER_STREAM}\b", strip_clause_comments(body)):
        raise RuleOfferShapeError(
            f"rule must not reference {SENDER_STREAM}; a clause is evaluated "
            "only for its owner, so it must not carry a sender guard"
        )
    return body


def validate_clause_target(body: str) -> int:
    """Return the single output stream this clause targets, or raise."""
    streams = clause_output_streams(body)
    if not streams:
        raise RuleOfferShapeError("rule body writes no output stream")
    if len(streams) > 1:
        raise RuleOfferShapeError(
            "rule body must write exactly one output stream, found "
            + ", ".join(f"o{s}" for s in streams)
        )
    target = streams[0]
    if target in FORBIDDEN_CLAUSE_OUTPUT_STREAMS:
        raise RuleOfferShapeError(
            f"o{target} is reserved and may not be written by a shared rule"
        )
    if target not in ALLOWED_TARGET_STREAMS:
        raise RuleOfferShapeError(
            f"o{target} is not an accepted target stream; supported: "
            + ", ".join(f"o{s}" for s in sorted(ALLOWED_TARGET_STREAMS))
        )
    return target


# CONSENSUS-FROZEN. A clause whose body is exactly this removes the author's
# registered clause: "always allow" and "no clause" give the same verdict.
# Exact match on one spelling keeps text analysis off the consensus path.
NEUTRAL_O5_CLAUSE_BODY = "(o5[t]:bv[24] = { #x000001 }:bv[24])"


def is_neutral_clause_body(body: str, stream_index: int) -> bool:
    """True when this body is the frozen "no opinion" spelling for the stream."""
    if stream_index != tau_defs.USER_POLICY_STREAM_INDEX:
        return False
    flat = re.sub(r"\s+", " ", (body or "").strip())
    return flat in (NEUTRAL_O5_CLAUSE_BODY, NEUTRAL_O5_CLAUSE_BODY[1:-1])


def normalize_offer_rule_text(rule_text: str) -> Tuple[str, int]:
    """Full offer-shape validation. Returns (canonical body, target stream)."""
    body = clause_body_v1(rule_text)
    return body, validate_clause_target(body)


def normalize_acceptor_pubkey(pubkey: Any) -> str:
    """Lowercase 96-hex form. The guard literal is compared byte-for-byte
    across nodes, so casing has to be pinned."""
    if isinstance(pubkey, (bytes, bytearray)):
        text = bytes(pubkey).hex()
    elif isinstance(pubkey, str):
        text = pubkey.strip().lower()
    else:
        raise RuleOfferShapeError("public key must be hex text or bytes")
    if len(text) != 96 or any(c not in "0123456789abcdef" for c in text):
        raise RuleOfferShapeError("public key must be 96 lowercase hex digits")
    return text


# --- Transaction payloads ---------------------------------------------------

@dataclass
class RuleOffer:
    offerer_pubkey: str
    recipient_pubkey: str
    rule_text: str
    expire_at_height: int

    @property
    def offer_id(self) -> bytes:
        return compute_offer_id(
            offerer_pubkey=self.offerer_pubkey,
            recipient_pubkey=self.recipient_pubkey,
            rule_text=self.rule_text,
            expire_at_height=self.expire_at_height,
        )

    @property
    def offer_id_hex(self) -> str:
        return self.offer_id.hex()


@dataclass
class RuleOfferDecision:
    offer_id: bytes
    actor_pubkey: str
    accept: bool
    # Present on accepts only. Repeating the text on the accept means the apply
    # path can validate entirely from hashed state plus the transaction bytes,
    # so a node that never saw the offer payload still applies it identically.
    rule_text: Optional[str] = None

    @property
    def offer_id_hex(self) -> str:
        return self.offer_id.hex()


def parse_rule_offer(tx: Dict[str, Any]) -> Optional[RuleOffer]:
    """Read every field from ROOT fields only; a nested `payload` is unsigned data."""
    if tx.get("tx_type") != TX_TYPE_RULE_OFFER:
        return None

    offerer = tx.get("sender_pubkey")
    recipient = tx.get("recipient_pubkey")
    rule_text = tx.get("rule_text")
    expire_at = tx.get("expire_at_height")

    if not isinstance(offerer, str) or not isinstance(recipient, str):
        return None
    if not isinstance(rule_text, str):
        return None
    if isinstance(expire_at, bool) or not isinstance(expire_at, int):
        return None
    try:
        offerer_n = normalize_acceptor_pubkey(offerer)
        recipient_n = normalize_acceptor_pubkey(recipient)
    except RuleOfferShapeError:
        return None

    return RuleOffer(
        offerer_pubkey=offerer_n,
        recipient_pubkey=recipient_n,
        rule_text=rule_text,
        expire_at_height=expire_at,
    )


def _parse_decision(tx: Dict[str, Any], tx_type: str, accept: bool) -> Optional[RuleOfferDecision]:
    """Read every field from ROOT fields only; a nested `payload` is unsigned data."""
    if tx.get("tx_type") != tx_type:
        return None

    actor = tx.get("sender_pubkey")
    offer_id_hex = tx.get("offer_id")
    if not isinstance(actor, str) or not isinstance(offer_id_hex, str):
        return None
    try:
        offer_id = bytes.fromhex(offer_id_hex)
    except ValueError:
        return None
    if len(offer_id) != 32:
        return None
    try:
        actor_n = normalize_acceptor_pubkey(actor)
    except RuleOfferShapeError:
        return None

    rule_text = tx.get("rule_text")
    if accept:
        if not isinstance(rule_text, str):
            return None
    else:
        rule_text = None

    return RuleOfferDecision(
        offer_id=offer_id, actor_pubkey=actor_n, accept=accept, rule_text=rule_text
    )


def parse_rule_offer_accept(tx: Dict[str, Any]) -> Optional[RuleOfferDecision]:
    return _parse_decision(tx, TX_TYPE_RULE_OFFER_ACCEPT, True)


def parse_rule_offer_reject(tx: Dict[str, Any]) -> Optional[RuleOfferDecision]:
    return _parse_decision(tx, TX_TYPE_RULE_OFFER_REJECT, False)


# --- Lifecycle --------------------------------------------------------------

STATUS_OFFERED = "offered"
STATUS_ACCEPTED = "accepted"
STATUS_REJECTED = "rejected"
STATUS_EXPIRED = "expired"


@dataclass
class OfferEntry:
    """The hash-bound part of an outstanding offer.

    Deliberately self-describing: offerer, recipient and expiry are all in the
    hashed preimage even though offer_id already commits to them, so expiry and
    recipient authorization are computable from hashed state alone with no
    dependency on the node-local payload store.
    """
    offerer_pubkey: str
    recipient_pubkey: str
    expire_at_height: int


class RuleOfferLifecycleManager:
    """offered -> accepted | rejected | expired, plus the clause registry.

    Composed as a FIELD of ConsensusLifecycleManager rather than a sibling, so
    `consensus_meta_hash()` picks it up automatically. A sibling would have to
    be threaded through every state-hash call site, and a missed site is a
    silent fork.
    """

    def __init__(
        self,
        offered: Optional[Dict[bytes, OfferEntry]] = None,
        resolved: Optional[Iterable[bytes]] = None,
        accepted_clauses: Optional[Mapping[Tuple[str, int], str]] = None,
    ) -> None:
        self.offered: Dict[bytes, OfferEntry] = dict(offered or {})
        self.resolved: Set[bytes] = set(resolved or ())
        # (acceptor pubkey, target stream) -> canonical clause body.
        self._accepted_clauses = ClauseRegistry(accepted_clauses)
        # Node-local only: never hashed, re-derivable by replay. Kept for the
        # RPC surface so a wallet can show what an offer actually said.
        self.terminal_status: Dict[bytes, str] = {}
        self.offer_payloads: Dict[bytes, str] = {}

    @property
    def accepted_clauses(self) -> ClauseRegistry:
        return self._accepted_clauses

    @accepted_clauses.setter
    def accepted_clauses(self, clauses: Mapping[Tuple[str, int], str]) -> None:
        self._accepted_clauses = (
            clauses if isinstance(clauses, ClauseRegistry) else ClauseRegistry(clauses)
        )

    # -- hashing ------------------------------------------------------------

    def is_empty(self) -> bool:
        """True when nothing has ever been offered or accepted.

        Load-bearing for hash compatibility: while this is True the manager
        contributes no key to mechanism_specific_metadata, so every chain that
        predates rule sharing keeps a byte-identical state hash. `resolved` is
        therefore never pruned -- a prune could flip this back to True and fork
        the chain.
        """
        return not self.offered and not self.resolved and not self.accepted_clauses

    def offers_root(self) -> bytes:
        return compute_rule_offer_book_root(
            offered=[
                (
                    offer_id,
                    entry.offerer_pubkey,
                    entry.recipient_pubkey,
                    entry.expire_at_height,
                )
                for offer_id, entry in self.offered.items()
            ],
            resolved=list(self.resolved),
        )

    def clauses_root(self) -> bytes:
        return self._accepted_clauses.root()

    # -- queries ------------------------------------------------------------

    def knows_offer(self, offer_id: bytes) -> bool:
        return offer_id in self.offered or offer_id in self.resolved

    def get_offer(self, offer_id: bytes) -> Optional[OfferEntry]:
        return self.offered.get(offer_id)

    def pending_count_for_recipient(self, pubkey: str) -> int:
        target = normalize_acceptor_pubkey(pubkey)
        return sum(1 for e in self.offered.values() if e.recipient_pubkey == target)

    def pending_count_for_offerer(self, pubkey: str) -> int:
        target = normalize_acceptor_pubkey(pubkey)
        return sum(1 for e in self.offered.values() if e.offerer_pubkey == target)

    def clause_for(self, acceptor_pubkey: str, stream_index: int) -> Optional[str]:
        return self.accepted_clauses.get(
            (normalize_acceptor_pubkey(acceptor_pubkey), stream_index)
        )

    # -- transitions --------------------------------------------------------

    def can_admit_offer(self, offer: RuleOffer, next_height: int) -> Tuple[bool, str]:
        """Deterministic admissibility. Returns (ok, reason)."""
        if offer.offerer_pubkey == offer.recipient_pubkey:
            return False, "offer recipient must differ from the offerer"
        if len(offer.rule_text.encode("utf-8")) > MAX_OFFER_RULE_BYTES:
            return False, f"rule text exceeds {MAX_OFFER_RULE_BYTES} bytes"
        if offer.expire_at_height <= next_height:
            return False, "expire_at_height must be in the future"
        if offer.expire_at_height > next_height + MAX_OFFER_WINDOW_BLOCKS:
            return False, (
                f"expire_at_height is more than {MAX_OFFER_WINDOW_BLOCKS} "
                "blocks ahead"
            )
        if self.knows_offer(offer.offer_id):
            return False, "duplicate offer"
        if self.pending_count_for_recipient(offer.recipient_pubkey) >= MAX_PENDING_OFFERS_PER_RECIPIENT:
            return False, "recipient has too many pending offers"
        if self.pending_count_for_offerer(offer.offerer_pubkey) >= MAX_PENDING_OFFERS_PER_OFFERER:
            return False, "offerer has too many pending offers"
        try:
            normalize_offer_rule_text(offer.rule_text)
        except RuleOfferShapeError as exc:
            return False, str(exc)
        return True, ""

    def submit_offer(self, offer: RuleOffer) -> bool:
        """Record an offer. False when already known (duplicate)."""
        offer_id = offer.offer_id
        if self.knows_offer(offer_id):
            return False
        self.offered[offer_id] = OfferEntry(
            offerer_pubkey=offer.offerer_pubkey,
            recipient_pubkey=offer.recipient_pubkey,
            expire_at_height=offer.expire_at_height,
        )
        self.terminal_status[offer_id] = STATUS_OFFERED
        self.offer_payloads[offer_id] = offer.rule_text
        return True

    def can_admit_decision(
        self, decision: RuleOfferDecision
    ) -> Tuple[bool, str]:
        entry = self.offered.get(decision.offer_id)
        if entry is None:
            if decision.offer_id in self.resolved:
                return False, "offer already resolved"
            return False, "unknown offer"
        if entry.recipient_pubkey != decision.actor_pubkey:
            return False, "only the offer recipient may accept or reject it"
        if not decision.accept:
            return True, ""
        if not isinstance(decision.rule_text, str):
            return False, "accept must carry the offered rule text"
        # The accept re-derives the offer id from its own copy of the text, so
        # a mismatch means the text is not the one that was offered.
        rebuilt = compute_offer_id(
            offerer_pubkey=entry.offerer_pubkey,
            recipient_pubkey=entry.recipient_pubkey,
            rule_text=decision.rule_text,
            expire_at_height=entry.expire_at_height,
        )
        if rebuilt != decision.offer_id:
            return False, "rule text does not match the offer digest"
        try:
            normalize_offer_rule_text(decision.rule_text)
        except RuleOfferShapeError as exc:
            return False, str(exc)
        return True, ""

    def submit_decision(self, decision: RuleOfferDecision) -> Optional[int]:
        """Resolve an offer.

        Returns the target stream index when an accept registered a clause,
        or None when the offer was rejected or unknown.
        """
        entry = self.offered.pop(decision.offer_id, None)
        if entry is None:
            return None
        self.resolved.add(decision.offer_id)

        if not decision.accept:
            self.terminal_status[decision.offer_id] = STATUS_REJECTED
            return None

        body, target = normalize_offer_rule_text(decision.rule_text or "")
        # An acceptor holds at most one clause per stream; accepting a new one
        # replaces it.
        self.accepted_clauses[(decision.actor_pubkey, target)] = body
        self.terminal_status[decision.offer_id] = STATUS_ACCEPTED
        return target

    def expire_at_height(self, height: int) -> List[bytes]:
        """Resolve every offer whose window has closed. Returns their ids."""
        expired = [
            offer_id
            for offer_id, entry in self.offered.items()
            if entry.expire_at_height <= height
        ]
        for offer_id in expired:
            self.offered.pop(offer_id, None)
            self.resolved.add(offer_id)
            self.terminal_status[offer_id] = STATUS_EXPIRED
        return expired

    # -- persistence helpers ------------------------------------------------

    def snapshot_offers(self) -> List[Dict[str, Any]]:
        """Rows for the node-local offer table, including resolved history."""
        rows: List[Dict[str, Any]] = []
        for offer_id, entry in self.offered.items():
            rows.append({
                "offer_id": offer_id.hex(),
                "offerer_pubkey": entry.offerer_pubkey,
                "recipient_pubkey": entry.recipient_pubkey,
                "rule_text": self.offer_payloads.get(offer_id, ""),
                "expire_at_height": entry.expire_at_height,
                "status": self.terminal_status.get(offer_id, STATUS_OFFERED),
            })
        for offer_id in self.resolved:
            rows.append({
                "offer_id": offer_id.hex(),
                "offerer_pubkey": "",
                "recipient_pubkey": "",
                "rule_text": self.offer_payloads.get(offer_id, ""),
                "expire_at_height": 0,
                "status": self.terminal_status.get(offer_id, STATUS_REJECTED),
            })
        return rows

    def clause_plan(self) -> ClausePlan:
        """The registry writes for one state save; confirm it after the commit."""
        return self._accepted_clauses.storage_plan()
