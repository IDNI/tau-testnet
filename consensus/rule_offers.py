"""Rule sharing: offer lifecycle, per-user clause registry, composite emitter.

WHY THIS EXISTS
---------------
A user can send a Tau rule to another user, who reviews it and either accepts
it into their own specification or rejects it. There is no per-user
specification in the engine: `chain_state.save_effective_tau_spec` appends to
ONE global newline-joined rule string, and the documented convention is that a
user "scopes" a rule by guarding it on their own sender identity (`i12`).

That convention does not hold. Measured on the real engine (pinned by
tests/test_rule_scoping_native.py):

  1. An output stream that no clause constrains for a given input still
     MATERIALIZES, with an arbitrary witness -- observed as 0, which for `o5`
     is exactly USER_POLICY_BLOCK_VALUE. So `always ( (i12 = A) -> (o5 = 1) ).`
     yields o5=1 for A and o5=0 (BLOCK) for every other sender. Implication
     guards do not isolate users; they are a network-wide transfer block.

  2. Two total-form rules on the same stream do not compose: conjoined, the
     spec is unsatisfiable and the interpreter fails to build; fed sequentially
     through `i0`, the later one silently SUPERSEDES the earlier. So "append
     one guarded unit per user" cannot work for a shared stream either.

  3. A SINGLE nested total-form unit does work, and applying it through `i0`
     is equivalent to building it conjoined -- which is what makes a replaying
     node match a live one.

Hence the model here: the accepted-clause registry IS the per-user
specification, and the node deterministically emits ONE composite rule unit
per shared output stream from it:

    always ( (i12[t]:bv[384] = { #x<acceptor_1> }:bv[384]) ? ( <body_1> )
           : ( (i12[t]:bv[384] = { #x<acceptor_2> }:bv[384]) ? ( <body_2> )
           : ( <neutral for this stream> ) ) ).

Acceptors are ordered by raw public-key bytes; the innermost else-branch is
the stream's frozen neutral value. Because one composite REPLACES the previous
one rather than accumulating, the live spec keeps exactly one unit per stream.

CONSENSUS-FROZEN SURFACE
------------------------
`canonicalize_clause_v1`, `clause_body_v1` and `compose_stream_rule` determine
the exact text appended to the application-rules state, which is hashed into
the block state hash. Changing any of them changes every accepted rule's
canonical text and breaks replay of all historical blocks. They are pure,
versioned, and deliberately do NOT call into tau_native: `preprocess_spec_text`
exists to normalize interpreter *output* quirks and its width-inference
heuristic is tied to tau-lang pretty-printer behaviour, so coupling the state
hash to it would let a tau-lang upgrade silently invalidate history.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import tau_defs
from consensus.serialization import (
    compute_offer_id,
    compute_clause_registry_root,
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
# Bounds composite nesting depth, and with it the interpreter rebuild cost:
# rebuild time grows steeply with spec complexity, and a runaway composite
# would eventually exceed COMM_TIMEOUT and get the node killed by the watchdog.
MAX_ACCEPTORS_PER_STREAM = 64

# Output streams an offered clause may target, with the value the composite
# emits for everyone NOT covered by a clause. The neutral value must mean
# "no opinion" for that stream, because (per finding 1 above) the stream
# materializes for every sender once any clause mentions it.
#
# o5 is the user-policy stream: 1 = allow, 0 = block, absent = allow. Neutral
# is therefore 1 -- emitting 0 would block every unrelated user's transfers.
ALLOWED_TARGET_STREAMS: Dict[int, Dict[str, Any]] = {
    tau_defs.USER_POLICY_STREAM_INDEX: {
        "width": 24,
        "neutral": tau_defs.USER_POLICY_ALLOW_VALUE,
    },
}

# Streams a clause may never write: consensus-owned verdicts and fees, plus the
# rule/ack channel. Kept as a frozen tuple so admission and apply screen the
# same set.
FORBIDDEN_CLAUSE_OUTPUT_STREAMS = (0, 1, 2, 3, 4, 6, 7, 8, 9)

# Guard construction. i12 is the node-injected sender public key, bv[384].
SENDER_STREAM = "i12"
SENDER_WIDTH = 384


class RuleOfferShapeError(ValueError):
    """An offered rule does not have a shape the node can safely compose."""


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
    """CONSENSUS-FROZEN. Extract the guardable body of a single `always` unit.

    Rejects anything the composite cannot safely wrap. The balanced-paren check
    is load-bearing, not cosmetic: `_ALWAYS_UNIT_RE` uses a greedy `.*`, so
    "always (a). always (b)." matches with body "a). always (b" -- accepting it
    would smuggle a second, unguarded unit into the composite.
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
            f"rule must not reference {SENDER_STREAM}; the node supplies the "
            "sender guard when composing"
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


def normalize_offer_rule_text(rule_text: str) -> Tuple[str, int]:
    """Full offer-shape validation. Returns (canonical body, target stream)."""
    body = clause_body_v1(rule_text)
    return body, validate_clause_target(body)


# --- Composite emitter ------------------------------------------------------

def _guard_expr(acceptor_pubkey: str) -> str:
    return (
        f"({SENDER_STREAM}[t]:bv[{SENDER_WIDTH}] = "
        f"{{ #x{acceptor_pubkey} }}:bv[{SENDER_WIDTH}])"
    )


def _neutral_expr(stream_index: int) -> str:
    spec = ALLOWED_TARGET_STREAMS[stream_index]
    width = spec["width"]
    hex_digits = format(int(spec["neutral"]), "x").rjust(width // 4, "0")
    return f"(o{stream_index}[t]:bv[{width}] = {{ #x{hex_digits} }}:bv[{width}])"


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


def compose_stream_rule(stream_index: int, clauses: Dict[str, str]) -> Optional[str]:
    """CONSENSUS-FROZEN. Build the composite rule unit for one output stream.

    `clauses` maps acceptor pubkey (96 lc hex) -> canonical clause body.
    Returns None when there are no clauses, so the stream is never mentioned
    and therefore never materializes for anybody.
    """
    if stream_index not in ALLOWED_TARGET_STREAMS:
        raise RuleOfferShapeError(f"o{stream_index} is not an accepted target stream")
    if not clauses:
        return None
    if len(clauses) > MAX_ACCEPTORS_PER_STREAM:
        raise RuleOfferShapeError(
            f"o{stream_index} has {len(clauses)} clauses, over the "
            f"{MAX_ACCEPTORS_PER_STREAM} limit"
        )

    # Sort by raw key bytes so every node emits identical text.
    ordered = sorted(
        (normalize_acceptor_pubkey(pk), body) for pk, body in clauses.items()
    )
    expr = _neutral_expr(stream_index)
    for pubkey, body in reversed(ordered):
        expr = f"({_guard_expr(pubkey)} ? ( {body} ) : {expr})"
    return f"always ( {expr} )."


# --- Transaction payloads ---------------------------------------------------

def _payload_of(tx: Dict[str, Any]) -> Dict[str, Any]:
    """Accept fields at the tx root or nested under "payload", matching the
    tolerance of the governance parsers."""
    root_val = tx.get("payload")
    if isinstance(root_val, dict):
        return root_val
    if isinstance(root_val, str):
        try:
            parsed = json.loads(root_val)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return tx


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
    if tx.get("tx_type") != TX_TYPE_RULE_OFFER:
        return None
    payload = _payload_of(tx)

    offerer = tx.get("sender_pubkey")
    if not isinstance(offerer, str):
        offerer = payload.get("sender_pubkey")
    recipient = payload.get("recipient_pubkey")
    rule_text = payload.get("rule_text")
    expire_at = payload.get("expire_at_height")

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
    if tx.get("tx_type") != tx_type:
        return None
    payload = _payload_of(tx)

    actor = tx.get("sender_pubkey")
    if not isinstance(actor, str):
        actor = payload.get("sender_pubkey")
    offer_id_hex = payload.get("offer_id")
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

    rule_text = payload.get("rule_text")
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
        accepted_clauses: Optional[Dict[Tuple[str, int], str]] = None,
    ) -> None:
        self.offered: Dict[bytes, OfferEntry] = dict(offered or {})
        self.resolved: Set[bytes] = set(resolved or ())
        # (acceptor pubkey, target stream) -> canonical clause body.
        self.accepted_clauses: Dict[Tuple[str, int], str] = dict(accepted_clauses or {})
        # Node-local only: never hashed, re-derivable by replay. Kept for the
        # RPC surface so a wallet can show what an offer actually said.
        self.terminal_status: Dict[bytes, str] = {}
        self.offer_payloads: Dict[bytes, str] = {}

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
        return compute_clause_registry_root(self.accepted_clauses)

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

    def clauses_for_stream(self, stream_index: int) -> Dict[str, str]:
        return {
            acceptor: body
            for (acceptor, stream), body in self.accepted_clauses.items()
            if stream == stream_index
        }

    def composite_for_stream(self, stream_index: int) -> Optional[str]:
        return compose_stream_rule(stream_index, self.clauses_for_stream(stream_index))

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

        Returns the target stream index when an accept registered a clause
        (so the caller knows which composite to re-emit), or None.
        """
        entry = self.offered.pop(decision.offer_id, None)
        if entry is None:
            return None
        self.resolved.add(decision.offer_id)

        if not decision.accept:
            self.terminal_status[decision.offer_id] = STATUS_REJECTED
            return None

        body, target = normalize_offer_rule_text(decision.rule_text or "")
        key = (decision.actor_pubkey, target)
        if key not in self.accepted_clauses:
            existing = len(self.clauses_for_stream(target))
            if existing >= MAX_ACCEPTORS_PER_STREAM:
                # Soft no-op: the offer is consumed but no clause registers, so
                # block validity stays deterministic across replays.
                self.terminal_status[decision.offer_id] = STATUS_REJECTED
                return None
        # An acceptor holds at most one clause per stream; accepting a new one
        # replaces it. There is no separate retraction primitive.
        self.accepted_clauses[key] = body
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

    def snapshot_clauses(self) -> List[Dict[str, Any]]:
        return [
            {"acceptor_pubkey": acceptor, "target_stream": stream, "clause_body": body}
            for (acceptor, stream), body in sorted(self.accepted_clauses.items())
        ]
