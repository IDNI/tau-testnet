"""Co-signature approval requests: the pending-transfer book and its votes.

WHY THIS EXISTS
---------------
A user can already write a Tau policy that blocks their own high-value
transfers. What they cannot do is get anyone to *unblock* one: a blocked
transfer is rejected at admission, no third party ever learns it was attempted,
and nothing in consensus holds a transaction while an external party decides.

This module holds the missing state. A sender parks a transfer as an
`approval_request` naming the approvers whose signatures that amount needs; each
approver submits a `transfer_vote`; the node writes the pubkey of every approver
who actually voted into that request's reserved slot streams (i18..i25) and
re-evaluates the sender's OWN policy clause. The moment o5 flips to allow, the
transfer executes.

THE DIVISION OF AUTHORITY
-------------------------
The declared approver list is ROUTING, not authority: it decides whose inbox is
filled and which slot each vote lands in. The sender's registered o5 clause
decides what is actually REQUIRED. Nothing here parses that clause, and no
consensus path does.

Both ways the declaration can be wrong are safe and land on the sender:

  * under-declare (one approver named on a transfer the clause gates on three)
    -> the clause never allows, the request expires, the transfer amount never
    moves. The request-time fee is spent either way, so a sender cannot buy
    cheaper approval by naming fewer approvers.
  * over-declare -> unnecessary notifications, but no wrong execution, and
    crucially NO VETO: see `record_decline`. If a decline resolved the request,
    an over-declared approver would hold terminal veto power and the
    declaration would be authority after all.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, deliberately not config: a per-node value
would let two honest nodes disagree about whether a transaction is admissible,
which forks. `MAX_TIER_AUTHORS` is a *measured* ceiling, not a taste -- see the
note on it.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import tau_defs

# --- Transaction type names -------------------------------------------------

TX_TYPE_APPROVAL_REQUEST = "approval_request"
TX_TYPE_TRANSFER_VOTE = "transfer_vote"

APPROVAL_TX_TYPES = frozenset({TX_TYPE_APPROVAL_REQUEST, TX_TYPE_TRANSFER_VOTE})

# --- Frozen consensus bounds ------------------------------------------------

MAX_APPROVERS_PER_REQUEST = 8
MAX_PENDING_REQUESTS_PER_SENDER = 8
MAX_PENDING_REQUESTS_PER_APPROVER = 64
MAX_APPROVAL_WINDOW_BLOCKS = 10_000
MAX_CUSTOM_INPUTS_PER_REQUEST = 8

# How many candidate slots `getapprovalpreview` will enumerate subsets over.
# 2**6 = 64 engine steps, each single-digit milliseconds and none of them a
# rebuild. Above this the RPC reports `unavailable` instead of returning a
# partial search dressed up as an answer.
MAX_PREVIEW_SLOTS = 6
MAX_CUSTOM_INPUT_BYTES = 256

# Signed and inside the block merkle root (it is part of the transaction, so
# `block.compute_tx_hash` covers it), but deliberately NOT in the approval-state
# root: node-local colour, no consensus meaning.
MAX_VOTE_REASON_BYTES = 256

# How many principals may hold a registered o5 policy clause at once.
#
# MEASURED CEILING, not a preference. `get_interpreter` build time against the
# number of tier authors in the derived composite, with tau_shrink on:
#   1 author  ~2.5s      2 authors ~13-22s      4 authors ~110s
# `config.COMM_TIMEOUT` is 60s and the watchdog SIGKILLs past it, so four
# authors is fatal and three is already marginal. Raising this needs a fresh
# measurement, not an opinion. Deliberately separate from rule_offers'
# consensus-frozen MAX_ACCEPTORS_PER_STREAM (64), which must not be edited in
# place; this is the activation-scoped cap that actually binds.
MAX_TIER_AUTHORS = 2

# --- Terminal status, encoded as a uint8 in the hashed root ------------------

STATUS_OPEN = 0
STATUS_EXECUTED = 1
STATUS_EXPIRED = 2
STATUS_FAILED = 3

STATUS_NAMES = {
    STATUS_OPEN: "open",
    STATUS_EXECUTED: "executed",
    STATUS_EXPIRED: "expired",
    STATUS_FAILED: "failed",
}


class ApprovalShapeError(ValueError):
    """A request or vote does not have a shape the node can safely record."""


def approval_slots_active(tip_view) -> bool:
    """Whether the co-signature approval slots are reserved at the tip.

    Requires a genuine `True`, not merely a truthy value. The real
    TipAdmissionView property returns a bool, so production is unaffected, but a
    partial or mocked view returns something truthy for any attribute it was
    never given -- and silently running as if a consensus feature were activated
    is the kind of thing that passes every test and then diverges on a live
    chain. Absent or non-bool therefore reads as "not activated", which is also
    the pre-activation behaviour of every existing chain.
    """
    return getattr(tip_view, "approval_slots_active", False) is True


# --- Slot width screening ---------------------------------------------------
#
# Per-stream bitvector typing is process-global and sticky: one rule typing i18
# at bv[384] and another at bv[24] leaves get_interpreter returning None for
# everyone. Measured, and it fails closed rather than silently.
#
# So the screen is REJECT-UNLESS-ANNOTATED: every occurrence of a slot stream
# must carry an explicit `[t]:bv[384]`. Checking only for a *mismatched*
# annotation (the shape `_WIDTH_RE` supports) would let an unannotated mention
# through, and an unannotated mention is exactly what lets the engine infer some
# other width.

_SLOT_OCCURRENCE_RE = re.compile(r"\bi(\d+)\b")
_SLOT_TYPED_RE = re.compile(r"\bi(\d+)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*(\d+)\s*\]")


def screen_slot_widths(body: str) -> Optional[str]:
    """None when every approval-slot mention is typed bv[384], else the reason.

    Operates on comment-stripped text: a slot named inside a comment is not a
    typing hazard, and rejecting it would be a confusing false positive.
    """
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(body or "")
    slots = set(tau_defs.approval_slot_indices())
    width = tau_defs.APPROVAL_SLOT_BV_WIDTH

    typed: Dict[int, Set[int]] = {}
    for match in _SLOT_TYPED_RE.finditer(scrubbed):
        idx, w = int(match.group(1)), int(match.group(2))
        if idx in slots:
            typed.setdefault(idx, set()).add(w)
            if w != width:
                return (
                    f"i{idx} is an approval slot and must be typed bv[{width}], "
                    f"found bv[{w}]"
                )

    # Every *occurrence* must be one of the typed ones, so count them.
    for match in _SLOT_OCCURRENCE_RE.finditer(scrubbed):
        idx = int(match.group(1))
        if idx not in slots:
            continue
        tail = scrubbed[match.end():]
        if not re.match(r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*%d\s*\]" % width, tail):
            return (
                f"every mention of approval slot i{idx} must be written "
                f"i{idx}[t]:bv[{width}]; an untyped mention lets the engine "
                f"infer a conflicting width process-wide"
            )
    return None


# --- User-policy / custom-fee width screening (o5, o8) ----------------------
#
# Same reject-unless-annotated contract as the approval slots, for the shared
# application streams. The first unit that types o5 pins the interpreter
# process-wide; a later bv[16] (or an untyped `o5[t] = 0` that lets the engine
# infer one) poisons get_interpreter for everyone until restart.

_POLICY_OCCURRENCE_RE = re.compile(r"\bo(\d+)\b")
_POLICY_TYPED_RE = re.compile(r"\bo(\d+)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*(\d+)\s*\]")
_POLICY_ASSIGN_RE = re.compile(r"\s*=\s*")
_POLICY_BV_LIT_RE = re.compile(r"\s*:\s*bv\s*\[\s*(\d+)\s*\]")


def _policy_width_streams() -> set:
    return {
        tau_defs.USER_POLICY_STREAM_INDEX,
        tau_defs.CUSTOM_FEE_STREAM_INDEX,
    }


def _screen_policy_literal(rhs: str, idx: int, width: int) -> Optional[str]:
    """None when RHS is not a literal, or is a correctly typed bv[width] one."""
    text = (rhs or "").lstrip()
    # Skip grouping parens wrapping a literal (`( { #x1 }:bv[24] )`).
    while text.startswith("("):
        text = text[1:].lstrip()
    if not text:
        return None
    if text[0].isdigit():
        return (
            f"literals assigned to o{idx} must be typed bv[{width}], "
            f"found a bare integer"
        )
    if text[0] != "{":
        return None
    close = text.find("}")
    if close < 0:
        return (
            f"literals assigned to o{idx} must be typed bv[{width}], "
            f"found an untyped literal"
        )
    after = text[close + 1:]
    match = _POLICY_BV_LIT_RE.match(after)
    if not match:
        return (
            f"literals assigned to o{idx} must be typed bv[{width}], "
            f"found an untyped literal"
        )
    found = int(match.group(1))
    if found != width:
        return (
            f"literals assigned to o{idx} must be typed bv[{width}], "
            f"found bv[{found}]"
        )
    return None


def screen_policy_widths(text: str) -> Optional[str]:
    """None when every o5/o8 mention is typed bv[24], else the reason.

    Comment-stripped, word-boundary: `o50` and a stream named only in a comment
    are not a typing hazard. Untyped `o5[t] = 0` / `1` is refused — that is
    how a stray width gets inferred. Literals assigned to o5/o8 must themselves
    be `bv[24]` (`{ #x000001 }:bv[24]`, not `{1}:bv[16]` or bare `1`).
    """
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(text or "")
    streams = _policy_width_streams()
    width = tau_defs.USER_POLICY_BV_WIDTH
    typed_tail = re.compile(r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*%d\s*\]" % width)

    for match in _POLICY_TYPED_RE.finditer(scrubbed):
        idx, w = int(match.group(1)), int(match.group(2))
        if idx in streams and w != width:
            return (
                f"o{idx} must be typed bv[{width}], found bv[{w}]"
            )

    for match in _POLICY_OCCURRENCE_RE.finditer(scrubbed):
        idx = int(match.group(1))
        if idx not in streams:
            continue
        tail = scrubbed[match.end():]
        typed_ok = typed_tail.match(tail)
        if not typed_ok:
            return (
                f"every mention of o{idx} must be written "
                f"o{idx}[t]:bv[{width}]; an untyped mention lets the engine "
                f"infer a conflicting width process-wide"
            )
        rest = tail[typed_ok.end():]
        assign = _POLICY_ASSIGN_RE.match(rest)
        if not assign:
            continue
        lit_err = _screen_policy_literal(rest[assign.end():], idx, width)
        if lit_err:
            return lit_err
    return None


def screen_unsatisfiable_sender_conjunction(text: str) -> Optional[str]:
    """Refuse a top-level `i12 = me && …` total-form unit (routing off only).

    That shape is unsatisfiable for every other sender: Tau conjoins every
    deployed o5 unit, so `always (i12 = A && o5 = 0)` cannot hold when the
    current sender is not A. Implication (`->`) and ternary (`? :`) are the
    documented guards and are left alone. Cheap heuristic, not a proof of
    scoping; unused once o5 is routed into the clause registry.
    """
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(text or "")
    if not re.search(r"\bo5\b", scrubbed):
        return None
    if not re.search(r"\bi12\b", scrubbed):
        return None
    if "->" in scrubbed or "?" in scrubbed:
        return None
    if "&&" not in scrubbed:
        return None
    return (
        "top-level i12 conjunction (i12 = me && …) is unsatisfiable for every "
        "other sender; guard with -> or ? : instead of &&"
    )


# --- Activation audit -------------------------------------------------------

def audit_stream_collisions(spec_texts) -> List[str]:
    """Reasons the approval slots cannot safely be activated. Empty means clear.

    Reserving i18..i25 and routing o5 rules into the clause registry are both
    consensus-visible changes, and a source grep proves nothing about a LIVE
    chain: before activation the slots were ordinary custom input streams that
    any user rule could type at any width, and o5 rules were appended raw.

    Two collisions matter, and both are fatal rather than untidy:

    1. **A slot already typed somewhere in the effective spec.** Per-stream
       bitvector typing is process-global and sticky, so a deployed rule typing
       i18 at, say, bv[24] means the first co-signature clause typing it bv[384]
       leaves `get_interpreter` returning None -- for everyone, until restart.

    2. **A legacy raw o5 writer.** The first derived composite becomes a second
       total-form unit on o5 beside it, and two of those either fail to conjoin
       (unsatisfiable) or silently supersede one another. Grandfathering them is
       not safe, which is why this reports rather than tolerates.

    `spec_texts` is an iterable of (label, text) pairs covering the COMPLETE
    effective spec: consensus rules, genesis/builtin rules, the application-rules
    accumulation and every stored clause body. Auditing the application rules
    alone would miss a collision hiding in a consensus revision.
    """
    from consensus.rule_offers import clause_output_streams, strip_clause_comments

    findings: List[str] = []
    slots = tau_defs.approval_slot_indices()

    for label, text in spec_texts or ():
        if not isinstance(text, str) or not text.strip():
            continue
        scrubbed = strip_clause_comments(text)

        hit = [f"i{idx}" for idx in slots
               if re.search(r"\bi%d\b" % idx, scrubbed)]
        if hit:
            findings.append(
                f"{label} already references approval slot(s) {', '.join(hit)}; "
                f"activating would let a bv[{tau_defs.APPROVAL_SLOT_BV_WIDTH}] "
                f"clause collide with it and poison process-global stream typing"
            )

        # Only the raw accumulation can hold a legacy o5 writer: a registered
        # clause is fed with apply_rules_update=False and never enters it.
        if label.startswith("application_rules") and \
                tau_defs.USER_POLICY_STREAM_INDEX in clause_output_streams(text):
            findings.append(
                f"{label} contains a raw o5 policy rule; the first derived "
                f"composite would be a second total-form unit on o5 beside it, "
                f"which either fails to conjoin or silently supersedes it. Clear "
                f"it or start from fresh state before activating."
            )
    return findings


# --- Payload parsing --------------------------------------------------------

def _payload_of(tx: Dict[str, Any]) -> Dict[str, Any]:
    """Accept fields at the tx root or nested under "payload", matching the
    tolerance of the governance and rule-offer parsers."""
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


def _normalize_pubkey(value: Any) -> str:
    from consensus.rule_offers import normalize_acceptor_pubkey, RuleOfferShapeError

    try:
        return normalize_acceptor_pubkey(value)
    except RuleOfferShapeError as exc:
        raise ApprovalShapeError(str(exc)) from exc


def _normalize_index_map(raw: Any, what: str) -> Dict[int, Any]:
    """JSON object keys are strings; consensus needs ints in ascending NUMERIC
    order, which is not string order ("10" < "9")."""
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise ApprovalShapeError(f"{what} must be an object")
    out: Dict[int, Any] = {}
    for key, val in raw.items():
        if isinstance(key, bool) or not isinstance(key, (int, str)):
            raise ApprovalShapeError(f"{what} keys must be stream indices")
        try:
            idx = int(key)
        except (TypeError, ValueError):
            raise ApprovalShapeError(f"{what} key {key!r} is not a stream index")
        if idx in out:
            raise ApprovalShapeError(f"{what} names stream {idx} twice")
        out[idx] = val
    return dict(sorted(out.items()))


@dataclass
class ApprovalRequest:
    """A parked transfer, as the transaction declared it."""

    sender_pubkey: str
    recipient_pubkey: str
    amount: int
    sequence_number: int
    expire_at_height: int
    approvers: Dict[int, str]          # slot index -> approver pubkey
    custom_inputs: Dict[int, str]      # stream index -> sender-supplied value

    @property
    def request_id(self) -> bytes:
        from consensus.serialization import compute_request_id

        return compute_request_id(
            sender_pubkey=self.sender_pubkey,
            recipient_pubkey=self.recipient_pubkey,
            amount=self.amount,
            sequence_number=self.sequence_number,
            expire_at_height=self.expire_at_height,
            approvers=self.approvers,
            custom_inputs=self.custom_inputs,
        )

    @property
    def request_id_hex(self) -> str:
        return self.request_id.hex()


@dataclass
class TransferVote:
    request_id: bytes
    voter_pubkey: str
    approve: bool
    reason: str = ""

    @property
    def request_id_hex(self) -> str:
        return self.request_id.hex()


def parse_approval_request(tx: Dict[str, Any]) -> Optional[ApprovalRequest]:
    if tx.get("tx_type") != TX_TYPE_APPROVAL_REQUEST:
        return None
    payload = _payload_of(tx)

    sender = tx.get("sender_pubkey")
    if not isinstance(sender, str):
        sender = payload.get("sender_pubkey")
    seq = tx.get("sequence_number")
    if seq is None:
        seq = payload.get("sequence_number")

    recipient = payload.get("recipient_pubkey")
    amount = payload.get("amount")
    expire_at = payload.get("expire_at_height")

    if isinstance(amount, str):
        try:
            amount = int(amount)
        except ValueError:
            return None
    for val in (amount, expire_at, seq):
        if isinstance(val, bool) or not isinstance(val, int):
            return None

    try:
        sender_n = _normalize_pubkey(sender)
        recipient_n = _normalize_pubkey(recipient)
        approvers_raw = _normalize_index_map(payload.get("approvers"), "approvers")
        customs_raw = _normalize_index_map(payload.get("custom_inputs"), "custom_inputs")
        approvers = {idx: _normalize_pubkey(pk) for idx, pk in approvers_raw.items()}
    except ApprovalShapeError:
        return None

    customs: Dict[int, str] = {}
    for idx, val in customs_raw.items():
        if isinstance(val, bool) or not isinstance(val, (int, str)):
            return None
        customs[idx] = str(val)

    return ApprovalRequest(
        sender_pubkey=sender_n,
        recipient_pubkey=recipient_n,
        amount=amount,
        sequence_number=seq,
        expire_at_height=expire_at,
        approvers=approvers,
        custom_inputs=customs,
    )


def parse_transfer_vote(tx: Dict[str, Any]) -> Optional[TransferVote]:
    if tx.get("tx_type") != TX_TYPE_TRANSFER_VOTE:
        return None
    payload = _payload_of(tx)

    voter = tx.get("sender_pubkey")
    if not isinstance(voter, str):
        voter = payload.get("sender_pubkey")
    request_id_hex = payload.get("request_id")
    approve = payload.get("approve", True)
    reason = payload.get("reason", "")

    if not isinstance(request_id_hex, str):
        return None
    # `approve` must be a real bool: accepting 1/0 would let a wallet bug turn a
    # decline into an approval.
    if not isinstance(approve, bool):
        return None
    if not isinstance(reason, str) or len(reason.encode("utf-8")) > MAX_VOTE_REASON_BYTES:
        return None

    try:
        request_id = bytes.fromhex(request_id_hex)
    except ValueError:
        return None
    if len(request_id) != 32:
        return None

    try:
        voter_n = _normalize_pubkey(voter)
    except ApprovalShapeError:
        return None

    return TransferVote(
        request_id=request_id, voter_pubkey=voter_n, approve=approve, reason=reason
    )


# --- The hash-bound entry ---------------------------------------------------

@dataclass
class ApprovalRequestEntry:
    """The hash-bound part of a parked transfer.

    Deliberately self-describing: everything needed to execute the transfer and
    to authorize a vote is in the hashed preimage, even though request_id already
    commits to the declaration. That way expiry, vote authorization and execution
    are computable from hashed state alone, with no dependency on the node-local
    payload store -- the same reasoning as rule_offers.OfferEntry.

    `custom_inputs` is snapshotted rather than re-read at execution: the sender
    signed those values, and a deferred execution must feed exactly what was
    signed.
    """

    sender_pubkey: str
    recipient_pubkey: str
    amount: int
    expire_at_height: int
    approvers: Dict[int, str] = field(default_factory=dict)
    custom_inputs: Dict[int, str] = field(default_factory=dict)
    # slot -> approver pubkey, for approvers who actually voted YES.
    voted: Dict[int, str] = field(default_factory=dict)
    # slots whose approver explicitly declined. Recorded so "everyone has
    # answered and the clause still blocks" is decidable, NOT as a veto.
    declined: Set[int] = field(default_factory=set)

    def slot_values(self) -> Dict[int, str]:
        """What to feed on every approval slot for this request.

        A slot with a YES vote carries that approver's pubkey; every other slot
        carries 0, which no pubkey equals, so the sender's clause keeps blocking.
        """
        out = {idx: "0" for idx in tau_defs.approval_slot_indices()}
        for slot, pubkey in self.voted.items():
            out[slot] = pubkey
        return out

    def all_answered(self) -> bool:
        answered = set(self.voted) | self.declined
        return answered >= set(self.approvers)


def validate_request_shape(
    request: "ApprovalRequest", next_height: int
) -> Optional[str]:
    """Stateless admissibility of a parked transfer. None when acceptable.

    Shared verbatim by mempool admission (which reads the tip tables) and block
    apply (which holds the manager), because the two must reject exactly the same
    inputs -- a disagreement is a consensus split. Everything here is a pure
    function of the transaction plus the target height; anything needing the book
    (duplicates, per-account caps) lives in the caller.
    """
    slots = set(tau_defs.approval_slot_indices())

    if not request.approvers:
        return "a request must name at least one approver"
    if len(request.approvers) > MAX_APPROVERS_PER_REQUEST:
        return f"more than {MAX_APPROVERS_PER_REQUEST} approvers"
    bad_slot = next((s for s in sorted(request.approvers) if s not in slots), None)
    if bad_slot is not None:
        return (
            f"i{bad_slot} is not an approval slot; slots are "
            f"i{min(slots)}..i{max(slots)}"
        )

    approver_keys = list(request.approvers.values())
    if len(set(approver_keys)) != len(approver_keys):
        return "approvers must be distinct accounts"
    if request.sender_pubkey in approver_keys:
        return "the sender may not be their own approver"

    if not (1 <= request.amount <= tau_defs.MAX_TRANSFER_VALUE):
        return f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"

    if len(request.custom_inputs) > MAX_CUSTOM_INPUTS_PER_REQUEST:
        return f"more than {MAX_CUSTOM_INPUTS_PER_REQUEST} custom inputs"
    for idx, val in sorted(request.custom_inputs.items()):
        if idx < tau_defs.REQUEST_CUSTOM_INPUT_MIN:
            return (
                f"custom input i{idx} is below i{tau_defs.REQUEST_CUSTOM_INPUT_MIN}; "
                "lower streams are reserved or are approval slots"
            )
        if len(str(val).encode("utf-8")) > MAX_CUSTOM_INPUT_BYTES:
            return f"custom input i{idx} exceeds {MAX_CUSTOM_INPUT_BYTES} bytes"

    if request.expire_at_height <= next_height:
        return "expire_at_height must be in the future"
    if request.expire_at_height > next_height + MAX_APPROVAL_WINDOW_BLOCKS:
        return (
            f"expire_at_height is more than {MAX_APPROVAL_WINDOW_BLOCKS} "
            "blocks ahead"
        )
    return None


class ApprovalRequestLifecycleManager:
    """open -> executed | expired | failed, plus the recorded votes.

    Composed as a FIELD of ConsensusLifecycleManager rather than a sibling, so
    `consensus_meta_hash()` picks it up automatically. A sibling would have to be
    threaded through every state-hash call site and a missed one is a silent
    fork. The same reasoning as RuleOfferLifecycleManager.

    TRANSACTIONAL DISCIPLINE
    ------------------------
    Vote application is deliberately split into `prospective_slot_values` (pure)
    and `commit_vote` (mutating). The apply path must evaluate Tau against the
    prospective values and only commit once that call has returned, because
    `hard_reject` in the engine suppresses staged balances and nonces but does
    NOT roll back lifecycle-manager mutations. The rule-offer path shows the
    hazard directly: `submit_decision` mutates at engine.py:1067, before a
    possible hard reject at :1083.
    """

    def __init__(
        self,
        open_requests: Optional[Dict[bytes, ApprovalRequestEntry]] = None,
        resolved: Optional[Iterable[bytes]] = None,
    ) -> None:
        self.open_requests: Dict[bytes, ApprovalRequestEntry] = dict(open_requests or {})
        self.resolved: Set[bytes] = set(resolved or ())
        # Node-local only: never hashed, re-derivable by replay. Kept so the RPC
        # surface can show what actually happened to a request.
        self.terminal_status: Dict[bytes, int] = {}
        self.decline_reasons: Dict[Tuple[bytes, str], str] = {}
        # Node-local history so a resolved request stays queryable by address.
        self.resolved_details: Dict[bytes, ApprovalRequestEntry] = {}

    # -- hashing ------------------------------------------------------------

    def is_empty(self) -> bool:
        """True when nothing has ever been requested.

        Load-bearing for hash compatibility: while this is True the manager
        contributes no key to mechanism_specific_metadata, so a chain that
        predates the feature keeps a byte-identical state hash. `resolved` is
        therefore never pruned -- a prune could flip this back to True and fork.
        """
        return not self.open_requests and not self.resolved

    def requests_root(self) -> bytes:
        from consensus.serialization import compute_approval_request_book_root

        return compute_approval_request_book_root(
            open_entries=[
                (
                    request_id,
                    entry.sender_pubkey,
                    entry.recipient_pubkey,
                    entry.amount,
                    entry.expire_at_height,
                    entry.approvers,
                    entry.custom_inputs,
                    entry.voted,
                    entry.declined,
                    STATUS_OPEN,
                )
                for request_id, entry in self.open_requests.items()
            ],
            resolved=list(self.resolved),
        )

    # -- queries ------------------------------------------------------------

    def knows_request(self, request_id: bytes) -> bool:
        return request_id in self.open_requests or request_id in self.resolved

    def get_request(self, request_id: bytes) -> Optional[ApprovalRequestEntry]:
        return self.open_requests.get(request_id)

    def pending_count_for_sender(self, pubkey: str) -> int:
        target = _normalize_pubkey(pubkey)
        return sum(1 for e in self.open_requests.values() if e.sender_pubkey == target)

    def pending_count_for_approver(self, pubkey: str) -> int:
        target = _normalize_pubkey(pubkey)
        return sum(
            1 for e in self.open_requests.values() if target in set(e.approvers.values())
        )

    def inbox_for(self, pubkey: str) -> List[Tuple[bytes, ApprovalRequestEntry]]:
        """Open requests naming this account as an approver.

        This IS the tier scoping: a request declares only the approvers its
        amount needs, so an approver whose vote is not needed never sees it.
        """
        target = _normalize_pubkey(pubkey)
        return [
            (rid, entry)
            for rid, entry in sorted(self.open_requests.items())
            if target in set(entry.approvers.values())
        ]

    # -- transitions --------------------------------------------------------

    def can_admit_request(
        self, request: ApprovalRequest, next_height: int
    ) -> Tuple[bool, str]:
        """Deterministic admissibility. Returns (ok, reason).

        Stateless checks are delegated to the module-level
        `validate_request_shape` so the mempool path (which reads the tip tables,
        not this manager) applies byte-identical rules. Admission and apply
        disagreeing about what is admissible is a consensus split.

        Deliberately excludes the "does the sender's clause actually block this?"
        question: that needs a Tau evaluation, so it lives at the call site.
        """
        shape_error = validate_request_shape(request, next_height)
        if shape_error:
            return False, shape_error

        if self.knows_request(request.request_id):
            return False, "duplicate request"
        if self.pending_count_for_sender(request.sender_pubkey) >= MAX_PENDING_REQUESTS_PER_SENDER:
            return False, "sender has too many open requests"
        for approver in sorted(request.approvers.values()):
            if self.pending_count_for_approver(approver) >= MAX_PENDING_REQUESTS_PER_APPROVER:
                return False, "an approver has too many open requests"

        return True, ""

    def submit_request(self, request: ApprovalRequest) -> bool:
        """Record a request. False when already known (duplicate)."""
        request_id = request.request_id
        if self.knows_request(request_id):
            return False
        self.open_requests[request_id] = ApprovalRequestEntry(
            sender_pubkey=request.sender_pubkey,
            recipient_pubkey=request.recipient_pubkey,
            amount=request.amount,
            expire_at_height=request.expire_at_height,
            approvers=dict(request.approvers),
            custom_inputs=dict(request.custom_inputs),
        )
        self.terminal_status[request_id] = STATUS_OPEN
        return True

    def withdraw_request(self, request_id: bytes) -> bool:
        """Un-do a `submit_request` outright. False when it was not open.

        NOT a terminal state: the id is forgotten entirely, so the same request
        may be submitted again. Used when the transaction that parked a request
        does not survive its own fee settlement -- parking is committed in the
        apply branch, but the fee is settled afterwards and may hard-reject the
        tx, and a request that paid nothing must not stay parked.
        """
        if self.open_requests.pop(request_id, None) is None:
            return False
        self.terminal_status.pop(request_id, None)
        return True

    def can_admit_vote(self, vote: TransferVote, height: int) -> Tuple[bool, str]:
        entry = self.open_requests.get(vote.request_id)
        if entry is None:
            if vote.request_id in self.resolved:
                return False, "request already resolved"
            return False, "unknown request"
        if entry.expire_at_height <= height:
            # Checked here AND at apply: process_height_transitions runs after
            # the transaction loop, so the sweep cannot be relied on to stop a
            # vote included at exactly the expiry height.
            return False, "request has expired"
        slot = self._slot_for_voter(entry, vote.voter_pubkey)
        if slot is None:
            return False, "only a declared approver may vote on this request"
        if slot in entry.voted or slot in entry.declined:
            return False, "this approver has already voted"
        return True, ""

    @staticmethod
    def _slot_for_voter(entry: ApprovalRequestEntry, voter_pubkey: str) -> Optional[int]:
        for slot, pubkey in sorted(entry.approvers.items()):
            if pubkey == voter_pubkey:
                return slot
        return None

    def prospective_slot_values(
        self, request_id: bytes, vote: TransferVote
    ) -> Optional[Dict[int, str]]:
        """Slot feed AS IF this approval were recorded -- no mutation.

        Returns None when the vote could not apply. The apply path evaluates Tau
        against this and only then calls `commit_vote`, so a Tau failure cannot
        leave a recorded vote behind.
        """
        entry = self.open_requests.get(request_id)
        if entry is None:
            return None
        slot = self._slot_for_voter(entry, vote.voter_pubkey)
        if slot is None:
            return None
        values = entry.slot_values()
        if vote.approve:
            values[slot] = vote.voter_pubkey
        return values

    def commit_vote(self, vote: TransferVote) -> Optional[int]:
        """Record a decided vote. Returns the slot it landed in, or None.

        Call only AFTER any Tau evaluation for this vote has succeeded.
        """
        entry = self.open_requests.get(vote.request_id)
        if entry is None:
            return None
        slot = self._slot_for_voter(entry, vote.voter_pubkey)
        if slot is None or slot in entry.voted or slot in entry.declined:
            return None
        if vote.approve:
            entry.voted[slot] = vote.voter_pubkey
        else:
            # NOT a veto. An over-declared approver must not be able to kill a
            # request the sender's clause never needed, or the declaration would
            # be authority rather than routing. The request stays open and can
            # still execute without this slot.
            entry.declined.add(slot)
            if vote.reason:
                self.decline_reasons[(vote.request_id, vote.voter_pubkey)] = vote.reason
        return slot

    def resolve(self, request_id: bytes, status: int) -> bool:
        """Move a request to a terminal state. False when it was not open."""
        entry = self.open_requests.pop(request_id, None)
        if entry is None:
            return False
        self.resolved.add(request_id)
        self.terminal_status[request_id] = status
        self.resolved_details[request_id] = entry
        return True

    def resolve_all_for_sender(self, pubkey: str, status: int) -> List[bytes]:
        """Terminate every open request of one sender, in canonical id order.

        Used when that principal's o5 clause is replaced: a request snapshots its
        approvers but re-evaluates the CURRENT clause, so leaving requests open
        across a replacement would silently change what recorded votes mean, or
        strand them forever.
        """
        target = _normalize_pubkey(pubkey)
        doomed = sorted(
            rid for rid, e in self.open_requests.items() if e.sender_pubkey == target
        )
        for rid in doomed:
            self.resolve(rid, status)
        return doomed

    def expire_at_height(self, height: int) -> List[bytes]:
        """Resolve every request whose window has closed. Returns their ids."""
        expired = sorted(
            rid
            for rid, entry in self.open_requests.items()
            if entry.expire_at_height <= height
        )
        for rid in expired:
            self.resolve(rid, STATUS_EXPIRED)
        return expired

    # -- persistence helpers ------------------------------------------------

    def snapshot_requests(self) -> List[Dict[str, Any]]:
        """Rows for the node-local request table, including resolved history."""
        rows: List[Dict[str, Any]] = []
        for rid, entry in self.open_requests.items():
            rows.append({
                "request_id": rid.hex(),
                "sender_pubkey": entry.sender_pubkey,
                "recipient_pubkey": entry.recipient_pubkey,
                "amount": entry.amount,
                "expire_at_height": entry.expire_at_height,
                "approvers_json": json.dumps(
                    {str(k): v for k, v in sorted(entry.approvers.items())},
                    sort_keys=True, separators=(",", ":")),
                "custom_inputs_json": json.dumps(
                    {str(k): v for k, v in sorted(entry.custom_inputs.items())},
                    sort_keys=True, separators=(",", ":")),
                "voted_json": json.dumps(
                    {str(k): v for k, v in sorted(entry.voted.items())},
                    sort_keys=True, separators=(",", ":")),
                "declined_json": json.dumps(sorted(entry.declined)),
                "status": STATUS_OPEN,
            })
        # Resolved rows KEEP the parties, unlike rule_offers' snapshot_offers,
        # which writes "" for offerer/recipient and thereby drops a resolved
        # offer out of every per-address listing (playbook §7 records this as an
        # unfixed wart). Only the bare id is hash-bound, so retaining the
        # details node-locally touches no hash and keeps history queryable.
        for rid in sorted(self.resolved):
            entry = self.resolved_details.get(rid)
            rows.append({
                "request_id": rid.hex(),
                "sender_pubkey": entry.sender_pubkey if entry else "",
                "recipient_pubkey": entry.recipient_pubkey if entry else "",
                "amount": entry.amount if entry else 0,
                "expire_at_height": entry.expire_at_height if entry else 0,
                "approvers_json": json.dumps(
                    {str(k): v for k, v in sorted((entry.approvers if entry else {}).items())},
                    sort_keys=True, separators=(",", ":")),
                "custom_inputs_json": json.dumps(
                    {str(k): v for k, v in sorted((entry.custom_inputs if entry else {}).items())},
                    sort_keys=True, separators=(",", ":")),
                "voted_json": json.dumps(
                    {str(k): v for k, v in sorted((entry.voted if entry else {}).items())},
                    sort_keys=True, separators=(",", ":")),
                "declined_json": json.dumps(sorted(entry.declined if entry else [])),
                "status": self.terminal_status.get(rid, STATUS_FAILED),
            })
        return rows
