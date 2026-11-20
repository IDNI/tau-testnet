"""Envelopes: funds sent with spending conditions (spending limits).

Alice sends Bob money in an envelope with `envelope_send`. The money leaves
Alice at once and waits in the envelope; it is Bob's to spend, under the
conditions Alice wrote on it. Bob spends with `envelope_spend`, naming the
envelope, a payee (anyone, himself included) and an amount. Alice cannot take
the money back; she can only be more generous and release the rest to Bob at
once with `envelope_release`. Every envelope ends: when its end is reached the
rest goes to Bob, and an envelope spent to zero closes on its own.

THE SPENDING LIMIT (CONSENSUS-FROZEN)
-------------------------------------
A limit is a list of caps and a period on one clock (blocks or seconds):

    period n   = (clock - anchor) // period      anchor = the clock when sent
    cap(n)     = caps[n]                 while n < len(caps)
               = caps[-1]                after the list, when recurring
               = no limit                after the list, when not recurring
    a spend    1 <= amount <= remaining
               spent in period n + amount <= cap(n)

One cap and `recurring` is the classic allowance: at most 500 a week, the
counter starting again every week. One cap without `recurring` limits only the
first period ("at most 500 in the first month, then freely"). A list is a custom
allowance: [1000, 500] recurring pays an advance up front and then 500 a period.
Nothing carries over: what was not spent in a period does not raise the next
one's cap.

A spend is a transfer Bob signs, judged by the same gates as any transfer he
signs: his o5 clause on the same inputs (the money leaves the envelope, not his
balance), the fee steps, and the fee paid from his own balance. Alice's send is
judged as the transfer it is: her o5 clause sees "Alice pays Bob amount".
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.serialization import (
    compute_envelope_book_root,
    compute_envelope_id,
    compute_envelope_resolved_acc,
)

TX_TYPE_ENVELOPE_SEND = "envelope_send"
TX_TYPE_ENVELOPE_SPEND = "envelope_spend"
TX_TYPE_ENVELOPE_RELEASE = "envelope_release"

ENVELOPE_TX_TYPES = frozenset(
    {TX_TYPE_ENVELOPE_SEND, TX_TYPE_ENVELOPE_SPEND, TX_TYPE_ENVELOPE_RELEASE}
)

KIND_BLOCKS = 0
KIND_SECONDS = 1
KIND_NAMES = {KIND_BLOCKS: "blocks", KIND_SECONDS: "seconds"}
PERIOD_FIELDS = (("period_blocks", KIND_BLOCKS), ("period_seconds", KIND_SECONDS))

# How an envelope closed, folded into the book's commitment.
OUTCOME_EMPTIED = 1      # spent to zero
OUTCOME_RELEASED = 2     # the sender released the rest to the recipient
OUTCOME_ENDED = 3        # its end was reached; the rest went to the recipient
OUTCOME_NAMES = {OUTCOME_EMPTIED: "emptied", OUTCOME_RELEASED: "released",
                 OUTCOME_ENDED: "ended"}

MAX_CAPS = 12
MAX_OPEN_ENVELOPES_PER_SENDER = 16
MAX_OPEN_ENVELOPES_TOTAL = 4096
MAX_PERIOD_BLOCKS = 1_000_000
MAX_PERIOD_SECONDS = 31_622_400            # 366 days
MAX_LIFETIME_BLOCKS = 10_000_000
MAX_LIFETIME_SECONDS = 4 * 31_622_400      # four years of 366 days

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class EnvelopeShapeError(ValueError):
    """An envelope transaction does not have a shape the node can record."""


class EnvelopeRefused(ValueError):
    """A spend or release the envelope does not allow. Nothing moves."""


# --- Terms and state -------------------------------------------------------------


@dataclass(frozen=True)
class EnvelopeTerms:
    """What the sender signed. Immutable."""

    sender_pubkey: str
    sequence_number: int
    recipient_pubkey: str
    amount: int
    caps: Tuple[int, ...]
    kind: int
    period: int
    recurring: bool
    expires_at: int

    @property
    def envelope_id(self) -> bytes:
        return compute_envelope_id(
            self.sender_pubkey, self.sequence_number, self.recipient_pubkey, self.amount,
            self.caps, self.kind, self.period, self.recurring, self.expires_at,
        )

    def clock(self, height: int, ts: int) -> int:
        return int(height) if self.kind == KIND_BLOCKS else int(ts)

    def ended(self, height: int, ts: int) -> bool:
        return self.clock(height, ts) >= self.expires_at

    def cap_for(self, index: int) -> Optional[int]:
        """The cap of period `index`; None when the limit no longer applies."""
        if index < len(self.caps):
            return self.caps[index]
        return self.caps[-1] if self.recurring else None


@dataclass(frozen=True)
class EnvelopeState:
    """Where an open envelope stands. Replaced, never mutated."""

    anchor: int                  # the clock when the envelope was sent
    remaining: int
    period_index: int = 0        # the period `spent_in_period` belongs to
    spent_in_period: int = 0
    spends: int = 0
    last_height: int = 0         # height of the last spend, 0 = never

    def period_at(self, terms: EnvelopeTerms, clock: int) -> int:
        return max(0, int(clock) - self.anchor) // terms.period

    def spent_at(self, terms: EnvelopeTerms, clock: int) -> int:
        return self.spent_in_period if self.period_index == self.period_at(terms, clock) else 0

    def left_at(self, terms: EnvelopeTerms, clock: int) -> int:
        """The most one spend may take at `clock`."""
        cap = terms.cap_for(self.period_at(terms, clock))
        if cap is None:
            return self.remaining
        return max(0, min(self.remaining, cap - self.spent_at(terms, clock)))

    def next_reset(self, terms: EnvelopeTerms, clock: int) -> Optional[int]:
        """The clock at which the next period starts, while a limit still applies."""
        index = self.period_at(terms, clock)
        if terms.cap_for(index) is None:
            return None
        return self.anchor + (index + 1) * terms.period


@dataclass(frozen=True)
class EnvelopeSpend:
    spender_pubkey: str
    envelope_id: bytes
    to_pubkey: str
    amount: int


@dataclass(frozen=True)
class EnvelopeRelease:
    signer_pubkey: str
    envelope_id: bytes


# --- Parsing ---------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise EnvelopeShapeError(f"{what} must be 96 lowercase hex characters")
    return value


def _u64(fields: Dict[str, Any], name: str) -> int:
    value = fields.get(name)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise EnvelopeShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _envelope_id(tx: Dict[str, Any]) -> bytes:
    raw = tx.get("envelope_id")
    if not isinstance(raw, str) or not _ID_RE.match(raw):
        raise EnvelopeShapeError("envelope_id must be 64 lowercase hex characters")
    return bytes.fromhex(raw)


def parse_envelope_send(tx: Dict[str, Any]) -> EnvelopeTerms:
    """Read an envelope from ROOT fields only; a nested `payload` is unsigned."""
    if not isinstance(tx, dict):
        raise EnvelopeShapeError("transaction must be an object")
    sender = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    caps = tx.get("caps")
    if not isinstance(caps, list) or not 1 <= len(caps) <= MAX_CAPS:
        raise EnvelopeShapeError(f"caps must be a list of 1..{MAX_CAPS} amounts")
    for k, cap in enumerate(caps):
        if not _is_int(cap) or cap < 0 or cap > _U64_MAX:
            raise EnvelopeShapeError(f"caps[{k}] must be an unsigned 64-bit integer")
    present = [(n, kind) for n, kind in PERIOD_FIELDS if tx.get(n) is not None]
    if len(present) != 1:
        raise EnvelopeShapeError("exactly one of period_blocks and period_seconds is required")
    name, kind = present[0]
    recurring = tx.get("recurring", False)
    if recurring is None:
        recurring = False
    if not isinstance(recurring, bool):
        raise EnvelopeShapeError("recurring must be true or false")
    return EnvelopeTerms(
        sender_pubkey=sender,
        sequence_number=_u64(tx, "sequence_number"),
        recipient_pubkey=_pubkey(tx.get("recipient_pubkey"), "recipient_pubkey"),
        amount=_u64(tx, "amount"),
        caps=tuple(caps),
        kind=kind,
        period=_u64(tx, name),
        recurring=recurring,
        expires_at=_u64(tx, "expires_at"),
    )


def parse_envelope_spend(tx: Dict[str, Any]) -> EnvelopeSpend:
    if not isinstance(tx, dict):
        raise EnvelopeShapeError("transaction must be an object")
    spender = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    amount = tx.get("amount")
    if not _is_int(amount) or not 1 <= amount <= tau_defs.MAX_TRANSFER_VALUE:
        raise EnvelopeShapeError(f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}")
    return EnvelopeSpend(spender, _envelope_id(tx), _pubkey(tx.get("to_pubkey"), "to_pubkey"),
                         amount)


def parse_envelope_release(tx: Dict[str, Any]) -> EnvelopeRelease:
    if not isinstance(tx, dict):
        raise EnvelopeShapeError("transaction must be an object")
    return EnvelopeRelease(_pubkey(tx.get("sender_pubkey"), "sender_pubkey"),
                           _envelope_id(tx))


def validate_send_shape(terms: EnvelopeTerms, height: int, ts: int) -> Optional[str]:
    """Stateless admissibility of an envelope against the block that sends it.
    Shared by admission and apply: they must refuse the same envelopes."""
    if terms.recipient_pubkey == terms.sender_pubkey:
        return "an envelope may not be sent to its own sender"
    if not 1 <= terms.amount <= tau_defs.MAX_TRANSFER_VALUE:
        return f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    for k, cap in enumerate(terms.caps):
        if not 1 <= cap <= tau_defs.MAX_TRANSFER_VALUE:
            return f"caps[{k}] must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if terms.kind == KIND_BLOCKS:
        hi, now, life = MAX_PERIOD_BLOCKS, int(height), MAX_LIFETIME_BLOCKS
    else:
        hi, now, life = MAX_PERIOD_SECONDS, int(ts), MAX_LIFETIME_SECONDS
    if not 1 <= terms.period <= hi:
        return f"the period must be in 1..{hi} {KIND_NAMES[terms.kind]}"
    if terms.expires_at <= now:
        return "expires_at must be in the future"
    if terms.expires_at > now + life:
        return f"expires_at is more than {life} {KIND_NAMES[terms.kind]} ahead"
    return None


# --- The book --------------------------------------------------------------------

_Row = Tuple[bytes, str, int, str, int, Tuple[int, ...], int, int, bool, int,
             int, int, int, int, int, int]


class EnvelopeBook:
    """Open envelopes and where each stands. Copies share the frozen terms and states.

    Composed as a FIELD of ConsensusLifecycleManager, so the meta hash picks it
    up; it joins the hash only once it has held an envelope.
    """

    def __init__(self) -> None:
        self.open: Dict[bytes, EnvelopeTerms] = {}
        self.state: Dict[bytes, EnvelopeState] = {}
        self._ends: Dict[int, List[Tuple[int, bytes]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        self._per_sender: Dict[str, int] = {}
        self._escrow = 0
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "EnvelopeBook":
        clone = EnvelopeBook.__new__(EnvelopeBook)
        clone.open = dict(self.open)
        clone.state = dict(self.state)
        clone._ends = {k: list(rows) for k, rows in self._ends.items()}
        clone._per_sender = dict(self._per_sender)
        clone._escrow = self._escrow
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[Tuple], resolved_count: int,
                resolved_acc: bytes) -> "EnvelopeBook":
        """Rebuild from stored rows (id, terms..., anchor, state...); refuses a row
        whose id does not recompute or whose state no block could reach."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for row in rows:
            (stored_id, sender, sequence, recipient, amount, caps, kind, period,
             recurring, expires_at, anchor, remaining, period_index, spent, spends,
             last_height) = row
            if kind not in KIND_NAMES:
                raise ValueError("stored envelope has an unknown clock")
            terms = EnvelopeTerms(sender, sequence, recipient, amount, tuple(caps), kind,
                                  period, bool(recurring), expires_at)
            eid = terms.envelope_id
            if eid != bytes(stored_id):
                raise ValueError(f"stored envelope id does not match its terms: {eid.hex()}")
            if eid in book.open:
                raise ValueError(f"envelope stored twice: {eid.hex()}")
            if not (_is_int(period) and period >= 1 and caps and all(
                    _is_int(c) and c >= 1 for c in caps) and sender != recipient):
                raise ValueError(f"stored envelope has impossible terms: {eid.hex()}")
            state = EnvelopeState(anchor, remaining, period_index, spent, spends, last_height)
            if not all(_is_int(v) and v >= 0 for v in (anchor, remaining, period_index,
                                                        spent, spends, last_height)):
                raise ValueError(f"stored envelope has bad progress: {eid.hex()}")
            cap = terms.cap_for(period_index)
            if not 1 <= remaining <= amount or (cap is not None and spent > cap) \
                    or spent > amount - remaining or (spends == 0) != (remaining == amount):
                raise ValueError(f"stored envelope has inconsistent progress: {eid.hex()}")
            book._insert(terms, state)
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals ---------------------------------------------------------------

    def _insert(self, terms: EnvelopeTerms, state: EnvelopeState) -> bytes:
        eid = terms.envelope_id
        self.open[eid] = terms
        self.state[eid] = state
        bisect.insort(self._ends[terms.kind], (terms.expires_at, eid))
        self._per_sender[terms.sender_pubkey] = self._per_sender.get(terms.sender_pubkey, 0) + 1
        self._escrow += state.remaining
        self._root = None
        return eid

    def _close(self, eid: bytes, outcome: int) -> Tuple[EnvelopeTerms, int]:
        """Remove an envelope; (terms, what was left in it)."""
        terms = self.open.pop(eid)
        state = self.state.pop(eid)
        rows = self._ends[terms.kind]
        del rows[bisect.bisect_left(rows, (terms.expires_at, eid))]
        left = self._per_sender[terms.sender_pubkey] - 1
        if left:
            self._per_sender[terms.sender_pubkey] = left
        else:
            del self._per_sender[terms.sender_pubkey]
        self._escrow -= state.remaining
        self.resolved_acc = compute_envelope_resolved_acc(
            self.resolved_acc, eid, outcome, state.remaining)
        self.resolved_count += 1
        self._root = None
        return terms, state.remaining

    def _row(self, eid: bytes) -> _Row:
        t, s = self.open[eid], self.state[eid]
        return (eid, t.sender_pubkey, t.sequence_number, t.recipient_pubkey, t.amount,
                t.caps, t.kind, t.period, t.recurring, t.expires_at, s.anchor, s.remaining,
                s.period_index, s.spent_in_period, s.spends, s.last_height)

    # -- queries -----------------------------------------------------------------

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_envelope_book_root(
                [self._row(e) for e in self.open], self.resolved_count, self.resolved_acc)
        return self._root

    def is_empty(self) -> bool:
        """True while the book has never held an envelope (it then stays out of the hash)."""
        return not self.open and self.resolved_count == 0

    def get(self, eid: bytes) -> Optional[EnvelopeTerms]:
        return self.open.get(bytes(eid))

    def state_of(self, eid: bytes) -> Optional[EnvelopeState]:
        return self.state.get(bytes(eid))

    def open_count(self) -> int:
        return len(self.open)

    def open_count_for_sender(self, sender: str) -> int:
        return self._per_sender.get(sender, 0)

    def escrow_total(self) -> int:
        return self._escrow

    def of(self, pubkey: str, role: str = "all") -> List[bytes]:
        """Open envelope ids `pubkey` sent ("out"), holds ("in") or either, by id."""
        out = []
        for eid in sorted(self.open):
            t = self.open[eid]
            if (role in ("out", "all") and t.sender_pubkey == pubkey) or \
                    (role in ("in", "all") and t.recipient_pubkey == pubkey):
                out.append(eid)
        return out

    def held_for(self, pubkey: str) -> int:
        """What open envelopes hold for `pubkey` to spend."""
        return sum(self.state[e].remaining for e, t in self.open.items()
                   if t.recipient_pubkey == pubkey)

    def has_ending(self, height: int, ts: int) -> bool:
        h, t = self._ends[KIND_BLOCKS], self._ends[KIND_SECONDS]
        return bool((h and h[0][0] <= int(height)) or (t and t[0][0] <= int(ts)))

    def store_rows(self) -> List[_Row]:
        return [self._row(e) for e in sorted(self.open)]

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    # -- admission ---------------------------------------------------------------

    def can_admit_send(self, terms: EnvelopeTerms, height: int, ts: int) -> Tuple[bool, str]:
        reason = validate_send_shape(terms, height, ts)
        if reason:
            return False, reason
        if terms.envelope_id in self.open:
            return False, "this envelope is already open"
        if self.open_count_for_sender(terms.sender_pubkey) >= MAX_OPEN_ENVELOPES_PER_SENDER:
            return False, (f"the sender already has {MAX_OPEN_ENVELOPES_PER_SENDER} "
                           "open envelopes")
        if len(self.open) >= MAX_OPEN_ENVELOPES_TOTAL:
            return False, "the envelope book is full"
        return True, ""

    def check_spend(self, spend: EnvelopeSpend, height: int,
                    ts: int) -> Tuple[EnvelopeTerms, EnvelopeState]:
        """The envelope and its state for this spend, or EnvelopeRefused."""
        terms = self.open.get(spend.envelope_id)
        if terms is None:
            raise EnvelopeRefused("no open envelope has this id")
        if spend.spender_pubkey != terms.recipient_pubkey:
            raise EnvelopeRefused("only the envelope's recipient may spend from it")
        if terms.ended(height, ts):
            raise EnvelopeRefused("the envelope has reached its end")
        state = self.state[spend.envelope_id]
        if spend.amount > state.remaining:
            raise EnvelopeRefused(
                f"the envelope holds {state.remaining}, the spend asks for {spend.amount}")
        clock = terms.clock(height, ts)
        left = state.left_at(terms, clock)
        if spend.amount > left:
            cap = terms.cap_for(state.period_at(terms, clock))
            raise EnvelopeRefused(
                f"the spend asks for {spend.amount}; with {state.spent_at(terms, clock)} "
                f"spent this period, the cap {cap} leaves {left}")
        return terms, state

    def can_admit_release(self, release: EnvelopeRelease) -> Tuple[bool, str]:
        terms = self.open.get(release.envelope_id)
        if terms is None:
            return False, "no open envelope has this id"
        if release.signer_pubkey != terms.sender_pubkey:
            return False, "only the envelope's sender may release it"
        return True, ""

    # -- mutation ----------------------------------------------------------------

    def send(self, terms: EnvelopeTerms, height: int, ts: int) -> bytes:
        return self._insert(terms, EnvelopeState(anchor=terms.clock(height, ts),
                                                 remaining=terms.amount))

    def record_spend(self, eid: bytes, amount: int, height: int,
                     ts: int) -> Tuple[EnvelopeState, bool]:
        """Take `amount` out; (the new state, True when that closed the envelope)."""
        terms, state = self.open[eid], self.state[eid]
        clock = terms.clock(height, ts)
        index = state.period_at(terms, clock)
        state = replace(state, remaining=state.remaining - int(amount), period_index=index,
                        spent_in_period=state.spent_at(terms, clock) + int(amount),
                        spends=state.spends + 1, last_height=int(height))
        self.state[eid] = state
        self._escrow -= int(amount)
        self._root = None
        if state.remaining == 0:
            self._close(eid, OUTCOME_EMPTIED)
            return state, True
        return state, False

    def release(self, eid: bytes) -> Tuple[EnvelopeTerms, int]:
        return self._close(eid, OUTCOME_RELEASED)

    def end_due(self, height: int, ts: int) -> List[Tuple[EnvelopeTerms, int]]:
        """Close every envelope whose end this block reached, earliest first;
        (terms, what was left) for each."""
        gone: List[Tuple[EnvelopeTerms, int]] = []
        for kind, clock in ((KIND_BLOCKS, int(height)), (KIND_SECONDS, int(ts))):
            rows = self._ends[kind]
            while rows and rows[0][0] <= clock:
                gone.append(self._close(rows[0][1], OUTCOME_ENDED))
        return gone


# --- What wallets and history read ------------------------------------------------


def describe(terms: EnvelopeTerms, state: EnvelopeState, *, height: int = 0,
             ts: int = 0) -> Dict[str, Any]:
    """One open envelope as a wallet reads it."""
    clock = terms.clock(height, ts) if (height or ts) else None
    out: Dict[str, Any] = {
        "envelope_id": terms.envelope_id.hex(),
        "sender_pubkey": terms.sender_pubkey,
        "recipient_pubkey": terms.recipient_pubkey,
        "sequence_number": terms.sequence_number,
        "amount": terms.amount,
        "remaining": state.remaining,
        "spent_total": terms.amount - state.remaining,
        "caps": list(terms.caps),
        "recurring": terms.recurring,
        "period_clock": KIND_NAMES[terms.kind],
        "period": terms.period,
        "anchor": state.anchor,
        "expires_at": terms.expires_at,
        "spends": state.spends,
        "last_height": state.last_height or None,
    }
    if clock is not None:
        index = state.period_at(terms, clock)
        cap = terms.cap_for(index)
        out.update({
            "status": "ended" if terms.ended(height, ts) else "open",
            "period_index": index,
            "cap_this_period": cap,
            "spent_this_period": state.spent_at(terms, clock),
            "left_this_period": state.left_at(terms, clock),
            "next_reset": state.next_reset(terms, clock),
        })
    return out


def close_event(terms: EnvelopeTerms, outcome: str, paid_out: int, **extra: Any) -> Dict[str, Any]:
    return {
        "outcome": outcome,
        "envelope_id": terms.envelope_id.hex(),
        "sender_pubkey": terms.sender_pubkey,
        "recipient_pubkey": terms.recipient_pubkey,
        "paid_out": int(paid_out),
        **{k: v for k, v in extra.items() if v is not None},
    }


SEMANTICS: Dict[str, Any] = {
    "supported": True,
    "version": 1,
    "conditions": ["spending_limit"],
    "spending_limit": "in period n = (clock - anchor) // period, at most cap(n) may be "
                      "spent: cap(n) = caps[n] while n < len(caps), then caps[-1] when "
                      "recurring, else no limit; nothing carries over",
    "clocks": list(KIND_NAMES.values()),
    "who": "the sender sends and may release the rest early; only the recipient "
           "spends, to anyone (itself included); nobody else touches it",
    "end": "every envelope ends at expires_at (on its period clock); the rest then goes "
           "to the recipient. An envelope spent to zero closes on its own",
    "policy": "a send is judged by the sender's o5 clause as a transfer to the "
              "recipient; a spend by the recipient's o5 clause as a transfer it signs",
    "fees": "send and spend pay the fee of a transfer, from the signer's own balance; "
            "release is fee-free",
    "routing": "a spend's payee and the recipient at release or end receive through "
               "their receive routes (credit classes envelope_spend, envelope_release)",
    "limits": {
        "caps": MAX_CAPS,
        "open_per_sender": MAX_OPEN_ENVELOPES_PER_SENDER,
        "open_total": MAX_OPEN_ENVELOPES_TOTAL,
        "period_blocks_max": MAX_PERIOD_BLOCKS,
        "period_seconds_max": MAX_PERIOD_SECONDS,
        "lifetime_blocks_max": MAX_LIFETIME_BLOCKS,
        "lifetime_seconds_max": MAX_LIFETIME_SECONDS,
    },
}
