"""Envelopes: funds sent with spending conditions (spending limits, time
conditions).

Alice sends Bob money in an envelope with `envelope_send`. The money leaves
Alice at once and waits in the envelope; it is Bob's to spend, under the
conditions Alice wrote on it. Bob spends with `envelope_spend`, naming the
envelope, a payee (anyone, himself included) and an amount. Alice cannot take
the money back early; she can only be more generous and release the rest to Bob
at once with `envelope_release`. Every envelope ends: when its end is reached
the rest goes to Bob, and an envelope spent to zero closes on its own.

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

TIME CONDITIONS (CONSENSUS-FROZEN)
----------------------------------
An envelope may also carry, each optional, all judged on its one clock:

    not_before   no spend before this clock value
    hold         no spend for this long after the envelope arrives
    days, hours  spends only on these weekdays / in these hours (seconds clock
                 only), read at utc_offset
    utc_offset   where days and hours are read: quarter hours east of UTC,
                 -48 .. 56 (UTC-12:00 .. UTC+14:00); left out = UTC. A fixed
                 offset: it does not follow daylight saving time

    unlock       = max(sent, not_before, sent + hold); the limit's periods start here

A spend lands only at a clock c with unlock <= c < expires_at, inside the
windows, within the limit. The block whose clock reaches the end closes the
envelope after its transactions and pays the rest to the recipient.

WHICH CLOCK
-----------
Every envelope has exactly one clock, blocks or seconds, and every condition on
it is read on that clock: one clock means two conditions can always be compared,
so an envelope that could never be spent is refused when it is sent. Height is
exact and no proposer chooses it. Block time is chosen by the proposer: at least
the parent's time, at most 120 s (MAX_BLOCK_FUTURE_DRIFT_SECONDS) past the
clock of every node that validates the block. So a seconds condition can be
reached up to 120 s early, and a proposer can hold time back (a lock opens late,
a window stays open late), never run it backwards. Weekdays
and hours need the seconds clock and are read at the envelope's fixed offset from
UTC (utc_offset, UTC when left out). Clause-step clocks are never used.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
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

CLOCK_FIELDS = {"blocks": KIND_BLOCKS, "seconds": KIND_SECONDS}

# Signed root fields of `envelope_send` beyond the spending limit, each optional.
OPTIONAL_FIELDS = ("clock", "not_before", "hold", "days", "hours", "utc_offset")

# How an envelope closed, folded into the book's commitment.
OUTCOME_EMPTIED = 1      # spent to zero
OUTCOME_RELEASED = 2     # the sender released the rest to the recipient
OUTCOME_ENDED = 3        # its end was reached; the rest went to the recipient
OUTCOME_NAMES = {OUTCOME_EMPTIED: "emptied", OUTCOME_RELEASED: "released",
                 OUTCOME_ENDED: "ended"}

DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
ALL_DAYS = (1 << 7) - 1
ALL_HOURS = (1 << 24) - 1
SECONDS_PER_DAY = 86_400
SECONDS_PER_HOUR = 3_600
# Where weekdays and hours are read: quarter hours east of UTC, the range of the
# offsets in civil use (UTC-12:00 .. UTC+14:00; some are not whole hours).
SECONDS_PER_OFFSET_UNIT = 900
UTC_OFFSET_MIN = -48
UTC_OFFSET_MAX = 56

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


# --- Clock helpers -------------------------------------------------------------


def weekday(ts: int) -> int:
    """0 = Monday ... 6 = Sunday, UTC. 1970-01-01 was a Thursday."""
    return (int(ts) // SECONDS_PER_DAY + 3) % 7


def hour_of(ts: int) -> int:
    """0..23, UTC."""
    return (int(ts) % SECONDS_PER_DAY) // SECONDS_PER_HOUR


def offset_text(utc_offset: int) -> str:
    """A fixed offset as people write it: "UTC", "UTC+02:00", "UTC-03:30"."""
    if not utc_offset:
        return "UTC"
    minutes = abs(int(utc_offset)) * 15
    return f"UTC{'+' if utc_offset > 0 else '-'}{minutes // 60:02d}:{minutes % 60:02d}"


def day_names(mask: int) -> List[str]:
    return [name for d, name in enumerate(DAY_NAMES) if (mask >> d) & 1]


def hour_list(mask: int) -> List[int]:
    return [h for h in range(24) if (mask >> h) & 1]


# --- Terms and state -------------------------------------------------------------


@dataclass(frozen=True)
class EnvelopeTerms:
    """What the sender signed. Immutable.

    `caps` is empty (and `period` 0) for an envelope without a spending limit.
    The fields after `expires_at` are the time conditions; at their defaults the
    envelope is exactly a spending-limit envelope, with the same id.
    """

    sender_pubkey: str
    sequence_number: int
    recipient_pubkey: str
    amount: int
    caps: Tuple[int, ...]
    kind: int
    period: int
    recurring: bool
    expires_at: int
    not_before: Optional[int] = None
    hold: Optional[int] = None
    days: int = 0                 # bit d = weekday d (0 = Monday); 0 = every day
    hours: int = 0                # bit h = hour h; 0 = every hour
    utc_offset: int = 0           # days and hours are read this many quarter hours east of UTC

    @property
    def conditions(self) -> Optional[Tuple]:
        """The conditions beyond the limit as they are stored and hashed, None when
        there are none. The fifth and sixth places are kept free for the refund
        conditions of the next stage, so that stage changes no stored row and no id."""
        c = (self.not_before, self.hold, self.days, self.hours, None, 0, self.utc_offset)
        return None if c == (None, None, 0, 0, None, 0, 0) else c

    @property
    def extended(self) -> bool:
        return self.conditions is not None

    @property
    def limited(self) -> bool:
        return bool(self.caps)

    @property
    def windowed(self) -> bool:
        return bool(self.days or self.hours)

    @property
    def envelope_id(self) -> bytes:
        return compute_envelope_id(
            self.sender_pubkey, self.sequence_number, self.recipient_pubkey, self.amount,
            self.caps, self.kind, self.period, self.recurring, self.expires_at,
            self.conditions,
        )

    def clock(self, height: int, ts: int) -> int:
        return int(height) if self.kind == KIND_BLOCKS else int(ts)

    def cap_for(self, index: int) -> Optional[int]:
        """The cap of period `index`; None when no limit applies."""
        if not self.caps:
            return None
        if index < len(self.caps):
            return self.caps[index]
        return self.caps[-1] if self.recurring else None

    def unlock_at(self, sent: int) -> int:
        """The first clock a spend may land at, for an envelope sent at `sent`."""
        t = int(sent)
        if self.not_before is not None:
            t = max(t, self.not_before)
        if self.hold is not None:
            t = max(t, int(sent) + self.hold)
        return t

    def local(self, ts: int) -> int:
        """Block time `ts` moved to the envelope's offset: the weekday and the hour
        of this value are the ones the windows are read on."""
        return int(ts) + self.utc_offset * SECONDS_PER_OFFSET_UNIT

    def in_window(self, ts: int) -> bool:
        """True when a block at time `ts` lies in the envelope's weekdays and hours."""
        at = self.local(ts)
        if self.days and not (self.days >> weekday(at)) & 1:
            return False
        if self.hours and not (self.hours >> hour_of(at)) & 1:
            return False
        return True

    def next_window(self, ts: int) -> Optional[int]:
        """The first second at or after `ts` inside the windows (one week ahead at most).
        A window opens on a whole hour at the envelope's offset, which is a quarter
        hour of UTC when the offset is not a whole hour."""
        if self.in_window(ts):
            return int(ts)
        shift = self.utc_offset * SECONDS_PER_OFFSET_UNIT
        t = (self.local(ts) // SECONDS_PER_HOUR + 1) * SECONDS_PER_HOUR - shift
        for _ in range(7 * 24):
            if self.in_window(t):
                return t
            t += SECONDS_PER_HOUR
        return None


@dataclass(frozen=True)
class EnvelopeState:
    """Where an open envelope stands. Replaced, never mutated."""

    anchor: int                  # the unlock point: the clock when sent, moved on by
                                 # not_before / hold; the limit's periods start here
    remaining: int
    period_index: int = 0        # the period `spent_in_period` belongs to
    spent_in_period: int = 0
    spends: int = 0
    last_height: int = 0         # height of the last spend, 0 = never
    last_clock: int = 0          # clock of the last spend (extended envelopes), 0 = never;
                                 # kept for the refund stage, which counts idle time from it

    def period_at(self, terms: EnvelopeTerms, clock: int) -> int:
        if not terms.limited:
            return 0
        return max(0, int(clock) - self.anchor) // terms.period

    def spent_at(self, terms: EnvelopeTerms, clock: int) -> int:
        return self.spent_in_period if self.period_index == self.period_at(terms, clock) else 0

    def left_at(self, terms: EnvelopeTerms, clock: int) -> int:
        """The most one spend may take at `clock` under the limit."""
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

    def due_point(self, terms: EnvelopeTerms) -> int:
        """The clock at which the envelope closes on its own: its end."""
        return terms.expires_at


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


def _opt_u64(fields: Dict[str, Any], name: str) -> Optional[int]:
    return None if fields.get(name) is None else _u64(fields, name)


def _days_mask(value: Any) -> int:
    if value is None:
        return 0
    if not isinstance(value, list) or not value or not all(
            isinstance(d, str) and d in DAY_NAMES for d in value):
        raise EnvelopeShapeError(f"days must be a list of day names {list(DAY_NAMES)}")
    order = [DAY_NAMES.index(d) for d in value]
    if order != sorted(set(order)):
        raise EnvelopeShapeError("days must be listed once each, Monday first")
    return sum(1 << d for d in order)


def _hours_mask(value: Any) -> int:
    if value is None:
        return 0
    if not isinstance(value, list) or not value or not all(
            _is_int(h) and 0 <= h <= 23 for h in value):
        raise EnvelopeShapeError("hours must be a list of hours 0..23")
    if list(value) != sorted(set(value)):
        raise EnvelopeShapeError("hours must be listed once each, in increasing order")
    return sum(1 << h for h in value)


def _utc_offset(value: Any) -> int:
    if value is None:
        return 0
    if not _is_int(value) or not UTC_OFFSET_MIN <= value <= UTC_OFFSET_MAX:
        raise EnvelopeShapeError(
            f"utc_offset must be a whole number of quarter hours east of UTC, "
            f"{UTC_OFFSET_MIN}..{UTC_OFFSET_MAX}")
    if value == 0:
        raise EnvelopeShapeError("utc_offset 0 is UTC, the default: leave utc_offset out")
    return int(value)


def parse_envelope_send(tx: Dict[str, Any]) -> EnvelopeTerms:
    """Read an envelope from ROOT fields only; a nested `payload` is unsigned."""
    if not isinstance(tx, dict):
        raise EnvelopeShapeError("transaction must be an object")
    sender = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    caps = tx.get("caps")
    present = [(n, kind) for n, kind in PERIOD_FIELDS if tx.get(n) is not None]
    clock = tx.get("clock")
    if clock is not None and clock not in CLOCK_FIELDS:
        raise EnvelopeShapeError(f"clock must be one of {sorted(CLOCK_FIELDS)}")
    recurring = tx.get("recurring", False)
    if recurring is None:
        recurring = False
    if not isinstance(recurring, bool):
        raise EnvelopeShapeError("recurring must be true or false")
    if caps is not None:
        if not isinstance(caps, list) or not 1 <= len(caps) <= MAX_CAPS:
            raise EnvelopeShapeError(f"caps must be a list of 1..{MAX_CAPS} amounts")
        for k, cap in enumerate(caps):
            if not _is_int(cap) or cap < 0 or cap > _U64_MAX:
                raise EnvelopeShapeError(f"caps[{k}] must be an unsigned 64-bit integer")
        if len(present) != 1:
            raise EnvelopeShapeError(
                "exactly one of period_blocks and period_seconds is required")
        name, kind = present[0]
        period = _u64(tx, name)
        if clock is not None and CLOCK_FIELDS[clock] != kind:
            raise EnvelopeShapeError(f"clock {clock} does not match {name}")
    else:
        if present:
            raise EnvelopeShapeError(f"{present[0][0]} needs caps")
        if recurring:
            raise EnvelopeShapeError("recurring needs caps")
        if clock is None:
            raise EnvelopeShapeError(
                "an envelope without caps names its clock: blocks or seconds")
        kind, period, caps = CLOCK_FIELDS[clock], 0, []
    return EnvelopeTerms(
        sender_pubkey=sender,
        sequence_number=_u64(tx, "sequence_number"),
        recipient_pubkey=_pubkey(tx.get("recipient_pubkey"), "recipient_pubkey"),
        amount=_u64(tx, "amount"),
        caps=tuple(caps),
        kind=kind,
        period=period,
        recurring=recurring,
        expires_at=_u64(tx, "expires_at"),
        not_before=_opt_u64(tx, "not_before"),
        hold=_opt_u64(tx, "hold"),
        days=_days_mask(tx.get("days")),
        hours=_hours_mask(tx.get("hours")),
        utc_offset=_utc_offset(tx.get("utc_offset")),
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


def terms_problem(terms: EnvelopeTerms) -> Optional[str]:
    """What makes these terms impossible whatever the block; None when they are fine.
    Shared by admission, apply and restore."""
    if terms.kind not in KIND_NAMES:
        return "the clock must be blocks or seconds"
    if terms.recipient_pubkey == terms.sender_pubkey:
        return "an envelope may not be sent to its own sender"
    if not 1 <= terms.amount <= tau_defs.MAX_TRANSFER_VALUE:
        return f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if terms.kind == KIND_BLOCKS:
        hi, life = MAX_PERIOD_BLOCKS, MAX_LIFETIME_BLOCKS
    else:
        hi, life = MAX_PERIOD_SECONDS, MAX_LIFETIME_SECONDS
    unit = KIND_NAMES[terms.kind]
    if terms.caps:
        if len(terms.caps) > MAX_CAPS:
            return f"at most {MAX_CAPS} caps"
        for k, cap in enumerate(terms.caps):
            if not 1 <= cap <= tau_defs.MAX_TRANSFER_VALUE:
                return f"caps[{k}] must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
        if not 1 <= terms.period <= hi:
            return f"the period must be in 1..{hi} {unit}"
    elif terms.period or terms.recurring:
        return "a period needs caps"
    if not terms.caps and not terms.extended:
        return ("an envelope needs at least one condition: caps, not_before, hold, days "
                "or hours (else send a transfer)")
    if terms.windowed and terms.kind != KIND_SECONDS:
        return "days and hours need the seconds clock"
    if terms.days and not 0 < terms.days < ALL_DAYS:
        return "days must leave out at least one day (else leave days out)"
    if terms.hours and not 0 < terms.hours < ALL_HOURS:
        return "hours must leave out at least one hour (else leave hours out)"
    if not UTC_OFFSET_MIN <= terms.utc_offset <= UTC_OFFSET_MAX:
        return f"utc_offset must be in {UTC_OFFSET_MIN}..{UTC_OFFSET_MAX} quarter hours"
    if terms.utc_offset and not terms.windowed:
        return "utc_offset needs days or hours (it says where they are read)"
    if terms.hold is not None and not 1 <= terms.hold <= life:
        return f"hold must be in 1..{life} {unit}"
    return None


def first_spend_point(terms: EnvelopeTerms, sent: int) -> Optional[int]:
    """The earliest clock a spend could land at, for an envelope sent at `sent`;
    None when no spend can ever land (it is locked or outside its windows until its
    end)."""
    unlock = terms.unlock_at(sent)
    due = EnvelopeState(anchor=unlock, remaining=terms.amount).due_point(terms)
    first = terms.next_window(unlock) if terms.windowed else unlock
    if first is None or first >= due:
        return None
    return first


def validate_send_shape(terms: EnvelopeTerms, height: int, ts: int) -> Optional[str]:
    """Stateless admissibility of an envelope against the block that sends it.
    Shared by admission and apply: they must refuse the same envelopes."""
    problem = terms_problem(terms)
    if problem:
        return problem
    if terms.kind == KIND_BLOCKS:
        now, life = int(height), MAX_LIFETIME_BLOCKS
    else:
        now, life = int(ts), MAX_LIFETIME_SECONDS
    if terms.expires_at <= now:
        return "expires_at must be in the future"
    if terms.expires_at > now + life:
        return f"expires_at is more than {life} {KIND_NAMES[terms.kind]} ahead"
    unlock = terms.unlock_at(now)
    if unlock >= terms.expires_at:
        return f"it would unlock at {unlock}, not before its end at {terms.expires_at}"
    if first_spend_point(terms, now) is None:
        due = EnvelopeState(anchor=unlock, remaining=terms.amount).due_point(terms)
        return (f"it could never be spent: no spending window opens between its "
                f"unlock at {unlock} and {due}")
    return None


# --- The book --------------------------------------------------------------------

_Row = Tuple[bytes, str, int, str, int, Tuple[int, ...], int, int, bool, int,
             int, int, int, int, int, int, Optional[Tuple], int]


class EnvelopeBook:
    """Open envelopes and where each stands. Copies share the frozen terms and states.

    Composed as a FIELD of ConsensusLifecycleManager, so the meta hash picks it
    up; it joins the hash only once it has held an envelope.
    """

    def __init__(self) -> None:
        self.open: Dict[bytes, EnvelopeTerms] = {}
        self.state: Dict[bytes, EnvelopeState] = {}
        # (due point, id) per clock, kept sorted. The due point is the end.
        self._due: Dict[int, List[Tuple[int, bytes]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        self._per_sender: Dict[str, int] = {}
        self._escrow = 0
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "EnvelopeBook":
        clone = EnvelopeBook.__new__(EnvelopeBook)
        clone.open = dict(self.open)
        clone.state = dict(self.state)
        clone._due = {k: list(rows) for k, rows in self._due.items()}
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
        """Rebuild from stored rows (id, terms..., anchor, state..., conditions,
        last_clock); refuses a row whose id does not recompute or whose state no
        block could reach. A row without the last two is a spending-limit-only row."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for row in rows:
            row = tuple(row)
            if len(row) == 16:
                row = row + (None, 0)
            (stored_id, sender, sequence, recipient, amount, caps, kind, period,
             recurring, expires_at, anchor, remaining, period_index, spent, spends,
             last_height, conditions, last_clock) = row
            if kind not in KIND_NAMES:
                raise ValueError("stored envelope has an unknown clock")
            extra: Dict[str, Any] = {}
            if conditions is not None:
                not_before, hold, days, hours, free_a, free_b, utc_offset = conditions
                if free_a is not None or free_b:
                    raise ValueError("stored envelope has a condition this node does not know")
                extra = dict(not_before=not_before, hold=hold, days=int(days or 0),
                             hours=int(hours or 0), utc_offset=int(utc_offset or 0))
            terms = EnvelopeTerms(sender, sequence, recipient, amount, tuple(caps), kind,
                                  period, bool(recurring), expires_at, **extra)
            eid = terms.envelope_id
            if eid != bytes(stored_id):
                raise ValueError(f"stored envelope id does not match its terms: {eid.hex()}")
            if eid in book.open:
                raise ValueError(f"envelope stored twice: {eid.hex()}")
            if conditions is not None and not terms.extended:
                raise ValueError(f"stored envelope has empty conditions: {eid.hex()}")
            if not all(v is None or (_is_int(v) and v >= 0) for v in (
                    terms.not_before, terms.hold)) \
                    or terms_problem(terms) or not _is_int(period):
                raise ValueError(f"stored envelope has impossible terms: {eid.hex()}")
            state = EnvelopeState(anchor, remaining, period_index, spent, spends,
                                  last_height, last_clock)
            if not all(_is_int(v) and v >= 0 for v in (anchor, remaining, period_index,
                                                        spent, spends, last_height,
                                                        last_clock)):
                raise ValueError(f"stored envelope has bad progress: {eid.hex()}")
            cap = terms.cap_for(period_index)
            if not 1 <= remaining <= amount or (cap is not None and spent > cap) \
                    or spent > amount - remaining or (spends == 0) != (remaining == amount) \
                    or (not terms.limited and period_index) \
                    or (last_clock and (not terms.extended or not spends
                                        or last_clock < anchor)) \
                    or anchor >= terms.expires_at:
                raise ValueError(f"stored envelope has inconsistent progress: {eid.hex()}")
            book._insert(terms, state)
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals ---------------------------------------------------------------

    def _index(self, eid: bytes) -> None:
        terms = self.open[eid]
        bisect.insort(self._due[terms.kind], (self.state[eid].due_point(terms), eid))

    def _unindex(self, eid: bytes) -> None:
        terms = self.open[eid]
        rows = self._due[terms.kind]
        del rows[bisect.bisect_left(rows, (self.state[eid].due_point(terms), eid))]

    def _insert(self, terms: EnvelopeTerms, state: EnvelopeState) -> bytes:
        eid = terms.envelope_id
        self.open[eid] = terms
        self.state[eid] = state
        self._index(eid)
        self._per_sender[terms.sender_pubkey] = self._per_sender.get(terms.sender_pubkey, 0) + 1
        self._escrow += state.remaining
        self._root = None
        return eid

    def _close(self, eid: bytes, outcome: int) -> Tuple[EnvelopeTerms, int]:
        """Remove an envelope; (terms, what was left in it)."""
        self._unindex(eid)
        terms = self.open.pop(eid)
        state = self.state.pop(eid)
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
                s.period_index, s.spent_in_period, s.spends, s.last_height,
                t.conditions, s.last_clock)

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

    def has_due(self, height: int, ts: int) -> bool:
        """True when a block at this height and time closes an envelope (its end);
        the miner wakes an idle chain for it."""
        h, t = self._due[KIND_BLOCKS], self._due[KIND_SECONDS]
        return bool((h and h[0][0] <= int(height)) or (t and t[0][0] <= int(ts)))

    has_ending = has_due

    def due_points(self) -> Dict[str, Tuple[int, int]]:
        """Per open envelope (hex id): (clock kind, due point). A node-local hint."""
        return {eid.hex(): (self.open[eid].kind, d)
                for rows in self._due.values() for d, eid in rows}

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
        """The envelope and its state for this spend, or EnvelopeRefused.

        Order: closed -> who -> end reached -> locked -> window -> holds -> limit.
        """
        terms = self.open.get(spend.envelope_id)
        if terms is None:
            raise EnvelopeRefused("no open envelope has this id")
        if spend.spender_pubkey != terms.recipient_pubkey:
            raise EnvelopeRefused("only the envelope's recipient may spend from it")
        state = self.state[spend.envelope_id]
        clock = terms.clock(height, ts)
        if clock >= state.due_point(terms):
            raise EnvelopeRefused("the envelope has reached its end")
        if clock < state.anchor:
            raise EnvelopeRefused(
                f"the envelope is locked until {state.anchor} ({KIND_NAMES[terms.kind]}"
                + ("" if terms.kind == KIND_BLOCKS else f", {utc_text(state.anchor)}") + ")")
        if terms.windowed and not terms.in_window(ts):
            nxt = terms.next_window(ts)
            raise EnvelopeRefused(
                f"the spend is outside its spending window ({window_text(terms)}); "
                + (f"the next window opens at {nxt} ({moment_text(nxt, terms.utc_offset)})"
                   if nxt is not None
                   else "no later window opens"))
        if spend.amount > state.remaining:
            raise EnvelopeRefused(
                f"the envelope holds {state.remaining}, the spend asks for {spend.amount}")
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
        return self._insert(terms, EnvelopeState(
            anchor=terms.unlock_at(terms.clock(height, ts)), remaining=terms.amount))

    def record_spend(self, eid: bytes, amount: int, height: int,
                     ts: int) -> Tuple[EnvelopeState, bool]:
        """Take `amount` out; (the new state, True when that closed the envelope)."""
        terms, state = self.open[eid], self.state[eid]
        clock = terms.clock(height, ts)
        index = state.period_at(terms, clock)
        state = replace(state, remaining=state.remaining - int(amount), period_index=index,
                        spent_in_period=state.spent_at(terms, clock) + int(amount),
                        spends=state.spends + 1, last_height=int(height),
                        last_clock=clock if terms.extended else 0)
        self.state[eid] = state
        self._escrow -= int(amount)
        self._root = None
        if state.remaining == 0:
            self._close(eid, OUTCOME_EMPTIED)
            return state, True
        return state, False

    def release(self, eid: bytes) -> Tuple[EnvelopeTerms, int]:
        return self._close(eid, OUTCOME_RELEASED)

    def end_due(self, height: int, ts: int) -> List[Tuple[EnvelopeTerms, int, int]]:
        """Close every envelope whose due point this block reached, block clock
        first, then by (due point, id); (terms, what was left, outcome) for each.
        The outcome is ENDED: the rest goes to the recipient."""
        gone: List[Tuple[EnvelopeTerms, int, int]] = []
        for kind, clock in ((KIND_BLOCKS, int(height)), (KIND_SECONDS, int(ts))):
            rows = self._due[kind]
            while rows and rows[0][0] <= clock:
                terms, left = self._close(rows[0][1], OUTCOME_ENDED)
                gone.append((terms, left, OUTCOME_ENDED))
        return gone


# --- What wallets and history read ------------------------------------------------


def utc_text(ts: int) -> str:
    """A moment on the seconds clock as people read it (refusal reasons)."""
    moment = datetime.fromtimestamp(int(ts), timezone.utc)
    return moment.strftime("%a %Y-%m-%d %H:%M:%S UTC" if moment.second else "%a %Y-%m-%d %H:%M UTC")


def moment_text(ts: int, utc_offset: int = 0) -> str:
    """A moment in UTC and, for an envelope read at another offset, there too."""
    if not utc_offset:
        return utc_text(ts)
    there = datetime.fromtimestamp(
        int(ts) + int(utc_offset) * SECONDS_PER_OFFSET_UNIT, timezone.utc)
    return f"{utc_text(ts)}, {there.strftime('%a %H:%M')} {offset_text(utc_offset)}"


def window_text(terms: EnvelopeTerms) -> str:
    parts = []
    if terms.days:
        parts.append(", ".join(day_names(terms.days)))
    if terms.hours:
        parts.append("hours " + ", ".join(str(h) for h in hour_list(terms.hours)))
    return "; ".join(parts) + " " + offset_text(terms.utc_offset) if parts else "any time"


def conditions_json(terms: EnvelopeTerms) -> Optional[Dict[str, Any]]:
    """The conditions beyond the limit as signed fields (for storage and wallets)."""
    if not terms.extended:
        return None
    return {
        "not_before": terms.not_before,
        "hold": terms.hold,
        "days": day_names(terms.days) or None,
        "hours": hour_list(terms.hours) or None,
        "utc_offset": terms.utc_offset or None,
    }


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
        "clock": KIND_NAMES[terms.kind],
        "caps": list(terms.caps),
        "recurring": terms.recurring,
        "period_clock": KIND_NAMES[terms.kind],
        "period": terms.period if terms.limited else None,
        "anchor": state.anchor,
        "expires_at": terms.expires_at,
        "not_before": terms.not_before,
        "hold": terms.hold,
        "days": day_names(terms.days) or None,
        "hours": hour_list(terms.hours) or None,
        "utc_offset": terms.utc_offset or None,
        "windows_read_at": offset_text(terms.utc_offset) if terms.windowed else None,
        "unlocks_at": state.anchor,
        "spends": state.spends,
        "last_height": state.last_height or None,
    }
    if clock is not None:
        index = state.period_at(terms, clock)
        cap = terms.cap_for(index)
        ended = clock >= terms.expires_at
        locked = clock < state.anchor
        in_window = (not terms.windowed) or terms.in_window(ts)
        left = state.left_at(terms, clock)
        out.update({
            "status": "ended" if ended else ("locked" if locked else "open"),
            "locked": locked,
            "in_window": in_window,
            "next_window": (terms.next_window(max(int(ts), state.anchor))
                            if terms.windowed and not ended else None),
            "spendable_now": (not ended and not locked and in_window and left > 0),
            "period_index": index,
            "cap_this_period": cap,
            "spent_this_period": state.spent_at(terms, clock),
            "left_this_period": left,
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
    "version": 2,
    "conditions": ["spending_limit", "not_before", "hold", "days", "hours",
                   "utc_offset"],
    "spending_limit": "in period n = (clock - unlock) // period, at most cap(n) may be "
                      "spent: cap(n) = caps[n] while n < len(caps), then caps[-1] when "
                      "recurring, else no limit; nothing carries over. Optional",
    "clock": "every envelope has one clock, blocks or seconds, and every condition is "
             "read on it. Height is exact; block time is chosen by the proposer, at "
             "least the parent's and at most 120 s past the validating node's clock, "
             "so a seconds condition can be reached up to 120 s early and can be held "
             "back, never run backwards",
    "clocks": list(KIND_NAMES.values()),
    "unlock": "unlock = max(sent, not_before, sent + hold); no spend before it",
    "windows": "days (mon..sun) and hours (0..23) need the seconds clock and are read "
               "at utc_offset, a fixed offset in quarter hours east of UTC (-48..56, "
               "UTC when left out; no daylight saving); a spend lands only in a block "
               "whose time is in both",
    "never_spendable": "an envelope that could never be spent (it unlocks at or after "
                       "its end, or no window opens before its end) is "
                       "refused when sent",
    "who": "the sender sends and may release the rest early; only the recipient "
           "spends, to anyone (itself included); nobody else touches it. Nobody can "
           "change the conditions after the send",
    "end": "every envelope ends at expires_at (on its clock); the rest then goes to "
           "the recipient. An envelope spent to zero closes on its own",
    "order": "a spend is refused once the end is reached, before the unlock, "
             "outside the windows, above what the envelope holds, or above the cap",
    "policy": "a send is judged by the sender's o5 clause as a transfer to the "
              "recipient; a spend by the recipient's o5 clause as a transfer it signs; "
              "the end is not judged again (the money left the sender at the send)",
    "fees": "send and spend pay the fee of a transfer, from the signer's own balance; "
            "release and the end are fee-free",
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
