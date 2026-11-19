"""Standing payments (#34): a fixed amount to a fixed recipient on a schedule.

A payer signs ``standing_payment_create`` once. From then on ANYONE (the payee,
the payer's wallet, a validator, a relayer) may submit
``standing_payment_execute`` for a period that is currently due, and the node
moves exactly the signed amount to the signed recipient -- never more, never to
anyone else, never twice in one period. The payer's private key is not needed
again; the chain does not wake itself up, someone submits the execution.

Schedule
--------
The schedule is a period (``consensus.periods``: UTC day, ISO week, UTC month,
or a fixed length anchored at ``start_at``) and a due point inside it:

- month: day ``due_day`` (1..31; a day the month lacks clamps to its last day)
  at ``due_offset_seconds`` into that day;
- day / week / fixed: ``due_offset_seconds`` after the period starts.

An occurrence is executable from its due point for ``window_seconds``. Missed
windows are skipped: there is no catch-up, and one execution never collects
more than one occurrence. Every check uses the block header timestamp.

Every standing payment needs an end: ``end_at`` (no execution at or after it),
``max_occurrences``, or both. The first block at or past ``end_at`` resolves it.

Funds and policy
----------------
Creation reserves nothing. Execution runs the ordinary transfer gates for the
PAYER at that moment -- the payer's current o5 policy against the real recipient
and amount, the fee step, the balance check -- so a later freeze or stricter
policy stops it. Insufficient funds fail the execution whole: no debt, no
partial payment, and the period stays executable until its window closes.
The executor pays the network fee for the execution transaction.

CONSENSUS-FROZEN SURFACE: bounds are module constants; validation is shared by
admission and apply.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus import periods
from consensus.serialization import (
    compute_standing_book_root,
    compute_standing_id,
    compute_standing_resolved_acc,
)

TX_TYPE_STANDING_CREATE = "standing_payment_create"
TX_TYPE_STANDING_CANCEL = "standing_payment_cancel"
TX_TYPE_STANDING_EXECUTE = "standing_payment_execute"

STANDING_TX_TYPES = frozenset(
    {TX_TYPE_STANDING_CREATE, TX_TYPE_STANDING_CANCEL, TX_TYPE_STANDING_EXECUTE}
)

OUTCOME_COMPLETED = 1  # max_occurrences reached
OUTCOME_ENDED = 2  # end_at reached
OUTCOME_CANCELLED = 3

MAX_OPEN_STANDING_PER_PAYER = 16
MAX_OPEN_STANDING_TOTAL = 4096
MAX_STANDING_HORIZON_SECONDS = 5 * 31_536_000
MAX_OCCURRENCES = 10_000
MIN_WINDOW_SECONDS = periods.SECONDS_PER_HOUR

# Shortest length of each calendar kind; a window may not exceed it, so at most
# the current and the previous period can be inside their window at once.
_MIN_PERIOD_LENGTH = {
    periods.PERIOD_DAY: periods.SECONDS_PER_DAY,
    periods.PERIOD_WEEK: periods.SECONDS_PER_WEEK,
    periods.PERIOD_MONTH: 28 * periods.SECONDS_PER_DAY,
}

ZERO_ACC = bytes(32)
_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class StandingShapeError(ValueError):
    """A standing-payment transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class StandingTerms:
    payer_pubkey: str
    recipient_pubkey: str
    amount: int
    sequence_number: int
    period_kind: int
    period_seconds: int
    start_at: int
    due_day: int
    due_offset_seconds: int
    window_seconds: int
    end_at: int  # 0 = no end time (then max_occurrences is required)
    max_occurrences: int  # 0 = unlimited (then end_at is required)

    def as_tuple(self) -> tuple:
        return (
            self.payer_pubkey, self.recipient_pubkey, self.amount, self.sequence_number,
            self.period_kind, self.period_seconds, self.start_at, self.due_day,
            self.due_offset_seconds, self.window_seconds, self.end_at, self.max_occurrences,
        )

    @property
    def standing_id(self) -> bytes:
        return compute_standing_id(*self.as_tuple())

    def period_length(self) -> int:
        if self.period_kind == periods.PERIOD_FIXED:
            return self.period_seconds
        return _MIN_PERIOD_LENGTH[self.period_kind]

    def period_of(self, ts: int) -> int:
        return periods.period_index(
            self.period_kind, ts, anchor=self.start_at, length=self.period_seconds
        )

    def due_at(self, period: int) -> int:
        if self.period_kind == periods.PERIOD_MONTH:
            return periods.monthly_due_ts(period, self.due_day, self.due_offset_seconds)
        start = periods.period_start(
            self.period_kind, period, anchor=self.start_at, length=self.period_seconds
        )
        return start + self.due_offset_seconds

    def first_period(self) -> int:
        """First period whose due point is at or after start_at."""
        p = self.period_of(self.start_at)
        return p if self.due_at(p) >= self.start_at else p + 1


@dataclass(frozen=True)
class StandingState:
    terms: StandingTerms
    next_period: int  # lowest period that may still execute
    executions: int
    total_executed: int

    def due_period(self, ts: int) -> Optional[int]:
        """The period executable at ``ts``, or None."""
        t = self.terms
        if ts < t.start_at or (t.end_at and ts >= t.end_at):
            return None
        if t.max_occurrences and self.executions >= t.max_occurrences:
            return None
        current = t.period_of(ts)
        for p in (current - 1, current):
            if p < max(self.next_period, t.first_period()):
                continue
            due = t.due_at(p)
            if due <= ts < due + t.window_seconds and (not t.end_at or due < t.end_at):
                return p
        return None

    def next_due_at(self, ts: int) -> Optional[int]:
        """Due time of the next occurrence that can still execute (for RPC)."""
        t = self.terms
        if t.max_occurrences and self.executions >= t.max_occurrences:
            return None
        p = max(self.next_period, t.first_period(), t.period_of(max(ts, t.start_at)) - 1)
        for _ in range(3):
            due = t.due_at(p)
            if t.end_at and due >= t.end_at:
                return None
            if due + t.window_seconds > ts:
                return due
            p += 1
        return None


@dataclass(frozen=True)
class StandingExecute:
    executor_pubkey: str
    standing_id: bytes
    period: int


@dataclass(frozen=True)
class StandingCancel:
    payer_pubkey: str
    standing_id: bytes


# --- Parsing (ROOT fields only) --------------------------------------------------


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _pubkey(tx: Dict[str, Any], name: str) -> str:
    v = tx.get(name)
    if not isinstance(v, str) or not _PUBKEY_RE.match(v):
        raise StandingShapeError(f"{name} must be 96 lowercase hex characters")
    return v


def _u64(tx: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    v = tx.get(name, default)
    if not _is_int(v) or v < 0 or v > _U64_MAX:
        raise StandingShapeError(f"{name} must be an unsigned 64-bit integer")
    return v


def _sid(tx: Dict[str, Any]) -> bytes:
    raw = tx.get("standing_id")
    if not isinstance(raw, str) or not _ID_RE.match(raw):
        raise StandingShapeError("standing_id must be 64 lowercase hex characters")
    return bytes.fromhex(raw)


def parse_standing_create(tx: Dict[str, Any]) -> StandingTerms:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return StandingTerms(
        payer_pubkey=_pubkey(tx, "sender_pubkey"),
        recipient_pubkey=_pubkey(tx, "recipient_pubkey"),
        amount=_u64(tx, "amount"),
        sequence_number=_u64(tx, "sequence_number"),
        period_kind=_u64(tx, "period_kind"),
        period_seconds=_u64(tx, "period_seconds", 0),
        start_at=_u64(tx, "start_at"),
        due_day=_u64(tx, "due_day", 0),
        due_offset_seconds=_u64(tx, "due_offset_seconds", 0),
        window_seconds=_u64(tx, "window_seconds"),
        end_at=_u64(tx, "end_at", 0),
        max_occurrences=_u64(tx, "max_occurrences", 0),
    )


def parse_standing_execute(tx: Dict[str, Any]) -> StandingExecute:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return StandingExecute(_pubkey(tx, "sender_pubkey"), _sid(tx), _u64(tx, "period"))


def parse_standing_cancel(tx: Dict[str, Any]) -> StandingCancel:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return StandingCancel(_pubkey(tx, "sender_pubkey"), _sid(tx))


def validate_standing_terms(t: StandingTerms, ts: int) -> Optional[str]:
    """Stateless admissibility at block time ``ts``. None when fine."""
    if not (1 <= t.amount <= tau_defs.MAX_TRANSFER_VALUE):
        return f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if t.recipient_pubkey == t.payer_pubkey:
        return "recipient must differ from payer"
    try:
        periods.validate_period(t.period_kind, t.period_seconds)
    except periods.PeriodError as exc:
        return f"invalid period ({exc})"
    if not t.end_at and not t.max_occurrences:
        return "an end is required: end_at, max_occurrences or both"
    if t.max_occurrences > MAX_OCCURRENCES:
        return f"max_occurrences is above {MAX_OCCURRENCES}"
    if t.start_at + MAX_STANDING_HORIZON_SECONDS < ts:
        return "start_at is too far in the past"
    horizon = max(ts, t.start_at) + MAX_STANDING_HORIZON_SECONDS
    if t.start_at > ts + MAX_STANDING_HORIZON_SECONDS:
        return "start_at is too far ahead"
    if t.end_at and (t.end_at <= ts or t.end_at <= t.start_at):
        return "end_at must be in the future and after start_at"
    if t.end_at and t.end_at > horizon:
        return f"end_at is more than {MAX_STANDING_HORIZON_SECONDS} seconds ahead"
    length = t.period_length()
    if not MIN_WINDOW_SECONDS <= t.window_seconds <= length:
        return f"window_seconds must be between {MIN_WINDOW_SECONDS} and the period length ({length})"
    if t.period_kind == periods.PERIOD_MONTH:
        if not 1 <= t.due_day <= 31:
            return "due_day must be 1..31 for a monthly schedule"
        if t.due_offset_seconds >= periods.SECONDS_PER_DAY:
            return "due_offset_seconds must be within the due day"
    else:
        if t.due_day:
            return "due_day is only for monthly schedules"
        if t.due_offset_seconds >= length:
            return "due_offset_seconds must be within the period"
    return None


# --- The book ----------------------------------------------------------------------

_Row = Tuple[bytes, StandingTerms, int, int, int]


class StandingBook:
    """open -> completed | ended | cancelled, with a constant-size resolved commitment."""

    def __init__(self) -> None:
        self.open: Dict[bytes, StandingState] = {}
        self._per_payer: Dict[str, int] = {}
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "StandingBook":
        clone = StandingBook.__new__(StandingBook)
        clone.open = dict(self.open)
        clone._per_payer = dict(self._per_payer)
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[_Row], resolved_count: int, resolved_acc: bytes) -> "StandingBook":
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for stored_id, terms, next_period, executions, total in rows:
            sid = terms.standing_id
            if sid != bytes(stored_id):
                raise ValueError(f"stored standing payment id does not match its terms: {sid.hex()}")
            if sid in book.open:
                raise ValueError(f"duplicate stored standing payment: {sid.hex()}")
            if total != executions * terms.amount:
                raise ValueError(f"stored standing payment has an impossible total: {sid.hex()}")
            book._insert(sid, StandingState(terms, next_period, executions, total))
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    def _insert(self, sid: bytes, state: StandingState) -> None:
        self.open[sid] = state
        p = state.terms.payer_pubkey
        self._per_payer[p] = self._per_payer.get(p, 0) + 1
        self._root = None

    def _resolve(self, sid: bytes, outcome: int) -> StandingState:
        state = self.open.pop(sid)
        p = state.terms.payer_pubkey
        left = self._per_payer[p] - 1
        if left:
            self._per_payer[p] = left
        else:
            del self._per_payer[p]
        self.resolved_acc = compute_standing_resolved_acc(self.resolved_acc, sid, outcome)
        self.resolved_count += 1
        self._root = None
        return state

    # -- queries --

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_standing_book_root(
                [(sid, s.terms.as_tuple(), s.next_period, s.executions, s.total_executed)
                 for sid, s in self.open.items()],
                self.resolved_count, self.resolved_acc,
            )
        return self._root

    def get(self, sid: bytes) -> Optional[StandingState]:
        return self.open.get(sid)

    def open_count(self) -> int:
        return len(self.open)

    def open_count_for_payer(self, payer: str) -> int:
        return self._per_payer.get(payer, 0)

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    def has_due(self, ts: int) -> bool:
        return any(s.terms.end_at and s.terms.end_at <= ts for s in self.open.values())

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        out = []
        for sid, s in sorted(self.open.items()):
            t = s.terms
            out.append({
                "standing_id": sid.hex(),
                "payer_pubkey": t.payer_pubkey,
                "recipient_pubkey": t.recipient_pubkey,
                "amount": t.amount,
                "sequence_number": t.sequence_number,
                "period_kind": t.period_kind,
                "period_seconds": t.period_seconds,
                "start_at": t.start_at,
                "due_day": t.due_day,
                "due_offset_seconds": t.due_offset_seconds,
                "window_seconds": t.window_seconds,
                "end_at": t.end_at,
                "max_occurrences": t.max_occurrences,
                "next_period": s.next_period,
                "executions": s.executions,
                "total_executed": s.total_executed,
            })
        return out

    # -- admission --

    def can_admit_create(self, terms: StandingTerms, ts: int) -> Tuple[bool, str]:
        reason = validate_standing_terms(terms, ts)
        if reason:
            return False, reason
        if terms.standing_id in self.open:
            return False, "standing payment already exists"
        if self.open_count_for_payer(terms.payer_pubkey) >= MAX_OPEN_STANDING_PER_PAYER:
            return False, f"payer already has {MAX_OPEN_STANDING_PER_PAYER} open standing payments"
        if len(self.open) >= MAX_OPEN_STANDING_TOTAL:
            return False, "standing payment book is full"
        return True, ""

    def can_admit_execute(self, req: StandingExecute, ts: int) -> Tuple[bool, str]:
        state = self.open.get(req.standing_id)
        if state is None:
            return False, "unknown or already resolved standing payment"
        due = state.due_period(ts)
        if due is None:
            return False, "no occurrence is due now (before the window, after it, or already executed)"
        if req.period != due:
            return False, f"period {req.period} is not the due period ({due})"
        return True, ""

    def can_admit_cancel(self, req: StandingCancel, ts: int) -> Tuple[bool, str]:
        state = self.open.get(req.standing_id)
        if state is None:
            return False, "unknown or already resolved standing payment"
        if req.payer_pubkey != state.terms.payer_pubkey:
            return False, "only the payer may cancel"
        return True, ""

    # -- mutation --

    def submit(self, terms: StandingTerms) -> bytes:
        sid = terms.standing_id
        if sid in self.open:
            raise ValueError("standing payment already exists")
        self._insert(sid, StandingState(terms, terms.first_period(), 0, 0))
        return sid

    def record_execution(self, req: StandingExecute, ts: int) -> StandingState:
        """Mark the due period executed. Completes the payment at max_occurrences."""
        ok, reason = self.can_admit_execute(req, ts)
        if not ok:
            raise ValueError(reason)
        state = self.open[req.standing_id]
        after = replace(
            state,
            next_period=req.period + 1,
            executions=state.executions + 1,
            total_executed=state.total_executed + state.terms.amount,
        )
        self.open[req.standing_id] = after
        self._root = None
        if after.terms.max_occurrences and after.executions >= after.terms.max_occurrences:
            self._resolve(req.standing_id, OUTCOME_COMPLETED)
        return after

    def cancel(self, sid: bytes) -> StandingState:
        if sid not in self.open:
            raise KeyError(sid.hex())
        return self._resolve(sid, OUTCOME_CANCELLED)

    def end_due(self, ts: int) -> List[StandingState]:
        """Resolve every payment whose end_at has passed, ascending id. Moves no funds."""
        due = sorted(
            sid for sid, s in self.open.items() if s.terms.end_at and s.terms.end_at <= ts
        )
        return [self._resolve(sid, OUTCOME_ENDED) for sid in due]


def load_standing_book(state: Dict[str, Any]) -> StandingBook:
    rows = []
    for r in state.get("rows", []):
        terms = parse_standing_create({
            "sender_pubkey": r["payer_pubkey"],
            "recipient_pubkey": r["recipient_pubkey"],
            "amount": r["amount"],
            "sequence_number": r["sequence_number"],
            "period_kind": r["period_kind"],
            "period_seconds": r["period_seconds"],
            "start_at": r["start_at"],
            "due_day": r["due_day"],
            "due_offset_seconds": r["due_offset_seconds"],
            "window_seconds": r["window_seconds"],
            "end_at": r["end_at"],
            "max_occurrences": r["max_occurrences"],
        })
        rows.append((bytes.fromhex(r["standing_id"]), terms, int(r["next_period"]),
                     int(r["executions"]), int(r["total_executed"])))
    return StandingBook.restore(
        rows, int(state.get("resolved_count", 0)),
        bytes.fromhex(state.get("resolved_acc", "00" * 32)),
    )
