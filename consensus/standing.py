"""Standing payments: a payer signs once, the network pays on a schedule (#34).

A payer creates an authorization with `standing_payment_create`: a fixed
recipient, a fixed amount, a schedule (every N blocks, every N seconds, or every
N calendar months in UTC) and a number of periods. From then on each period is
paid at most once, without the payer's key, until the periods run out or the
payer sends `standing_payment_cancel`. Two things can pay a period:

- the sweep at the end of a block, on its own, once the period is due;
- `standing_payment_execute`, which ANYONE may send (the payee, a relayer, the
  payer's own wallet) to pay the period that is due now, in the block it lands
  in. It names only the authorization: the executor chooses nothing but the
  moment, and pays the fee for its own transaction.

`standing_payment_update` replaces an authorization with a new version: the old
one ends (outcome "replaced") and a new one with its own id starts in the same
transaction, carrying `version` + 1 and the id it replaces. Signed terms are
never edited in place.

Lifecycle of one authorization, with period p in 0..periods-1 and its window
[due(p), due(p+1)):

    waiting --due(p) reached--> queued --paid--------> waiting for p+1
                                   |----policy block-> waiting for p+1 (p missed)
                                   |----no funds-----> queued again (retry later
                                   |                   in the same window)
                                   '----window closed> p missed, next period
    after the last period, on cancel or on update: resolved

An execute acts on the same states: it pays the period the block falls in, marks
any earlier period whose window closed unpaid as missed, and leaves the entry
waiting for the next period. It is refused, and changes nothing, when that
period is already settled, when the payer cannot fund it or the payer's policy
blocks it, before the first due point and after the end.

Nothing is reserved at creation: an occurrence the payer cannot fund is retried
in later blocks of the same window and then counts as missed. It never pays
part, never borrows, and never pays two periods in one go (no catch-up).

Every payment re-checks the payer's CURRENT o5 clause against the real recipient
and amount, so a later freeze or a stricter rule stops it. The check goes
through the per-clause policy evaluator, never the main interpreter, so a
payment the sweep makes steps no consensus interpreter and pays no fee: the
creation is the one charge, as for an approval request or a retractable
transfer. An execute is a transaction like any other and its sender pays its fee.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would make
two honest nodes disagree about what a block does, which forks. The calendar is
computed with integer arithmetic (no platform time functions), so every node
derives the same due points.

The book commits its open entries WITH their progress (period, counters, queue
position), because which entries a capped sweep reaches in a block depends on
it. Resolved entries leave memory; a count and an order-dependent running hash
remain (the retractable pattern).
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, replace
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.serialization import (
    compute_standing_book_root,
    compute_standing_id,
    compute_standing_resolved_acc,
)

TX_TYPE_STANDING_PAYMENT_CREATE = "standing_payment_create"
TX_TYPE_STANDING_PAYMENT_CANCEL = "standing_payment_cancel"
TX_TYPE_STANDING_PAYMENT_EXECUTE = "standing_payment_execute"
TX_TYPE_STANDING_PAYMENT_UPDATE = "standing_payment_update"

STANDING_TX_TYPES = frozenset(
    {TX_TYPE_STANDING_PAYMENT_CREATE, TX_TYPE_STANDING_PAYMENT_CANCEL,
     TX_TYPE_STANDING_PAYMENT_EXECUTE, TX_TYPE_STANDING_PAYMENT_UPDATE}
)

# Schedule kinds. BLOCKS counts heights; SECONDS and MONTHS read the block
# timestamp (consensus time, UTC).
KIND_BLOCKS = 0
KIND_SECONDS = 1
KIND_MONTHS = 2

KIND_NAMES = {KIND_BLOCKS: "blocks", KIND_SECONDS: "seconds", KIND_MONTHS: "months"}

# Root field -> kind. Exactly one of them is present on a create.
INTERVAL_FIELDS = (
    ("interval_blocks", KIND_BLOCKS),
    ("interval_seconds", KIND_SECONDS),
    ("interval_months", KIND_MONTHS),
)

# Folded into the resolved commitment as one byte per resolution.
OUTCOME_ENDED = 1
OUTCOME_CANCELLED = 2
OUTCOME_REPLACED = 3

# What one attempt did.
ATTEMPT_PAID = "paid"
ATTEMPT_NO_FUNDS = "no_funds"
ATTEMPT_BLOCKED = "blocked"

MAX_OPEN_STANDING_PER_PAYER = 16
MAX_OPEN_STANDING_TOTAL = 4096
# Queue entries the sweep handles in one block: an attempt, or closing an entry
# whose window or schedule ran out. Bounds what one block costs a validator.
MAX_STANDING_ACTIONS_PER_BLOCK = 32
# `standing_payment_execute` transactions one block may carry. Each runs at most
# one o5 clause step and pays its own fee; the bound keeps a block's worst case
# at sweep cap + this many clause steps.
MAX_STANDING_EXECUTIONS_PER_BLOCK = 32

MIN_INTERVAL_BLOCKS = 128
MAX_INTERVAL_BLOCKS = 1_000_000
MIN_INTERVAL_SECONDS = 3_600
MAX_INTERVAL_SECONDS = 31_622_400  # 366 days
MAX_INTERVAL_MONTHS = 12
MAX_PERIODS = 1_200
# How far ahead the first due point may lie.
MAX_FIRST_DUE_BLOCKS = 100_000
MAX_FIRST_DUE_SECONDS = 31_622_400

# Last second of 9999-12-31 UTC: every due point of a time schedule is a valid
# calendar instant, and the end of every schedule fits a u64.
MAX_TIME = 253_402_300_799

# The queue is FIFO and holds each entry at most once, so with the book full an
# entry reaches the front within ceil(total / cap) blocks. A block window at
# least that long is attempted at least once in every period.
assert MIN_INTERVAL_BLOCKS >= -(-MAX_OPEN_STANDING_TOTAL // MAX_STANDING_ACTIONS_PER_BLOCK)

ZERO_ACC = bytes(32)
# Lineage of an entry that replaces nothing: version 1, no predecessor.
FIRST_VERSION = (1, bytes(32))

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U32_MAX = 0xFFFFFFFF
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_ID_MAX = b"\xff" * 33

# Due lists, by the clock they read.
_BY_HEIGHT = 0
_BY_TIME = 1


class StandingShapeError(ValueError):
    """A standing-payment transaction does not have a shape the node can record."""


# --- Calendar (integer arithmetic, proleptic Gregorian, UTC) -------------------


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 for a valid date (H. Hinnant's algorithm)."""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(days: int) -> Tuple[int, int, int]:
    """(year, month, day) of a day count since 1970-01-01."""
    days += 719468
    era = days // 146097
    doe = days - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    return yoe + era * 400 + (month <= 2), month, day


def _month_length(year: int, month: int) -> int:
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def add_months(anchor: int, months: int) -> int:
    """`anchor` moved by whole calendar months, keeping day and time of day.

    A day the target month does not have becomes its last day: a schedule
    anchored on the 31st pays on 30 April and on 28 or 29 February. Each due
    point is derived from the anchor, never from the previous due point, so the
    31st comes back in May (no drift).
    """
    days, seconds = divmod(int(anchor), 86400)
    year, month, day = _civil_from_days(days)
    total = (month - 1) + int(months)
    year, month = year + total // 12, total % 12 + 1
    day = min(day, _month_length(year, month))
    return _days_from_civil(year, month, day) * 86400 + seconds


def _months_between(earlier: int, later: int) -> int:
    """Whole calendar months from the month of `earlier` to the month of `later`."""
    y1, m1, _ = _civil_from_days(int(earlier) // 86400)
    y2, m2, _ = _civil_from_days(int(later) // 86400)
    return (y2 - y1) * 12 + (m2 - m1)


# --- Terms and progress --------------------------------------------------------


@dataclass(frozen=True)
class StandingTerms:
    """What the payer signed. Immutable: nothing the sweep does changes it."""

    payer_pubkey: str
    recipient_pubkey: str
    amount: int
    sequence_number: int
    kind: int
    interval: int
    first_due: int
    periods: int

    @property
    def standing_id(self) -> bytes:
        return compute_standing_id(
            self.payer_pubkey,
            self.recipient_pubkey,
            self.amount,
            self.sequence_number,
            self.kind,
            self.interval,
            self.first_due,
            self.periods,
        )

    def due(self, period: int) -> int:
        """Due point of `period` (a height for BLOCKS, a UTC timestamp otherwise).

        due(periods) is the end: the window of the last period closes there.
        """
        if self.kind == KIND_MONTHS:
            return add_months(self.first_due, period * self.interval)
        return self.first_due + period * self.interval

    @property
    def end(self) -> int:
        return self.due(self.periods)

    def clock(self, height: int, ts: int) -> int:
        return height if self.kind == KIND_BLOCKS else ts

    def period_at(self, height: int, ts: int) -> int:
        """Index of the period whose window holds this block, capped at `periods`.

        -1 before the first due point; `periods` once the schedule ended.
        """
        now = self.clock(height, ts)
        if now < self.first_due:
            return -1
        if self.kind == KIND_MONTHS:
            p = _months_between(self.first_due, now) // self.interval
            p = max(0, min(p, self.periods))
            while p > 0 and self.due(p) > now:
                p -= 1
            while p < self.periods and self.due(p + 1) <= now:
                p += 1
            return p
        return min((now - self.first_due) // self.interval, self.periods)


@dataclass(frozen=True)
class StandingProgress:
    """What the sweep keeps. Replaced, never mutated, so book copies share it."""

    period: int = 0          # the next period to settle, 0..periods-1
    paid_count: int = 0
    missed_count: int = 0
    tries: int = 0           # unfunded attempts in `period`; 0 = not tried yet
    queued_at: int = 0       # 0 = waiting for due(period); else the queue height
    last_paid_height: int = 0


# --- Parsing ------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise StandingShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str) -> int:
    value = tx.get(name)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise StandingShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def parse_standing_payment_create(tx: Dict[str, Any]) -> StandingTerms:
    """Read an authorization from ROOT fields only; a nested `payload` is unsigned."""
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    payer = _pubkey_field(tx, "sender_pubkey")
    recipient = _pubkey_field(tx, "recipient_pubkey")
    amount = _u64_field(tx, "amount")
    sequence = _u64_field(tx, "sequence_number")
    present = [(name, kind) for name, kind in INTERVAL_FIELDS if tx.get(name) is not None]
    if len(present) != 1:
        raise StandingShapeError(
            "exactly one of interval_blocks, interval_seconds and interval_months is required"
        )
    name, kind = present[0]
    interval = _u64_field(tx, name)
    first_due = _u64_field(tx, "first_due")
    periods = _u64_field(tx, "periods")
    if periods > _U32_MAX:
        raise StandingShapeError("periods must fit 32 bits")
    return StandingTerms(payer, recipient, amount, sequence, kind, interval, first_due, periods)


def _id_field(tx: Dict[str, Any]) -> bytes:
    raw_id = tx.get("standing_id")
    if not isinstance(raw_id, str) or not _ID_RE.match(raw_id):
        raise StandingShapeError("standing_id must be 64 lowercase hex characters")
    return bytes.fromhex(raw_id)


def parse_standing_payment_cancel(tx: Dict[str, Any]) -> Tuple[str, bytes]:
    """(signer, standing id) of a cancel."""
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return _pubkey_field(tx, "sender_pubkey"), _id_field(tx)


def parse_standing_payment_execute(tx: Dict[str, Any]) -> Tuple[str, bytes]:
    """(executor, standing id) of an execute.

    The id is the only thing an executor names: amount, recipient and period
    all come from the stored authorization and the block, never from the tx.
    """
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return _pubkey_field(tx, "sender_pubkey"), _id_field(tx)


def parse_standing_payment_update(tx: Dict[str, Any]) -> Tuple[bytes, StandingTerms]:
    """(id it replaces, new terms) of an update.

    The new terms are read exactly as a create's, from root fields, with the
    update's own sequence number, so the new version gets an id of its own.
    """
    terms = parse_standing_payment_create(tx)
    return _id_field(tx), terms


def validate_create_shape(terms: StandingTerms, height: int, ts: int) -> Optional[str]:
    """Stateless admissibility of an authorization against the target block.

    None when fine. Shared by admission and apply: they must reject the same
    inputs or the chain splits. Anything needing the book is `can_admit_create`.
    """
    if not (1 <= terms.amount <= tau_defs.MAX_TRANSFER_VALUE):
        return f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if terms.recipient_pubkey == terms.payer_pubkey:
        return "recipient must differ from the payer"
    if not (1 <= terms.periods <= MAX_PERIODS):
        return f"periods must be in 1..{MAX_PERIODS}"
    if terms.kind == KIND_BLOCKS:
        lo, hi, now, ahead = MIN_INTERVAL_BLOCKS, MAX_INTERVAL_BLOCKS, height, MAX_FIRST_DUE_BLOCKS
        unit = "blocks"
    elif terms.kind == KIND_SECONDS:
        lo, hi, now, ahead = MIN_INTERVAL_SECONDS, MAX_INTERVAL_SECONDS, ts, MAX_FIRST_DUE_SECONDS
        unit = "seconds"
    elif terms.kind == KIND_MONTHS:
        lo, hi, now, ahead = 1, MAX_INTERVAL_MONTHS, ts, MAX_FIRST_DUE_SECONDS
        unit = "months"
    else:
        return "unknown schedule kind"
    if not (lo <= terms.interval <= hi):
        return f"interval_{unit} must be in {lo}..{hi}"
    if terms.first_due <= now:
        return "first_due must be in the future"
    if terms.first_due > now + ahead:
        return f"first_due is more than {ahead} {'blocks' if unit == 'blocks' else 'seconds'} ahead"
    if terms.kind != KIND_BLOCKS and terms.end > MAX_TIME:
        return "the schedule ends after the year 9999"
    if terms.end > _U64_MAX:
        return "the schedule end does not fit 64 bits"
    return None


# --- The book -----------------------------------------------------------------

# Terms, progress, then lineage (version, id replaced or 32 zero bytes).
_Row = Tuple[bytes, str, str, int, int, int, int, int, int, int, int, int, int, int, int,
             int, bytes]

# attempt(terms) -> ATTEMPT_PAID | ATTEMPT_NO_FUNDS | ATTEMPT_BLOCKED. A paid
# attempt has already moved the money; the book only records the outcome.
Attempt = Callable[[StandingTerms], str]


class StandingBook:
    """waiting -> queued -> (paid | missed | retried) ... -> resolved.

    Terms are frozen and progress is replaced, so copies share both and only the
    containers are duplicated. Composed as a FIELD of ConsensusLifecycleManager
    so the meta hash picks it up without a call site to forget.
    """

    def __init__(self) -> None:
        self.terms: Dict[bytes, StandingTerms] = {}
        self.progress: Dict[bytes, StandingProgress] = {}
        # (due point, id), sorted, for entries waiting for their next period.
        self._waiting: Dict[int, List[Tuple[int, bytes]]] = {_BY_HEIGHT: [], _BY_TIME: []}
        # (queued_at, id), sorted: due entries the sweep has not settled yet.
        self._queue: List[Tuple[int, bytes]] = []
        self._fresh = 0  # queued entries not yet tried in their period
        self._per_payer: Dict[str, int] = {}
        # (version, id replaced) of entries made by an update; absent = FIRST_VERSION.
        self.lineage: Dict[bytes, Tuple[int, bytes]] = {}
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    # -- copying / restoring -------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "StandingBook":
        clone = StandingBook.__new__(StandingBook)
        clone.terms = dict(self.terms)
        clone.progress = dict(self.progress)
        clone._waiting = {k: list(rows) for k, rows in self._waiting.items()}
        clone._queue = list(self._queue)
        clone._fresh = self._fresh
        clone._per_payer = dict(self._per_payer)
        clone.lineage = dict(self.lineage)
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls,
        rows: Iterable[_Row],
        resolved_count: int,
        resolved_acc: bytes,
    ) -> "StandingBook":
        """Rebuild from stored rows; refuses a row whose id does not recompute or
        whose progress could not have come from the sweep."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for row in rows:
            (stored_id, payer, recipient, amount, sequence, kind, interval, first_due,
             periods, period, paid, missed, tries, queued_at, last_paid,
             version, replaces) = row
            if kind not in KIND_NAMES:
                raise ValueError("stored standing payment has an unknown kind")
            if not (_is_int(interval) and interval >= 1 and _is_int(periods)
                    and 1 <= periods <= _U32_MAX):
                raise ValueError("stored standing payment has a bad schedule")
            terms = StandingTerms(payer, recipient, amount, sequence, kind, interval,
                                  first_due, periods)
            sid = terms.standing_id
            if sid != bytes(stored_id):
                raise ValueError(f"stored standing payment id does not match its terms: {sid.hex()}")
            if sid in book.terms:
                raise ValueError(f"duplicate stored standing payment: {sid.hex()}")
            progress = StandingProgress(period, paid, missed, tries, queued_at, last_paid)
            if not all(_is_int(v) and v >= 0 for v in (period, paid, missed, tries,
                                                        queued_at, last_paid)):
                raise ValueError(f"stored standing payment has bad progress: {sid.hex()}")
            if period >= periods or paid + missed != period or (tries and not queued_at):
                raise ValueError(f"stored standing payment has inconsistent progress: {sid.hex()}")
            lineage = (version, bytes(replaces) if isinstance(replaces, (bytes, bytearray))
                       else b"")
            if not (_is_int(version) and 1 <= version <= _U32_MAX and len(lineage[1]) == 32
                    and (version == 1) == (lineage[1] == ZERO_ACC) and lineage[1] != sid):
                raise ValueError(f"stored standing payment has a bad version: {sid.hex()}")
            book._insert(sid, terms, progress, lineage)
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _list_for(terms: StandingTerms) -> int:
        return _BY_HEIGHT if terms.kind == KIND_BLOCKS else _BY_TIME

    def _place(self, sid: bytes) -> None:
        terms, progress = self.terms[sid], self.progress[sid]
        if progress.queued_at:
            bisect.insort(self._queue, (progress.queued_at, sid))
            if progress.tries == 0:
                self._fresh += 1
        else:
            bisect.insort(self._waiting[self._list_for(terms)], (terms.due(progress.period), sid))

    def _unplace(self, sid: bytes) -> None:
        terms, progress = self.terms[sid], self.progress[sid]
        if progress.queued_at:
            rows, key = self._queue, (progress.queued_at, sid)
            if progress.tries == 0:
                self._fresh -= 1
        else:
            rows, key = self._waiting[self._list_for(terms)], (terms.due(progress.period), sid)
        del rows[bisect.bisect_left(rows, key)]

    def _insert(self, sid: bytes, terms: StandingTerms, progress: StandingProgress,
                lineage: Tuple[int, bytes] = FIRST_VERSION) -> None:
        self.terms[sid] = terms
        self.progress[sid] = progress
        if lineage != FIRST_VERSION:
            self.lineage[sid] = lineage
        self._place(sid)
        self._per_payer[terms.payer_pubkey] = self._per_payer.get(terms.payer_pubkey, 0) + 1
        self._root = None

    def _set(self, sid: bytes, progress: StandingProgress) -> None:
        """Replace an entry's progress and re-file it."""
        self._unplace(sid)
        self.progress[sid] = progress
        self._place(sid)
        self._root = None

    def _resolve(self, sid: bytes, outcome: int) -> StandingTerms:
        self._unplace(sid)
        terms = self.terms.pop(sid)
        del self.progress[sid]
        self.lineage.pop(sid, None)
        left = self._per_payer[terms.payer_pubkey] - 1
        if left:
            self._per_payer[terms.payer_pubkey] = left
        else:
            del self._per_payer[terms.payer_pubkey]
        self.resolved_acc = compute_standing_resolved_acc(self.resolved_acc, sid, outcome)
        self.resolved_count += 1
        self._root = None
        return terms

    # -- queries -------------------------------------------------------------

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_standing_book_root(
                [self._row(sid) for sid in self.terms],
                self.resolved_count,
                self.resolved_acc,
            )
        return self._root

    def is_empty(self) -> bool:
        """True while the book has never held anything: it then stays out of the
        meta hash, so a chain that never uses the feature hashes as before."""
        return not self.terms and self.resolved_count == 0

    def _row(self, sid: bytes) -> _Row:
        t, p = self.terms[sid], self.progress[sid]
        version, replaces = self.version_of(sid)
        return (sid, t.payer_pubkey, t.recipient_pubkey, t.amount, t.sequence_number,
                t.kind, t.interval, t.first_due, t.periods, p.period, p.paid_count,
                p.missed_count, p.tries, p.queued_at, p.last_paid_height,
                version, replaces)

    def version_of(self, sid: bytes) -> Tuple[int, bytes]:
        """(version, id it replaced) of an open entry; (1, zeros) for a create."""
        return self.lineage.get(sid, FIRST_VERSION)

    def describe(self, sid: bytes) -> Dict[str, Any]:
        """One open entry as a wallet reads it (see `describe`)."""
        return describe(self.terms[sid], self.progress[sid], sid, self.version_of(sid))

    def get(self, sid: bytes) -> Optional[StandingTerms]:
        return self.terms.get(sid)

    def knows(self, sid: bytes) -> bool:
        return sid in self.terms

    def open_count(self) -> int:
        return len(self.terms)

    def open_count_for_payer(self, payer_pubkey: str) -> int:
        return self._per_payer.get(payer_pubkey, 0)

    def has_due(self, height: int, ts: int) -> bool:
        """True when this block would make a first attempt on some entry.

        Retries do not count: an unfunded payment must not keep an idle chain
        producing empty blocks for the length of its window. It is retried in
        the blocks the chain produces anyway.
        """
        h_rows, t_rows = self._waiting[_BY_HEIGHT], self._waiting[_BY_TIME]
        return bool(
            self._fresh
            or (h_rows and h_rows[0][0] <= height)
            or (t_rows and t_rows[0][0] <= ts)
        )

    def rows(self) -> List[_Row]:
        return [self._row(sid) for sid in sorted(self.terms)]

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        return [self.describe(sid) for sid in sorted(self.terms)]

    def for_account(self, pubkey: str) -> List[Tuple[bytes, StandingTerms, StandingProgress]]:
        """Open entries this account pays or receives, by id."""
        return [
            (sid, t, self.progress[sid]) for sid, t in sorted(self.terms.items())
            if pubkey in (t.payer_pubkey, t.recipient_pubkey)
        ]

    # -- admission -----------------------------------------------------------

    def can_admit_create(self, terms: StandingTerms, height: int, ts: int) -> Tuple[bool, str]:
        reason = validate_create_shape(terms, height, ts)
        if reason:
            return False, reason
        if terms.standing_id in self.terms:
            return False, "standing payment already exists"
        if self.open_count_for_payer(terms.payer_pubkey) >= MAX_OPEN_STANDING_PER_PAYER:
            return False, f"payer already has {MAX_OPEN_STANDING_PER_PAYER} open standing payments"
        if len(self.terms) >= MAX_OPEN_STANDING_TOTAL:
            return False, "standing payment book is full"
        return True, ""

    def can_admit_cancel(self, sid: bytes, signer: str) -> Tuple[bool, str]:
        terms = self.terms.get(sid)
        if terms is None:
            return False, "unknown or already ended standing payment"
        if signer != terms.payer_pubkey:
            return False, "only the payer may cancel"
        return True, ""

    def payable_period(self, sid: bytes, height: int, ts: int) -> Tuple[int, str]:
        """(period an execute in the block at (height, ts) would pay, "") or (-1, why not).

        The period is the one whose window holds the block, and only while it
        is not settled yet: before the first due point, after the end, or a
        second time in a period there is nothing to pay. Who sends the execute
        does not matter here; funds and policy are judged by the caller.
        """
        terms = self.terms.get(sid)
        if terms is None:
            return -1, "unknown or already ended standing payment"
        current = terms.period_at(height, ts)
        if current < 0:
            return -1, f"not due yet: the first period opens at {terms.first_due}"
        if current >= terms.periods:
            return -1, "the schedule has ended"
        progress = self.progress[sid]
        if current < progress.period:
            return -1, (f"period {current} is already settled; period {progress.period} "
                        f"opens at {terms.due(progress.period)}")
        return current, ""

    def can_admit_update(self, sid: bytes, signer: str, terms: StandingTerms,
                         height: int, ts: int) -> Tuple[bool, str]:
        """Same order of checks as admission's: the entry, then the new terms."""
        old = self.terms.get(sid)
        if old is None:
            return False, "unknown or already ended standing payment"
        if signer != old.payer_pubkey or terms.payer_pubkey != signer:
            return False, "only the payer may update"
        reason = validate_create_shape(terms, height, ts)
        if reason:
            return False, reason
        if terms.standing_id in self.terms:
            return False, "standing payment already exists"
        if self.version_of(sid)[0] >= _U32_MAX:
            return False, "no more versions"
        # One entry leaves as the other enters: neither cap can be crossed.
        return True, ""

    # -- mutation ------------------------------------------------------------

    def create(self, terms: StandingTerms) -> bytes:
        sid = terms.standing_id
        if sid in self.terms:
            raise ValueError("standing payment already exists")
        self._insert(sid, terms, StandingProgress())
        return sid

    def cancel(self, sid: bytes) -> StandingTerms:
        if sid not in self.terms:
            raise KeyError(sid.hex())
        return self._resolve(sid, OUTCOME_CANCELLED)

    def execute(self, sid: bytes, height: int, ts: int,
                executor: str) -> List[Dict[str, Any]]:
        """Record a paid execute of the period due now; its events.

        The caller has already moved the money. A period whose window closed
        while the entry waited is missed first, exactly as the sweep would miss
        it, so the counters read the same whichever path paid.
        """
        period, reason = self.payable_period(sid, height, ts)
        if reason:
            raise ValueError(reason)
        terms, progress = self.terms[sid], self.progress[sid]
        events: List[Dict[str, Any]] = []
        skipped = period - progress.period
        if skipped:
            events.append(_event(sid, "missed", progress.period, terms,
                                 reason="window_closed", count=skipped))
        events.append(_event(sid, "paid", period, terms, executor_pubkey=executor))
        self._settle(sid, replace(progress, period=period + 1, tries=0,
                                  paid_count=progress.paid_count + 1,
                                  missed_count=progress.missed_count + skipped,
                                  last_paid_height=height), events)
        return events

    def update(self, sid: bytes, terms: StandingTerms) -> Tuple[bytes, List[Dict[str, Any]]]:
        """Replace `sid` by a new version with `terms`; (new id, events)."""
        if sid not in self.terms:
            raise KeyError(sid.hex())
        new_sid = terms.standing_id
        if new_sid in self.terms:
            raise ValueError("standing payment already exists")
        version = self.version_of(sid)[0] + 1
        old = self._resolve(sid, OUTCOME_REPLACED)
        self._insert(new_sid, terms, StandingProgress(), (version, sid))
        return new_sid, [
            _event(sid, "replaced", 0, old, replaced_by=new_sid.hex()),
            _event(new_sid, "created", 0, terms, version=version, replaces=sid.hex()),
        ]

    def sweep(self, height: int, ts: int, attempt: Attempt,
              cap: int = MAX_STANDING_ACTIONS_PER_BLOCK) -> List[Dict[str, Any]]:
        """Settle due entries for the block at (height, ts); returns its events.

        1. Every waiting entry whose due point this block reached joins the
           queue at this height. The queue is ordered by the height an entry
           joined it, then by id.
        2. At most `cap` queue entries are handled, from the front:
           - window of its period already closed: that period (and any period
             skipped while it waited) is missed; it moves to the period this
             block falls in, or ends;
           - otherwise one attempt: paid or blocked settles the period, an
             unfunded attempt goes to the back of the queue for the next block.
        An entry is handled at most once per block, so one block pays at most
        one period of it.
        """
        events: List[Dict[str, Any]] = []
        for which, cutoff in ((_BY_HEIGHT, height), (_BY_TIME, ts)):
            rows = self._waiting[which]
            end = bisect.bisect_right(rows, (cutoff, _ID_MAX))
            due, rows[:end] = rows[:end], []
            for _, sid in due:
                self.progress[sid] = replace(self.progress[sid], queued_at=height)
                bisect.insort(self._queue, (height, sid))
                self._fresh += self.progress[sid].tries == 0
            if due:
                self._root = None

        actions = 0
        while actions < cap and self._queue and self._queue[0][0] <= height:
            _, sid = self._queue[0]
            actions += 1
            terms, progress = self.terms[sid], self.progress[sid]
            current = terms.period_at(height, ts)
            if current > progress.period:
                skipped = current - progress.period
                events.append(_event(sid, "missed", progress.period, terms,
                                     reason="window_closed", count=skipped))
                progress = replace(progress, period=current, tries=0,
                                   missed_count=progress.missed_count + skipped)
                if current >= terms.periods:
                    self._settle(sid, progress, events)
                    continue
            verdict = attempt(terms)
            if verdict == ATTEMPT_PAID:
                events.append(_event(sid, "paid", progress.period, terms))
                progress = replace(progress, period=progress.period + 1, tries=0,
                                   paid_count=progress.paid_count + 1,
                                   last_paid_height=height)
                self._settle(sid, progress, events)
            elif verdict == ATTEMPT_BLOCKED:
                events.append(_event(sid, "missed", progress.period, terms,
                                     reason="policy_block", count=1))
                progress = replace(progress, period=progress.period + 1, tries=0,
                                   missed_count=progress.missed_count + 1)
                self._settle(sid, progress, events)
            elif verdict == ATTEMPT_NO_FUNDS:
                events.append(_event(sid, "unfunded", progress.period, terms))
                self._set(sid, replace(progress, tries=progress.tries + 1,
                                       queued_at=height + 1))
            else:
                raise ValueError(f"unknown attempt verdict {verdict!r}")
        return events

    def _settle(self, sid: bytes, progress: StandingProgress,
                events: List[Dict[str, Any]]) -> None:
        """File an entry whose period just advanced: wait for it, or end."""
        terms = self.terms[sid]
        if progress.period >= terms.periods:
            self._resolve(sid, OUTCOME_ENDED)
            events.append(_event(sid, "ended", progress.period, terms,
                                 paid=progress.paid_count, missed=progress.missed_count))
            return
        self._set(sid, replace(progress, queued_at=0))


def _event(sid: bytes, outcome: str, period: int, terms: StandingTerms,
           **extra: Any) -> Dict[str, Any]:
    event = {"standing_id": sid.hex(), "outcome": outcome, "period": period,
             "amount": terms.amount if outcome == "paid" else 0}
    event.update(extra)
    return event


def describe(terms: StandingTerms, progress: StandingProgress, sid: bytes,
             lineage: Tuple[int, bytes] = FIRST_VERSION) -> Dict[str, Any]:
    """One entry as a wallet reads it: terms, progress, and the next due point."""
    next_due = terms.due(progress.period)
    version, replaces = lineage
    return {
        "standing_id": sid.hex(),
        "version": version,
        "replaces": replaces.hex() if version > 1 else None,
        "payer_pubkey": terms.payer_pubkey,
        "recipient_pubkey": terms.recipient_pubkey,
        "amount": terms.amount,
        "sequence_number": terms.sequence_number,
        "schedule": KIND_NAMES[terms.kind],
        "interval": terms.interval,
        "first_due": terms.first_due,
        "periods": terms.periods,
        "end": terms.end,
        "period": progress.period,
        "period_due": next_due,
        "period_closes": terms.due(progress.period + 1),
        "status": ("retrying" if progress.tries else "due") if progress.queued_at else "waiting",
        "tries": progress.tries,
        "paid_count": progress.paid_count,
        "missed_count": progress.missed_count,
        "paid_total": progress.paid_count * terms.amount,
        "last_paid_height": progress.last_paid_height or None,
        "queued_at": progress.queued_at or None,
    }
