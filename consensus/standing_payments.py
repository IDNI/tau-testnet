"""Standing payments: a payer-signed authorization the node executes when due (#34).

A payer signs an authorization once — fixed recipient, fixed amount, a
calendar schedule and one explicit execution window per period — and anyone
may then submit an execution; the node is the gate for whether an occurrence
is due. This module is the book: the pure consensus state, its validation,
the due/window evaluation, the execute/cancel state machine, and the
paid-for-period facts. The engine wiring (op-0 installation, the execute and
cancel commands, RPC) lands in a later slice; everything it needs is decided
here, so admission and apply can never disagree about an authorization.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would
make two honest nodes disagree about admissibility, which forks.

- One time source: the block header timestamp (UTC), read through
  consensus/payment_calendar.py. "Monthly" is a calendar month, never 30
  days; a signed day that does not exist in a month clamps to its last day
  and the following month returns to the signed day (no drift).
- REQUIRED end condition (gmikeyg on #34): an authorization must carry a
  final period, an occurrence limit, or a maximum total — open-ended
  authorizations are rejected at creation, by default and without exception.
- At most once per period: settled-period markers are consensus state. An
  execution that cannot be paid in full (insufficient balance) settles
  nothing and advances no marker, so a retry inside the same window is a
  well-defined, explicit operation — never a debt, never a partial payment,
  never a false completion.
- No unbounded catch-up: an execution must land inside a live execution
  window. A period whose window lapses is skipped — unless the signed terms
  explicitly permit catch-up, in which case an execution inside a later live
  window also settles the earlier unsettled periods, oldest first.
- The executor cannot alter the signed terms: execution reads only the
  stored entry. Amount, recipient, cadence, expiry and fee terms are the
  entry's, and the authorization's identity is a hash of exactly those
  fields, so a tampered copy is a different, unknown authorization.
- Update is a new version that supersedes, never an invisible mutation.
  Progress does not carry across versions (the terms may have changed);
  paid-for-period facts are history and are never rewritten.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import tau_defs
from consensus.payment_calendar import (
    SECONDS_PER_DAY,
    SECONDS_PER_WEEK,
    clamped_day,
    month_index_containing,
    monthly_due_ts,
)
from consensus.serialization import (
    compute_standing_payment_book_root,
    compute_standing_payment_id,
)

TX_TYPE_CREATE_STANDING_PAYMENT = "create_standing_payment"
TX_TYPE_CANCEL_STANDING_PAYMENT = "cancel_standing_payment"
TX_TYPE_EXECUTE_STANDING_PAYMENT = "execute_standing_payment"

STANDING_PAYMENT_TX_TYPES = frozenset(
    {
        TX_TYPE_CREATE_STANDING_PAYMENT,
        TX_TYPE_CANCEL_STANDING_PAYMENT,
        TX_TYPE_EXECUTE_STANDING_PAYMENT,
    }
)

SCHEDULE_DAILY = 1
SCHEDULE_WEEKLY = 2
SCHEDULE_MONTHLY = 3

SCHEDULE_KINDS = frozenset({SCHEDULE_DAILY, SCHEDULE_WEEKLY, SCHEDULE_MONTHLY})
SCHEDULE_NAME_TO_KIND = {
    "daily": SCHEDULE_DAILY,
    "weekly": SCHEDULE_WEEKLY,
    "monthly": SCHEDULE_MONTHLY,
}
_FIXED_PERIOD_SECONDS = {
    SCHEDULE_DAILY: SECONDS_PER_DAY,
    SCHEDULE_WEEKLY: SECONDS_PER_WEEK,
}

# One signed execution window per period. A window may never reach a second
# period's due date, so the caps are the shortest possible period lengths.
MAX_WINDOW_SECONDS = {
    SCHEDULE_DAILY: SECONDS_PER_DAY,
    SCHEDULE_WEEKLY: SECONDS_PER_WEEK,
    SCHEDULE_MONTHLY: 28 * SECONDS_PER_DAY,
}

STATUS_ACTIVE = "active"
STATUS_CANCELLED = "cancelled"
STATUS_ENDED = "ended"

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_AUTH_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class StandingPaymentShapeError(ValueError):
    """A standing-payment transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class StandingPaymentEntry:
    """The signed terms of one authorization version. Nothing here mutates."""

    payer_pubkey: str
    recipient_pubkey: str
    amount: int
    schedule_kind: int
    signed_day: int
    anchor_ts: int
    window_seconds: int
    final_ts: int
    max_occurrences: int
    max_total: int
    fee_limit: int
    policy_version_ref: int
    allow_catch_up: bool
    version: int

    @property
    def auth_id(self) -> bytes:
        return compute_standing_payment_id(
            self.payer_pubkey,
            self.recipient_pubkey,
            self.amount,
            self.schedule_kind,
            self.signed_day,
            self.anchor_ts,
            self.window_seconds,
            self.final_ts,
            self.max_occurrences,
            self.max_total,
            self.fee_limit,
            self.policy_version_ref,
            int(self.allow_catch_up),
            self.version,
        )

    @property
    def series_key(self) -> Tuple[str, str, int, int]:
        """What makes two versions versions of the same authorization."""
        return (
            self.payer_pubkey,
            self.recipient_pubkey,
            self.schedule_kind,
            self.anchor_ts,
        )


@dataclass(frozen=True)
class PaidForPeriodFact:
    """The readable "paid for this period" fact (gmikeyg on #34).

    Written by every settled period, keyed by authorization and period, so
    other rules — membership, keep-alive, heartbeat — can read whether a
    period was paid without replaying history. Facts are history: they
    survive cancellation and supersession.
    """

    auth_id: bytes
    payer_pubkey: str
    period_index: int
    period_start_ts: int
    period_end_ts: int
    amount: int
    execution_ts: int


@dataclass(frozen=True)
class ExecutionDecision:
    """The outcome of presenting one execution to the book.

    `executed` False means nothing moved: no marker advanced, no fact was
    written, totals are unchanged. `reason` names why, for receipts and
    tests. On success `amount` is the total moved (more than one period's
    amount only under signed catch-up) and `period_index` is the current
    period the execution landed in.
    """

    executed: bool
    reason: str
    period_index: int
    amount: int
    periods_collected: int
    total_paid_after: int


@dataclass
class _Progress:
    """Live progress of one authorization version. Book-internal."""

    settled_periods: Set[int] = field(default_factory=set)
    total_paid: int = 0
    last_execution_ts: int = 0
    cancelled: bool = False
    cancelled_ts: int = 0

    def copy(self) -> "_Progress":
        return _Progress(
            settled_periods=set(self.settled_periods),
            total_paid=self.total_paid,
            last_execution_ts=self.last_execution_ts,
            cancelled=self.cancelled,
            cancelled_ts=self.cancelled_ts,
        )


# --- Schedule arithmetic -------------------------------------------------------


def due_ts(entry: StandingPaymentEntry, period_index: int) -> int:
    """When period `period_index` (0-based from the anchor) falls due."""
    if period_index < 0:
        raise ValueError("period_index must be >= 0")
    if entry.schedule_kind == SCHEDULE_MONTHLY:
        return monthly_due_ts(entry.anchor_ts, entry.signed_day, period_index)
    return entry.anchor_ts + period_index * _FIXED_PERIOD_SECONDS[entry.schedule_kind]


def period_bounds(entry: StandingPaymentEntry, period_index: int) -> Tuple[int, int]:
    """[start, end) of a period: its due date up to the next due date."""
    return due_ts(entry, period_index), due_ts(entry, period_index + 1)


def period_index_at(entry: StandingPaymentEntry, ts: int) -> int:
    """Which period contains `ts`; -1 before the first due date."""
    if entry.schedule_kind == SCHEDULE_MONTHLY:
        return month_index_containing(entry.anchor_ts, entry.signed_day, ts)
    if ts < entry.anchor_ts:
        return -1
    return (ts - entry.anchor_ts) // _FIXED_PERIOD_SECONDS[entry.schedule_kind]


# --- Parsing -------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise StandingPaymentShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str, default: int = 0) -> int:
    value = tx.get(name, default)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise StandingPaymentShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _auth_id_field(tx: Dict[str, Any]) -> bytes:
    value = tx.get("standing_auth_id")
    if not isinstance(value, str) or not _AUTH_ID_RE.match(value):
        raise StandingPaymentShapeError(
            "standing_auth_id must be 64 lowercase hex characters"
        )
    return bytes.fromhex(value)


def parse_create_standing_payment(tx: Dict[str, Any]) -> StandingPaymentEntry:
    """Read a creation from ROOT fields only; a nested `payload` is unsigned data."""
    if not isinstance(tx, dict):
        raise StandingPaymentShapeError("transaction must be an object")
    schedule_name = tx.get("standing_schedule")
    if schedule_name not in SCHEDULE_NAME_TO_KIND:
        raise StandingPaymentShapeError(
            "standing_schedule must be one of: daily, weekly, monthly"
        )
    catch_up = _u64_field(tx, "standing_allow_catch_up")
    if catch_up not in (0, 1):
        raise StandingPaymentShapeError("standing_allow_catch_up must be 0 or 1")
    return StandingPaymentEntry(
        payer_pubkey=_pubkey_field(tx, "sender_pubkey"),
        recipient_pubkey=_pubkey_field(tx, "standing_recipient_pubkey"),
        amount=_u64_field(tx, "standing_amount"),
        schedule_kind=SCHEDULE_NAME_TO_KIND[schedule_name],
        signed_day=_u64_field(tx, "standing_signed_day"),
        anchor_ts=_u64_field(tx, "standing_anchor_ts"),
        window_seconds=_u64_field(tx, "standing_window_seconds"),
        final_ts=_u64_field(tx, "standing_final_ts"),
        max_occurrences=_u64_field(tx, "standing_max_occurrences"),
        max_total=_u64_field(tx, "standing_max_total"),
        fee_limit=_u64_field(tx, "standing_fee_limit"),
        policy_version_ref=_u64_field(tx, "standing_policy_version_ref"),
        allow_catch_up=bool(catch_up),
        version=_u64_field(tx, "standing_version", default=1),
    )


def parse_cancel_standing_payment(tx: Dict[str, Any]) -> bytes:
    """Read a cancellation's authorization id from ROOT fields only."""
    if not isinstance(tx, dict):
        raise StandingPaymentShapeError("transaction must be an object")
    return _auth_id_field(tx)


def parse_execute_standing_payment(tx: Dict[str, Any]) -> bytes:
    """Read an execution's authorization id from ROOT fields only."""
    if not isinstance(tx, dict):
        raise StandingPaymentShapeError("transaction must be an object")
    return _auth_id_field(tx)


def validate_standing_payment_shape(
    entry: StandingPaymentEntry, now_ts: int
) -> Optional[str]:
    """Stateless admissibility of an authorization. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything needing the book lives in `can_create`.
    """
    if entry.recipient_pubkey == entry.payer_pubkey:
        return "standing payment recipient must differ from the payer"
    if not 1 <= entry.amount <= tau_defs.MAX_TRANSFER_VALUE:
        return "standing_amount must be in 1..MAX_TRANSFER_VALUE"
    if entry.schedule_kind not in SCHEDULE_KINDS:
        return "unknown schedule kind"
    if entry.schedule_kind == SCHEDULE_MONTHLY:
        if not 1 <= entry.signed_day <= 31:
            return "standing_signed_day must be in 1..31 for a monthly schedule"
        anchor = datetime.fromtimestamp(entry.anchor_ts, tz=timezone.utc)
        if anchor.day != clamped_day(anchor.year, anchor.month, entry.signed_day):
            return (
                "the anchor must be the first due date: its day-of-month must "
                "be the signed day clamped into the anchor month"
            )
    elif entry.signed_day != 0:
        return "standing_signed_day applies only to a monthly schedule"
    if not 1 <= entry.window_seconds <= MAX_WINDOW_SECONDS[entry.schedule_kind]:
        return (
            "standing_window_seconds must be in "
            f"1..{MAX_WINDOW_SECONDS[entry.schedule_kind]} for this schedule"
        )
    # gmikeyg on #34: no open-ended authorizations — a required end
    # condition, the same reasoning as the #57 expiry.
    if not (entry.final_ts or entry.max_occurrences or entry.max_total):
        return (
            "a standing payment must carry an end condition: a final period, "
            "an occurrence limit, or a maximum total"
        )
    if entry.final_ts and entry.final_ts <= entry.anchor_ts:
        return "standing_final_ts must be after the first due date"
    if entry.max_total and entry.max_total < entry.amount:
        return "standing_max_total must cover at least one payment"
    if entry.fee_limit > tau_defs.MAX_TRANSFER_VALUE:
        return "standing_fee_limit exceeds the maximum transfer value"
    if entry.version < 1:
        return "standing_version must start at 1"
    return None


# --- The book ------------------------------------------------------------------

_EntryRow = Tuple[
    bytes, str, str, int, int, int, int, int, int, int, int, int, int, int, int,
    Tuple[int, ...], int, int, int, int,
]
_FactRow = Tuple[bytes, str, int, int, int, int, int]


class StandingPaymentBook:
    """Standing-payment authorizations, their progress, and their facts.

    Composed as a field of ConsensusLifecycleManager in the wiring slice, so
    the meta hash picks the book root up without a call site to forget (the
    RetractableBook pattern). Entries and facts are frozen, so copies share
    them; only the progress records are duplicated.
    """

    def __init__(self) -> None:
        self._entries: Dict[bytes, StandingPaymentEntry] = {}
        self._series: Dict[Tuple[str, str, int, int], bytes] = {}
        self._progress: Dict[bytes, _Progress] = {}
        self._facts: Dict[Tuple[bytes, int], PaidForPeriodFact] = {}
        self._root: Optional[bytes] = None

    # -- copying / restoring ---------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "StandingPaymentBook":
        clone = StandingPaymentBook.__new__(StandingPaymentBook)
        clone._entries = dict(self._entries)
        clone._series = dict(self._series)
        clone._progress = {k: v.copy() for k, v in self._progress.items()}
        clone._facts = dict(self._facts)
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls, rows: Iterable[_EntryRow], facts: Iterable[_FactRow] = ()
    ) -> "StandingPaymentBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute."""
        book = cls()
        for row in rows:
            (auth_id, payer, recipient, amount, kind, day, anchor, window,
             final_ts, max_occ, max_total, fee_limit, policy_ref, catch_up,
             version, settled, total_paid, last_exec, cancelled, cancelled_ts) = row
            entry = StandingPaymentEntry(
                payer, recipient, amount, kind, day, anchor, window, final_ts,
                max_occ, max_total, fee_limit, policy_ref, bool(catch_up), version,
            )
            if entry.auth_id != bytes(auth_id):
                raise ValueError(
                    f"stored authorization id does not match its fields: {entry.auth_id.hex()}"
                )
            if entry.auth_id in book._entries:
                raise ValueError(f"duplicate stored authorization: {entry.auth_id.hex()}")
            if entry.series_key in book._series:
                raise ValueError("duplicate stored authorization series")
            if total_paid != amount * len(settled):
                raise ValueError("stored total_paid disagrees with the settled markers")
            book._entries[entry.auth_id] = entry
            book._series[entry.series_key] = entry.auth_id
            book._progress[entry.auth_id] = _Progress(
                settled_periods=set(settled),
                total_paid=total_paid,
                last_execution_ts=last_exec,
                cancelled=bool(cancelled),
                cancelled_ts=cancelled_ts,
            )
        for auth_id, payer, period, start, end, amount, exec_ts in facts:
            fact = PaidForPeriodFact(
                bytes(auth_id), payer, period, start, end, amount, exec_ts
            )
            if (fact.auth_id, period) in book._facts:
                raise ValueError("duplicate stored paid-period fact")
            book._facts[(fact.auth_id, period)] = fact
        return book

    def rows(self) -> List[_EntryRow]:
        out: List[_EntryRow] = []
        for auth_id, entry in self._entries.items():
            progress = self._progress[auth_id]
            out.append(
                (
                    auth_id,
                    entry.payer_pubkey,
                    entry.recipient_pubkey,
                    entry.amount,
                    entry.schedule_kind,
                    entry.signed_day,
                    entry.anchor_ts,
                    entry.window_seconds,
                    entry.final_ts,
                    entry.max_occurrences,
                    entry.max_total,
                    entry.fee_limit,
                    entry.policy_version_ref,
                    int(entry.allow_catch_up),
                    entry.version,
                    tuple(sorted(progress.settled_periods)),
                    progress.total_paid,
                    progress.last_execution_ts,
                    int(progress.cancelled),
                    progress.cancelled_ts,
                )
            )
        return out

    def fact_rows(self) -> List[_FactRow]:
        return [
            (
                f.auth_id,
                f.payer_pubkey,
                f.period_index,
                f.period_start_ts,
                f.period_end_ts,
                f.amount,
                f.execution_ts,
            )
            for f in self._facts.values()
        ]

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_standing_payment_book_root(self.rows(), self.fact_rows())
        return self._root

    # -- queries -----------------------------------------------------------------

    def get(self, auth_id: bytes) -> Optional[StandingPaymentEntry]:
        return self._entries.get(bytes(auth_id))

    def authorization_count(self) -> int:
        return len(self._entries)

    def is_empty(self) -> bool:
        """True while no authorization and no paid-period fact exists.

        Facts are rooted with the entries and outlive their authorization
        versions, so a book that has ever settled is never empty again —
        that is what the meta-hash gate in governance keys off.
        """
        return not self._entries and not self._facts

    def _entry_and_progress(
        self, auth_id: bytes
    ) -> Tuple[StandingPaymentEntry, _Progress]:
        auth_id = bytes(auth_id)
        entry = self._entries.get(auth_id)
        if entry is None:
            raise ValueError(f"no standing payment with id {auth_id.hex()}")
        return entry, self._progress[auth_id]

    def paid_for_period(
        self, auth_id: bytes, period_index: int
    ) -> Optional[PaidForPeriodFact]:
        """The "paid for this period" fact, or None when the period is unpaid."""
        return self._facts.get((bytes(auth_id), period_index))

    def facts_for(self, auth_id: bytes) -> List[PaidForPeriodFact]:
        auth_id = bytes(auth_id)
        return sorted(
            (f for (aid, _), f in self._facts.items() if aid == auth_id),
            key=lambda f: f.period_index,
        )

    def has_paid_period_containing(self, payer_pubkey: str, ts: int) -> bool:
        """The rule-readable projection of the paid-for-period facts (#34).

        True when at least one of `payer_pubkey`'s authorizations has the
        period containing `ts` recorded paid. This is the value the node
        feeds on tau_defs.STANDING_PAID_STREAM_INDEX (i17) for a transfer
        from that account: per account, across ALL its authorizations —
        a membership rule asks "is my current period paid?", not about
        one named authorization. The recorded fact bounds are the
        payment-calendar period bounds written at settlement
        (period_bounds in execute()), so the period containing `ts` is
        the fact whose [period_start_ts, period_end_ts) contains it.
        Facts are history (they survive cancellation and supersession),
        so a period paid under a since-replaced authorization version
        still counts for that period.
        """
        payer = str(payer_pubkey).lower()
        return any(
            fact.payer_pubkey.lower() == payer
            and fact.period_start_ts <= ts < fact.period_end_ts
            for fact in self._facts.values()
        )

    def total_executed(self, auth_id: bytes) -> Tuple[int, int]:
        """(settled occurrence count, cumulative total paid) for RPC/history."""
        _, progress = self._entry_and_progress(auth_id)
        return len(progress.settled_periods), progress.total_paid

    def status(self, auth_id: bytes, ts: int) -> str:
        entry, progress = self._entry_and_progress(auth_id)
        if progress.cancelled:
            return STATUS_CANCELLED
        if self._capacity(entry, progress) == 0:
            return STATUS_ENDED
        if entry.final_ts and ts >= entry.final_ts:
            return STATUS_ENDED
        return STATUS_ACTIVE

    def next_due_ts(self, auth_id: bytes, ts: int) -> Optional[int]:
        """The next timestamp at which an execution can settle a period.

        None when the authorization is cancelled or its end condition leaves
        nothing to pay. A period whose window has lapsed is skipped (it can
        still be collected by a catch-up execution inside a later window,
        whose due date is what this returns).
        """
        entry, progress = self._entry_and_progress(auth_id)
        if progress.cancelled or self._capacity(entry, progress) == 0:
            return None
        period = 0
        while True:
            due = due_ts(entry, period)
            if entry.final_ts and due >= entry.final_ts:
                return None
            if period not in progress.settled_periods and ts < due + entry.window_seconds:
                return due
            period += 1

    # -- creation / update ---------------------------------------------------------

    def can_create(
        self, entry: StandingPaymentEntry, now_ts: int
    ) -> Tuple[bool, str]:
        problem = validate_standing_payment_shape(entry, now_ts)
        if problem is not None:
            return False, problem
        if entry.auth_id in self._entries:
            return False, "this authorization already exists"
        current_id = self._series.get(entry.series_key)
        if current_id is not None:
            current = self._entries[current_id]
            if entry.version != current.version + 1:
                return (
                    False,
                    "an update must be the next version "
                    f"({current.version + 1}), got {entry.version}",
                )
        elif entry.version != 1:
            return False, "a first authorization must be version 1"
        return True, ""

    def create(self, entry: StandingPaymentEntry, now_ts: int) -> bytes:
        """Install an authorization; a new version supersedes the old one.

        Supersession is wholesale: the old version can no longer execute and
        its progress is discarded with it (its terms may have changed), but
        its paid-for-period facts stay readable — history is not rewritten.
        """
        ok, reason = self.can_create(entry, now_ts)
        if not ok:
            raise ValueError(reason)
        old_id = self._series.get(entry.series_key)
        if old_id is not None:
            del self._entries[old_id]
            del self._progress[old_id]
        self._entries[entry.auth_id] = entry
        self._series[entry.series_key] = entry.auth_id
        self._progress[entry.auth_id] = _Progress()
        self._root = None
        return entry.auth_id

    # -- cancellation ----------------------------------------------------------------

    def can_cancel(self, auth_id: bytes, now_ts: int) -> Tuple[bool, str]:
        auth_id = bytes(auth_id)
        if auth_id not in self._entries:
            return False, "no standing payment with this id"
        if self._progress[auth_id].cancelled:
            return False, "authorization is already cancelled"
        return True, ""

    def cancel(self, auth_id: bytes, now_ts: int) -> StandingPaymentEntry:
        """Cancel: prevents every later execution, immediately and for good.

        The authorization stays in the book (status `cancelled`) so the
        cancellation itself is part of consensus state, visible to admission
        from the latest committed state.
        """
        ok, reason = self.can_cancel(auth_id, now_ts)
        if not ok:
            raise ValueError(reason)
        auth_id = bytes(auth_id)
        progress = self._progress[auth_id]
        progress.cancelled = True
        progress.cancelled_ts = now_ts
        self._root = None
        return self._entries[auth_id]

    # -- execution -------------------------------------------------------------------

    @staticmethod
    def _capacity(entry: StandingPaymentEntry, progress: _Progress) -> int:
        """How many more occurrences the end conditions still allow."""
        capacity: Optional[int] = None
        if entry.max_occurrences:
            capacity = entry.max_occurrences - len(progress.settled_periods)
        if entry.max_total:
            by_total = (entry.max_total - progress.total_paid) // entry.amount
            capacity = by_total if capacity is None else min(capacity, by_total)
        return capacity if capacity is not None else 1 << 62

    def _evaluate(
        self,
        entry: StandingPaymentEntry,
        progress: _Progress,
        ts: int,
        payer_balance: int,
    ) -> Tuple[ExecutionDecision, List[int]]:
        """Pure evaluation: the decision, plus the periods it would settle."""

        def refuse(reason: str, period_index: int = -1) -> Tuple[ExecutionDecision, List[int]]:
            return (
                ExecutionDecision(
                    False, reason, period_index, 0, 0, progress.total_paid
                ),
                [],
            )

        if progress.cancelled:
            return refuse("authorization is cancelled")
        if entry.final_ts and ts >= entry.final_ts:
            return refuse("authorization has ended: the final period has passed")
        current = period_index_at(entry, ts)
        if current < 0:
            return refuse("nothing is due yet")
        if entry.final_ts and due_ts(entry, current) >= entry.final_ts:
            return refuse("authorization has ended: the final period has passed")
        if ts >= due_ts(entry, current) + entry.window_seconds:
            return refuse("the execution window for this period has lapsed", current)
        if current in progress.settled_periods and not entry.allow_catch_up:
            return refuse("this period is already settled", current)
        if entry.allow_catch_up:
            to_settle = [
                j
                for j in range(current + 1)
                if j not in progress.settled_periods
                and not (entry.final_ts and due_ts(entry, j) >= entry.final_ts)
            ]
        else:
            to_settle = [current]
        if not to_settle:
            return refuse("this period is already settled", current)
        capacity = self._capacity(entry, progress)
        if capacity == 0:
            return refuse("the authorization's end condition is reached", current)
        to_settle = to_settle[:capacity]
        affordable = payer_balance // entry.amount
        if affordable == 0:
            return refuse(
                "insufficient funds: the occurrence is not settled and its "
                "marker does not advance",
                current,
            )
        if affordable < len(to_settle):
            if not entry.allow_catch_up:
                return refuse(
                    "insufficient funds: the occurrence is not settled and "
                    "its marker does not advance",
                    current,
                )
            to_settle = to_settle[:affordable]
        amount = entry.amount * len(to_settle)
        return (
            ExecutionDecision(
                True,
                "executed",
                current,
                amount,
                len(to_settle),
                progress.total_paid + amount,
            ),
            to_settle,
        )

    def execution_due(
        self,
        auth_id: bytes,
        ts: int,
        payer_balance: int,
        executor_pubkey: Optional[str] = None,
    ) -> ExecutionDecision:
        """What an execution at `ts` would do, without doing it."""
        entry, progress = self._entry_and_progress(auth_id)
        self._check_executor(executor_pubkey)
        decision, _ = self._evaluate(entry, progress, ts, payer_balance)
        return decision

    @staticmethod
    def _check_executor(executor_pubkey: Optional[str]) -> None:
        if executor_pubkey is not None and not _PUBKEY_RE.match(executor_pubkey):
            raise StandingPaymentShapeError(
                "executor_pubkey must be 96 lowercase hex characters"
            )

    def execute(
        self,
        auth_id: bytes,
        ts: int,
        payer_balance: int,
        executor_pubkey: Optional[str] = None,
    ) -> ExecutionDecision:
        """Settle what is due at `ts`, or settle nothing.

        Any party may submit an execution: `executor_pubkey` names the
        submitter for receipts, but the outcome depends only on the stored
        entry, the progress, the timestamp and the payer's balance — never
        on who submits, and the submitter cannot steer amount, recipient,
        cadence, expiry or fee terms, which are the entry's alone. A refused
        execution changes no state: no marker advances, no fact is written,
        totals do not move.
        """
        entry, progress = self._entry_and_progress(auth_id)
        self._check_executor(executor_pubkey)
        decision, to_settle = self._evaluate(entry, progress, ts, payer_balance)
        if not decision.executed:
            return decision
        for period in to_settle:
            start, end = period_bounds(entry, period)
            progress.settled_periods.add(period)
            self._facts[(entry.auth_id, period)] = PaidForPeriodFact(
                auth_id=entry.auth_id,
                payer_pubkey=entry.payer_pubkey,
                period_index=period,
                period_start_ts=start,
                period_end_ts=end,
                amount=entry.amount,
                execution_ts=ts,
            )
        progress.total_paid += decision.amount
        progress.last_execution_ts = ts
        self._root = None
        return decision


# --- Capability reporting -------------------------------------------------------


def standing_payment_capabilities() -> Dict[str, Any]:
    """The standing-payment semantics a capability endpoint reports (#34 case 9).

    Built from the module's own values so the report can never drift from
    the code: if a bound changes, this record changes with it. (Support and
    schedule semantics, stated before send — the consensus-level record an
    endpoint serves, there being no capability-endpoint infrastructure in
    the codebase yet.)
    """
    return {
        "supported": True,
        "schedules": sorted(SCHEDULE_NAME_TO_KIND),
        "max_window_seconds": {
            name: MAX_WINDOW_SECONDS[kind]
            for name, kind in sorted(SCHEDULE_NAME_TO_KIND.items())
        },
        "end_condition": (
            "required: a final period, an occurrence limit, or a maximum total"
        ),
        "execution": "any party may trigger; the signed terms cannot be altered",
        "catch_up": "only when the signed terms permit it",
        "fee": (
            "the submitter pays the ordinary fee; payer funding only under "
            "the authorization's signed fee_limit"
        ),
        "paid_for_period_fact": True,
        "paid_fact_rule_stream": {
            "stream": tau_defs.TAU_INPUT_STREAM_STANDING_PAID,
            "meaning": (
                "fed on every transfer evaluation: 1 when the sender has "
                "at least one standing authorization whose period "
                "containing the block timestamp is recorded paid, else 0; "
                "per account, across all of the sender's authorizations"
            ),
            "read_by": "any Tau rule, e.g. a membership o5 clause",
        },
    }
