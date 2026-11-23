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
- TWO FORMS (FIX 2, the stage-1 clause form): an authorization is either
  the DECLARED form above — fixed recipient, fixed amount — or the TAU
  CLAUSE form: the payer's own Tau clause, stepped by the node through
  the existing policy-evaluation path (sender_policy.clause_outputs)
  over a node-built input map (standing_clause_inputs), names the legs
  of a due execution under the stage's shared output encoding (o30 leg
  count, o31.. candidate/amount pairs). The clause decides; the book
  re-checks every leg against the candidate set (the signed recipient),
  the per-execution cap (the signed amount times the periods being
  settled), the per-period cap (the signed amount, by attribution), the
  max_total end condition and the payer's balance — and settles
  atomically or not at all. The calendar, window, at-most-once and
  catch-up machinery is the book's and is identical for both forms:
  the clause never decides WHEN a period is due, only what a due
  execution pays. The form is a signed field, inside the authorization
  id (a domain-separated id for the clause form), so the form an
  execution runs under is the form the payer signed.
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
    compute_standing_payment_tau_id,
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

# The two forms an authorization can take. The form is a signed field of
# the authorization: it is inside the creation signature and the
# authorization id, so the form an execution runs under is the form the
# payer signed.
FORM_DECLARED = 1
FORM_TAU_CLAUSE = 2
STANDING_FORMS = frozenset({FORM_DECLARED, FORM_TAU_CLAUSE})

# The Tau form's clause text bound, in UTF-8 bytes — the same bound the
# payout-rule form puts on its clause (consensus/payout_rules
# MAX_PAYOUT_CLAUSE_BYTES), so a stage-1 clause is no larger than a
# clause the node already carries.
MAX_STANDING_CLAUSE_BYTES = 8192

# The Tau form's output encoding — the stage's shared encoding, the same
# one the payout-rule form pins: o30 carries the leg count, then each
# leg is a (recipient candidate index, amount) pair on consecutive
# streams.
STANDING_OUTPUT_COUNT_STREAM = 30
STANDING_OUTPUT_FIRST_STREAM = 31

# A clause names at most this many legs in one execution (the payout
# form's MAX_LEGS bound, shared across the stage).
MAX_CLAUSE_LEGS = 32

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_AUTH_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class StandingPaymentShapeError(ValueError):
    """A standing-payment transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class StandingPaymentEntry:
    """The signed terms of one authorization version. Nothing here mutates.

    `form` and `clause_text` default to the declared form, so every
    entry constructed before the Tau form existed — and every
    declared-form entry constructed now — is byte-identical to what
    it was. For the declared form, `amount` is the fixed per-period
    payment; for the Tau form it is the signed per-period CAP: the
    clause names what a due execution pays, never more than `amount`
    per settled period.
    """

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
    form: int = FORM_DECLARED
    clause_text: str = ""

    @property
    def auth_id(self) -> bytes:
        if self.form == FORM_TAU_CLAUSE:
            return compute_standing_payment_tau_id(
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
                self.clause_text,
                self.version,
            )
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
    def candidates(self) -> Tuple[str, ...]:
        """The recipient candidate set a clause's legs index into.

        A standing authorization has exactly one signed recipient, so
        the set has one member: candidate 0 is the recipient, and any
        other index names something the payer never signed.
        """
        return (self.recipient_pubkey,)

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
    legs: Tuple[Tuple[str, int], ...] = ()
    period_amounts: Tuple[Tuple[int, int], ...] = ()


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


# --- The Tau form: input map and output decoding ------------------------------

_OUTPUT_VALUE_RE = re.compile(
    r"^\{?\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}?(?::bv\[\d+\])?$"
)


def _parse_output_value(value: Any) -> Optional[int]:
    """One clause output as an integer, or None when it is not one.

    The worker reports outputs as Tau value strings; this reads them
    with the same grammar tau_policy.parse_o5 reads o5 with (hex /
    binary / decimal, optional braces and :bv[N] annotation) — the
    payout form's identical reader, kept per book as this codebase
    keeps its small helpers.
    """
    if value is None:
        return None
    match = _OUTPUT_VALUE_RE.match(str(value).strip())
    if not match:
        return None
    hex_digits, bin_digits, dec_digits = match.groups()
    if hex_digits is not None:
        return int(hex_digits, 16)
    if bin_digits is not None:
        return int(bin_digits, 2)
    return int(dec_digits)


def standing_clause_inputs(
    entry: StandingPaymentEntry,
    executor_pubkey: str,
    ts: int,
    payer_balance: int,
    period_paid_total: int,
) -> Dict[int, Any]:
    """The input map a Tau-form execution steps the payer's clause over.

    ONE definition, called by the engine at apply and by admission at
    the tip with their own site values — the construction cannot drift
    between them. The value formats mirror the transfer input map
    (consensus/engine._transfer_input_map) exactly: amounts and the
    timestamp as decimal strings, accounts as `{ #x.. }:bv[384]`
    literals. The map is the payout form's map (i1..i5/i26) with the
    standing meanings:

    - i1: the signed per-period amount — for the clause form, the
      per-period cap its legs are checked against
    - i2: the payer's balance
    - i3: the payer's pubkey
    - i4: the execution submitter's pubkey (anyone may execute)
    - i5: the block timestamp
    - i26 (tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX): what this
      authorization has already paid for the period containing `ts`,
      from the book's recorded paid-for-period facts — the
      release-schedule input a prorating clause computes from

    Nothing in the map comes from the execution transaction: the map
    is node-built, so no submitter can steer the clause by writing a
    stream.
    """
    return {
        1: str(int(entry.amount)),
        2: str(int(payer_balance)),
        3: "{ #x" + str(entry.payer_pubkey) + " }:bv[384]",
        4: "{ #x" + str(executor_pubkey) + " }:bv[384]",
        5: str(int(ts)),
        tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX: str(int(period_paid_total)),
    }


def decode_clause_legs(
    entry: StandingPaymentEntry, outputs: Dict[str, Any]
) -> Tuple[Optional[Tuple[Tuple[str, int], ...]], str]:
    """The legs a stepped clause named, or (None, why not).

    The encoding (pinned in standing_payment_capabilities): o30 is the
    leg count; leg k reads its recipient candidate index — 0-based
    into the entry's candidate set — from o(31+2k) and its amount from
    o(32+2k). Zero-amount legs are dropped, as the payout form drops
    them. A count above the bound, a missing or unreadable value, or
    an index outside the candidate set means the clause named
    something the node cannot settle: no legs, and the execution
    settles nothing.
    """
    count = _parse_output_value(outputs.get(f"o{STANDING_OUTPUT_COUNT_STREAM}"))
    if count is None:
        return None, "the authorization's clause did not report a leg count"
    if count < 0 or count > MAX_CLAUSE_LEGS:
        return None, f"the authorization's clause reported {count} legs"
    legs: List[Tuple[str, int]] = []
    for k in range(count):
        index = _parse_output_value(
            outputs.get(f"o{STANDING_OUTPUT_FIRST_STREAM + 2 * k}")
        )
        amount = _parse_output_value(
            outputs.get(f"o{STANDING_OUTPUT_FIRST_STREAM + 2 * k + 1}")
        )
        if index is None or amount is None:
            return None, "the authorization's clause reported an unreadable leg"
        if not 0 <= index < len(entry.candidates):
            return None, (
                "the authorization's clause named recipient candidate "
                f"{index}, outside the declared set"
            )
        if amount > 0:
            legs.append((entry.candidates[index], amount))
    return tuple(legs), ""


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


def _form_field(tx: Dict[str, Any]) -> int:
    value = tx.get("standing_form", FORM_DECLARED)
    if not _is_int(value) or value not in STANDING_FORMS:
        raise StandingPaymentShapeError(
            "standing_form must be 1 (declared) or 2 (Tau clause)"
        )
    return int(value)


def _clause_field(tx: Dict[str, Any]) -> str:
    value = tx.get("standing_clause", "")
    if not isinstance(value, str):
        raise StandingPaymentShapeError("standing_clause must be a string")
    return value


def parse_create_standing_payment(tx: Dict[str, Any]) -> StandingPaymentEntry:
    """Read a creation from ROOT fields only; a nested `payload` is unsigned data.

    The form selects which fields carry the payment decision, and the
    two forms' fields are mutually exclusive (the payout form's parse
    discipline): the Tau form reads `standing_clause` and the declared
    form refuses one. A transaction that mixes them is malformed, not
    ambiguous.
    """
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
    form = _form_field(tx)
    clause_text = _clause_field(tx)
    if form == FORM_TAU_CLAUSE:
        if not clause_text:
            raise StandingPaymentShapeError(
                "a Tau-form standing payment must carry standing_clause"
            )
    elif clause_text:
        raise StandingPaymentShapeError(
            "standing_clause is only for the Tau form (standing_form 2)"
        )
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
        form=form,
        clause_text=clause_text,
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
    if (
        entry.max_total
        and entry.max_total < entry.amount
        and entry.form == FORM_DECLARED
    ):
        # A declared payment is exactly `amount`, so a smaller total
        # could never pay even once. A Tau-form clause names its own
        # amounts under the cap, so a max_total below the cap is a
        # meaningful, tighter end condition there — not a dead entry.
        return "standing_max_total must cover at least one payment"
    if entry.fee_limit > tau_defs.MAX_TRANSFER_VALUE:
        return "standing_fee_limit exceeds the maximum transfer value"
    if entry.version < 1:
        return "standing_version must start at 1"
    if entry.form not in STANDING_FORMS:
        return "unknown standing payment form"
    if entry.form == FORM_TAU_CLAUSE:
        if not entry.clause_text:
            return "a Tau-form standing payment must carry a clause"
        if len(entry.clause_text.encode("utf-8")) > MAX_STANDING_CLAUSE_BYTES:
            return (
                f"a standing clause is at most {MAX_STANDING_CLAUSE_BYTES} bytes"
            )
    elif entry.clause_text:
        return "a declared-form standing payment carries no clause"
    return None


# --- The book ------------------------------------------------------------------

_EntryRow = Tuple[
    bytes, str, str, int, int, int, int, int, int, int, int, int, int, int, int,
    Tuple[int, ...], int, int, int, int, int, str,
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
        tau_entries: List[StandingPaymentEntry] = []
        for row in rows:
            (auth_id, payer, recipient, amount, kind, day, anchor, window,
             final_ts, max_occ, max_total, fee_limit, policy_ref, catch_up,
             version, settled, total_paid, last_exec, cancelled, cancelled_ts,
             form, clause_text) = row
            entry = StandingPaymentEntry(
                payer, recipient, amount, kind, day, anchor, window, final_ts,
                max_occ, max_total, fee_limit, policy_ref, bool(catch_up), version,
                form, clause_text,
            )
            if entry.auth_id != bytes(auth_id):
                raise ValueError(
                    f"stored authorization id does not match its fields: {entry.auth_id.hex()}"
                )
            if entry.auth_id in book._entries:
                raise ValueError(f"duplicate stored authorization: {entry.auth_id.hex()}")
            if entry.series_key in book._series:
                raise ValueError("duplicate stored authorization series")
            if entry.form == FORM_TAU_CLAUSE:
                # A clause-form total is the sum of its settled periods'
                # fact amounts — variable per period, so it is verified
                # against the facts below, once they are loaded.
                tau_entries.append(entry)
            elif total_paid != amount * len(settled):
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
        for entry in tau_entries:
            progress = book._progress[entry.auth_id]
            fact_total = 0
            for period in progress.settled_periods:
                fact = book._facts.get((entry.auth_id, period))
                if fact is None:
                    raise ValueError(
                        "stored Tau-form authorization settles a period "
                        "with no paid-period fact"
                    )
                if not 1 <= fact.amount <= entry.amount:
                    raise ValueError(
                        "stored Tau-form fact amount is outside the "
                        "per-period cap"
                    )
                fact_total += fact.amount
            if fact_total != progress.total_paid:
                raise ValueError(
                    "stored Tau-form total_paid disagrees with its facts"
                )
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
                    entry.form,
                    entry.clause_text,
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
            if entry.form == FORM_TAU_CLAUSE:
                # A clause names variable amounts, so max_total cannot
                # be divided into whole occurrences: it bounds the
                # money (checked on the clause total in the evaluation),
                # and as a period capacity it is exhausted exactly when
                # the recorded total reaches it.
                by_total = 0 if progress.total_paid >= entry.max_total else 1 << 62
            else:
                by_total = (entry.max_total - progress.total_paid) // entry.amount
            capacity = by_total if capacity is None else min(capacity, by_total)
        return capacity if capacity is not None else 1 << 62

    def period_paid_total(self, auth_id: bytes, ts: int) -> int:
        """What the authorization has recorded paid for the period
        containing `ts` — the value standing_clause_inputs feeds at
        i26, identical at admission and apply because both read the
        book's recorded facts."""
        entry, _ = self._entry_and_progress(auth_id)
        period = period_index_at(entry, ts)
        if period < 0:
            return 0
        fact = self._facts.get((entry.auth_id, period))
        return fact.amount if fact is not None else 0

    def _evaluate(
        self,
        entry: StandingPaymentEntry,
        progress: _Progress,
        ts: int,
        payer_balance: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
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
        if entry.form == FORM_TAU_CLAUSE:
            return self._evaluate_clause(
                entry, progress, current, to_settle, payer_balance, clause_legs,
            )
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
                legs=((entry.recipient_pubkey, amount),),
                period_amounts=tuple((p, entry.amount) for p in to_settle),
            ),
            to_settle,
        )

    def _evaluate_clause(
        self,
        entry: StandingPaymentEntry,
        progress: _Progress,
        current: int,
        to_settle: List[int],
        payer_balance: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]],
    ) -> Tuple[ExecutionDecision, List[int]]:
        """The Tau form's evaluation of one due execution.

        The calendar half (which periods are due, the window, the
        occurrence capacity) has already run — it is the book's, shared
        with the declared form. What the clause named is re-checked
        here, leg by leg, against everything the payer signed: the
        candidate set, the per-execution cap (the signed amount times
        the periods being settled), the max_total end condition and
        the balance. Attribution then fills the periods oldest first
        at no more than the signed amount each (the per-period cap),
        so every settled period's fact records an amount inside its
        cap, and a period the total does not reach is not settled.
        """

        def refuse(reason: str) -> Tuple[ExecutionDecision, List[int]]:
            return (
                ExecutionDecision(
                    False, reason, current, 0, 0, progress.total_paid
                ),
                [],
            )

        if clause_legs is None:
            return refuse("the authorization's clause was not evaluated")
        for recipient, leg_amount in clause_legs:
            if recipient not in entry.candidates:
                return refuse(
                    "the clause named a leg outside the declared set"
                )
            if leg_amount <= 0:
                return refuse("the clause named a non-positive leg")
        total = sum(leg_amount for _, leg_amount in clause_legs)
        if total == 0:
            return refuse("the authorization's clause named no legs")
        if total > entry.amount * len(to_settle):
            return refuse(
                "the clause's legs exceed the per-execution cap "
                f"({entry.amount} per period over {len(to_settle)} periods)"
            )
        if entry.max_total and progress.total_paid + total > entry.max_total:
            return refuse("the authorization's end condition is reached")
        if payer_balance < total:
            return refuse(
                "insufficient funds: the occurrence is not settled and its "
                "marker does not advance"
            )
        period_amounts: List[Tuple[int, int]] = []
        remaining = total
        for period in to_settle:
            attributed = min(entry.amount, remaining)
            if attributed <= 0:
                break
            period_amounts.append((period, attributed))
            remaining -= attributed
        settled = [period for period, _ in period_amounts]
        return (
            ExecutionDecision(
                True,
                "executed",
                current,
                total,
                len(period_amounts),
                progress.total_paid + total,
                legs=((entry.recipient_pubkey, total),),
                period_amounts=tuple(period_amounts),
            ),
            settled,
        )

    def execution_due(
        self,
        auth_id: bytes,
        ts: int,
        payer_balance: int,
        executor_pubkey: Optional[str] = None,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
    ) -> ExecutionDecision:
        """What an execution at `ts` would do, without doing it.

        `clause_legs` is the Tau form's leg source: the legs the caller
        (engine at apply, admission at the tip) decoded from stepping
        the payer's clause. Declared entries never consult it; Tau
        entries REQUIRE it — None refuses, because stepping is the
        caller's job, exactly as the payer balance is a parameter.
        """
        entry, progress = self._entry_and_progress(auth_id)
        self._check_executor(executor_pubkey)
        decision, _ = self._evaluate(
            entry, progress, ts, payer_balance, clause_legs=clause_legs
        )
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
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
    ) -> ExecutionDecision:
        """Settle what is due at `ts`, or settle nothing.

        Any party may submit an execution: `executor_pubkey` names the
        submitter for receipts, but the outcome depends only on the stored
        entry, the progress, the timestamp and the payer's balance — never
        on who submits, and the submitter cannot steer amount, recipient,
        cadence, expiry or fee terms, which are the entry's alone. For the
        Tau form the amounts are the clause's, re-checked by the book (see
        _evaluate_clause); the facts record the attributed per-period
        amounts, so a fact always states what its period was actually
        paid. A refused execution changes no state: no marker advances,
        no fact is written, totals do not move.
        """
        entry, progress = self._entry_and_progress(auth_id)
        self._check_executor(executor_pubkey)
        decision, to_settle = self._evaluate(
            entry, progress, ts, payer_balance, clause_legs=clause_legs
        )
        if not decision.executed:
            return decision
        for period, period_amount in decision.period_amounts:
            start, end = period_bounds(entry, period)
            progress.settled_periods.add(period)
            self._facts[(entry.auth_id, period)] = PaidForPeriodFact(
                auth_id=entry.auth_id,
                payer_pubkey=entry.payer_pubkey,
                period_index=period,
                period_start_ts=start,
                period_end_ts=end,
                amount=period_amount,
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
        "forms": {
            "declared": FORM_DECLARED,
            "tau_clause": FORM_TAU_CLAUSE,
        },
        "clause_form": {
            "input_streams": {
                "i1": "the signed per-period amount (the per-period cap)",
                "i2": "the payer's balance",
                "i3": "the payer's pubkey",
                "i4": "the execution submitter's pubkey",
                "i5": "the block timestamp",
                "i26": "what this authorization already paid for the "
                       "period containing the timestamp (recorded facts)",
            },
            "output_encoding": (
                f"o{STANDING_OUTPUT_COUNT_STREAM} leg count; leg k reads "
                f"o{STANDING_OUTPUT_FIRST_STREAM}+2k (candidate index) and "
                f"o{STANDING_OUTPUT_FIRST_STREAM + 1}+2k (amount)"
            ),
            "candidate_set": "the signed recipient (candidate 0)",
            "max_clause_bytes": MAX_STANDING_CLAUSE_BYTES,
            "max_legs": MAX_CLAUSE_LEGS,
        },
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
