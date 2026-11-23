"""Conditional grants: held money released on a schedule, refunded at expiry.

A funder creates a grant: a total amount moves out of the funder's balance
into the book's custody at creation, and the beneficiary draws against it
as the signed schedule releases it — a fixed amount per period, the periods
anchored at the grant's start by the same calendar arithmetic the standing
payments use. Time conditions (a lock, a scheduled window, an inactivity
trigger) combine by AND at draw time. At the deadline the unspent remainder
returns to the funder through the end-of-block sweep, fee-free and in full:
the refund wins at expiry. This module is the book — the pure consensus
state, its validation, the release/draw evaluation and the expiry
evaluation. The engine wiring (the create/draw transactions, the sweep
refund) consults exactly these verbs, so admission and apply can never
disagree about a grant.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would
make two honest nodes disagree about admissibility, which forks.

- Held money lives in the book entry, never in the beneficiary's balance:
  the recipient's own balance is never capped by a grant, and a refund
  never pulls from a balance that may no longer hold the money — it pays
  out of the custody the creation funded.
- Releases are calendar-anchored and counted exactly once: by any
  timestamp, the released amount is a pure function of the signed terms —
  min(total, release x periods begun since the start) — so no history of
  draws, retries or replays can release a period twice or skip one.
  Unreleased funds are never spendable; a draw never exceeds
  released-minus-spent.
- The refund is total - spent, exactly: unreleased-but-unspent funds were
  held, never the beneficiary's, and they return with the rest. It settles
  once, at the effective deadline, through the sweep (a sweep movement —
  no fee, per the design's fee section). The effective deadline is the
  signed deadline shortened by the inactivity condition when one is set:
  last activity (the start, then every settled draw) plus the signed
  inactivity period. At or after it, the refund wins — draws refuse.
- A combination that could never be drawn is refused at creation: a lock
  running to the deadline, or a scheduled window that cannot intersect
  the drawable span. Conditions are evaluated against the block timestamp
  at draw time, never a wall clock.
- A funder may also set a SHARED cap: one per-period ceiling on the sum of
  draws across every grant that funder has made. Its per-period totals are
  book state, and every settled draw advances exactly one period's total
  by exactly its amount — counted exactly once, which is what the
  108-history shared-cap check (the maintainer's design gate) verifies.
  Replacing the cap takes the next version with the same period shape, so
  the totals survive the replacement and cannot be reset by re-setting.
- A grant never supersedes another grant (the standing book's rule does
  not carry over): a grant holds money, and superseding one would strand
  the funds it holds. Version distinguishes otherwise-identical grants.
- A grant may instead be a TAU CLAUSE (form 2, FIX 5): the release
  schedule is the funder's own Tau clause, stepped by the node over a
  node-built input map (the draw amount, the held amount, the parties,
  the block timestamp, the total spent so far at i27); the clause names
  the cumulative amount released, in o30, and the book re-checks that
  answer against the declared schedule cap before any draw settles on
  it — the clause can never release more than the signed schedule
  allows, and the refund stays the book's own invariant (total - spent,
  once), never a clause computation. The release grid for a clause-form
  grant is anchored at the signed periods_from, not the install day:
  the clause is written against that anchor, and the book's cap uses
  it. The declared form (form 1) is byte-identical to before the clause
  form existed: its id, its record bytes and its book root do not move.
- Credit classes (the design's table): a draw is a grant_draw credit and
  the refund is a refund credit; neither ever triggers a receive route, a
  payout, or a standing payment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.payment_calendar import (
    SECONDS_PER_DAY,
    SECONDS_PER_WEEK,
    clamped_day,
    month_index_containing,
    monthly_due_ts,
)
from consensus.serialization import (
    compute_grant_book_root,
    compute_grant_id,
    compute_grant_shared_cap_id,
    compute_grant_tau_id,
)
from consensus.standing_payments import (
    SCHEDULE_DAILY,
    SCHEDULE_KINDS,
    SCHEDULE_MONTHLY,
    SCHEDULE_NAME_TO_KIND,
    SCHEDULE_WEEKLY,
)

TX_TYPE_CREATE_GRANT = "create_grant"
TX_TYPE_DRAW_GRANT = "draw_grant"
TX_TYPE_SET_GRANT_SHARED_CAP = "set_grant_shared_cap"

GRANT_TX_TYPES = frozenset(
    {TX_TYPE_CREATE_GRANT, TX_TYPE_DRAW_GRANT, TX_TYPE_SET_GRANT_SHARED_CAP}
)

_FIXED_PERIOD_SECONDS = {
    SCHEDULE_DAILY: SECONDS_PER_DAY,
    SCHEDULE_WEEKLY: SECONDS_PER_WEEK,
}

# An inactivity trigger longer than this can only ever leave the signed
# deadline standing; the bound keeps the field a considered choice.
MAX_INACTIVITY_SECONDS = 3660 * SECONDS_PER_DAY
MAX_SHARED_CAP_PERIOD_SECONDS = 366 * SECONDS_PER_DAY

# The two forms a grant may take (Bounty 01, FIX 5): the declared
# program the stages 2-5 shipped, and the Tau clause form, in which the
# funder's own Tau clause names the cumulative released amount. The
# standing book's identical pair (consensus/standing_payments) is the
# precedent; the values match it on purpose.
FORM_DECLARED = 1
FORM_TAU_CLAUSE = 2
GRANT_FORMS = frozenset({FORM_DECLARED, FORM_TAU_CLAUSE})

# A grant clause is no larger than a payout or standing clause (both
# 8192 bytes), so a stage-1 clause is no larger than a stage-0 one.
MAX_GRANT_CLAUSE_BYTES = 8192

# The clause's one output stream: o30 is the cumulative amount the
# grant has released by the draw's timestamp (grant_clause_inputs /
# decode_clause_released below). The payout and standing forms share
# the o30 count stream; a grant has one recipient, so it needs no leg
# count and no candidate pairs — one number is the whole answer.
GRANT_RELEASED_OUTPUT_STREAM = 30

STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_LOCKED = "locked"
STATUS_EXPIRED = "expired"
STATUS_REFUNDED = "refunded"

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class GrantShapeError(ValueError):
    """A grant transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class GrantEntry:
    """The signed terms of one grant. Nothing here mutates.

    `form` selects the release program: FORM_DECLARED (1) is the
    per-period schedule the stages 2-5 shipped; FORM_TAU_CLAUSE (2)
    hands the release decision to the funder's Tau clause
    (`clause_text`), stepped over grant_clause_inputs at draw time.
    `periods_from_ts` is the clause form's signed release anchor: the
    period grid is counted from it, not from the grant's start — the
    clause is written against that anchor. Both are 0 / empty on the
    declared form, and the declared form's id is computed exactly as
    before the clause form existed.
    """

    funder_pubkey: str
    beneficiary_pubkey: str
    total_amount: int
    release_per_period: int
    schedule_kind: int
    signed_day: int
    start_ts: int
    deadline_ts: int
    locked_until_ts: int
    window_start_ts: int
    window_end_ts: int
    inactivity_seconds: int
    version: int
    form: int = FORM_DECLARED
    clause_text: str = ""
    periods_from_ts: int = 0

    @property
    def grant_id(self) -> bytes:
        if self.form == FORM_TAU_CLAUSE:
            return compute_grant_tau_id(
                self.funder_pubkey,
                self.beneficiary_pubkey,
                self.total_amount,
                self.release_per_period,
                self.schedule_kind,
                self.signed_day,
                self.start_ts,
                self.deadline_ts,
                self.locked_until_ts,
                self.window_start_ts,
                self.window_end_ts,
                self.inactivity_seconds,
                self.version,
                self.form,
                self.clause_text,
                self.periods_from_ts,
            )
        return compute_grant_id(
            self.funder_pubkey,
            self.beneficiary_pubkey,
            self.total_amount,
            self.release_per_period,
            self.schedule_kind,
            self.signed_day,
            self.start_ts,
            self.deadline_ts,
            self.locked_until_ts,
            self.window_start_ts,
            self.window_end_ts,
            self.inactivity_seconds,
            self.version,
        )


@dataclass(frozen=True)
class GrantSharedCapEntry:
    """One funder's shared per-period draw ceiling. Nothing here mutates."""

    funder_pubkey: str
    cap_amount: int
    period_seconds: int
    period_anchor_ts: int
    version: int

    @property
    def cap_id(self) -> bytes:
        return compute_grant_shared_cap_id(
            self.funder_pubkey,
            self.cap_amount,
            self.period_seconds,
            self.period_anchor_ts,
            self.version,
        )


@dataclass(frozen=True)
class GrantDrawDecision:
    """The outcome of presenting one draw to the book.

    `drawn` False means nothing moved: no amount was recorded, no shared
    total advanced, the inactivity clock did not move. `reason` names why,
    for receipts and tests. On success `period_index` is the grant period
    the draw landed in, `spendable_after` the released-but-unspent amount
    left, and `shared_period_index`/`shared_total_after` the shared cap's
    accounting for the draw (-1/unchanged when no shared cap binds it).
    """

    drawn: bool
    reason: str
    amount: int
    period_index: int
    spendable_after: int
    shared_period_index: int
    shared_total_after: int


@dataclass
class _GrantProgress:
    """Live progress of one grant. Book-internal."""

    total_spent: int = 0
    last_draw_ts: int = 0
    refunded: bool = False
    refunded_amount: int = 0
    refunded_ts: int = 0

    def copy(self) -> "_GrantProgress":
        return _GrantProgress(
            total_spent=self.total_spent,
            last_draw_ts=self.last_draw_ts,
            refunded=self.refunded,
            refunded_amount=self.refunded_amount,
            refunded_ts=self.refunded_ts,
        )


# --- Schedule arithmetic (the standing book's, over the grant's anchor) -------


def _release_anchor_ts(entry: GrantEntry) -> int:
    """The timestamp the release grid is anchored at.

    The declared form anchors at the grant's start; the Tau form anchors
    at the signed periods_from — the anchor the funder's clause was
    written against — so the release boundaries follow the clause, not
    the install day. A clause-form anchor may predate the start, which
    releases the elapsed periods at opening; it may postdate it, which
    holds every release until the anchor. Either way the book's cap is
    what it is: the clause can never release past it.
    """
    if entry.form == FORM_TAU_CLAUSE and entry.periods_from_ts:
        return entry.periods_from_ts
    return entry.start_ts


def release_due_ts(entry: GrantEntry, period_index: int) -> int:
    """When period `period_index` (0-based from the anchor) begins."""
    if period_index < 0:
        raise ValueError("period_index must be >= 0")
    anchor = _release_anchor_ts(entry)
    if entry.schedule_kind == SCHEDULE_MONTHLY:
        return monthly_due_ts(anchor, entry.signed_day, period_index)
    return anchor + period_index * _FIXED_PERIOD_SECONDS[entry.schedule_kind]


def period_bounds(entry: GrantEntry, period_index: int) -> Tuple[int, int]:
    """[start, end) of a period: its release date up to the next one."""
    return release_due_ts(entry, period_index), release_due_ts(entry, period_index + 1)


def period_index_at(entry: GrantEntry, ts: int) -> int:
    """Which period contains `ts`; -1 before the release grid opens."""
    anchor = _release_anchor_ts(entry)
    if entry.schedule_kind == SCHEDULE_MONTHLY:
        return month_index_containing(anchor, entry.signed_day, ts)
    if ts < anchor:
        return -1
    return (ts - anchor) // _FIXED_PERIOD_SECONDS[entry.schedule_kind]


def released_by(entry: GrantEntry, ts: int) -> int:
    """The cumulative amount released by `ts` under the signed schedule.

    A pure function of the terms and the timestamp — min(total, release x
    periods begun) — so a period's release is counted exactly once however
    the draws interleave, and unreleased funds are never spendable. For a
    Tau-form grant this is the cap the book holds the clause's answer
    to: the clause names a released amount, and this function says how
    much the signed schedule allows at this time.
    """
    period = period_index_at(entry, ts)
    if period < 0:
        return 0
    return min(entry.total_amount, entry.release_per_period * (period + 1))


def effective_deadline(entry: GrantEntry, progress: _GrantProgress) -> int:
    """When the refund wins: the deadline, shortened by inactivity if set."""
    deadline = entry.deadline_ts
    if entry.inactivity_seconds:
        last_activity = progress.last_draw_ts or entry.start_ts
        deadline = min(deadline, last_activity + entry.inactivity_seconds)
    return deadline


def shared_period_index_at(cap: GrantSharedCapEntry, ts: int) -> int:
    """Which shared period contains `ts`; -1 before the cap's anchor."""
    if ts < cap.period_anchor_ts:
        return -1
    return (ts - cap.period_anchor_ts) // cap.period_seconds


# --- The Tau form: input map and output decoding ------------------------------


_OUTPUT_VALUE_RE = re.compile(
    r"^\{?\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}?(?::bv\[\d+\])?$"
)


def _parse_output_value(value: Any) -> Optional[int]:
    """One clause output as an integer, or None when it is not one.

    The worker reports outputs as Tau value strings; this reads them with
    the same grammar tau_policy.parse_o5 reads o5 with (hex / binary /
    decimal, optional braces and :bv[N] annotation) — the payout form's
    identical reader, kept per book as this codebase keeps its small
    helpers.
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


def grant_clause_inputs(
    entry: GrantEntry,
    drawer_pubkey: str,
    amount: int,
    ts: int,
    held: int,
    total_spent: int,
) -> Dict[int, Any]:
    """The input map a Tau-form draw steps the funder's clause over.

    ONE definition, called by the engine at apply and by admission at
    the tip with their own site values — the construction cannot drift
    between them. The value formats mirror the transfer input map
    (consensus/engine._transfer_input_map) exactly: amounts and the
    timestamp as decimal strings, accounts as `{ #x.. }:bv[384]`
    literals. The map is the payout form's map (i1..i5/i26) with the
    grant meanings:

    - i1: the draw's requested amount
    - i2: the held amount (total - spent - refunded)
    - i3: the funder's pubkey
    - i4: the drawer's pubkey (anyone may submit a draw; the value can
      only ever land on the grant's beneficiary)
    - i5: the block timestamp
    - i27 (tau_defs.GRANT_SPENT_STREAM_INDEX): what this grant has
      already spent, from the book's recorded totals — the
      release-schedule input a grant clause computes its cumulative
      released amount from

    Nothing in the map comes from the draw transaction beyond the
    amount: the map is node-built, so no submitter can steer the clause
    by writing a stream.
    """
    return {
        1: str(int(amount)),
        2: str(int(held)),
        3: "{ #x" + str(entry.funder_pubkey) + " }:bv[384]",
        4: "{ #x" + str(drawer_pubkey) + " }:bv[384]",
        5: str(int(ts)),
        tau_defs.GRANT_SPENT_STREAM_INDEX: str(int(total_spent)),
    }


def decode_clause_released(
    entry: GrantEntry, outputs: Dict[str, Any]
) -> Tuple[Optional[int], str]:
    """The cumulative released amount a stepped clause named, or (None, why not).

    The encoding (pinned in grant_capabilities): o30 is the cumulative
    amount the grant has released by the draw's timestamp. A missing or
    unreadable value means the clause named something the node cannot
    settle: no released amount, and the draw settles nothing. The book
    re-checks the value against the declared schedule cap before any
    draw settles on it, so a clause that names more than the schedule
    allows is refused at the spendable step, not here.
    """
    released = _parse_output_value(
        outputs.get(f"o{GRANT_RELEASED_OUTPUT_STREAM}")
    )
    if released is None:
        return None, "the grant's clause did not report a released amount"
    if released < 0:
        return None, "the grant's clause reported a negative released amount"
    return released, ""


# --- Parsing -------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise GrantShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str, default: int = 0) -> int:
    value = tx.get(name, default)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise GrantShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _id_field(tx: Dict[str, Any], name: str) -> bytes:
    value = tx.get(name)
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise GrantShapeError(f"{name} must be 64 lowercase hex characters")
    return bytes.fromhex(value)


def _form_field(tx: Dict[str, Any]) -> int:
    value = tx.get("grant_form", FORM_DECLARED)
    if not _is_int(value) or value not in GRANT_FORMS:
        raise GrantShapeError(
            "grant_form must be 1 (declared) or 2 (Tau clause)"
        )
    return value


def _clause_field(tx: Dict[str, Any]) -> str:
    value = tx.get("grant_clause", "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise GrantShapeError("grant_clause must be a string")
    return value


def parse_create_grant(tx: Dict[str, Any]) -> GrantEntry:
    """Read a creation from ROOT fields only; a nested `payload` is unsigned data."""
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    schedule_name = tx.get("grant_schedule")
    if schedule_name not in SCHEDULE_NAME_TO_KIND:
        raise GrantShapeError(
            "grant_schedule must be one of: daily, weekly, monthly"
        )
    return GrantEntry(
        funder_pubkey=_pubkey_field(tx, "sender_pubkey"),
        beneficiary_pubkey=_pubkey_field(tx, "grant_beneficiary_pubkey"),
        total_amount=_u64_field(tx, "grant_total_amount"),
        release_per_period=_u64_field(tx, "grant_release_per_period"),
        schedule_kind=SCHEDULE_NAME_TO_KIND[schedule_name],
        signed_day=_u64_field(tx, "grant_signed_day"),
        start_ts=_u64_field(tx, "grant_start_ts"),
        deadline_ts=_u64_field(tx, "grant_deadline_ts"),
        locked_until_ts=_u64_field(tx, "grant_locked_until_ts"),
        window_start_ts=_u64_field(tx, "grant_window_start_ts"),
        window_end_ts=_u64_field(tx, "grant_window_end_ts"),
        inactivity_seconds=_u64_field(tx, "grant_inactivity_seconds"),
        version=_u64_field(tx, "grant_version", default=1),
        form=_form_field(tx),
        clause_text=_clause_field(tx),
        periods_from_ts=_u64_field(tx, "grant_periods_from_ts"),
    )


def parse_draw_grant(tx: Dict[str, Any]) -> Tuple[bytes, int]:
    """Read a draw from ROOT fields: (grant id, amount)."""
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    return (
        _id_field(tx, "grant_id"),
        _u64_field(tx, "grant_draw_amount"),
    )


def parse_set_grant_shared_cap(tx: Dict[str, Any]) -> GrantSharedCapEntry:
    """Read a shared-cap setting from ROOT fields only."""
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    return GrantSharedCapEntry(
        funder_pubkey=_pubkey_field(tx, "sender_pubkey"),
        cap_amount=_u64_field(tx, "grant_shared_cap_amount"),
        period_seconds=_u64_field(tx, "grant_shared_cap_period_seconds"),
        period_anchor_ts=_u64_field(tx, "grant_shared_cap_anchor_ts"),
        version=_u64_field(tx, "grant_shared_cap_version", default=1),
    )


def validate_grant_shape(entry: GrantEntry, now_ts: int) -> Optional[str]:
    """Stateless admissibility of a grant. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything needing the book lives in `can_create`.
    """
    if entry.beneficiary_pubkey == entry.funder_pubkey:
        return "grant beneficiary must differ from the funder"
    if not 1 <= entry.total_amount <= tau_defs.MAX_TRANSFER_VALUE:
        return "grant_total_amount must be in 1..MAX_TRANSFER_VALUE"
    if not 1 <= entry.release_per_period <= tau_defs.MAX_TRANSFER_VALUE:
        return "grant_release_per_period must be in 1..MAX_TRANSFER_VALUE"
    if entry.schedule_kind not in SCHEDULE_KINDS:
        return "unknown schedule kind"
    if entry.form not in GRANT_FORMS:
        return "grant_form must be 1 (declared) or 2 (Tau clause)"
    if entry.form == FORM_TAU_CLAUSE:
        if not entry.clause_text or not entry.clause_text.strip():
            return "a Tau-form grant must carry a clause"
        if len(entry.clause_text.encode("utf-8")) > MAX_GRANT_CLAUSE_BYTES:
            return (
                f"a grant clause is at most {MAX_GRANT_CLAUSE_BYTES} bytes"
            )
        if not entry.periods_from_ts:
            return "a Tau-form grant must carry a signed periods_from"
    else:
        if entry.clause_text:
            return "a declared grant carries no clause"
        if entry.periods_from_ts:
            return "a declared grant carries no periods_from"
    if entry.schedule_kind == SCHEDULE_MONTHLY:
        if not 1 <= entry.signed_day <= 31:
            return "grant_signed_day must be in 1..31 for a monthly schedule"
        # The release grid's anchor is the start for the declared form
        # and the signed periods_from for the Tau form: the monthly
        # day-of-month check follows the grid, not the install day.
        grid_anchor = (
            entry.periods_from_ts
            if entry.form == FORM_TAU_CLAUSE
            else entry.start_ts
        )
        anchor = datetime.fromtimestamp(grid_anchor, tz=timezone.utc)
        if anchor.day != clamped_day(anchor.year, anchor.month, entry.signed_day):
            if entry.form == FORM_TAU_CLAUSE:
                return (
                    "periods_from must be the first release date: its "
                    "day-of-month must be the signed day clamped into its month"
                )
            return (
                "the start must be the first release date: its day-of-month "
                "must be the signed day clamped into the start month"
            )
    elif entry.signed_day != 0:
        return "grant_signed_day applies only to a monthly schedule"
    if entry.deadline_ts <= entry.start_ts:
        return "grant_deadline_ts must be after the start"
    # Conditions combine by AND (the design): a combination that could
    # never be drawn is refused here, not discovered at draw time.
    drawable_from = max(entry.start_ts, entry.locked_until_ts)
    if entry.locked_until_ts and entry.locked_until_ts >= entry.deadline_ts:
        return "the lock runs to the deadline: the grant could never be drawn"
    if entry.window_start_ts or entry.window_end_ts:
        if not entry.window_start_ts < entry.window_end_ts:
            return "grant_window_start_ts must be before grant_window_end_ts"
        if (entry.window_end_ts <= drawable_from
                or entry.window_start_ts >= entry.deadline_ts):
            return (
                "the scheduled window never meets the drawable span: "
                "the grant could never be drawn"
            )
    if entry.inactivity_seconds > MAX_INACTIVITY_SECONDS:
        return f"grant_inactivity_seconds exceeds {MAX_INACTIVITY_SECONDS}"
    if entry.version < 1:
        return "grant_version must start at 1"
    return None


def validate_shared_cap_shape(
    entry: GrantSharedCapEntry, now_ts: int
) -> Optional[str]:
    """Stateless admissibility of a shared cap. None when fine."""
    if not 1 <= entry.cap_amount <= tau_defs.MAX_TRANSFER_VALUE:
        return "grant_shared_cap_amount must be in 1..MAX_TRANSFER_VALUE"
    if not 1 <= entry.period_seconds <= MAX_SHARED_CAP_PERIOD_SECONDS:
        return (
            "grant_shared_cap_period_seconds must be in "
            f"1..{MAX_SHARED_CAP_PERIOD_SECONDS}"
        )
    if entry.version < 1:
        return "grant_shared_cap_version must start at 1"
    return None


# --- The book ------------------------------------------------------------------

_EntryRow = Tuple[
    bytes, str, str, int, int, int, int, int, int, int, int, int, int, int,
    int, int, int, int, int, int, str, int,
]
_CapRow = Tuple[bytes, str, int, int, int, int, Tuple[Tuple[int, int], ...]]


class GrantBook:
    """Grants in custody, their progress, and the funders' shared caps.

    Composed as a field of ConsensusLifecycleManager in the wiring slice, so
    the meta hash picks the book root up without a call site to forget (the
    RetractableBook pattern). Entries and caps are frozen, so copies share
    them; only the progress records and shared totals are duplicated.
    """

    def __init__(self) -> None:
        self._entries: Dict[bytes, GrantEntry] = {}
        self._progress: Dict[bytes, _GrantProgress] = {}
        self._shared_caps: Dict[str, GrantSharedCapEntry] = {}
        self._shared_totals: Dict[str, Dict[int, int]] = {}
        self._root: Optional[bytes] = None

    # -- copying / restoring ---------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "GrantBook":
        clone = GrantBook.__new__(GrantBook)
        clone._entries = dict(self._entries)
        clone._progress = {k: v.copy() for k, v in self._progress.items()}
        clone._shared_caps = dict(self._shared_caps)
        clone._shared_totals = {
            k: dict(v) for k, v in self._shared_totals.items()
        }
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls,
        rows: Iterable[_EntryRow],
        shared_caps: Iterable[_CapRow] = (),
    ) -> "GrantBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute.

        The row carries the Tau form's signed fields (form, clause_text,
        periods_from_ts) as trailing fields; the id recompute dispatches
        on the form, so a stored clause-form grant rebuilds under its
        Tau-domain id and a stored declared grant under its declared id.
        """
        book = cls()
        for row in rows:
            (grant_id, funder, beneficiary, total, release, kind, day, start,
             deadline, locked, win_start, win_end, inactivity, version,
             spent, last_draw, refunded, refunded_amount, refunded_ts,
             form, clause_text, periods_from_ts) = row
            entry = GrantEntry(
                funder, beneficiary, total, release, kind, day, start,
                deadline, locked, win_start, win_end, inactivity, version,
                form, clause_text, periods_from_ts,
            )
            if entry.grant_id != bytes(grant_id):
                raise ValueError(
                    f"stored grant id does not match its fields: {entry.grant_id.hex()}"
                )
            if entry.grant_id in book._entries:
                raise ValueError(f"duplicate stored grant: {entry.grant_id.hex()}")
            if not 0 <= spent <= total:
                raise ValueError("stored total_spent is outside the grant's total")
            if refunded:
                if refunded_amount != total - spent:
                    raise ValueError(
                        "stored refunded amount disagrees with total - spent"
                    )
            elif refunded_amount:
                raise ValueError("stored refund without the refunded flag")
            book._entries[entry.grant_id] = entry
            book._progress[entry.grant_id] = _GrantProgress(
                total_spent=spent,
                last_draw_ts=last_draw,
                refunded=bool(refunded),
                refunded_amount=refunded_amount,
                refunded_ts=refunded_ts,
            )
        for cap_id, funder, amount, period_seconds, anchor, version, totals in shared_caps:
            cap = GrantSharedCapEntry(funder, amount, period_seconds, anchor, version)
            if cap.cap_id != bytes(cap_id):
                raise ValueError(
                    f"stored shared cap id does not match its fields: {cap.cap_id.hex()}"
                )
            if funder in book._shared_caps:
                raise ValueError(f"duplicate stored shared cap for funder: {funder}")
            cap_totals: Dict[int, int] = {}
            for index, total in totals:
                if index in cap_totals:
                    raise ValueError("duplicate stored shared period total")
                if total < 0:
                    raise ValueError("stored shared period total is negative")
                cap_totals[int(index)] = int(total)
            book._shared_caps[funder] = cap
            book._shared_totals[funder] = cap_totals
        return book

    def rows(self) -> List[_EntryRow]:
        out: List[_EntryRow] = []
        for grant_id, entry in self._entries.items():
            progress = self._progress[grant_id]
            out.append(
                (
                    grant_id,
                    entry.funder_pubkey,
                    entry.beneficiary_pubkey,
                    entry.total_amount,
                    entry.release_per_period,
                    entry.schedule_kind,
                    entry.signed_day,
                    entry.start_ts,
                    entry.deadline_ts,
                    entry.locked_until_ts,
                    entry.window_start_ts,
                    entry.window_end_ts,
                    entry.inactivity_seconds,
                    entry.version,
                    progress.total_spent,
                    progress.last_draw_ts,
                    int(progress.refunded),
                    progress.refunded_amount,
                    progress.refunded_ts,
                    entry.form,
                    entry.clause_text,
                    entry.periods_from_ts,
                )
            )
        return out

    def shared_cap_rows(self) -> List[_CapRow]:
        out: List[_CapRow] = []
        for funder, cap in self._shared_caps.items():
            totals = self._shared_totals.get(funder, {})
            out.append(
                (
                    cap.cap_id,
                    funder,
                    cap.cap_amount,
                    cap.period_seconds,
                    cap.period_anchor_ts,
                    cap.version,
                    tuple(sorted(totals.items())),
                )
            )
        return out

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_grant_book_root(
                self.rows(), self.shared_cap_rows()
            )
        return self._root

    # -- queries -----------------------------------------------------------------

    def get(self, grant_id: bytes) -> Optional[GrantEntry]:
        return self._entries.get(bytes(grant_id))

    def grant_count(self) -> int:
        return len(self._entries)

    def is_empty(self) -> bool:
        """True while no grant and no shared cap exists.

        Settled grants stay in the book as rooted history (their refund is
        part of consensus state), so a book that has ever held a grant is
        never empty again — that is what the meta-hash gate keys off.
        """
        return not self._entries and not self._shared_caps

    def _entry_and_progress(
        self, grant_id: bytes
    ) -> Tuple[GrantEntry, _GrantProgress]:
        grant_id = bytes(grant_id)
        entry = self._entries.get(grant_id)
        if entry is None:
            raise ValueError(f"no grant with id {grant_id.hex()}")
        return entry, self._progress[grant_id]

    def held(self, grant_id: bytes) -> int:
        """What the book still custodies for one grant."""
        entry, progress = self._entry_and_progress(grant_id)
        return entry.total_amount - progress.total_spent - progress.refunded_amount

    def held_total(self) -> int:
        """The total value in the book's custody, across every grant.

        The engine's supply invariant counts this beside the retractable
        book's escrow: value held here is in no account's balance, but it
        exists and it is spoken for.
        """
        total = 0
        for grant_id, entry in self._entries.items():
            progress = self._progress[grant_id]
            total += (
                entry.total_amount
                - progress.total_spent
                - progress.refunded_amount
            )
        return total

    def spendable(self, grant_id: bytes, ts: int) -> int:
        """Released-but-unspent at `ts` (0 once the refund has settled)."""
        entry, progress = self._entry_and_progress(grant_id)
        if progress.refunded:
            return 0
        return released_by(entry, ts) - progress.total_spent

    def deadline_of(self, grant_id: bytes) -> int:
        """The grant's effective deadline (inactivity applied)."""
        entry, progress = self._entry_and_progress(grant_id)
        return effective_deadline(entry, progress)

    def status(self, grant_id: bytes, ts: int) -> str:
        entry, progress = self._entry_and_progress(grant_id)
        if progress.refunded:
            return STATUS_REFUNDED
        if ts >= effective_deadline(entry, progress):
            return STATUS_EXPIRED
        if ts < entry.start_ts:
            return STATUS_PENDING
        if entry.locked_until_ts and ts < entry.locked_until_ts:
            return STATUS_LOCKED
        return STATUS_ACTIVE

    def accounting(self, grant_id: bytes) -> Dict[str, int]:
        """principal / drawn / held / refunded for one grant.

        The four always satisfy principal == drawn + held + refunded: every
        unit the creation custodied is accounted for at every moment.
        """
        entry, progress = self._entry_and_progress(grant_id)
        return {
            "principal": entry.total_amount,
            "drawn": progress.total_spent,
            "held": (
                entry.total_amount
                - progress.total_spent
                - progress.refunded_amount
            ),
            "refunded": progress.refunded_amount,
        }

    def grants_for_beneficiary(self, beneficiary_pubkey: str) -> List[GrantEntry]:
        return sorted(
            (e for e in self._entries.values()
             if e.beneficiary_pubkey == beneficiary_pubkey),
            key=lambda e: e.grant_id,
        )

    def grants_for_funder(self, funder_pubkey: str) -> List[GrantEntry]:
        return sorted(
            (e for e in self._entries.values()
             if e.funder_pubkey == funder_pubkey),
            key=lambda e: e.grant_id,
        )

    # -- shared caps ---------------------------------------------------------------

    def shared_cap_for(self, funder_pubkey: str) -> Optional[GrantSharedCapEntry]:
        return self._shared_caps.get(funder_pubkey)

    def shared_period_total(self, funder_pubkey: str, period_index: int) -> int:
        return self._shared_totals.get(funder_pubkey, {}).get(period_index, 0)

    def can_set_shared_cap(
        self, entry: GrantSharedCapEntry, now_ts: int
    ) -> Tuple[bool, str]:
        problem = validate_shared_cap_shape(entry, now_ts)
        if problem is not None:
            return False, problem
        existing = self._shared_caps.get(entry.funder_pubkey)
        if existing is not None:
            if entry.cap_id == existing.cap_id:
                return False, "this shared cap is already set"
            if entry.version != existing.version + 1:
                return (
                    False,
                    "a replacement must be the next version "
                    f"({existing.version + 1}), got {entry.version}",
                )
            # Only the amount may change: the period shape is the axis the
            # per-period totals are counted on, and moving it would orphan
            # the count — a settled draw must stay counted exactly once.
            if (entry.period_seconds != existing.period_seconds
                    or entry.period_anchor_ts != existing.period_anchor_ts):
                return (
                    False,
                    "a replacement shared cap keeps the period shape "
                    "(period_seconds and anchor); only the amount may change",
                )
        elif entry.version != 1:
            return False, "a first shared cap must be version 1"
        return True, ""

    def set_shared_cap(
        self, entry: GrantSharedCapEntry, now_ts: int
    ) -> bytes:
        """Set (or replace) a funder's shared cap; totals carry across."""
        ok, reason = self.can_set_shared_cap(entry, now_ts)
        if not ok:
            raise ValueError(reason)
        self._shared_caps[entry.funder_pubkey] = entry
        self._shared_totals.setdefault(entry.funder_pubkey, {})
        self._root = None
        return entry.cap_id

    # -- creation --------------------------------------------------------------------

    def can_create(self, entry: GrantEntry, now_ts: int) -> Tuple[bool, str]:
        problem = validate_grant_shape(entry, now_ts)
        if problem is not None:
            return False, problem
        if entry.grant_id in self._entries:
            return False, "this grant already exists"
        return True, ""

    def create(self, entry: GrantEntry, now_ts: int) -> bytes:
        """Record a grant whose total the creation has custodied.

        The engine stages the funder's debit through the transfer seam
        (escrow) in the same transaction; this verb records the custody.
        It is called only at the post-settlement site, so a fee-rejected
        creation records nothing and holds nothing.
        """
        ok, reason = self.can_create(entry, now_ts)
        if not ok:
            raise ValueError(reason)
        self._entries[entry.grant_id] = entry
        self._progress[entry.grant_id] = _GrantProgress()
        self._root = None
        return entry.grant_id

    # -- draws -----------------------------------------------------------------------

    def _evaluate_draw(
        self,
        entry: GrantEntry,
        progress: _GrantProgress,
        amount: int,
        ts: int,
        clause_released: Optional[int] = None,
    ) -> GrantDrawDecision:
        """Pure evaluation: the decision a draw would produce.

        For a Tau-form grant the caller steps the funder's clause over
        the node-built input map first and passes the released amount it
        named as `clause_released` — the book never steps a clause
        itself, mirroring the payout book's evaluate_execution
        (clause_legs=...). A clause-form evaluation without a stepped
        value is refused outright, so a caller that forgot to step
        cannot silently fall back to the declared schedule: admission
        and apply step the same clause over the same map, and the book
        is the enforcer that both must satisfy.
        """
        # The released amount refusals report: the declared schedule's
        # answer until the clause's answer is validated, the clause's
        # answer after — the closure reads the current value at call
        # time, so a refusal before the clause step and one after it
        # each report the amount that was actually in force.
        released = released_by(entry, ts)

        def refuse(reason: str) -> GrantDrawDecision:
            shared_index = -1
            shared_total = 0
            cap = self._shared_caps.get(entry.funder_pubkey)
            if cap is not None:
                shared_index = shared_period_index_at(cap, ts)
                if shared_index >= 0:
                    shared_total = self.shared_period_total(
                        entry.funder_pubkey, shared_index
                    )
            return GrantDrawDecision(
                False, reason, 0, period_index_at(entry, ts),
                released - progress.total_spent
                if ts >= entry.start_ts else 0,
                shared_index, shared_total,
            )

        if progress.refunded:
            return refuse("the grant's refund has settled: nothing is left to draw")
        if amount < 1:
            return refuse("grant_draw_amount must be at least 1")
        if ts < entry.start_ts:
            return refuse("the grant has not opened yet")
        if ts >= effective_deadline(entry, progress):
            return refuse("the grant has expired: the refund wins at the deadline")
        if entry.locked_until_ts and ts < entry.locked_until_ts:
            return refuse("the grant is locked until its signed unlock time")
        if entry.window_start_ts or entry.window_end_ts:
            if not entry.window_start_ts <= ts < entry.window_end_ts:
                return refuse("the draw falls outside the grant's scheduled window")
        if entry.form == FORM_TAU_CLAUSE:
            # The clause names the released amount; the book re-checks
            # it against the declared schedule cap (released_by, counted
            # from the signed periods_from) and the grant total. A clause
            # that names more than the schedule allows settles nothing —
            # the schedule is the guard, the clause is the voice.
            if clause_released is None:
                return refuse(
                    "the grant's clause must be stepped before evaluation: "
                    "no released amount was supplied"
                )
            if clause_released > entry.total_amount:
                return refuse(
                    f"the grant's clause released {clause_released}, "
                    f"above the grant total {entry.total_amount}"
                )
            if clause_released > released_by(entry, ts):
                return refuse(
                    f"the grant's clause released {clause_released}, "
                    f"above the declared schedule's {released_by(entry, ts)} "
                    "at this time"
                )
            released = clause_released
        spendable = released - progress.total_spent
        if amount > spendable:
            return refuse(
                f"the draw {amount} exceeds the released-but-unspent "
                f"amount {spendable}"
            )
        cap = self._shared_caps.get(entry.funder_pubkey)
        shared_index = -1
        shared_after = 0
        if cap is not None:
            shared_index = shared_period_index_at(cap, ts)
            if shared_index >= 0:
                shared_now = self.shared_period_total(
                    entry.funder_pubkey, shared_index
                )
                if shared_now + amount > cap.cap_amount:
                    return refuse(
                        f"the draw {amount} would push this period's draws "
                        f"across the funder's grants past the shared cap "
                        f"{cap.cap_amount} (already drawn {shared_now})"
                    )
                shared_after = shared_now + amount
        return GrantDrawDecision(
            True, "drawn", amount, period_index_at(entry, ts),
            spendable - amount, shared_index, shared_after,
        )

    def evaluate_draw(
        self, grant_id: bytes, amount: int, ts: int,
        clause_released: Optional[int] = None,
    ) -> GrantDrawDecision:
        """What a draw at `ts` would do, without doing it.

        For a Tau-form grant pass the stepped clause's released amount
        (see _evaluate_draw): without it the evaluation refuses.
        """
        entry, progress = self._entry_and_progress(grant_id)
        return self._evaluate_draw(
            entry, progress, amount, ts, clause_released=clause_released
        )

    def draw(
        self, grant_id: bytes, amount: int, ts: int,
        clause_released: Optional[int] = None,
    ) -> GrantDrawDecision:
        """Settle a draw, or settle nothing.

        On success exactly three writes happen: the grant's spent total
        advances by the amount, its activity clock moves to `ts`, and —
        when a shared cap binds the draw — the funder's shared total for
        the draw's one shared period advances by the amount. That is what
        "counted exactly once" is made of. A refused draw changes no state.

        For a Tau-form grant the caller passes the same stepped released
        amount the branch evaluation used, so the settlement re-evaluates
        to the staged decision by construction.
        """
        entry, progress = self._entry_and_progress(grant_id)
        decision = self._evaluate_draw(
            entry, progress, amount, ts, clause_released=clause_released
        )
        if not decision.drawn:
            return decision
        progress.total_spent += amount
        progress.last_draw_ts = ts
        if decision.shared_period_index >= 0:
            totals = self._shared_totals.setdefault(entry.funder_pubkey, {})
            totals[decision.shared_period_index] = (
                totals.get(decision.shared_period_index, 0) + amount
            )
        self._root = None
        return decision

    # -- expiry / refund -------------------------------------------------------------

    def expired_grants(self, ts: int) -> List[GrantEntry]:
        """Grants whose refund falls due at `ts` and has not settled."""
        return sorted(
            (
                entry
                for entry in self._entries.values()
                if not self._progress[entry.grant_id].refunded
                and ts >= effective_deadline(
                    entry, self._progress[entry.grant_id]
                )
            ),
            key=lambda e: e.grant_id,
        )

    def settle_expiry_refund(self, grant_id: bytes, ts: int) -> int:
        """Settle one grant's expiry refund; returns the remainder paid.

        The remainder is total - spent, exactly: released or not, every
        unspent unit the book custodies returns to the funder. Settles
        once — a second call raises, and the sweep asks `expired_grants`
        first, so it never makes one.
        """
        entry, progress = self._entry_and_progress(grant_id)
        if progress.refunded:
            raise ValueError("the grant's refund has already settled")
        if ts < effective_deadline(entry, progress):
            raise ValueError("the grant has not reached its deadline")
        amount = entry.total_amount - progress.total_spent
        progress.refunded = True
        progress.refunded_amount = amount
        progress.refunded_ts = ts
        self._root = None
        return amount


# --- Capability reporting -------------------------------------------------------


def grant_capabilities() -> Dict[str, Any]:
    """The grant semantics a capability endpoint reports (stages 2-5).

    Built from the module's own values so the report can never drift from
    the code: if a bound changes, this record changes with it. (Support,
    conditions, credit classes and refund semantics, stated before send —
    the consensus-level record an endpoint serves, there being no
    capability-endpoint infrastructure in the codebase yet.)
    """
    return {
        "supported": True,
        "schedules": sorted(SCHEDULE_NAME_TO_KIND),
        "conditions": (
            "per-period release cap, locked-until, scheduled window, "
            "inactivity expiry — combined by AND, evaluated at draw time"
        ),
        "refund": (
            "the unspent remainder (total - spent) returns to the funder "
            "at the deadline through the block sweep, fee-free, in full"
        ),
        "shared_cap": (
            "one per-period ceiling per funder across all their grants; "
            "every settled draw counted exactly once"
        ),
        "draw_credit_class": "grant_draw",
        "refund_credit_class": "refund",
        "fee": (
            "creation and draws are ordinary submitted transactions "
            "(submitter pays); the sweep refund moves with no fee"
        ),
        "max_inactivity_seconds": MAX_INACTIVITY_SECONDS,
        "tau_clause": {
            "forms": {
                "declared_program": FORM_DECLARED,
                "tau_clause": FORM_TAU_CLAUSE,
            },
            "inputs": {
                "i1": "the draw's requested amount",
                "i2": "the held amount (total - spent - refunded)",
                "i3": "the funder's pubkey",
                "i4": "the drawer's pubkey",
                "i5": "the block timestamp",
                tau_defs.TAU_INPUT_STREAM_GRANT_SPENT: (
                    "what this grant has already spent"
                ),
            },
            "outputs": {
                f"o{GRANT_RELEASED_OUTPUT_STREAM}": (
                    "the cumulative amount released by the draw's timestamp"
                ),
            },
            "max_clause_bytes": MAX_GRANT_CLAUSE_BYTES,
            "release_cap": (
                "the clause's released amount is re-checked against the "
                "declared schedule (release x periods begun from the "
                "signed periods_from, capped at the total); above it the "
                "draw settles nothing"
            ),
            "refund": (
                "the refund stays the book's invariant (total - spent, "
                "once at the deadline), never a clause computation"
            ),
        },
    }
