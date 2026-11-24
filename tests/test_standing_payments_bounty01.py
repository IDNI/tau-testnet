"""Bounty 01, issue #34: standing payments — the book level (slice 2).

The named tests below carry the exact names the jr11ikhsan design posted on
issue #34 promised, for the cases a pure book can prove: #34 cases 1–6, plus
named case 4 end-to-end at book level. Engine-wiring cases (#34-7's o5
re-check at apply, #34-8 admission/apply parity, #34-9 capability endpoints)
land with the wiring slice; case 7 is claimed here only for the
per-authorization totals the book itself keeps, exactly as the posted
design's honesty note states.
"""
import copy
from dataclasses import FrozenInstanceError

import pytest

from consensus.payment_calendar import SECONDS_PER_DAY, SECONDS_PER_WEEK
from consensus.standing_payments import (
    SCHEDULE_MONTHLY,
    SCHEDULE_WEEKLY,
    STATUS_ACTIVE,
    STATUS_CANCELLED,
    STATUS_ENDED,
    StandingPaymentBook,
    StandingPaymentEntry,
    StandingPaymentShapeError,
    due_ts,
    parse_create_standing_payment,
    period_bounds,
    validate_standing_payment_shape,
)

ALICE = "a" * 96  # the payer
BOB = "b" * 96  # the recipient
CAROL = "c" * 96  # any third party

WEEK = SECONDS_PER_WEEK
DAY = SECONDS_PER_DAY
ANCHOR = None  # set below, after _ts is defined


def _ts(year, month, day, hour=0):
    from datetime import datetime, timezone

    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


ANCHOR = _ts(2026, 12, 1, 12)  # weekly schedules anchor here
JAN31 = _ts(2026, 1, 31, 12)  # monthly day-31 schedules anchor here


def sp(
    payer=ALICE,
    recipient=BOB,
    amount=500,
    kind=SCHEDULE_WEEKLY,
    day=0,
    anchor=ANCHOR,
    window=2 * DAY,
    final=0,
    max_occ=0,
    max_total=0,
    fee_limit=0,
    policy_ref=0,
    catch_up=False,
    catch_up_periods=0,
    version=1,
):
    return StandingPaymentEntry(
        payer, recipient, amount, kind, day, anchor, window, final, max_occ,
        max_total, fee_limit, policy_ref, catch_up, version,
        catch_up_periods=catch_up_periods,
    )


def book_with(entry, now=ANCHOR):
    book = StandingPaymentBook()
    book.create(entry, now)
    return book


# --- #34 cases at book level ---------------------------------------------------


def test_monthly_authorization_executes_at_most_once_per_period():
    """#34 case 1: at most one settlement per eligible calendar period."""
    entry = sp(kind=SCHEDULE_MONTHLY, day=31, anchor=JAN31, window=5 * DAY, max_occ=12)
    book = book_with(entry, now=JAN31)
    first = book.execute(entry.auth_id, JAN31, 10_000)
    assert first.executed and first.period_index == 0 and first.amount == 500
    again = book.execute(entry.auth_id, JAN31 + 3600, 10_000)
    assert not again.executed and "already settled" in again.reason
    feb = due_ts(entry, 1)
    assert book.execute(entry.auth_id, feb, 10_000).executed
    assert not book.execute(entry.auth_id, feb + 60, 10_000).executed
    assert book.execute(entry.auth_id, due_ts(entry, 2), 10_000).executed
    assert book.total_executed(entry.auth_id) == (3, 1500)


def test_execution_outside_window_or_twice_in_period_rejected():
    """#34 case 2: before the window, after the window, and a second
    execution inside the same period are all rejected; a period whose
    window lapses is skipped, not collected later (no catch-up signed)."""
    entry = sp(window=DAY, max_occ=10)
    book = book_with(entry)
    early = book.execute(entry.auth_id, ANCHOR - 1, 10_000)
    assert not early.executed and "nothing is due" in early.reason
    late = book.execute(entry.auth_id, ANCHOR + DAY, 10_000)
    assert not late.executed and "lapsed" in late.reason
    # The lapsed period 0 stays unsettled even once period 1 is live.
    nxt = book.execute(entry.auth_id, ANCHOR + WEEK, 10_000)
    assert nxt.executed and nxt.period_index == 1 and nxt.periods_collected == 1
    assert book.paid_for_period(entry.auth_id, 0) is None
    twice = book.execute(entry.auth_id, ANCHOR + WEEK + 60, 10_000)
    assert not twice.executed and "already settled" in twice.reason


def test_any_party_can_trigger_but_cannot_alter_signed_terms():
    """#34 case 3: the outcome never depends on who submits, and the signed
    terms are the entry's alone — frozen, and identical after execution."""
    entry = sp(max_occ=10)
    outcomes = []
    for executor in (ALICE, BOB, CAROL, None):
        book = book_with(entry)
        outcomes.append(book.execute(entry.auth_id, ANCHOR, 10_000, executor_pubkey=executor))
    assert all(o.executed and o.amount == entry.amount for o in outcomes)
    assert len({(o.period_index, o.amount, o.total_paid_after) for o in outcomes}) == 1
    book = book_with(entry)
    book.execute(entry.auth_id, ANCHOR, 10_000, executor_pubkey=CAROL)
    assert book.get(entry.auth_id) == entry  # terms untouched by executing
    with pytest.raises(FrozenInstanceError):
        entry.amount = 501  # type: ignore[misc]
    with pytest.raises(StandingPaymentShapeError):
        book.execute(entry.auth_id, ANCHOR + WEEK, 10_000, executor_pubkey="zz")


def test_cancel_prevents_all_later_executions():
    """#34 case 4: after cancellation every later execution is refused, and
    the refusal is visible immediately from the same committed state."""
    entry = sp(max_occ=10)
    book = book_with(entry)
    assert book.execute(entry.auth_id, ANCHOR, 10_000).executed
    book.cancel(entry.auth_id, ANCHOR + 100)
    assert book.status(entry.auth_id, ANCHOR + 100) == STATUS_CANCELLED
    refused = book.execute(entry.auth_id, ANCHOR + WEEK, 10_000)
    assert not refused.executed and "cancelled" in refused.reason
    assert book.total_executed(entry.auth_id) == (1, 500)  # history stands
    ok, reason = book.can_cancel(entry.auth_id, ANCHOR + 200)
    assert not ok and "already cancelled" in reason
    fresh = sp(recipient=CAROL, max_occ=10)
    book.create(fresh, ANCHOR)
    book.cancel(fresh.auth_id, ANCHOR)
    assert not book.execute(fresh.auth_id, ANCHOR, 10_000).executed


def test_insufficient_funds_no_debt_no_partial_no_false_completion():
    """#34 case 5: insufficient balance settles nothing — no debt, no
    partial payment, no completion marker — and a retry inside the same
    window with funds succeeds explicitly."""
    entry = sp(window=DAY, max_occ=10)
    book = book_with(entry)
    refused = book.execute(entry.auth_id, ANCHOR, 499)
    assert not refused.executed and "insufficient funds" in refused.reason
    assert book.total_executed(entry.auth_id) == (0, 0)
    assert book.paid_for_period(entry.auth_id, 0) is None
    assert book.next_due_ts(entry.auth_id, ANCHOR) == ANCHOR  # marker unmoved
    retried = book.execute(entry.auth_id, ANCHOR + 3600, 500)  # exact balance
    assert retried.executed and retried.amount == 500
    assert book.total_executed(entry.auth_id) == (1, 500)


def test_replay_and_cross_network_execution_rejected():
    """#34 case 6: replaying a creation or an execution fails, and an
    authorization whose signed fields were tampered with — the shape a
    cross-network copy takes — is a different id this book never created.

    (Chain-id binding itself lives in the signed transaction envelope and
    lands with the wiring slice; the book guarantees content-bound identity
    and once-only settlement, which is what makes reuse detectable.)
    """
    entry = sp(max_occ=10)
    book = book_with(entry)
    with pytest.raises(ValueError):
        book.create(entry, ANCHOR)  # replayed creation
    assert book.execute(entry.auth_id, ANCHOR, 10_000).executed
    assert not book.execute(entry.auth_id, ANCHOR, 10_000).executed  # replayed execution
    assert book.total_executed(entry.auth_id) == (1, 500)  # counted exactly once
    for tampered in (sp(amount=501, max_occ=10), sp(recipient=CAROL, max_occ=10)):
        assert tampered.auth_id != entry.auth_id
        with pytest.raises(ValueError):
            book.execute(tampered.auth_id, ANCHOR, 10_000)


# --- The five named cases (gmikeyg) at book level -------------------------------


def test_monthly_on_31st_runs_on_last_day_of_short_month():
    """Named case 4, end-to-end at book level: a payment signed for the 31st
    settles period 0 on Jan 31, period 1 on Feb 28 (the last day of the
    shorter month), and period 2 back on Mar 31 — clamp-and-return, no
    drift — then the signed occurrence limit ends it."""
    entry = sp(kind=SCHEDULE_MONTHLY, day=31, anchor=JAN31, window=3 * DAY, max_occ=3)
    book = book_with(entry, now=JAN31)
    feb28, mar31 = _ts(2026, 2, 28, 12), _ts(2026, 3, 31, 12)
    assert due_ts(entry, 1) == feb28 and due_ts(entry, 2) == mar31
    assert book.execute(entry.auth_id, JAN31, 10_000).period_index == 0
    settled = book.execute(entry.auth_id, feb28, 10_000)
    assert settled.executed and settled.period_index == 1
    fact = book.paid_for_period(entry.auth_id, 1)
    assert (fact.period_start_ts, fact.period_end_ts) == (feb28, mar31)
    assert book.execute(entry.auth_id, mar31, 10_000).period_index == 2
    ended = book.execute(entry.auth_id, _ts(2026, 4, 30, 12), 10_000)
    assert not ended.executed and "end condition" in ended.reason
    assert book.status(entry.auth_id, _ts(2026, 4, 30, 12)) == STATUS_ENDED


# --- The maintainer's additions as first-class objects ---------------------------


def test_open_ended_authorization_rejected_end_condition_required():
    """gmikeyg on #34: no open-ended authorizations. Each single end
    condition on its own is sufficient; none at all is refused at creation."""
    book = StandingPaymentBook()
    open_ended = sp()  # final/max_occ/max_total all zero
    ok, reason = book.can_create(open_ended, ANCHOR)
    assert not ok and "end condition" in reason
    with pytest.raises(ValueError):
        book.create(open_ended, ANCHOR)
    for entry in (
        sp(final=ANCHOR + 30 * DAY),
        sp(max_occ=4),
        sp(max_total=2000),
        sp(kind=SCHEDULE_MONTHLY, day=31, anchor=JAN31, max_occ=12),
    ):
        ok, reason = book.can_create(entry, entry.anchor_ts)
        assert ok, reason
    # Stillborn ends are refused too: an end at/before the first due date,
    # and a total cap that cannot cover even one payment.
    assert validate_standing_payment_shape(sp(final=ANCHOR, max_occ=0), ANCHOR)
    assert validate_standing_payment_shape(sp(max_total=499), ANCHOR)


def test_end_conditions_stop_execution():
    """Each end condition binds at execution, not just at creation."""
    by_total = sp(max_total=1200)  # two 500 payments fit, the third does not
    book = book_with(by_total)
    assert book.execute(by_total.auth_id, ANCHOR, 10_000).executed
    assert book.execute(by_total.auth_id, ANCHOR + WEEK, 10_000).executed
    refused = book.execute(by_total.auth_id, ANCHOR + 2 * WEEK, 10_000)
    assert not refused.executed and "end condition" in refused.reason
    assert book.total_executed(by_total.auth_id) == (2, 1000)

    by_final = sp(final=ANCHOR + 10 * DAY)
    book = book_with(by_final)
    assert book.execute(by_final.auth_id, ANCHOR, 10_000).executed
    assert book.execute(by_final.auth_id, ANCHOR + WEEK, 10_000).executed
    refused = book.execute(by_final.auth_id, ANCHOR + 2 * WEEK, 10_000)
    assert not refused.executed and "final period" in refused.reason
    assert book.status(by_final.auth_id, ANCHOR + 2 * WEEK) == STATUS_ENDED


def test_paid_for_period_fact_written_and_readable():
    """gmikeyg on #34: the "paid for this period" fact is written by every
    settled occurrence, readable per authorization and per period, and
    survives cancellation — other rules read it without replaying history."""
    entry = sp(max_occ=10)
    book = book_with(entry)
    assert book.paid_for_period(entry.auth_id, 0) is None
    book.execute(entry.auth_id, ANCHOR + 60, 10_000, executor_pubkey=CAROL)
    fact = book.paid_for_period(entry.auth_id, 0)
    assert fact is not None
    assert fact.payer_pubkey == ALICE and fact.amount == 500
    assert (fact.period_start_ts, fact.period_end_ts) == period_bounds(entry, 0)
    assert fact.execution_ts == ANCHOR + 60
    assert book.paid_for_period(entry.auth_id, 1) is None  # unpaid period: no fact
    book.cancel(entry.auth_id, ANCHOR + 120)
    assert book.paid_for_period(entry.auth_id, 0) == fact  # history stands


def test_catch_up_only_when_signed_terms_permit():
    """No catch-up by default; with the signed permission AND the signed
    count (FIX 9), one execution inside a live window settles the missed
    periods too — whole periods only, oldest first, bounded by the
    payer's balance. The flag alone (the pre-FIX 9 terms, count 0)
    collects nothing late: the count is the explicit permission."""
    strict = sp(window=DAY, max_occ=10)
    book = book_with(strict)
    settled = book.execute(strict.auth_id, ANCHOR + WEEK, 10_000)  # period 0 missed
    assert settled.executed and settled.periods_collected == 1
    assert book.paid_for_period(strict.auth_id, 0) is None

    flag_only = sp(window=DAY, max_occ=10, catch_up=True)
    book = book_with(flag_only)
    settled = book.execute(flag_only.auth_id, ANCHOR + WEEK, 10_000)
    assert settled.executed and settled.periods_collected == 1
    assert book.paid_for_period(flag_only.auth_id, 0) is None

    lax = sp(window=DAY, max_occ=10, catch_up=True, catch_up_periods=1)
    book = book_with(lax)
    settled = book.execute(lax.auth_id, ANCHOR + WEEK, 10_000)
    assert settled.executed and settled.periods_collected == 2 and settled.amount == 1000
    assert book.paid_for_period(lax.auth_id, 0).execution_ts == ANCHOR + WEEK
    assert book.total_executed(lax.auth_id) == (2, 1000)

    short = sp(window=DAY, max_occ=10, catch_up=True, catch_up_periods=1)
    book = book_with(short)
    settled = book.execute(short.auth_id, ANCHOR + WEEK, 500)  # covers one period
    assert settled.executed and settled.periods_collected == 1 and settled.amount == 500
    assert book.paid_for_period(short.auth_id, 0) is not None  # oldest first
    assert book.paid_for_period(short.auth_id, 1) is None


def test_update_is_new_version_superseding():
    """Update = a new signed version, never an invisible mutation: the old
    version stops executing, and the old version's facts remain readable.
    FIX 5C: the new version starts with the settled current period carried
    over — an update never lets one period be paid twice — so its first
    period is already settled and the next period pays under the new terms.
    """
    v1 = sp(max_occ=10)
    book = book_with(v1)
    book.execute(v1.auth_id, ANCHOR, 10_000)
    for bad_version in (1, 3):
        ok, reason = book.can_create(sp(amount=700, max_occ=10, version=bad_version), ANCHOR)
        assert not ok and "next version" in reason
    v2 = sp(amount=700, max_occ=10, version=2)
    assert book.create(v2, ANCHOR) == v2.auth_id and v2.auth_id != v1.auth_id
    assert book.get(v1.auth_id) is None
    with pytest.raises(ValueError):
        book.execute(v1.auth_id, ANCHOR + WEEK, 10_000)
    # FIX 5C: period 0 arrives settled with v1's 500 already paid.
    assert book.total_executed(v2.auth_id) == (1, 500)
    assert book.paid_for_period(v2.auth_id, 0).amount == 500
    again = book.execute(v2.auth_id, ANCHOR, 10_000)
    assert not again.executed and "already settled" in again.reason
    settled = book.execute(v2.auth_id, ANCHOR + WEEK, 10_000)
    assert settled.executed and settled.amount == 700
    old_fact = book.paid_for_period(v1.auth_id, 0)
    assert old_fact is not None and old_fact.amount == 500  # history not rewritten


# --- Book mechanics --------------------------------------------------------------


def test_book_exposes_next_due_status_and_total_executed():
    """The RPC-facing queries the issue asks for: next due time, status,
    total executed — all derived from the same book state."""
    entry = sp(window=DAY, max_occ=10)
    book = book_with(entry)
    assert book.status(entry.auth_id, ANCHOR) == STATUS_ACTIVE
    assert book.next_due_ts(entry.auth_id, ANCHOR) == ANCHOR
    book.execute(entry.auth_id, ANCHOR, 10_000)
    assert book.next_due_ts(entry.auth_id, ANCHOR) == ANCHOR + WEEK
    # Period 1's window lapses unsettled: next due skips ahead to period 2.
    assert book.next_due_ts(entry.auth_id, ANCHOR + WEEK + 2 * DAY) == ANCHOR + 2 * WEEK
    book.cancel(entry.auth_id, ANCHOR + WEEK + 2 * DAY)
    assert book.next_due_ts(entry.auth_id, ANCHOR) is None

    once = sp(recipient=CAROL, max_occ=1)
    book.create(once, ANCHOR)
    book.execute(once.auth_id, ANCHOR, 10_000)
    assert book.status(once.auth_id, ANCHOR) == STATUS_ENDED
    assert book.next_due_ts(once.auth_id, ANCHOR) is None


def test_create_parses_root_fields_and_rejects_bad_shapes():
    """Creation reads ROOT fields only; a nested payload is unsigned data
    and cannot smuggle terms past the parser."""
    tx = {
        "sender_pubkey": ALICE,
        "standing_recipient_pubkey": BOB,
        "standing_amount": 500,
        "standing_schedule": "monthly",
        "standing_signed_day": 31,
        "standing_anchor_ts": JAN31,
        "standing_window_seconds": 3 * DAY,
        "standing_max_occurrences": 12,
        "payload": {"standing_amount": 999_999},
    }
    entry = parse_create_standing_payment(tx)
    assert entry.amount == 500 and entry.schedule_kind == SCHEDULE_MONTHLY
    assert entry.allow_catch_up is False and entry.version == 1
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment({**tx, "standing_schedule": "fortnightly"})
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment({**tx, "standing_allow_catch_up": 2})
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment({**tx, "standing_recipient_pubkey": "zz"})
    # A monthly anchor that is not the signed first due date fails closed.
    bad_anchor = sp(kind=SCHEDULE_MONTHLY, day=31, anchor=_ts(2026, 1, 30, 12), max_occ=3)
    assert validate_standing_payment_shape(bad_anchor, JAN31)


def test_restore_recomputes_ids_and_root_is_deterministic():
    weekly = sp(window=DAY, max_occ=10, catch_up=True, catch_up_periods=2)
    monthly = sp(kind=SCHEDULE_MONTHLY, day=31, anchor=JAN31, window=3 * DAY, max_occ=3)
    book = book_with(weekly)
    book.create(monthly, JAN31)
    book.execute(weekly.auth_id, ANCHOR + WEEK, 10_000)  # catch-up: periods 0+1
    book.execute(monthly.auth_id, JAN31, 10_000)
    book.cancel(monthly.auth_id, JAN31 + 10)
    clone = StandingPaymentBook.restore(book.rows(), book.fact_rows())
    assert clone.root() == book.root()
    assert copy.deepcopy(book).root() == book.root()
    assert clone.paid_for_period(weekly.auth_id, 0) == book.paid_for_period(weekly.auth_id, 0)
    assert clone.status(monthly.auth_id, JAN31 + 10) == STATUS_CANCELLED
    rows = book.rows()
    tampered_id = [(b"\x00" * 32,) + rows[0][1:]] + rows[1:]
    with pytest.raises(ValueError):
        StandingPaymentBook.restore(tampered_id, book.fact_rows())
    tampered_total = [rows[0][:16] + (999,) + rows[0][17:]] + rows[1:]
    with pytest.raises(ValueError):
        StandingPaymentBook.restore(tampered_total, book.fact_rows())
