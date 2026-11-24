"""Bounty 01, FIX 9 (catch_up_periods, the S-1 term): the signed catch-up
count on the standing-payment book, at book level.

The differential audit AUDIT-178-DUE-FIX8-2026-11-24 measured this line
BEHIND on the missed-period axis: #178's missed periods are final (its
retry is window-bound and a closed window is never collected again),
while this book's catch-up — gated only by the `allow_catch_up` flag —
collected EVERY lapsed period in one execution. The issue-#34 default
is that an expired period is skipped and one execution collects at most
one period "unless the signed authorization explicitly permits it".

FIX 9 makes that permission a signed COUNT: `catch_up_periods`
(0..MAX_CATCH_UP_PERIODS), a term of both forms, gated by the flag.
Default 0 — including every authorization that signs only the flag, as
all pre-FIX 9 authorizations do — is the issue default exactly. A
signed N > 0 lets one execution collect at most N lapsed periods,
oldest first, on top of the period it lands in, under the same
per-execution cap (the signed amount times the periods being settled).

Covered: (a) default 0 never collects a lapsed period, with and
without the flag; (b) N=2 collects exactly the two oldest lapsed
periods and not the third; (c) the per-execution cap is the amount
times the PERMITTED periods (clause form) and balance truncation stays
oldest-first (declared form); (d) the composition with FIX 5's
due_retry — a retry still pays its own period inside its own window, a
period whose retry window has closed is collected later only under a
signed count, and a settled period drops its retry (never two
payments); (e) restore round-trips the count, a pre-FIX 9 row without
the field reads as 0, and a rewritten count is refused. Plus the
parse/shape bounds and the capability record.
"""
import pytest

from consensus.standing_payments import (
    FORM_TAU_CLAUSE,
    MAX_CATCH_UP_PERIODS,
    SCHEDULE_DAILY,
    StandingPaymentBook,
    StandingPaymentEntry,
    parse_create_standing_payment,
    standing_payment_capabilities,
    validate_standing_payment_shape,
)

PAYER = "aa" * 48
RECIPIENT = "bb" * 48
DAY = 86_400
T0 = 1_800_000_000
WINDOW = 3600
AMOUNT = 500

CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 200 }:bv[64]))"
)


def _declared(**kw):
    fields = dict(
        payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=AMOUNT,
        schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=T0,
        window_seconds=WINDOW, final_ts=0, max_occurrences=30,
        max_total=0, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1,
    )
    fields.update(kw)
    return StandingPaymentEntry(**fields)


def _clause(**kw):
    fields = dict(
        payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=AMOUNT,
        schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=T0,
        window_seconds=WINDOW, final_ts=0, max_occurrences=0,
        max_total=100_000, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1, form=FORM_TAU_CLAUSE,
        clause_text=CLAUSE,
    )
    fields.update(kw)
    return StandingPaymentEntry(**fields)


def _book_with(entry):
    book = StandingPaymentBook()
    book.create(entry, T0 - 100)
    return book


def _in_window(period):
    """A timestamp inside `period`'s execution window."""
    return T0 + period * DAY + 60


# --- (a) the default: a lapsed period is never collected -----------------------


def test_default_zero_never_collects_lapsed_periods():
    entry = _declared()
    book = _book_with(entry)
    # Periods 0, 1, 2 lapse unexecuted; the execution lands in period 3.
    decision = book.execute(entry.auth_id, _in_window(3), 10_000)
    assert decision.executed and decision.period_index == 3
    assert decision.periods_collected == 1 and decision.amount == AMOUNT
    assert [book.paid_for_period(entry.auth_id, p) for p in (0, 1, 2)] == [None] * 3
    assert book.paid_for_period(entry.auth_id, 3).amount == AMOUNT
    assert book.total_executed(entry.auth_id) == (1, AMOUNT)
    # A later execution collects its own period only — the lapsed three
    # stay unpaid forever, and period 4 (skipped over) joins them.
    decision = book.execute(entry.auth_id, _in_window(5), 10_000)
    assert decision.executed and decision.periods_collected == 1
    assert book.paid_for_period(entry.auth_id, 4) is None
    assert book.total_executed(entry.auth_id) == (2, 2 * AMOUNT)


def test_flag_without_count_collects_nothing_late():
    """The pre-FIX 9 terms — flag set, no count — are the default now:
    the flag alone no longer opens the old unbounded catch-up."""
    entry = _declared(allow_catch_up=True)
    assert entry.catch_up_periods == 0 and entry.catch_up_limit == 0
    book = _book_with(entry)
    decision = book.execute(entry.auth_id, _in_window(3), 10_000)
    assert decision.executed and decision.periods_collected == 1
    assert decision.amount == AMOUNT
    assert [book.paid_for_period(entry.auth_id, p) for p in (0, 1, 2)] == [None] * 3
    assert book.total_executed(entry.auth_id) == (1, AMOUNT)


# --- (b) a signed count collects exactly that many, oldest first ---------------


def test_count_two_collects_exactly_two_oldest_lapsed():
    entry = _declared(allow_catch_up=True, catch_up_periods=2)
    book = _book_with(entry)
    # Periods 0..3 lapsed; the execution lands in period 4: it collects
    # the two OLDEST lapsed (0, 1) plus its own period — never 2 or 3.
    decision = book.execute(entry.auth_id, _in_window(4), 10_000)
    assert decision.executed and decision.period_index == 4
    assert decision.periods_collected == 3 and decision.amount == 3 * AMOUNT
    assert decision.period_amounts == ((0, AMOUNT), (1, AMOUNT), (4, AMOUNT))
    assert book.paid_for_period(entry.auth_id, 2) is None
    assert book.paid_for_period(entry.auth_id, 3) is None
    assert book.total_executed(entry.auth_id) == (3, 3 * AMOUNT)
    # The two periods the first execution left behind are the oldest
    # lapsed for the next one: period 5's execution collects exactly
    # those two plus period 5 — the count is per execution, not global.
    decision = book.execute(entry.auth_id, _in_window(5), 10_000)
    assert decision.executed and decision.periods_collected == 3
    assert decision.period_amounts == ((2, AMOUNT), (3, AMOUNT), (5, AMOUNT))
    assert book.total_executed(entry.auth_id) == (6, 6 * AMOUNT)


# --- (c) the per-execution cap is the amount times the permitted periods -------


def test_clause_cap_is_amount_times_permitted_periods():
    entry = _clause(allow_catch_up=True, catch_up_periods=2)
    book = _book_with(entry)
    # At period 4 the permitted set is {0, 1, 4}: the cap is 3 * 500.
    # A clause naming 2000 exceeds it and settles nothing.
    decision = book.execute(
        entry.auth_id, _in_window(4), 10_000, clause_legs=((RECIPIENT, 2000),))
    assert not decision.executed and "per-execution cap" in decision.reason
    assert book.total_executed(entry.auth_id) == (0, 0)
    # Exactly the cap settles, attributed oldest first at the
    # per-period cap.
    decision = book.execute(
        entry.auth_id, _in_window(4), 10_000, clause_legs=((RECIPIENT, 1500),))
    assert decision.executed and decision.amount == 1500
    assert decision.period_amounts == ((0, 500), (1, 500), (4, 500))
    assert book.total_executed(entry.auth_id) == (3, 1500)


def test_declared_balance_truncation_stays_oldest_first_under_count():
    entry = _declared(allow_catch_up=True, catch_up_periods=2)
    book = _book_with(entry)
    # Balance covers exactly two periods: the permitted set {0, 1, 4}
    # truncates oldest-first — the two lapsed periods settle and the
    # current one does not (the pre-FIX 9 truncation order, unchanged).
    decision = book.execute(entry.auth_id, _in_window(4), 2 * AMOUNT)
    assert decision.executed and decision.periods_collected == 2
    assert decision.amount == 2 * AMOUNT
    assert decision.period_amounts == ((0, AMOUNT), (1, AMOUNT))
    assert book.paid_for_period(entry.auth_id, 4) is None
    # Still inside period 4's window, a funded re-execution is offered
    # the count again (the count is per execution): the remaining
    # lapsed pair (2, 3) plus the current period settle.
    decision = book.execute(entry.auth_id, _in_window(4) + 60, 10_000)
    assert decision.executed and decision.periods_collected == 3
    assert decision.period_amounts == ((2, AMOUNT), (3, AMOUNT), (4, AMOUNT))
    assert book.total_executed(entry.auth_id) == (5, 5 * AMOUNT)


# --- (d) the composition with due_retry -----------------------------------------


def test_retry_pays_its_own_period_inside_its_window():
    entry = _clause(due_retry_seconds=12 * 3600)
    book = _book_with(entry)
    # Period 0 is refused short; the retry is owed and pays exactly its
    # own period — catch-up (count 0 here) plays no part in it.
    decision = book.execute(
        entry.auth_id, _in_window(0), 0, clause_legs=((RECIPIENT, 200),))
    assert not decision.executed and "insufficient funds" in decision.reason
    assert book.note_retry_owed(entry.auth_id, 0, _in_window(0), 20)
    retry = book.owed_retries()[0]
    decision = book.execute_retry(retry, T0 + 7200, 10_000, ((RECIPIENT, 200),))
    assert decision.executed and decision.amount == 200
    assert decision.period_amounts == ((0, 200),)
    assert book.owed_retries() == []
    assert book.total_executed(entry.auth_id) == (1, 200)


def test_catch_up_collects_a_period_whose_retry_window_closed():
    entry = _clause(
        allow_catch_up=True, catch_up_periods=1, due_retry_seconds=12 * 3600)
    book = _book_with(entry)
    decision = book.execute(
        entry.auth_id, _in_window(0), 0, clause_legs=((RECIPIENT, 200),))
    assert not decision.executed and "insufficient funds" in decision.reason
    assert book.note_retry_owed(entry.auth_id, 0, _in_window(0), 20)
    # The retry window (12h) and then period 1's due point both pass:
    # the retry is dead — the sweep would drop it, never run it.
    retry = book.owed_retries()[0]
    live, reason = book.retry_live(retry, _in_window(1))
    assert not live and "retry window" in reason
    # But the signed count permits collecting the lapsed period inside
    # period 1's live window: one execution settles period 0 (under
    # the count) and period 1, at the 2 * 500 cap, and settling period
    # 0 drops its dead retry — the period is paid exactly once.
    decision = book.execute(
        entry.auth_id, _in_window(1), 10_000, clause_legs=((RECIPIENT, 1000),))
    assert decision.executed and decision.amount == 1000
    assert decision.period_amounts == ((0, 500), (1, 500))
    assert book.owed_retries() == []
    assert book.total_executed(entry.auth_id) == (2, 1000)


def test_without_count_a_dead_retry_period_is_never_collected():
    entry = _clause(due_retry_seconds=12 * 3600)
    book = _book_with(entry)
    decision = book.execute(
        entry.auth_id, _in_window(0), 0, clause_legs=((RECIPIENT, 200),))
    assert not decision.executed and "insufficient funds" in decision.reason
    assert book.note_retry_owed(entry.auth_id, 0, _in_window(0), 20)
    # Retry dies with its window; with no signed count, period 0 is
    # missed for good — period 1's execution settles period 1 alone.
    decision = book.execute(
        entry.auth_id, _in_window(1), 10_000, clause_legs=((RECIPIENT, 500),))
    assert decision.executed and decision.periods_collected == 1
    assert decision.period_amounts == ((1, 500),)
    assert book.paid_for_period(entry.auth_id, 0) is None
    assert book.total_executed(entry.auth_id) == (1, 500)


# --- parse / shape ----------------------------------------------------------------


def test_parse_and_shape_bounds_for_the_count():
    tx = {
        "sender_pubkey": PAYER,
        "standing_recipient_pubkey": RECIPIENT,
        "standing_amount": AMOUNT,
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": T0,
        "standing_window_seconds": WINDOW,
        "standing_final_ts": 0,
        "standing_max_occurrences": 30,
        "standing_max_total": 0,
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 1,
    }
    entry = parse_create_standing_payment(tx)
    assert entry.catch_up_periods == 0  # absent term reads as the default
    entry = parse_create_standing_payment({**tx, "standing_catch_up_periods": 2})
    assert entry.catch_up_periods == 2 and entry.catch_up_limit == 2
    assert validate_standing_payment_shape(entry, T0) is None
    # The count is a term of BOTH forms: the declared form carries it
    # (unlike due_retry, which is clause-only).
    assert validate_standing_payment_shape(_declared(
        allow_catch_up=True, catch_up_periods=MAX_CATCH_UP_PERIODS), T0) is None
    # Above the cap, and a count without the permission flag, both
    # fail closed at creation.
    problem = validate_standing_payment_shape(
        _declared(allow_catch_up=True,
                  catch_up_periods=MAX_CATCH_UP_PERIODS + 1), T0)
    assert problem is not None and f"0..{MAX_CATCH_UP_PERIODS}" in problem
    problem = validate_standing_payment_shape(
        _declared(catch_up_periods=2), T0)
    assert problem is not None and "requires standing_allow_catch_up" in problem


# --- (e) restore --------------------------------------------------------------------


def test_restore_round_trips_the_count_and_prefix9_rows_read_zero():
    entry = _declared(allow_catch_up=True, catch_up_periods=2)
    book = _book_with(entry)
    book.execute(entry.auth_id, _in_window(4), 10_000)
    rows = book.rows()
    assert len(rows[0]) == 24 and rows[0][-1] == 2
    clone = StandingPaymentBook.restore(rows, book.fact_rows())
    assert clone.root() == book.root()
    restored = clone.get(entry.auth_id)
    assert restored.catch_up_periods == 2 and restored.catch_up_limit == 2
    # The restored book enforces the same bound: at period 6 the two
    # oldest lapsed (2, 3) plus period 6 settle — no more.
    decision = clone.execute(entry.auth_id, _in_window(6), 10_000)
    assert decision.executed and decision.periods_collected == 3
    assert decision.period_amounts == ((2, AMOUNT), (3, AMOUNT), (6, AMOUNT))

    # A pre-FIX 9 row (23 elements, no trailing count) restores with
    # the count at its default 0 and the SAME root: a zero count adds
    # no term to the record encoding.
    plain = _declared()
    book = _book_with(plain)
    book.execute(plain.auth_id, _in_window(0), 10_000)
    row23 = book.rows()[0][:23]
    assert len(row23) == 23
    clone = StandingPaymentBook.restore([row23], book.fact_rows())
    assert clone.root() == book.root()
    assert clone.get(plain.auth_id).catch_up_periods == 0


def test_restore_refuses_a_rewritten_count():
    entry = _declared(allow_catch_up=True, catch_up_periods=2)
    book = _book_with(entry)
    row = list(book.rows()[0])
    row[-1] = 3  # a count the payer never signed: the id no longer recomputes
    with pytest.raises(ValueError):
        StandingPaymentBook.restore([tuple(row)], book.fact_rows())


def test_capabilities_record_names_the_catch_up_term():
    record = standing_payment_capabilities()
    catch_up = record["catch_up_periods"]
    assert catch_up["term"] == "standing_catch_up_periods"
    assert catch_up["range"] == f"0..{MAX_CATCH_UP_PERIODS}"
    assert "never collected" in catch_up["semantics"]
