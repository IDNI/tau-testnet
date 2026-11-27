"""Calendar regression vectors for monthly standing payments.

On issue #34 MarcoDiPolo checked the monthly helpers of several
designs against an independent UTC calendar: 62 monthly schedules
followed to December 2399, every comparison passing on this line.
He proposed carrying those vectors as a regression check through
the public standing-payment flow, not only against the isolated
helper. This module does both:

1. A helper-level grid: every schedule's due point and relative
   period index, checked against a reference calendar written in
   this file (month-by-month iteration over the proleptic Gregorian
   calendar, plus hard-coded known answers for the leap and century
   cases). The reference never calls consensus.periods.

2. A flow-level pass: each schedule is installed as a standing
   payment through the public payout_rule_install transaction and
   settled by block application -- the same path a node's operator
   and users exercise -- at its first due point, at its clamped
   February point for the 29/30/31 anchors, and at the last period
   of the horizon (December 2399), with the periods in between
   skipped, never caught up.

3. A dense drive: one 31st-anchored schedule settled month by
   month for 25 years through the flow, asserting the settlement
   id and balances at every single period.

4. The exact scenario the proposal named: one January 31
   authorization crossing February and March, a restart in
   between (the book rebuilt from its snapshot rows), and a
   repeated attempt inside an already settled period.

Schedule set: the same 62 schedules MarcoDiPolo used -- anchors
on the 1st..31st of January 2000 at midnight and at 23:59:59 UTC,
4,800 monthly periods each, the last period starting in December
2399.

The flow tests apply ~600 blocks in total, so this file takes
about a minute; it is a regression check, not a smoke test.
"""

import bisect
import calendar as _cal
from datetime import datetime, timezone

from consensus import periods
from consensus.payouts import clock_settlement_id

from test_payout_triggers import (
    ALICE, BOB, CAROL, MALLORY, PROPOSER, SK_ALICE, Chain,
)


def _balances():
    return {ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0}

HORIZON_PERIODS = 4_800  # Jan 2000 .. Dec 2399, one period per month
ANCHOR_YEAR = 2000
ANCHOR_TIMES = [(0, 0, 0), (23, 59, 59)]


def _ts(year, month, day, hour=0, minute=0, second=0):
    return int(datetime(year, month, day, hour, minute, second,
                        tzinfo=timezone.utc).timestamp())


def _ref_dues(anchor_day, hour, minute, second):
    """Due timestamps of one monthly schedule, periods 0..4800.

    Written from the calendar rules directly: advance one month at
    a time from the anchor; the due day is the anchor's day-of-month
    clamped to the target month's last day. Period 4800 (Jan 2400)
    is included so the last horizon period has an end.
    """
    dues = []
    year, month = ANCHOR_YEAR, 1
    for _ in range(HORIZON_PERIODS + 1):
        day = min(anchor_day, _cal.monthrange(year, month)[1])
        dues.append(_ts(year, month, day, hour, minute, second))
        month += 1
        if month > 12:
            month = 1
            year += 1
    return dues


def _schedules():
    for day in range(1, 32):
        for (hour, minute, second) in ANCHOR_TIMES:
            yield day, hour, minute, second


def test_monthly_known_answers_hard_coded():
    # Leap year: a 31st anchor runs on Feb 29 in 2000, returns to
    # the 31st in March -- the clamp never drifts.
    a31 = _ts(2000, 1, 31)
    assert periods.period_start(a31, periods.PERIOD_MONTH, 1) == _ts(2000, 2, 29)
    assert periods.period_start(a31, periods.PERIOD_MONTH, 2) == _ts(2000, 3, 31)
    assert periods.period_start(a31, periods.PERIOD_MONTH, 13) == _ts(2001, 2, 28)
    # Century years: 2100 and 2200 are not leap years, 2400 is.
    a29 = _ts(2000, 1, 29)
    assert periods.period_start(a29, periods.PERIOD_MONTH, 1201) == _ts(2100, 2, 28)
    assert periods.period_start(a29, periods.PERIOD_MONTH, 2401) == _ts(2200, 2, 28)
    assert periods.period_start(a29, periods.PERIOD_MONTH, 4801) == _ts(2400, 2, 29)
    # The maintainer's case, at helper level: Jan 31 2026 anchor.
    a26 = _ts(2026, 1, 31)
    assert periods.period_start(a26, periods.PERIOD_MONTH, 1) == _ts(2026, 2, 28)
    assert periods.period_start(a26, periods.PERIOD_MONTH, 2) == _ts(2026, 3, 31)
    # Relative index around a clamped point.
    assert periods.period_index_at(a31, periods.PERIOD_MONTH,
                                   _ts(2000, 2, 28)) == 0
    assert periods.period_index_at(a31, periods.PERIOD_MONTH,
                                   _ts(2000, 2, 29)) == 1
    assert periods.period_index_at(a31, periods.PERIOD_MONTH,
                                   _ts(2000, 3, 30)) == 1
    assert periods.period_index_at(a31, periods.PERIOD_MONTH,
                                   _ts(2000, 3, 31)) == 2


def test_monthly_grid_matches_independent_calendar():
    due_checks = 0
    index_checks = 0
    for day, hour, minute, second in _schedules():
        anchor = _ts(ANCHOR_YEAR, 1, day, hour, minute, second)
        dues = _ref_dues(day, hour, minute, second)
        for n in range(HORIZON_PERIODS):
            assert periods.period_start(
                anchor, periods.PERIOD_MONTH, n) == dues[n]
            due_checks += 1
            # Relative period index, probed around the due point:
            # the second before belongs to the previous period, the
            # due second and the one after to this one, and the
            # second before the next due point still to this one.
            assert periods.period_index_at(
                anchor, periods.PERIOD_MONTH, dues[n] - 1) == n - 1
            assert periods.period_index_at(
                anchor, periods.PERIOD_MONTH, dues[n]) == n
            assert periods.period_index_at(
                anchor, periods.PERIOD_MONTH, dues[n] + 1) == n
            assert periods.period_index_at(
                anchor, periods.PERIOD_MONTH, dues[n + 1] - 1) == n
            index_checks += 4
    # The grid must not silently shrink: 62 schedules x 4,800
    # periods, one due check and four index checks per period.
    assert due_checks == 297_600
    assert index_checks == 1_190_400


def _install_monthly(ch, anchor, end_period_index):
    terms = ch.install_rule(
        ALICE, SK_ALICE, height=20, ts=anchor - 86_400,
        recipients=[BOB], anchor_ts=anchor,
        extra={"due": True, "end_period_index": end_period_index})
    ch.legs = {20: "1", 21: "1", 22: "0"}
    return terms


def test_monthly_vectors_flow_through_standing_payment_settlement():
    last = HORIZON_PERIODS - 1
    for day, hour, minute, second in _schedules():
        anchor = _ts(ANCHOR_YEAR, 1, day, hour, minute, second)
        dues = _ref_dues(day, hour, minute, second)
        ch = Chain(_balances())
        terms = _install_monthly(ch, anchor, last)
        height = 20

        def block(ts):
            nonlocal height
            height += 1
            ch.block([], height=height, ts=ts)

        # One second before the first due point: nothing settles.
        block(dues[0] - 1)
        assert ch.bal[BOB] == 0
        assert ch.book.get(ALICE).fires == 0

        # At the first due point exactly one settlement lands,
        # under period 0's settlement id.
        block(dues[0])
        state = ch.book.get(ALICE)
        assert ch.bal[BOB] == 1
        assert state.fires == 1
        assert state.settlements == [clock_settlement_id(terms.rule_id, 0)]

        expected_fires = 1
        if day >= 29:
            # February of the first year is the first clamped (or
            # leap-exact) point for these anchors; settle it through
            # the flow as well.
            block(dues[1])
            expected_fires = 2
            state = ch.book.get(ALICE)
            assert state.fires == 2
            assert state.settlements[-1] == clock_settlement_id(
                terms.rule_id, 1)

        # Jump straight to the last period of the horizon
        # (December 2399): only that period settles -- the ~4,800
        # periods in between are skipped, never caught up.
        block(dues[last])
        state = ch.book.get(ALICE)
        assert state.fires == expected_fires + 1
        assert state.period_index == last
        assert state.settlements[-1] == clock_settlement_id(
            terms.rule_id, last)
        assert ch.bal[BOB] == expected_fires + 1
        assert ch.bal[ALICE] == 10_000 - (expected_fires + 1)

        # A later block inside the same period settles nothing more.
        block(dues[last] + 3_600)
        assert ch.book.get(ALICE).fires == expected_fires + 1
        assert ch.bal[BOB] == expected_fires + 1


def test_monthly_31st_dense_drive_25_years_through_the_flow():
    day, hour, minute, second = 31, 0, 0, 0
    anchor = _ts(ANCHOR_YEAR, 1, day, hour, minute, second)
    dues = _ref_dues(day, hour, minute, second)
    periods_to_drive = 300  # Jan 2000 .. Dec 2024
    ch = Chain(_balances())
    terms = _install_monthly(ch, anchor, periods_to_drive - 1)
    for n in range(periods_to_drive):
        ch.block([], height=21 + n, ts=dues[n])
        state = ch.book.get(ALICE)
        assert state.fires == n + 1
        assert state.period_index == n
        assert ch.bal[BOB] == n + 1
        assert state.settlements[-1] == clock_settlement_id(
            terms.rule_id, n)
    state = ch.book.get(ALICE)
    assert state.settlements == [
        clock_settlement_id(terms.rule_id, n)
        for n in range(periods_to_drive)
    ]
    assert ch.bal[ALICE] == 10_000 - periods_to_drive
    # The end condition stops the rule: period 300 never settles.
    ch.block([], height=21 + periods_to_drive, ts=dues[periods_to_drive])
    assert ch.book.get(ALICE).fires == periods_to_drive
    assert ch.bal[BOB] == periods_to_drive


def test_january_31_authorization_survives_a_restart():
    # The flow the proposal named: one January 31 authorization on
    # a local chain, crossing February and March. The period the
    # book records and the occurrence on record after a restart
    # must agree, and a repeated attempt in an already settled
    # period must leave the recorded payout unchanged.
    from consensus.payouts import PayoutBook

    anchor = _ts(2000, 1, 31)
    dues = _ref_dues(31, 0, 0, 0)
    ch = Chain(_balances())
    terms = _install_monthly(ch, anchor, 2)

    # Period 0 settles on the anchor day itself.
    ch.block([], height=21, ts=dues[0])
    assert ch.bal[BOB] == 1
    # February has no 31st: the firing lands on Feb 29 (2000 is a
    # leap year), and the book records period 1.
    ch.block([], height=22, ts=dues[1])
    state = ch.book.get(ALICE)
    assert state.period_index == 1
    assert state.settlements == [
        clock_settlement_id(terms.rule_id, 0),
        clock_settlement_id(terms.rule_id, 1),
    ]
    assert ch.bal[BOB] == 2

    # A repeated attempt inside the settled February period
    # leaves the recorded payout unchanged.
    ch.block([], height=23, ts=dues[1] + 3_600)
    assert ch.book.get(ALICE).fires == 2
    assert ch.bal[BOB] == 2

    # Restart: the book is rebuilt from its snapshot rows, as a
    # node restart rebuilds it. The recorded occurrence -- the
    # settlement ids, the firing count, the period -- is identical.
    restored = PayoutBook.restore(ch.book.snapshot_rows())
    assert restored.root() == ch.book.root()
    rstate = restored.get(ALICE)
    assert rstate.period_index == 1
    assert rstate.settlements == state.settlements
    assert rstate.fires == 2
    assert rstate.total_spent == 2
    ch.lm.payout_rules = restored

    # March: the schedule is back on the 31st, and the restored
    # book settles period 2 on top of the same record.
    ch.block([], height=24, ts=dues[2])
    state = ch.book.get(ALICE)
    assert state.period_index == 2
    assert state.settlements == [
        clock_settlement_id(terms.rule_id, 0),
        clock_settlement_id(terms.rule_id, 1),
        clock_settlement_id(terms.rule_id, 2),
    ]
    assert ch.bal[BOB] == 3
