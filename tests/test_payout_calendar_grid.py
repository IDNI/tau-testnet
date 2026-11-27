"""Monthly due points against a calendar that shares no code with the node.

The node derives a monthly due point with its own integer arithmetic
(`consensus.payout.add_months`). Here every due point of a grid of schedules is
compared with Python's `datetime` and `calendar`: the days 1 to 31 of January
2000, at the first and at the last second of the day, every month through
December 2399, and the same for rules that run every 2, 3, 6 and 12 months.
The grid crosses 97 leap days, the century years that are no leap years (2100,
2200, 2300) and the one that is (2000).

Then the same schedules through the book the node keeps: a rule signed for
each day of January 2026 is asked for at the second of each due point, not a
second earlier, until it ends four years later (February 2028 has 29 days).
"""
import calendar
from datetime import datetime, timezone

import pytest

from consensus.payout import PayoutBook, due_point_of, validate_terms_shape
from tests.bls_keys import pubkey_hex
from tests.test_payout_options import NOW, NOW_TS, seconds, terms

A = pubkey_hex(0x1A)
DAY = 86_400
MONTHS = 400 * 12                       # January 2000 .. December 2399
TIMES = (0, DAY - 1)                    # 00:00:00 and 23:59:59 UTC


def _calendar_point(year0, day, second_of_day, month_number):
    """Day `day` of month `month_number` after January `year0` on Python's own
    calendar; a day the month does not have is its last day."""
    year, month = year0 + month_number // 12, month_number % 12 + 1
    day = min(day, calendar.monthrange(year, month)[1])
    hours, rest = divmod(second_of_day, 3_600)
    return int(datetime(year, month, day, hours, rest // 60, rest % 60,
                        tzinfo=timezone.utc).timestamp())


@pytest.mark.parametrize("every", [1, 2, 3, 6, 12])
def test_every_due_point_of_the_grid_is_the_calendars(every):
    compared = 0
    for day in range(1, 32):
        for second_of_day in TIMES:
            anchor = _calendar_point(2000, day, second_of_day, 0)
            for index in range(MONTHS // every):
                assert due_point_of(anchor, None, every, index) == _calendar_point(
                    2000, day, second_of_day, index * every), (day, second_of_day, index)
                compared += 1
    assert compared == 62 * MONTHS // every


def test_the_grid_holds_the_cases_that_matter():
    feb = [calendar.monthrange(year, 2)[1] for year in range(2000, 2400)]
    assert feb.count(29) == 97
    assert [calendar.isleap(year) for year in (2000, 2100, 2200, 2300)] == [
        True, False, False, False]
    # signed for 31 January 2000: 29 February, back to 31 March, 30 April
    anchor = _calendar_point(2000, 31, 0, 0)
    days = [datetime.fromtimestamp(due_point_of(anchor, None, 1, k), timezone.utc).day
            for k in range(4)]
    assert days == [31, 29, 31, 30]
    # a century later February has 28 days
    assert datetime.fromtimestamp(
        due_point_of(anchor, None, 1, 1201), timezone.utc).strftime("%Y-%m-%d") == "2100-02-28"


def test_a_due_point_never_comes_from_the_one_before():
    """Twelve steps of one month from the 31st end on the 31st, although
    February and the months of 30 days lie between."""
    anchor = _calendar_point(2000, 31, DAY - 1, 0)
    assert due_point_of(anchor, None, 1, 12) == _calendar_point(2001, 31, DAY - 1, 0)
    assert due_point_of(anchor, None, 1, 12) == due_point_of(anchor, None, 12, 1)


@pytest.mark.parametrize("second_of_day", TIMES)
def test_the_book_asks_for_each_schedule_at_its_second_and_not_before(second_of_day):
    assert datetime.fromtimestamp(NOW_TS, timezone.utc).strftime("%Y-%m-%d") == "2026-01-01"
    asked = 0
    for day in range(1, 32):
        due_at = _calendar_point(2026, day, second_of_day, 0)
        if due_at <= NOW_TS:
            continue                    # a due point must lie ahead of the install
        rule = terms(**dict(seconds(due_at=due_at, due_months=1),
                            expires_at=NOW_TS + 4 * 365 * DAY))
        assert validate_terms_shape(rule, NOW, NOW_TS) is None
        book = PayoutBook()
        book.install(rule, NOW_TS)
        month = 0
        while _calendar_point(2026, day, second_of_day, month) < rule.expires_at:
            point = _calendar_point(2026, day, second_of_day, month)
            assert book.due(NOW, point - 1) == [], (day, month)
            assert book.due(NOW, point) == [A], (day, month)
            book.due_ran(A, point)
            month += 1
            asked += 1
        assert month >= 47, (day, month)
    assert asked >= 30 * 47
