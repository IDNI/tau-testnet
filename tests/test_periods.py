"""Tests for consensus.periods (Bounty 01, Stage 1).

Two layers: a literal reference table (values verified against GNU `date -u`,
so a regression in the Hinnant conversions shows up as a wrong literal, not
as a wrong oracle), and a `datetime` oracle sweep over ~12,600 timestamps
spanning the 2024 leap day. The implementation must never import datetime;
the oracle lives only in this test.
"""
import datetime

import pytest

from consensus.periods import (
    PERIOD_DAY,
    PERIOD_FIXED,
    PERIOD_MONTH,
    PERIOD_WEEK,
    PeriodError,
    civil_from_days,
    days_from_civil,
    hour_of_day,
    next_period_start,
    period_bounds,
    period_index,
    period_start,
    validate_period_spec,
    weekday,
)

# Verified with `TZ=UTC date -d "<date>" "+%s %A"`:
#   2026-12-01 00:00:00 UTC = 1796083200 Tuesday
#   2026-11-16 00:00:00 UTC = 1794787200 Monday
#   2026-11-20 13:30:00 UTC = 1795181400 Friday
#   2026-01-31 00:00:00 UTC = 1769817600, 2026-02-28 = 1772236800
#   2026-03-31 = 1774915200, 2026-04-30 = 1777507200
#   2024-01-31 = 1706659200, 2024-02-29 = 1709164800 (leap year)
#   1970-01-05 = 345600 Monday, 1969-12-29 = -259200 Monday


def test_epoch_reference_values():
    assert weekday(0) == 3  # 1970-01-01 was a Thursday
    assert hour_of_day(0) == 0
    assert period_index(PERIOD_DAY, 0) == 0
    assert period_start(PERIOD_DAY, 0) == 0
    assert period_bounds(PERIOD_DAY, 0) == (0, 86400)
    # Week 0 is the week of Monday 1969-12-29, so the epoch sits inside it.
    assert period_index(PERIOD_WEEK, 0) == 0
    assert period_start(PERIOD_WEEK, 0) == -259200
    assert period_bounds(PERIOD_WEEK, 0) == (-259200, 345600)
    # January 1970 is month index 1970*12 + 0.
    assert period_index(PERIOD_MONTH, 0) == 23640
    assert period_start(PERIOD_MONTH, 23640) == 0
    assert period_bounds(PERIOD_MONTH, 0) == (0, 2678400)  # 31 days


def test_weekday_and_hour_literals():
    assert weekday(1796083200) == 1  # 2026-12-01, Tuesday (0 = Monday)
    assert weekday(1794787200) == 0  # 2026-11-16, Monday
    assert weekday(1795181400) == 4  # 2026-11-20, Friday
    assert hour_of_day(1795181400) == 13
    assert hour_of_day(1795181400 + 1799) == 13  # 13:59:59
    assert hour_of_day(1795181400 + 1800) == 14  # 14:00:00


def test_week_starts_on_monday():
    assert period_start(PERIOD_WEEK, period_index(PERIOD_WEEK, 1794787200)) == 1794787200
    assert period_start(PERIOD_WEEK, period_index(PERIOD_WEEK, 1795181400)) == 1794787200
    assert period_bounds(PERIOD_WEEK, 1795181400) == (1794787200, 1794787200 + 604800)


def test_month_anchor_day_31_clamps_to_month_end():
    anchor = 1769817600  # 2026-01-31
    assert period_start(PERIOD_MONTH, 2026 * 12 + 1, anchor=anchor) == 1772236800  # Feb 28
    assert period_start(PERIOD_MONTH, 2026 * 12 + 2, anchor=anchor) == 1774915200  # Mar 31
    assert period_start(PERIOD_MONTH, 2026 * 12 + 3, anchor=anchor) == 1777507200  # Apr 30
    assert period_bounds(PERIOD_MONTH, 1772236800, anchor=anchor) == (1772236800, 1774915200)


def test_month_anchor_day_31_clamps_to_leap_day():
    anchor = 1706659200  # 2024-01-31
    assert period_start(PERIOD_MONTH, 2024 * 12 + 1, anchor=anchor) == 1709164800  # Feb 29


def test_fixed_periods():
    anchor, length = 1000000, 3600
    assert period_index(PERIOD_FIXED, anchor + 3599, anchor=anchor, length=length) == 0
    assert period_index(PERIOD_FIXED, anchor + 3600, anchor=anchor, length=length) == 1
    assert period_start(PERIOD_FIXED, 1, anchor=anchor, length=length) == 1003600
    assert period_bounds(PERIOD_FIXED, anchor + 7200, anchor=anchor, length=length) == (1007200, 1010800)
    assert next_period_start(PERIOD_FIXED, anchor + 3600, anchor=anchor, length=length) == 1007200


def test_next_period_start():
    assert next_period_start(PERIOD_DAY, 0) == 86400
    assert next_period_start(PERIOD_DAY, 86399) == 86400
    assert next_period_start(PERIOD_DAY, 86400) == 172800
    # Next month after January 1970 is February 1970 (28 days, 1970 not leap).
    assert next_period_start(PERIOD_MONTH, 0) == 2678400
    # With a day-31 anchor, the month after January 1970 is February 28, 1970.
    assert next_period_start(PERIOD_MONTH, 0, anchor=1769817600) == 5011200
    # The month after January 31, 2026 is February 28, 2026 (clamped).
    assert next_period_start(PERIOD_MONTH, 1769817600, anchor=1769817600) == 1772236800


def test_validation_errors():
    assert validate_period_spec(None) == "unknown period kind: None"
    assert validate_period_spec(99) == "unknown period kind: 99"
    assert validate_period_spec(PERIOD_FIXED) == "fixed period requires a length in seconds"
    assert validate_period_spec(PERIOD_FIXED, length=3599) is not None
    assert validate_period_spec(PERIOD_FIXED, length=31536001) is not None
    assert validate_period_spec(PERIOD_FIXED, length=3600) is None
    assert validate_period_spec(PERIOD_FIXED, length=31536000) is None
    assert validate_period_spec(PERIOD_DAY) is None
    assert validate_period_spec(PERIOD_DAY, length=3600) is not None
    assert validate_period_spec(PERIOD_DAY, anchor=-1) is not None
    assert validate_period_spec(PERIOD_MONTH, anchor=0) is None


def test_invalid_inputs_raise():
    with pytest.raises(PeriodError):
        period_index(PERIOD_FIXED, 999999, anchor=1000000, length=3600)
    with pytest.raises(PeriodError):
        period_index(99, 0)
    with pytest.raises(PeriodError):
        period_index(PERIOD_DAY, -1)
    with pytest.raises(PeriodError):
        period_start(PERIOD_MONTH, -1)
    with pytest.raises(PeriodError):
        period_bounds(PERIOD_FIXED, 0, anchor=0, length=0)


def test_datetime_oracle():
    """The implementation must agree with datetime across leap days and month ends."""
    for ts in range(1700000000, 1800000000, 7919):
        dt = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        assert weekday(ts) == dt.weekday()
        assert hour_of_day(ts) == dt.hour
        days = ts // 86400
        assert days_from_civil(*civil_from_days(days)) == days
        assert period_index(PERIOD_MONTH, ts) == dt.year * 12 + (dt.month - 1)
        assert period_start(PERIOD_MONTH, dt.year * 12 + (dt.month - 1)) == int(
            datetime.datetime(dt.year, dt.month, 1, tzinfo=datetime.timezone.utc).timestamp()
        )
