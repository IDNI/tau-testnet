"""Unit tests for consensus/periods.py (Bounty 01 schedule arithmetic)."""

from datetime import datetime, timezone

import pytest

from consensus.periods import (
    PERIOD_DAY,
    PERIOD_MONTH,
    PERIOD_WEEK,
    SECONDS_PER_DAY,
    SECONDS_PER_WEEK,
    is_within_window,
    period_end,
    period_index_at,
    period_start,
    window_bounds,
)


def ts(year, month, day, hour=0, minute=0, second=0):
    return int(datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp())


def test_monthly_on_31st_runs_on_last_day_of_short_month():
    # Named case 4 of the Bounty 01 design, at the arithmetic level:
    # anchored Jan 31 -> Feb runs on its last day, Mar returns to the 31st.
    anchor = ts(2026, 1, 31, 12)
    assert period_start(anchor, PERIOD_MONTH, 0) == ts(2026, 1, 31, 12)
    assert period_start(anchor, PERIOD_MONTH, 1) == ts(2026, 2, 28, 12)
    assert period_start(anchor, PERIOD_MONTH, 2) == ts(2026, 3, 31, 12)
    assert period_start(anchor, PERIOD_MONTH, 3) == ts(2026, 4, 30, 12)
    assert period_start(anchor, PERIOD_MONTH, 4) == ts(2026, 5, 31, 12)


def test_monthly_31st_leap_year_february_has_29_days():
    anchor = ts(2028, 1, 31)
    assert period_start(anchor, PERIOD_MONTH, 1) == ts(2028, 2, 29)
    assert period_start(anchor, PERIOD_MONTH, 2) == ts(2028, 3, 31)


def test_monthly_anchor_on_30th_clamps_only_in_february():
    anchor = ts(2026, 1, 30)
    assert period_start(anchor, PERIOD_MONTH, 1) == ts(2026, 2, 28)
    assert period_start(anchor, PERIOD_MONTH, 2) == ts(2026, 3, 30)


def test_period_index_at_month_boundaries():
    anchor = ts(2026, 1, 31, 12)
    assert period_index_at(anchor, PERIOD_MONTH, anchor - 1) == -1
    assert period_index_at(anchor, PERIOD_MONTH, anchor) == 0
    assert period_index_at(anchor, PERIOD_MONTH, ts(2026, 2, 28, 12)) == 1
    assert period_index_at(anchor, PERIOD_MONTH, ts(2026, 2, 28, 11, 59)) == 0
    assert period_index_at(anchor, PERIOD_MONTH, ts(2026, 3, 31, 12)) == 2
    assert period_index_at(anchor, PERIOD_MONTH, ts(2027, 1, 31, 12)) == 12


def test_day_and_week_periods_are_fixed_length():
    anchor = ts(2026, 6, 15, 8, 30)
    assert period_start(anchor, PERIOD_DAY, 3) == anchor + 3 * SECONDS_PER_DAY
    assert period_start(anchor, PERIOD_WEEK, 2) == anchor + 2 * SECONDS_PER_WEEK
    assert period_end(anchor, PERIOD_DAY, 0) == anchor + SECONDS_PER_DAY
    assert period_index_at(anchor, PERIOD_WEEK, anchor + SECONDS_PER_WEEK - 1) == 0
    assert period_index_at(anchor, PERIOD_WEEK, anchor + SECONDS_PER_WEEK) == 1


def test_window_bounds_stay_inside_the_period():
    anchor = ts(2026, 1, 31, 12)
    lo, hi = window_bounds(anchor, PERIOD_MONTH, 1, 0, SECONDS_PER_DAY)
    assert lo == ts(2026, 2, 28, 12)
    assert hi == ts(2026, 3, 1, 12)
    assert is_within_window(anchor, PERIOD_MONTH, 1, 0, SECONDS_PER_DAY, lo)
    assert not is_within_window(anchor, PERIOD_MONTH, 1, 0, SECONDS_PER_DAY, hi)
    assert not is_within_window(anchor, PERIOD_MONTH, 1, 0, SECONDS_PER_DAY, lo - 1)


def test_window_may_not_cross_into_next_period():
    anchor = ts(2026, 1, 15)
    with pytest.raises(ValueError):
        # February 2026 has 28 days; a 29-day window from Feb 15 crosses.
        window_bounds(anchor, PERIOD_MONTH, 1, 0, 29 * SECONDS_PER_DAY)


def test_window_offsets_must_be_ordered():
    anchor = ts(2026, 1, 15)
    with pytest.raises(ValueError):
        window_bounds(anchor, PERIOD_DAY, 0, 100, 100)
    with pytest.raises(ValueError):
        window_bounds(anchor, PERIOD_DAY, 0, -1, 100)
