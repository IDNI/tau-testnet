"""Calendar period arithmetic (Bounty 01, stages 4/5).

Written only from the public APIs in ``consensus/periods.py``.
Deterministic, no native bindings.
"""
from __future__ import annotations

from datetime import datetime, timezone

from consensus.periods import period_bounds, period_index_at, period_start

SECONDS_PER_WEEK = 7 * 24 * 60 * 60


def ts(year: int, month: int, day: int, hour: int = 0) -> int:
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


# Anchor for the monthly tests: Jan 31 2027, 12:00 UTC.
ANCHOR_31ST = ts(2027, 1, 31, hour=12)


def test_monthly_anchor_31st_clamps_and_does_not_drift():
    expected = [
        ts(2027, 1, 31, hour=12),
        ts(2027, 2, 28, hour=12),
        ts(2027, 3, 31, hour=12),
        ts(2027, 4, 30, hour=12),
        ts(2027, 5, 31, hour=12),
    ]
    for index, want in enumerate(expected):
        assert period_start("month", ANCHOR_31ST, index) == want
    # Index 0 is the anchor itself.
    assert period_start("month", ANCHOR_31ST, 0) == ANCHOR_31ST


def test_period_index_at_month_boundaries():
    assert period_index_at("month", ANCHOR_31ST, ANCHOR_31ST) == 0
    assert period_index_at("month", ANCHOR_31ST, ts(2027, 2, 27, hour=12)) == 0
    assert period_index_at("month", ANCHOR_31ST, ts(2027, 2, 28, hour=12)) == 1
    assert period_index_at("month", ANCHOR_31ST, ts(2027, 3, 30, hour=12)) == 1
    assert period_index_at("month", ANCHOR_31ST, ts(2027, 3, 31, hour=12)) == 2
    assert period_index_at("month", ANCHOR_31ST, ANCHOR_31ST - 1) == -1


def test_week_periods_are_anchored_seven_day_windows():
    anchor = ts(2026, 12, 1)
    for index in range(4):
        start, end = period_bounds("week", anchor, index)
        assert end - start == 604800
        assert end - start == SECONDS_PER_WEEK
        assert start == anchor + index * SECONDS_PER_WEEK
    assert period_index_at("week", anchor, anchor + 13 * 24 * 60 * 60) == 1
    assert period_index_at("week", anchor, anchor + 14 * 24 * 60 * 60) == 2


def test_period_bounds_are_half_open_and_contiguous():
    anchors = {"week": ts(2026, 12, 1), "month": ANCHOR_31ST}
    for kind, anchor in anchors.items():
        bounds = [period_bounds(kind, anchor, i) for i in range(7)]
        for i in range(6):
            start, end = bounds[i]
            next_start, _next_end = bounds[i + 1]
            assert start < end
            assert end == next_start
