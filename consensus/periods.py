"""Calendar period arithmetic for programmable payments (Bounty 01).

Pure functions over Unix timestamps (UTC). A *schedule* is an anchor
timestamp plus a period kind; period ``n`` is the half-open interval
``[period_start(n), period_start(n + 1))``. Every node must derive the
same boundaries from the same signed terms, so this module uses integer
arithmetic and the proleptic Gregorian calendar only -- never wall clock,
never local timezone, never floats.

Month semantics (issue #34): a monthly schedule keeps the anchor's
day-of-month, clamped to the target month's last day when that day does
not exist there, and returns to the signed day in the next month that has
it. A payment anchored on the 31st therefore runs on Feb 28/29 and again
on Mar 31 -- it never drifts to the 28th permanently.
"""

from __future__ import annotations

import calendar as _calendar
from datetime import datetime, timedelta, timezone

PERIOD_DAY = 0
PERIOD_WEEK = 1
PERIOD_MONTH = 2

SECONDS_PER_DAY = 86_400
SECONDS_PER_WEEK = 604_800

_PERIOD_KINDS = (PERIOD_DAY, PERIOD_WEEK, PERIOD_MONTH)


def _to_dt(ts: int) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _to_ts(dt: datetime) -> int:
    return int(dt.timestamp())


def _add_months_clamped(anchor: datetime, months: int) -> datetime:
    """``anchor`` shifted by ``months`` calendar months.

    The day is the anchor's own day-of-month, clamped to the last day of
    the target month. Because the day is always recomputed from the
    anchor (never from the previous period), clamping does not drift.
    """
    total = (anchor.year * 12 + (anchor.month - 1)) + months
    year, month0 = divmod(total, 12)
    month = month0 + 1
    last_day = _calendar.monthrange(year, month)[1]
    return anchor.replace(year=year, month=month, day=min(anchor.day, last_day))


def validate_schedule(anchor_ts: int, kind: int) -> None:
    if kind not in _PERIOD_KINDS:
        raise ValueError(f"unknown period kind: {kind!r}")
    if anchor_ts < 0:
        raise ValueError("anchor timestamp must be non-negative")


def period_start(anchor_ts: int, kind: int, index: int) -> int:
    """Start timestamp of period ``index`` (0-based) of a schedule."""
    validate_schedule(anchor_ts, kind)
    if index < 0:
        raise ValueError("period index must be non-negative")
    if kind == PERIOD_DAY:
        return anchor_ts + index * SECONDS_PER_DAY
    if kind == PERIOD_WEEK:
        return anchor_ts + index * SECONDS_PER_WEEK
    return _to_ts(_add_months_clamped(_to_dt(anchor_ts), index))


def period_end(anchor_ts: int, kind: int, index: int) -> int:
    """End timestamp (exclusive) of period ``index``."""
    return period_start(anchor_ts, kind, index + 1)


def period_index_at(anchor_ts: int, kind: int, ts: int) -> int:
    """Index of the period containing ``ts``; -1 before the anchor."""
    validate_schedule(anchor_ts, kind)
    if ts < anchor_ts:
        return -1
    if kind == PERIOD_DAY:
        return (ts - anchor_ts) // SECONDS_PER_DAY
    if kind == PERIOD_WEEK:
        return (ts - anchor_ts) // SECONDS_PER_WEEK
    anchor = _to_dt(anchor_ts)
    moment = _to_dt(ts)
    months = (moment.year - anchor.year) * 12 + (moment.month - anchor.month)
    # ``months`` is the candidate; the clamped start of that period can
    # still be after ``ts`` when the anchor day exceeds the moment's day.
    if period_start(anchor_ts, kind, months) > ts:
        months -= 1
    return months


def window_bounds(
    anchor_ts: int,
    kind: int,
    index: int,
    window_start_offset: int,
    window_end_offset: int,
) -> tuple[int, int]:
    """Execution window of one period: [start + start_offset, start + end_offset).

    Offsets are seconds from the period start and are validated against
    the period's real length, so a window can never reach into the next
    period (a month window is checked against that month's length).
    """
    start = period_start(anchor_ts, kind, index)
    end = period_end(anchor_ts, kind, index)
    if window_start_offset < 0:
        raise ValueError("window start offset must be non-negative")
    if window_end_offset <= window_start_offset:
        raise ValueError("window end offset must exceed window start offset")
    if start + window_end_offset > end:
        raise ValueError("window extends past the period end")
    return (start + window_start_offset, start + window_end_offset)


def is_within_window(
    anchor_ts: int,
    kind: int,
    index: int,
    window_start_offset: int,
    window_end_offset: int,
    ts: int,
) -> bool:
    lo, hi = window_bounds(anchor_ts, kind, index, window_start_offset, window_end_offset)
    return lo <= ts < hi
