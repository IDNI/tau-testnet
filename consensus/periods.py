"""Calendar period arithmetic over consensus block timestamps (issue #34).

Programmable payments measure time in calendar periods against the block
timestamp (consensus UTC, validated non-decreasing and bounded by
MAX_BLOCK_FUTURE_DRIFT_SECONDS), never against an outside clock. This module
is the single source of that arithmetic: pure integer/datetime functions of
the timestamp, identical on every node.

Two period kinds:

- ``week``: fixed 7-day periods anchored at the schedule's start timestamp.
  Period k is [start + k*7d, start + (k+1)*7d).
- ``month``: calendar months anchored on the start's day-of-month. A monthly
  schedule anchored on the 31st executes on the last day of a shorter month
  (Jan 31 -> Feb 28 -> Mar 31): the anchor day does not drift after a short
  month, because every period start is computed from the ORIGINAL anchor,
  never from the previous period's start.

Bounds are half-open: a period is [start, end), and the end of period k is
the start of period k+1.
"""
from __future__ import annotations

import calendar as _calendar
from datetime import datetime, timezone
from typing import Tuple

PERIOD_WEEK = "week"
PERIOD_MONTH = "month"
PERIOD_KINDS = frozenset({PERIOD_WEEK, PERIOD_MONTH})

SECONDS_PER_WEEK = 7 * 24 * 60 * 60


def _check(kind: str, anchor_ts: int, index: int) -> None:
    if kind not in PERIOD_KINDS:
        raise ValueError(f"unknown period kind: {kind!r}")
    if not isinstance(anchor_ts, int) or isinstance(anchor_ts, bool) or anchor_ts < 0:
        raise ValueError("anchor_ts must be a non-negative integer timestamp")
    if not isinstance(index, int) or isinstance(index, bool) or index < 0:
        raise ValueError("period index must be a non-negative integer")


def _month_start_ts(anchor: datetime, months_ahead: int) -> int:
    """Start of the anchor's month + `months_ahead`, day clamped, no drift."""
    total = (anchor.year * 12 + (anchor.month - 1)) + months_ahead
    year, month0 = divmod(total, 12)
    month = month0 + 1
    last_day = _calendar.monthrange(year, month)[1]
    day = min(anchor.day, last_day)
    dt = datetime(
        year, month, day,
        anchor.hour, anchor.minute, anchor.second,
        tzinfo=timezone.utc,
    )
    return int(dt.timestamp())


def period_start(kind: str, anchor_ts: int, index: int) -> int:
    """Inclusive start timestamp of period `index` for a schedule anchored at
    `anchor_ts` (the schedule's first period start)."""
    _check(kind, anchor_ts, index)
    if kind == PERIOD_WEEK:
        return anchor_ts + index * SECONDS_PER_WEEK
    anchor = datetime.fromtimestamp(anchor_ts, tz=timezone.utc)
    return _month_start_ts(anchor, index)


def period_bounds(kind: str, anchor_ts: int, index: int) -> Tuple[int, int]:
    """Half-open [start, end) bounds of period `index`."""
    start = period_start(kind, anchor_ts, index)
    end = period_start(kind, anchor_ts, index + 1)
    return start, end


def period_index_at(kind: str, anchor_ts: int, ts: int) -> int:
    """Index of the period containing `ts`, or -1 when `ts` precedes the
    anchor. Pure function of the anchor and `ts`."""
    _check(kind, anchor_ts, 0)
    if ts < anchor_ts:
        return -1
    if kind == PERIOD_WEEK:
        return (ts - anchor_ts) // SECONDS_PER_WEEK
    anchor = datetime.fromtimestamp(anchor_ts, tz=timezone.utc)
    moment = datetime.fromtimestamp(ts, tz=timezone.utc)
    candidate = (moment.year - anchor.year) * 12 + (moment.month - anchor.month)
    # The clamped day can shift the boundary within the candidate month;
    # settle it against the exact bounds.
    start, end = period_bounds(kind, anchor_ts, candidate)
    if ts < start:
        return candidate - 1
    if ts >= end:
        return candidate + 1
    return candidate
