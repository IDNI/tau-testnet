"""Calendar arithmetic for programmable payments (Bounty 01).

One time source for the whole bounty: the block header timestamp (UTC), the
same value the consensus rules read — never a node's wall clock. Period
arithmetic lives here, in pure functions over integer timestamps, so the
standing-payment book, the grant book and their tests all share exactly one
definition of "monthly".

CONSENSUS-FROZEN SEMANTICS
--------------------------
- Day = 86400 seconds, week = 604800 seconds, both anchored at the
  authorization's own anchor timestamp (no global epoch alignment).
- Month = a UTC calendar month. A signed day-of-month that does not exist in
  a given month clamps to that month's last day, and the following month
  returns to the signed day: a payment signed for the 31st is due on
  Feb 28/29, then on Mar 31 again — it never drifts to the 28th for good.
"""
from __future__ import annotations

import calendar as _calendar
from datetime import datetime, timezone
from typing import Tuple

SECONDS_PER_DAY = 86_400
SECONDS_PER_WEEK = 604_800


def _utc(ts: int) -> datetime:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc)


def _ts(dt: datetime) -> int:
    return int(dt.timestamp())


def last_day_of_month(year: int, month: int) -> int:
    """The number of days in the given UTC calendar month (28..31)."""
    return _calendar.monthrange(year, month)[1]


def clamped_day(year: int, month: int, signed_day: int) -> int:
    """The day a `signed_day` payment falls on in the given month.

    min(signed_day, last day of month): the 31st clamps to Feb 28/29, Apr 30,
    and stays the 31st in months that have one.
    """
    if not 1 <= signed_day <= 31:
        raise ValueError("signed_day must be in 1..31")
    return min(signed_day, last_day_of_month(year, month))


def monthly_due_ts(anchor_ts: int, signed_day: int, months_after: int) -> int:
    """Timestamp of the due date `months_after` months after the anchor month.

    The due moment keeps the anchor's time-of-day; only the calendar day is
    recomputed, by clamping the *signed* day into the target month. Because
    the clamp always starts from the signed day (never from the previous
    month's clamped result), the schedule returns to the signed day after a
    short month instead of drifting.
    """
    if months_after < 0:
        raise ValueError("months_after must be >= 0")
    anchor = _utc(anchor_ts)
    total = (anchor.year * 12 + (anchor.month - 1)) + months_after
    year, month0 = divmod(total, 12)
    month = month0 + 1
    day = clamped_day(year, month, signed_day)
    due = anchor.replace(year=year, month=month, day=day)
    return _ts(due)


def month_index_containing(anchor_ts: int, signed_day: int, ts: int) -> int:
    """Which monthly period (0-based from the anchor month) contains `ts`.

    Period k is [due(k), due(k+1)). A timestamp before the first due date is
    period -1 (nothing due yet).
    """
    if ts < monthly_due_ts(anchor_ts, signed_day, 0):
        return -1
    anchor = _utc(anchor_ts)
    probe = _utc(ts)
    k = (probe.year - anchor.year) * 12 + (probe.month - anchor.month)
    # due(k) is in the same calendar month as ts or the one before; settle by
    # direct comparison so month lengths never accumulate error.
    while monthly_due_ts(anchor_ts, signed_day, k) > ts:
        k -= 1
    while monthly_due_ts(anchor_ts, signed_day, k + 1) <= ts:
        k += 1
    return k


def period_bounds(anchor_ts: int, period_seconds: int, ts: int) -> Tuple[int, int]:
    """[start, end) of the fixed-length period containing `ts`.

    For day/week periods anchored at `anchor_ts` (period 0 starts at the
    anchor). Raises for a timestamp before the anchor.
    """
    if period_seconds <= 0:
        raise ValueError("period_seconds must be positive")
    if ts < anchor_ts:
        raise ValueError("timestamp is before the anchor")
    k = (ts - anchor_ts) // period_seconds
    start = anchor_ts + k * period_seconds
    return start, start + period_seconds
