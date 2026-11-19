"""Period arithmetic for programmable payments, on block timestamps only.

Every time-based programmable-payment rule (standing payments, spending caps
that reset each period, weekday/hour windows) measures "now" as the block
header timestamp: UTC Unix seconds, already validated by chain_state as
non-decreasing and bounded in the future. Nothing here reads a clock.

CONSENSUS-FROZEN SURFACE
------------------------
This module is pure integer arithmetic: no datetime, no locale, no timezone
database, no floats. Two honest nodes on different platforms must compute the
same period index for the same timestamp, or they fork. Calendar math uses the
proleptic Gregorian days<->civil conversion (H. Hinnant's algorithm), valid for
every non-negative u64 timestamp the chain can carry.

Period kinds
------------
- ``PERIOD_FIXED``: ``length`` seconds anchored at ``anchor``;
  index = floor((ts - anchor) / length).
- ``PERIOD_DAY``: UTC calendar day; index = days since 1970-01-01.
- ``PERIOD_WEEK``: ISO week starting Monday 00:00 UTC; index 0 is the week of
  Monday 1969-12-29 (so 1970-01-01, a Thursday, is in week 0).
- ``PERIOD_MONTH``: UTC calendar month; index = year * 12 + (month - 1).
"""
from __future__ import annotations

from typing import Tuple

PERIOD_FIXED = 0
PERIOD_DAY = 1
PERIOD_WEEK = 2
PERIOD_MONTH = 3

PERIOD_KINDS = frozenset({PERIOD_FIXED, PERIOD_DAY, PERIOD_WEEK, PERIOD_MONTH})

SECONDS_PER_HOUR = 3_600
SECONDS_PER_DAY = 86_400
SECONDS_PER_WEEK = 7 * SECONDS_PER_DAY

MIN_FIXED_PERIOD_SECONDS = SECONDS_PER_HOUR
MAX_FIXED_PERIOD_SECONDS = 31_536_000

# 1970-01-01 is a Thursday: shifting by 3 days puts Monday at offset 0.
_EPOCH_WEEKDAY_SHIFT_DAYS = 3

_U64_MAX = 0xFFFFFFFFFFFFFFFF

ALL_WEEKDAYS_MASK = (1 << 7) - 1
ALL_HOURS_MASK = (1 << 24) - 1


class PeriodError(ValueError):
    """A period definition or timestamp the node cannot evaluate."""


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_ts(ts: int, name: str = "ts") -> None:
    if not _is_int(ts) or ts < 0 or ts > _U64_MAX:
        raise PeriodError(f"{name} must be an unsigned 64-bit integer")


# --- Gregorian calendar (integer only) ---------------------------------------


def civil_from_days(days: int) -> Tuple[int, int, int]:
    """Days since 1970-01-01 -> (year, month 1..12, day 1..31)."""
    z = days + 719_468
    era = z // 146_097
    doe = z - era * 146_097
    yoe = (doe - doe // 1_460 + doe // 36_524 - doe // 146_096) // 365
    y = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    d = doy - (153 * mp + 2) // 5 + 1
    m = mp + 3 if mp < 10 else mp - 9
    return (y + 1 if m <= 2 else y), m, d


def days_from_civil(year: int, month: int, day: int) -> int:
    """(year, month 1..12, day 1..31) -> days since 1970-01-01."""
    y = year - 1 if month <= 2 else year
    era = y // 400
    yoe = y - era * 400
    mp = month - 3 if month > 2 else month + 9
    doy = (153 * mp + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146_097 + doe - 719_468


def is_leap_year(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def days_in_month(year: int, month: int) -> int:
    if month == 2:
        return 29 if is_leap_year(year) else 28
    return 30 if month in (4, 6, 9, 11) else 31


# --- Calendar fields of a timestamp ------------------------------------------


def weekday(ts: int) -> int:
    """ISO weekday of a timestamp, 0 = Monday .. 6 = Sunday (UTC)."""
    _check_ts(ts)
    return (ts // SECONDS_PER_DAY + _EPOCH_WEEKDAY_SHIFT_DAYS) % 7


def hour_of_day(ts: int) -> int:
    """UTC hour 0..23 of a timestamp."""
    _check_ts(ts)
    return (ts % SECONDS_PER_DAY) // SECONDS_PER_HOUR


def in_time_window(ts: int, weekday_mask: int, hour_mask: int) -> bool:
    """True when ``ts`` falls on an allowed weekday AND an allowed hour.

    ``weekday_mask`` bit i (0 = Monday) and ``hour_mask`` bit h (0..23, UTC)
    mark the allowed slots. A zero mask allows nothing.
    """
    if not _is_int(weekday_mask) or not 0 <= weekday_mask <= ALL_WEEKDAYS_MASK:
        raise PeriodError("weekday_mask must fit in 7 bits")
    if not _is_int(hour_mask) or not 0 <= hour_mask <= ALL_HOURS_MASK:
        raise PeriodError("hour_mask must fit in 24 bits")
    return bool((weekday_mask >> weekday(ts)) & 1) and bool(
        (hour_mask >> hour_of_day(ts)) & 1
    )


# --- Period definitions -------------------------------------------------------


def validate_period(kind: int, length: int = 0) -> None:
    """Reject a period definition before it reaches consensus state."""
    if not _is_int(kind) or kind not in PERIOD_KINDS:
        raise PeriodError(f"unknown period kind: {kind!r}")
    if kind == PERIOD_FIXED:
        if not _is_int(length) or not (
            MIN_FIXED_PERIOD_SECONDS <= length <= MAX_FIXED_PERIOD_SECONDS
        ):
            raise PeriodError(
                "fixed period length must be between "
                f"{MIN_FIXED_PERIOD_SECONDS} and {MAX_FIXED_PERIOD_SECONDS} seconds"
            )
    elif length not in (0, None):
        raise PeriodError("calendar periods take no length")


def period_index(kind: int, ts: int, *, anchor: int = 0, length: int = 0) -> int:
    """Index of the period containing ``ts``.

    For ``PERIOD_FIXED`` a timestamp before ``anchor`` has no period and raises;
    callers check ``ts >= anchor`` (a time lock) before asking.
    """
    validate_period(kind, length)
    _check_ts(ts)
    if kind == PERIOD_FIXED:
        _check_ts(anchor, "anchor")
        if ts < anchor:
            raise PeriodError("timestamp is before the period anchor")
        return (ts - anchor) // length
    days = ts // SECONDS_PER_DAY
    if kind == PERIOD_DAY:
        return days
    if kind == PERIOD_WEEK:
        return (days + _EPOCH_WEEKDAY_SHIFT_DAYS) // 7
    year, month, _ = civil_from_days(days)
    return year * 12 + (month - 1)


def period_start(kind: int, index: int, *, anchor: int = 0, length: int = 0) -> int:
    """First second (inclusive) of period ``index``."""
    validate_period(kind, length)
    if not _is_int(index) or index < 0:
        raise PeriodError("period index must be a non-negative integer")
    if kind == PERIOD_FIXED:
        _check_ts(anchor, "anchor")
        return anchor + index * length
    if kind == PERIOD_DAY:
        return index * SECONDS_PER_DAY
    if kind == PERIOD_WEEK:
        return (index * 7 - _EPOCH_WEEKDAY_SHIFT_DAYS) * SECONDS_PER_DAY
    year, month0 = divmod(index, 12)
    return days_from_civil(year, month0 + 1, 1) * SECONDS_PER_DAY


def period_end(kind: int, index: int, *, anchor: int = 0, length: int = 0) -> int:
    """First second AFTER period ``index`` (exclusive end)."""
    return period_start(kind, index + 1, anchor=anchor, length=length)


def monthly_due_ts(month_index: int, day_of_month: int, second_of_day: int = 0) -> int:
    """Due time inside a calendar month; a missing day clamps to the last day.

    ``day_of_month`` 31 in April is due on April 30; 29..31 in a non-leap
    February is due on February 28.
    """
    if not _is_int(month_index) or month_index < 0:
        raise PeriodError("month index must be a non-negative integer")
    if not _is_int(day_of_month) or not 1 <= day_of_month <= 31:
        raise PeriodError("day_of_month must be 1..31")
    if not _is_int(second_of_day) or not 0 <= second_of_day < SECONDS_PER_DAY:
        raise PeriodError("second_of_day must be 0..86399")
    year, month0 = divmod(month_index, 12)
    day = min(day_of_month, days_in_month(year, month0 + 1))
    return days_from_civil(year, month0 + 1, day) * SECONDS_PER_DAY + second_of_day
