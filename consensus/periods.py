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
  A monthly schedule anchored on a day that does not exist in a month (e.g. the
  31st) runs on the **last calendar day** of that month, so the period that
  starts on the anchor day is clamped, not skipped.

Design reference: Bounty 01 design, section 1.2 (periods) and section 3
(bounds). Stage 1 of the delivery plan (section 6): this module plus the
credit classes (``consensus.credits``) and the sweep framework
(``consensus.sweep``) are the shared foundation the later stages build on.
"""
from __future__ import annotations

from typing import Optional, Tuple

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


# --- Period specs ------------------------------------------------------------


def validate_period_spec(
    kind: int, length: Optional[int] = None, anchor: Optional[int] = None
) -> Optional[str]:
    """Stateless admissibility of a period spec. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. ``anchor`` defaults to 0 (the Unix epoch) when omitted;
    it is only used by ``PERIOD_FIXED`` (the anchor) and ``PERIOD_MONTH``
    (the anchor's day-of-month, clamped); ``PERIOD_DAY`` and ``PERIOD_WEEK``
    ignore it.
    """
    if not _is_int(kind) or kind not in PERIOD_KINDS:
        return f"unknown period kind: {kind!r}"
    if anchor is not None and (not _is_int(anchor) or anchor < 0 or anchor > _U64_MAX):
        return "anchor must be an unsigned 64-bit integer"
    if kind == PERIOD_FIXED:
        if length is None:
            return "fixed period requires a length in seconds"
        if not _is_int(length):
            return "fixed period length must be an integer number of seconds"
        if not MIN_FIXED_PERIOD_SECONDS <= length <= MAX_FIXED_PERIOD_SECONDS:
            return (
                "fixed period length must be in "
                f"{MIN_FIXED_PERIOD_SECONDS}..{MAX_FIXED_PERIOD_SECONDS} seconds"
            )
    elif length is not None:
        return "calendar periods (day/week/month) take no length"
    return None


def _check_spec(kind: int, length: Optional[int], anchor: Optional[int]) -> None:
    problem = validate_period_spec(kind, length, anchor)
    if problem is not None:
        raise PeriodError(problem)


def _anchor_day(anchor: int) -> int:
    """Day-of-month (1..31) of the anchor timestamp, for monthly clamping."""
    return civil_from_days(anchor // SECONDS_PER_DAY)[2]


# --- Period index / bounds ---------------------------------------------------


def period_index(
    kind: int, ts: int, *, anchor: int = 0, length: Optional[int] = None
) -> int:
    """Index of the period containing ``ts``.

    Fixed periods count from ``anchor``; a timestamp before the anchor is a
    caller error (the object has not started yet). Calendar periods are
    absolute: day = days since the epoch, week = ISO weeks since the week of
    Monday 1969-12-29, month = year * 12 + (month - 1).
    """
    _check_spec(kind, length, anchor)
    _check_ts(ts)
    if kind == PERIOD_FIXED:
        if ts < anchor:
            raise PeriodError("timestamp is before the fixed period anchor")
        return (ts - anchor) // length  # type: ignore[operator]
    if kind == PERIOD_DAY:
        return ts // SECONDS_PER_DAY
    if kind == PERIOD_WEEK:
        return (ts // SECONDS_PER_DAY + _EPOCH_WEEKDAY_SHIFT_DAYS) // 7
    year, month, _day = civil_from_days(ts // SECONDS_PER_DAY)
    return year * 12 + (month - 1)


def period_start(
    kind: int, index: int, *, anchor: int = 0, length: Optional[int] = None
) -> int:
    """Start timestamp (inclusive) of period ``index``.

    For ``PERIOD_MONTH`` the start lands on the anchor's day-of-month,
    clamped to the last day of the target month when that day does not exist
    (a schedule anchored on the 31st starts February on the 28th, or the
    29th in a leap year).
    """
    _check_spec(kind, length, anchor)
    if not _is_int(index) or index < 0:
        raise PeriodError("period index must be a non-negative integer")
    if kind == PERIOD_FIXED:
        start = anchor + index * length  # type: ignore[operator]
        if start > _U64_MAX:
            raise PeriodError("period start overflows u64")
        return start
    if kind == PERIOD_DAY:
        return index * SECONDS_PER_DAY
    if kind == PERIOD_WEEK:
        return (index * 7 - _EPOCH_WEEKDAY_SHIFT_DAYS) * SECONDS_PER_DAY
    year, month = index // 12, index % 12 + 1
    day = min(_anchor_day(anchor), days_in_month(year, month))
    return days_from_civil(year, month, day) * SECONDS_PER_DAY


def period_bounds(
    kind: int, ts: int, *, anchor: int = 0, length: Optional[int] = None
) -> Tuple[int, int]:
    """``(start, end)`` of the period containing ``ts``; end is exclusive."""
    index = period_index(kind, ts, anchor=anchor, length=length)
    start = period_start(kind, index, anchor=anchor, length=length)
    end = period_start(kind, index + 1, anchor=anchor, length=length)
    return start, end


def next_period_start(
    kind: int, ts: int, *, anchor: int = 0, length: Optional[int] = None
) -> int:
    """Start timestamp of the first period that begins after ``ts``."""
    index = period_index(kind, ts, anchor=anchor, length=length)
    return period_start(kind, index + 1, anchor=anchor, length=length)
