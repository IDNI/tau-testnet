"""Integer UTC period arithmetic for programmable payments.

Consensus code paths call only this module for dates. It does not read the
node clock, a timezone database, or ``datetime``. A missing calendar day
(the 31st in a short month) clamps to the last day of that month, and the
clamp is always computed from the original anchor, so a short month does
not shift later months.

A day is 86,400 seconds and a week is 604,800 seconds, both measured from
the anchor the signer chose (an allowance's unlock, a standing payment's
first due time). A month is a real UTC calendar month from that anchor.
"""
from __future__ import annotations

DAY = 86_400
WEEK = 604_800
MAX_HORIZON = 4 * 366 * DAY
MIN_FIXED = 3_600
MAX_FIXED = 366 * DAY

PERIOD_KINDS = ("day", "week", "month", "fixed")


def month_length(year: int, month: int) -> int:
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    if month in (4, 6, 9, 11):
        return 30
    return 31


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Howard Hinnant's civil_from_days inverse. 1970-01-01 is day 0."""
    year -= month <= 2
    era = (year if year >= 0 else year - 399) // 400
    yoe = year - era * 400
    doy = (153 * (month - 3 if month > 2 else month + 9) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(z: int) -> tuple[int, int, int]:
    z += 719468
    era = (z if z >= 0 else z - 146096) // 146097
    doe = z - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    year = yoe + era * 400
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    year += month <= 2
    return year, month, day


def civil_to_unix(year: int, month: int, day: int, hour: int = 0,
                  minute: int = 0, second: int = 0) -> int:
    if not (1 <= month <= 12 and 1 <= day <= month_length(year, month)):
        raise ValueError(f"not a UTC date: {year}-{month}-{day}")
    if not (0 <= hour <= 23 and 0 <= minute <= 59 and 0 <= second <= 59):
        raise ValueError("not a UTC time")
    return (_days_from_civil(year, month, day) * DAY
            + hour * 3600 + minute * 60 + second)


def unix_parts(ts: int) -> tuple[int, int, int, int, int, int]:
    """(year, month, day, hour, minute, second) of a UTC unix timestamp."""
    ts = int(ts)
    days = ts // DAY
    sod = ts - days * DAY
    year, month, day = _civil_from_days(days)
    return year, month, day, sod // 3600, (sod % 3600) // 60, sod % 60


def weekday_monday0(ts: int) -> int:
    """0 = Monday ... 6 = Sunday. 1970-01-01 was a Thursday."""
    return (_days_from_civil_of(ts) + 3) % 7


def _days_from_civil_of(ts: int) -> int:
    return int(ts) // DAY


def add_months(ts: int, months: int) -> int:
    """The same clock time, ``months`` calendar months from ``ts``.

    The day clamps to the last day of the destination month. ``months`` is
    applied to the original timestamp, never to a previously clamped one.
    """
    year, month, day, hour, minute, second = unix_parts(ts)
    index = year * 12 + (month - 1) + int(months)
    year, month0 = divmod(index, 12)
    month = month0 + 1
    day = min(day, month_length(year, month))
    return civil_to_unix(year, month, day, hour, minute, second)


def period_length(kind: str, length: int = 0) -> int:
    """Seconds in one equal-length period. Months have no fixed length."""
    if kind == "day":
        return DAY
    if kind == "week":
        return WEEK
    if kind == "fixed":
        return int(length)
    raise ValueError(f"{kind} is not an equal-length period")


def period_index(kind: str, ts: int, anchor: int, length: int = 0) -> int:
    """Index of the period containing ``ts``, or -1 when ``ts`` is before ``anchor``.

    ``day`` / ``week`` / ``fixed`` are equal lengths counted from ``anchor``.
    ``month`` is the calendar month of ``anchor``: index 0 is
    ``[anchor, add_months(anchor, 1))``.
    """
    ts = int(ts)
    anchor = int(anchor)
    if ts < anchor:
        return -1
    if kind == "month":
        # At most the horizon, so a linear walk stays bounded.
        index = 0
        while index < 1200:
            nxt = add_months(anchor, index + 1)
            if ts < nxt:
                return index
            index += 1
        return index
    step = period_length(kind, length)
    if step <= 0:
        raise ValueError("period length must be positive")
    return (ts - anchor) // step


def period_start(kind: str, index: int, anchor: int, length: int = 0) -> int:
    if index < 0:
        raise ValueError("period index must be >= 0")
    if kind == "month":
        return add_months(anchor, index)
    return int(anchor) + index * period_length(kind, length)


def masks_allow(local_ts: int, weekday_mask: int, hour_mask: int) -> bool:
    """A zero mask means every day or every hour. Otherwise the bit must be set.

    Weekday bit 0 is Monday. Hour bit ``h`` is UTC hour ``h`` of ``local_ts``
    (the caller has already applied the signer's fixed offset).
    """
    if weekday_mask:
        if not (weekday_mask & (1 << weekday_monday0(local_ts))):
            return False
    if hour_mask:
        hour = (int(local_ts) % DAY) // 3600
        if not (hour_mask & (1 << hour)):
            return False
    return True


def any_moment_allowed(start: int, end: int, weekday_mask: int, hour_mask: int,
                       offset_quarters: int) -> bool:
    """Whether some instant in ``[start, end)`` passes both masks.

    Checked once per local hour that overlaps the window, so a one-hour
    window cannot hide between samples. The window is capped at the horizon.
    """
    if end <= start:
        return False
    if weekday_mask == 0 and hour_mask == 0:
        return True
    offset = int(offset_quarters) * 900
    local_start = start + offset
    local_end = min(end, start + MAX_HORIZON) + offset
    if local_end <= local_start:
        return False
    hour = local_start // 3600
    last = (local_end - 1) // 3600
    while hour <= last:
        probe = max(local_start, hour * 3600)
        if masks_allow(probe, weekday_mask, hour_mask):
            return True
        hour += 1
    return False
