"""Period arithmetic: integer-only results must match the reference calendar."""
import random
from datetime import datetime, timedelta, timezone

import pytest

from consensus import periods as P


def _dt(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def _ts(dt):
    return int(dt.replace(tzinfo=timezone.utc).timestamp())


RNG = random.Random(20261119)
SAMPLE_TS = [0, 1, 86_399, 86_400, 951_782_400, 4_102_444_800] + [
    RNG.randrange(0, 253_402_300_799) for _ in range(3000)
]


@pytest.mark.parametrize("ts", SAMPLE_TS[:300])
def test_civil_roundtrip_matches_datetime(ts):
    days = ts // 86_400
    d = _dt(ts)
    assert P.civil_from_days(days) == (d.year, d.month, d.day)
    assert P.days_from_civil(d.year, d.month, d.day) == days


def test_weekday_and_hour_match_datetime():
    for ts in SAMPLE_TS:
        d = _dt(ts)
        assert P.weekday(ts) == d.weekday()
        assert P.hour_of_day(ts) == d.hour


def test_calendar_period_index_matches_datetime():
    for ts in SAMPLE_TS:
        d = _dt(ts)
        assert P.period_index(P.PERIOD_DAY, ts) == ts // 86_400
        assert P.period_index(P.PERIOD_MONTH, ts) == d.year * 12 + d.month - 1
        monday = (d - timedelta(days=d.weekday())).replace(hour=0, minute=0, second=0)
        week = P.period_index(P.PERIOD_WEEK, ts)
        assert P.period_start(P.PERIOD_WEEK, week) == _ts(monday)


@pytest.mark.parametrize("kind", [P.PERIOD_DAY, P.PERIOD_WEEK, P.PERIOD_MONTH])
def test_period_bounds_contain_the_timestamp(kind):
    for ts in SAMPLE_TS:
        idx = P.period_index(kind, ts)
        assert P.period_start(kind, idx) <= ts < P.period_end(kind, idx)
        start = P.period_start(kind, idx)
        if start >= 0:  # ISO week 0 starts on 1969-12-29, before the epoch
            assert P.period_index(kind, start) == idx
        assert P.period_index(kind, P.period_end(kind, idx) - 1) == idx


def test_epoch_is_in_week_zero_starting_on_monday():
    assert P.period_index(P.PERIOD_WEEK, 0) == 0
    assert _dt(P.period_start(P.PERIOD_WEEK, 0)) == datetime(1969, 12, 29, tzinfo=timezone.utc)
    assert P.weekday(P.period_start(P.PERIOD_WEEK, 1)) == 0


def test_fixed_period_index_and_anchor():
    anchor = 1_764_547_200  # 2025-12-01T00:00Z
    length = 7 * 86_400
    assert P.period_index(P.PERIOD_FIXED, anchor, anchor=anchor, length=length) == 0
    assert P.period_index(P.PERIOD_FIXED, anchor + length - 1, anchor=anchor, length=length) == 0
    assert P.period_index(P.PERIOD_FIXED, anchor + length, anchor=anchor, length=length) == 1
    assert P.period_start(P.PERIOD_FIXED, 3, anchor=anchor, length=length) == anchor + 3 * length
    with pytest.raises(P.PeriodError):
        P.period_index(P.PERIOD_FIXED, anchor - 1, anchor=anchor, length=length)


@pytest.mark.parametrize(
    "year,month,day,expected_day",
    [
        (2026, 1, 31, 31),
        (2026, 2, 31, 28),
        (2028, 2, 31, 29),
        (2028, 2, 29, 29),
        (2100, 2, 29, 28),
        (2000, 2, 30, 29),
        (2026, 4, 31, 30),
        (2026, 12, 15, 15),
    ],
)
def test_monthly_due_clamps_to_last_day(year, month, day, expected_day):
    idx = year * 12 + month - 1
    due = P.monthly_due_ts(idx, day, 9 * 3600)
    assert _dt(due) == datetime(year, month, expected_day, 9, tzinfo=timezone.utc)
    assert P.period_index(P.PERIOD_MONTH, due) == idx


def test_time_window_masks():
    # 2026-12-01 is a Tuesday.
    ts = _ts(datetime(2026, 12, 1, 10, 30))
    tuesday = 1 << 1
    ten = 1 << 10
    assert P.in_time_window(ts, tuesday, ten)
    assert not P.in_time_window(ts, 1 << 0, ten)
    assert not P.in_time_window(ts, tuesday, 1 << 11)
    assert P.in_time_window(ts, P.ALL_WEEKDAYS_MASK, P.ALL_HOURS_MASK)
    assert not P.in_time_window(ts, 0, P.ALL_HOURS_MASK)
    with pytest.raises(P.PeriodError):
        P.in_time_window(ts, 1 << 7, ten)
    with pytest.raises(P.PeriodError):
        P.in_time_window(ts, tuesday, 1 << 24)


@pytest.mark.parametrize(
    "kind,length",
    [
        (P.PERIOD_FIXED, 0),
        (P.PERIOD_FIXED, P.MIN_FIXED_PERIOD_SECONDS - 1),
        (P.PERIOD_FIXED, P.MAX_FIXED_PERIOD_SECONDS + 1),
        (P.PERIOD_FIXED, True),
        (P.PERIOD_DAY, 60),
        (9, 0),
        ("1", 0),
    ],
)
def test_invalid_period_definitions_are_rejected(kind, length):
    with pytest.raises(P.PeriodError):
        P.validate_period(kind, length)


@pytest.mark.parametrize("bad", [-1, 2**64, 1.5, True, "0"])
def test_invalid_timestamps_are_rejected(bad):
    with pytest.raises(P.PeriodError):
        P.period_index(P.PERIOD_DAY, bad)


def test_no_float_or_datetime_in_consensus_module():
    import inspect

    src = inspect.getsource(P)
    assert "import datetime" not in src and "from datetime" not in src
    assert "float(" not in src and "time.time" not in src
