"""Standing payments: schedule semantics, due windows, ends and persistence (#34)."""
import copy
from datetime import datetime, timezone

import pytest

from consensus import periods as P
from consensus import standing as S

PAYER = "a1" * 48
PAYEE = "b0" * 48
ANYONE = "c0" * 48


def at(*a):
    return int(datetime(*a, tzinfo=timezone.utc).timestamp())


NOW = at(2026, 11, 20)


def rent(**over):
    tx = {
        "sender_pubkey": PAYER, "recipient_pubkey": PAYEE, "amount": 1000,
        "sequence_number": 0, "period_kind": P.PERIOD_MONTH, "start_at": at(2026, 12, 1),
        "due_day": 31, "due_offset_seconds": 0, "window_seconds": 5 * 86_400,
        "max_occurrences": 12,
    }
    tx.update(over)
    return S.parse_standing_create(tx)


def booked(**over):
    book = S.StandingBook()
    terms = rent(**over)
    ok, reason = book.can_admit_create(terms, NOW)
    assert ok, reason
    return book, book.submit(terms)


def ex(sid, period, who=ANYONE):
    return S.StandingExecute(who, sid, period)


def month(y, m):
    return y * 12 + m - 1


def test_monthly_on_the_31st_clamps_and_executes_once_per_month():
    book, sid = booked()
    state = book.get(sid)
    # December: due on the 31st, window 5 days.
    assert state.due_period(at(2026, 12, 30)) is None
    assert state.due_period(at(2026, 12, 31)) == month(2026, 12)
    # Window crosses into January and is still the December occurrence.
    assert state.due_period(at(2027, 1, 2)) == month(2026, 12)
    book.record_execution(ex(sid, month(2026, 12)), at(2027, 1, 2))
    ok, reason = book.can_admit_execute(ex(sid, month(2026, 12)), at(2027, 1, 3))
    assert not ok and "no occurrence" in reason
    # February 2027 has 28 days: due on the 28th.
    assert book.get(sid).due_period(at(2027, 2, 27, 23)) is None
    assert book.get(sid).due_period(at(2027, 2, 28)) == month(2027, 2)


def test_missed_periods_are_skipped_not_caught_up():
    book, sid = booked()
    # Nobody executed December or January; in February only February is due.
    state = book.get(sid)
    assert state.due_period(at(2027, 1, 20)) is None
    assert state.due_period(at(2027, 2, 28, 1)) == month(2027, 2)
    ok, _ = book.can_admit_execute(ex(sid, month(2026, 12)), at(2027, 2, 28, 1))
    assert not ok
    book.record_execution(ex(sid, month(2027, 2)), at(2027, 2, 28, 1))
    assert book.get(sid).executions == 1 and book.get(sid).total_executed == 1000


def test_wrong_period_is_rejected():
    book, sid = booked()
    ok, reason = book.can_admit_execute(ex(sid, month(2027, 1)), at(2026, 12, 31))
    assert not ok and "not the due period" in reason


def test_max_occurrences_completes_the_payment():
    book, sid = booked(max_occurrences=2)
    book.record_execution(ex(sid, month(2026, 12)), at(2026, 12, 31))
    book.record_execution(ex(sid, month(2027, 1)), at(2027, 1, 31))
    assert book.get(sid) is None and book.resolved_count == 1


def test_end_at_stops_execution_and_resolves():
    end = at(2027, 2, 1)
    book, sid = booked(max_occurrences=0, end_at=end)
    assert book.get(sid).due_period(at(2027, 1, 31)) == month(2027, 1)
    assert book.get(sid).due_period(end) is None
    assert not book.has_due(end - 1) and book.has_due(end)
    ended = book.end_due(end)
    assert len(ended) == 1 and book.open_count() == 0


def test_weekly_and_fixed_schedules():
    # Every Monday 09:00 UTC, 2-hour window.
    book, sid = booked(period_kind=P.PERIOD_WEEK, due_day=0, due_offset_seconds=9 * 3600,
                       window_seconds=2 * 3600)
    mon = at(2026, 12, 7, 9, 30)
    p = book.get(sid).due_period(mon)
    assert p is not None and P.weekday(mon) == 0
    assert book.get(sid).due_period(at(2026, 12, 7, 11, 0)) is None
    # Fixed 10-day period anchored at start.
    start = at(2026, 12, 1)
    book2, sid2 = booked(period_kind=P.PERIOD_FIXED, period_seconds=10 * 86_400, due_day=0,
                         start_at=start, window_seconds=86_400)
    assert book2.get(sid2).due_period(start) == 0
    assert book2.get(sid2).due_period(start + 86_400) is None
    assert book2.get(sid2).due_period(start + 10 * 86_400) == 1


def test_first_period_skips_a_due_point_before_start():
    # Monthly on the 1st, starting Dec 15: December's due point (Dec 1) is
    # before start, so the first occurrence is January 1.
    book, sid = booked(due_day=1, start_at=at(2026, 12, 15))
    assert book.get(sid).due_period(at(2026, 12, 15)) is None
    assert book.get(sid).due_period(at(2027, 1, 1)) == month(2027, 1)
    assert book.get(sid).next_due_at(at(2026, 12, 20)) == at(2027, 1, 1)


@pytest.mark.parametrize("over,needle", [
    ({"amount": 0}, "amount"),
    ({"recipient_pubkey": PAYER}, "differ"),
    ({"max_occurrences": 0}, "end is required"),
    ({"max_occurrences": S.MAX_OCCURRENCES + 1}, "max_occurrences"),
    ({"window_seconds": 60}, "window_seconds"),
    ({"window_seconds": 29 * 86_400}, "window_seconds"),
    ({"due_day": 0}, "due_day"),
    ({"due_day": 32}, "due_day"),
    ({"due_offset_seconds": 86_400}, "due_offset"),
    ({"period_kind": P.PERIOD_WEEK}, "only for monthly"),
    ({"period_kind": 7}, "period"),
    ({"end_at": NOW - 1}, "end_at"),
    ({"start_at": NOW + S.MAX_STANDING_HORIZON_SECONDS + 1}, "too far ahead"),
])
def test_invalid_terms(over, needle):
    reason = S.validate_standing_terms(rent(**over), NOW)
    assert reason and needle in reason


def test_cancel_only_by_payer():
    book, sid = booked()
    assert not book.can_admit_cancel(S.StandingCancel(PAYEE, sid), NOW)[0]
    assert book.can_admit_cancel(S.StandingCancel(PAYER, sid), NOW)[0]
    book.cancel(sid)
    assert book.open_count() == 0
    assert not book.can_admit_execute(ex(sid, month(2026, 12)), at(2026, 12, 31))[0]


def test_id_binds_every_term_and_root_tracks_state():
    base = rent().standing_id
    for k, v in [("amount", 1001), ("recipient_pubkey", ANYONE), ("due_day", 30),
                 ("window_seconds", 86_400), ("max_occurrences", 11), ("sequence_number", 1),
                 ("start_at", at(2026, 12, 2)), ("end_at", at(2028, 1, 1))]:
        assert rent(**{k: v}).standing_id != base, k
    book, sid = booked()
    r0 = book.root()
    book.record_execution(ex(sid, month(2026, 12)), at(2026, 12, 31))
    assert book.root() != r0


def test_restore_roundtrip_and_tamper():
    book, sid = booked()
    book.record_execution(ex(sid, month(2026, 12)), at(2026, 12, 31))
    state = {"rows": book.snapshot_rows(), "resolved_count": 0, "resolved_acc": "00" * 32}
    assert S.load_standing_book(state).root() == book.root()
    state["rows"][0]["amount"] = 1
    with pytest.raises(ValueError):
        S.load_standing_book(state)


def test_deepcopy_independent():
    book, sid = booked()
    clone = copy.deepcopy(book)
    clone.record_execution(ex(sid, month(2026, 12)), at(2026, 12, 31))
    assert book.get(sid).executions == 0 and clone.get(sid).executions == 1
