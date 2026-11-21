"""Bounty 01, stage 3: the grant book's time conditions, pure state.

PR-4 claims only the time conditions of consensus/grants.py — a lock
(locked-until), a scheduled window, and the inactivity-shortened
deadline — each proved in isolation, at the book level. The refund
sweep and the combination cases are PR-5's: no test here settles a
refund or asserts a refund amount, and the inactivity test below
asserts draws refuse after the shortened deadline without touching
the sweep.

The cases:
- a locked grant refuses draws until the signed unlock time, then
  draws normally;
- a scheduled window admits only draws inside [start, end);
- inactivity shortens the effective deadline: a draw at the shortened
  deadline is refused, a draw just before it moves the deadline;
- time combinations that could never be drawn are refused at
  creation (a lock past the deadline, a window that never meets the
  drawable span, an inactivity trigger longer than the book's cap).
"""
from datetime import datetime, timezone

from consensus.grants import (
    MAX_INACTIVITY_SECONDS,
    GrantBook,
    GrantEntry,
)
from consensus.standing_payments import SCHEDULE_WEEKLY

FUNDER = "aa" * 48
BOB = "bb" * 48

WEEK = 604_800
DAY = 86_400
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
DEADLINE = DEC1 + 8 * WEEK


def _entry(**kw):
    fields = dict(
        funder_pubkey=FUNDER,
        beneficiary_pubkey=BOB,
        total_amount=5000,
        release_per_period=500,
        schedule_kind=SCHEDULE_WEEKLY,
        signed_day=0,
        start_ts=DEC1,
        deadline_ts=DEADLINE,
        locked_until_ts=0,
        window_start_ts=0,
        window_end_ts=0,
        inactivity_seconds=0,
        version=1,
    )
    fields.update(kw)
    return GrantEntry(**fields)


def _book_with(**kw):
    book = GrantBook()
    entry = _entry(**kw)
    book.create(entry, DEC1 - 100)
    return book, entry


# --- locked-until ------------------------------------------------------------------


def test_locked_grant_refuses_draws_until_the_lock_lifts():
    book, entry = _book_with(locked_until_ts=DEC1 + WEEK)
    gid = entry.grant_id
    # Locked: refused even though the first release has landed.
    refused = book.draw(gid, 100, DEC1 + 10)
    assert not refused.drawn
    assert "locked" in refused.reason
    assert book.accounting(gid)["drawn"] == 0
    # At the unlock time the same draw settles (1000 released by then).
    assert book.draw(gid, 100, DEC1 + WEEK + 10).drawn
    assert book.accounting(gid) == {
        "principal": 5000, "drawn": 100, "held": 4900, "refunded": 0,
    }


# --- scheduled window --------------------------------------------------------------


def test_scheduled_window_admits_only_draws_inside_it():
    book, entry = _book_with(
        window_start_ts=DEC1 + 2 * WEEK,
        window_end_ts=DEC1 + 3 * WEEK,
    )
    gid = entry.grant_id
    # Before the window opens: refused.
    refused = book.draw(gid, 100, DEC1 + WEEK + 10)
    assert not refused.drawn
    assert "window" in refused.reason
    # Inside the window: drawn (1500 released by then).
    assert book.draw(gid, 100, DEC1 + 2 * WEEK + 10).drawn
    # The last second inside the window still draws.
    assert book.draw(gid, 100, DEC1 + 3 * WEEK - 1).drawn
    # At the window's end (the window is [start, end)): refused again.
    refused = book.draw(gid, 100, DEC1 + 3 * WEEK + 10)
    assert not refused.drawn
    assert "window" in refused.reason
    assert book.accounting(gid)["drawn"] == 200


# --- inactivity-shortened deadline -------------------------------------------------


def test_inactivity_shortens_the_effective_deadline():
    book, entry = _book_with(inactivity_seconds=WEEK)
    gid = entry.grant_id
    # No draws yet: the last activity is the start, so the effective
    # deadline is one week after it — seven weeks before the signed one.
    assert book.deadline_of(gid) == DEC1 + WEEK
    # A draw AT the shortened deadline is refused (the refund half of
    # this moment is PR-5's; this test asserts only the refusal).
    refused = book.draw(gid, 500, DEC1 + WEEK)
    assert not refused.drawn
    assert "expired" in refused.reason
    # One second before it the week's release draws, and the deadline
    # moves with the activity.
    assert book.draw(gid, 500, DEC1 + WEEK - 1).drawn
    assert book.deadline_of(gid) == DEC1 + 2 * WEEK - 1
    # At the moved deadline a draw is refused again.
    refused = book.draw(gid, 1, DEC1 + 2 * WEEK - 1)
    assert not refused.drawn
    assert "expired" in refused.reason
    # Nothing was refunded by this test: the sweep is not its subject.
    assert book.accounting(gid)["refunded"] == 0


# --- creation refusals ---------------------------------------------------------------


def test_time_conditions_that_can_never_be_drawn_are_refused_at_creation():
    book = GrantBook()
    cases = [
        # The lock runs past the deadline: no drawable moment exists.
        _entry(locked_until_ts=DEADLINE + WEEK),
        # The window has zero width.
        _entry(window_start_ts=DEC1 + WEEK, window_end_ts=DEC1 + WEEK),
        # The window ends exactly when the lock lifts: it never meets
        # the drawable span.
        _entry(
            locked_until_ts=DEC1 + 3 * WEEK,
            window_start_ts=DEC1 + 2 * WEEK,
            window_end_ts=DEC1 + 3 * WEEK,
        ),
        # The window opens after the deadline.
        _entry(
            window_start_ts=DEADLINE + WEEK,
            window_end_ts=DEADLINE + 2 * WEEK,
        ),
        # The inactivity trigger exceeds the book's cap.
        _entry(inactivity_seconds=MAX_INACTIVITY_SECONDS + 1),
    ]
    for entry in cases:
        ok, reason = book.can_create(entry, DEC1 - 100)
        assert not ok, (entry, reason)
    # The cap itself is admissible, and so is a plain entry.
    ok, _ = book.can_create(
        _entry(inactivity_seconds=MAX_INACTIVITY_SECONDS), DEC1 - 100)
    assert ok
    ok, _ = book.can_create(_entry(), DEC1 - 100)
    assert ok
