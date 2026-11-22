"""Catch-up semantics for standing payments (Bounty 01, issue #34).

Issue #34 defines the missed-period behavior: the recommended safe
default is that an expired period is skipped and one execution never
collects multiple missed payments -- unless the signed authorization
says otherwise. ``catch_up_limit`` is that signed otherwise: part of
the terms (and of the authorization id), it lets one execution also
settle up to that many lapsed periods, oldest first, under the same
end-condition rule a single execution has always used.

Book level here; the engine-level half (one transfer of the summed
amount) lives in tests/test_standing_apply.py.
"""

from datetime import datetime, timezone

import pytest

from consensus.periods import PERIOD_MONTH, SECONDS_PER_DAY
from consensus.standing import (
    END_FINAL_PERIOD,
    END_MAX_OCCURRENCES,
    END_MAX_TOTAL,
    MAX_CATCH_UP_LIMIT,
    StandingBook,
    StandingTerms,
    parse_standing_create,
)

MAXV = 10**12
PAYER = "aa" * 48
RECIPIENT = "bb" * 48


def ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


def monthly_terms(**overrides):
    base = dict(
        payer=PAYER,
        recipient=RECIPIENT,
        amount=1000,
        kind=PERIOD_MONTH,
        anchor_ts=ts(2026, 1, 31, 12),
        window_start_offset=0,
        window_end_offset=SECONDS_PER_DAY,
        end_kind=END_MAX_OCCURRENCES,
        end_value=12,
        sequence_number=1,
    )
    base.update(overrides)
    return StandingTerms(**base)


def book_with(terms):
    book = StandingBook()
    book.create(terms, MAXV)
    return book


# Monthly windows: period 0 = Jan 31, 1 = Feb 28, 2 = Mar 31,
# 3 = Apr 30, 4 = May 31 (each window opens at 12:00 on that day).


def test_default_terms_skip_lapsed_periods_forever():
    terms = monthly_terms()
    assert terms.catch_up_limit == 0
    book = book_with(terms)
    sid = terms.standing_id
    # Period 0 is never executed; at period 1 only period 1 is due.
    assert book.due_periods(sid, ts(2026, 2, 28, 12)) == [1]
    assert book.settle(sid, ts(2026, 2, 28, 12)) == ((1,), 1000)
    assert not book.paid_for_period(sid, 0)
    # And it stays skipped: period 2's execution does not revive it.
    assert book.due_periods(sid, ts(2026, 3, 31, 12)) == [2]
    book.settle(sid, ts(2026, 3, 31, 12))
    assert not book.paid_for_period(sid, 0)


def test_catch_up_collects_oldest_lapsed_first_within_the_signed_limit():
    terms = monthly_terms(catch_up_limit=2)
    book = book_with(terms)
    sid = terms.standing_id
    # Periods 0, 1, 2 lapse unexecuted. At period 3 the execution
    # collects the two oldest lapsed plus the due period.
    assert book.due_periods(sid, ts(2026, 4, 30, 12)) == [0, 1, 3]
    assert book.settle(sid, ts(2026, 4, 30, 12)) == ((0, 1, 3), 3000)
    assert book.paid_for_period(sid, 0)
    assert book.paid_for_period(sid, 1)
    assert not book.paid_for_period(sid, 2)
    assert book.paid_for_period(sid, 3)
    # The remaining lapsed period rides on the next execution.
    assert book.due_periods(sid, ts(2026, 5, 31, 12)) == [2, 4]
    assert book.settle(sid, ts(2026, 5, 31, 12)) == ((2, 4), 2000)
    assert book.paid_for_period(sid, 2)


def test_catch_up_never_exceeds_the_occurrence_cap():
    terms = monthly_terms(catch_up_limit=12, end_value=3)
    book = book_with(terms)
    sid = terms.standing_id
    # Periods 0 and 1 lapsed; period 2's execution fills the cap
    # exactly and the authorization completes.
    assert book.due_periods(sid, ts(2026, 3, 31, 12)) == [0, 1, 2]
    assert book.settle(sid, ts(2026, 3, 31, 12)) == ((0, 1, 2), 3000)
    assert book.get(sid) is None


def test_catch_up_can_exhaust_the_cap_before_the_due_period():
    terms = monthly_terms(catch_up_limit=12, end_value=2)
    book = book_with(terms)
    sid = terms.standing_id
    # Three periods lapsed and the cap is two: the two oldest settle,
    # the authorization completes, the due period is left unsettled.
    assert book.due_periods(sid, ts(2026, 4, 30, 12)) == [0, 1]
    assert book.settle(sid, ts(2026, 4, 30, 12)) == ((0, 1), 2000)
    assert book.get(sid) is None


def test_catch_up_stops_at_the_max_total_like_a_single_execution():
    terms = monthly_terms(
        catch_up_limit=12, end_kind=END_MAX_TOTAL, end_value=2000
    )
    book = book_with(terms)
    sid = terms.standing_id
    # Periods 0 and 1 fill the total cap; period 2 is not admitted.
    assert book.due_periods(sid, ts(2026, 3, 31, 12)) == [0, 1]
    assert book.settle(sid, ts(2026, 3, 31, 12)) == ((0, 1), 2000)
    assert book.get(sid) is None


def test_catch_up_with_final_period_end():
    terms = monthly_terms(
        catch_up_limit=5, end_kind=END_FINAL_PERIOD, end_value=2
    )
    book = book_with(terms)
    sid = terms.standing_id
    assert book.due_periods(sid, ts(2026, 3, 31, 12)) == [0, 1, 2]
    assert book.settle(sid, ts(2026, 3, 31, 12)) == ((0, 1, 2), 3000)
    assert book.get(sid) is None


def test_catch_up_limit_is_bounded_by_the_protocol_cap():
    terms = monthly_terms(catch_up_limit=MAX_CATCH_UP_LIMIT + 1)
    book = StandingBook()
    with pytest.raises(ValueError):
        book.create(terms, MAXV)
    # The cap itself is admissible.
    book_with(monthly_terms(catch_up_limit=MAX_CATCH_UP_LIMIT))


def test_catch_up_limit_is_part_of_the_signed_identity():
    plain = monthly_terms()
    opted = monthly_terms(catch_up_limit=2)
    assert plain.standing_id != opted.standing_id


def test_create_tx_catch_up_limit_parsing():
    tx = {
        "sender_pubkey": PAYER,
        "recipient_pubkey": RECIPIENT,
        "amount": 1000,
        "sequence_number": 1,
        "period_kind": PERIOD_MONTH,
        "anchor_timestamp": ts(2026, 1, 31, 12),
        "window_start_offset": 0,
        "window_end_offset": SECONDS_PER_DAY,
        "max_occurrences": 12,
    }
    # Absent means the recommended default: no catch-up.
    assert parse_standing_create(tx).catch_up_limit == 0
    tx["catch_up_limit"] = 3
    assert parse_standing_create(tx).catch_up_limit == 3


def test_snapshot_round_trip_keeps_the_catch_up_terms():
    terms = monthly_terms(catch_up_limit=3)
    book = book_with(terms)
    rows = book.snapshot_rows()
    assert rows[0]["catch_up_limit"] == 3
    restored = StandingBook.restore(rows, 0, bytes(32))
    rec = restored.get(terms.standing_id)
    assert rec is not None
    assert rec.terms == terms
    # Behavior survives the round trip, not just the field.
    assert restored.due_periods(terms.standing_id, ts(2026, 3, 31, 12)) == [0, 1, 2]
