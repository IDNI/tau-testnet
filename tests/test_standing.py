"""Book-level tests for consensus/standing.py (Bounty 01, issue #34).

These exercise the standing-payment state machine. Engine-level tests
(balance, fee and o5 policy application) live with the engine wiring;
here a settle() call stands for "the engine moved the money", and the
absence of a settle() call is exactly what an insufficient-funds or
policy-refused execution looks like to the book.
"""

from datetime import datetime, timezone

import pytest

from consensus.periods import PERIOD_DAY, PERIOD_MONTH, SECONDS_PER_DAY
from consensus.standing import (
    END_FINAL_PERIOD,
    END_MAX_OCCURRENCES,
    END_MAX_TOTAL,
    StandingBook,
    StandingTerms,
)

MAXV = 10**12
PAYER = "aa" * 48
RECIPIENT = "bb" * 48
OTHER = "cc" * 48


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


def test_monthly_authorization_executes_at_most_once_per_period():
    terms = monthly_terms()
    book = book_with(terms)
    sid = terms.standing_id
    # January window: Jan 31 12:00 .. Feb 1 12:00.
    assert book.due_period(sid, ts(2026, 1, 31, 13)) == 0
    assert book.settle(sid, ts(2026, 1, 31, 13)) == (0, 1000)
    # A second execution in the same period finds nothing due.
    with pytest.raises(ValueError):
        book.settle(sid, ts(2026, 1, 31, 14))
    # February's period becomes due in its own window (Feb 28, clamped).
    assert book.due_period(sid, ts(2026, 2, 28, 12)) == 1
    assert book.settle(sid, ts(2026, 2, 28, 12)) == (1, 1000)


def test_monthly_on_31st_runs_on_last_day_of_short_month():
    terms = monthly_terms()
    book = book_with(terms)
    sid = terms.standing_id
    book.settle(sid, ts(2026, 1, 31, 12))
    # February 2026 has no 31st; the occurrence is due on the 28th.
    assert book.due_period(sid, ts(2026, 2, 27, 12)) is None
    assert book.due_period(sid, ts(2026, 2, 28, 12)) == 1
    book.settle(sid, ts(2026, 2, 28, 12))
    # March returns to the 31st -- no drift to the 28th.
    assert book.due_period(sid, ts(2026, 3, 30, 12)) is None
    assert book.due_period(sid, ts(2026, 3, 31, 12)) == 2


def test_execution_outside_window_or_twice_in_period_rejected():
    terms = monthly_terms()
    book = book_with(terms)
    sid = terms.standing_id
    with pytest.raises(ValueError):
        book.settle(sid, ts(2026, 1, 30, 12))  # before the first window
    with pytest.raises(ValueError):
        book.settle(sid, ts(2026, 2, 1, 12))  # after the January window
    book.settle(sid, ts(2026, 1, 31, 12))
    with pytest.raises(ValueError):
        book.settle(sid, ts(2026, 1, 31, 18))  # second time, same period


def test_cancel_prevents_all_later_executions():
    terms = monthly_terms()
    book = book_with(terms)
    sid = terms.standing_id
    book.settle(sid, ts(2026, 1, 31, 12))
    book.cancel(sid, PAYER)
    assert book.get(sid) is None
    assert book.due_period(sid, ts(2026, 2, 28, 12)) is None
    with pytest.raises(ValueError):
        book.settle(sid, ts(2026, 2, 28, 12))


def test_only_the_payer_can_cancel():
    terms = monthly_terms()
    book = book_with(terms)
    with pytest.raises(ValueError):
        book.cancel(terms.standing_id, OTHER)


def test_unsettled_occurrence_stays_due_in_window_then_lapses_no_catchup():
    # Insufficient funds at execution: the engine never calls settle().
    # The occurrence stays due for the rest of its window...
    terms = monthly_terms()
    book = book_with(terms)
    sid = terms.standing_id
    assert book.due_period(sid, ts(2026, 1, 31, 23)) == 0
    # ...lapses when the window closes, and never comes back: February's
    # window offers period 1 only, not a double collection.
    assert book.due_period(sid, ts(2026, 2, 28, 12)) == 1
    assert book.settle(sid, ts(2026, 2, 28, 12)) == (1, 1000)
    rec = book.get(sid)
    assert rec.executed_count == 1
    assert rec.total_executed == 1000


def test_end_condition_is_required_and_positive():
    book = StandingBook()
    with pytest.raises(ValueError):
        book.create(monthly_terms(end_kind=99), MAXV)
    with pytest.raises(ValueError):
        book.create(monthly_terms(end_value=0), MAXV)
    with pytest.raises(ValueError):
        book.create(monthly_terms(end_kind=END_MAX_TOTAL, end_value=999), MAXV)


def test_max_occurrences_completion_closes_the_authorization():
    terms = monthly_terms(end_value=2)
    book = book_with(terms)
    sid = terms.standing_id
    book.settle(sid, ts(2026, 1, 31, 12))
    assert book.get(sid) is not None
    book.settle(sid, ts(2026, 2, 28, 12))
    assert book.get(sid) is None  # completed and folded into resolved
    assert book.resolved_count == 1


def test_final_period_end_condition():
    terms = monthly_terms(end_kind=END_FINAL_PERIOD, end_value=0)
    book = book_with(terms)
    sid = terms.standing_id
    book.settle(sid, ts(2026, 1, 31, 12))
    assert book.get(sid) is None
    assert book.due_period(sid, ts(2026, 2, 28, 12)) is None


def test_update_supersedes_and_old_terms_cannot_execute():
    v1 = monthly_terms()
    book = book_with(v1)
    v2 = monthly_terms(amount=2000, sequence_number=2, supersedes=v1.standing_id)
    book.create(v2, MAXV)
    assert book.get(v1.standing_id) is None
    with pytest.raises(ValueError):
        book.settle(v1.standing_id, ts(2026, 1, 31, 12))
    assert book.settle(v2.standing_id, ts(2026, 1, 31, 12)) == (0, 2000)


def test_paid_for_period_fact():
    terms = monthly_terms()
    book = book_with(terms)
    sid = terms.standing_id
    assert not book.paid_for_period(sid, 0)
    book.settle(sid, ts(2026, 1, 31, 12))
    assert book.paid_for_period(sid, 0)
    assert not book.paid_for_period(sid, 1)


def test_create_rejects_self_payment_and_bad_window():
    book = StandingBook()
    with pytest.raises(ValueError):
        book.create(monthly_terms(recipient=PAYER), MAXV)
    with pytest.raises(ValueError):
        book.create(monthly_terms(window_end_offset=40 * SECONDS_PER_DAY), MAXV)


def test_daily_schedule_due_each_day():
    terms = monthly_terms(
        kind=PERIOD_DAY,
        anchor_ts=ts(2026, 3, 1, 9),
        window_end_offset=3600,
        end_value=3,
    )
    book = book_with(terms)
    sid = terms.standing_id
    assert book.due_period(sid, ts(2026, 3, 1, 9)) == 0
    book.settle(sid, ts(2026, 3, 1, 9))
    assert book.due_period(sid, ts(2026, 3, 2, 9)) == 1


# --- transaction parsing -----------------------------------------------------


def create_tx(**overrides):
    tx = {
        "tx_type": "standing_payment_create",
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
    tx.update(overrides)
    return tx


def test_parse_create_round_trips_terms():
    from consensus.standing import parse_standing_create

    terms = parse_standing_create(create_tx())
    assert terms.payer == PAYER
    assert terms.recipient == RECIPIENT
    assert terms.end_kind == END_MAX_OCCURRENCES
    assert terms.end_value == 12


def test_parse_create_requires_exactly_one_end_condition():
    from consensus.standing import StandingShapeError, parse_standing_create

    with pytest.raises(StandingShapeError):
        parse_standing_create(create_tx(max_total=12000))  # two ends
    tx = create_tx()
    del tx["max_occurrences"]
    with pytest.raises(StandingShapeError):
        parse_standing_create(tx)  # no end


def test_parse_create_rejects_malformed_fields():
    from consensus.standing import StandingShapeError, parse_standing_create

    with pytest.raises(StandingShapeError):
        parse_standing_create(create_tx(sender_pubkey="zz"))
    with pytest.raises(StandingShapeError):
        parse_standing_create(create_tx(amount=-5))
    with pytest.raises(StandingShapeError):
        parse_standing_create(create_tx(amount=True))


def test_parse_execute_and_cancel():
    from consensus.standing import parse_standing_cancel, parse_standing_execute

    terms = monthly_terms()
    sid_hex = terms.standing_id.hex()
    ex = parse_standing_execute(
        {"tx_type": "standing_payment_execute", "sender_pubkey": OTHER, "standing_id": sid_hex}
    )
    assert ex.executor_pubkey == OTHER
    assert ex.standing_id == terms.standing_id
    cx = parse_standing_cancel(
        {"tx_type": "standing_payment_cancel", "sender_pubkey": PAYER, "standing_id": sid_hex}
    )
    assert cx.payer_pubkey == PAYER


def test_validate_standing_shape_horizon():
    from consensus.standing import validate_standing_shape

    now = ts(2026, 1, 1)
    assert validate_standing_shape(monthly_terms(), now) is None
    far = monthly_terms(anchor_ts=ts(2028, 6, 1))
    assert validate_standing_shape(far, now) is not None


def test_snapshot_restore_round_trip():
    terms = monthly_terms()
    book = book_with(terms)
    book.settle(terms.standing_id, ts(2026, 1, 31, 12))
    rows = book.snapshot_rows()
    count, acc = book.resolved_state()
    back = StandingBook.restore(rows, count, acc)
    assert back.root() == book.root()
    rec = back.get(terms.standing_id)
    assert rec.executed_count == 1
    assert back.paid_for_period(terms.standing_id, 0)


def test_restore_refuses_id_mismatch():
    terms = monthly_terms()
    book = book_with(terms)
    rows = book.snapshot_rows()
    rows[0]["amount"] = 999  # stored fields no longer hash to the stored id
    with pytest.raises(ValueError):
        StandingBook.restore(rows, 0, bytes(32))
