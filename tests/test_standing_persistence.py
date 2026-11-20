"""Standing payments survive a restart (Bounty 01).

The open book and the resolved commitment are bound into
consensus_meta_hash, so the rows and the commitment are written in the
canonical transaction and restored exactly; a corrupted row fails the
restore loudly.
"""

import pytest

import chain_state
import db
from consensus.governance import ConsensusLifecycleManager
from consensus.periods import PERIOD_MONTH, SECONDS_PER_DAY
from consensus.standing import END_MAX_OCCURRENCES, StandingBook, StandingTerms
from errors import DatabaseError

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = "aa" * 48
B = "bb" * 48


def _terms(**overrides):
    base = dict(
        payer=A,
        recipient=B,
        amount=1000,
        kind=PERIOD_MONTH,
        anchor_ts=1767220800,
        window_start_offset=0,
        window_end_offset=SECONDS_PER_DAY,
        end_kind=END_MAX_OCCURRENCES,
        end_value=12,
        sequence_number=1,
    )
    base.update(overrides)
    return StandingTerms(**base)


def _populated_book():
    book = StandingBook()
    t1 = _terms()
    book.create(t1, 10**12)
    book.settle(t1.standing_id, 1767220800 + 3600)
    t2 = _terms(amount=250, sequence_number=2)
    book.create(t2, 10**12)
    book.cancel(t2.standing_id, A)  # folds into the resolved commitment
    return book


def test_db_round_trip_restores_the_same_root():
    book = _populated_book()
    state = {
        "rows": book.snapshot_rows(),
        "resolved_count": book.resolved_count,
        "resolved_acc": book.resolved_acc.hex(),
    }
    db.init_db()
    with db._db_lock:
        db._write_standing_rows(state)
        db._db_conn.commit()
    rows, count, acc = db.load_standing_state()
    back = StandingBook.restore(rows, count, acc)
    assert back.root() == book.root()
    assert back.resolved_count == 1


def test_chain_state_restore_standings(tmp_path):
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.standing_payments = _populated_book()
    db.init_db()
    with db._db_lock:
        db._write_standing_rows(chain_state._standing_state(lm))
        db._db_conn.commit()
    fresh = ConsensusLifecycleManager(active_validators=[A])
    chain_state._restore_standings(fresh)
    assert fresh.standing_payments.root() == lm.standing_payments.root()


def test_restore_standings_refuses_corrupt_rows():
    book = _populated_book()
    db.init_db()
    with db._db_lock:
        db._write_standing_rows(chain_state._standing_state(
            type("LM", (), {"standing_payments": book})()
        ))
        db._db_conn.execute(
            "UPDATE standing_payments_v1 SET amount = amount + 1"
        )
        db._db_conn.commit()
    fresh = ConsensusLifecycleManager(active_validators=[A])
    with pytest.raises(DatabaseError):
        chain_state._restore_standings(fresh)


def test_getstandingpayments_command_reports_next_due():
    import json

    from commands import getstandingpayments

    book = _populated_book()
    db.init_db()
    with db._db_lock:
        db._write_standing_rows({
            "rows": book.snapshot_rows(),
            "resolved_count": book.resolved_count,
            "resolved_acc": book.resolved_acc.hex(),
        })
        db._db_conn.commit()
    resp = getstandingpayments.execute(f"getstandingpayments {A}", None)
    payload = json.loads(resp) if isinstance(resp, str) else resp
    text = json.dumps(payload)
    assert "standing_payments" in text
    assert '"executed_count": 1' in text or '"executed_count":1' in text
    assert "next_due_period" in text
