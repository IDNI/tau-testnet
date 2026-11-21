"""Payout rules and grants survive a restart (Bounty 01, issue #63).

Both books are bound into consensus_meta_hash, so their rows are
written in the canonical transaction and restored exactly; a
corrupted row fails the restore loudly.
"""

import pytest

import chain_state
import db
from consensus.governance import ConsensusLifecycleManager
from consensus.grants import GrantBook, GrantTerms
from consensus.payouts import PayoutBook, PayoutTerms
from errors import DatabaseError

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
JAN1 = 1767225600
DEC1 = 1764547200
WEEK = 604800


def _payout_book():
    book = PayoutBook()
    state = book.install(PayoutTerms(
        owner=A, max_per_execution=1000, max_per_period=1500,
        recipients=(B, C), anchor_ts=JAN1, sequence_number=1))
    state.record_settlement("s1", 700)
    return book


def _grant_book():
    book = GrantBook()
    state = book.create(GrantTerms(
        sender=A, recipient=B, total=5000, cap_per_period=500,
        opens_at=DEC1, deadline=DEC1 + 4 * WEEK, sequence_number=1))
    state.apply_draw(500, ts=DEC1 + 60)
    return book


def _write(book, writer):
    db.init_db()
    with db._db_lock:
        writer({"rows": book.snapshot_rows()})
        db._db_conn.commit()


def test_payout_state_round_trip_through_db():
    book = _payout_book()
    _write(book, db._write_payout_rows)
    restored = PayoutBook.restore(db.load_payout_state())
    assert restored.root() == book.root()
    assert restored.get(A).already_settled("s1")


def test_grant_state_round_trip_through_db():
    book = _grant_book()
    _write(book, db._write_grant_rows)
    restored = GrantBook.restore(db.load_grant_state())
    assert restored.root() == book.root()
    gid = book.snapshot_rows()[0]["grant_id"]
    assert restored.get(gid).remaining == 4500


def test_restore_into_lifecycle_manager():
    _write(_payout_book(), db._write_payout_rows)
    _write(_grant_book(), db._write_grant_rows)
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._restore_payouts(lm)
    chain_state._restore_grants(lm)
    assert lm.payout_rules.root() == _payout_book().root()
    assert lm.grants.root() == _grant_book().root()


def test_corrupt_payout_row_refuses_restore():
    _write(_payout_book(), db._write_payout_rows)
    with db._db_lock:
        db._db_conn.execute(
            "UPDATE payout_rules_v1 SET max_per_period = max_per_period + 1"
        )
        db._db_conn.commit()
    lm = ConsensusLifecycleManager(active_validators=[A])
    with pytest.raises(DatabaseError):
        chain_state._restore_payouts(lm)


def test_corrupt_grant_row_refuses_restore():
    _write(_grant_book(), db._write_grant_rows)
    with db._db_lock:
        db._db_conn.execute(
            "UPDATE grants_v1 SET total = total + 1"
        )
        db._db_conn.commit()
    lm = ConsensusLifecycleManager(active_validators=[A])
    with pytest.raises(DatabaseError):
        chain_state._restore_grants(lm)
