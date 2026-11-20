"""Receive routes survive a restart (Bounty 01, issue #35).

The installed book is bound into consensus_meta_hash, so its rows are
written in the canonical transaction and restored exactly; a
corrupted row fails the restore loudly.
"""

import pytest

import chain_state
import db
from consensus.governance import ConsensusLifecycleManager
from consensus.routes import RouteBook, RouteTerms
from errors import DatabaseError

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48


def _populated_book():
    book = RouteBook()
    book.install(RouteTerms(owner=A, destination=B, bps=2000, sequence_number=1))
    book.install(RouteTerms(owner=C, destination=B, bps=500, min_incoming=10,
                            locked=True, expiry_ts=1_800_000_000,
                            sequence_number=2))
    return book


def _write(book):
    db.init_db()
    with db._db_lock:
        db._write_route_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()


def test_routes_state_round_trip_through_db():
    book = _populated_book()
    _write(book)
    restored = RouteBook.restore(db.load_route_state())
    assert restored.root() == book.root()
    assert restored.get(C).locked is True
    assert restored.get(C).min_incoming == 10


def test_restore_routes_into_lifecycle_manager():
    book = _populated_book()
    _write(book)
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._restore_routes(lm)
    assert lm.receive_routes.root() == book.root()


def test_corrupt_row_refuses_restore():
    book = _populated_book()
    _write(book)
    with db._db_lock:
        db._db_conn.execute(
            "UPDATE receive_routes_v1 SET bps = bps + 1"
        )
        db._db_conn.commit()
    lm = ConsensusLifecycleManager(active_validators=[A])
    with pytest.raises(DatabaseError):
        chain_state._restore_routes(lm)


def test_empty_book_round_trip():
    _write(RouteBook())
    assert db.load_route_state() == []
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._restore_routes(lm)
    assert lm.receive_routes.is_empty()
