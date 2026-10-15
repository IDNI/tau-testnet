"""Escrowed retractable transfers survive a restart, and fail atomically.

The open book and the resolved commitment are bound into `consensus_meta_hash`,
so a reload that disagrees with memory yields a state hash no peer shares. The
open rows and the resolved count/acc live in the canonical transaction; the
`retractable_events` history is node-local and filtered to the canonical chain.
"""
import json
import sqlite3

import pytest

import chain_state
import db
from consensus.governance import ConsensusLifecycleManager
from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    RetractableBook,
    RetractableEntry,
)
from consensus.state import TauStateSnapshot
from errors import DatabaseError

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48


def _entry(sender=A, recipient=B, amount=10, seq=0, kind=KIND_HEIGHT, at=100):
    return RetractableEntry(sender, recipient, amount, seq, kind, at)


def _seed(lm):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 500, B: 7})
    chain_state._sequence_numbers.update({A: 3})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    return lm


def _populated():
    lm = _seed(ConsensusLifecycleManager(active_validators=[A]))
    book = lm.retractable_transfers
    first = book.submit(_entry(seq=0, amount=10, at=100))
    book.submit(_entry(seq=1, amount=20, kind=KIND_TIME, at=1_900_000_000))
    book.submit(_entry(sender=C, recipient=A, seq=0, amount=5, at=120))
    book.submit(_entry(seq=2, amount=1, at=130))
    book.retract(first)
    book.release_due(130, 0)
    return lm


def _view(book):
    return (
        {rid: e for rid, e in book.open.items()},
        book.escrow_total(),
        book.resolved_state(),
        book.root(),
    )


def _reload():
    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


def test_open_set_escrow_and_resolved_commitment_round_trip(temp_database):
    lm = _populated()
    before = _view(lm.retractable_transfers)
    meta = lm.consensus_meta_hash()
    assert before[2][0] == 3 and len(before[0]) == 1

    reloaded = _reload()

    assert _view(reloaded.retractable_transfers) == before
    assert reloaded.consensus_meta_hash() == meta


def test_an_empty_book_reloads_empty_with_the_same_hash(temp_database):
    lm = _seed(ConsensusLifecycleManager(active_validators=[A]))
    meta = lm.consensus_meta_hash()

    reloaded = _reload()

    assert _view(reloaded.retractable_transfers) == _view(RetractableBook())
    assert reloaded.consensus_meta_hash() == meta


def test_the_tables_hold_exactly_the_open_rows(temp_database):
    lm = _populated()
    chain_state.commit_state_to_db("head-hash", 20)
    rows = db._db_conn.execute(
        "SELECT retractable_id, sender_pubkey, recipient_pubkey, amount, "
        "sequence_number, release_kind, release_at FROM retractable_transfers_v1"
    ).fetchall()
    expected = [
        (r["retractable_id"], r["sender_pubkey"], r["recipient_pubkey"], r["amount"],
         r["sequence_number"], r["release_kind"], r["release_at"])
        for r in lm.retractable_transfers.snapshot_rows()
    ]
    assert sorted(tuple(r) for r in rows) == sorted(expected)

    stored = json.loads(db.get_chain_state_value("retractable_resolved", "{}"))
    count, acc = lm.retractable_transfers.resolved_state()
    assert stored == {"count": count, "acc": acc.hex()}


def test_a_later_commit_replaces_the_rows(temp_database):
    lm = _populated()
    chain_state.commit_state_to_db("head-1", 20)
    lm.retractable_transfers.retract(next(iter(lm.retractable_transfers.open)))
    chain_state.commit_state_to_db("head-2", 21)

    reloaded = _reload()

    assert not reloaded.retractable_transfers.open
    assert reloaded.retractable_transfers.resolved_count == 4


@pytest.mark.parametrize("column,value", [
    ("amount", 11),
    ("sequence_number", 9),
    ("recipient_pubkey", "cc" * 48),
    ("release_at", 101),
])
def test_a_tampered_row_refuses_to_load(temp_database, column, value):
    lm = _populated()
    chain_state.commit_state_to_db("head-hash", 20)
    with db._db_conn as conn:
        conn.execute(f"UPDATE retractable_transfers_v1 SET {column} = ?", (value,))

    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="retractable"):
        chain_state.load_state_from_db()


def test_a_duplicate_stored_row_refuses_to_load():
    entry = _entry()
    row = (entry.retractable_id, A, B, 10, 0, KIND_HEIGHT, 100)
    with pytest.raises(ValueError, match="duplicate"):
        RetractableBook.restore([row, row], 0, bytes(32))


# --- atomicity ---------------------------------------------------------------

def _db_state():
    conn = db._db_conn
    return {
        "accounts": sorted(tuple(r) for r in conn.execute(
            "SELECT address, balance, sequence_number FROM accounts")),
        "rows": sorted(tuple(r) for r in conn.execute(
            "SELECT retractable_id, amount FROM retractable_transfers_v1")),
        "resolved": db.get_chain_state_value("retractable_resolved", None),
        "head": db.get_chain_state_value("canonical_head_hash", None),
    }


def _memory_state():
    lm = chain_state._lifecycle_manager
    return (
        dict(chain_state._balances),
        dict(chain_state._sequence_numbers),
        _view(lm.retractable_transfers),
    )


def test_a_failing_retractable_write_rolls_back_the_whole_commit(temp_database, monkeypatch):
    lm = _populated()
    chain_state.commit_state_to_db("head-1", 20)
    db_before, mem_before = _db_state(), _memory_state()

    lm.retractable_transfers.submit(_entry(seq=7, amount=3))
    chain_state._balances[A] = 1
    mem_mutated = _memory_state()

    def boom(_state):
        raise RuntimeError("disk full")

    monkeypatch.setattr(db, "_write_retractable_rows", boom)
    with pytest.raises(RuntimeError, match="disk full"):
        chain_state.commit_state_to_db("head-2", 21)

    assert _db_state() == db_before, "a partial canonical write survived"
    assert _memory_state() == mem_mutated, "the failed commit touched memory"
    assert mem_mutated != mem_before


def test_a_failing_retractable_write_rolls_back_a_prepared_block_commit(temp_database, monkeypatch):
    lm = _populated()
    chain_state.commit_state_to_db("head-1", 20)
    db_before = _db_state()

    snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"rules",
        metadata={
            "balances": {A: 1},
            "sequence_numbers": {A: 4},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "consensus rules",
        },
    )
    canonical = chain_state._canonical_state_kwargs(snapshot, head_hash="head-2", head_num=21)
    assert canonical["retractable_transfers"]["rows"]

    monkeypatch.setattr(db, "_write_retractable_rows",
                        lambda _s: (_ for _ in ()).throw(RuntimeError("disk full")))
    with pytest.raises(RuntimeError, match="disk full"):
        db.commit_prepared_block(
            execution_id="exec-x", tip="head-2", parent="head-1",
            journal_entries=[], expected_journal_seq=0, allocation_delta={},
            expected_epoch=db.shrink_mapping_epoch(), journal_head=None,
            allocator_digest="d", plan_id="p", spec_revision=0, time_point=0,
            canonical=canonical,
        )

    assert _db_state() == db_before
    assert db.find_block_commit("exec-x") is None


# --- events history ----------------------------------------------------------

def _block_row(conn, block_hash, number, previous):
    conn.execute(
        "INSERT INTO blocks (block_hash, block_number, previous_hash, timestamp, block_data) "
        "VALUES (?, ?, ?, ?, ?)",
        (block_hash, number, previous, 1_700_000_000 + number, "{}"),
    )


def _fork(temp_database):
    conn = db._db_conn
    with conn:
        _block_row(conn, "g0", 0, "")
        _block_row(conn, "a1", 1, "g0")
        _block_row(conn, "a2", 2, "a1")
        _block_row(conn, "b1", 1, "g0")
        _block_row(conn, "b2", 2, "b1")
    return conn


def _head(block_hash, number):
    db.set_chain_state_value("canonical_head_hash", block_hash)
    db.set_chain_state_value("canonical_head_number", str(number))


def test_events_are_filtered_to_the_canonical_chain(temp_database):
    _fork(temp_database)
    rid = "ab" * 32
    db.record_retractable_events("a1", 1, [(rid, "parked")])
    db.record_retractable_events("a2", 2, [(rid, "released")])
    db.record_retractable_events("b1", 1, [(rid, "parked")])
    db.record_retractable_events("b2", 2, [(rid, "retracted")])

    _head("a2", 2)
    assert db.get_canonical_retractable_events(rid) == [
        {"block_hash": "a1", "block_number": 1, "outcome": "parked"},
        {"block_hash": "a2", "block_number": 2, "outcome": "released"},
    ]

    _head("b2", 2)
    assert db.get_canonical_retractable_events(rid) == [
        {"block_hash": "b1", "block_number": 1, "outcome": "parked"},
        {"block_hash": "b2", "block_number": 2, "outcome": "retracted"},
    ]


def test_recording_the_same_block_twice_keeps_one_row(temp_database):
    _fork(temp_database)
    rid = "cd" * 32
    db.record_retractable_events("a1", 1, [(rid, "parked")])
    db.record_retractable_events("a1", 1, [(rid, "parked")])
    _head("a2", 2)
    assert len(db.get_canonical_retractable_events(rid)) == 1


def test_a_failing_history_write_never_raises(temp_database, monkeypatch):
    _fork(temp_database)

    class _Broken:
        def __enter__(self):
            raise sqlite3.OperationalError("locked")

        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(db, "_db_conn", _Broken())
    try:
        db.record_retractable_events("a1", 1, [("ef" * 32, "parked")])
    finally:
        monkeypatch.undo()


class _Result:
    """The snapshot a block's evaluation produced; events ride in its metadata."""

    def __init__(self, events):
        self.metadata = {"retractable_events": events}


class _Block:
    block_hash = "a1"

    class header:
        block_number = 1


def test_chain_state_hook_swallows_history_failures(temp_database, monkeypatch):
    monkeypatch.setattr(db, "record_retractable_events",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    chain_state._record_retractable_events(_Block(), _Result([("ab" * 32, "parked")]))


def test_chain_state_hook_records_the_apply_events(temp_database):
    _fork(temp_database)
    rid = "12" * 32
    chain_state._record_retractable_events(
        _Block(), _Result([(rid, "parked"), ("34" * 32, "released")]))
    _head("a2", 2)
    assert [e["outcome"] for e in db.get_canonical_retractable_events(rid)] == ["parked"]


def test_a_snapshot_without_events_records_nothing(monkeypatch):
    seen = []
    monkeypatch.setattr(db, "record_retractable_events", lambda *a: seen.append(a))
    chain_state._record_retractable_events(_Block(), TauStateSnapshot(state_hash="s", tau_bytes=b"", metadata={}))
    assert seen == []
