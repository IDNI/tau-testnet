"""One transaction, or nothing.

The canonical snapshot, the journal delta, the exact-id allocator delta, the
commit record and the tip become durable together or not at all. They share one
SQLite file behind one connection, so this is a real transaction rather than a
sequence of best-effort writes with a recovery story bolted on.

Each test breaks one of them and requires the ENTIRE commit to be absent -- not
"mostly absent", because a published mapping for a block that does not exist
permanently burns those ids for nothing, and a journal entry for a block that
does not exist makes every later reconstruction wrong.
"""
import json

import pytest
from unittest.mock import patch

import db


def _entry(seq, prev=None, rule="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).",
           link=None):
    return {"seq": seq, "kind": "revision", "phase": "apply", "rule_text": rule,
            "inputs": {}, "target": 0, "accumulate": True, "outcome": "ACCEPTED_CHANGED",
            "result_fingerprint": "fp", "identity": None, "prev": prev,
            "link": link or f"link{seq}"}


def _commit(**kw):
    args = dict(
        execution_id="exec-1", tip="tip-1", parent="tip-0",
        journal_entries=[_entry(1), _entry(2, prev="link1")],
        expected_journal_seq=0,
        allocation_delta={"bv384:aa": 1, "bv384:bb": 2},
        expected_epoch=db.shrink_mapping_epoch(),
        journal_head="link2", allocator_digest="digest-1", plan_id="plan-1",
        spec_revision=2, time_point=7,
    )
    args.update(kw)
    return db.commit_prepared_block(**args)


def _state():
    head, seq = db.committed_journal_head()
    return {
        "journal_head": head,
        "journal_seq": seq,
        "max_shrink_id": db.get_max_shrink_id(),
        "epoch": db.shrink_mapping_epoch(),
        "commit": db.find_block_commit("exec-1"),
    }


# --- the happy path -----------------------------------------------------------

def test_everything_becomes_durable_together(temp_database):
    before = _state()
    out = _commit()

    assert out["committed"] is True
    after = _state()
    assert after["journal_seq"] == 2
    assert after["journal_head"] == "link2"
    assert after["max_shrink_id"] == 2
    assert after["epoch"] != before["epoch"]
    assert after["commit"]["tip"] == "tip-1"
    assert after["commit"]["spec_revision"] == 2

    entries = db.committed_journal_entries()
    assert [e["link"] for e in entries] == ["link1", "link2"]
    assert entries[0]["accumulate"] is True


def test_the_canonical_snapshot_goes_in_the_same_transaction(temp_database):
    _commit(canonical=dict(
        head_hash="tip-1", head_num=1, balances={"aa" * 48: 10},
        sequences={}, application_rules="RULES", consensus_rules="",
        active_consensus_id="", pending_updates=[], votes=[], scheduled=[],
        archival=[],
    ))
    assert db.get_chain_state_value("application_rules", "") == "RULES"
    assert db.get_chain_state_value("canonical_head_hash", "") == "tip-1"
    assert db.find_block_commit("exec-1") is not None


# --- each failure takes the whole thing with it -------------------------------

def test_a_stale_allocator_epoch_leaves_nothing(temp_database):
    before = _state()
    with pytest.raises(ValueError, match="shrink mapping moved"):
        _commit(expected_epoch="0:deadbeef")
    assert _state() == before, "a stale mapping epoch left something behind"


def test_a_moved_journal_base_leaves_nothing(temp_database):
    before = _state()
    with pytest.raises(ValueError, match="journal base moved"):
        _commit(expected_journal_seq=5)
    assert _state() == before


def test_an_unavailable_allocator_id_leaves_nothing(temp_database):
    db.publish_shrink_ids({"bv384:someone-else": 1}, db.shrink_mapping_epoch())
    before = _state()
    with pytest.raises(ValueError, match="already belongs to"):
        _commit(expected_epoch=db.shrink_mapping_epoch())
    assert _state() == before, "a rejected id publication left journal rows behind"


def test_a_failing_canonical_write_leaves_nothing(temp_database):
    """Including the journal rows and the mapping, which were written FIRST."""
    before = _state()
    with patch("db._write_canonical_state_rows", side_effect=RuntimeError("disk")):
        with pytest.raises(RuntimeError, match="disk"):
            _commit(canonical={"head_hash": "tip-1"})
    after = _state()
    assert after == before, (
        "a failed canonical write left the journal or the mapping behind: "
        f"{before} -> {after}"
    )


def test_a_failing_commit_record_leaves_nothing(temp_database):
    """The record is written LAST, so this is the interval where a naive
    implementation has already published everything else."""
    before = _state()
    real_conn = db._db_conn

    class _Cursor:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def execute(self, sql, *a, **kw):
            if "INSERT INTO block_commits_v1" in sql:
                raise RuntimeError("record write failed")
            return self._inner.execute(sql, *a, **kw)

    class _Conn:
        """sqlite3.Connection.cursor is read-only, so the connection itself is
        proxied rather than patched."""

        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            return getattr(self._inner, name)

        def __enter__(self):
            return self._inner.__enter__()

        def __exit__(self, *a):
            return self._inner.__exit__(*a)

        def cursor(self):
            return _Cursor(self._inner.cursor())

    db._db_conn = _Conn(real_conn)
    try:
        with pytest.raises(RuntimeError, match="record write failed"):
            _commit()
    finally:
        db._db_conn = real_conn
    assert _state() == before, (
        "the commit record failed but the journal, mapping or state stayed"
    )


# --- idempotency --------------------------------------------------------------

def test_the_same_commit_twice_applies_once(temp_database):
    first = _commit()
    after_first = _state()
    assert first["committed"] is True

    second = _commit(expected_journal_seq=0, expected_epoch=db.shrink_mapping_epoch())
    assert second["committed"] is False
    assert second["already"]["tip"] == "tip-1"
    assert _state() == after_first, "the retry applied something a second time"


def test_a_retry_is_recognised_before_anything_is_attempted(temp_database):
    """A retry must not fail on the anchors it would legitimately no longer
    match -- the journal base and mapping epoch have both moved BECAUSE the
    first commit succeeded. Answering "already durable" has to come first."""
    _commit()
    out = _commit(expected_journal_seq=0, expected_epoch="0:whatever-stale")
    assert out["committed"] is False
    assert out["already"]["execution_id"] == "exec-1"


def test_a_different_execution_is_not_a_retry(temp_database):
    _commit()
    out = _commit(execution_id="exec-2", tip="tip-2", parent="tip-1",
                  journal_entries=[_entry(3, prev="link2", link="link3")],
                  expected_journal_seq=2,
                  allocation_delta={"bv384:cc": 3},
                  expected_epoch=db.shrink_mapping_epoch(),
                  journal_head="link3")
    assert out["committed"] is True
    assert db.committed_journal_head() == ("link3", 3)
    assert db.find_block_commit("exec-1")["tip"] == "tip-1"
    assert db.find_block_commit("exec-2")["tip"] == "tip-2"


def test_the_commit_record_survives_a_restart(temp_database):
    """The durable answer to "did this cross the boundary". Written in the same
    transaction as the state it describes, so a crash between the two is not
    representable."""
    _commit()
    db.close_db() if hasattr(db, "close_db") else None
    db._db_conn = None
    db.init_db()
    record = db.find_block_commit("exec-1")
    assert record is not None and record["tip"] == "tip-1"
    assert db.committed_journal_head() == ("link2", 2)
