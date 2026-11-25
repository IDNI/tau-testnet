"""Bounty 02 (issue #42) gap-closer: the journal cross-check for spec
snapshots (see consensus/spec_verify.py and the design note
b02-gap-closer-journal-crosscheck-design-2026-11-24.md).

The objection these tests answer: the active-rules view served text
captured from a process-local accumulation, while the authoritative
evaluator is rebuilt from the committed journal (tau_journal_v1). A
capture could therefore drift from the journal and the view would serve
the drift as fact.

The harness reuses tests/test_active_rules_view.py's fake-engine node,
with one change of order that mirrors production: the block's journal
delta is committed (db.commit_prepared_block, the commit protocol's own
transaction) BEFORE chain_state records the view data, so the snapshot
record path can cross-check each capture against the journal segment
the block itself committed.

Cases:
  * displacement probe with verification on -- install o26={7} &&
    o27={9}, then displace o26={3}: both steps are stored
    journal-verified, and the served text+hash equal the journal
    reconstruction at both heights;
  * intra-block steps -- one block installing two successive revisions
    keeps both steps addressable and journal-verified;
  * a capture the journal contradicts is stored flagged, and the view
    serves the journal reconstruction, never the stale capture;
  * tamper -- a journal row for a revising block is deleted after the
    fact: the affected step answers not-available, never the stale
    capture, while the earlier height (whose journal prefix is intact)
    still verifies;
  * restart -- the manager's process-global spec is reset to None (and
    then poisoned): the view still answers correctly from the persisted
    snapshots + journal.
"""
import hashlib
import sqlite3

import chain_state
import config
import db
import tau_journal
import tau_manager
from block import Block
from consensus import spec_verify
from test_active_rules_view import (
    ALICE,
    GENESIS_TS,
    RULE_DISPLACE,
    RULE_DISPLACE_O27,
    RULE_INSTALL,
    FakeTauEngine,
    _apply_block,
    _genesis_snapshot,
    _rule_tx,
    _set_canonical_head,
    _use_database,
    _view,
)


def _entry_dict(entry):
    return {
        "seq": entry.seq,
        "kind": entry.kind,
        "phase": entry.phase,
        "rule_text": entry.rule_text,
        "inputs": entry.inputs,
        "target": entry.target,
        "accumulate": entry.accumulate,
        "units": [list(unit) for unit in entry.units],
        "outcome": entry.outcome,
        "result_fingerprint": entry.result_fingerprint,
        "identity": entry.identity,
        "prev": entry.prev,
        "link": entry.link,
    }


class _JournalNode:
    """A fake-engine node whose blocks commit their journal delta in
    production order: journal first (the commit protocol's transaction),
    view data recorded from the committed snapshot afterwards."""

    def __init__(self, db_path):
        _use_database(db_path)
        self.fake = FakeTauEngine()
        self.parent_snapshot = _genesis_snapshot()
        genesis = Block.create(
            block_number=0, previous_hash="00" * 32, transactions=[],
            proposer_pubkey=ALICE, timestamp=GENESIS_TS,
        )
        db.add_block(genesis)
        _set_canonical_head(genesis.block_hash, 0)
        self.prev_hash = genesis.block_hash
        self.height = 0
        self.journal = tau_journal.Journal(authoritative=True)
        self.journal_seq = 0

    def commit(self, txs, rule_texts):
        self.height += 1
        result, block_obj = _apply_block(
            self.fake, txs, self.height, self.parent_snapshot, self.prev_hash
        )
        db.add_block(block_obj)
        _set_canonical_head(block_obj.block_hash, self.height)
        before = len(self.journal.entries())
        for text in rule_texts:
            self.journal.record(
                tau_journal.REVISION, phase=tau_journal.PHASE_APPLY,
                rule_text=text, outcome="ACCEPTED_CHANGED",
            )
        delta = self.journal.entries()[before:]
        if delta:
            db.commit_prepared_block(
                execution_id=f"xcheck-{self.height}-{block_obj.block_hash[:12]}",
                tip=block_obj.block_hash,
                parent=self.prev_hash,
                journal_entries=[_entry_dict(entry) for entry in delta],
                expected_journal_seq=self.journal_seq,
                allocation_delta={},
                expected_epoch=db.shrink_mapping_epoch(),
                journal_head=delta[-1].link,
                allocator_digest="xcheck",
                plan_id="xcheck",
                spec_revision=self.fake.revision,
                time_point=self.height,
            )
            self.journal_seq += len(delta)
        chain_state._record_rule_view_data(block_obj, result.next_snapshot)
        self.parent_snapshot = result.next_snapshot
        self.prev_hash = block_obj.block_hash
        return result, block_obj


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _displacement_node(tmp_path):
    node = _JournalNode(tmp_path / "node.sqlite")
    node.commit([_rule_tx("install-1", RULE_INSTALL, seq=0)], [RULE_INSTALL])
    installed_text = node.fake.composed_text()
    node.commit([_rule_tx("displace-1", RULE_DISPLACE, seq=1)], [RULE_DISPLACE])
    return node, installed_text


# --- (a) displacement probe with verification on -----------------------------


def test_displacement_probe_journal_verified(temp_database, tmp_path):
    node, installed_text = _displacement_node(tmp_path)

    stored_1 = db.get_spec_snapshot(1)
    stored_2 = db.get_spec_snapshot(2)
    assert stored_1["journal_verified"] is True
    assert stored_1["journal_sha256"] == _sha(stored_1["canonical_text"])
    assert stored_2["journal_verified"] is True
    assert stored_2["journal_sha256"] == _sha(stored_2["canonical_text"])

    view_1 = _view("1")
    assert view_1["available"] is True
    assert view_1["source"] == "captured+journal-verified"
    assert view_1["canonical_text"] == installed_text
    assert view_1["canonical_text"] == spec_verify.reconstruct_snapshot(1, 1)
    assert view_1["sha256"] == _sha(installed_text)

    view_2 = _view("2")
    assert view_2["available"] is True
    assert view_2["source"] == "captured+journal-verified"
    assert view_2["canonical_text"] == node.fake.composed_text()
    assert view_2["canonical_text"] == spec_verify.reconstruct_snapshot(2, 2)
    assert "o26[t]:bv[64] = { 3 }:bv[64]" in view_2["canonical_text"]
    assert "o27[t]:bv[64] = { 9 }:bv[64]" in view_2["canonical_text"]
    assert "o26[t]:bv[64] = { 7 }:bv[64]" not in view_2["canonical_text"]
    assert view_2["sha256"] == _sha(view_2["canonical_text"])


def test_intra_block_steps_both_journal_verified(temp_database, tmp_path):
    """One block, two revising steps: both snapshots stay addressable,
    and each is verified against the journal state after its own step."""
    node = _JournalNode(tmp_path / "node.sqlite")
    node.commit([_rule_tx("install-1", RULE_INSTALL, seq=0)], [RULE_INSTALL])
    node.commit(
        [
            _rule_tx("displace-1", RULE_DISPLACE, seq=1),
            _rule_tx("displace-2", RULE_DISPLACE_O27, seq=2),
        ],
        [RULE_DISPLACE, RULE_DISPLACE_O27],
    )

    stored_2 = db.get_spec_snapshot(2)
    stored_3 = db.get_spec_snapshot(3)
    assert stored_2["height"] == stored_3["height"] == 2
    assert stored_2["journal_verified"] is True
    assert stored_3["journal_verified"] is True

    intermediate = spec_verify.reconstruct_snapshot(2, 2)
    assert intermediate == stored_2["canonical_text"]
    assert "o26[t]:bv[64] = { 3 }:bv[64]" in intermediate
    assert "o27[t]:bv[64] = { 9 }:bv[64]" in intermediate

    final = spec_verify.reconstruct_snapshot(2, 3)
    assert final == stored_3["canonical_text"]
    assert "o27[t]:bv[64] = { 5 }:bv[64]" in final

    view = _view("2")
    assert view["available"] is True
    assert view["spec_revision"] == 3
    assert view["source"] == "captured+journal-verified"
    assert view["canonical_text"] == final


# --- a capture the journal contradicts ---------------------------------------


def test_contradicted_capture_serves_journal_reconstruction(
    temp_database, tmp_path
):
    node, _installed = _displacement_node(tmp_path)
    honest_text = db.get_spec_snapshot(2)["canonical_text"]

    lying_text = "always ( o26[t]:bv[64] = { 8 }:bv[64] )."
    db.record_spec_snapshots(2, [(2, lying_text)])

    stored = db.get_spec_snapshot(2)
    assert stored["canonical_text"] == lying_text
    assert stored["journal_verified"] is False
    assert stored["journal_sha256"] == _sha(honest_text)

    view = _view("2")
    assert view["available"] is True
    assert view["source"] == "journal-reconstructed"
    assert view["canonical_text"] == honest_text
    assert view["canonical_text"] != lying_text
    assert view["sha256"] == _sha(honest_text)


# --- (b) tamper ---------------------------------------------------------------


def test_deleted_journal_row_flags_the_step(temp_database, tmp_path):
    node, _installed = _displacement_node(tmp_path)
    assert _view("2")["source"] == "captured+journal-verified"
    captured_2 = db.get_spec_snapshot(2)["canonical_text"]

    # Delete the revising block's journal row after the fact.
    with db._db_conn:
        db._db_conn.execute("DELETE FROM tau_journal_v1 WHERE seq = 2")

    view_2 = _view("2")
    assert view_2["available"] is False
    assert "canonical_text" not in view_2
    assert captured_2 not in str(view_2)

    # The earlier height's journal prefix is intact: it still verifies.
    view_1 = _view("1")
    assert view_1["available"] is True
    assert view_1["source"] == "captured+journal-verified"


# --- (c) restart --------------------------------------------------------------


def test_restart_resets_manager_global_view_still_answers(
    temp_database, tmp_path
):
    node, installed_text = _displacement_node(tmp_path)
    original = tau_manager.last_known_tau_spec
    try:
        # Process restart: the process-global spec cache starts empty...
        tau_manager.last_known_tau_spec = None
        view_2 = _view("2")
        assert view_2["available"] is True
        assert view_2["source"] == "captured+journal-verified"
        assert view_2["canonical_text"] == node.fake.composed_text()
        view_1 = _view("1")
        assert view_1["canonical_text"] == installed_text

        # ...and a poisoned global is just as irrelevant to the answer.
        tau_manager.last_known_tau_spec = (
            "always ( o26[t]:bv[64] = { 99 }:bv[64] )."
        )
        view_2 = _view("2")
        assert view_2["canonical_text"] == node.fake.composed_text()
        assert "99" not in view_2["canonical_text"]
    finally:
        tau_manager.last_known_tau_spec = original


# --- schema migration ----------------------------------------------------------


def test_old_schema_database_gains_verdict_columns(tmp_path):
    """A database written before the cross-check (four-column
    spec_snapshots, one row in it) opens under the new code: the
    verdict columns are added additively, the row survives, and it
    reads back unverified with no journal hash -- never silently
    trusted."""
    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(str(path))
    conn.execute(
        "CREATE TABLE spec_snapshots ("
        "spec_revision INTEGER PRIMARY KEY, height INTEGER NOT NULL, "
        "canonical_text TEXT NOT NULL, sha256 TEXT NOT NULL)"
    )
    text = "always ( o26[t]:bv[64] = { 7 }:bv[64] )."
    conn.execute(
        "INSERT INTO spec_snapshots VALUES (1, 1, ?, ?)", (text, _sha(text))
    )
    conn.commit()
    conn.close()

    if db._db_conn is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(str(path))
    db.init_db()
    try:
        cols = {
            row[1]
            for row in db._db_conn.execute(
                "PRAGMA table_info(spec_snapshots);"
            ).fetchall()
        }
        assert {"journal_verified", "journal_sha256"} <= cols
        stored = db.get_spec_snapshot(1)
        assert stored["canonical_text"] == text
        assert stored["journal_verified"] is False
        assert stored["journal_sha256"] is None
    finally:
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
