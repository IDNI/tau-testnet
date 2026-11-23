"""Gap verification for OUR Bounty 02 build (measured, not read-only).

Our build claims, by design, to close the three read-audit gaps that were
CONFIRMED against mendhow's branch:
(c) head-row deletion misreported as NOT_FOUND -> our db.JournalTampered +
    running_spec_at code TAMPERED.
(d) None outcome inferring clause-ness from absence -> our _annotate_effect
    positive registry check + _outcome "unmatched" for effect-less rule txs.
(cache) view cache serving stale text, skipping verify_chain() on hit ->
    our running_spec(_at) re-verifies the chain on every cache hit.

Harness: real db.commit_prepared_block + real tau_journal.Journal on the
temp_database fixture; FakeEngine from test_running_spec (engine stub, as in
our own tests); baseline BASE.
"""
import hashlib
import json

import pytest

import db
import tau_journal
import tau_running_spec as rs
from commands import gettxstatus
from test_running_spec import A, B, BASE, FakeEngine

X = "always ( o26[t]:bv[24] = { 4 }:bv[24] )."  # never committed anywhere
ALICE = "1a1a"
STREAM = 5


class _Chain:
    """Two blocks on the REAL commit path, reset + A then B."""

    def __init__(self):
        self.journal = tau_journal.Journal(authoritative=True)
        self.parent = None
        self.revision = 0
        self.n = 0

    def commit(self, *texts, steps=1):
        base = len(self.journal)
        if self.n == 0:
            self.journal.record("reset", phase=tau_journal.PHASE_APPLY,
                                units=[("c1", True)])
        for text in texts:
            self.journal.record("revision", phase=tau_journal.PHASE_APPLY,
                                rule_text=text, outcome="ACCEPTED_CHANGED")
            self.revision += 1
            for _ in range(steps):
                self.journal.record("step", phase=tau_journal.PHASE_APPLY,
                                    inputs={"i1": "0"}, result={"o1": "1"})
        delta = [e.to_dict() for e in self.journal.entries()[base:]]
        self.n += 1
        tip = hashlib.sha256(f"block-{self.n}".encode()).hexdigest()
        db.commit_prepared_block(
            execution_id=f"exec-{self.n}", tip=tip, parent=self.parent,
            journal_entries=delta, expected_journal_seq=base,
            allocation_delta=None, expected_epoch=None,
            journal_head=self.journal.entries()[-1].link
            if len(self.journal) else None,
            allocator_digest=None, plan_id=None,
            spec_revision=self.revision,
            timestamp=1_700_000_000 + self.n,
        )
        self.parent = tip
        return tip


def _journal_links():
    cur = db._db_conn.cursor()
    return [(int(r[0]), r[1]) for r in cur.execute(
        "SELECT seq, link FROM tau_journal_v1 ORDER BY seq")]


def _delete_seq(seq):
    db._db_conn.execute("DELETE FROM tau_journal_v1 WHERE seq = ?", (seq,))
    db._db_conn.commit()


@pytest.fixture(autouse=True)
def _fresh_cache():
    rs.reset_cache()
    yield
    rs.reset_cache()


def test_gap_c_head_row_deleted_is_tampered_not_not_found(temp_database):
    chain = _Chain()
    chain.commit(A)
    b2 = chain.commit(B)
    # commit record for b2 exists; now delete the head journal row
    seqs = _journal_links()
    head_seq = seqs[-1][0]
    _delete_seq(head_seq)
    assert db.get_block_commit(b2) is not None
    out = rs.running_spec_at(db, b2, baseline=BASE, spawn=FakeEngine())
    assert out["text"] is None, out
    assert out["code"] == "TAMPERED", out


def test_gap_c_middle_row_deleted_is_tampered(temp_database):
    chain = _Chain()
    chain.commit(A)
    b2 = chain.commit(B)
    before = rs.running_spec_at(db, b2, baseline=BASE, spawn=FakeEngine())
    assert before["text"] is not None and A in before["text"] \
        and B in before["text"], before
    # delete a middle STEP row (head row intact, so the cut is found)
    seqs = _journal_links()
    mid = seqs[1][0]
    assert mid != seqs[-1][0]
    _delete_seq(mid)
    rs.reset_cache()
    after = rs.running_spec_at(db, b2, baseline=BASE, spawn=FakeEngine())
    assert after["text"] is None, after
    assert after["code"] == "TAMPERED", after


def test_gap_c_unknown_block_still_not_found(temp_database):
    chain = _Chain()
    chain.commit(A)
    out = rs.running_spec_at(db, "ff" * 32, baseline=BASE, spawn=FakeEngine())
    assert out["text"] is None, out
    assert out["code"] == "NOT_FOUND", out


def test_gap_cache_refuses_stale_text_after_tamper(temp_database):
    chain = _Chain()
    chain.commit(A)
    b2 = chain.commit(B)
    engine = FakeEngine()
    first = rs.running_spec_at(db, b2, baseline=BASE, spawn=engine)
    assert first["text"] is not None and A in first["text"], first
    assert engine.spawned == 1
    # tamper AFTER the view is cached: delete a middle row, head unchanged,
    # so the cache key (journal_head) is identical
    seqs = _journal_links()
    _delete_seq(seqs[1][0])
    second = rs.running_spec_at(db, b2, baseline=BASE, spawn=engine)
    # the cache must refuse, not serve the stale pre-tamper text
    assert second["text"] is None, second
    assert second["code"] == "TAMPERED", second


def test_gap_cache_serves_on_clean_second_call(temp_database):
    chain = _Chain()
    chain.commit(A)
    b2 = chain.commit(B)
    engine = FakeEngine()
    first = rs.running_spec_at(db, b2, baseline=BASE, spawn=engine)
    second = rs.running_spec_at(db, b2, baseline=BASE, spawn=engine)
    assert first["text"] is not None and first == second, (first, second)
    assert engine.spawned == 1, engine.spawned


def _record_outcome(block_hash, tx_hash, effects):
    db.record_tx_outcomes(block_hash, 0, [{
        "tx_hash": tx_hash, "index": 0, "status": "applied",
        "fee_charged": 10, "logs": [], "rule_effects": effects,
    }])


def test_gap_d_effectless_rule_tx_is_unmatched_not_clause(temp_database):
    from test_tx_outcomes import _chain_of
    (blk,) = _chain_of(1)
    tx_hash = "ab" * 32
    _record_outcome(blk.block_hash, tx_hash, [])
    # a user_tx whose operations carry a rule payload IS rule-bearing
    tx = {"tx_type": "user_tx", "operations": {"0": X}}
    assert gettxstatus._is_rule_bearing(tx) is True
    out = gettxstatus._outcome(db, tx_hash, blk.block_hash, tx=tx)
    assert out["rule_outcome"]["status"] == "unmatched", out
    assert "clause" not in json.dumps(out), out


def test_gap_d_clause_effect_registry_check_is_honest(temp_database):
    from test_tx_outcomes import _chain_of
    (blk,) = _chain_of(1)
    tx_hash = "ab" * 32
    sha = hashlib.sha256(X.encode("utf-8")).hexdigest()
    effect = {"account": ALICE, "kind": "clause", "stream": STREAM,
              "action": "registered", "sha256": sha}
    _record_outcome(blk.block_hash, tx_hash, [dict(effect)])
    tx = {"tx_type": "user_tx", "operations": {"0": X}}
    # registry does NOT hold the clause: the annotation must say so honestly
    out = gettxstatus._outcome(db, tx_hash, blk.block_hash, tx=tx)
    assert out["rule_effects"][0]["registry_confirmed"] is False, out
    # clause-ness still comes from the RECORDED effect, not from absence --
    # and the outcome says unconfirmed, it does not claim a registry hit
    assert out["rule_outcome"] == {"status": "clause",
                                   "registry_confirmed": False}, out
    # now put the clause in the registry with the matching body: confirmed
    db._db_conn.execute(
        "INSERT INTO rule_clauses_v1 (acceptor_pubkey, target_stream,"
        " clause_body) VALUES (?, ?, ?)", (ALICE, STREAM, X))
    db._db_conn.commit()
    out2 = gettxstatus._outcome(db, tx_hash, blk.block_hash, tx=tx)
    assert out2["rule_effects"][0]["registry_confirmed"] is True, out2
    assert out2["rule_outcome"] == {"status": "clause",
                                    "registry_confirmed": True}, out2
