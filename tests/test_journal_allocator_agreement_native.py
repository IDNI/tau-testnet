"""The two nested-transaction systems must agree with each other.

Each is individually correct: the journal's accepted branch contains A and C but
never B, and the allocator's delta contains A's and C's bindings but never B's.
This checks that a worker reconstructed from one, encoded with the other,
reproduces the verdict the proposal actually computed -- which is the property
that makes a speculative worker self-contained with respect to BOTH execution
history and node-local value identity.
"""
import os

import pytest

import db
import tau_allocator as alloc
import tau_journal as tj
import tau_shrink as ts
import tau_speculation as spec


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDR_A = "aa" * 48
ADDR_B = "bb" * 48
ADDR_C = "cc" * 48


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _allow_rule(shrunk_id, width):
    """`sender is <id> -> allow`, in the runtime representation."""
    return (f"always ( i12[t]:bv[{width}] = {{ {shrunk_id} }}:bv[{width}] -> "
            f"o5[t]:bv[24] = {{ #x000001 }}:bv[24] ).")


def test_the_journal_and_the_allocator_agree_after_a_dirty_block(temp_database):
    width = ts.current_shrink_width()
    committed_journal = tj.Journal()
    proposal_journal = committed_journal.branch()
    proposal_alloc = alloc.Allocator(alloc.DbMappingSnapshot(), width=16,
                                     label="proposal")

    session = spec.SpeculationSession(cwd=REPO, env=_env())
    ids = {}
    try:
        session.init(_router())

        for name, address, accept in (("A", ADDR_A, True),
                                      ("B", ADDR_B, False),
                                      ("C", ADDR_C, True)):
            tx_journal = proposal_journal.child(name)
            tx_alloc = proposal_alloc.child(name)
            with ts.speculative_allocation(allocator=tx_alloc):
                ids[name] = ts.intern_value(address, 384)
            rule = _allow_rule(ids[name], width)
            receipt = session.revise(rule, name)
            tx_journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE,
                              rule_text=rule, outcome=receipt.get("outcome"))
            if accept:
                proposal_journal.merge(tx_journal)
                proposal_alloc.merge(tx_alloc)
            else:
                proposal_journal.discard(tx_journal)
                proposal_alloc.discard(tx_alloc)
    finally:
        session.kill()

    # The journal's accepted branch holds two entries, and B is not one of them.
    # Note the ids: C reuses B's NUMBER, because B was fully discarded and a
    # disposed context's integer is free again -- what must not survive B is the
    # mapping, not the number. That makes rule TEXT an ambiguous identity here,
    # so the checks below are on the facts rather than the string.
    recorded = proposal_journal.entries()
    assert len(recorded) == 2, [e.rule_text for e in recorded]
    assert ids["C"] == ids["B"], "a disposed context's number should be reusable"
    assert all(e.outcome == "ACCEPTED_CHANGED" for e in recorded)

    # the allocator's delta
    delta = proposal_alloc.delta()
    assert ts.canonical_intern_key(ADDR_A, 384) in delta
    assert ts.canonical_intern_key(ADDR_C, 384) in delta
    assert ts.canonical_intern_key(ADDR_B, 384) not in delta, "B survived in the mapping"

    # a worker reconstructed from the journal, encoded with the allocator,
    # reproduces the verdicts the proposal computed
    rebuilt = spec.SpeculationSession(cwd=REPO, env=_env())
    try:
        rebuilt.init(_router())
        for entry in proposal_journal.entries():
            rebuilt.revise(entry.rule_text, "replay")
        allowed_a = (rebuilt.step({"i12": str(ids["A"])}).get("outputs") or {}).get("o5")
        allowed_c = (rebuilt.step({"i12": str(ids["C"])}).get("outputs") or {}).get("o5")
        # an id the accepted branch never bound: nothing should allow it
        unbound = max(ids.values()) + 50
        allowed_other = (rebuilt.step({"i12": str(unbound)}).get("outputs") or {}).get("o5")
    finally:
        rebuilt.kill()

    assert allowed_a == "1", "A was accepted and must be allowed"
    assert allowed_c == "1", "C was accepted and must be allowed"
    assert allowed_other != "1", "an unbound sender must not inherit an accepted rule"


def test_a_rejected_proposal_publishes_neither_record(temp_database):
    before_epoch = db.shrink_mapping_epoch()
    proposal_alloc = alloc.Allocator(alloc.DbMappingSnapshot(), width=16)
    committed_journal = tj.Journal()
    proposal_journal = committed_journal.branch()

    tx_alloc = proposal_alloc.child("B")
    with ts.speculative_allocation(allocator=tx_alloc):
        ts.intern_value(ADDR_B, 384)
    tx_journal = proposal_journal.child("B")
    tx_journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="R")
    proposal_alloc.discard(tx_alloc)
    proposal_journal.discard(tx_journal)

    assert db.shrink_mapping_epoch() == before_epoch
    assert len(committed_journal) == 0
    assert proposal_alloc.delta() == {}
    assert len(proposal_journal) == 0


def test_an_accepted_proposal_publishes_exactly_the_tested_ids(temp_database):
    proposal_alloc = alloc.Allocator(alloc.DbMappingSnapshot(), width=16)
    tx_alloc = proposal_alloc.child("A")
    with ts.speculative_allocation(allocator=tx_alloc):
        tested = ts.intern_value(ADDR_A, 384)
    proposal_alloc.merge(tx_alloc)
    alloc.publish_to_db(proposal_alloc)
    assert db.lookup_shrink_id(ts.canonical_intern_key(ADDR_A, 384)) == tested
