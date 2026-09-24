"""Reconstruct from ONE anchor, and prove the proposal branch stays clean.

The criterion is not "can a worker replay?" but: given one committed
journal/allocator anchor and a chosen representation plan, can a fresh process
reconstruct exactly the authoritative semantic state without reading or mutating
ambient global state?
"""
import os

import pytest

import db
import tau_allocator as alloc
import tau_journal as tj
import tau_reconstruction as tr
import tau_session as ts
import tau_shrink as tshrink


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDR_X = "11aa" + "bb" * 46
ADDR_Y = "22cc" + "dd" * 46
ADDR_Z = "33ee" + "ff" * 46
ADDR_Q = "44ab" + "cd" * 46


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _allow(address, width=384):
    return (f"always ( i12[t]:bv[{width}] = {{ #x{address} }}:bv[{width}] -> "
            f"o5[t]:bv[24] = {{ #x000001 }}:bv[24] ).")


HIST = "always ( o8[t]:bv[24] = i1[t-3]:bv[24] )."
DEPTH1 = "always ( o9[t]:bv[24] = i1[t-1]:bv[24] )."
NOOP = "always ( o5[t]:bv[24] = o5[t]:bv[24] )."


def _committed_history(temp_database):
    """Build a committed journal + committed mapping, the way apply would."""
    journal = tj.Journal()
    # X and Y become committed allocations
    id_x = tshrink.intern_value(ADDR_X, 384)
    id_y = tshrink.intern_value(ADDR_Y, 384)

    session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env())
    try:
        for rule in (_allow(ADDR_X), HIST, DEPTH1):
            session.apply_rule(rule, record=False)
            journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text=rule,
                           outcome=(session.last_outcome or {}).get("outcome"),
                           result=(session.last_outcome or {}).get("outputs"))
        for value in ("#x000005", "#x000009", "#x000042"):
            out = session.evaluate({1: value}, multi=True, record=False)
            journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: value}, result=out)
        session.apply_rule(_allow(ADDR_Y), record=False)
        journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text=_allow(ADDR_Y),
                       outcome=(session.last_outcome or {}).get("outcome"),
                       result=(session.last_outcome or {}).get("outputs"))
        session.apply_rule(NOOP, record=False)
        journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text=NOOP,
                       outcome=(session.last_outcome or {}).get("outcome"),
                       result=(session.last_outcome or {}).get("outputs"))
        out = session.evaluate({1: "#x000011"}, multi=True, record=False)
        journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "#x000011"}, result=out)
        control = _observe(session)
    finally:
        session.dispose()
    return journal, control, {"X": id_x, "Y": id_y}


def _observe(session):
    seen = []
    for value in ("#x000001", "#x000002", "#x000003"):
        out = session.evaluate({1: value}, multi=True, record=False)
        seen.append((out.get(8), out.get(9)))
    return seen


def test_reconstruction_from_one_anchor_matches_and_stays_clean(temp_database):
    journal, control, ids = _committed_history(temp_database)
    journal.verify_chain()

    plan = tr.plan_representation(
        history_rules=[e.rule_text for e in journal.entries() if e.rule_text],
        candidate_rules=[_allow(ADDR_Z), _allow(ADDR_Q)],
    )
    snapshot = alloc.DbMappingSnapshot()
    descriptor = tr.ReconstructionDescriptor.capture(journal=journal, tip_id="block-7",
                                                     plan=plan)
    epoch_before = db.shrink_mapping_epoch()

    rebuilt = ts.WorkerSession.reconstruct(
        _router(), journal=journal, plan=plan, snapshot=snapshot,
        descriptor=descriptor, cwd=REPO, env=_env(),
    )
    try:
        assert _observe(rebuilt) == control, "the reconstruction diverged"
        # replay consumed no committed capacity
        assert db.shrink_mapping_epoch() == epoch_before

        # --- open a proposal on top -------------------------------------------
        proposal_alloc = alloc.Allocator(snapshot, width=plan.width, label="proposal")
        rebuilt.begin_proposal(proposal_alloc)
        committed_journal = journal
        proposal_journal = committed_journal.branch()

        results = {}
        for name, address, accept in (("A", ADDR_Z, True),
                                      ("B", ADDR_Q, False),
                                      ("C", ADDR_Z, True)):
            tx_journal = proposal_journal.child(name)
            tx_alloc = proposal_alloc.child(name)
            rebuilt.allocation = tx_alloc
            rebuilt.journal = tx_journal
            results[name] = rebuilt.apply_rule(_allow(address))
            if accept:
                proposal_journal.merge(tx_journal)
                proposal_alloc.merge(tx_alloc)
            else:
                proposal_journal.discard(tx_journal)
                proposal_alloc.discard(tx_alloc)

        assert len(proposal_journal) == 2, "B survived in the proposal journal"
        delta = proposal_alloc.delta()
        assert tshrink.canonical_intern_key(ADDR_Z, 384) in delta
        assert tshrink.canonical_intern_key(ADDR_Q, 384) not in delta, \
            "B survived in the proposal mapping"
        # and nothing published
        assert db.shrink_mapping_epoch() == epoch_before
        assert db.lookup_shrink_id(tshrink.canonical_intern_key(ADDR_Z, 384)) is None
    finally:
        rebuilt.dispose()


def test_replay_never_allocates_and_reports_anchor_disagreement(temp_database):
    """The journal and the allocator snapshot describe the same committed
    history. A value the journal references and the mapping lacks is a
    disagreement to report, not to repair -- repairing it would hide the
    mismatch and spend committed capacity on a reconstruction."""
    journal = tj.Journal()
    rule = _allow(ADDR_X)
    journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text=rule)
    # ADDR_X was never interned: the mapping does not know it
    snapshot = alloc.DbMappingSnapshot()
    plan = tr.plan_representation(history_rules=[rule])
    with pytest.raises(tr.ReconstructionMismatch):
        ts.WorkerSession.reconstruct(_router(), journal=journal, plan=plan,
                                     snapshot=snapshot, cwd=REPO, env=_env())


def test_the_plan_sees_the_candidate_before_the_worker_is_built(temp_database):
    """A committed history whose i12 use is equality-only replays fine as
    interned; a candidate that uses i12 in an ordering comparison needs it plain.
    Deciding from history alone pins the narrow width and then cannot type the
    candidate -- the original incident wearing a different hat."""
    history = [_allow(ADDR_X)]
    ordering = ("always ( i12[t]:bv[384] > { #x" + ADDR_Y + " }:bv[384] -> "
                "o5[t]:bv[24] = { #x000000 }:bv[24] ).")
    from_history_only = tr.plan_representation(history_rules=history)
    with_candidate = tr.plan_representation(history_rules=history,
                                            candidate_rules=[ordering])
    assert 12 in from_history_only.interned
    assert 12 in with_candidate.plain, "the candidate's requirement was ignored"
    assert 12 not in with_candidate.interned
    assert from_history_only.plan_id != with_candidate.plan_id


def test_the_descriptor_detects_a_moved_anchor(temp_database):
    journal = tj.Journal()
    journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text=_allow(ADDR_X))
    first = tr.ReconstructionDescriptor.capture(journal=journal, tip_id="block-1")
    tshrink.intern_value(ADDR_Z, 384)                     # the mapping moves
    second = tr.ReconstructionDescriptor.capture(journal=journal, tip_id="block-1")
    assert "allocator_state_id" in " ".join(first.mismatches(second))

    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "5"})
    third = tr.ReconstructionDescriptor.capture(journal=journal, tip_id="block-1")
    reasons = " ".join(second.mismatches(third))
    assert "journal_head_hash" in reasons and "journal_sequence" in reasons
