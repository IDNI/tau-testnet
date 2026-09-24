"""One owner of the node's authoritative Tau state, and no fallback.

Before this the authoritative evaluator was a module global that several paths
advanced independently -- the startup restore, a governance activation after a
block, the block-apply path, the miner's save/restore. Each correct alone, none
able to see the others. That is how a node ends up with two sources of evaluator
truth and no way to say which is right.

The rule these tests exist to hold: failing to reconstruct or promote means
UNAVAILABLE. It never means "serve the in-process interpreter instead".
"""
import threading
from types import SimpleNamespace

import pytest

import db
import tau_authority as auth
import tau_commit as tc
import tau_journal as tj


class _Spec:
    def __init__(self, spec_revision=2, time_point=7):
        self._state = {"spec_revision": spec_revision, "time_point": time_point,
                       "session_healthy": True}

    def state(self):
        return dict(self._state)


class _Worker:
    def __init__(self, name):
        self.name = name
        self._spec = _Spec()
        self.journal = None
        self.allocation = None
        self.disposed = False

    def dispose(self):
        self.disposed = True


def _owner():
    ready = threading.Event()
    return auth.AuthoritativeTauOwner(ready=ready), ready


# --- availability -------------------------------------------------------------

def test_an_uninitialised_owner_refuses_rather_than_substituting(temp_database):
    owner, ready = _owner()
    with pytest.raises(auth.AuthorityUnavailable, match="UNINITIALIZED"):
        owner.current()
    assert not ready.is_set()


def test_marking_unavailable_drops_readiness_and_advances_the_generation(temp_database):
    owner, ready = _owner()
    owner._serve(_Worker("w"))
    assert ready.is_set()
    before = owner.generation

    owner.mark_unavailable("the worker died")

    assert owner.state == auth.UNAVAILABLE
    assert not ready.is_set()
    assert owner.generation == before + 1, (
        "a result prepared against the previous session could still be published"
    )
    with pytest.raises(auth.AuthorityUnavailable, match="the worker died"):
        owner.current()


def test_unavailable_is_reported_not_worked_around(temp_database):
    """The whole point. There is no `current()` path that answers with anything
    other than the authoritative session."""
    owner, ready = _owner()
    owner._serve(_Worker("w"))
    owner.mark_unavailable("gone")
    with pytest.raises(auth.AuthorityUnavailable):
        owner.current()
    # and nothing about tau_manager's in-process interpreter changes that
    import tau_manager
    tau_manager.tau_direct_interface = object()
    try:
        with pytest.raises(auth.AuthorityUnavailable):
            owner.current()
    finally:
        tau_manager.tau_direct_interface = None


# --- promotion ----------------------------------------------------------------

def _prepared(worker, temp_database):
    import tau_allocator as alloc
    import tau_proposal as tp
    import tau_reconstruction as tr

    plan = tr.plan_representation(candidate_rules=[])
    ctx = tp.ProposalContext(
        session=worker, journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width),
        plan=plan,
    )
    ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE,
                       rule_text="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")
    return ctx, tc.PreparedBlockCommit.freeze(ctx, execution_id="exec-1",
                                              next_snapshot=object())


def test_promotion_takes_the_exact_worker(temp_database):
    owner, ready = _owner()
    old = _Worker("old")
    owner._serve(old)
    new = _Worker("new")
    ctx, prepared = _prepared(new, temp_database)

    owner.promote(ctx, prepared)

    assert owner.current() is new
    assert old.disposed
    assert ready.is_set()
    assert owner.descriptor.journal_head_hash == prepared.journal_final_head


def test_disposing_the_proposal_after_promotion_is_harmless(temp_database):
    owner, ready = _owner()
    new = _Worker("new")
    ctx, prepared = _prepared(new, temp_database)
    owner.promote(ctx, prepared)

    ctx.dispose()

    assert not new.disposed
    assert owner.current() is new


def test_promotion_is_one_shot(temp_database):
    owner, ready = _owner()
    ctx, prepared = _prepared(_Worker("new"), temp_database)
    owner.promote(ctx, prepared)
    with pytest.raises(tc.CommitStateError, match="one-shot"):
        owner.promote(ctx, prepared)


# --- anchors ------------------------------------------------------------------

def _commit_one(tip="tip-1", execution_id="exec-1"):
    entry = {"kind": "revision", "phase": "apply", "rule_text": "r",
             "inputs": {}, "target": 0, "accumulate": True,
             "outcome": "ACCEPTED_CHANGED", "result_fingerprint": None,
             "identity": None, "prev": None, "link": "link1"}
    db.commit_prepared_block(
        execution_id=execution_id, tip=tip, parent=None, journal_entries=[entry],
        expected_journal_seq=0, allocation_delta={},
        expected_epoch=db.shrink_mapping_epoch(), journal_head="link1",
        allocator_digest="digest-1", plan_id="plan-1",
    )
    db.set_chain_state_value("canonical_head_hash", tip)


def test_agreeing_anchors_pass(temp_database):
    owner, ready = _owner()
    _commit_one()
    out = owner.verify_committed_anchors()
    assert out["journal_head"] == "link1"
    assert out["commit"]["tip"] == "tip-1"


def test_a_journal_with_no_commit_record_is_not_ready(temp_database):
    """Entries nobody committed. A node cannot know what state they describe."""
    owner, ready = _owner()
    import tau_commit as _tc
    j = tj.Journal(authoritative=False)
    j.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="r")
    with db._db_lock:
        db._db_conn.execute(
            'INSERT INTO tau_journal_v1 (seq, kind, phase, rule_text, inputs, '
            'target, accumulate, outcome, result_fp, identity, prev, link, tip) '
            'VALUES (1, "revision", "apply", "r", "{}", 0, 1, NULL, NULL, NULL, '
            'NULL, "orphan", NULL)'
        )
        db._db_conn.commit()
    with pytest.raises(auth.AuthorityMismatch, match="no commit record"):
        owner.verify_committed_anchors()


def test_a_tip_the_commit_record_does_not_name_is_not_ready(temp_database):
    owner, ready = _owner()
    _commit_one()
    db.set_chain_state_value("canonical_head_hash", "some-other-tip")
    with pytest.raises(auth.AuthorityMismatch, match="not the one the last commit"):
        owner.verify_committed_anchors()


def test_a_serving_evaluator_built_from_another_head_is_not_ready(temp_database):
    """The evaluator and the committed journal have to describe the same
    history, or the node is answering for a state the chain does not have."""
    import tau_reconstruction as tr

    owner, ready = _owner()
    _commit_one()
    owner.descriptor = tr.ReconstructionDescriptor(journal_head_hash="a-different-head")
    with pytest.raises(auth.AuthorityMismatch, match="was built from journal head"):
        owner.verify_committed_anchors()


# --- reconstruction refuses rather than falls back ----------------------------

def test_reconstruction_without_a_baseline_is_unavailable(temp_database):
    owner, ready = _owner()
    with pytest.raises(auth.AuthorityUnavailable, match="baseline"):
        owner.reconstruct_from_committed()
    assert owner.state == auth.UNAVAILABLE
    assert not ready.is_set()


def test_a_corrupt_committed_journal_is_a_mismatch_not_a_retry(temp_database):
    owner, ready = _owner()
    owner._baseline = "always ( o0[t] = 1 )."
    with db._db_lock:
        db._db_conn.execute(
            'INSERT INTO tau_journal_v1 (seq, kind, phase, rule_text, inputs, '
            'target, accumulate, outcome, result_fp, identity, prev, link, tip) '
            'VALUES (1, "revision", "apply", "r", "{}", 0, 1, NULL, NULL, NULL, '
            'NULL, "not-the-real-link", NULL)'
        )
        db._db_conn.commit()
    with pytest.raises(auth.AuthorityMismatch, match="journal"):
        owner.reconstruct_from_committed()
    assert owner.state == auth.UNAVAILABLE


# --- no in-process block application once the owner is enabled ----------------

@pytest.fixture
def enabled_owner():
    owner = auth.AuthoritativeTauOwner(ready=threading.Event())
    owner.enabled = True
    auth.reset(owner)
    yield owner
    auth.reset(None)


def test_apply_without_a_proposal_is_refused_under_the_owner(enabled_owner, temp_database):
    """Without a proposal apply() drives the in-process interpreter as though it
    were authoritative. Refusing in the engine makes "one source of evaluator
    truth" a property of the engine rather than of every caller."""
    from unittest.mock import MagicMock
    from consensus.engine import TauConsensusEngine
    from consensus.state import TauStateSnapshot

    engine = TauConsensusEngine(state_store=MagicMock())
    with pytest.raises(auth.AuthorityUnavailable, match="without a proposal"):
        engine.apply(TauStateSnapshot(b"h", b"", {}), [], 1700000000,
                     target_balances={}, target_sequences={})


def test_apply_block_without_a_proposal_is_refused_under_the_owner(enabled_owner):
    from unittest.mock import MagicMock
    from consensus.engine import TauConsensusEngine

    engine = TauConsensusEngine(state_store=MagicMock())
    with pytest.raises(auth.AuthorityUnavailable, match="without a proposal"):
        engine.apply_block(MagicMock(), MagicMock(), MagicMock())


def test_tick_governance_is_refused_under_the_owner(enabled_owner):
    import chain_state
    with pytest.raises(auth.AuthorityUnavailable, match="tick_governance"):
        chain_state.tick_governance(1)


def test_the_not_enabled_path_is_unchanged(temp_database):
    """Guard the guard: the mock/test configuration still applies in-process."""
    from unittest.mock import MagicMock
    from consensus.engine import TauConsensusEngine
    from consensus.state import TauStateSnapshot

    auth.reset(None)
    assert not auth.owner().enabled
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    engine.apply(TauStateSnapshot(b"h", b"", {}), [], 1700000000,
                 target_balances={}, target_sequences={})
