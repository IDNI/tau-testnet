"""Promotion is ownership transfer, and the interval after durable commit.

Two rules this pins:

* The EXACT worker that computed the committed state becomes authoritative. Not
  "commit, build another worker, replay the journal into it" -- that throws away
  the reason the journal and reconstruction work exists and adds one more chance
  to diverge.
* Once persistence succeeds the old evaluator is obsolete, so it goes out of
  service BEFORE promotion is attempted. Otherwise a failed promotion leaves the
  node serving a worker that describes the state before the block that is now
  committed.
"""
import threading
from types import SimpleNamespace

import pytest

import db
import tau_allocator as alloc
import tau_commit as tc
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr


class _Spec:
    def __init__(self, spec_revision=2, time_point=7):
        self._state = {"spec_revision": spec_revision, "time_point": time_point}


    def state(self):
        return dict(self._state)


class _Worker:
    def __init__(self, name, **kw):
        self.name = name
        self._spec = _Spec(**kw)
        self.journal = None
        self.allocation = None
        self.disposed = False

    def dispose(self):
        self.disposed = True


def _proposal(worker, *, entries=2, allocate=("bv384:aa",)):
    plan = tr.plan_representation(candidate_rules=[])
    snapshot = alloc.DbMappingSnapshot()
    ctx = tp.ProposalContext(
        session=worker,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan,
    )
    for i in range(entries):
        ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE,
                           rule_text=f"always ( o5[t]:bv[24] = {{ #x00000{i} }}:bv[24] ).")
    for key in allocate:
        ctx.allocator.id_for(key)
    return ctx


def _setup(**kw):
    old = _Worker("old", spec_revision=1, time_point=3)
    new = _Worker("new", **kw)
    ready = threading.Event()
    ready.set()
    owner = tc.EvaluatorOwner(old, ready=ready)
    ctx = _proposal(new)
    prepared = tc.PreparedBlockCommit.freeze(
        ctx, execution_id="exec-1", next_snapshot=object(), parent_tip_id=None,
    )
    return old, new, ready, owner, ctx, prepared


# --- the healthy path ---------------------------------------------------------

def test_the_exact_worker_becomes_authoritative(temp_database):
    old, new, ready, owner, ctx, prepared = _setup()
    coord = tc.PreparedCommitCoordinator(owner)

    result = coord.commit(prepared, proposal=ctx, tip="tip-1")

    assert result["state"] == tc.ACTIVE
    assert owner.session is new, "a different evaluator was promoted"
    assert old.disposed, "the superseded evaluator was not disposed"
    assert ready.is_set(), "readiness was not republished"
    assert coord.ready


def test_the_proposal_can_no_longer_kill_the_promoted_worker(temp_database):
    """`dispose()` is called on proposals routinely, in `finally` blocks that
    know nothing about whether the block committed."""
    old, new, ready, owner, ctx, prepared = _setup()
    coord = tc.PreparedCommitCoordinator(owner)
    coord.commit(prepared, proposal=ctx, tip="tip-1")

    ctx.dispose()

    assert not new.disposed, "disposing the proposal killed the authoritative evaluator"
    assert owner.session is new


def test_promotion_is_one_shot(temp_database):
    old, new, ready, owner, ctx, prepared = _setup()
    tc.PreparedCommitCoordinator(owner).commit(prepared, proposal=ctx, tip="tip-1")

    with pytest.raises(tc.CommitStateError, match="one-shot"):
        owner.promote(ctx, prepared)


def test_promoting_a_different_worker_is_refused(temp_database):
    old, new, ready, owner, ctx, prepared = _setup()
    ctx.session = _Worker("impostor")

    with pytest.raises(tc.PreparedCommitMismatch, match="different evaluator"):
        owner.promote(ctx, prepared)


# --- the dangerous interval ---------------------------------------------------

def test_a_failed_promotion_never_falls_back_to_the_old_worker(temp_database):
    old, new, ready, owner, ctx, prepared = _setup()

    def _boom(proposal, prep):
        raise RuntimeError("the worker died between commit and promotion")

    owner.promote = _boom
    coord = tc.PreparedCommitCoordinator(owner)
    result = coord.commit(prepared, proposal=ctx, tip="tip-1")

    assert result["state"] == tc.COMMITTED_BUT_UNAVAILABLE
    assert "worker died" in result["unavailable_reason"]
    # The block HAPPENED. Never rejected, never abandoned.
    assert coord.committed
    assert db.find_block_commit("exec-1")["tip"] == "tip-1"
    # And the old evaluator is not an answer.
    assert not owner.serving, "the node kept serving the superseded evaluator"
    assert not ready.is_set(), "readiness survived a failed promotion"
    assert not coord.ready


def test_the_old_worker_goes_out_of_service_before_promotion_can_fail(temp_database):
    """Ordering, measured rather than assumed: if gating happened after a failed
    promotion there would be a window in which the node serves the pre-block
    state while the block is already committed."""
    old, new, ready, owner, ctx, prepared = _setup()
    observed = {}

    def _watch(proposal, prep):
        observed["serving_at_promotion"] = owner.serving
        observed["ready_at_promotion"] = ready.is_set()
        observed["generation_at_promotion"] = owner.generation
        raise RuntimeError("no")

    owner.promote = _watch
    tc.PreparedCommitCoordinator(owner).commit(prepared, proposal=ctx, tip="tip-1")

    assert observed["serving_at_promotion"] is False
    assert observed["ready_at_promotion"] is False
    assert observed["generation_at_promotion"] == 1, (
        "the generation did not advance, so a result prepared against the old "
        "evaluator could still be published"
    )


def test_recovery_rebuilds_from_the_committed_anchors(temp_database):
    old, new, ready, owner, ctx, prepared = _setup()
    owner.promote = lambda p, q: (_ for _ in ()).throw(RuntimeError("no"))
    coord_new = _Worker("rebuilt")
    coord = tc.PreparedCommitCoordinator(
        owner, reconstruct=lambda store: coord_new,
    )
    assert coord.commit(prepared, proposal=ctx, tip="tip-1")["state"] == \
        tc.COMMITTED_BUT_UNAVAILABLE

    out = coord.recover()

    assert out["state"] == tc.ACTIVE
    assert owner.session is coord_new
    assert owner.session is not old, "recovery fell back to the superseded evaluator"
    assert ready.is_set()
    assert coord.ready


# --- idempotency --------------------------------------------------------------

def test_a_retried_commit_returns_the_first_result(temp_database):
    old, new, ready, owner, ctx, prepared = _setup()
    coord = tc.PreparedCommitCoordinator(owner)
    first = coord.commit(prepared, proposal=ctx, tip="tip-1")
    seq_after_first = db.committed_journal_head()

    second = coord.commit(prepared, proposal=ctx, tip="tip-1")

    assert second == first
    assert db.committed_journal_head() == seq_after_first, "the retry appended again"


def test_a_fresh_coordinator_retrying_the_same_execution_commits_once(temp_database):
    """The realistic crash shape: the process died after durable storage, so the
    in-memory state machine is gone and the retry arrives with no memory of the
    first attempt. The DURABLE record has to be what answers."""
    old, new, ready, owner, ctx, prepared = _setup()
    tc.PreparedCommitCoordinator(owner).commit(prepared, proposal=ctx, tip="tip-1")
    head_after_first = db.committed_journal_head()
    max_id_after_first = db.get_max_shrink_id()

    old2, new2, ready2, owner2, ctx2, _ = _setup()
    # The same execution, re-prepared from a rebuilt proposal after the restart.
    prepared2 = tc.PreparedBlockCommit.freeze(
        ctx2, execution_id="exec-1", next_snapshot=object(), parent_tip_id=None,
    )
    result = tc.PreparedCommitCoordinator(owner2).commit(
        prepared2, proposal=ctx2, tip="tip-1",
    )

    assert result["retried"] is True
    assert result["state"] == tc.DURABLY_COMMITTED
    assert db.committed_journal_head() == head_after_first, "the journal grew twice"
    assert db.get_max_shrink_id() == max_id_after_first, "ids were allocated twice"


# --- the gate still applies ---------------------------------------------------

def test_a_stale_artifact_is_refused_before_anything_durable(temp_database):
    old, new, ready, owner, ctx, prepared = _setup()
    ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="later")
    coord = tc.PreparedCommitCoordinator(owner)

    with pytest.raises(tc.PreparedCommitMismatch):
        coord.commit(prepared, proposal=ctx, tip="tip-1")

    assert db.find_block_commit("exec-1") is None
    assert db.committed_journal_head() == (None, 0)
    assert owner.session is old, "a refused commit took the evaluator out of service"
    assert ready.is_set()


# --- the rest of the failure matrix -------------------------------------------

def test_a_worker_that_died_before_prepared_cannot_be_frozen(temp_database):
    """Discard the proposal; committed state untouched. Freezing an artifact
    that names None for every counter would pass the gate by comparing None to
    None, and then have nothing to promote."""
    class _Dead:
        def state(self):
            raise RuntimeError("worker gone")

    worker = _Worker("dying")
    worker._spec = _Dead()
    ctx = _proposal(worker)
    before = (db.committed_journal_head(), db.get_max_shrink_id())

    with pytest.raises(tc.WorkerUnavailable, match="could not report its state"):
        tc.PreparedBlockCommit.freeze(ctx, execution_id="exec-1",
                                      next_snapshot=object())
    assert (db.committed_journal_head(), db.get_max_shrink_id()) == before


def test_a_worker_reporting_itself_unhealthy_cannot_be_frozen(temp_database):
    worker = _Worker("sick")
    worker._spec._state["session_healthy"] = False
    ctx = _proposal(worker)
    with pytest.raises(tc.WorkerUnavailable, match="unhealthy"):
        tc.PreparedBlockCommit.freeze(ctx, execution_id="exec-1",
                                      next_snapshot=object())


def test_a_session_without_counters_is_not_treated_as_dead(temp_database):
    """The in-process session reports no counters at all. That is a session
    TYPE, not a dead worker, and refusing it would make the artifact unusable
    for the authoritative path."""
    class _NoSpec:
        journal = None
        allocation = None

    ctx = _proposal(_NoSpec())
    frozen = tc.PreparedBlockCommit.freeze(ctx, execution_id="exec-1",
                                           next_snapshot=object())
    assert frozen.proposal_spec_revision is None
    frozen.verify(proposal=ctx)


def test_dying_just_before_the_durable_commit_leaves_the_old_state(temp_database):
    """The gate passed and the process died before the transaction. On restart
    there is no commit record, so the block did not happen -- and the old
    evaluator is still the right one to serve."""
    old, new, ready, owner, ctx, prepared = _setup()
    before = (db.committed_journal_head(), db.get_max_shrink_id(),
              db.find_block_commit(prepared.execution_id))

    # Everything the coordinator does up to, but not including, the irreversible
    # step.
    prepared.verify(proposal=ctx, execution_id=prepared.execution_id)

    assert (db.committed_journal_head(), db.get_max_shrink_id(),
            db.find_block_commit(prepared.execution_id)) == before
    assert owner.session is old, "the old evaluator was retired before it had to be"
    assert ready.is_set(), "readiness went down before anything was durable"
    assert db.find_block_commit(prepared.execution_id) is None


def test_an_artifact_for_a_different_block_is_refused(temp_database):
    """A stale local proposal presented for a block that was rebuilt. The
    execution id covers the timestamp and the transaction list, so a block with
    the same parent but a dropped transaction does not match."""
    old, new, ready, owner, ctx, prepared_unused = _setup()
    mined = tc.block_execution_id(parent="H", height=1, timestamp=1700000000,
                                  proposer="d4" * 48,
                                  transactions=[{"tx_id": "A"}, {"tx_id": "B"}])
    rebuilt = tc.block_execution_id(parent="H", height=1, timestamp=1700000000,
                                    proposer="d4" * 48,
                                    transactions=[{"tx_id": "A"}])
    prepared = tc.PreparedBlockCommit.freeze(ctx, execution_id=mined,
                                             next_snapshot=object())
    coord = tc.PreparedCommitCoordinator(owner)

    with pytest.raises(tc.PreparedCommitMismatch, match="execution"):
        coord.commit(prepared, proposal=ctx, tip="H+1", execution_id=rebuilt)
    assert db.find_block_commit(mined) is None
    assert db.find_block_commit(rebuilt) is None
    assert owner.session is old
