"""A refused step is a verdict only when a fresh full-width evaluator refuses it too.

A refusal that only this node's shrunk evaluator gives depends on the node, so
the block apply stops with no verdict and the proposer defers the transaction.
"""
import threading
from unittest.mock import MagicMock, patch

import pytest

import tau_allocator as alloc
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session
import test_apply_local_error_verdict as le
import test_approval_apply as ap
from consensus import local_errors
from consensus.approvals import STATUS_FAILED
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot


@pytest.fixture(autouse=True)
def _tau_ready():
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        yield


def _refused():
    return tau_session.StepRefused("the engine refused the step's inputs")


class RecheckSession(le.FakeSession):
    """The fresh evaluator of a recheck: refuses with `step_exc`, else answers."""

    def __init__(self, step_exc=None):
        super().__init__(step_exc=step_exc)
        self.steps = []

    def evaluate(self, inputs, **kwargs):
        self.steps.append((dict(inputs or {}), kwargs))
        return super().evaluate(inputs, **kwargs)


class Rebuild:
    """The rebuild closure of a proposal, answering with one fresh session."""

    def __init__(self, step_exc=None, raises=None):
        self.step_exc = step_exc
        self.raises = raises
        self.calls = []
        self.sessions = []

    def __call__(self, journal, plan, *, allocation=None, on_spawn=None, extra=()):
        self.calls.append({"journal": journal, "plan": plan,
                           "allocation": allocation, "extra": list(extra)})
        if self.raises is not None:
            raise self.raises
        session = RecheckSession(step_exc=self.step_exc)
        self.sessions.append(session)
        if on_spawn is not None:
            on_spawn(session)
        return session


def _proposal(session, rebuild, plan=None):
    plan = plan or tr.RepresentationPlan(width=8, interned=frozenset({12}),
                                         widths=((12, 384),))
    return tp.ProposalContext(
        session=session, journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.MappingSnapshot(epoch="e0"), width=8,
                                  label="proposal"),
        plan=plan, rebuild=rebuild, lifecycle=ConsensusLifecycleManager(),
    )


def _apply(proposal, tx, *, replay_mode=False, proposer=le.PROPOSER, store=None):
    if store is None:
        store = MagicMock()
        store.commit.side_effect = lambda snap: snap
    return TauConsensusEngine(state_store=store).apply(
        TauStateSnapshot(b"hash", b"rules", {}), [tx], 1700000000,
        target_balances={le.SENDER: 1000}, target_sequences={},
        target_lifecycle=proposal.lifecycle, replay_mode=replay_mode,
        proposer_pubkey=proposer, block_height=1, session=proposal.session,
        proposal=proposal,
    )


# Each step site at apply: the transaction and the session that refuses there.
SITES = {
    "fee-era transfer": lambda: (le._transfer_tx(), {}, {}),
    "feeless transfer": lambda: (le._transfer_tx(), {}, {"proposer": None}),
    "custom-input step": lambda: (le._rule_tx(), {"single_only": True}, {}),
    "fee-query step": lambda: (le._rule_tx(), {"multi_only": True}, {}),
}


def _site(name):
    tx, session_kwargs, apply_kwargs = SITES[name]()
    return tx, le.FakeSession(step_exc=_refused(), **session_kwargs), apply_kwargs


# --- the verdict rule at each site ---

@pytest.mark.parametrize("name", list(SITES))
def test_a_refusal_that_the_recheck_confirms_keeps_its_verdict(name):
    tx, session, kwargs = _site(name)
    baseline = le._apply(tx, le.FakeSession(step_exc=_refused(),
                                            multi_only=session.multi_only,
                                            single_only=session.single_only),
                         **kwargs)[0]
    rebuild = Rebuild(step_exc=_refused())
    result = _apply(_proposal(session, rebuild), tx, **kwargs)
    assert len(rebuild.calls) == 1
    assert ([t["tx_id"] for t in result.accepted_transactions]
            == [t["tx_id"] for t in baseline.accepted_transactions])
    assert result.receipts["tx1"]["status"] == baseline.receipts["tx1"]["status"]


@pytest.mark.parametrize("replay_mode", [False, True])
def test_a_confirmed_refusal_at_the_transfer_step_keeps_its_verdict_in_replay(replay_mode):
    rebuild = Rebuild(step_exc=_refused())
    result = _apply(_proposal(le.FakeSession(step_exc=_refused()), rebuild),
                    le._transfer_tx(), replay_mode=replay_mode)
    if replay_mode:
        assert [t["tx_id"] for t in result.accepted_transactions] == ["tx1"]
        assert result.receipts["tx1"]["status"] == "failed"
    else:
        assert [t["tx_id"] for t in result.rejected_transactions] == ["tx1"]


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("name", list(SITES))
def test_a_refusal_only_on_the_shrunk_evaluator_stops_the_block(name, replay_mode):
    tx, session, kwargs = _site(name)
    store = MagicMock()
    rebuild = Rebuild()
    with pytest.raises(tau_session.StepRefusedLocally) as info:
        _apply(_proposal(session, rebuild), tx, replay_mode=replay_mode, store=store,
               **kwargs)
    store.commit.assert_not_called()
    assert local_errors.is_local_apply_error(info.value)
    assert local_errors.owner_of(info.value) == "tx1"
    assert rebuild.sessions[0].disposed


def test_a_recheck_that_fails_stops_the_block():
    store = MagicMock()
    with pytest.raises(tau_session.StepRefusedLocally) as info:
        _apply(_proposal(le.FakeSession(step_exc=_refused()),
                         Rebuild(raises=OSError(28, "No space left on device"))),
               le._transfer_tx(), store=store)
    store.commit.assert_not_called()
    assert isinstance(info.value.__cause__, OSError)
    assert local_errors.owner_of(info.value) == "tx1"


def test_without_a_proposal_a_refusal_keeps_its_verdict_with_no_recheck():
    result, _ = le._apply(le._transfer_tx(), le.FakeSession(step_exc=_refused()))
    assert [t["tx_id"] for t in result.rejected_transactions] == ["tx1"]


def test_the_recheck_gets_the_inputs_of_the_refused_step():
    rebuild = Rebuild(step_exc=_refused())
    _apply(_proposal(le.FakeSession(step_exc=_refused()), rebuild), le._transfer_tx())
    (inputs, kwargs), = rebuild.sessions[0].steps
    assert str(inputs[1]) == "5"
    assert kwargs.get("record") is False


# --- the recheck itself ---

def test_the_recheck_replays_the_branch_on_a_no_shrink_plan():
    rebuild = Rebuild()
    proposal = _proposal(le.FakeSession(), rebuild)
    branch = proposal.transaction("tx1")
    branch.journal.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={13: "7"})
    assert proposal.recheck_step({13: "300"}, branch=branch) == {1: "1"}
    (call,) = rebuild.calls
    assert call["journal"] is proposal.journal
    assert call["extra"] == branch.journal.entries()
    assert call["plan"] == tr.RepresentationPlan.no_shrink(8)
    assert call["allocation"] is not proposal.allocator


@pytest.mark.parametrize("step_exc", [None, _refused()])
def test_the_recheck_leaves_the_proposal_as_it_was(step_exc):
    rebuild = Rebuild(step_exc=step_exc)
    session = le.FakeSession()
    proposal = _proposal(session, rebuild)
    proposal.journal.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "5"})
    proposal.allocator.id_for("bv384:alice")
    branch = proposal.transaction("tx1")
    before = (len(proposal.journal), proposal.allocator.delta(), len(branch.journal))
    try:
        proposal.recheck_step({1: "5"}, branch=branch)
    except tau_session.StepRefused:
        assert step_exc is not None
    assert proposal.session is session and not session.disposed
    assert (len(proposal.journal), proposal.allocator.delta(), len(branch.journal)) == before
    assert not proposal.dirty and not proposal.poisoned
    assert rebuild.sessions[0].disposed


def test_a_refusal_in_the_replay_is_not_a_refusal_verdict():
    proposal = _proposal(le.FakeSession(), Rebuild(raises=_refused()))
    with pytest.raises(RuntimeError, match="replay refused a recorded step") as info:
        proposal.recheck_step({1: "5"})
    assert not isinstance(info.value, tau_session.StepRefused)


def test_a_recheck_that_runs_out_of_its_budget_is_a_timeout():
    class Hanging(RecheckSession):
        def __init__(self):
            super().__init__()
            self.gone = threading.Event()

        def evaluate(self, inputs, **kwargs):
            self.gone.wait(10)
            raise RuntimeError("worker lost")

        def dispose(self):
            super().dispose()
            self.gone.set()

    hanging = Hanging()

    def rebuild(journal, plan, *, allocation=None, on_spawn=None, extra=()):
        on_spawn(hanging)
        return hanging

    proposal = _proposal(le.FakeSession(), rebuild)
    with pytest.raises(TimeoutError):
        proposal.recheck_budget = 0.05
        proposal.recheck_step({1: "5"})
    assert hanging.disposed


def test_a_session_that_starts_after_the_deadline_is_disposed_at_once():
    import time

    late = RecheckSession()

    def rebuild(journal, plan, *, allocation=None, on_spawn=None, extra=()):
        time.sleep(0.2)
        on_spawn(late)
        assert late.disposed
        raise RuntimeError("worker lost")

    proposal = _proposal(le.FakeSession(), rebuild)
    proposal.recheck_budget = 0.01
    with pytest.raises(TimeoutError):
        proposal.recheck_step({1: "5"})


def test_a_failed_dispose_does_not_hide_the_answer():
    class Sticky(RecheckSession):
        def dispose(self):
            raise RuntimeError("already gone")

    def rebuild(journal, plan, *, allocation=None, on_spawn=None, extra=()):
        session = Sticky()
        on_spawn(session)
        return session

    assert _proposal(le.FakeSession(), rebuild).recheck_step({1: "5"}) == {1: "1"}


def test_a_recheck_needs_a_rebuild():
    with pytest.raises(tp.ProposalPoisoned):
        _proposal(le.FakeSession(), None).recheck_step({1: "5"})


# --- the proposer defers the owning transaction ---

@pytest.fixture
def clean_deferrals():
    from commands import createblock

    createblock._deferred.clear()
    yield createblock._deferred
    createblock._deferred.clear()


def test_the_proposer_defers_a_transaction_that_only_the_shrunk_evaluator_refuses(
        node_state, clean_deferrals):
    import db

    (_, good1), (bad_pk, bad), (_, good2) = le._queued_transfers(["sa", "sb", "sc"])
    head = db.get_canonical_head()["block_hash"]

    def factory(**kw):
        plan = tr.plan_representation(candidate_rules=[])
        return tp.ProposalContext(
            session=le.SenderFailingSession(bad_pk, _refused()),
            journal=tj.Journal(authoritative=False),
            allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                      label="proposal"),
            plan=plan, rebuild=Rebuild(),
        )

    out = le._mine(factory)
    assert "error" in out, out
    assert db.get_canonical_head()["block_hash"] == head
    assert set(clean_deferrals) == {bad}

    out = le._mine(factory)
    assert "block_hash" in out, out
    mined = db.get_canonical_head_block().get("tx_ids") or []
    assert good1 in mined and good2 in mined and bad not in mined
    assert le._pending(bad)


# --- the deadline: only the proposer of a new block has one ---

class SlowRebuild(Rebuild):
    """A recheck that takes `seconds`, then answers like Rebuild."""

    def __init__(self, seconds, step_exc=None):
        super().__init__(step_exc=step_exc)
        self.seconds = seconds
        self.finished = 0

    def __call__(self, journal, plan, *, allocation=None, on_spawn=None, extra=()):
        import time

        session = super().__call__(journal, plan, allocation=allocation,
                                   on_spawn=on_spawn, extra=extra)
        end = time.monotonic() + self.seconds
        while time.monotonic() < end:
            if session.disposed:
                raise RuntimeError("worker lost")
            time.sleep(0.01)
        self.finished += 1
        return session


def test_a_proposal_has_no_recheck_deadline_unless_its_proposer_sets_one():
    assert _proposal(le.FakeSession(), Rebuild()).recheck_budget is None


def test_the_proposer_gives_up_on_a_slow_recheck_and_defers_the_transaction(
        node_state, clean_deferrals, monkeypatch):
    import db

    monkeypatch.setattr(tp, "RECHECK_BUDGET_SECONDS", 0.05)
    (_, good), (bad_pk, bad) = le._queued_transfers(["ta", "tb"])
    rebuild = SlowRebuild(0.5, step_exc=_refused())

    def factory(**kw):
        plan = tr.plan_representation(candidate_rules=[])
        return tp.ProposalContext(
            session=le.SenderFailingSession(bad_pk, _refused()),
            journal=tj.Journal(authoritative=False),
            allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                      label="proposal"),
            plan=plan, rebuild=rebuild,
        )

    out = le._mine(factory)
    assert "error" in out, out
    assert rebuild.finished == 0
    assert set(clean_deferrals) == {bad}
    assert le._pending(bad)


def test_the_receive_path_waits_for_a_slow_recheck_and_gives_its_verdict(
        node_state, monkeypatch, caplog):
    import chain_state
    import db
    import tau_authority as auth
    import tau_commit

    monkeypatch.setattr(tp, "RECHECK_BUDGET_SECONDS", 0.05)
    owner = auth.AuthoritativeTauOwner(ready=threading.Event())
    owner.enabled = True
    auth.reset(owner)
    tau_commit.registry().discard()
    rebuilds = []

    proposals = []

    def build_proposal(**kw):
        rebuilds.append(SlowRebuild(0.3, step_exc=_refused()))
        proposals.append(_proposal(le.FakeSession(step_exc=_refused()), rebuilds[-1],
                                   plan=tr.plan_representation(candidate_rules=[])))
        return proposals[-1]

    owner.build_proposal = build_proposal
    try:
        with patch.object(TauConsensusEngine, "verify_block_header",
                          lambda *a, **k: True):
            block = le._transfer_block()
            head = db.get_canonical_head()["block_hash"]
            accepted = chain_state.process_new_block(block)
    finally:
        tau_commit.registry().discard()
        auth.reset(None)
    assert proposals and all(p.recheck_budget is None for p in proposals)
    assert rebuilds and rebuilds[0].finished == 1
    assert "node-local" not in caplog.text.lower()
    # The verdict: the block is accepted and its refused transfer moves nothing.
    assert accepted is True
    assert db.get_canonical_head()["block_hash"] == block.block_hash != head
    assert chain_state.get_balance(le.RECIPIENT) == 0


# --- the parked transfer measure ---

def _measure_raises(exc, amount):
    real = tau_session.InProcessSession.evaluate

    def evaluate(self, inputs, **kwargs):
        if kwargs.get("multi") and str((inputs or {}).get(1)) == str(amount):
            raise exc
        return real(self, inputs, **kwargs)

    return patch.object(tau_session.InProcessSession, "evaluate", evaluate)


def test_a_refused_measure_of_an_approval_request_rejects_it():
    req = ap._request()
    with _measure_raises(_refused(), req.amount):
        result, lm, _ = ap._apply([ap.request_tx(req)])
    assert lm.approval_requests.get_request(req.request_id) is None
    (outcome,) = result.outcomes
    assert outcome.status == "invalid"
    assert "Approval request rejected: the engine refused its transfer" in ap._logs(result)


def test_a_refused_measure_of_an_approval_request_in_replay_stays_in_the_block():
    """In replay the transaction stays in the block, as at a refused transfer step."""
    real = TauConsensusEngine.apply_block

    def replayed(self, *args, **kwargs):
        return real(self, *args, replay_mode=True, **kwargs)

    req = ap._request()
    with _measure_raises(_refused(), req.amount), \
            patch.object(TauConsensusEngine, "apply_block", replayed):
        result, lm, _ = ap._apply([ap.request_tx(req)])
    assert lm.approval_requests.get_request(req.request_id) is None
    (outcome,) = result.outcomes
    assert outcome.status != "invalid"
    assert "Approval request rejected: the engine refused its transfer" in ap._logs(result)


def test_a_refused_measure_of_a_vote_fails_the_request_and_keeps_the_vote():
    req = ap._request()
    lm = ap._seeded(req)
    with _measure_raises(_refused(), req.amount):
        result, post, _ = ap._apply([ap.vote_tx(req)], lm=lm)
    assert post.approval_requests.get_request(req.request_id) is None
    assert post.approval_requests.terminal_status[req.request_id] == STATUS_FAILED
    logs = ap._logs(result)
    assert "Transfer vote recorded" in logs
    assert "Parked transfer could not be executed" in logs
    assert ap._balances(result)[ap.BOB] == 0


@pytest.mark.parametrize("make_tx", ["request", "vote"])
def test_a_local_refusal_of_the_measure_stops_the_block_with_an_owner(make_tx):
    req = ap._request()
    lm = ap._seeded(req) if make_tx == "vote" else None
    tx = ap.vote_tx(req) if make_tx == "vote" else ap.request_tx(req)
    with _measure_raises(tau_session.StepRefusedLocally("shrunk only"), req.amount):
        with pytest.raises(tau_session.StepRefusedLocally) as info:
            ap._apply([tx], lm=lm)
    assert local_errors.owner_of(info.value) is not None
