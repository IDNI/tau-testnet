"""A worker that cannot serve is a lost worker, and a dead one is never promoted.

Whatever the worker says about its own health is node-local, so it must reach the
owners as a loss and never as a verdict on the rule or transaction in flight.
"""
import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import block as block_mod
import chain_state
import db
import tau_allocator as alloc
import tau_commit as tc
import tau_journal as tj
import tau_session
import tau_speculation as spec
from commands import createblock
from consensus.engine import TauConsensusEngine

import test_block_artifact_reuse as reuse
import test_commit_promotion as promotion
import test_worker_lost as wl
from test_tau_speculation import _assert_lost_and_reaped, _session
from test_worker_lost import _accept_headers, enabled_owner  # noqa: F401 - fixtures

UNHEALTHY = {"ok": False, "phase": "session", "error": "session unusable",
             "session_healthy": False}
REFUSED = {"ok": False, "outputs": None, "diagnostics": "error: refused",
           "session_healthy": True}


def _answers(**fields):
    """A worker that answers every request with the same fields."""
    return f'''
        n = 0
        while True:
            req = read()
            if req is None: break
            n += 1
            write({{"request_id": req["request_id"], "state_revision": n,
                   "candidate_id": req.get("candidate_id", ""), **{fields!r}}})
    '''


def _call(session, op):
    return {
        "init": lambda: session.init("always ( o0[t] = 1 )."),
        "revise": lambda: session.revise(wl.RULE, "c"),
        "step": lambda: session.step({}),
        "state": session.state,
    }[op]()


def _worker_session(tmp_path, body):
    return tau_session.WorkerSession(
        _session(tmp_path, body),
        allocation=alloc.Allocator(alloc.MappingSnapshot(epoch="e0", committed={}),
                                   width=8, label="proposal"))


@pytest.fixture(autouse=True)
def _clean():
    createblock._deferred.clear()
    tc.registry().discard()
    yield
    createblock._deferred.clear()
    tc.registry().discard()


# --- the client ------------------------------------------------------------------

@pytest.mark.parametrize("op", ["init", "revise", "step", "state"])
def test_an_unhealthy_session_is_a_lost_worker_on_every_operation(tmp_path, op):
    s = _session(tmp_path, _answers(**UNHEALTHY))
    with pytest.raises(spec.WorkerLost, match="session unusable"):
        _call(s, op)
    _assert_lost_and_reaped(s)


def test_an_unhealthy_session_is_not_absorbed_by_a_broad_handler(tmp_path):
    s = _session(tmp_path, _answers(**UNHEALTHY))
    with pytest.raises(spec.WorkerLost):
        try:
            s.step({})
        except Exception:  # noqa: BLE001 - the point of the test
            pytest.fail("a broad catch absorbed an unusable worker")


def test_an_unavailable_response_is_a_lost_worker(tmp_path):
    s = _session(tmp_path, _answers(ok=False, unavailable=True,
                                    error="native tau unavailable"))
    with pytest.raises(spec.WorkerLost, match="native tau unavailable"):
        s.state()
    _assert_lost_and_reaped(s)


def test_the_startup_refusal_is_a_lost_worker_and_not_a_protocol_error(tmp_path):
    """It is written before any request is read, so it names no request."""
    s = _session(tmp_path, '''
        write({"ok": False, "phase": "startup", "unavailable": True,
               "error": "native tau unavailable: no module"})
        while read() is not None: pass
    ''')
    with pytest.raises(spec.WorkerLost, match="no module"):
        s.init("always ( o0[t] = 1 ).")
    _assert_lost_and_reaped(s)


def test_an_interpreter_that_could_not_be_built_is_a_lost_worker(tmp_path):
    """The worker marks a session without an interpreter unhealthy, so the failure
    arrives as a loss that carries the engine's diagnostics."""
    s = _session(tmp_path, _answers(
        ok=False, phase="interpreter_construction",
        diagnostics="syntax error near x", session_healthy=False))
    with pytest.raises(spec.WorkerLost, match="syntax error near x"):
        s.init("always ( o0[t] = 1 ).")
    _assert_lost_and_reaped(s)


def test_a_healthy_refusal_to_build_stays_an_ordinary_speculation_error(tmp_path):
    s = _session(tmp_path, _answers(
        ok=False, phase="interpreter_construction", diagnostics="bad",
        session_healthy=True))
    with pytest.raises(spec.SpeculationError, match="construction failed"):
        s.init("always ( o0[t] = 1 ).")
    assert s._proc.poll() is None, "a healthy refusal cost the worker"
    s.kill()


def test_a_worker_that_turns_unhealthy_is_lost_from_then_on(tmp_path):
    s = _session(tmp_path, '''
        n = 0
        while True:
            req = read()
            if req is None: break
            n += 1
            healthy = n < 3
            write({"request_id": req["request_id"], "state_revision": n,
                   "ok": healthy, "session_healthy": healthy, "outputs": {},
                   "error": "worker raised RuntimeError('boom')"})
    ''')
    assert s.step({})["ok"] and s.step({})["ok"]
    with pytest.raises(spec.WorkerLost, match="boom"):
        s.step({})
    _assert_lost_and_reaped(s)


def test_a_malformed_response_is_still_a_protocol_error(tmp_path):
    s = _session(tmp_path, '''
        while True:
            req = read()
            if req is None: break
            write({"ok": True, "request_id": 999, "state_revision": 1})
    ''')
    with pytest.raises(spec.SpeculationProtocolError):
        s.state()
    s.kill()


# --- the session -----------------------------------------------------------------

def test_a_healthy_session_that_refuses_a_step_is_a_refusal_not_a_loss(tmp_path):
    session = _worker_session(tmp_path, _answers(**REFUSED))
    with pytest.raises(tau_session.StepRefused):
        session.evaluate({1: "5"})
    assert session._spec._proc.poll() is None, "a refusal cost the worker"
    session.dispose()


def test_an_unhealthy_step_through_a_session_is_a_loss_not_a_refusal(tmp_path):
    session = _worker_session(tmp_path, _answers(**UNHEALTHY))
    with pytest.raises(spec.WorkerLost):
        session.evaluate({1: "5"})
    assert session._spec._proc.returncode is not None


def test_an_unhealthy_revision_through_a_session_is_a_loss(tmp_path):
    session = _worker_session(tmp_path, _answers(**UNHEALTHY))
    with pytest.raises(spec.WorkerLost):
        session.apply_rule(wl.RULE)
    assert session._spec._proc.returncode is not None


# --- the owners ------------------------------------------------------------------

def test_apply_aborts_on_an_unhealthy_step_instead_of_rejecting(temp_database, tmp_path):
    session = _worker_session(tmp_path, _answers(**UNHEALTHY))
    with pytest.raises(spec.WorkerLost):
        wl._apply(session, wl._proposal(session), wl._transfer_tx())


def test_apply_still_rejects_when_a_healthy_session_refuses_the_step(
        temp_database, tmp_path):
    session = _worker_session(tmp_path, _answers(**REFUSED))
    result = wl._apply(session, wl._proposal(session), wl._transfer_tx())
    assert result.rejected_transactions, result
    session.dispose()


def test_a_round_aborts_on_an_unhealthy_step_and_the_batch_stays_pending(
        node_state, tmp_path):
    tx_hash = wl._queued_transfer("sick")
    head = db.get_canonical_head()["block_hash"]
    session = _worker_session(tmp_path, _answers(**UNHEALTHY))

    out = wl._mine_with(lambda **kw: wl._proposal(session))

    assert "error" in out and "evaluator lost" in out["error"], out
    assert db.get_canonical_head()["block_hash"] == head
    assert wl._where(tx_hash) == "mempool", "an unusable worker became a verdict"
    assert db.get_dropped_tx(tx_hash) is None
    assert set(createblock._deferred) == {tx_hash}, (
        "the transaction in evaluation was not deferred")


def test_a_block_is_not_accepted_now_when_its_evaluation_meets_an_unhealthy_step(
        node_state, enabled_owner, tmp_path):
    enabled_owner.enabled = False      # admission would need a native engine
    tx_hash = wl._queued_transfer("ingest")
    enabled_owner.enabled = True
    tx = json.loads(db.get_mempool_entry(tx_hash)["payload"])
    snapshot = wl._next_snapshot()
    head = db.get_canonical_head()
    block = block_mod.Block.create(
        block_number=int(head["header"]["block_number"]) + 1,
        previous_hash=head["block_hash"], transactions=[tx],
        proposer_pubkey="d4" * 48, timestamp=int(time.time()),
        state_hash=snapshot.state_hash)
    session = _worker_session(tmp_path, _answers(**UNHEALTHY))
    proposal = wl._proposal(session)
    enabled_owner.build_proposal = lambda **kw: proposal

    assert chain_state.process_new_block(block) is False

    assert db.get_canonical_head()["block_hash"] == head["block_hash"]
    assert "evaluator lost" in (proposal.poisoned or ""), (
        "the block was refused as invalid, not left for a retry")


# --- the commit gate -------------------------------------------------------------

def _frozen(worker=None):
    worker = worker or promotion._Worker("w")
    ctx = promotion._proposal(worker)
    frozen = tc.PreparedBlockCommit.freeze(ctx, execution_id="exec-1",
                                           next_snapshot=object())
    return worker, ctx, frozen


def _dies():
    raise spec.WorkerLost(wl.LOST)


def test_the_gate_refuses_a_worker_that_died_after_freezing(temp_database):
    worker, ctx, frozen = _frozen()
    worker._spec.state = _dies
    with pytest.raises(tc.PreparedCommitMismatch, match="could not report its state"):
        frozen.verify(proposal=ctx, execution_id="exec-1")


def test_the_gate_refuses_a_dead_worker_without_a_proposal_too(temp_database):
    worker, _, frozen = _frozen()
    worker._spec.state = _dies
    with pytest.raises(tc.PreparedCommitMismatch, match="could not report its state"):
        frozen.verify()


def test_the_gate_refuses_a_worker_that_fell_unhealthy_after_freezing(temp_database):
    worker, ctx, frozen = _frozen()
    worker._spec._state["session_healthy"] = False
    with pytest.raises(tc.PreparedCommitMismatch, match="unhealthy"):
        frozen.verify(proposal=ctx, execution_id="exec-1")


def test_the_gate_refuses_a_worker_whose_state_call_fails(temp_database):
    worker, ctx, frozen = _frozen()

    def _fails():
        raise RuntimeError("boom")

    worker._spec.state = _fails
    with pytest.raises(tc.PreparedCommitMismatch, match="boom"):
        frozen.verify(proposal=ctx, execution_id="exec-1")


def test_the_gate_reports_a_dead_worker_beside_every_other_problem(temp_database):
    worker, ctx, frozen = _frozen()
    worker._spec.state = _dies
    ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="later")
    with pytest.raises(tc.PreparedCommitMismatch) as caught:
        frozen.verify(proposal=ctx, execution_id="exec-1")
    assert "could not report its state" in str(caught.value)
    assert "journal head moved" in str(caught.value)


def test_a_worker_that_still_answers_passes_the_gate(temp_database):
    _, ctx, frozen = _frozen()
    frozen.verify(proposal=ctx, execution_id="exec-1")


def test_a_session_without_counters_still_passes_the_gate(temp_database):
    class _InProcess:
        journal = None
        allocation = None

    ctx = promotion._proposal(_InProcess())
    frozen = tc.PreparedBlockCommit.freeze(ctx, execution_id="exec-1",
                                           next_snapshot=object())
    frozen.verify(proposal=ctx, execution_id="exec-1")
    ctx.session._spec = SimpleNamespace()       # a spec that reports nothing
    frozen.verify(proposal=ctx, execution_id="exec-1")


def test_a_real_worker_killed_after_freezing_fails_the_gate(temp_database, tmp_path):
    session = _worker_session(tmp_path, _answers(
        ok=True, session_healthy=True, spec_revision=1, time_point=2))
    ctx = promotion._proposal(session)
    frozen = tc.PreparedBlockCommit.freeze(ctx, execution_id="exec-1",
                                           next_snapshot=object())
    frozen.verify(proposal=ctx, execution_id="exec-1")

    session._spec._proc.kill()
    session._spec._proc.wait(timeout=10)

    with pytest.raises(tc.PreparedCommitMismatch, match="could not report its state"):
        frozen.verify(proposal=ctx, execution_id="exec-1")
    session.dispose()


def test_ingestion_evaluates_the_block_itself_when_the_artifacts_worker_died(node_state):
    snapshot = reuse._next_snapshot()
    blk = reuse._block(snapshot)
    execution_id, prepared, ctx, worker = reuse._artifact(blk, snapshot)
    worker._spec = SimpleNamespace(state=_dies)
    tc.registry().offer(execution_id, prepared, ctx)

    calls = []
    real = TauConsensusEngine.apply_block

    def _record(self, *a, **k):
        calls.append(True)
        return real(self, *a, **k)

    with patch.object(TauConsensusEngine, "apply_block", _record):
        assert chain_state.process_new_block(blk) is True

    assert calls, "a dead worker's artifact was reused"
    assert worker.disposed, "the refused artifact's worker was leaked"
    assert db.get_canonical_head()["block_hash"] == blk.block_hash
    assert tc.registry().pending is None
