"""A worker that dies is an operational failure, never a verdict.

Apply's broad handlers turn any `Exception` into a rejection, so `WorkerLost`
bypasses them and every session owner translates it at its own edge.
"""
import ast
import os
import re
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import tau_admission
import tau_advisory
import tau_allocator as alloc
import tau_authority as auth
import tau_commit
import tau_journal as tj
import tau_preflight
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session
import tau_speculation as spec
from consensus.engine import TauConsensusEngine, _apply_composite_rule
from consensus.state import TauStateSnapshot
from errors import EvaluatorLost, TauTestnetError

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENDER = "aa" * 48
RECIPIENT = "cc" * 48
PROPOSER = "bb" * 48
RULE = "always ( o5[t]:bv[24] = { #x000002 }:bv[24] )."
LOST = "worker closed the result channel"


class _LostSession:
    """A speculative session whose worker is gone at the named call."""

    is_speculative = True

    def __init__(self, lost_on, failure=None):
        self.lost_on = lost_on
        self.failure = failure or (lambda: spec.WorkerLost(LOST))
        self.allocation = None
        self.journal = None
        self.disposed = False

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, **kwargs):
        if self.lost_on == "apply_rule":
            raise self.failure()
        return "ok"

    def evaluate(self, inputs, *, multi=False, target=None, **kwargs):
        if self.lost_on == "evaluate":
            raise self.failure()
        outputs = {1: "1", 5: "1", 9: "0"}
        if multi:
            return outputs
        return "" if target is None else outputs.get(target, "")

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        self.disposed = True


def _proposal(session, label="proposal"):
    plan = tr.plan_representation(candidate_rules=[RULE])
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan,
        lifecycle=MagicMock(approval_slots_active=False),
        label=label,
    )


def _rule_tx():
    return {"tx_id": "r1", "tx_type": "user_tx", "sender_pubkey": SENDER,
            "sequence_number": 0, "fee_limit": "100", "operations": {"0": RULE}}


def _transfer_tx():
    return {"tx_id": "t1", "tx_type": "user_tx", "sender_pubkey": SENDER,
            "sequence_number": 0, "fee_limit": "100",
            "operations": {"1": [[SENDER, RECIPIENT, "5"]]}}


def _apply(session, proposal, tx):
    engine = TauConsensusEngine(state_store=MagicMock())
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        return engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [tx], 1700000000,
            target_balances={SENDER: 1000},
            target_sequences={},
            target_lifecycle=proposal.lifecycle,
            proposer_pubkey=PROPOSER,
            block_height=1,
            proposal=proposal,
            session=session,
        )


# --- the types -------------------------------------------------------------------

def test_the_typed_failure_is_an_ordinary_operational_exception():
    assert issubclass(EvaluatorLost, Exception)
    assert issubclass(EvaluatorLost, TauTestnetError)
    assert not issubclass(spec.WorkerLost, Exception)


def test_no_broad_except_can_absorb_a_lost_worker():
    with pytest.raises(spec.WorkerLost):
        try:
            raise spec.WorkerLost(LOST)
        except Exception:  # noqa: BLE001 - the point of the test
            pytest.fail("a broad catch absorbed the loss of the worker")


# --- the boundary ----------------------------------------------------------------

def test_the_boundary_turns_a_lost_worker_into_a_typed_failure():
    proposal = MagicMock()
    proposal.poisoned = None
    with pytest.raises(EvaluatorLost, match=LOST):
        with tp.boundary(proposal, label="test"):
            raise spec.WorkerLost(LOST)
    proposal.poison.assert_called_once()
    assert proposal.poison.call_args[0][0].startswith("evaluator lost:")


def test_the_boundary_poisons_a_real_proposal():
    proposal = _proposal(_LostSession("evaluate"))
    with pytest.raises(EvaluatorLost):
        with tp.boundary(proposal, label="test"):
            raise spec.WorkerLost(LOST)
    assert "evaluator lost" in (proposal.poisoned or "")


def test_the_boundary_without_a_proposal_still_translates():
    with pytest.raises(EvaluatorLost):
        with tp.boundary(label="build"):
            raise spec.WorkerLost(LOST)


def test_an_already_poisoned_proposal_keeps_its_first_reason():
    proposal = MagicMock()
    proposal.poisoned = "isolation breach: first"
    with pytest.raises(EvaluatorLost):
        with tp.boundary(proposal, label="test"):
            raise spec.WorkerLost(LOST)
    proposal.poison.assert_not_called()


def test_cleanup_inside_the_boundary_runs_before_the_failure_surfaces():
    session = _LostSession("evaluate")
    proposal = _proposal(session)
    with pytest.raises(EvaluatorLost):
        with tp.boundary(proposal, label="test"):
            try:
                raise spec.WorkerLost(LOST)
            finally:
                proposal.dispose()
    assert session.disposed


# --- apply: the loss passes through every per-transaction handler -------------------

@pytest.mark.parametrize("lost_on,tx", [
    ("apply_rule", _rule_tx),
    ("evaluate", _transfer_tx),
])
def test_apply_does_not_turn_a_lost_worker_into_a_rejection(temp_database, lost_on, tx):
    session = _LostSession(lost_on)
    proposal = _proposal(session)
    with pytest.raises(spec.WorkerLost):
        _apply(session, proposal, tx())


@pytest.mark.parametrize("lost_on,tx", [
    ("apply_rule", _rule_tx),
    ("evaluate", _transfer_tx),
])
def test_an_ordinary_failure_at_the_same_call_is_still_a_rejection(
        temp_database, lost_on, tx):
    """The discriminator: the handlers are real, and an `Exception` from the
    same call IS taken for a verdict -- which a lost worker would be, were it one."""
    session = _LostSession(lost_on, failure=lambda: RuntimeError(LOST))
    proposal = _proposal(session)
    result = _apply(session, proposal, tx())
    assert result.rejected_transactions, result


def test_a_composite_rule_does_not_report_a_lost_worker_as_a_refusal():
    session = _LostSession("apply_rule")
    with pytest.raises(spec.WorkerLost):
        _apply_composite_rule(RULE, {"logs": []}, session=session)


def test_a_composite_rule_still_reports_an_ordinary_failure_as_a_refusal():
    session = _LostSession("apply_rule", failure=lambda: RuntimeError("boom"))
    ok, detail = _apply_composite_rule(RULE, {"logs": []}, session=session)
    assert (ok, detail) == (False, "boom")


def test_a_healthy_session_gives_the_same_verdicts(temp_database):
    session = _LostSession(None)
    result = _apply(session, _proposal(session), _transfer_tx())
    assert not result.rejected_transactions, result


# --- the commit artifact ---------------------------------------------------------------

class _DeadSpec:
    def state(self):
        raise spec.WorkerLost(LOST)


def test_a_lost_worker_cannot_report_its_state_strictly():
    session = SimpleNamespace(_spec=_DeadSpec())
    with pytest.raises(tau_commit.WorkerUnavailable, match=LOST):
        tau_commit._worker_state(session, strict=True)


def test_a_lost_worker_reports_no_counters_when_not_strict():
    session = SimpleNamespace(_spec=_DeadSpec())
    assert tau_commit._worker_state(session) == {}


# --- admission --------------------------------------------------------------------------

class _Deadline:
    def __init__(self, expired=False):
        self.expired = expired

    def cancel(self):
        pass


class _AdmissionSession:
    def __init__(self, deadline=None, expire=False):
        self._deadline = deadline
        self._expire = expire

    def _lose(self):
        if self._expire:
            self._deadline.expired = True
        raise spec.WorkerLost(LOST)

    def apply_rule(self, *a, **k):
        self._lose()

    def evaluate(self, *a, **k):
        self._lose()

    def dispose(self):
        pass


def _context(session, deadline=None):
    return tau_admission.AdmissionContext(
        session, anchor={}, plan=None, label="admission", deadline=deadline,
        release=None)


@pytest.mark.parametrize("call", ["revise", "step"])
def test_admission_reports_a_lost_worker_as_unavailable(call):
    context = _context(_AdmissionSession())
    args = (RULE,) if call == "revise" else ({},)
    with pytest.raises(tau_admission.AdmissionUnavailable, match=LOST) as caught:
        getattr(context, call)(*args)
    assert not isinstance(caught.value, tau_admission.AdmissionTimeout)


@pytest.mark.parametrize("call", ["revise", "step"])
def test_admission_reports_a_loss_after_the_deadline_as_a_timeout(call):
    """The deadline kills the worker to unblock the read; the loss it causes is
    the budget running out, not a worker failing on its own."""
    deadline = _Deadline()
    context = _context(_AdmissionSession(deadline, expire=True), deadline)
    args = (RULE,) if call == "revise" else ({},)
    with pytest.raises(tau_admission.AdmissionTimeout):
        getattr(context, call)(*args)


def _store(rows=()):
    anchor = {"rows": list(rows), "journal_head": None, "journal_sequence": 0,
              "epoch": "e0", "high_water": 0}
    return SimpleNamespace(committed_anchor=lambda *a, **k: anchor)


def test_building_a_context_reports_a_lost_worker_as_unavailable():
    with patch.object(tau_session, "replay_entries",
                      side_effect=spec.WorkerLost(LOST)):
        with pytest.raises(tau_admission.AdmissionUnavailable, match="replayed"):
            tau_admission._build(candidate_rules=(), label="t", deadline=None,
                                 cwd=None, env=None, store=_store())


def test_building_a_context_after_the_deadline_is_a_timeout():
    deadline = _Deadline(expired=True)
    with patch.object(tau_session, "replay_entries",
                      side_effect=spec.WorkerLost(LOST)):
        with pytest.raises(tau_admission.AdmissionTimeout):
            tau_admission._build(candidate_rules=(), label="t", deadline=deadline,
                                 cwd=None, env=None, store=_store())


def test_the_standby_thread_survives_a_lost_worker():
    standby = tau_admission._Standby()
    standby.enabled = True
    with patch.object(tau_admission, "_build", side_effect=spec.WorkerLost(LOST)):
        standby.refill()
        for thread in threading.enumerate():
            if thread.name == "admission-standby":
                thread.join(timeout=10)
    assert standby._building is False, "a lost worker left the standby marked busy"
    assert standby._ready is None


# --- advisory ---------------------------------------------------------------------------

class _LostStep:
    def __init__(self):
        self.killed = False

    def step(self, inputs):
        raise spec.WorkerLost(LOST)

    def kill(self):
        self.killed = True


@pytest.mark.parametrize("call,ensure,args", [
    ("evaluate", "_ensure", ("spec", {}, 5)),
    ("evaluate_many", "_ensure", ("spec", {}, [5, 8])),
    ("evaluate_consensus", "_ensure_consensus", ("rules", {}, [6, 7])),
])
def test_an_advisory_answer_is_no_opinion_when_the_worker_is_lost(call, ensure, args):
    evaluator = tau_advisory.AdvisoryEvaluator()
    session = _LostStep()
    with patch.object(evaluator, ensure, return_value=session):
        assert getattr(evaluator, call)(*args) is None
    assert session.killed or evaluator._session is None


# --- preflight --------------------------------------------------------------------------

def test_preflight_is_unavailable_when_the_worker_is_lost():
    with patch.object(spec, "validate_once", side_effect=spec.WorkerLost(LOST)):
        result = tau_preflight.preflight_rule("always ( o0[t] = 1 ).", RULE)
    assert result.verdict == tau_preflight.UNAVAILABLE
    assert LOST in result.detail


def test_preflight_is_unavailable_when_the_worker_exits_without_answering(tmp_path):
    worker = tmp_path / "dies.py"
    worker.write_text("import sys\nsys.stdin.buffer.read(4)\nsys.exit(3)\n")
    result = tau_preflight.preflight_rule(
        "always ( o0[t] = 1 ).", RULE, worker=str(worker))
    assert result.verdict == tau_preflight.UNAVAILABLE


# --- the session factories ---------------------------------------------------------------

class _SpecSession:
    def __init__(self, init_fails=False):
        self.init_fails = init_fails
        self.killed = False

    def init(self, text):
        if self.init_fails:
            raise spec.WorkerLost(LOST)

    def revise(self, *a, **k):
        raise spec.WorkerLost(LOST)

    def kill(self):
        self.killed = True


def test_a_worker_that_dies_while_starting_is_not_left_behind():
    started = _SpecSession(init_fails=True)
    with patch.object(spec, "SpeculationSession", return_value=started):
        with pytest.raises(spec.WorkerLost):
            tau_session.WorkerSession.spawn("always ( o0[t] = 1 ).")
    assert started.killed


def test_a_worker_that_dies_during_the_trace_is_not_left_behind():
    started = _SpecSession()
    with patch.object(spec, "SpeculationSession", return_value=started):
        with pytest.raises(spec.WorkerLost):
            tau_session.WorkerSession.spawn(
                "always ( o0[t] = 1 ).",
                trace=[{"kind": tau_session.RULE, "rule_text": RULE}],
                allocation=alloc.Allocator(alloc.DbMappingSnapshot(), width=24,
                                           label="t"))
    assert started.killed


class _Replayed:
    def __init__(self, fail=False):
        self.fail = fail
        self.disposed = False
        self.last_outcome = {"outputs": {}, "outcome": "ACCEPTED_CHANGED"}

    def apply_rule(self, text, **kwargs):
        if self.fail:
            raise spec.WorkerLost(LOST)

    def last_receipt(self):
        return {"accepted": True}

    def dispose(self):
        self.disposed = True


def _revision(text=RULE):
    journal = tj.Journal(authoritative=False)
    journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text=text)
    return journal.entries()[-1]


def test_a_replay_that_loses_its_worker_disposes_what_it_spawned():
    spawned = []

    def respawn():
        spawned.append(_Replayed(fail=True))
        return spawned[-1]

    with pytest.raises(spec.WorkerLost):
        tau_session.replay_entries(None, [_revision()], respawn=respawn)
    assert spawned and all(s.disposed for s in spawned)


def test_a_replay_does_not_dispose_the_session_it_was_given():
    given = _Replayed(fail=True)
    with pytest.raises(spec.WorkerLost):
        tau_session.replay_entries(given, [_revision()], respawn=lambda: _Replayed())
    assert not given.disposed


def test_a_successful_replay_keeps_what_it_spawned():
    spawned = []

    def respawn():
        spawned.append(_Replayed())
        return spawned[-1]

    session = tau_session.replay_entries(None, [_revision()], respawn=respawn)
    assert session is spawned[0] and not session.disposed


# --- the authoritative owner ----------------------------------------------------------------

def _owner():
    ready = threading.Event()
    owner = auth.AuthoritativeTauOwner(ready=ready,
                                       program_baseline="always ( o0[t] = 1 ).")
    return owner, ready


def test_a_lost_worker_during_reconstruction_leaves_the_owner_unavailable(temp_database):
    owner, ready = _owner()
    with patch.object(tau_session.WorkerSession, "reconstruct",
                      side_effect=spec.WorkerLost(LOST)):
        with pytest.raises(auth.AuthorityUnavailable, match=LOST):
            owner.reconstruct_from_committed()
    assert owner.state == auth.UNAVAILABLE
    assert not ready.is_set()
    assert LOST in owner.reason


def test_a_lost_worker_while_starting_the_genesis_worker_is_unavailable(temp_database):
    owner, ready = _owner()
    with patch.object(tau_session.WorkerSession, "spawn",
                      side_effect=spec.WorkerLost(LOST)):
        with pytest.raises(auth.AuthorityUnavailable, match=LOST):
            owner.rebuild_genesis("g" * 64)
    assert owner.state == auth.UNAVAILABLE
    assert not ready.is_set()


def test_a_lost_worker_while_applying_the_genesis_rules_is_unavailable(temp_database):
    owner, ready = _owner()
    worker = _Replayed(fail=True)
    plan = [{"text": RULE, "persist": False, "label": "r"}]
    with patch.object(tau_session.WorkerSession, "spawn", return_value=worker), \
         patch("chain_state.get_tau_restore_plan", return_value=plan):
        with pytest.raises(auth.AuthorityUnavailable, match=LOST):
            owner.rebuild_genesis("g" * 64)
    assert worker.disposed
    assert owner.state == auth.UNAVAILABLE


def test_a_lost_worker_during_startup_reaches_the_server_as_an_ordinary_error(temp_database):
    """`server.py` wraps `initialize` in `except Exception`; a BaseException
    escaping it would not be wrapped and would unwind the process."""
    owner, ready = _owner()
    with patch.object(tau_session.WorkerSession, "spawn",
                      side_effect=spec.WorkerLost(LOST)):
        with pytest.raises(Exception) as caught:
            owner.initialize()
    assert isinstance(caught.value, auth.AuthorityUnavailable)


# --- ingestion and rebuild ---------------------------------------------------------------

class _Worker:
    """What a proposal holds: enough surface for freezing and disposal."""

    def __init__(self):
        self._spec = SimpleNamespace(
            state=lambda: {"spec_revision": 1, "time_point": 4,
                           "session_healthy": True})
        self.journal = None
        self.allocation = None
        self.disposed = False

    def dispose(self):
        self.disposed = True


@pytest.fixture
def enabled_owner():
    owner = auth.AuthoritativeTauOwner(ready=threading.Event())
    owner.enabled = True
    auth.reset(owner)
    tau_commit.registry().discard()
    yield owner
    tau_commit.registry().discard()
    auth.reset(None)


@pytest.fixture(autouse=True)
def _accept_headers():
    with patch.object(TauConsensusEngine, "verify_block_header",
                      lambda *a, **k: True):
        yield


def _next_snapshot():
    import chain_state
    from chain_state import compute_accounts_hash
    from consensus.state import compute_consensus_state_hash

    app_rules = (chain_state._application_rules_state or "").encode("utf-8")
    cons_rules = (chain_state._consensus_rules_state or "").encode("utf-8")
    acc_hash = compute_accounts_hash(chain_state._balances,
                                     chain_state._sequence_numbers)
    meta_hash = chain_state._lifecycle_manager.consensus_meta_hash()
    return TauStateSnapshot(
        state_hash=compute_consensus_state_hash(cons_rules, app_rules, acc_hash,
                                                meta_hash),
        tau_bytes=app_rules,
        metadata={
            "balances": dict(chain_state._balances),
            "sequence_numbers": dict(chain_state._sequence_numbers),
            "last_transfer_ts": dict(chain_state._last_transfer_ts),
            "lifecycle_manager": chain_state._lifecycle_manager,
            "consensus_rules_state": chain_state._consensus_rules_state,
            "active_consensus_id": chain_state._active_consensus_id,
        },
    )


def _next_block(snapshot):
    import block as block_mod
    import db

    head = db.get_canonical_head() or {}
    header = head.get("header") or {}
    return block_mod.Block.create(
        block_number=int(header.get("block_number", -1)) + 1,
        previous_hash=head.get("block_hash") or "0" * 64,
        transactions=[],
        proposer_pubkey="d4" * 48,
        timestamp=int(time.time()),
        state_hash=snapshot.state_hash,
    )


def _empty_proposal(worker):
    plan = tr.plan_representation(candidate_rules=[])
    return tp.ProposalContext(
        session=worker, journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan,
    )


def _ingest_with(owner, *, build=None, apply=None, freeze=None):
    """Ingest an empty block with the worker lost at the chosen step."""
    import chain_state
    import db

    snapshot = _next_snapshot()
    block = _next_block(snapshot)
    head = db.get_canonical_head()["block_hash"]
    worker = _Worker()
    proposal = _empty_proposal(worker)
    if build is None:
        owner.build_proposal = lambda **kw: proposal
    else:
        owner.build_proposal = build
    patches = []
    if apply is not None:
        patches.append(patch.object(TauConsensusEngine, "apply_block", apply))
    if freeze is not None:
        patches.append(patch.object(tau_commit.PreparedBlockCommit, "freeze",
                                    classmethod(freeze)))
    for p in patches:
        p.start()
    try:
        accepted = chain_state.process_new_block(block)
    finally:
        for p in patches:
            p.stop()
    return accepted, head, worker, proposal


def _lose(*args, **kwargs):
    raise spec.WorkerLost(LOST)


def test_a_received_block_is_not_accepted_when_its_evaluator_cannot_be_built(
        node_state, enabled_owner):
    import db

    accepted, head, _, _ = _ingest_with(enabled_owner, build=_lose)
    assert accepted is False
    assert db.get_canonical_head()["block_hash"] == head


def test_a_received_block_is_not_accepted_when_its_evaluation_loses_the_worker(
        node_state, enabled_owner):
    import db

    accepted, head, worker, proposal = _ingest_with(enabled_owner, apply=_lose)
    assert accepted is False
    assert db.get_canonical_head()["block_hash"] == head
    assert worker.disposed, "the lost proposal was not disposed"
    assert "evaluator lost" in (proposal.poisoned or "")


def test_a_received_block_is_not_accepted_when_freezing_loses_the_worker(
        node_state, enabled_owner):
    import db

    snapshot = _next_snapshot()
    result = SimpleNamespace(next_snapshot=snapshot, accepted_tx_ids=[],
                             invalid_tx_ids=[], skipped_tx_ids=[])
    accepted, head, worker, _ = _ingest_with(
        enabled_owner, apply=lambda *a, **k: result, freeze=_lose)
    assert accepted is False
    assert db.get_canonical_head()["block_hash"] == head
    assert worker.disposed


def test_a_rebuild_stops_instead_of_raising_when_the_worker_is_lost(
        node_state, enabled_owner):
    import chain_state

    enabled_owner.rebuild_genesis = lambda *a, **k: None
    enabled_owner.build_proposal = _lose
    result = chain_state.rebuild_state_from_blockchain(start_block=0)
    assert not result.ok
    assert "evaluation failed" in (result.reason or "")


# --- mining ------------------------------------------------------------------------------

def _funded_sender(tag):
    from py_ecc.bls import G2Basic as bls
    import chain_state

    sk = bls.KeyGen(f"{tag}_sender".encode())
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = 1_000
    return sk, pk


def _queued_transfer(tag):
    import hashlib
    import json

    from py_ecc.bls import G2Basic as bls

    from commands import sendtx

    sk, pk = _funded_sender(tag)
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": 0,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": {"1": [[pk, RECIPIENT, "10"]]}, "fee_limit": "0"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        sendtx._get_signing_message_bytes(tx)).digest()).hex()
    out = sendtx.queue_transaction(json.dumps(tx), propagate=False)
    assert out.get("ok"), out
    return out["tx_hash"]


def _mine_with(proposal_factory, *, apply=None, freeze=None):
    from commands import createblock

    patches = [
        patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True),
        patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True),
        patch.object(createblock, "_speculative_proposal", proposal_factory),
    ]
    if apply is not None:
        patches.append(patch.object(TauConsensusEngine, "apply_block", apply))
    if freeze is not None:
        patches.append(patch.object(tau_commit.PreparedBlockCommit, "freeze",
                                    classmethod(freeze)))
    for p in patches:
        p.start()
    try:
        return createblock.create_block_from_mempool()
    finally:
        for p in reversed(patches):
            p.stop()


def _where(tx_hash):
    import db

    if db.get_mempool_entry(tx_hash) is not None:
        return "mempool"
    if db.get_dropped_tx(tx_hash) is not None:
        return "dropped"
    return "elsewhere"


def test_a_lost_worker_building_the_proposal_aborts_the_round(node_state):
    import db

    tx_hash = _queued_transfer("build")
    head = db.get_canonical_head()["block_hash"]
    out = _mine_with(_lose)
    assert "error" in out and "evaluator lost" in out["error"], out
    assert db.get_canonical_head()["block_hash"] == head
    assert _where(tx_hash) == "mempool", "the transaction was disposed of"
    assert db.get_dropped_tx(tx_hash) is None


def test_a_lost_worker_evaluating_the_batch_aborts_the_round(node_state):
    import db

    tx_hash = _queued_transfer("apply")
    head = db.get_canonical_head()["block_hash"]
    worker = _Worker()
    out = _mine_with(lambda **kw: _empty_proposal(worker), apply=_lose)
    assert "error" in out and "evaluator lost" in out["error"], out
    assert db.get_canonical_head()["block_hash"] == head
    assert _where(tx_hash) == "mempool", "a lost worker became a dropped transaction"
    assert db.get_dropped_tx(tx_hash) is None
    assert worker.disposed, "the lost proposal was left holding its worker"
    assert tau_commit.registry().pending is None


def test_a_lost_worker_while_freezing_the_artifact_costs_the_artifact_only(node_state):
    """Ingestion evaluates the block itself when there is no artifact, so the
    round still produces its block."""
    import db

    tx_hash = _queued_transfer("freeze")
    head = db.get_canonical_head()["block_hash"]
    session = _LostSession(None)
    proposal = _proposal(session)
    out = _mine_with(lambda **kw: proposal, freeze=_lose)
    assert "block_hash" in out, out
    assert db.get_canonical_head()["block_hash"] != head
    assert tx_hash in (db.get_canonical_head_block().get("tx_ids") or [])
    assert session.disposed, "the proposal without an artifact was leaked"
    assert tau_commit.registry().pending is None


# --- ownership: every user of a session translates the loss ---------------------------------

_SESSION_APIS = re.compile(
    r"SpeculationSession|WorkerSession|validate_once|build_proposal\(|"
    r"replay_entries\(|\.reconstruct\(|\bproposal\.(?:reset|replan)\(|"
    r"\.replan\(")

#: Modules that define the loss, or carry it without catching it.
_DEFINES = {"tau_speculation.py", "tau_session.py", "tau_proposal.py"}
_PROPAGATES = {os.path.join("consensus", "engine.py")}

#: Modules that own a session or a proposal, and so must translate the loss.
_OWNERS = {
    "chain_state.py": "boundary",
    os.path.join("commands", "createblock.py"): "boundary",
    "tau_admission.py": "WorkerLost",
    "tau_advisory.py": "WorkerLost",
    "tau_authority.py": "WorkerLost",
    "tau_preflight.py": "WorkerLost",
}

_SKIP_DIRS = {".git", ".claude", ".local", "venv", ".venv", "data", "tests",
              "scripts", "web-wallet", "android", "docs", "node_modules",
              "__pycache__", "py_ecc", "build", "tmp"}


def _production_sources():
    for root, dirs, files in os.walk(REPO):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for name in files:
            if name.endswith(".py"):
                path = os.path.join(root, name)
                yield os.path.relpath(path, REPO), path


def _code_without_docs(path):
    """The module's code with comments and docstrings gone, so a word in prose
    cannot make a module look like it handles the loss."""
    with open(path, encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    for node in ast.walk(tree):
        body = getattr(node, "body", None)
        if (isinstance(body, list) and body and isinstance(body[0], ast.Expr)
                and isinstance(getattr(body[0], "value", None), ast.Constant)
                and isinstance(body[0].value.value, str)):
            body[0].value.value = ""
    return ast.unparse(tree)


def test_every_user_of_a_session_is_accounted_for():
    users = set()
    for relative, path in _production_sources():
        if _SESSION_APIS.search(_code_without_docs(path)):
            users.add(relative)
    known = _DEFINES | _PROPAGATES | set(_OWNERS)
    assert users <= known, (
        f"{sorted(users - known)} use a speculation session or proposal and are "
        "not classified: translate WorkerLost there (or at the owner above them) "
        "and list the module in _OWNERS"
    )


@pytest.mark.parametrize("relative,how", sorted(_OWNERS.items()))
def test_every_owner_translates_the_loss(relative, how):
    code = _code_without_docs(os.path.join(REPO, relative))
    needle = "boundary(" if how == "boundary" else "WorkerLost"
    assert needle in code, f"{relative} owns a session and never translates WorkerLost"


def test_the_commit_gate_reads_a_lost_worker():
    code = _code_without_docs(os.path.join(REPO, "tau_commit.py"))
    assert "WorkerLost" in code


def test_the_engine_does_not_catch_the_loss_it_must_pass_through():
    code = _code_without_docs(os.path.join(REPO, "consensus", "engine.py"))
    assert "WorkerLost" not in code and "BaseException" not in code
