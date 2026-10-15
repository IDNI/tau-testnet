"""A Tau request carries a deadline only while a transaction is being evaluated.

Block-level work and replays are consensus-mandated or already within budget, so
a deadline there would only stall them. An overrun defers, never judges.
"""
import inspect
import json
import logging
import re
import threading
import time
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import config
import db
import tau_admission
import tau_advisory
import tau_allocator as alloc
import tau_authority as auth
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session
import tau_speculation as spec
from commands import createblock, gettxstatus
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot
from errors import ConfigurationError, EvaluatorLost

import test_worker_lost as wl
from test_worker_lost import _accept_headers, enabled_owner  # noqa: F401 - fixtures

TIMEOUT = "worker gave no answer within 60s"


def _snapshot():
    return alloc.MappingSnapshot(epoch="e0", committed={})


# --- configuration ------------------------------------------------------------------

def test_the_budgets_default_to_a_minute_and_ten_minutes():
    defaults = config.TimeoutSettings()
    assert (defaults.mining_budget, defaults.validation_ceiling) == (60, 600)
    assert (config.MINING_BUDGET, config.VALIDATION_CEILING) == (60, 600)


def test_the_budgets_follow_the_environment(monkeypatch):
    monkeypatch.setenv("TAU_MINING_BUDGET", "7")
    monkeypatch.setenv("TAU_VALIDATION_CEILING", "70")
    try:
        loaded = config.reload_settings(env="test")
        assert (loaded.timeouts.mining_budget, loaded.timeouts.validation_ceiling) == (7, 70)
        assert (config.MINING_BUDGET, config.VALIDATION_CEILING) == (7, 70)
    finally:
        monkeypatch.delenv("TAU_MINING_BUDGET", raising=False)
        monkeypatch.delenv("TAU_VALIDATION_CEILING", raising=False)
        config.reload_settings(env="test")
    assert (config.MINING_BUDGET, config.VALIDATION_CEILING) == (60, 600)


@pytest.mark.parametrize("name", ["mining_budget", "validation_ceiling"])
@pytest.mark.parametrize("value", [0, -5])
def test_a_budget_must_be_positive(name, value):
    with pytest.raises(ConfigurationError, match=name):
        config.TimeoutSettings(**{name: value}).validate()


def test_the_ceiling_may_not_undercut_the_budget():
    with pytest.raises(ConfigurationError, match="validation_ceiling"):
        config.TimeoutSettings(mining_budget=100, validation_ceiling=99).validate()
    config.TimeoutSettings(mining_budget=100, validation_ceiling=100).validate()


def test_an_environment_that_inverts_the_budgets_is_refused(monkeypatch):
    monkeypatch.setenv("TAU_MINING_BUDGET", "700")      # above the default ceiling
    try:
        with pytest.raises(ConfigurationError, match="validation_ceiling"):
            config.reload_settings(env="test")
    finally:
        monkeypatch.delenv("TAU_MINING_BUDGET", raising=False)
        config.reload_settings(env="test")


# --- the session carries the deadline ---------------------------------------------------

class _RecordingSpec:
    """A worker that records the deadline each request carried."""

    def __init__(self, requests=None, label="worker", seen_by=None):
        self.requests = requests if requests is not None else []
        self.label = label
        self.seen_by = seen_by

    def _note(self, op, timeout):
        open_tx = self.seen_by["proposal"].open_tx if self.seen_by else None
        self.requests.append((self.label, op, timeout, open_tx))

    def revise(self, text, cid="", *, timeout="unset"):
        self._note("revise", timeout)
        return spec.RevisionReceipt({"outcome": "ACCEPTED_CHANGED", "ok": True, "outputs": {}})

    def step(self, inputs, *, timeout="unset"):
        self._note("step", timeout)
        return {"outputs": {"o1": "1"}}

    def kill(self):
        pass


def test_a_worker_session_sends_its_budget_with_every_request(temp_database):
    worker = _RecordingSpec()
    session = tau_session.WorkerSession(worker)
    session.apply_rule(wl.RULE)
    session.evaluate({1: "5"})
    session.request_budget = 7
    session.apply_rule(wl.RULE)
    session.evaluate({1: "5"})
    session.request_budget = None
    session.evaluate({1: "5"})
    assert [(op, timeout) for _, op, timeout, _ in worker.requests] == [
        ("revise", None), ("step", None), ("revise", 7), ("step", 7), ("step", None)]


@pytest.mark.parametrize("call", ["init", "revise", "step", "state"])
def test_the_speculation_client_accepts_the_deadline_the_session_sends(call):
    parameter = inspect.signature(getattr(spec.SpeculationSession, call)).parameters["timeout"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY


# --- the branch hands it over --------------------------------------------------------------

class _Budgeted:
    """A session with the deadline slot a branch fills."""

    is_speculative = True
    request_budget = None

    def __init__(self):
        self.allocation = None
        self.journal = None

    def dispose(self):
        pass


def _context(session, rebuild=None):
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(_snapshot(), width=8, label="proposal"),
        plan=tr.RepresentationPlan(width=8, interned=frozenset({12}), plain=frozenset()),
        rebuild=rebuild,
    )


def test_a_proposal_starts_with_no_budget_and_no_open_transaction():
    ctx = _context(_Budgeted())
    assert ctx.budget is None and ctx.open_tx is None


@pytest.mark.parametrize("verdict", ["accept", "reject"])
def test_a_branch_hands_the_budget_to_the_session_and_takes_it_back(verdict):
    session = _Budgeted()
    ctx = _context(session, rebuild=lambda j, p: _Budgeted())
    ctx.budget = 12
    branch = ctx.transaction("T1")
    assert session.request_budget == 12 and ctx.open_tx == "T1"
    getattr(branch, verdict)()
    assert session.request_budget is None and ctx.open_tx is None


def test_an_unresolved_branch_takes_the_budget_back_on_exit():
    session = _Budgeted()
    ctx = _context(session)
    ctx.budget = 12
    with pytest.raises(RuntimeError):
        with ctx.transaction("T1"):
            assert session.request_budget == 12
            raise RuntimeError("boom")
    assert session.request_budget is None and ctx.open_tx is None


def test_without_a_budget_a_branch_leaves_requests_undeadlined():
    session = _Budgeted()
    ctx = _context(session)
    with ctx.transaction("T1") as branch:
        assert session.request_budget is None and ctx.open_tx == "T1"
        branch.accept()


def test_a_session_without_the_slot_is_left_alone():
    session = SimpleNamespace(allocation=None, journal=None, dispose=lambda: None)
    ctx = _context(session)
    ctx.budget = 12
    with ctx.transaction("T1") as branch:
        assert not hasattr(session, "request_budget")
        assert ctx.open_tx == "T1"
        branch.accept()
    assert ctx.open_tx is None


def test_each_branch_is_bound_to_the_session_the_proposal_holds_when_it_opens():
    first, second = _Budgeted(), _Budgeted()
    ctx = _context(first, rebuild=lambda j, p: second)
    ctx.budget = 5
    with ctx.transaction("A") as branch:
        branch.journal.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "5"})
        branch.reject("fee")
    with ctx.transaction("B") as branch:
        assert ctx.session is second
        assert second.request_budget == 5 and first.request_budget is None
        branch.accept()


# --- nothing outside a branch carries it ---------------------------------------------------

def _proposal_over_recording_workers(requests):
    holder = {}
    made = []

    def new(label):
        worker = tau_session.WorkerSession(
            _RecordingSpec(requests, label, holder),
            allocation=alloc.Allocator(_snapshot(), width=8, label="proposal"))
        made.append(worker)
        return worker

    def rebuild(journal, current_plan):
        session = new("rebuilt")
        return tau_session.replay_entries(
            session, journal.entries(), respawn=lambda: new("respawned"))

    ctx = tp.ProposalContext(
        session=new("first"),
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(_snapshot(), width=8, label="proposal"),
        plan=tr.RepresentationPlan(width=8, interned=frozenset(), plain=frozenset()),
        rebuild=rebuild, respawn=lambda plan: new("collapsed"),
    )
    holder["proposal"] = ctx
    return ctx, made


def test_a_request_carries_a_deadline_exactly_while_a_branch_is_open(temp_database):
    requests = []
    ctx, made = _proposal_over_recording_workers(requests)
    ctx.budget = 5

    with ctx.transaction("A") as branch:          # accepted: on the first worker
        ctx.session.apply_rule(wl.RULE)
        ctx.session.evaluate({1: "5"})
        branch.accept()
    with ctx.transaction("B") as branch:          # rejected after stepping: dirty
        ctx.session.evaluate({1: "6"})
        branch.reject("fee")
    assert ctx.dirty
    with ctx.transaction("C") as branch:          # reconstructs first, then evaluates
        ctx.session.evaluate({1: "7"})
        branch.accept()
    ctx.reset([(wl.RULE, True)])                  # block-level collapse
    tau_session.replay_entries(                   # a replay on fresh workers
        None, ctx.journal.entries(),
        respawn=lambda: tau_session.WorkerSession(
            _RecordingSpec(requests, "replayed", {"proposal": ctx}),
            allocation=alloc.Allocator(_snapshot(), width=8, label="proposal")))

    labels = {label for label, *_ in requests}
    assert {"first", "rebuilt", "collapsed", "replayed"} <= labels, labels
    for label, op, timeout, open_tx in requests:
        assert (timeout == 5) == (open_tx is not None), (label, op, timeout, open_tx)
        assert timeout in (None, 5), (label, op, timeout)
    in_branches = [(label, open_tx) for label, _, timeout, open_tx in requests if timeout == 5]
    assert in_branches == [("first", "A"), ("first", "A"), ("first", "B"), ("rebuilt", "C")]
    assert all(worker.request_budget is None for worker in made)


# --- the boundary names what was lost ---------------------------------------------------------

def test_a_timeout_reaches_the_owner_as_a_timed_out_failure_naming_the_transaction():
    proposal = wl._proposal(wl._LostSession(None))
    proposal.open_tx = "T1"
    with pytest.raises(EvaluatorLost) as caught:
        with tp.boundary(proposal, label="test"):
            raise spec.WorkerTimeout(TIMEOUT)
    assert caught.value.timed_out is True
    assert caught.value.tx_id == "T1"
    assert TIMEOUT in str(caught.value)
    assert "evaluator lost" in (proposal.poisoned or "")


def test_a_plain_loss_is_not_a_timeout_but_still_names_the_transaction():
    proposal = wl._proposal(wl._LostSession(None))
    proposal.open_tx = "T1"
    with pytest.raises(EvaluatorLost) as caught:
        with tp.boundary(proposal, label="test"):
            raise spec.WorkerLost(wl.LOST)
    assert caught.value.timed_out is False
    assert caught.value.tx_id == "T1"


def test_a_loss_between_transactions_names_none():
    proposal = wl._proposal(wl._LostSession(None))
    with pytest.raises(EvaluatorLost) as caught:
        with tp.boundary(proposal, label="test"):
            raise spec.WorkerTimeout(TIMEOUT)
    assert caught.value.tx_id is None and caught.value.timed_out is True


def test_a_loss_without_a_proposal_names_none():
    with pytest.raises(EvaluatorLost) as caught:
        with tp.boundary(label="build"):
            raise spec.WorkerTimeout(TIMEOUT)
    assert caught.value.tx_id is None and caught.value.timed_out is True


def test_an_evaluator_lost_built_by_hand_is_not_a_timeout():
    failure = EvaluatorLost("evaluator lost: x")
    assert failure.timed_out is False and failure.tx_id is None
    assert str(failure) == "evaluator lost: x"


# --- the backoff registry --------------------------------------------------------------------

class _Clock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    ticking = _Clock()
    monkeypatch.setattr(createblock, "_now", ticking)
    return ticking


@pytest.fixture(autouse=True)
def _no_deferrals():
    createblock._deferred.clear()
    yield
    createblock._deferred.clear()


def test_the_backoff_doubles_with_every_overrun_up_to_the_cap(clock):
    delays = [createblock._defer("h")[1] for _ in range(9)]
    assert delays == [60, 120, 240, 480, 960, 1920, 3600, 3600, 3600]
    assert createblock._deferred["h"] == (9, clock.now + 3600)


def test_a_deferral_is_forgotten_once_it_has_been_stale_for_more_than_the_cap(clock):
    createblock._defer("h")                                  # eligible again at +60
    clock.now += 60 + createblock.DEFER_CAP_SECONDS
    createblock._prune_deferred(clock.now)
    assert "h" in createblock._deferred
    clock.now += 1
    createblock._prune_deferred(clock.now)
    assert createblock._deferred == {}


def test_strikes_start_over_after_a_deferral_has_been_forgotten(clock):
    createblock._defer("h")
    createblock._defer("h")                                  # eligible again at +120
    clock.now += 120 + createblock.DEFER_CAP_SECONDS + 1
    assert createblock._defer("h") == (1, 60)


def test_only_hashes_still_backing_off_are_excluded_from_the_selection(clock):
    createblock._defer("b")
    createblock._defer("c")
    assert createblock._backing_off() == {"b", "c"}
    clock.now += 61
    assert createblock._backing_off() == set()
    assert createblock._backing_off() == set(), "an elapsed deferral came back"


def test_a_deferral_that_was_never_registered_excludes_nothing(clock):
    assert createblock._backing_off() == set()


def test_an_overrun_is_attributed_through_the_id_the_engine_opened():
    rows = [{"id": 10, "tx_hash": "h0"}, {"id": 11, "tx_hash": "h1"}, {"id": 12, "tx_hash": "h2"}]
    batch = [{"tx_id": "own-id"}, {"tx_id": "h1"}, {}]
    lost = EvaluatorLost("evaluator lost", tx_id="own-id", timed_out=True)
    createblock._defer_lost(lost, batch, [10, 11, 12], rows)
    assert set(createblock._deferred) == {"h0"}
    createblock._deferred.clear()
    createblock._defer_lost(EvaluatorLost("x", tx_id="tx2", timed_out=True),
                            batch, [10, 11, 12], rows)
    assert set(createblock._deferred) == {"h2"}


def test_an_overrun_nobody_owns_defers_nothing(caplog):
    rows = [{"id": 10, "tx_hash": "h0"}]
    with caplog.at_level(logging.WARNING, logger=createblock.logger.name):
        createblock._defer_lost(EvaluatorLost("x", tx_id="ghost", timed_out=True),
                                [{"tx_id": "h0"}], [10], rows)
        createblock._defer_lost(EvaluatorLost("x", tx_id=None, timed_out=True),
                                [{"tx_id": "h0"}], [10], rows)
    assert createblock._deferred == {}
    assert "nothing deferred" in caplog.text


def test_only_an_evaluator_lost_naming_a_transaction_is_deferred():
    rows = [{"id": 10, "tx_hash": "h0"}]
    for failure in (RuntimeError("x"), EvaluatorLost("x", tx_id=None),
                    EvaluatorLost("x", tx_id=None, timed_out=False)):
        createblock._defer_lost(failure, [{"tx_id": "h0"}], [10], rows)
    assert createblock._deferred == {}
    createblock._defer_lost(EvaluatorLost("x", tx_id="h0", timed_out=False),
                            [{"tx_id": "h0"}], [10], rows)
    assert set(createblock._deferred) == {"h0"}


def test_a_loss_nobody_owns_defers_nothing_and_says_so(caplog):
    rows = [{"id": 10, "tx_hash": "h0"}]
    with caplog.at_level(logging.WARNING, logger=createblock.logger.name):
        createblock._defer_lost(EvaluatorLost("x", tx_id="ghost", timed_out=False),
                                [{"tx_id": "h0"}], [10], rows)
    assert createblock._deferred == {}
    assert "evaluator was lost" in caplog.text and "nothing deferred" in caplog.text
    assert "mining budget" not in caplog.text


def test_the_branch_ids_the_owners_derive_are_the_ones_the_engine_opens(temp_database):
    batch = [
        {**wl._transfer_tx(), "tx_id": "own-id"},
        {**{k: v for k, v in wl._transfer_tx().items() if k != "tx_id"}, "tx_hash": "by-hash"},
        {k: v for k, v in wl._transfer_tx().items() if k != "tx_id"},
    ]
    opened = []
    session = wl._LostSession(None)
    proposal = wl._proposal(session)
    real = proposal.transaction
    proposal.transaction = lambda tx_id: (opened.append(tx_id), real(tx_id))[1]
    engine = TauConsensusEngine(state_store=MagicMock())
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}), batch, 1700000000,
            target_balances={wl.SENDER: 1000}, target_sequences={},
            target_lifecycle=proposal.lifecycle, proposer_pubkey=wl.PROPOSER,
            block_height=1, proposal=proposal, session=session,
        )
    assert opened == [tp.branch_id(tx, i) for i, tx in enumerate(batch)]
    assert opened == ["own-id", "by-hash", "tx2"]


# --- mining ------------------------------------------------------------------------------------

class _SlowOn(wl._LostSession):
    """Evaluates every transaction but the named one, whose request is lost."""

    request_budget = None

    def __init__(self, slow_tx, failure):
        super().__init__(None, failure=failure)
        self.slow_tx = slow_tx
        self.proposal = None
        self.budgets = []

    def evaluate(self, inputs, *, multi=False, target=None, **kwargs):
        self.budgets.append(self.request_budget)
        if self.proposal is not None and self.proposal.open_tx == self.slow_tx:
            raise self.failure()
        return super().evaluate(inputs, multi=multi, target=target, **kwargs)


def _slow_on(slow_tx, failure=None, sessions=None):
    failure = failure or (lambda: spec.WorkerTimeout(TIMEOUT))

    def build(**kwargs):
        session = _SlowOn(slow_tx, failure)
        proposal = wl._proposal(session)
        session.proposal = proposal
        if sessions is not None:
            sessions.append(session)
        return proposal

    return build


def _healthy(**kwargs):
    return wl._proposal(wl._LostSession(None))


def _queued(tx_hash):
    """Still waiting its turn, with no verdict recorded against it."""
    entry = db.get_mempool_entry(tx_hash)
    assert entry is not None, "the transaction left the mempool"
    assert entry["status"] == "pending", entry
    assert db.get_dropped_tx(tx_hash) is None, "a verdict was recorded"
    status = json.loads(gettxstatus.execute(
        f"gettxstatus {tx_hash}", SimpleNamespace(db=db)))
    assert status["data"]["status"] == "queued", status


def _mined():
    return (db.get_canonical_head_block() or {}).get("tx_ids") or []


def test_a_timeout_aborts_the_round_and_defers_that_transaction_alone(
        node_state, clock, monkeypatch):
    monkeypatch.setattr(config, "MINING_BUDGET", 7)
    slow = wl._queued_transfer("slow")
    fast = wl._queued_transfer("fast")
    head = db.get_canonical_head()["block_hash"]
    sessions = []

    out = wl._mine_with(_slow_on(slow, sessions=sessions))

    assert "error" in out and "evaluator lost" in out["error"], out
    assert db.get_canonical_head()["block_hash"] == head
    _queued(slow)
    _queued(fast)
    assert createblock._deferred == {slow: (1, clock.now + createblock.DEFER_BASE_SECONDS)}
    assert sessions[0].budgets and set(sessions[0].budgets) == {7}, (
        "the round's budget never reached the evaluator")


def test_the_deferral_is_logged_once_with_the_budget_and_the_backoff(node_state, clock, caplog):
    slow = wl._queued_transfer("slow")
    wl._queued_transfer("fast")
    with caplog.at_level(logging.WARNING, logger=createblock.logger.name):
        wl._mine_with(_slow_on(slow))
    lines = [r.getMessage() for r in caplog.records if "deferred for" in r.getMessage()]
    assert len(lines) == 1, lines
    assert slow in lines[0] and "60s mining budget" in lines[0] and "deferred for 60s" in lines[0]


def test_the_next_round_mines_the_others_without_it(node_state, clock):
    slow = wl._queued_transfer("slow")
    fast = wl._queued_transfer("fast")
    wl._mine_with(_slow_on(slow))

    mined = wl._mine_with(_healthy)

    assert "block_hash" in mined, mined
    assert _mined() == [fast]
    _queued(slow)


def test_a_deferred_transaction_is_not_retried_while_it_backs_off(node_state, clock):
    slow = wl._queued_transfer("slow")
    wl._mine_with(_slow_on(slow))
    clock.now += createblock.DEFER_BASE_SECONDS - 1
    sessions = []

    out = wl._mine_with(_slow_on(slow, sessions=sessions))

    assert "error" not in out and "block_hash" not in out, out
    assert out["message"].startswith("Mempool is empty"), out
    assert not sessions, "a deferred transaction was evaluated again"
    _queued(slow)
    assert createblock._deferred[slow][0] == 1


def test_the_transaction_returns_once_its_backoff_has_elapsed(node_state, clock):
    slow = wl._queued_transfer("slow")
    fast = wl._queued_transfer("fast")
    wl._mine_with(_slow_on(slow))
    wl._mine_with(_healthy)
    assert _mined() == [fast]

    clock.now += createblock.DEFER_BASE_SECONDS + 1
    mined = wl._mine_with(_healthy)

    assert "block_hash" in mined, mined
    assert _mined() == [slow]


def test_a_second_timeout_doubles_the_backoff(node_state, clock):
    slow = wl._queued_transfer("slow")
    wl._mine_with(_slow_on(slow))
    clock.now += createblock.DEFER_BASE_SECONDS + 1

    out = wl._mine_with(_slow_on(slow))

    assert "evaluator lost" in out["error"], out
    assert createblock._deferred[slow] == (2, clock.now + 2 * createblock.DEFER_BASE_SECONDS)
    _queued(slow)
    clock.now += 2 * createblock.DEFER_BASE_SECONDS - 1
    out = wl._mine_with(_slow_on(slow))
    assert "error" not in out and out["message"].startswith("Mempool is empty"), out


def test_a_plain_loss_naming_a_transaction_defers_it_like_a_timeout(
        node_state, clock, caplog):
    """A transaction that kills the worker every time would otherwise stall every
    round the miner retries."""
    slow = wl._queued_transfer("plain")
    fast = wl._queued_transfer("fast")
    with caplog.at_level(logging.WARNING, logger=createblock.logger.name):
        out = wl._mine_with(_slow_on(slow, failure=lambda: spec.WorkerLost(wl.LOST)))
    assert "evaluator lost" in out["error"], out
    assert createblock._deferred == {slow: (1, clock.now + createblock.DEFER_BASE_SECONDS)}
    _queued(slow)
    _queued(fast)

    lines = [r.getMessage() for r in caplog.records if "deferred for" in r.getMessage()]
    assert len(lines) == 1, lines
    assert slow in lines[0] and "evaluator was lost" in lines[0] and wl.LOST in lines[0]
    assert "mining budget" not in lines[0], "a plain loss was reported as a timeout"

    mined = wl._mine_with(_healthy)

    assert "block_hash" in mined, mined
    assert _mined() == [fast]
    _queued(slow)


def test_a_loss_with_no_transaction_in_evaluation_defers_nothing(node_state, clock):
    tx_hash = wl._queued_transfer("between")
    out = wl._mine_with(wl._lose)
    assert "evaluator lost" in out["error"], out
    assert createblock._deferred == {}
    _queued(tx_hash)

    mined = wl._mine_with(_healthy)

    assert "block_hash" in mined, mined
    assert _mined() == [tx_hash]


@pytest.fixture
def reservations(monkeypatch):
    """What each reservation was told to leave out, what it took, and the
    status the deferred rows held at that moment."""
    real = db.reserve_mempool_txs
    seen = []

    def spy(*args, **kwargs):
        rows = real(*args, **kwargs)
        excluded = set(kwargs.get("exclude_hashes") or ())
        seen.append({
            "exclude": excluded,
            "taken": [row["tx_hash"] for row in rows],
            "status": {h: (db.get_mempool_entry(h) or {}).get("status") for h in excluded},
        })
        return rows

    monkeypatch.setattr(db, "reserve_mempool_txs", spy)
    return seen


def test_the_reservation_is_told_which_transactions_are_backing_off(
        node_state, clock, reservations):
    slow = wl._queued_transfer("slow")
    fast = wl._queued_transfer("fast")
    wl._mine_with(_slow_on(slow))
    wl._mine_with(_healthy)

    first, second = reservations
    assert first["exclude"] == set() and set(first["taken"]) == {slow, fast}
    assert second["exclude"] == {slow}
    assert second["taken"] == [fast], "a deferred transaction was reserved"
    assert second["status"] == {slow: "pending"}, "a deferred transaction was held"


def test_a_transaction_is_reserved_again_once_its_backoff_has_elapsed(
        node_state, clock, reservations):
    slow = wl._queued_transfer("slow")
    wl._mine_with(_slow_on(slow))
    clock.now += createblock.DEFER_BASE_SECONDS + 1
    wl._mine_with(_healthy)

    assert reservations[-1]["exclude"] == set()
    assert reservations[-1]["taken"] == [slow]


def test_a_deferred_transaction_is_never_reserved_while_it_backs_off(
        node_state, clock, reservations):
    slow = wl._queued_transfer("slow")
    wl._mine_with(_slow_on(slow))
    with patch.object(createblock.db, "unreserve_mempool_txs") as unreserve:
        for _ in range(3):
            out = wl._mine_with(_healthy)
            assert out["message"].startswith("Mempool is empty"), out
    assert all(slow not in seen["taken"] for seen in reservations[1:])
    unreserve.assert_not_called()


def test_a_deferred_rule_transaction_does_not_hold_the_slow_lane_slot(
        node_state, clock, reservations, monkeypatch):
    from test_mempool_lanes import _add, _rule

    monkeypatch.setattr(config, "BLOCK_MAX_RULE_TXS", 1)
    _add(_rule(sender="aa" * 48), "rule-rich", 1000, estimated_fee=500)
    _add(_rule(sender="bb" * 48), "rule-poor", 1001, estimated_fee=1)
    createblock._defer("rule-rich")

    wl._mine_with(_healthy)

    assert reservations[0]["exclude"] == {"rule-rich"}
    assert reservations[0]["taken"] == ["rule-poor"], (
        "the deferred rule transaction took the only slow-lane slot")


def test_a_deferred_transaction_is_never_dropped_or_reported_rejected(node_state, clock):
    slow = wl._queued_transfer("slow")
    for _ in range(3):
        wl._mine_with(_slow_on(slow))
        _queued(slow)
        clock.now += createblock.DEFER_CAP_SECONDS
    assert db.get_dropped_tx(slow) is None
    assert wl._where(slow) == "mempool"


def _queue_transfer(sk, pk, sequence, **extra):
    import hashlib

    from py_ecc.bls import G2Basic as bls

    from commands import sendtx

    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": sequence,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": {"1": [[pk, wl.RECIPIENT, "10"]]}, "fee_limit": "0", **extra}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        sendtx._get_signing_message_bytes(tx)).digest()).hex()
    queued = sendtx.queue_transaction(json.dumps(tx), propagate=False)
    assert queued.get("ok"), queued
    return queued["tx_hash"]


def test_a_transaction_that_carries_its_own_id_is_deferred_under_its_mempool_row(
        node_state, clock):
    sk, pk = wl._funded_sender("own_id")
    row_hash = _queue_transfer(sk, pk, 0, tx_id="my-own-id")
    assert row_hash != "my-own-id"

    out = wl._mine_with(_slow_on("my-own-id"))

    assert "evaluator lost" in out["error"], out
    assert set(createblock._deferred) == {row_hash}
    _queued(row_hash)


def test_a_deferred_transaction_holds_back_the_later_ones_of_its_sender(node_state, clock):
    """Mined past it, the successor would fail the engine's sequence check and be
    disposed of; it has to wait for the transaction it follows."""
    sk, pk = wl._funded_sender("chain")
    first = _queue_transfer(sk, pk, 0)
    second = _queue_transfer(sk, pk, 1)
    wl._mine_with(_slow_on(first))

    out = wl._mine_with(_healthy)

    assert "block_hash" not in out and "error" not in out, out
    _queued(first)
    _queued(second)
    clock.now += createblock.DEFER_BASE_SECONDS + 1
    mined = wl._mine_with(_healthy)
    assert "block_hash" in mined, mined
    assert _mined() == [first, second]


def test_a_round_with_no_proposal_to_budget_still_mines(node_state, clock):
    """The in-process fallback has no worker to put a deadline on."""
    tx_hash = wl._queued_transfer("inprocess")
    mined = wl._mine_with(lambda **kwargs: None)
    assert "block_hash" in mined, mined
    assert _mined() == [tx_hash]


# --- ingestion -----------------------------------------------------------------------------------

def _record_budget(seen, then):
    def apply(self, active_view, block, parent, *, session=None, replay_mode=False,
              proposal=None):
        seen["budget"] = proposal.budget
        return then(proposal, block)
    return apply


def _stop(proposal, block):
    raise RuntimeError("stop here")


def test_a_received_block_is_evaluated_under_the_validation_ceiling(
        node_state, enabled_owner, monkeypatch):
    monkeypatch.setattr(config, "VALIDATION_CEILING", 123)
    seen = {}
    accepted, head, _, _ = wl._ingest_with(enabled_owner, apply=_record_budget(seen, _stop))
    assert accepted is False
    assert seen["budget"] == 123
    assert db.get_canonical_head()["block_hash"] == head


def test_a_timeout_while_validating_leaves_the_block_for_a_later_retry(
        node_state, enabled_owner, caplog):
    def timeout_in_a_transaction(proposal, block):
        proposal.transaction("TX1")
        raise spec.WorkerTimeout(TIMEOUT)

    seen = {}
    with caplog.at_level(logging.ERROR, logger="chain_state"):
        accepted, head, worker, proposal = wl._ingest_with(
            enabled_owner, apply=_record_budget(seen, timeout_in_a_transaction))

    assert accepted is False
    assert db.get_canonical_head()["block_hash"] == head
    assert worker.disposed and "evaluator lost" in (proposal.poisoned or "")
    assert seen["budget"] == config.VALIDATION_CEILING
    ceiling = [r.getMessage() for r in caplog.records
               if "validation ceiling" in r.getMessage()]
    assert len(ceiling) == 1, caplog.text
    assert "TX1" in ceiling[0] and f"{config.VALIDATION_CEILING}s" in ceiling[0]
    assert "block #" in ceiling[0]


def test_a_ceiling_overrun_names_the_transaction_by_the_hash_the_block_holds():
    import chain_state

    block = SimpleNamespace(
        transactions=[{"tx_id": "own-id"}, {}, {"tx_hash": "by-hash"}],
        tx_ids=["hash-0", "hash-1", "hash-2"])
    assert chain_state._overrun_tx(block, "own-id") == "hash-0"
    assert chain_state._overrun_tx(block, "tx1") == "hash-1"
    assert chain_state._overrun_tx(block, "by-hash") == "hash-2"
    assert chain_state._overrun_tx(block, "unknown") == "unknown"
    assert chain_state._overrun_tx(block, None) == "?"
    assert chain_state._overrun_tx(SimpleNamespace(transactions=[{}]), "tx0") == "tx0"


def test_a_plain_loss_while_validating_is_not_reported_as_a_ceiling(
        node_state, enabled_owner, caplog):
    with caplog.at_level(logging.ERROR, logger="chain_state"):
        accepted, _, _, _ = wl._ingest_with(enabled_owner, apply=wl._lose)
    assert accepted is False
    assert "validation ceiling" not in caplog.text
    assert "could not evaluate block" in caplog.text


def test_a_rebuild_of_stored_blocks_carries_no_budget(node_state, enabled_owner):
    import chain_state

    seen = {}
    worker = wl._Worker()
    enabled_owner.rebuild_genesis = lambda *a, **k: None
    enabled_owner.build_proposal = lambda **kw: wl._empty_proposal(worker)
    with patch.object(TauConsensusEngine, "apply_block", _record_budget(seen, _stop)):
        result = chain_state.rebuild_state_from_blockchain(start_block=0)
    assert not result.ok
    assert "budget" in seen, "the rebuild never reached an evaluation"
    assert seen["budget"] is None


# --- advisory ---------------------------------------------------------------------------------------

class _FakeSpeculation:
    created = []

    def __init__(self, **kwargs):
        type(self).created.append(kwargs)
        self.killed = False

    def init(self, text, **kwargs):
        return {"ok": True}

    def revise(self, text, candidate_id="", **kwargs):
        return spec.RevisionReceipt({"outcome": "ACCEPTED_CHANGED"})

    def step(self, inputs, **kwargs):
        return {"outputs": {}}

    def kill(self):
        self.killed = True


def test_advisory_sessions_carry_the_comm_timeout(monkeypatch):
    _FakeSpeculation.created = []
    monkeypatch.setattr(spec, "SpeculationSession", _FakeSpeculation)
    monkeypatch.setattr(auth, "program_baseline", lambda: "baseline")
    monkeypatch.setattr(config, "COMM_TIMEOUT", 17)
    evaluator = tau_advisory.AdvisoryEvaluator()
    evaluator._ensure("always ( o5[t] = 1 ).")
    evaluator._ensure_consensus("always ( o6[t] = 1 ).")
    assert [made["timeout"] for made in _FakeSpeculation.created] == [17, 17]


@pytest.mark.parametrize("call,ensure,args", [
    ("evaluate", "_ensure", ("spec", {}, 5)),
    ("evaluate_many", "_ensure", ("spec", {}, [5, 8])),
    ("evaluate_consensus", "_ensure_consensus", ("rules", {}, [6, 7])),
])
def test_an_advisory_request_that_times_out_is_no_opinion(call, ensure, args):
    class _TimesOut:
        killed = False

        def step(self, inputs):
            raise spec.WorkerTimeout(TIMEOUT)

        def kill(self):
            self.killed = True

    evaluator = tau_advisory.AdvisoryEvaluator()
    session = _TimesOut()
    with patch.object(evaluator, ensure, return_value=session):
        assert getattr(evaluator, call)(*args) is None
    assert session.killed or evaluator._session is None


# --- the admission standby ---------------------------------------------------------------------------

class _Victim:
    def __init__(self):
        self.disposed = False

    def dispose(self):
        self.disposed = True


_ANCHOR = {"journal_head": "h", "journal_sequence": 1, "epoch": "e", "high_water": 0}


def _refill(build, *, budget, factor=1):
    standby = tau_admission._Standby()
    standby.enabled = True
    with patch.object(tau_admission, "_build", build), \
         patch.object(tau_admission, "default_budget", lambda: budget), \
         patch.object(tau_admission, "STANDBY_BUDGET_FACTOR", factor):
        standby.refill()
        for thread in threading.enumerate():
            if thread.name == "admission-standby":
                thread.join(timeout=10)
    return standby


def test_the_standby_build_is_bounded_by_a_multiple_of_the_request_budget():
    seen = {}

    def build(*, deadline, **kwargs):
        seen["left"] = deadline.remaining()
        raise spec.WorkerLost(wl.LOST)

    _refill(build, budget=30, factor=3)
    assert 85 < seen["left"] <= 90, seen


def test_the_standby_factor_is_three_request_budgets():
    assert tau_admission.STANDBY_BUDGET_FACTOR == 3


def test_a_finished_standby_outlives_the_budget_it_was_built_under():
    victim = _Victim()

    def build(*, deadline, **kwargs):
        deadline.watch(victim)
        return victim, dict(_ANCHOR), None

    standby = _refill(build, budget=0.2)
    time.sleep(0.6)
    assert not victim.disposed, "the build's timer killed the standby that was waiting"
    assert standby._ready is not None and standby._ready[1] is victim
    assert standby._building is False


def test_a_failed_build_cancels_its_timer():
    seen = {}

    def build(*, deadline, **kwargs):
        seen["deadline"] = deadline
        raise spec.WorkerLost(wl.LOST)

    standby = _refill(build, budget=0.2)
    time.sleep(0.5)
    assert seen["deadline"].expired is False
    assert standby._building is False and standby._ready is None


def test_a_build_that_runs_out_of_time_is_reported_and_leaves_nothing_behind(caplog):
    victim = _Victim()

    def build(*, deadline, **kwargs):
        deadline.watch(victim)
        while not deadline.expired:
            time.sleep(0.01)
        raise tau_admission.AdmissionTimeout("the admission budget ran out during replay")

    with caplog.at_level(logging.INFO, logger=tau_admission.logger.name):
        standby = _refill(build, budget=0.1)
    assert standby._building is False and standby._ready is None
    assert victim.disposed, "a live worker was left behind"
    assert "ran out of time" in caplog.text


def test_a_build_the_timer_overtook_is_not_stored():
    victim = _Victim()

    def build(*, deadline, **kwargs):
        deadline.watch(victim)
        deadline._fire()            # the timer fires as the build finishes
        return victim, dict(_ANCHOR), None

    standby = _refill(build, budget=60)
    assert victim.disposed
    assert standby._ready is None and standby._building is False


# --- replay ---------------------------------------------------------------------------------------------

def test_a_slow_replay_entry_and_the_replay_as_a_whole_are_reported(caplog):
    entry = wl._revision()
    with patch.object(tau_session, "SLOW_REPLAY_SECONDS", 0.0), \
         caplog.at_level(logging.INFO, logger=tau_session.logger.name):
        tau_session.replay_entries(None, [entry], respawn=lambda: wl._Replayed())
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    summaries = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert len(warnings) == 1, warnings
    assert re.fullmatch(
        rf"replay: entry {entry.seq} \(revision\) took \d+\.\ds", warnings[0]), warnings
    assert len(summaries) == 1, summaries
    assert re.fullmatch(r"replay: 1 entries took \d+\.\ds", summaries[0]), summaries


def test_a_quick_replay_logs_nothing(caplog):
    with caplog.at_level(logging.INFO, logger=tau_session.logger.name):
        tau_session.replay_entries(None, [wl._revision()], respawn=lambda: wl._Replayed())
    assert not [r for r in caplog.records if r.name == tau_session.logger.name]


def test_the_slow_replay_threshold_is_ten_seconds():
    assert tau_session.SLOW_REPLAY_SECONDS == 10.0


def test_a_slow_replay_still_finishes_and_hands_back_its_session():
    with patch.object(tau_session, "SLOW_REPLAY_SECONDS", 0.0):
        session = tau_session.replay_entries(
            None, [wl._revision(), wl._revision()], respawn=lambda: wl._Replayed())
    assert not session.disposed
