"""A node-local error at block apply stops the block and gives no verdict.

Another node, or this node after the cause is gone, reaches a different result,
so a local error must never reject a transaction. Errors that every node
reaches from the block alone keep their verdict.
"""
import io
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import tau_allocator as alloc
import tau_authority as auth
import tau_commit
import tau_journal as tj
import tau_policy
import tau_proposal as tp
import tau_reconstruction as tr
import tau_shrink
import tau_speculation as spec
from bls_keys import SK_ALICE, SK_CAROL, pubkey_hex, sign_tx
from consensus import engine as engine_mod
from consensus import local_errors, sender_policy
from consensus.engine import TauConsensusEngine
from consensus.fees import FeeRuleError
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from errors import (
    DatabaseError,
    TauCommunicationError,
    TauEngineCrash,
    TauSpecIntegrationError,
    TauSpecRejected,
)

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_CAROL)
PROPOSER = "b" * 96
RULE = ("always ((i12[t]:bv[384] = { #x" + SENDER + " }:bv[384]) "
        "-> o8[t]:bv[24] = { #x000000 }:bv[24]).")

LOCAL_ERRORS = {
    "ShrinkUnavailable": lambda: tau_shrink.ShrinkUnavailable(
        "intern failed: id 255 exceeds bv[8] usable range"),
    "ShrinkWidthOverflow": lambda: tau_shrink.ShrinkWidthOverflow("id 255 exceeds bv[8]"),
    "AllocatorCapacityExceeded": lambda: alloc.AllocatorCapacityExceeded(
        "id 255 exceeds bv[8]", required_id=255, width=8, plan={}),
    "ShrinkTypeConflict": lambda: tau_shrink.ShrinkTypeConflict("i12 pinned"),
    "TauSpecIntegrationError": lambda: TauSpecIntegrationError("node text refused"),
    "ShrinkAuditFailure": lambda: tau_shrink.ShrinkAuditFailure("audit"),
    "RepresentationConflict": lambda: tr.RepresentationConflict("plain needed"),
    "ReconstructionMismatch": lambda: tr.ReconstructionMismatch("anchor"),
    "SpeculationError": lambda: spec.SpeculationError("no answer"),
    "SpeculationProtocolError": lambda: spec.SpeculationProtocolError("stale"),
    "TauCommunicationError": lambda: TauCommunicationError("pipe"),
    "TauEngineCrash": lambda: TauEngineCrash("pipe closed"),
    "MemoryError": lambda: MemoryError(),
    "RecursionError": lambda: RecursionError(),
    "OSError": lambda: OSError(28, "No space left on device"),
    "TimeoutError": lambda: TimeoutError("timed out"),
    "DatabaseError": lambda: DatabaseError("db"),
    "sqlite3.Error": lambda: sqlite3.OperationalError("disk I/O error"),
}

DETERMINISTIC_ERRORS = {
    "PolicyBuildError": lambda: tau_policy.PolicyBuildError("bad clause"),
    "PolicyStepError": lambda: tau_policy.PolicyStepError("refused"),
}


class FakeSession:
    """A speculative evaluator session that raises at the chosen call."""

    is_speculative = True
    request_budget = None

    def __init__(self, step_exc=None, rule_exc=None, multi_only=False,
                 ready=True, single_only=False):
        self.step_exc = step_exc
        self.rule_exc = rule_exc
        self.multi_only = multi_only
        self.single_only = single_only
        self._ready = ready
        self._spec = SimpleNamespace(
            state=lambda: {"spec_revision": 1, "time_point": 4,
                           "session_healthy": True})
        self.journal = None
        self.allocation = None
        self.disposed = False

    def ready(self, timeout=5.0):
        return self._ready

    def evaluate(self, inputs, *, multi=False, target=None, **kwargs):
        if self.step_exc is not None and (multi or not self.multi_only) \
                and not (multi and self.single_only):
            raise self.step_exc
        if multi:
            return {1: "1"}
        return "1"

    def apply_rule(self, rule_text, **kwargs):
        if self.rule_exc is not None:
            raise self.rule_exc
        return "ok"

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        self.disposed = True


def _transfer_tx(tx_id="tx1"):
    return sign_tx({
        "tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": SENDER,
        "sequence_number": 0, "fee_limit": "50",
        "operations": {"1": [[SENDER, RECIPIENT, 5]]},
    })


def _rule_tx(tx_id="tx1", rule=RULE):
    return sign_tx({
        "tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": SENDER,
        "sequence_number": 0, "fee_limit": "50",
        "operations": {"0": rule},
    })


def _apply(tx, session, replay_mode=False, proposer=PROPOSER, lifecycle=None,
           store=None):
    if store is None:
        store = MagicMock()
        store.commit.side_effect = lambda snap: snap
    engine = TauConsensusEngine(state_store=store)
    result = engine.apply(
        TauStateSnapshot(b"hash", b"rules", {}), [tx], 1700000000,
        target_balances={SENDER: 1000}, target_sequences={},
        target_lifecycle=lifecycle or ConsensusLifecycleManager(),
        replay_mode=replay_mode, proposer_pubkey=proposer, block_height=1,
        session=session,
    )
    return result, store


def _stops(exc_type, tx, session, match=None, **kwargs):
    """Apply raises `exc_type`, and no state is committed."""
    store = MagicMock()
    with pytest.raises(exc_type, match=match) as info:
        _apply(tx, session, store=store, **kwargs)
    store.commit.assert_not_called()
    return info.value


@pytest.fixture(autouse=True)
def _tau_ready():
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        yield


# --- the classification ---

@pytest.mark.parametrize("name", list(LOCAL_ERRORS))
def test_each_local_class_is_local(name):
    assert local_errors.is_local_apply_error(LOCAL_ERRORS[name]())


@pytest.mark.parametrize("name", list(DETERMINISTIC_ERRORS))
def test_a_policy_error_is_not_local(name):
    exc = DETERMINISTIC_ERRORS[name]()
    assert isinstance(exc, spec.SpeculationError)
    assert not local_errors.is_local_apply_error(exc)


@pytest.mark.parametrize("exc", [ValueError("bad"), TypeError("bad"),
                                 TauSpecRejected("bad text")])
def test_an_ordinary_error_is_not_local(exc):
    assert not local_errors.is_local_apply_error(exc)


# --- apply: a local error stops the block ---

@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("name", list(LOCAL_ERRORS))
def test_a_local_error_at_the_transfer_step_stops_the_block(name, replay_mode):
    exc = LOCAL_ERRORS[name]()
    raised = _stops(type(exc), _transfer_tx(), FakeSession(step_exc=exc),
                    replay_mode=replay_mode)
    assert raised is exc
    assert local_errors.owner_of(raised) == "tx1"


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("name", list(LOCAL_ERRORS))
def test_a_local_error_at_the_rule_step_stops_the_block(name, replay_mode):
    exc = LOCAL_ERRORS[name]()
    raised = _stops(type(exc), _rule_tx(), FakeSession(rule_exc=exc),
                    replay_mode=replay_mode)
    assert local_errors.owner_of(raised) == "tx1"


@pytest.mark.parametrize("name", ["OSError", "ShrinkUnavailable", "SpeculationError"])
def test_a_local_error_at_the_feeless_transfer_step_stops_the_block(name):
    exc = LOCAL_ERRORS[name]()
    raised = _stops(type(exc), _transfer_tx(), FakeSession(step_exc=exc), proposer=None)
    assert local_errors.owner_of(raised) == "tx1"


@pytest.mark.parametrize("name", ["OSError", "ShrinkUnavailable", "SpeculationError"])
def test_a_local_error_at_the_fee_query_step_stops_the_block(name):
    exc = LOCAL_ERRORS[name]()
    raised = _stops(type(exc), _rule_tx(), FakeSession(step_exc=exc, multi_only=True))
    assert local_errors.owner_of(raised) == "tx1"


def test_a_local_error_in_the_sender_policy_clause_stops_the_block():
    class RaisingPolicy:
        def verdict(self, body, inputs, timeout=None):
            raise OSError(24, "Too many open files")

    lm = ConsensusLifecycleManager()
    lm.rule_offers.accepted_clauses[(SENDER.lower(), 5)] = "o5[t] = { #x01 }:bv[8]"
    sender_policy.set_evaluator("apply", RaisingPolicy())
    try:
        raised = _stops(OSError, _transfer_tx(), FakeSession(), lifecycle=lm)
    finally:
        sender_policy.set_evaluator("apply", None)
    assert local_errors.owner_of(raised) == "tx1"


def _second_read_fails(exc):
    calls = []

    def _read():
        calls.append(1)
        if len(calls) == 2:
            raise exc
        return ""
    return _read


def test_a_local_error_reading_the_landed_rules_stops_the_block(caplog):
    session = FakeSession()
    session.is_speculative = False
    # Read 1 is before the transaction. Read 2 is the landing check.
    with caplog.at_level("ERROR", logger="consensus.engine"), \
         patch("chain_state.get_application_rules_state",
               side_effect=_second_read_fails(sqlite3.OperationalError("disk I/O error"))):
        raised = _stops(sqlite3.OperationalError, _rule_tx(), session)
    assert local_errors.owner_of(raised) == "tx1"
    logs = [r.getMessage() for r in caplog.records if "Node-local error" in r.getMessage()]
    assert len(logs) == 1, logs
    assert "rule step of tx tx1" in logs[0]


def test_an_ordinary_error_reading_the_landed_rules_is_not_landed():
    with patch("chain_state.get_application_rules_state",
               side_effect=ValueError("bad")):
        assert engine_mod._application_rule_landed(RULE) is False


def test_the_log_names_the_step_and_the_transaction(caplog):
    with caplog.at_level("ERROR", logger="consensus.engine"):
        _stops(OSError, _transfer_tx(), FakeSession(step_exc=OSError(28, "full")))
    assert any("Node-local error in the transfer step of tx tx1" in r.getMessage()
               and "no verdict" in r.getMessage() for r in caplog.records)


# --- apply: deterministic errors keep their verdict ---

@pytest.mark.parametrize("name", list(DETERMINISTIC_ERRORS))
def test_a_policy_error_at_the_transfer_step_keeps_its_reject(name):
    result, _ = _apply(_transfer_tx(),
                       FakeSession(step_exc=DETERMINISTIC_ERRORS[name]()))
    assert not result.accepted_transactions
    assert [t["tx_id"] for t in result.rejected_transactions] == ["tx1"]


@pytest.mark.parametrize("name", list(DETERMINISTIC_ERRORS))
def test_a_policy_error_in_the_sender_policy_clause_keeps_its_reject(name):
    class RaisingPolicy:
        def verdict(self, body, inputs, timeout=None):
            raise DETERMINISTIC_ERRORS[name]()

    lm = ConsensusLifecycleManager()
    lm.rule_offers.accepted_clauses[(SENDER.lower(), 5)] = "o5[t] = { #x01 }:bv[8]"
    sender_policy.set_evaluator("apply", RaisingPolicy())
    try:
        result, _ = _apply(_transfer_tx(), FakeSession(), lifecycle=lm)
    finally:
        sender_policy.set_evaluator("apply", None)
    assert not result.accepted_transactions
    assert result.receipts["tx1"]["reason"] == "user_policy_block"


@pytest.mark.parametrize("replay_mode", [False, True])
def test_a_refused_rule_text_keeps_its_reject(replay_mode):
    result, _ = _apply(_rule_tx(),
                       FakeSession(rule_exc=TauSpecRejected("bad text")),
                       replay_mode=replay_mode)
    assert not result.accepted_transactions
    assert result.receipts["tx1"]["reason"] == "rule_rejected"


def test_an_ordinary_error_at_the_transfer_step_keeps_its_reject():
    result, store = _apply(_transfer_tx(), FakeSession(step_exc=RuntimeError("x")))
    assert [t["tx_id"] for t in result.rejected_transactions] == ["tx1"]
    store.commit.assert_called_once()


# --- the rule step without an evaluator ---

def test_a_rule_step_without_an_evaluator_stops_the_block():
    _stops(FeeRuleError, _rule_tx(), FakeSession(ready=False), match="rule execution")


def test_a_replayed_rule_step_without_an_evaluator_keeps_the_transaction():
    result, _ = _apply(_rule_tx(), FakeSession(ready=False), replay_mode=True)
    assert [t["tx_id"] for t in result.accepted_transactions] == ["tx1"]
    assert "Tau not ready" in result.receipts["tx1"]["logs"]


# --- the worker pipe ---

def test_an_undecodable_result_frame_is_a_protocol_error():
    session = object.__new__(spec.SpeculationSession)
    body = b"{not json"
    session._result = io.BytesIO(spec._HDR.pack(len(body)) + body)
    with pytest.raises(spec.SpeculationProtocolError, match="undecodable"):
        session._recv()


# --- receive and rebuild ---

@pytest.fixture
def enabled_owner():
    owner = auth.AuthoritativeTauOwner(ready=threading.Event())
    owner.enabled = True
    auth.reset(owner)
    tau_commit.registry().discard()
    yield owner
    tau_commit.registry().discard()
    auth.reset(None)


@pytest.fixture
def accept_headers():
    with patch.object(TauConsensusEngine, "verify_block_header",
                      lambda *a, **k: True):
        yield


def _proposal(session):
    plan = tr.plan_representation(candidate_rules=[])
    return tp.ProposalContext(
        session=session, journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan,
    )


def _serve(owner, session):
    owner.build_proposal = lambda **kw: _proposal(session)


def _transfer_block():
    import block as block_mod
    import chain_state
    import db

    chain_state._balances[SENDER] = 1000
    chain_state._sequence_numbers[SENDER] = 0
    head = db.get_canonical_head()
    tx = sign_tx({
        "tx_type": "user_tx", "sender_pubkey": SENDER, "sequence_number": 0,
        "expiration_time": 9999999999, "expire_at_height": 5000,
        "fee_limit": "50", "operations": {"1": [[SENDER, RECIPIENT, "5"]]},
    })
    block = block_mod.Block.create(
        block_number=int(head["header"]["block_number"]) + 1,
        previous_hash=head["block_hash"], transactions=[tx],
        proposer_pubkey="d4" * 48, timestamp=1700000100,
    )
    # Empty skips the state-hash check, so the verdict alone decides acceptance.
    block.header.state_hash = ""
    return block


def test_a_received_block_with_a_local_error_is_not_accepted_then_applies(
        node_state, enabled_owner, accept_headers):
    import chain_state
    import db

    block = _transfer_block()
    head = db.get_canonical_head()["block_hash"]
    failing = FakeSession(step_exc=OSError(28, "No space left on device"))
    _serve(enabled_owner, failing)
    assert chain_state.process_new_block(block) is False
    assert db.get_canonical_head()["block_hash"] == head
    assert failing.disposed
    assert chain_state.get_balance(RECIPIENT) == 0

    _serve(enabled_owner, FakeSession())
    assert chain_state.process_new_block(block) is True
    assert db.get_canonical_head()["block_hash"] == block.block_hash
    assert chain_state.get_balance(RECIPIENT) == 5


def test_a_rebuild_with_a_local_error_stops(node_state, enabled_owner, accept_headers):
    import chain_state

    block = _transfer_block()
    _serve(enabled_owner, FakeSession())
    assert chain_state.process_new_block(block) is True

    enabled_owner.rebuild_genesis = lambda *a, **k: None
    _serve(enabled_owner, FakeSession(step_exc=tau_shrink.ShrinkUnavailable("capacity")))
    result = chain_state.rebuild_state_from_blockchain(start_block=0)
    assert not result.ok
    assert result.stopped_at_block == block.header.block_number
    assert "evaluation failed" in (result.reason or "")


# --- proposal ---

class SenderFailingSession(FakeSession):
    """Raises a local error only for transfers from `sender`."""

    def __init__(self, sender, exc):
        super().__init__()
        self.sender = sender
        self.exc = exc

    def evaluate(self, inputs, **kwargs):
        if any(self.sender in str(value) for value in (inputs or {}).values()):
            raise self.exc
        return super().evaluate(inputs, **kwargs)


@pytest.fixture
def clean_deferrals():
    from commands import createblock

    createblock._deferred.clear()
    yield createblock._deferred
    createblock._deferred.clear()


def _queued_transfers(tags):
    """One funded sender per tag, each with one queued transfer."""
    import hashlib
    import json
    import time

    from py_ecc.bls import G2Basic as bls

    import chain_state
    from commands import sendtx

    queued = []
    for tag in tags:
        sk = bls.KeyGen(f"{tag}_alev_sender".encode())
        pk = bls.SkToPk(sk).hex()
        chain_state._balances[pk] = 1_000
        tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": 0,
              "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
              "operations": {"1": [[pk, RECIPIENT, "10"]]}, "fee_limit": "0"}
        tx["signature"] = bls.Sign(sk, hashlib.sha256(
            sendtx._get_signing_message_bytes(tx)).digest()).hex()
        out = sendtx.queue_transaction(json.dumps(tx), propagate=False)
        assert out.get("ok"), out
        queued.append((pk, out["tx_hash"]))
    return queued


def _mine(proposal_factory, *, apply=None):
    from commands import createblock

    patches = [
        patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True),
        patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True),
        patch.object(createblock, "_speculative_proposal", proposal_factory),
    ]
    if apply is not None:
        patches.append(patch.object(TauConsensusEngine, "apply_block", apply))
    for p in patches:
        p.start()
    try:
        return createblock.create_block_from_mempool()
    finally:
        for p in reversed(patches):
            p.stop()


def _pending(tx_hash):
    import db

    entry = db.get_mempool_entry(tx_hash)
    return entry is not None and entry.get("status") != "reserved"


def test_a_local_error_in_one_transaction_defers_it_and_mines_the_others(
        node_state, clean_deferrals):
    import db

    (_, good1), (bad_pk, bad), (_, good2) = _queued_transfers(["a", "b", "c"])
    head = db.get_canonical_head()["block_hash"]
    session_factory = lambda **kw: _proposal(SenderFailingSession(
        bad_pk, OSError(28, "No space left on device")))

    out = _mine(session_factory)
    assert "error" in out, out
    assert db.get_canonical_head()["block_hash"] == head
    assert set(clean_deferrals) == {bad}
    for tx_hash in (good1, bad, good2):
        assert _pending(tx_hash), tx_hash
        assert db.get_dropped_tx(tx_hash) is None

    out = _mine(session_factory)
    assert "block_hash" in out, out
    mined = db.get_canonical_head_block().get("tx_ids") or []
    assert good1 in mined and good2 in mined
    assert bad not in mined
    assert _pending(bad)
    assert db.get_dropped_tx(bad) is None


def test_a_local_error_with_no_owner_returns_the_batch(node_state, clean_deferrals):
    import db

    hashes = [h for _, h in _queued_transfers(["d", "e", "f"])]
    head = db.get_canonical_head()["block_hash"]

    def _fail(*args, **kwargs):
        raise OSError(28, "No space left on device")

    out = _mine(lambda **kw: _proposal(FakeSession()), apply=_fail)
    assert "error" in out, out
    assert db.get_canonical_head()["block_hash"] == head
    assert not clean_deferrals
    for tx_hash in hashes:
        assert _pending(tx_hash), tx_hash
        assert db.get_dropped_tx(tx_hash) is None


def test_a_local_error_owned_by_no_queued_transaction_defers_nothing(clean_deferrals):
    from commands import createblock

    exc = OSError(28, "full")
    local_errors.mark_owner(exc, "not-in-batch")
    createblock._defer_local(exc, [{"tx_id": "t1"}], [7],
                             [{"id": 7, "tx_hash": "h1"}])
    assert not clean_deferrals


def test_the_first_owner_of_a_local_error_stays():
    exc = OSError(28, "full")
    local_errors.mark_owner(exc, None)
    assert local_errors.owner_of(exc) is None
    local_errors.mark_owner(exc, "inner")
    local_errors.mark_owner(exc, "outer")
    assert local_errors.owner_of(exc) == "inner"


# --- re-exec on width overflow ---

@pytest.fixture
def reexec_calls():
    """Record each call of the re-exec handler. Raise as test mode does, never exec."""
    import tau_manager

    calls = []

    def _handler(exc):
        calls.append(exc)
        raise exc

    with patch.object(tau_manager, "_handle_width_overflow", _handler):
        yield calls


def _overflow():
    return tau_shrink.ShrinkWidthOverflow("id 255 exceeds bv[8]")


def test_a_width_overflow_on_the_receive_path_reaches_the_reexec(
        node_state, enabled_owner, accept_headers, reexec_calls):
    import chain_state

    block = _transfer_block()
    _serve(enabled_owner, FakeSession(step_exc=_overflow()))
    assert chain_state.process_new_block(block) is False
    assert [type(e) for e in reexec_calls] == [tau_shrink.ShrinkWidthOverflow]


def test_a_width_overflow_in_the_rebuild_reaches_the_reexec(
        node_state, enabled_owner, accept_headers, reexec_calls):
    import chain_state

    block = _transfer_block()
    _serve(enabled_owner, FakeSession())
    assert chain_state.process_new_block(block) is True
    assert reexec_calls == []

    enabled_owner.rebuild_genesis = lambda *a, **k: None
    _serve(enabled_owner, FakeSession(step_exc=_overflow()))
    result = chain_state.rebuild_state_from_blockchain(start_block=0)
    assert not result.ok
    assert [type(e) for e in reexec_calls] == [tau_shrink.ShrinkWidthOverflow]


def test_a_width_overflow_in_the_proposal_reaches_the_reexec(
        node_state, clean_deferrals, reexec_calls):
    (pk, tx_hash), = _queued_transfers(["g"])
    out = _mine(lambda **kw: _proposal(SenderFailingSession(pk, _overflow())))
    assert "error" in out, out
    assert [type(e) for e in reexec_calls] == [tau_shrink.ShrinkWidthOverflow]
    assert _pending(tx_hash)


# --- one key function for the owner ---

def test_the_proposer_finds_the_owner_with_the_key_function_of_the_engine(
        clean_deferrals):
    from commands import createblock

    assert createblock.tx_receipt_key is engine_mod.tx_receipt_key
    tx = sign_tx({
        "tx_type": "user_tx", "sender_pubkey": SENDER, "sequence_number": 0,
        "fee_limit": "50", "operations": {"1": [[SENDER, RECIPIENT, 5]]},
    })
    assert "tx_id" not in tx
    raised = _stops(OSError, tx, FakeSession(step_exc=OSError(28, "full")))
    assert local_errors.owner_of(raised) == engine_mod.tx_receipt_key(tx, 0)
    createblock._defer_local(raised, [tx], [7], [{"id": 7, "tx_hash": "h1"}])
    assert set(clean_deferrals) == {"h1"}


# --- a local error outside the catches of the apply steps ---

O5_RULE = (
    "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def test_a_local_error_in_the_o5_clause_routing_names_its_transaction():
    class RaisingBuild:
        def validate(self, body, timeout=None):
            raise OSError(24, "Too many open files")

    sender_policy.set_evaluator("apply", RaisingBuild())
    try:
        raised = _stops(OSError, _rule_tx(rule=O5_RULE), FakeSession())
    finally:
        sender_policy.set_evaluator("apply", None)
    assert local_errors.owner_of(raised) == "tx1"


def test_a_clause_that_does_not_build_keeps_its_reject_in_the_routing():
    from consensus.policy_mock import MockPolicyEvaluator
    from consensus.rule_offers import clause_body_v1

    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.fail_build(clause_body_v1(O5_RULE), "Incompatible type information")
    sender_policy.set_evaluator("apply", evaluator)
    try:
        result, _ = _apply(_rule_tx(rule=O5_RULE), FakeSession())
    finally:
        sender_policy.set_evaluator("apply", None)
    assert not result.accepted_transactions
    assert result.receipts["tx1"]["reason"] == "rule_not_applied"


def _two_transfers(amount1):
    return [
        sign_tx({"tx_id": "tx1", "tx_type": "user_tx", "sender_pubkey": SENDER,
                 "sequence_number": 0, "fee_limit": "50",
                 "operations": {"1": [[SENDER, RECIPIENT, amount1]]}}),
        sign_tx({"tx_id": "tx2", "tx_type": "user_tx", "sender_pubkey": SENDER,
                 "sequence_number": 0, "fee_limit": "50",
                 "operations": {"1": [[SENDER, RECIPIENT, 5]]}}),
    ]


def test_a_local_error_of_the_reconstruct_before_a_transaction_has_no_owner(
        clean_deferrals):
    from unittest.mock import PropertyMock

    from commands import createblock

    def _rebuild(journal, plan):
        raise OSError(28, "No space left on device")

    session = FakeSession()
    plan = tr.plan_representation(candidate_rules=[])
    proposal = tp.ProposalContext(
        session=session, journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan, rebuild=_rebuild, lifecycle=ConsensusLifecycleManager(),
    )
    # tx1 is rejected for its balance after a step, so the proposal is dirty.
    txs = _two_transfers(amount1=5000)
    with patch.object(tp.TxBranch, "touched_evaluator", new_callable=PropertyMock,
                      return_value=True):
        with pytest.raises(OSError) as info:
            TauConsensusEngine(state_store=MagicMock()).apply(
                TauStateSnapshot(b"hash", b"rules", {}), txs, 1700000000,
                target_balances={SENDER: 1000}, target_sequences={},
                target_lifecycle=proposal.lifecycle, proposer_pubkey=PROPOSER,
                block_height=1, session=session, proposal=proposal,
            )
    assert "reconstruction failed" in (proposal.poisoned or "")
    assert local_errors.owner_of(info.value) is None
    createblock._defer_local(info.value, txs, [1, 2],
                             [{"id": 1, "tx_hash": "h1"}, {"id": 2, "tx_hash": "h2"}])
    assert not clean_deferrals


def test_a_local_error_in_an_uncaught_call_of_the_second_transaction_names_it():
    class RaisingBuild:
        def validate(self, body, timeout=None):
            raise OSError(24, "Too many open files")

    txs = [_two_transfers(amount1=5)[0], sign_tx({
        "tx_id": "tx2", "tx_type": "user_tx", "sender_pubkey": SENDER,
        "sequence_number": 1, "fee_limit": "50", "operations": {"0": O5_RULE},
    })]
    sender_policy.set_evaluator("apply", RaisingBuild())
    try:
        store = MagicMock()
        with pytest.raises(OSError) as info:
            TauConsensusEngine(state_store=store).apply(
                TauStateSnapshot(b"hash", b"rules", {}), txs, 1700000000,
                target_balances={SENDER: 1000}, target_sequences={},
                target_lifecycle=ConsensusLifecycleManager(),
                proposer_pubkey=PROPOSER, block_height=1, session=FakeSession(),
            )
    finally:
        sender_policy.set_evaluator("apply", None)
    store.commit.assert_not_called()
    assert local_errors.owner_of(info.value) == "tx2"


def test_a_local_error_outside_a_transaction_has_no_owner():
    with patch.object(TauConsensusEngine, "_apply",
                      side_effect=OSError(28, "full")):
        raised = _stops(OSError, _transfer_tx(), FakeSession())
    assert local_errors.owner_of(raised) is None


# --- the header check ---

def _header_block():
    return SimpleNamespace(
        header=SimpleNamespace(block_number=5, proposer_pubkey="aa" * 48,
                               timestamp=1700000000, previous_hash="00" * 32),
        consensus_proof="proof", transactions=[],
    )


def test_a_local_error_in_the_header_check_stops_the_check():
    with patch.object(TauConsensusEngine, "_build_consensus_input_streams",
                      side_effect=OSError(28, "full")):
        with pytest.raises(OSError):
            TauConsensusEngine().verify_block_header(_header_block())


def test_a_bad_header_field_keeps_the_refusal():
    with patch.object(TauConsensusEngine, "_build_consensus_input_streams",
                      side_effect=ValueError("value does not fit bv[64]")):
        assert TauConsensusEngine().verify_block_header(_header_block()) is False


def _ingest(verify):
    import time

    import block as block_mod
    import chain_state

    blk = block_mod.Block.create(
        block_number=3, previous_hash="ab" * 32, transactions=[],
        proposer_pubkey="d4" * 48, timestamp=int(time.time()),
    )
    with patch.object(block_mod.Block, "verify_consensus_proof", lambda self: True), \
         patch.object(TauConsensusEngine, "verify_block_header", verify):
        return blk, chain_state.ingest_block(blk)


def test_a_local_error_in_the_header_pre_check_keeps_the_block(temp_database):
    import db

    def _local(*args, **kwargs):
        raise TauCommunicationError("pipe")

    blk, res = _ingest(_local)
    assert res.status == "orphan"
    assert db.get_block_by_hash(blk.block_hash) is not None


def test_a_refused_header_is_still_invalid_at_ingest(temp_database):
    import db

    blk, res = _ingest(lambda *a, **k: False)
    assert res.status == "invalid"
    assert db.get_block_by_hash(blk.block_hash) is None


def test_an_ordinary_error_in_the_header_pre_check_goes_up(temp_database):
    def _bug(*args, **kwargs):
        raise KeyError("header")

    with pytest.raises(KeyError):
        _ingest(_bug)


def test_an_ordinary_error_in_the_header_check_stays_a_node_bug(node_state):
    import chain_state
    from errors import BlockchainBug

    def _bug(*args, **kwargs):
        raise KeyError("header")

    with patch.object(TauConsensusEngine, "verify_block_header", _bug):
        with pytest.raises(BlockchainBug):
            chain_state.process_new_block(_transfer_block())


def test_a_local_error_in_the_header_check_is_not_accepted_now(node_state):
    import chain_state
    import db

    block = _transfer_block()
    head = db.get_canonical_head()["block_hash"]

    def _local(*args, **kwargs):
        raise OSError(28, "No space left on device")

    with patch.object(TauConsensusEngine, "verify_block_header", _local):
        assert chain_state.process_new_block(block) is False
    assert db.get_canonical_head()["block_hash"] == head


# --- the activation audit ---

@pytest.mark.parametrize("exc", [
    OSError(5, "Input/output error"),
    UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte"),
])
def test_a_read_error_of_the_builtin_rules_stops_the_activation_audit(exc):
    import test_approval_apply as ap

    def _audit(self, height, effective_spec_texts=None):
        effective_spec_texts()
        return []

    with patch.object(ConsensusLifecycleManager, "process_height_transitions", _audit), \
         patch("chain_state.load_builtin_rules_from_disk", side_effect=exc):
        with pytest.raises(OSError):
            ap._apply([])


def test_the_activation_audit_reads_the_builtin_rules():
    import test_approval_apply as ap

    seen = []

    def _audit(self, height, effective_spec_texts=None):
        seen.extend(name for name, _ in effective_spec_texts())
        return []

    with patch.object(ConsensusLifecycleManager, "process_height_transitions", _audit), \
         patch("chain_state.load_builtin_rules_from_disk", return_value=["r1", "r2"]):
        ap._apply([])
    assert {"builtin_rule_0", "builtin_rule_1"} <= set(seen)


# --- the rules reads and the custom-input step ---

def test_a_local_error_reading_the_rules_before_the_transaction_stops_the_block():
    reads = iter([OSError(5, "Input/output error")])

    def _first_read_fails():
        exc = next(reads, None)
        if exc is not None:
            raise exc
        return ""

    with patch("chain_state.get_application_rules_state", side_effect=_first_read_fails):
        raised = _stops(OSError, _transfer_tx(), FakeSession())
    assert local_errors.owner_of(raised) == "tx1"


def test_an_ordinary_error_reading_the_rules_before_the_transaction_is_skipped():
    with patch("chain_state.get_application_rules_state",
               side_effect=ValueError("bad")):
        result, _ = _apply(_transfer_tx(), FakeSession())
    assert [t["tx_id"] for t in result.accepted_transactions] == ["tx1"]


def _landed_rule_reads(second):
    """The first rules read succeeds. The read after the landed rule gives `second`."""
    calls = []

    def _read():
        calls.append(1)
        if len(calls) >= 2:
            raise second
        return ""
    return _read


def test_a_local_error_reading_the_rules_after_the_rule_stops_the_block():
    session = FakeSession()
    session.is_speculative = False
    with patch.object(engine_mod, "_application_rule_landed", return_value=True), \
         patch("chain_state.get_application_rules_state",
               side_effect=_landed_rule_reads(sqlite3.OperationalError("disk I/O error"))):
        raised = _stops(sqlite3.OperationalError, _rule_tx(), session)
    assert local_errors.owner_of(raised) == "tx1"


def test_an_ordinary_error_reading_the_rules_after_the_rule_keeps_the_rule():
    session = FakeSession()
    session.is_speculative = False
    with patch.object(engine_mod, "_application_rule_landed", return_value=True), \
         patch("chain_state.get_application_rules_state",
               side_effect=_landed_rule_reads(ValueError("bad"))):
        result, _ = _apply(_rule_tx(), session)
    assert [t["tx_id"] for t in result.accepted_transactions] == ["tx1"]
    assert "Rule applied" in result.receipts["tx1"]["logs"]


def test_a_local_error_at_the_custom_input_step_stops_the_block():
    exc = OSError(28, "No space left on device")
    raised = _stops(OSError, _rule_tx(), FakeSession(step_exc=exc, single_only=True))
    assert local_errors.owner_of(raised) == "tx1"


def test_an_ordinary_error_at_the_custom_input_step_keeps_the_transaction():
    result, _ = _apply(_rule_tx(),
                       FakeSession(step_exc=RuntimeError("x"), single_only=True))
    assert [t["tx_id"] for t in result.accepted_transactions] == ["tx1"]
    assert result.receipts["tx1"]["status"] == "failed"


# --- the header check without a ready evaluator ---

@pytest.fixture
def no_evaluator():
    import tau_manager

    ready = MagicMock()
    ready.is_set.return_value = False
    with patch.object(tau_manager, "tau_ready", ready), \
         patch.object(engine_mod, "_advisory_is_available", return_value=False):
        yield


def test_a_header_check_without_an_evaluator_stops_with_no_refusal(no_evaluator):
    from errors import TauUnavailable

    assert local_errors.is_local_apply_error(TauUnavailable("x"))
    with pytest.raises(TauUnavailable, match="not ready"):
        TauConsensusEngine().verify_block_header(_header_block())


def test_a_header_pre_check_without_an_evaluator_keeps_the_block(temp_database):
    import time

    import block as block_mod
    import chain_state
    import db
    import tau_manager

    blk = block_mod.Block.create(
        block_number=3, previous_hash="ab" * 32, transactions=[],
        proposer_pubkey="d4" * 48, timestamp=int(time.time()),
    )
    blk.consensus_proof = "proof"
    ready = MagicMock()
    ready.is_set.return_value = False
    with patch.object(block_mod.Block, "verify_consensus_proof", lambda self: True), \
         patch.object(tau_manager, "tau_ready", ready), \
         patch.object(engine_mod, "_advisory_is_available", return_value=False):
        res = chain_state.ingest_block(blk)
    assert res.status == "orphan"
    assert db.get_block_by_hash(blk.block_hash) is not None


# --- the header check of the rebuild ---

def test_a_local_error_in_the_header_check_of_the_rebuild_names_it(
        node_state, enabled_owner, accept_headers):
    import chain_state

    block = _transfer_block()
    _serve(enabled_owner, FakeSession())
    assert chain_state.process_new_block(block) is True

    def _local(*args, **kwargs):
        raise TauCommunicationError("pipe")

    enabled_owner.rebuild_genesis = lambda *a, **k: None
    with patch.object(TauConsensusEngine, "verify_block_header", _local):
        result = chain_state.rebuild_state_from_blockchain(start_block=0)
    assert not result.ok
    assert result.stopped_at_block == block.header.block_number
    assert result.reason == ("header check stopped by a node-local error: "
                             "TauCommunicationError: pipe")


def test_a_refused_header_in_the_rebuild_keeps_its_reason(
        node_state, enabled_owner, accept_headers):
    import chain_state

    block = _transfer_block()
    _serve(enabled_owner, FakeSession())
    assert chain_state.process_new_block(block) is True

    enabled_owner.rebuild_genesis = lambda *a, **k: None
    with patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: False):
        result = chain_state.rebuild_state_from_blockchain(start_block=0)
    assert not result.ok
    assert result.reason == "header verification failed"


# --- the receive path with the authority off ---

def test_a_local_error_with_the_authority_off_is_not_accepted_now(
        node_state, accept_headers):
    import chain_state
    import db
    import tau_authority

    assert not tau_authority.owner().enabled
    block = _transfer_block()
    head = db.get_canonical_head()["block_hash"]
    with patch.object(TauConsensusEngine, "apply_block",
                      side_effect=OSError(28, "No space left on device")):
        assert chain_state.process_new_block(block) is False
    assert db.get_canonical_head()["block_hash"] == head


def test_an_ordinary_error_with_the_authority_off_stays_a_node_bug(
        node_state, accept_headers):
    import chain_state
    from errors import BlockchainBug

    with patch.object(TauConsensusEngine, "apply_block", side_effect=KeyError("x")):
        with pytest.raises(BlockchainBug):
            chain_state.process_new_block(_transfer_block())
