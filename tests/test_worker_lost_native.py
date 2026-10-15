"""A real worker killed mid-request is an operational failure, not a verdict.

Otherwise one valid transaction is rejected where the worker died and included
where it lived.
"""
import hashlib
import json
import os
import threading
import time
import types
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic as bls

import chain_state
import db
import tau_admission
import tau_authority as auth
import tau_commit as tc
import tau_speculation as spec
from commands import createblock, gettxstatus, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RULE = "always ( o12[t]:bv[24] = i13[t]:bv[24] )."
MARKER = "o12[t]:bv[24] = i13[t]:bv[24]"


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(),
                                reason="native tau module not built")


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _baseline():
    return "always ( " + open(os.path.join(REPO, "genesis.tau")).read().strip() + " )."


@pytest.fixture
def authority(node_state):
    ready = threading.Event()
    owner = auth.AuthoritativeTauOwner(ready=ready, program_baseline=_baseline())
    auth.reset(owner)
    tc.registry().discard()
    tau_admission.reset()
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    tau_admission.reset()
    tc.registry().discard()
    auth.reset(None)


@pytest.fixture(autouse=True)
def _no_deferrals():
    createblock._deferred.clear()
    yield
    createblock._deferred.clear()


@pytest.fixture(autouse=True)
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True):
        yield


class _Killer:
    """Kills the worker after a marked revision is sent and before it answers,
    which is what the caller sees when the kernel kills a working worker."""

    def __init__(self):
        self.marker = None
        self.kill_on = ()
        self.seen = 0
        self.killed = []

    def arm(self, *kill_on):
        self.marker, self.kill_on, self.seen = MARKER, kill_on, 0

    def disarm(self):
        self.marker = None


@pytest.fixture
def killer():
    hook = _Killer()
    real_send, real_recv = spec.SpeculationSession._send, spec.SpeculationSession._recv

    def _send(self, payload):
        self._pending = payload
        return real_send(self, payload)

    def _recv(self):
        payload = getattr(self, "_pending", None) or {}
        if (hook.marker and payload.get("op") == "revise"
                and hook.marker in (payload.get("candidate") or "")):
            hook.seen += 1
            if hook.seen in hook.kill_on:
                self._proc.kill()
                self._proc.wait(timeout=10)
                hook.killed.append(self)
        return real_recv(self)

    with patch.object(spec.SpeculationSession, "_send", _send), \
         patch.object(spec.SpeculationSession, "_recv", _recv):
        yield hook


def _sender(tag, balance=1_000_000):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = balance
    return sk, pk


def _submit(sk, pk, ops, fee_limit="100000"):
    seq = chain_state.get_sequence_number(pk)
    pending = db.get_pending_sequence(pk)
    if pending is not None and pending >= seq:
        seq = pending + 1
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": ops, "fee_limit": fee_limit}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _head():
    return db.get_canonical_head()["block_hash"]


def _included(tx_hash):
    return tx_hash in ((db.get_canonical_head_block() or {}).get("tx_ids") or [])


def _queued(tx_hash):
    """Still waiting its turn, with no verdict recorded against it."""
    entry = db.get_mempool_entry(tx_hash)
    assert entry is not None, "the transaction left the mempool"
    assert entry["status"] == "pending", entry
    assert db.get_dropped_tx(tx_hash) is None, "a verdict was recorded"
    status = json.loads(gettxstatus.execute(
        f"gettxstatus {tx_hash}", types.SimpleNamespace(db=db)))
    assert status["data"]["status"] == "queued", status


def _assert_serves_no_dead_worker(owner):
    served = owner._session if owner.active else None
    assert served is None or served._spec._proc.poll() is None, (
        "the node still serves a worker that was killed under it"
    )


def _queue_a_rule(tag):
    sk, pk = _sender(tag)
    admitted = _submit(sk, pk, {"0": RULE})
    assert admitted.get("ok"), admitted
    return admitted["tx_hash"]


# --- admission ------------------------------------------------------------------

def test_a_killed_worker_makes_admission_unavailable_not_a_rejection(authority, killer):
    sk, pk = _sender("lost_admission")
    killer.arm(1)
    refused = _submit(sk, pk, {"0": RULE})
    assert killer.killed, "the worker was never killed: the test reached no evaluation"
    assert not refused.get("ok") and refused.get("code") == "ADMISSION_UNAVAILABLE", refused
    assert db.get_dropped_tx(refused.get("tx_hash") or "0" * 64) is None

    killer.disarm()
    assert _submit(sk, pk, {"0": RULE}).get("ok"), "the rule is valid; only the worker was lost"


# --- mining ---------------------------------------------------------------------

def test_a_killed_worker_aborts_the_round_and_the_batch_stays_pending(authority, killer):
    tx_hash = _queue_a_rule("lost_mining")
    head = _head()
    pending_before = db.get_mempool_entry(tx_hash)["status"]
    assert pending_before == "pending"

    killer.arm(1)
    out = createblock.create_block_from_mempool()

    assert killer.killed, "the worker was never killed: the test reached no evaluation"
    assert "error" in out and "block_hash" not in out, out
    assert "evaluator lost" in out["error"], out
    assert _head() == head, "a block landed although its evaluation was lost"
    _queued(tx_hash)
    assert set(createblock._deferred) == {tx_hash}, (
        "the transaction in evaluation when the worker died was not deferred")
    _assert_serves_no_dead_worker(authority)

    killer.disarm()
    backed_off = createblock.create_block_from_mempool()
    assert "error" not in backed_off and "block_hash" not in backed_off, backed_off
    _queued(tx_hash)

    later = time.monotonic() + createblock.DEFER_BASE_SECONDS + 1
    with patch.object(createblock, "_now", lambda: later):
        mined = createblock.create_block_from_mempool()
    assert "error" not in mined, mined
    assert _included(tx_hash), "the transaction was not included once a worker lived"
    assert authority.state == auth.ACTIVE and authority.active


# --- the commit gate ------------------------------------------------------------

def test_a_worker_killed_between_freezing_and_the_gate_costs_the_artifact_only(
        authority):
    """A dead worker reads as an empty state, which agrees with every counter, so
    without a strict gate the artifact would be promoted."""
    tx_hash = _queue_a_rule("lost_gate")
    victims = []
    real_offer = tc.registry().offer

    def _offer_then_kill(execution_id, prepared, proposal):
        real_offer(execution_id, prepared, proposal)
        victim = proposal.session._spec
        victim._proc.kill()
        victim._proc.wait(timeout=10)
        victims.append(victim)

    with patch.object(tc.registry(), "offer", _offer_then_kill):
        out = createblock.create_block_from_mempool()

    assert victims, "no artifact was offered: the test reached nothing"
    assert "error" not in out and "block_hash" in out, out
    assert _included(tx_hash)
    assert authority.state == auth.ACTIVE and authority.active
    _assert_serves_no_dead_worker(authority)
    assert authority._session._spec is not victims[0], "the killed worker was promoted"


# --- ingestion ------------------------------------------------------------------

def test_a_block_whose_own_evaluation_loses_the_worker_is_not_accepted_now(
        authority, killer):
    """The miner's artifact is refused, so ingestion evaluates the block itself
    and loses its worker: not accepted yet, not invalid, transactions kept."""
    tx_hash = _queue_a_rule("lost_ingestion")
    head = _head()
    ingestion = []
    real_process = chain_state.process_new_block

    def _spy(block):
        try:
            result = real_process(block)
        except BaseException as exc:    # noqa: BLE001 - recording, then re-raising
            ingestion.append(("raised", exc))
            raise
        ingestion.append(("returned", result))
        return result

    built = []
    real_build = authority.build_proposal

    def _record(**kwargs):
        built.append(real_build(**kwargs))
        return built[-1]

    killer.arm(2)     # the miner's evaluation is the first, ingestion's the second
    with patch.object(tc.registry(), "offer", side_effect=RuntimeError("no artifact")), \
         patch.object(authority, "build_proposal", _record), \
         patch.object(chain_state, "process_new_block", _spy):
        out = createblock.create_block_from_mempool()

    assert killer.seen >= 2 and killer.killed, (
        "ingestion never evaluated the block itself; the test reached nothing"
    )
    assert ingestion == [("returned", False)], ingestion
    # Not accepted for the RIGHT reason: the evaluation was lost. A lost worker
    # read as a rejected transaction would also fail the block, on its state hash.
    ingestion_proposal = [p for p in built if p.label.startswith("block-")]
    assert ingestion_proposal and "evaluator lost" in (ingestion_proposal[-1].poisoned or ""), (
        [p.poisoned for p in built]
    )
    assert "error" in out and "block_hash" not in out, out
    assert _head() == head
    _queued(tx_hash)
    _assert_serves_no_dead_worker(authority)

    killer.disarm()
    mined = createblock.create_block_from_mempool()
    assert "error" not in mined, mined
    assert _included(tx_hash)
    assert authority.state == auth.ACTIVE and authority.active
