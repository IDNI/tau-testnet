"""Phase 3: stake-mode block verification + mode-conditional host gates.

In stake mode the host membership gate is bypassed and Tau's o7 (evaluated on
the proposer's PARENT-state balance fed on i14) is the eligibility authority.
The mode is read ONLY from the parent snapshot's lifecycle manager, never from
per-node config.
"""
import json
import os
import subprocess
import sys

import pytest
from unittest.mock import Mock, patch

from consensus.engine import TauConsensusEngine, ActiveConsensusView
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from block import Block


VALIDATOR = "a" * 96
OUTSIDER = "b" * 96


def _stake_fixture(*, parent_balances, proposer_hex=OUTSIDER, block_number=5):
    """Engine + stake-mode view where the proposer is NOT in the validator set."""
    active_view = ActiveConsensusView(
        target_height=block_number,
        consensus_rules="always (o6[t]:bv[64] = i10[t]:bv[64]).",
        active_validators=[bytes.fromhex(VALIDATOR)],
        mechanism_specific_metadata={"poa": False, "eligibility_mode": "stake"},
        parent_balances=parent_balances,
    )
    block_obj = Block.create(
        block_number=block_number,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=proposer_hex,
        timestamp=1234567890,
    )
    block_obj.consensus_proof = {"signature": "00" * 48}
    return TauConsensusEngine(), active_view, block_obj


def _ready():
    r = Mock()
    r.is_set.return_value = True
    return r


def test_stake_mode_outsider_with_stake_accepted():
    engine, view, block = _stake_fixture(parent_balances={OUTSIDER: 200000})
    with patch("tau_manager.tau_ready", _ready()), \
         patch("tau_manager.communicate_with_tau_multi", return_value={6: "1", 7: "1"}):
        assert engine.verify_block_header(view, block, {"proof_ok": True}) is True


def test_stake_mode_o7_zero_rejected():
    engine, view, block = _stake_fixture(parent_balances={OUTSIDER: 5})
    with patch("tau_manager.tau_ready", _ready()), \
         patch("tau_manager.communicate_with_tau_multi", return_value={6: "1", 7: "0"}):
        assert engine.verify_block_header(view, block, {"proof_ok": True}) is False


def test_stake_mode_missing_o7_rejected():
    engine, view, block = _stake_fixture(parent_balances={OUTSIDER: 200000})
    with patch("tau_manager.tau_ready", _ready()), \
         patch("tau_manager.communicate_with_tau_multi", return_value={6: "1"}):
        assert engine.verify_block_header(view, block, {"proof_ok": True}) is False


def test_stake_mode_missing_parent_balances_rejected():
    engine, view, block = _stake_fixture(parent_balances=None)
    multi = Mock(return_value={6: "1", 7: "1"})
    with patch("tau_manager.tau_ready", _ready()), \
         patch("tau_manager.communicate_with_tau_multi", multi):
        assert engine.verify_block_header(view, block, {"proof_ok": True}) is False
    multi.assert_not_called()


def test_stake_mode_feeds_stake_and_flag():
    engine, view, block = _stake_fixture(parent_balances={OUTSIDER: 200000})
    multi = Mock(return_value={6: "1", 7: "1"})
    with patch("tau_manager.tau_ready", _ready()), \
         patch("tau_manager.communicate_with_tau_multi", multi):
        assert engine.verify_block_header(view, block, {"proof_ok": True}) is True
    streams = multi.call_args.kwargs["input_stream_values"]
    assert streams[14] == "200000"
    assert streams[15] == "1"


def test_validator_mode_uses_single_target_and_flag_zero():
    """validator_set-mode verify goes through the single-target
    communicate_with_tau (o6 only), never the multi path, and feeds i15 == '0'."""
    active_view = ActiveConsensusView(
        target_height=5,
        consensus_rules="always (o6[t]:bv[64] = i10[t]:bv[64]).",
        active_validators=[bytes.fromhex(VALIDATOR)],
        mechanism_specific_metadata={"poa": True, "eligibility_mode": "validator_set"},
        parent_balances={VALIDATOR: 200000},
    )
    block = Block.create(
        block_number=5, previous_hash="00" * 32, transactions=[],
        proposer_pubkey=VALIDATOR, timestamp=1234567890,
    )
    block.consensus_proof = {"signature": "00" * 48}
    single = Mock(return_value="1")
    multi = Mock(return_value={6: "1", 7: "1"})
    with patch("tau_manager.tau_ready", _ready()), \
         patch("tau_manager.communicate_with_tau", single), \
         patch("tau_manager.communicate_with_tau_multi", multi):
        assert TauConsensusEngine().verify_block_header(active_view, block, {"proof_ok": True}) is True
    multi.assert_not_called()
    assert single.call_args.kwargs["input_stream_values"][15] == "0"


# --- derive_active_consensus ------------------------------------------------

def test_derive_active_consensus_stake_mode():
    lm = ConsensusLifecycleManager(active_validators=[VALIDATOR])
    lm.eligibility_mode = "stake"
    balances = {VALIDATOR: 200000}
    snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": balances,
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
        },
    )
    view = TauConsensusEngine().derive_active_consensus(snapshot, 9)
    assert view.mechanism_specific_metadata["eligibility_mode"] == "stake"
    assert view.mechanism_specific_metadata["poa"] is False
    assert view.parent_balances is balances


def test_derive_active_consensus_no_lifecycle_manager_defaults_validator_set():
    snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {},
            "active_validators": [VALIDATOR],
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
        },
    )
    view = TauConsensusEngine().derive_active_consensus(snapshot, 9)
    assert view.mechanism_specific_metadata["eligibility_mode"] == "validator_set"
    assert view.mechanism_specific_metadata["poa"] is True


# --- get_committed_balance --------------------------------------------------

def test_get_committed_balance_no_faucet(monkeypatch):
    import config
    import chain_state
    with chain_state._balance_lock:
        chain_state._balances.clear()
        chain_state._balances["known"] = 42
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", True, raising=False)
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000, raising=False)
    # Unknown address returns 0 (NOT the faucet amount get_balance would mint).
    assert chain_state.get_committed_balance("missing") == 0
    assert chain_state.get_balance("missing") == 100000
    assert chain_state.get_committed_balance("known") == 42


# --- Real-engine end-to-end (native tau) -------------------------------------

def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


_REAL_ENGINE_CHILD = r'''
import json, os, sys, tempfile
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import config; config.set_database_path(os.environ["SPIKE_DB"])
import db; db.init_db()
import tau_native, tau_manager
from consensus.engine import TauConsensusEngine, ActiveConsensusView
from block import Block

ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
GENESIS_GUARDED = "always ( o6[t]:bv[16] = i10[t]:bv[16] && ( i15[t]:bv[16] != { 0 }:bv[16] || o7[t]:bv[16] = { 1 }:bv[16] ) )"
STAKE = ("always ( o6[t]:bv[16] = i10[t]:bv[16] && "
         "( ( i15[t]:bv[16] = { 0 }:bv[16] && o7[t]:bv[16] = { 1 }:bv[16] ) || "
         "( i15[t]:bv[16] != { 0 }:bv[16] && "
         "( ( { 100000 }:bv[64] <= i14[t]:bv[64] && o7[t]:bv[16] = { 1 }:bv[16] ) || "
         "( { 100000 }:bv[64] >  i14[t]:bv[64] && o7[t]:bv[16] = { 0 }:bv[16] ) ) ) ) )")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(ROUTER + "\n"); boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()
tau_manager.tau_direct_interface.communicate(rule_text=GENESIS_GUARDED, target_output_stream_index=0)
tau_manager.tau_direct_interface.communicate(rule_text=STAKE, target_output_stream_index=0)

OUT = "b" * 96
def verify(bal):
    view = ActiveConsensusView(
        target_height=5, consensus_rules=STAKE,
        active_validators=[bytes.fromhex("a" * 96)],
        mechanism_specific_metadata={"poa": False, "eligibility_mode": "stake"},
        parent_balances={OUT: bal},
    )
    blk = Block.create(block_number=5, previous_hash="00" * 32, transactions=[],
                       proposer_pubkey=OUT, timestamp=1234567890)
    blk.consensus_proof = {"signature": "00" * 48}
    return TauConsensusEngine().verify_block_header(view, blk, {"proof_ok": True})

print("P3_RESULT " + json.dumps({"rich": verify(200000), "poor": verify(5)}))
sys.stdout.flush()
os._exit(0)  # skip native teardown segfault (result already emitted)
'''


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_stake_mode_verify_real_engine(tmp_path):
    """End-to-end on the REAL interpreter: verify_block_header drives the native
    engine through the composed genesis-guarded + stake rules. A rich outsider
    (stake 200000 >= 100000) verifies True; a poor one (5) verifies False —
    proving i14/i15 are fed and o6&o7 are both consulted. Runs in a subprocess
    (native per-stream width typing is process-global; teardown segfaults)."""
    script = tmp_path / "p3_real_engine.py"
    script.write_text(_REAL_ENGINE_CHILD)
    env = dict(os.environ)
    env["SPIKE_DB"] = str(tmp_path / "p3_real_engine.db")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)],
                          capture_output=True, text=True, env=env, timeout=180)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("P3_RESULT ")), None)
    assert line is not None, f"no result\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    r = json.loads(line[len("P3_RESULT "):])
    assert r["rich"] is True, f"rich outsider should verify: {r}"
    assert r["poor"] is False, f"poor outsider should be rejected: {r}"
