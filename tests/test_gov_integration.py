import json
import time
import pytest
import os
import sys
import importlib
from unittest.mock import Mock, patch
from py_ecc.bls import G2Basic as bls
import hashlib

# Add project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
from commands import sendtx
import chain_state, db

def setup_module(module):
    test_db = "test_gov_db.sqlite"
    config.set_database_path(test_db)
    if db._db_conn:
        db._db_conn.close(); db._db_conn = None
    if os.path.exists(test_db):
        os.remove(test_db)
        
    chain_state._balances.clear(); chain_state._sequence_numbers.clear()
    db.init_db()
    try:
        chain_state.load_genesis("data/genesis.json")
        if hasattr(chain_state, "_lifecycle_manager"):
            chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY}
    except Exception:
        pass
    db.clear_mempool()
    sendtx._PY_ECC_AVAILABLE = True
    
def teardown_module(module):
    if db._db_conn:
        db._db_conn.close(); db._db_conn = None
    if os.path.exists("test_gov_db.sqlite"):
        os.remove("test_gov_db.sqlite")

def test_gov_update_acceptance():
    # Clear mempool before test
    db.clear_mempool()
    
    # Use the active network validator identity
    sk = int(config.MINER_PRIVKEY, 16)
    pk_hex = config.MINER_PUBKEY
    
    # Create the payload (must match wallet's buildConsensusRuleUpdateTx logic)
    payload = {
        "tx_type": "consensus_rule_update",
        "sender_pubkey": pk_hex,
        "sequence_number": 0,
        "expiration_time": int(time.time()) + 600,
        "fee_limit": "0",
        "rule_revisions": ["always."],
        "activate_at_height": 100,
        "host_contract_patch": {
            "proof_scheme": "bls_header_sig",
            "fork_choice_scheme": "height_then_hash",
            "input_contract_version": 1
        }
    }
        
    # This exactly mimics wallet's canonicalize()
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    msg_hash = hashlib.sha256(canonical.encode("utf-8")).digest()
    sig = bls.Sign(sk, msg_hash)
    
    payload["signature"] = sig.hex()
    
    # Submit via sendtx handler
    cmd = f"sendtx {json.dumps(payload)}"
    response = sendtx.execute(cmd, None)
    parsed = json.loads(response)
    assert parsed["status"] == "ok", f"sendtx failed: {response}"
    assert parsed["command"] == "sendtx"
    assert "tx_hash" in parsed["data"]

    # Verify it entered the mempool
    mempool_txs = db.get_mempool_txs()
    assert len(mempool_txs) == 1
    tx1 = json.loads(mempool_txs[0])
    assert tx1["tx_type"] == "consensus_rule_update"

def test_gov_vote_acceptance():
    db.clear_mempool()
    
    sk = int(config.MINER_PRIVKEY, 16)
    pk_hex = config.MINER_PUBKEY
    
    payload = {
        "tx_type": "consensus_rule_vote",
        "sender_pubkey": pk_hex,
        "sequence_number": 0,
        "expiration_time": int(time.time()) + 600,
        "fee_limit": "0",
        "update_id": "a" * 64,
        "approve": True
    }
        
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    msg_hash = hashlib.sha256(canonical.encode("utf-8")).digest()
    sig = bls.Sign(sk, msg_hash)
    
    payload["signature"] = sig.hex()
    
    with patch('consensus.facade.TipAdmissionView.get_update_lifecycle_state', return_value="pending"):
        with patch('consensus.facade.TipAdmissionView.has_duplicate_vote', return_value=False):
            cmd = f"sendtx {json.dumps(payload)}"
            response = sendtx.execute(cmd, None)
            parsed = json.loads(response)
            assert parsed["status"] == "ok", f"sendtx failed: {response}"

    mempool_txs = db.get_mempool_txs()
    assert len(mempool_txs) == 1
    tx1 = json.loads(mempool_txs[0])
    assert tx1["tx_type"] == "consensus_rule_vote"

def test_gov_update_reject_approve_false():
    db.clear_mempool()
    sk = int(config.MINER_PRIVKEY, 16)
    pk_hex = config.MINER_PUBKEY
    
    payload = {
        "tx_type": "consensus_rule_vote",
        "sender_pubkey": pk_hex,
        "sequence_number": 0,
        "expiration_time": int(time.time()) + 600,
        "fee_limit": "0",
        "update_id": "a" * 64,
        "approve": False
    }
        
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    msg_hash = hashlib.sha256(canonical.encode("utf-8")).digest()
    sig = bls.Sign(sk, msg_hash)
    
    payload["signature"] = sig.hex()
    
    cmd = f"sendtx {json.dumps(payload)}"
    response = sendtx.execute(cmd, None)
    parsed = json.loads(response)
    assert parsed["status"] == "error", f"expected error envelope, got {response}"
    assert "approve=false is unsupported" in parsed["error"]["message"]


def test_apply_block_routes_activation_revisions_through_i0():
    """
    End-to-end activation regression. When `engine.apply_block` reaches a
    block height that activates a scheduled consensus_rule_update, every
    revision must be sent to Tau via `i0` (matching user_tx ops['0']
    semantics) and the resulting `next_snapshot.metadata` must:

      - record `consensus_rules_state == "\\n".join(rule_revisions)` (the
        deterministic provenance tag, not the buggy literal `"\\\\n"`);
      - produce a `state_hash` that matches a fresh recomputation against
        the same string. Validators replaying the block independently
        derive the identical hash without consulting the live interpreter.
    """
    from unittest.mock import patch as _patch
    from consensus.engine import TauConsensusEngine, ActiveConsensusView
    from consensus.governance import (
        ConsensusLifecycleManager,
        ConsensusRuleUpdate,
        ConsensusRuleVote,
    )
    from consensus.state import (
        TauStateSnapshot,
        compute_consensus_meta_hash,
        compute_consensus_state_hash,
    )
    from chain_state import compute_accounts_hash
    from block import Block

    validator_hex = "a" * 96
    voter_bytes = bytes.fromhex(validator_hex)

    revisions = [
        "always ( o6[t]:bv[16] = { 0 }:bv[16] ).",
        "always ( o7[t]:bv[16] = { 1 }:bv[16] ).",
    ]
    activate_at = 7

    update = ConsensusRuleUpdate(
        rule_revisions=revisions,
        activate_at_height=activate_at,
    )

    lm = ConsensusLifecycleManager(active_validators=[validator_hex])
    assert lm.submit_update(update)
    # One validator, threshold == 1, vote promotes to scheduled.
    lm.submit_vote(ConsensusRuleVote(update_id=update.update_id, approve=True), voter_bytes)
    assert any(uid == update.update_id for _, uid in lm.scheduled_updates)

    parent_app_rules = b"always (o0[t]=1)."
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=parent_app_rules,
        metadata={
            "balances": {},
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
            "active_consensus_id": "",
        },
    )

    active_view = ActiveConsensusView(
        target_height=activate_at,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[voter_bytes],
        mechanism_specific_metadata={"poa": True},
    )

    block_obj = Block.create(
        block_number=activate_at,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=validator_hex,
        timestamp=1234567890,
    )

    captured_calls = []

    def _fake_communicate_with_tau(**kwargs):
        captured_calls.append(kwargs)
        return "T"

    engine = TauConsensusEngine()

    with _patch("tau_manager.communicate_with_tau", side_effect=_fake_communicate_with_tau):
        result = engine.apply_block(active_view, block_obj, parent_snapshot)

    rule_text_calls = [c for c in captured_calls if c.get("rule_text") is not None]
    assert [c["rule_text"] for c in rule_text_calls] == revisions
    for call in rule_text_calls:
        assert call.get("target_output_stream_index") == 0
        # Activation revisions must NOT trigger the rules-handler — consensus
        # provenance is updated via the snapshot commit, not via the live
        # spec extracted from stdout. (See `engine.apply_block`.)
        assert call.get("apply_rules_update") is False
        assert str(call.get("source", "")).startswith("governance_activation:")

    next_snapshot = result.next_snapshot
    assert next_snapshot.metadata["consensus_rules_state"] == "\n".join(revisions)
    assert next_snapshot.metadata["active_consensus_id"] == update.update_id_hex[:16]

    # Recompute the state hash from the deterministic strings and confirm.
    # apply_block deep-copies the lifecycle manager and runs height transitions
    # on the copy, so use the post-activation lifecycle manager attached to
    # the returned snapshot for the meta-hash recomputation.
    post_lm = next_snapshot.metadata["lifecycle_manager"]
    # Recompute via the same centralized method the engine uses, so the test
    # also guards that the runtime hash binds the resolved quorum policy.
    expected_meta_hash = post_lm.consensus_meta_hash()
    expected_acc_hash = compute_accounts_hash({}, {})
    expected_state_hash = compute_consensus_state_hash(
        ("\n".join(revisions)).encode("utf-8"),
        next_snapshot.tau_bytes,
        expected_acc_hash,
        expected_meta_hash,
    )
    assert next_snapshot.state_hash == expected_state_hash


def test_apply_block_activates_multiple_updates_in_uid_order():
    """
    Determinism regression: when two updates share an `activate_at_height`,
    `ConsensusLifecycleManager.process_height_transitions` must surface them
    in `(height, update_id_bytes)` ascending order. `engine.apply_block` then
    emits each update's revisions through `i0` in that order, and the
    deterministic provenance recorded in the snapshot is the LAST activated
    update's joined revisions.

    A refactor that switched `scheduled_updates` to a dict/set or dropped the
    sort would silently make replay non-deterministic; this test pins the
    ordering down.
    """
    from unittest.mock import patch as _patch
    from consensus.engine import TauConsensusEngine, ActiveConsensusView
    from consensus.governance import (
        ConsensusLifecycleManager,
        ConsensusRuleUpdate,
        ConsensusRuleVote,
    )
    from consensus.state import TauStateSnapshot
    from block import Block

    validator_hex = "a" * 96
    voter_bytes = bytes.fromhex(validator_hex)

    # Two updates at the same height, distinguished only by their
    # rule_revisions content (which feeds into update_id via canonical hash).
    revisions_x = ["always ( o6[t]:bv[16] = { 0 }:bv[16] )."]
    revisions_y = ["always ( o7[t]:bv[16] = { 1 }:bv[16] )."]
    activate_at = 11

    update_x = ConsensusRuleUpdate(
        rule_revisions=revisions_x,
        activate_at_height=activate_at,
    )
    update_y = ConsensusRuleUpdate(
        rule_revisions=revisions_y,
        activate_at_height=activate_at,
    )

    # Identify the lexicographically smaller and larger updates by uid bytes.
    if update_x.update_id < update_y.update_id:
        first, second = update_x, update_y
        first_revs, second_revs = revisions_x, revisions_y
    else:
        first, second = update_y, update_x
        first_revs, second_revs = revisions_y, revisions_x

    lm = ConsensusLifecycleManager(active_validators=[validator_hex])
    assert lm.submit_update(update_x)
    assert lm.submit_update(update_y)
    lm.submit_vote(ConsensusRuleVote(update_id=update_x.update_id, approve=True), voter_bytes)
    lm.submit_vote(ConsensusRuleVote(update_id=update_y.update_id, approve=True), voter_bytes)

    # Both must be scheduled at the same height.
    scheduled_uids = [uid for h, uid in lm.scheduled_updates if h == activate_at]
    assert update_x.update_id in scheduled_uids
    assert update_y.update_id in scheduled_uids

    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {},
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
            "active_consensus_id": "",
        },
    )

    active_view = ActiveConsensusView(
        target_height=activate_at,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[voter_bytes],
        mechanism_specific_metadata={"poa": True},
    )

    block_obj = Block.create(
        block_number=activate_at,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=validator_hex,
        timestamp=1234567890,
    )

    captured_calls = []

    def _fake_communicate_with_tau(**kwargs):
        captured_calls.append(kwargs)
        return "T"

    engine = TauConsensusEngine()
    with _patch("tau_manager.communicate_with_tau", side_effect=_fake_communicate_with_tau):
        result = engine.apply_block(active_view, block_obj, parent_snapshot)

    # i0 calls in declaration order, with the smaller-uid update activating first.
    rule_text_calls = [c for c in captured_calls if c.get("rule_text") is not None]
    assert [c["rule_text"] for c in rule_text_calls] == list(first_revs) + list(second_revs)

    # Provenance: the LAST activated update wins (matches `last_update = newly_active[-1]`).
    next_snapshot = result.next_snapshot
    assert next_snapshot.metadata["consensus_rules_state"] == "\n".join(second_revs)
    assert next_snapshot.metadata["active_consensus_id"] == second.update_id_hex[:16]


def test_apply_block_raises_fee_rule_error_on_activation_failure():
    """
    Test that if communicate_with_tau raises TauCommunicationError (or TauEngineBug)
    during governance activation inside apply_block, FeeRuleError is raised.
    """
    from unittest.mock import patch as _patch
    from consensus.engine import TauConsensusEngine, ActiveConsensusView
    from consensus.governance import (
        ConsensusLifecycleManager,
        ConsensusRuleUpdate,
        ConsensusRuleVote,
    )
    from consensus.state import TauStateSnapshot
    from block import Block
    from errors import TauCommunicationError
    from consensus.fees import FeeRuleError

    validator_hex = "a" * 96
    voter_bytes = bytes.fromhex(validator_hex)

    revisions = [
        "always ( o6[t]:bv[16] = { 0 }:bv[16] ).",
    ]
    activate_at = 7

    update = ConsensusRuleUpdate(
        rule_revisions=revisions,
        activate_at_height=activate_at,
    )

    lm = ConsensusLifecycleManager(active_validators=[validator_hex])
    assert lm.submit_update(update)
    lm.submit_vote(ConsensusRuleVote(update_id=update.update_id, approve=True), voter_bytes)

    parent_app_rules = b"always (o0[t]=1)."
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=parent_app_rules,
        metadata={
            "balances": {},
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
            "active_consensus_id": "",
        },
    )

    active_view = ActiveConsensusView(
        target_height=activate_at,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[voter_bytes],
        mechanism_specific_metadata={"poa": True},
    )

    block_obj = Block.create(
        block_number=activate_at,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=validator_hex,
        timestamp=1234567890,
    )

    def _broken_communicate_with_tau(**kwargs):
        raise TauCommunicationError("Tau connection lost")

    engine = TauConsensusEngine()

    with _patch("tau_manager.communicate_with_tau", side_effect=_broken_communicate_with_tau):
        with pytest.raises(FeeRuleError) as excinfo:
            engine.apply_block(active_view, block_obj, parent_snapshot)

    assert "Governance rule activation rejected" in str(excinfo.value)
    assert "Tau connection lost" in str(excinfo.value)


def test_apply_block_raises_fee_rule_error_on_rejection_string():
    """
    Test that if communicate_with_tau returns a string containing "error" (except x1001)
    during governance activation inside apply_block, FeeRuleError is raised.
    """
    from unittest.mock import patch as _patch
    from consensus.engine import TauConsensusEngine, ActiveConsensusView
    from consensus.governance import (
        ConsensusLifecycleManager,
        ConsensusRuleUpdate,
        ConsensusRuleVote,
    )
    from consensus.state import TauStateSnapshot
    from block import Block
    from consensus.fees import FeeRuleError

    validator_hex = "a" * 96
    voter_bytes = bytes.fromhex(validator_hex)

    revisions = [
        "always ( o6[t]:bv[16] = { 0 }:bv[16] ).",
    ]
    activate_at = 7

    update = ConsensusRuleUpdate(
        rule_revisions=revisions,
        activate_at_height=activate_at,
    )

    lm = ConsensusLifecycleManager(active_validators=[validator_hex])
    assert lm.submit_update(update)
    lm.submit_vote(ConsensusRuleVote(update_id=update.update_id, approve=True), voter_bytes)

    parent_app_rules = b"always (o0[t]=1)."
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=parent_app_rules,
        metadata={
            "balances": {},
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
            "active_consensus_id": "",
        },
    )

    active_view = ActiveConsensusView(
        target_height=activate_at,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[voter_bytes],
        mechanism_specific_metadata={"poa": True},
    )

    block_obj = Block.create(
        block_number=activate_at,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=validator_hex,
        timestamp=1234567890,
    )

    def _reject_communicate_with_tau(**kwargs):
        return "Parsing Error: Invalid symbol inside rule"

    engine = TauConsensusEngine()

    with _patch("tau_manager.communicate_with_tau", side_effect=_reject_communicate_with_tau):
        with pytest.raises(FeeRuleError) as excinfo:
            engine.apply_block(active_view, block_obj, parent_snapshot)

    assert "Governance rule activation revision rejected by live Tau interpreter" in str(excinfo.value)
    assert "Parsing Error" in str(excinfo.value)


def test_apply_block_raises_fee_rule_error_on_engine_crash():
    """
    Test that if communicate_with_tau raises TauEngineCrash during governance
    activation inside apply_block, FeeRuleError is raised.
    """
    from unittest.mock import patch as _patch
    from consensus.engine import TauConsensusEngine, ActiveConsensusView
    from consensus.governance import (
        ConsensusLifecycleManager,
        ConsensusRuleUpdate,
        ConsensusRuleVote,
    )
    from consensus.state import TauStateSnapshot
    from block import Block
    from errors import TauEngineCrash
    from consensus.fees import FeeRuleError

    validator_hex = "a" * 96
    voter_bytes = bytes.fromhex(validator_hex)

    revisions = [
        "always ( o6[t]:bv[16] = { 0 }:bv[16] ).",
    ]
    activate_at = 7

    update = ConsensusRuleUpdate(
        rule_revisions=revisions,
        activate_at_height=activate_at,
    )

    lm = ConsensusLifecycleManager(active_validators=[validator_hex])
    assert lm.submit_update(update)
    lm.submit_vote(ConsensusRuleVote(update_id=update.update_id, approve=True), voter_bytes)

    parent_app_rules = b"always (o0[t]=1)."
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=parent_app_rules,
        metadata={
            "balances": {},
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
            "active_consensus_id": "",
        },
    )

    active_view = ActiveConsensusView(
        target_height=activate_at,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[voter_bytes],
        mechanism_specific_metadata={"poa": True},
    )

    block_obj = Block.create(
        block_number=activate_at,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=validator_hex,
        timestamp=1234567890,
    )

    def _crash_communicate_with_tau(**kwargs):
        raise TauEngineCrash("Tau process closed unexpectedly")

    engine = TauConsensusEngine()

    with _patch("tau_manager.communicate_with_tau", side_effect=_crash_communicate_with_tau):
        with pytest.raises(FeeRuleError) as excinfo:
            engine.apply_block(active_view, block_obj, parent_snapshot)

    assert "Governance rule activation rejected" in str(excinfo.value)
    assert "Tau process closed unexpectedly" in str(excinfo.value)


def test_rebuild_state_aborts_on_fee_rule_error():
    """
    Test that chain state rebuild aborts cleanly (returns) when FeeRuleError is raised.
    """
    from unittest.mock import patch as _patch
    from chain_state import rebuild_state_from_blockchain
    from consensus.fees import FeeRuleError
    from block import BlockHeader, sha256_hex

    hdr = BlockHeader(
        block_number=1,
        previous_hash="0" * 64,
        timestamp=100,
        merkle_root="0" * 64,
        state_hash="0" * 64,
        proposer_pubkey="a" * 96
    )
    correct_hash = sha256_hex(hdr.canonical_bytes())

    mock_block_data = {
        "header": {
            "block_number": 1,
            "previous_hash": "0" * 64,
            "timestamp": 100,
            "merkle_root": "0" * 64,
            "state_hash": "0" * 64,
            "proposer_pubkey": "a" * 96
        },
        "transactions": [],
        "consensus_proof": {},
        "block_hash": correct_hash
    }

    with _patch("db.get_canonical_blocks_at_or_after_height", return_value=[mock_block_data]):
        with _patch("consensus.engine.TauConsensusEngine.apply_block", side_effect=FeeRuleError("mock error")):
            # This should catch FeeRuleError and return cleanly without raising.
            rebuild_state_from_blockchain(start_block=1)




# --- W1 on-chain validator set: proposer membership gate + quorum roundtrip ---
def _w1_fixture(active_validator_hexes, proposer_hex, block_number=5):
    from consensus.engine import TauConsensusEngine, ActiveConsensusView
    from consensus.governance import ConsensusLifecycleManager
    from consensus.state import TauStateSnapshot
    from block import Block

    lm = ConsensusLifecycleManager(active_validators=list(active_validator_hexes))
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {},
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[64] = i10[t]:bv[64]).",
            "active_consensus_id": "",
        },
    )
    active_view = ActiveConsensusView(
        target_height=block_number,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(v) for v in active_validator_hexes],
        mechanism_specific_metadata={"poa": True},
    )
    block_obj = Block.create(
        block_number=block_number,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=proposer_hex,
        timestamp=1234567890,
    )
    return TauConsensusEngine(), lm, parent_snapshot, active_view, block_obj


def test_removed_validator_block_rejected():
    """A block proposed by a key outside the active validator set must fail
    header verification — before any Tau interaction."""
    validator_hex = "a" * 96
    outsider_hex = "b" * 96
    engine, _, _, active_view, block_obj = _w1_fixture([validator_hex], outsider_hex)
    assert engine.verify_block_header(active_view, block_obj, {"proof_ok": True}) is False


def test_in_set_proposer_passes_membership_gate():
    """Positive twin: an in-set proposer clears the membership gate and reaches
    the Tau verdict, which we mock to accept."""
    validator_hex = "a" * 96
    engine, _, _, active_view, block_obj = _w1_fixture([validator_hex], validator_hex)
    block_obj.consensus_proof = {"signature": "00" * 48}

    ready = Mock()
    ready.is_set.return_value = True
    with patch("tau_manager.tau_ready", ready), \
         patch("tau_manager.communicate_with_tau", return_value="1"), \
         patch("tau_manager.parse_tau_output", return_value=1):
        assert engine.verify_block_header(active_view, block_obj, {"proof_ok": True}) is True


def test_genesis_block_skips_membership_gate():
    """Block #0 has the all-zero sentinel proposer and must not be rejected."""
    validator_hex = "a" * 96
    engine, _, _, active_view, block_obj = _w1_fixture([validator_hex], "0" * 96, block_number=0)
    block_obj.consensus_proof = {"signature": "00" * 48}

    ready = Mock()
    ready.is_set.return_value = True
    with patch("tau_manager.tau_ready", ready), \
         patch("tau_manager.communicate_with_tau", return_value="1"), \
         patch("tau_manager.parse_tau_output", return_value=1):
        assert engine.verify_block_header(active_view, block_obj, {"proof_ok": True}) is True


def test_forged_vote_in_block_is_noop():
    """A vote tx from a non-validator inside a block must not hard-reject the
    block and must not advance the tally."""
    from consensus.governance import ConsensusRuleUpdate

    validator_hex = "a" * 96
    outsider_hex = "b" * 96
    engine, lm, parent_snapshot, active_view, _ = _w1_fixture([validator_hex], validator_hex)

    update = ConsensusRuleUpdate(["always ( o6[t]:bv[16] = { 0 }:bv[16] )."], 100)
    assert lm.submit_update(update)

    from block import Block
    vote_tx = {
        "tx_type": "consensus_rule_vote",
        "sender_pubkey": outsider_hex,
        "update_id": update.update_id.hex(),
        "approve": True,
    }
    block_obj = Block.create(
        block_number=5,
        previous_hash="00" * 32,
        transactions=[vote_tx],
        proposer_pubkey=validator_hex,
        timestamp=1234567890,
    )

    with patch("tau_manager.communicate_with_tau", return_value="T"):
        result = engine.apply_block(active_view, block_obj, parent_snapshot)

    post_lm = result.next_snapshot.metadata["lifecycle_manager"]
    assert len(post_lm.votes.get(update.update_id, set())) == 0
    assert update.update_id in post_lm.pending_updates
    # The tx itself is included (soft no-op), never a hard reject.
    assert not result.invalid_tx_ids if hasattr(result, "invalid_tx_ids") else True


def test_three_validator_roundtrip():
    """Add a 4th validator via quorum, then remove the original proposer; the
    removed key must fail header verification against the new set."""
    from consensus.governance import (
        ConsensusLifecycleManager,
        ConsensusRuleUpdate,
        ConsensusRuleVote,
    )
    from consensus.engine import TauConsensusEngine, ActiveConsensusView
    from block import Block

    v = [f"{i:096x}" for i in range(1, 4)]  # 3 validators, threshold 2
    lm = ConsensusLifecycleManager(active_validators=v)
    assert lm.approval_threshold == 2

    # Round 1: add v4.
    v4 = f"{4:096x}"
    add = ConsensusRuleUpdate(["test-add"], 10, {"validator_additions": [v4]})
    lm.submit_update(add)
    vote = ConsensusRuleVote(add.update_id, True)
    lm.submit_vote(vote, v[0])
    lm.submit_vote(vote, v[1])
    assert len(lm.process_height_transitions(10)) == 1
    assert v4 in lm.active_validators
    assert lm.approval_threshold == 3  # n=4 supermajority

    # Round 2: remove v1 (needs 3 of 4 votes).
    rm = ConsensusRuleUpdate(["test-rm"], 20, {"validator_removals": [v[0]]})
    lm.submit_update(rm)
    rm_vote = ConsensusRuleVote(rm.update_id, True)
    lm.submit_vote(rm_vote, v[1])
    lm.submit_vote(rm_vote, v[2])
    lm.submit_vote(rm_vote, v4)
    assert len(lm.process_height_transitions(20)) == 1
    assert v[0] not in lm.active_validators

    # The removed validator's block now fails verification.
    engine = TauConsensusEngine()
    view = ActiveConsensusView(
        target_height=21,
        consensus_rules="always (o6[t]:bv[64] = i10[t]:bv[64]).",
        active_validators=[bytes.fromhex(x) for x in lm.active_validators],
        mechanism_specific_metadata={"poa": True},
    )
    bad_block = Block.create(
        block_number=21,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=v[0],
        timestamp=1234567890,
    )
    assert engine.verify_block_header(view, bad_block, {"proof_ok": True}) is False
