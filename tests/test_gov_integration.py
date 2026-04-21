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
    assert response.startswith("SUCCESS:")
    
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
            assert response.startswith("SUCCESS:")
    
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
    assert response.startswith("FAILURE:")
    assert "approve=false is unsupported" in response
