import json

import pytest

import config
import db
from miner import SoleMiner
from poa import mempool as mempool_utils


def test_mempool_reconcile_with_block(temp_database):
    tx_payload = {"sender_pubkey": config.MINER_PUBKEY, "sequence_number": 0}
    db.add_mempool_tx(json.dumps(tx_payload), "tx_hash_a", 1000)
    stats = mempool_utils.reconcile_with_block({"transactions": [tx_payload]})
    assert stats["removed"] == 1
    assert stats["kept"] == 0


def test_sole_miner_mines_block_when_threshold_met(temp_database):
    # Fix: ensure MINER_PRIVKEY is set for SoleMiner and block creation
    original_privkey = config.MINER_PRIVKEY
    original_pubkey = config.MINER_PUBKEY
    config.MINER_PRIVKEY = "0" * 63 + "1"
    if not config.MINER_PUBKEY:
        config.MINER_PUBKEY = "0" * 96

    # Setup mocks for validation
    from commands import createblock
    original_validate = createblock._validate_signature
    createblock._validate_signature = lambda p: True
    createblock._BLS_AVAILABLE = True
    
    # Also mock tau_manager for createblock
    import tau_manager
    tau_manager.tau_ready.set()
    original_communicate = tau_manager.communicate_with_tau
    tau_manager.communicate_with_tau = lambda **kwargs: ""

    try:
        # Seed mempool with a valid-looking transaction
        sample_tx = {
            "sender_pubkey": config.MINER_PUBKEY or "0"*96,
            "sequence_number": 0,
            "expiration_time": 9999999999,
            "operations": {"1": []},
            "fee_limit": 1000,
            "signature": "00"*96,
        }
        db.add_mempool_tx(json.dumps(sample_tx), "tx_hash_b", 2000)

        # New SoleMiner only takes threshold/interval
        miner = SoleMiner(
            threshold=1,
            max_block_interval=1.0,
        )

        # Mimic mining behavior
        miner.try_mine()
        
        # Verify via DB side effects
        latest = db.get_latest_block()
        assert latest is not None
        assert latest["header"]["state_hash"]
        assert db.count_mempool_txs() == 0
        
    finally:
        # Cleanup mocks
        createblock._validate_signature = original_validate
        tau_manager.communicate_with_tau = original_communicate
        tau_manager.tau_ready.clear()
        
        # Restore config
        config.MINER_PRIVKEY = original_privkey
        config.MINER_PUBKEY = original_pubkey

