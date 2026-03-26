import pytest
import os
from unittest.mock import patch, MagicMock

from errors import ConfigurationError
import config
import db
from poa.engine import PoATauEngine
from block import BlockHeader
from commands.createblock import create_block_from_mempool
from miner.service import SoleMiner

# Valid 96-char hex strings
KEY_0 = "a1" + "00" * 47
KEY_1 = "a1" + "01" * 47
KEY_2 = "a1" + "02" * 47

def test_config_duplicate_pubkeys():
    with pytest.raises(ConfigurationError, match="duplicates"):
        config.load_settings(overrides={
            "authority": {"miner_pubkeys": [KEY_0, KEY_0], "miner_pubkey": KEY_0, "miner_pubkey_path": None}
        })

def test_config_missing_local_miner():
    with pytest.raises(ConfigurationError, match="is not in the validator schedule"):
        config.load_settings(overrides={
            "authority": {"miner_pubkeys": [KEY_0, KEY_1], "miner_pubkey": KEY_2, "miner_pubkey_path": None}
        })

def test_config_single_miner_fallback():
    settings = config.load_settings(overrides={
        "authority": {"miner_pubkeys": [], "miner_pubkey": KEY_0, "miner_pubkey_path": None}
    })
    # the fallback populates miner_pubkeys with [miner_pubkey]
    assert settings.authority.miner_pubkeys == [KEY_0]

def test_poa_engine_round_robin_verification():
    # Setup 3 validators
    config.MINER_PUBKEYS = [KEY_0, KEY_1, KEY_2]
    config.MINER_PUBKEY = KEY_0
    engine = PoATauEngine()
    
    # Block 0 should be from KEY_0
    class MockBlock:
        def __init__(self, block_number):
            self.header = BlockHeader(block_number=block_number, previous_hash="0"*64, timestamp=1, merkle_root="0"*64)
            self.block_signature = "sig"
            self.verified_against = None
            
        def verify_signature(self, miner_pubkey):
            self.verified_against = miner_pubkey
            # Return true only if it checks against the expected key
            return True
            
    b0 = MockBlock(0)
    assert engine.verify_block(b0) is True
    assert b0.verified_against == KEY_0
    
    b1 = MockBlock(1)
    assert engine.verify_block(b1) is True
    assert b1.verified_against == KEY_1
    
    b2 = MockBlock(2)
    assert engine.verify_block(b2) is True
    assert b2.verified_against == KEY_2
    
    b3 = MockBlock(3)
    assert engine.verify_block(b3) is True
    assert b3.verified_against == KEY_0

@patch("db.get_canonical_head_block")
@patch("db.reserve_mempool_txs")
def test_createblock_wrong_turn_abort(mock_reserve, mock_head):
    # Setup config
    config.MINER_PUBKEYS = [KEY_0, KEY_1]
    config.MINER_PUBKEY = KEY_1 # Local is Miner 1
    
    # Latest block is none -> next block is 0. Expected miner is KEY_0
    mock_head.return_value = None
    
    with patch("block.bls_signing_available", return_value=True):
        res = create_block_from_mempool()
        assert "Not our turn" in res.get("message", "")
        assert mock_reserve.called is False # Did not reserve!
        
        # Latest block is 0 -> next block is 1. Expected miner is KEY_1
        mock_head.return_value = {"header": {"block_number": 0}, "block_hash": "0"*64}
        
        # It should pass the turn check and proceed to reservation
        res = create_block_from_mempool()
        # It will reach reserving and probably return "Mempool is empty"
        assert mock_reserve.called is True

@patch("db.get_canonical_head_block")
def test_miner_service_should_mine_turn(mock_head):
    config.MINER_PUBKEYS = [KEY_0, KEY_1]
    config.MINER_PUBKEY = KEY_1
    
    with patch("config.MINER_PRIVKEY", "dummy"): # To pass init check
        miner = SoleMiner()
        # Mock time and txs to otherwise pass checks
        miner._last_mine_time = 0
        with patch("db.count_mempool_txs", return_value=10):
            # Next is 0 (KEY_0). Our is KEY_1
            mock_head.return_value = None
            assert miner._should_mine() is False
            
            # Next is 1 (KEY_1).
            mock_head.return_value = {"header": {"block_number": 0}, "block_hash": "0"*64}
            assert miner._should_mine() is True
