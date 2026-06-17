import unittest
import os
import sys
import tempfile
import time
from unittest.mock import patch

# Ensure project root is on sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
import chain_state
import db
from block import Block


class BlockTimestampTestBase(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(self.temp_db_fd)
        
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.temp_db_path)
        
        if hasattr(chain_state, '_balances'):
            chain_state._balances.clear()
        if hasattr(chain_state, '_sequence_numbers'):
            chain_state._sequence_numbers.clear()
            
        db._db_conn = None
        db.init_db()
        db.clear_mempool()
        chain_state.load_genesis("data/genesis.json")
        
        # Default mock verify_block_header to True to isolate timestamp tests from Tau/consensus rules
        self.verify_patch = patch('consensus.engine.TauConsensusEngine.verify_block_header', return_value=True)
        self.verify_patch.start()
        
        # Set TAU_FORCE_TEST=1 for test isolation
        self.os_env_patch = patch.dict("os.environ", {"TAU_FORCE_TEST": "1"})
        self.os_env_patch.start()
        
    def tearDown(self):
        self.verify_patch.stop()
        self.os_env_patch.stop()
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)
        config.set_database_path(self.original_db_path)


class TestBlockTimestampMonotonic(BlockTimestampTestBase):
    def test_block_timestamp_less_than_parent_rejected(self):
        # Retrieve genesis block
        genesis = db.get_canonical_head()
        genesis_hash = genesis['block_hash']
        
        # Create block #1 with timestamp 1000
        block1 = Block.create(
            block_number=1,
            previous_hash=genesis_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=1000
        )
        block1.header.state_hash = ""
        # Process block #1
        res1 = chain_state.process_new_block(block1)
        self.assertTrue(res1)
        
        # Create block #2 with timestamp 999 (less than parent timestamp 1000)
        block2 = Block.create(
            block_number=2,
            previous_hash=block1.block_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=999
        )
        block2.header.state_hash = ""
        # Process block #2: should be rejected
        res2 = chain_state.process_new_block(block2)
        self.assertFalse(res2)
        
        # Ingestion test:
        ingest_res = chain_state.ingest_block(block2)
        self.assertEqual(ingest_res.status, 'invalid')
        self.assertIn("Timestamp validation failed", ingest_res.message)

    def test_block_timestamp_equals_parent_accepted(self):
        genesis = db.get_canonical_head()
        genesis_hash = genesis['block_hash']
        
        block1 = Block.create(
            block_number=1,
            previous_hash=genesis_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=1000
        )
        block1.header.state_hash = ""
        res1 = chain_state.process_new_block(block1)
        self.assertTrue(res1)
        
        block2 = Block.create(
            block_number=2,
            previous_hash=block1.block_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=1000  # Equal to parent timestamp
        )
        block2.header.state_hash = ""
        res2 = chain_state.process_new_block(block2)
        self.assertTrue(res2)

    def test_block_timestamp_greater_than_parent_accepted(self):
        genesis = db.get_canonical_head()
        genesis_hash = genesis['block_hash']
        
        block1 = Block.create(
            block_number=1,
            previous_hash=genesis_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=1000
        )
        block1.header.state_hash = ""
        res1 = chain_state.process_new_block(block1)
        self.assertTrue(res1)
        
        block2 = Block.create(
            block_number=2,
            previous_hash=block1.block_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=1001  # Greater than parent timestamp
        )
        block2.header.state_hash = ""
        res2 = chain_state.process_new_block(block2)
        self.assertTrue(res2)


class TestBlockTimestampWallClockBounds(BlockTimestampTestBase):
    def test_block_timestamp_exceeds_future_drift_rejected(self):
        genesis = db.get_canonical_head()
        genesis_hash = genesis['block_hash']
        
        now = int(time.time())
        limit = config.MAX_BLOCK_FUTURE_DRIFT_SECONDS
        
        # Create block with timestamp now + limit + 10 (giving margin)
        block1 = Block.create(
            block_number=1,
            previous_hash=genesis_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=now + limit + 10
        )
        block1.header.state_hash = ""
        res1 = chain_state.process_new_block(block1)
        self.assertFalse(res1)
        
        # Ingesting should also fail
        ingest_res = chain_state.ingest_block(block1)
        self.assertEqual(ingest_res.status, 'invalid')

    def test_block_timestamp_within_future_drift_accepted(self):
        genesis = db.get_canonical_head()
        genesis_hash = genesis['block_hash']
        
        now = int(time.time())
        limit = config.MAX_BLOCK_FUTURE_DRIFT_SECONDS
        
        # Create block with timestamp now + limit - 5 (giving margin inside limits)
        block1 = Block.create(
            block_number=1,
            previous_hash=genesis_hash,
            transactions=[],
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=now + limit - 5
        )
        block1.header.state_hash = ""
        res1 = chain_state.process_new_block(block1)
        self.assertTrue(res1)


class TestGenesisBlockTimestamp(BlockTimestampTestBase):
    def test_genesis_block_timestamp_zero_accepted(self):
        # Genesis block in tests normally has timestamp=0 (from data/genesis.json).
        # We verify that even if genesis has timestamp=0, it is accepted/loaded.
        genesis_block_dict = db.get_canonical_head()
        self.assertEqual(genesis_block_dict['header']['block_number'], 0)
        self.assertEqual(genesis_block_dict['header']['timestamp'], 0)
