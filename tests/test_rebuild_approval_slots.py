"""A genesis with approval slots keeps them through a full rebuild and a reorg.

The state hash binds `approval_slots_active`, so a replay that starts without
the genesis flag computes another hash from block 1 on.
"""
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
import db
import chain_state
import tau_manager
from block import Block

PROPOSER = "a" * 96
TIMESTAMP = 1_700_000_001
GENESIS_TEMPLATE = os.path.join(
    project_root, "networks", "tau-testnet-v2", "genesis.json")


def _block_1(genesis_hash, state_hash):
    return Block.create(
        block_number=1, previous_hash=genesis_hash,
        transactions=[],
        proposer_pubkey=PROPOSER, timestamp=TIMESTAMP, state_hash=state_hash,
    )


class TestRebuildApprovalSlots(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(self.temp_db_fd)
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.temp_db_path)

        with open(GENESIS_TEMPLATE, encoding="utf-8") as fh:
            genesis = json.load(fh)
        genesis["consensus_meta"]["mechanism_specific_metadata"]["approval_slots_active"] = True
        self.genesis_fd, self.genesis_path = tempfile.mkstemp(suffix='.json')
        with os.fdopen(self.genesis_fd, "w", encoding="utf-8") as fh:
            json.dump(genesis, fh)

        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db._db_conn = None
        db.init_db()
        db.clear_mempool()
        chain_state.load_genesis(self.genesis_path)

        self.original_auto_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False
        self.verify_patch = patch(
            'consensus.engine.TauConsensusEngine.verify_block_header', return_value=True)
        self.verify_patch.start()
        self.wait_patch = patch.object(tau_manager.tau_ready, 'wait', return_value=False)
        self.wait_patch.start()
        self.genesis_hash = db.get_genesis_hash()

        # The mined block carries no stored hash, so its state hash comes from
        # the live path alone. The stored copy then holds that hash. The block
        # is empty because the mock engine defers a block with a user tx.
        self.mined = _block_1(self.genesis_hash, None)
        self.mined.header.state_hash = ""
        self.assertTrue(chain_state.process_new_block(self.mined))
        self.mined_hash = chain_state._tau_engine_state_hash
        self.assertTrue(self.mined_hash)
        self.stored = _block_1(self.genesis_hash, self.mined_hash)
        db.add_block(self.stored)

    def tearDown(self):
        config.TESTNET_AUTO_FAUCET = self.original_auto_faucet
        self.wait_patch.stop()
        self.verify_patch.stop()
        config.set_database_path(self.original_db_path)
        if getattr(db, '_db_conn', None) is not None:
            db._db_conn.close()
            db._db_conn = None
        for path in (self.temp_db_path, self.genesis_path):
            if os.path.exists(path):
                os.remove(path)

    def test_genesis_turns_the_slots_on(self):
        self.assertTrue(chain_state._genesis_approval_slots_active)
        self.assertTrue(chain_state._lifecycle_manager.approval_slots_active)

    def test_full_rebuild_gives_the_stored_state_hash(self):
        result = chain_state._rebuild_state_from_blockchain_internal(
            0, path_hashes=[self.stored.block_hash])
        self.assertTrue(result.ok, result.reason)
        self.assertEqual(result.stopped_at_block, 1)
        self.assertEqual(chain_state._tau_engine_state_hash, self.mined_hash)
        self.assertTrue(chain_state._lifecycle_manager.approval_slots_active)

    def test_rebuild_without_the_genesis_flag_disagrees(self):
        chain_state._genesis_approval_slots_active = False
        result = chain_state._rebuild_state_from_blockchain_internal(
            0, path_hashes=[self.stored.block_hash])
        self.assertFalse(result.ok)
        self.assertEqual(result.stopped_at_block, 1)
        self.assertEqual(result.stored_hash, self.mined_hash)

    def test_reorg_gives_the_stored_state_hash(self):
        self.assertTrue(chain_state.reorg_to(self.stored.block_hash))
        self.assertEqual(db.get_canonical_head()['block_hash'], self.stored.block_hash)
        self.assertEqual(chain_state._tau_engine_state_hash, self.mined_hash)
        self.assertTrue(chain_state._lifecycle_manager.approval_slots_active)

    def test_reload_keeps_the_genesis_flag_over_a_stale_row(self):
        db.set_chain_state_value("approval_slots_active", "0")
        self.assertTrue(chain_state.load_state_from_db())
        self.assertTrue(chain_state._lifecycle_manager.approval_slots_active)
        self.assertEqual(db.get_chain_state_value("approval_slots_active", None), "1")


if __name__ == "__main__":
    unittest.main()
