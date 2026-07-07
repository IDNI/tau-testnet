"""Phase 9A — rebuild aborts are loud and non-destructive.

Regression guard for Bug B (root-caused in demo/diagnostics/ROOT_CAUSE.md):
`reorg_to` used to commit the new head *number* even when the state rebuild
replay aborted on a state-hash invariant mismatch, so a node advertised an
advancing head while its applied state was frozen at the last good block.

These tests force a rebuild abort with the mock engine (no native Tau) by
giving the new chain's tip block a deliberately-wrong stored `state_hash`, then
assert the invariant: **advertised head == applied-state head**. On abort the
canonical head (DB row + in-memory) must stay put, balances must be restored to
the prior head, and the failure must be reported (not swallowed).
"""
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
from chain_state import GENESIS_ADDRESS, GENESIS_BALANCE
from block import Block

ADDR2 = "893c8134a31379c394b4ed31e67daf9565b1d2022aa96d83ca88d013bc208672bcf73dae5cc105da1e277109584239b2"
ADDR3 = "aabbccddee1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
BAD_HASH = "f" * 64


def _tx(sender, seq, transfers):
    return {
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "operations": {"1": transfers},
        "fee_limit": "0",
        "signature": "dummy_signature_for_testing",
    }


class TestReorgAbortHardening(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(self.temp_db_fd)
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.temp_db_path)

        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()

        db._db_conn = None
        db.init_db()
        db.clear_mempool()
        chain_state.load_genesis("data/genesis.json")
        # Pin the rebuild seed to the legacy single-account baseline these
        # synthetic histories are built on.
        chain_state._genesis_accounts_state = {GENESIS_ADDRESS: GENESIS_BALANCE}
        chain_state._balances[GENESIS_ADDRESS] = GENESIS_BALANCE

        self.original_auto_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False

        # Mock header verification: the abort under test must come from the
        # state-hash invariant check, not from header verification.
        self.verify_patch = patch(
            'consensus.engine.TauConsensusEngine.verify_block_header', return_value=True)
        self.verify_patch.start()

        # Build the fork:
        #   genesis --> A1 (canonical, addr1->addr2 5)
        #           \-> B1 (addr1->addr3 7) --> B2 (empty, BAD state_hash)
        # A1/B1 use the default EMPTY_STATE_HASH ("0"*64), which the invariant
        # check treats as "skip" (a valid, verifiable block). B2 bakes a wrong
        # non-empty state_hash into its block hash so replay validates the block
        # integrity but then fails the state-hash invariant — the exact Bug A
        # shape (miner's stored hash != replay-computed hash), forcing the abort.
        genesis_hash = db.get_genesis_hash()
        self.a1 = Block.create(block_number=1, previous_hash=genesis_hash,
                               transactions=[_tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR2, "5"]])],
                               proposer_pubkey="a" * 96)
        self.b1 = Block.create(block_number=1, previous_hash=genesis_hash,
                               transactions=[_tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR3, "7"]])],
                               proposer_pubkey="b" * 96)
        self.b2 = Block.create(block_number=2, previous_hash=self.b1.block_hash,
                               transactions=[], proposer_pubkey="b" * 96,
                               state_hash=BAD_HASH)

        db.add_block(self.a1)
        db.add_block(self.b1)
        db.add_block(self.b2)

    def tearDown(self):
        config.TESTNET_AUTO_FAUCET = self.original_auto_faucet
        self.verify_patch.stop()
        config.set_database_path(self.original_db_path)
        if getattr(db, '_db_conn', None) is not None:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    # --- direct RebuildResult contract ------------------------------------

    def test_rebuild_returns_failure_status_on_mismatch(self):
        result = chain_state._rebuild_state_from_blockchain_internal(
            0, path_hashes=[self.b1.block_hash, self.b2.block_hash])
        self.assertIsNotNone(result)
        self.assertFalse(result.ok)
        self.assertEqual(result.stopped_at_block, 2)
        self.assertEqual(result.stored_hash, BAD_HASH)
        self.assertIn("state_hash", result.reason)

    def test_rebuild_returns_success_status_on_clean_replay(self):
        result = chain_state._rebuild_state_from_blockchain_internal(
            0, path_hashes=[self.a1.block_hash])
        self.assertIsNotNone(result)
        self.assertTrue(result.ok)
        self.assertEqual(result.stopped_at_block, 1)

    # --- reorg_to success (unchanged behavior) ----------------------------

    def test_reorg_success_advances_head(self):
        advanced = chain_state.reorg_to(self.a1.block_hash)
        self.assertTrue(advanced)
        self.assertEqual(db.get_canonical_head()['block_hash'], self.a1.block_hash)
        self.assertEqual(chain_state._canonical_head_hash, self.a1.block_hash)
        # A1 applied: addr1 -5, addr2 +5.
        self.assertEqual(chain_state.get_balance(ADDR2), 5)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDRESS), GENESIS_BALANCE - 5)

    # --- reorg_to abort is loud and non-destructive -----------------------

    def test_reorg_abort_keeps_old_head_and_restores_state(self):
        # Establish A1 as the clean canonical head first.
        self.assertTrue(chain_state.reorg_to(self.a1.block_hash))
        head_before = db.get_canonical_head()['block_hash']
        bal_a1 = {a: chain_state.get_balance(a) for a in (GENESIS_ADDRESS, ADDR2, ADDR3)}

        # Reorg to the diverging B2 chain: must abort.
        advanced = chain_state.reorg_to(self.b2.block_hash)

        self.assertFalse(advanced, "reorg_to must report failure on rebuild abort")
        # DB canonical head unchanged.
        self.assertEqual(db.get_canonical_head()['block_hash'], head_before)
        self.assertEqual(db.get_canonical_head()['header']['block_number'], 1)
        # In-memory head restored to the prior (A1) head, NOT left at B1.
        self.assertEqual(chain_state._canonical_head_hash, self.a1.block_hash)
        # Balances restored to A1's state (not B1's addr3=7 partial replay).
        self.assertEqual(chain_state.get_balance(ADDR2), bal_a1[ADDR2])
        self.assertEqual(chain_state.get_balance(ADDR3), 0)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDRESS), bal_a1[GENESIS_ADDRESS])

    def test_maybe_update_canonical_head_tolerates_failed_reorg(self):
        # A1 canonical; a failed reorg attempt must leave the head intact and
        # not raise. (maybe_update picks the best candidate = B2 chain, height 2.)
        self.assertTrue(chain_state.reorg_to(self.a1.block_hash))
        head_before = db.get_canonical_head()['block_hash']
        status = chain_state.maybe_update_canonical_head()
        # Either it selected the diverging chain and aborted (False), or nothing
        # beat the current head (None) — never True, and never a crash.
        self.assertIn(status, (False, None))
        self.assertEqual(db.get_canonical_head()['block_hash'], head_before)


if __name__ == '__main__':
    unittest.main()
