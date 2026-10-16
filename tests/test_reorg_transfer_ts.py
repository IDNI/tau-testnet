"""A full rebuild must drop transfer stamps that the replayed chain does not rederive.

`_rebuild_state_from_blockchain_internal(start_block=0)` clears balances and
sequences, then replays. Transfer stamps were left in place and only ever
merged, so a stamp written on a chain that is no longer canonical survived the
rebuild: a sender who exists only on the losing fork persisted as a zero
balance / zero sequence row, and a restarted node hashed an account a peer
that never saw that fork does not have.
"""
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
tests_dir = os.path.dirname(__file__)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

import config
import db
import chain_state
from chain_state import GENESIS_ADDRESS, GENESIS_BALANCE
from consensus.engine import TauConsensusEngine
from consensus.fees import FeeRuleError
from test_reorg_deep_chain import ADDR2, ADDR3, BASE_TS, DeepChainTestCase, _tx, quiet

KEYED = "cc" * 48
STRAY = "dd" * 48


class TransferTsReorgTests(DeepChainTestCase):
    def setUp(self):
        # A fresh process starts with an empty stamp map. Clear before genesis
        # provisioning so this DB is not born holding another test's stamps.
        chain_state._last_transfer_ts.clear()
        super().setUp()
        self._extra_dbs = []

    def tearDown(self):
        super().tearDown()
        chain_state._last_transfer_ts.clear()
        for path in self._extra_dbs:
            if os.path.exists(path):
                os.remove(path)

    @staticmethod
    def _node_state():
        return (
            dict(chain_state._last_transfer_ts),
            db.load_last_transfer_ts(),
            chain_state.compute_accounts_hash(
                chain_state._balances, chain_state._sequence_numbers),
        )

    def _restart(self):
        path = config.STRING_DB_PATH
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(path)
        db.init_db()
        self.assertTrue(chain_state.load_state_from_db())

    def _fresh_node(self):
        """A follower process: new DB, genesis load, empty stamp map."""
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        fd, path = tempfile.mkstemp(suffix='.sqlite')
        os.close(fd)
        self._extra_dbs.append(path)
        config.set_database_path(path)
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._last_transfer_ts.clear()
        with quiet():
            chain_state.load_genesis("data/genesis.json")
        chain_state._genesis_accounts_state = {GENESIS_ADDRESS: GENESIS_BALANCE}
        chain_state._balances[GENESIS_ADDRESS] = GENESIS_BALANCE

    def _account_row(self, address):
        with db._db_lock:
            return db._db_conn.execute(
                "SELECT balance, sequence_number, last_transfer_ts "
                "FROM accounts WHERE address = ?",
                (address,),
            ).fetchone()

    def _assert_matches_follower(self, winning_blocks):
        node = self._node_state()
        self._restart()
        node_restarted = self._node_state()
        self._fresh_node()
        self.adopt(winning_blocks)
        follower = self._node_state()
        self._restart()
        follower_restarted = self._node_state()
        self.assertEqual(node, follower)
        self.assertEqual(node_restarted, follower_restarted)
        return node

    def test_losing_fork_stamp_is_dropped(self):
        """A transfer that exists only on the losing suffix does not keep its stamp."""
        prefix = self.extend(self.genesis_hash, 0, 6)
        losing_tx = _tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR2, "5"]])
        losing = self.extend(prefix[-1].block_hash, 6, 3, proposer="b" * 96,
                             txs={8: [losing_tx]})
        winning = self.extend(prefix[-1].block_hash, 6, 5, proposer="c" * 96)
        self.adopt(prefix + losing)
        self.assertEqual(
            chain_state._last_transfer_ts.get(GENESIS_ADDRESS), BASE_TS + 8)

        self.adopt(winning)
        self.assertNotIn(GENESIS_ADDRESS, chain_state._last_transfer_ts)
        self._assert_matches_follower(prefix + winning)

    def test_stamp_follows_winner_when_both_forks_send(self):
        """When both forks transfer, the stamp is the winner's block time."""
        prefix = self.extend(self.genesis_hash, 0, 6)
        losing = self.extend(
            prefix[-1].block_hash, 6, 3, proposer="b" * 96,
            txs={8: [_tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR2, "5"]])]})
        winning = self.extend(
            prefix[-1].block_hash, 6, 5, proposer="c" * 96,
            txs={9: [_tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR3, "7"]])]})
        self.adopt(prefix + losing)
        self.adopt(winning)

        self.assertEqual(
            chain_state._last_transfer_ts.get(GENESIS_ADDRESS), BASE_TS + 9)
        node = self._assert_matches_follower(prefix + winning)
        self.assertEqual(node[0].get(GENESIS_ADDRESS), BASE_TS + 9)

    def test_losing_fork_only_sender_leaves_no_account_row(self):
        """A sender funded only on the losing fork must not survive as a 0/0 row."""
        prefix = self.extend(self.genesis_hash, 0, 6)
        fund = _tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, KEYED, "100"]])
        send = _tx(KEYED, 0, [[KEYED, ADDR2, "5"]])
        losing = self.extend(prefix[-1].block_hash, 6, 3, proposer="b" * 96,
                             txs={7: [fund], 8: [send]})
        winning = self.extend(prefix[-1].block_hash, 6, 5, proposer="c" * 96)
        self.adopt(prefix + losing)
        self.assertIn(KEYED, chain_state._last_transfer_ts)

        self.adopt(winning)
        self.assertIsNone(self._account_row(KEYED))
        self._assert_matches_follower(prefix + winning)

    def test_aborted_reorg_restores_prior_stamps(self):
        """A replay that dies mid-winner must not leave the winner's stamps behind."""
        shared = self.extend(
            self.genesis_hash, 0, 4,
            txs={2: [_tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR3, "4"]])]})
        canonical = self.extend(shared[-1].block_hash, 4, 4)
        self.adopt(shared + canonical)
        prior = dict(chain_state._last_transfer_ts)
        self.assertEqual(prior.get(GENESIS_ADDRESS), BASE_TS + 2)
        self.assertNotIn(KEYED, prior)

        winner = self.extend(
            shared[-1].block_hash, 4, 3, proposer="b" * 96,
            txs={
                5: [_tx(GENESIS_ADDRESS, 1, [[GENESIS_ADDRESS, KEYED, "100"]])],
                6: [_tx(KEYED, 0, [[KEYED, ADDR2, "5"]])],
            })
        self.ingest(winner)
        fail_hash = winner[-1].block_hash
        applied = []
        original = TauConsensusEngine.apply_block

        def fail_on_winner_tip(engine, active_view, block, parent_snapshot, **kwargs):
            if block.block_hash == fail_hash:
                raise FeeRuleError("injected replay failure")
            applied.append(block.block_hash)
            return original(engine, active_view, block, parent_snapshot, **kwargs)

        with patch.object(TauConsensusEngine, "apply_block", fail_on_winner_tip), quiet():
            self.assertFalse(chain_state.reorg_to(winner[-1].block_hash))

        self.assertIn(winner[1].block_hash, applied)
        self.assertEqual(db.get_canonical_head()['block_hash'], canonical[-1].block_hash)
        self.assertEqual(dict(chain_state._last_transfer_ts), prior)

    def test_boot_rebuild_ignores_persisted_stamps(self):
        """A stamp loaded from disk is discarded; replay is the source of truth."""
        chain = self.extend(
            self.genesis_hash, 0, 6,
            txs={3: [_tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR2, "5"]])]})
        self.adopt(chain)
        expected = dict(chain_state._last_transfer_ts)
        self.assertEqual(expected.get(GENESIS_ADDRESS), BASE_TS + 3)

        with db._db_lock:
            db._db_conn.execute(
                "INSERT INTO accounts (address, balance, sequence_number, last_transfer_ts) "
                "VALUES (?, ?, ?, ?)",
                (STRAY, 0, 0, 1_600_000_000),
            )
            db._db_conn.commit()
        self._restart()
        self.assertEqual(chain_state._last_transfer_ts.get(STRAY), 1_600_000_000)

        with quiet():
            result = chain_state.rebuild_state_from_blockchain(0)
        self.assertTrue(result.ok)
        self.assertNotIn(STRAY, chain_state._last_transfer_ts)
        self.assertEqual(dict(chain_state._last_transfer_ts), expected)


if __name__ == '__main__':
    unittest.main()
