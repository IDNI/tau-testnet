"""Fork choice on a chain deeper than the old 2000-block ancestry cap.

`db.get_chain_path` gave up after 2000 blocks and raised ValueError. `reorg_to`
and the candidate filter in `maybe_update_canonical_head` both walked every head
back to genesis, caught that ValueError and did nothing. So once a chain was
deeper than the cap, a node catching up through sync (network/service.py
`_ingest_blocks`: `ingest_block` per block, then `maybe_update_canonical_head`)
left its canonical head where it was on every batch, and logged nothing above
DEBUG. Serving the chain to peers (`get_canonical_blocks_at_or_after_height`)
hit the same cap.

Fork choice now walks the two heads back only to where they meet
(`db.find_fork_point`); only the rebuild, which replays from genesis, walks the
rest, uncapped. An ancestry that cannot be resolved is logged, not dropped.

Mock engine throughout (TAU_FORCE_TEST=1 from conftest, header verification
patched the way test_state_reconstruction.py does it): what is under test is the
ancestry walk and the head it picks, not Tau.
"""
import contextlib
import io
import logging
import os
import sys
import tempfile
import unittest
from unittest.mock import call, patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
import db
import chain_state
import tau_manager
import tau_authority
from chain_state import GENESIS_ADDRESS, GENESIS_BALANCE
from block import Block, compute_tx_hash

ADDR2 = "893c8134a31379c394b4ed31e67daf9565b1d2022aa96d83ca88d013bc208672bcf73dae5cc105da1e277109584239b2"
ADDR3 = "aabbccddee1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

LEGACY_MAX_DEPTH = 2000
DEEP = LEGACY_MAX_DEPTH + 100
SYNC_BATCH = 700
BASE_TS = 1_700_000_000


def _tx(sender, seq, transfers):
    return {
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "operations": {"1": transfers},
        "fee_limit": "0",
        "signature": "dummy_signature_for_testing",
    }


@contextlib.contextmanager
def quiet():
    """Swallow the rebuild's per-block prints; a 2100-block replay is ~10k lines."""
    with contextlib.redirect_stdout(io.StringIO()):
        yield


class DeepChainTestCase(unittest.TestCase):
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
        chain_state._genesis_accounts_state = {GENESIS_ADDRESS: GENESIS_BALANCE}
        chain_state._balances[GENESIS_ADDRESS] = GENESIS_BALANCE

        self.original_auto_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False

        self.verify_patch = patch(
            'consensus.engine.TauConsensusEngine.verify_block_header', return_value=True)
        self.verify_patch.start()
        # Tau never comes up here. Answer the engine's readiness waits the way
        # they would end anyway (not ready) instead of sitting out 5 s on every
        # block that carries a transaction.
        self.wait_patch = patch.object(tau_manager.tau_ready, 'wait', return_value=False)
        self.wait_patch.start()
        self.genesis_hash = db.get_genesis_hash()

    def tearDown(self):
        config.TESTNET_AUTO_FAUCET = self.original_auto_faucet
        self.wait_patch.stop()
        self.verify_patch.stop()
        config.set_database_path(self.original_db_path)
        if getattr(db, '_db_conn', None) is not None:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)

    @staticmethod
    def extend(parent_hash, parent_number, count, proposer="a" * 96, txs=None):
        """`count` blocks on top of `parent_hash`, oldest first. `txs` maps a
        block number to its transactions; every other block is empty."""
        txs = txs or {}
        blocks = []
        prev = parent_hash
        for n in range(parent_number + 1, parent_number + count + 1):
            blk = Block.create(block_number=n, previous_hash=prev, transactions=txs.get(n, []),
                               proposer_pubkey=proposer, timestamp=BASE_TS + n)
            blocks.append(blk)
            prev = blk.block_hash
        return blocks

    def ingest(self, blocks, expect='added'):
        for blk in blocks:
            self.assertEqual(chain_state.ingest_block(blk).status, expect)

    def adopt(self, blocks):
        """Ingest `blocks` and run fork choice, as one synced batch."""
        self.ingest(blocks)
        with quiet():
            status = chain_state.maybe_update_canonical_head()
        self.assertTrue(status)
        self.assertEqual(self.head(), blocks[-1].block_hash)

    def head(self):
        return db.get_canonical_head()['block_hash']

    @staticmethod
    def drop_block(blk):
        """Lose a stored block, the way a damaged DB would."""
        with db._db_lock:
            db._db_conn.execute("DELETE FROM blocks WHERE block_hash = ?", (blk.block_hash,))
            db._db_conn.commit()


class TestDeepChainSync(DeepChainTestCase):
    def test_sync_keeps_advancing_the_head_past_the_legacy_cap(self):
        """What `_ingest_blocks` does per synced batch, until the chain is deep."""
        chain = self.extend(self.genesis_hash, 0, DEEP)
        for start in range(0, DEEP, SYNC_BATCH):
            batch = chain[start:start + SYNC_BATCH]
            self.ingest(batch)
            with quiet():
                status = chain_state.maybe_update_canonical_head()
            tip = batch[-1]
            self.assertTrue(
                status, f"head did not advance to #{tip.header.block_number} "
                        f"(maybe_update_canonical_head -> {status!r})")
            self.assertEqual(self.head(), tip.block_hash)
            self.assertEqual(chain_state._canonical_head_hash, tip.block_hash)

    def test_canonical_blocks_are_served_past_the_legacy_cap(self):
        """The sync server's view of the chain (headers + block ranges)."""
        chain = self.extend(self.genesis_hash, 0, DEEP)
        for blk in chain:
            db.add_block(blk)
        with db._db_lock:
            db._db_conn.execute(
                "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_hash', ?)",
                (chain[-1].block_hash,))
            db._db_conn.commit()

        served = db.get_canonical_blocks_at_or_after_height(DEEP - 4)
        self.assertEqual([b['block_hash'] for b in served],
                         [b.block_hash for b in chain[-5:]])


class TestDeepReorg(DeepChainTestCase):
    def test_real_fork_deep_in_the_chain_still_rebuilds_from_genesis(self):
        fork_at = DEEP - 10
        lost_tx = _tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR2, "5"]])
        won_tx = _tx(GENESIS_ADDRESS, 0, [[GENESIS_ADDRESS, ADDR3, "7"]])
        main = self.extend(self.genesis_hash, 0, DEEP, txs={DEEP - 5: [lost_tx]})
        self.adopt(main)
        self.assertEqual(chain_state.get_balance(ADDR2), 5)

        fork_block = main[fork_at - 1]
        branch = self.extend(fork_block.block_hash, fork_at, 15, proposer="b" * 96,
                             txs={fork_at + 1: [won_tx]})
        self.ingest(branch)
        rebuild = chain_state._rebuild_state_from_blockchain_internal
        with patch.object(chain_state, '_rebuild_state_from_blockchain_internal',
                          wraps=rebuild) as spy, quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())

        self.assertEqual(self.head(), branch[-1].block_hash)
        # One replay, from genesis, along the whole winning chain.
        expected_path = [b.block_hash for b in main[:fork_at] + branch]
        self.assertEqual(spy.call_args_list, [call(0, path_hashes=expected_path)])
        self.assertEqual(chain_state.get_balance(ADDR2), 0)
        self.assertEqual(chain_state.get_balance(ADDR3), 7)
        # The losing branch's transaction goes back to the mempool.
        self.assertIsNotNone(db.get_mempool_entry(compute_tx_hash(lost_tx)))
        self.assertIsNone(db.get_mempool_entry(compute_tx_hash(won_tx)))


class TestFindForkPoint(DeepChainTestCase):
    def setUp(self):
        super().setUp()
        #   genesis - 1 .. 10 - 11 .. 20          (main)
        #                    \- 11' .. 14'        (side)
        self.main = self.extend(self.genesis_hash, 0, 20)
        self.side = self.extend(self.main[9].block_hash, 10, 4, proposer="b" * 96)
        for blk in self.main + self.side:
            db.add_block(blk)

    @staticmethod
    def hashes(blocks):
        return [b.block_hash for b in blocks]

    def test_same_block(self):
        tip = self.main[-1].block_hash
        self.assertEqual(db.find_fork_point(tip, tip), (tip, [], []))

    def test_extension(self):
        base, tip = self.main[9], self.main[-1]
        self.assertEqual(db.find_fork_point(base.block_hash, tip.block_hash),
                         (base.block_hash, [], self.hashes(self.main[10:])))
        self.assertEqual(db.find_fork_point(tip.block_hash, base.block_hash),
                         (base.block_hash, self.hashes(self.main[10:]), []))

    def test_fork(self):
        ancestor, main_suffix, side_suffix = db.find_fork_point(
            self.main[-1].block_hash, self.side[-1].block_hash)
        self.assertEqual(ancestor, self.main[9].block_hash)
        self.assertEqual(main_suffix, self.hashes(self.main[10:]))
        self.assertEqual(side_suffix, self.hashes(self.side))

    def test_from_genesis(self):
        self.assertEqual(db.find_fork_point(self.genesis_hash, self.side[-1].block_hash),
                         (self.genesis_hash, [], self.hashes(self.main[:10] + self.side)))

    def test_stops_at_the_fork_point(self):
        # Lose a block below the fork: the walk to genesis breaks, the fork
        # point is still found because nothing below it is visited.
        self.drop_block(self.main[3])
        with self.assertRaises(db.ChainAncestryError) as ctx:
            db.get_chain_path(self.side[-1].block_hash, self.genesis_hash)
        self.assertEqual(ctx.exception.kind, "missing")
        ancestor, _, _ = db.find_fork_point(self.main[-1].block_hash, self.side[-1].block_hash)
        self.assertEqual(ancestor, self.main[9].block_hash)

    def test_missing_parent(self):
        orphan = self.extend("e" * 64, 30, 2)
        for blk in orphan:
            db.add_block(blk)
        with self.assertRaises(db.ChainAncestryError) as ctx:
            db.find_fork_point(self.main[-1].block_hash, orphan[-1].block_hash)
        self.assertEqual((ctx.exception.kind, ctx.exception.side), ("missing", "b"))
        self.assertEqual(ctx.exception.block_hash, "e" * 64)

    def test_numbering_break(self):
        # Claims #30 on top of #20: only an orphan stored before its parent
        # arrived skips ingest_block's parent+1 check.
        liar = Block.create(block_number=30, previous_hash=self.main[-1].block_hash,
                            transactions=[], proposer_pubkey="c" * 96, timestamp=BASE_TS + 30)
        db.add_block(liar)
        with self.assertRaises(db.ChainAncestryError) as ctx:
            db.find_fork_point(liar.block_hash, self.side[-1].block_hash)
        self.assertEqual((ctx.exception.kind, ctx.exception.side), ("corrupt", "a"))
        self.assertEqual(ctx.exception.block_hash, liar.block_hash)

    def test_disjoint_roots(self):
        other_root = Block.create(block_number=0, previous_hash="0" * 64, transactions=[],
                                  proposer_pubkey="d" * 96, timestamp=BASE_TS)
        db.add_block(other_root)
        other = self.extend(other_root.block_hash, 0, 3, proposer="d" * 96)
        for blk in other:
            db.add_block(blk)
        with self.assertRaises(db.ChainAncestryError) as ctx:
            db.find_fork_point(self.main[-1].block_hash, other[-1].block_hash)
        self.assertEqual((ctx.exception.kind, ctx.exception.side), ("disjoint", None))
        with self.assertRaises(db.ChainAncestryError) as ctx:
            db.get_chain_path(other[-1].block_hash, self.genesis_hash)
        self.assertEqual(ctx.exception.kind, "disjoint")


class TestUnresolvableAncestry(DeepChainTestCase):
    """Short chains: none of this depends on depth."""

    def setUp(self):
        super().setUp()
        self.main = self.extend(self.genesis_hash, 0, 20)
        self.adopt(self.main)

    def test_reorg_to_an_orphan_is_refused_loudly(self):
        orphan = self.extend("e" * 64, 40, 1)
        self.ingest(orphan, expect='orphan')
        with self.assertLogs('chain_state', level='ERROR') as logs:
            self.assertIsNone(chain_state.reorg_to(orphan[-1].block_hash))
        self.assertIn("REFUSED", logs.output[0])
        self.assertIn("missing", logs.output[0])
        self.assertEqual(self.head(), self.main[-1].block_hash)

    def test_orphan_candidates_are_routine_and_do_not_block_the_head(self):
        # Ranks first (#41 beats #21), but its parent has not arrived.
        orphan = self.extend("e" * 64, 40, 1)
        self.ingest(orphan, expect='orphan')
        nxt = self.extend(self.main[-1].block_hash, 20, 1)
        self.ingest(nxt)
        with self.assertLogs('chain_state', level='DEBUG') as logs, quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), nxt[-1].block_hash)
        about_orphan = [r for r in logs.records if orphan[-1].block_hash[:16] in r.getMessage()]
        self.assertTrue(about_orphan)
        self.assertTrue(all(r.levelno == logging.DEBUG for r in about_orphan))

    def test_numbering_break_is_reported_and_never_adopted(self):
        # The lying child arrives first and is stored as an orphan; its parent,
        # a valid #21, arrives next. The pair must not become a "#30" head.
        parent = self.extend(self.main[-1].block_hash, 20, 1)[0]
        liar = Block.create(block_number=30, previous_hash=parent.block_hash,
                            transactions=[], proposer_pubkey="c" * 96, timestamp=BASE_TS + 30)
        self.ingest([liar], expect='orphan')
        self.ingest([parent])
        with self.assertLogs('chain_state', level='WARNING') as logs:
            self.assertIsNone(chain_state.maybe_update_canonical_head())
        self.assertIn(liar.block_hash[:16], logs.output[0])
        self.assertIn("corrupt", logs.output[0])
        self.assertEqual(self.head(), self.main[-1].block_hash)

        with self.assertLogs('chain_state', level='ERROR') as logs:
            self.assertIsNone(chain_state.reorg_to(liar.block_hash))
        self.assertIn("REFUSED", logs.output[0])

    def test_a_rejected_child_does_not_send_the_head_back_to_an_old_fork(self):
        # Once the head has a child it is no longer a childless "candidate".
        # If everything above it is rejected, staying put must still beat the
        # tip of an old fork further down.
        stale = self.extend(self.main[4].block_hash, 5, 2, proposer="b" * 96)
        self.ingest(stale)
        parent = self.extend(self.main[-1].block_hash, 20, 1)[0]
        liar = Block.create(block_number=30, previous_hash=parent.block_hash,
                            transactions=[], proposer_pubkey="c" * 96, timestamp=BASE_TS + 30)
        self.ingest([liar], expect='orphan')
        self.ingest([parent])
        with self.assertLogs('chain_state', level='WARNING'), quiet():
            self.assertIsNone(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), self.main[-1].block_hash)

    def test_lost_block_below_the_fork_point_is_refused_loudly(self):
        branch = self.extend(self.main[14].block_hash, 15, 7, proposer="b" * 96)
        self.ingest(branch)
        self.drop_block(self.main[4])
        with self.assertLogs('chain_state', level='ERROR') as logs:
            self.assertIsNone(chain_state.maybe_update_canonical_head())
        self.assertIn("below fork point", logs.output[0])
        self.assertEqual(self.head(), self.main[-1].block_hash)
        self.assertEqual(chain_state._canonical_head_hash, self.main[-1].block_hash)

    def test_lost_block_under_the_current_head_does_not_strand_the_node(self):
        # The head's own chain is damaged above the fork point; the branch is
        # sound all the way to genesis. Reported, then the node moves onto it.
        branch = self.extend(self.main[9].block_hash, 10, 12, proposer="b" * 96)
        self.ingest(branch)
        self.drop_block(self.main[14])
        with self.assertLogs('chain_state', level='ERROR') as logs, quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertIn("broken ancestry", logs.output[0])
        self.assertEqual(self.head(), branch[-1].block_hash)

    def test_stale_fork_tips_below_the_head_are_not_walked(self):
        stale = self.extend(self.main[2].block_hash, 3, 2, proposer="b" * 96)
        self.ingest(stale)
        nxt = self.extend(self.main[-1].block_hash, 20, 1)
        self.ingest(nxt)
        with patch.object(db, 'find_fork_point', wraps=db.find_fork_point) as spy, quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), nxt[-1].block_hash)
        walked = {h for c in spy.call_args_list for h in c.args}
        self.assertNotIn(stale[-1].block_hash, walked)

    def test_a_non_hex_candidate_does_not_break_fork_choice(self):
        # Block.from_dict leaves a block #0's hash unverified, so one can be
        # stored under any name; ranking every candidate must not choke on it.
        junk = Block.create(block_number=0, previous_hash="0" * 64, transactions=[],
                            proposer_pubkey="d" * 96, timestamp=BASE_TS)
        junk.block_hash = "not-a-hex-hash"
        db.add_block(junk)
        nxt = self.extend(self.main[-1].block_hash, 20, 1)
        self.ingest(nxt)
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), nxt[-1].block_hash)



class TestExtensionFastPathUnderAuthority(DeepChainTestCase):
    """With worker-backed authority, a block that extends the head commits
    through the commit protocol instead of the rebuild. The two fork-choice
    lines met in one merge: the fast path asked only for an empty old suffix,
    and `_resolve_fork` returns exactly that -- forking at genesis -- when the
    CURRENT head's ancestry is broken. That is a rebuild, never an extension.

    The decision is what is under test, so both outcomes are stubbed: the
    extension helper records its calls, and the rebuild reports failure, which
    reorg_to answers by keeping the head where it was.
    """

    def setUp(self):
        super().setUp()
        self.main = self.extend(self.genesis_hash, 0, 20)
        self.adopt(self.main)
        owner = type("Owner", (), {"enabled": True})()
        self.patches = [
            patch.object(tau_authority, "owner", return_value=owner),
            patch.object(chain_state, "_extend_through_commit_protocol", return_value=True),
            patch.object(chain_state, "_rebuild_state_from_blockchain_internal", return_value=None),
        ]
        self.owner_patch, self.extension, self.rebuild = (p.start() for p in self.patches)

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        super().tearDown()

    def test_a_block_on_the_head_takes_the_extension(self):
        nxt = self.extend(self.main[-1].block_hash, 20, 1)
        self.ingest(nxt)
        with quiet():
            self.assertTrue(chain_state.reorg_to(nxt[-1].block_hash))
        self.extension.assert_called_once_with([nxt[-1].block_hash], nxt[-1].block_hash)
        self.rebuild.assert_not_called()

    def test_a_head_with_broken_ancestry_is_rebuilt_not_extended(self):
        branch = self.extend(self.main[9].block_hash, 10, 12, proposer="b" * 96)
        self.ingest(branch)
        self.drop_block(self.main[14])
        with self.assertLogs('chain_state', level='ERROR'), quiet():
            chain_state.reorg_to(branch[-1].block_hash)
        self.extension.assert_not_called()
        self.assertTrue(self.rebuild.called, "the broken-ancestry reorg never reached the rebuild")
        self.assertEqual(self.rebuild.call_args_list[0].kwargs["path_hashes"][-1],
                         branch[-1].block_hash)


if __name__ == '__main__':
    unittest.main()
