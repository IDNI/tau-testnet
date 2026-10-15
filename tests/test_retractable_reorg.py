"""Retractable transfers across reorgs and restarts.

A park, a retract and a release are all consequences of which blocks are
canonical. These tests fork the chain so the same entry is parked, retracted or
released on a branch that then loses, and require the winner's state to be what
a node that only ever followed the winner has: balances, sequences, escrow, the
open set, the resolved commitment and the meta hash, on disk as well as in
memory.

Mock engine, replayed without Tau (see test_reorg_deep_chain.py): what is under
test is the book across the rebuild, not the transfer verdict.
"""
import hashlib
import os
import tempfile

import config
import chain_state
import db
from block import Block, compute_tx_hash
from py_ecc.bls import G2Basic

from consensus.tx_signing import signing_message_bytes
from test_reorg_deep_chain import ADDR2, BASE_TS, GENESIS_ADDRESS, DeepChainTestCase, quiet

SK = 4242
SENDER = G2Basic.SkToPk(SK).hex()
FUNDED = 1000
AMOUNT = 40
RELEASE_TIME = BASE_TS + 1000
PROPOSER = "a" * 96


def _sign(tx):
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(SK, digest).hex()
    return tx


def funding():
    return {
        "sender_pubkey": GENESIS_ADDRESS, "sequence_number": 0,
        "expiration_time": 9999999999, "expire_at_height": 5000,
        "operations": {"1": [[GENESIS_ADDRESS, SENDER, str(FUNDED)]]},
        "fee_limit": "0", "signature": "dummy_signature_for_testing",
    }


def park(seq=0, *, at_height=None, at_time=None, amount=AMOUNT, expire_at_height=40,
         expiration_time=9999999999):
    tx = {
        "tx_type": "retractable_transfer", "sender_pubkey": SENDER,
        "sequence_number": seq, "expiration_time": expiration_time,
        "expire_at_height": expire_at_height, "fee_limit": "0",
        "recipient_pubkey": ADDR2, "amount": amount,
    }
    if at_time is not None:
        tx["release_at_time"] = at_time
    else:
        tx["release_at_height"] = at_height
    return _sign(tx)


def retract(rid, seq):
    return _sign({
        "tx_type": "retract_transfer", "sender_pubkey": SENDER,
        "sequence_number": seq, "expiration_time": 9999999999,
        "expire_at_height": 40, "fee_limit": "0", "retractable_id": rid,
    })


def rid_of(tx):
    from consensus.retractable import parse_retractable_transfer
    return parse_retractable_transfer(tx).retractable_id.hex()


class RetractableReorgTestCase(DeepChainTestCase):
    def setUp(self):
        super().setUp()
        chain_state._sequence_numbers.clear()

    def blocks(self, parent, specs):
        """Blocks on `parent`, oldest first. A spec is (timestamp offset, txs)."""
        out = []
        number = parent.header.block_number if isinstance(parent, Block) else 0
        prev_hash = parent.block_hash if isinstance(parent, Block) else parent
        for offset, txs in specs:
            number += 1
            blk = Block.create(block_number=number, previous_hash=prev_hash,
                               transactions=txs, proposer_pubkey=PROPOSER,
                               timestamp=BASE_TS + offset)
            out.append(blk)
            prev_hash = blk.block_hash
        return out

    def reorg_to(self, blocks):
        self.ingest(blocks)
        with quiet():
            assert chain_state.maybe_update_canonical_head()
        self.assertEqual(self.head(), blocks[-1].block_hash)

    # -- observable state ----------------------------------------------------

    @staticmethod
    def state():
        lm = chain_state._lifecycle_manager
        book = lm.retractable_transfers
        return {
            "balances": {k: v for k, v in chain_state._balances.items() if v},
            "sequences": {k: v for k, v in chain_state._sequence_numbers.items() if v},
            "open": dict(book.open),
            "escrow": book.escrow_total(),
            "resolved": book.resolved_state(),
            "root": book.root(),
            "meta": lm.consensus_meta_hash(),
        }

    @staticmethod
    def disk_rows():
        with db._db_lock:
            return sorted(r[0] for r in db._db_conn.execute(
                "SELECT retractable_id FROM retractable_transfers_v1"))

    def restart(self):
        """What a process restart does to the in-memory state."""
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._lifecycle_manager = chain_state.ConsensusLifecycleManager(
            active_validators=["d" * 96])
        self.assertTrue(chain_state.load_state_from_db())

    def fresh_node(self):
        """A brand-new database at genesis, as setUp builds one."""
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)
        fd, self.temp_db_path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        config.set_database_path(self.temp_db_path)
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        db.clear_mempool()
        chain_state.load_genesis("data/genesis.json")
        chain_state._genesis_accounts_state = {GENESIS_ADDRESS: chain_state.GENESIS_BALANCE}
        chain_state._balances[GENESIS_ADDRESS] = chain_state.GENESIS_BALANCE
        self.genesis_hash = db.get_genesis_hash()

    def assertState(self, got, **expected):
        for key, value in expected.items():
            self.assertEqual(got[key], value, key)


class TestParkOnADiscardedBranch(RetractableReorgTestCase):
    def build(self):
        common = self.blocks(self.genesis_hash, [(1, [funding()])])
        parked = park(at_height=50)
        fork_a = self.blocks(common[-1], [(2, [parked]), (3, [])])
        fork_b = self.blocks(common[-1], [(2, []), (3, []), (4, [])])
        return common, fork_a, fork_b, parked

    def test_the_escrow_disappears_and_the_sender_is_whole(self):
        common, fork_a, fork_b, parked = self.build()
        self.adopt(common + fork_a)
        before = self.state()
        self.assertEqual(before["escrow"], AMOUNT)
        self.assertEqual(before["balances"][SENDER], FUNDED - AMOUNT)
        self.assertEqual(self.disk_rows(), [rid_of(parked)])

        self.reorg_to(fork_b)

        after = self.state()
        self.assertState(after, escrow=0, open={}, resolved=(0, bytes(32)))
        self.assertEqual(after["balances"][SENDER], FUNDED)
        self.assertNotIn(ADDR2, after["balances"])
        self.assertNotIn(SENDER, after["sequences"])
        self.assertEqual(self.disk_rows(), [], "the winner's rows must replace the loser's")

    def test_the_discarded_park_is_not_a_canonical_event(self):
        common, fork_a, fork_b, parked = self.build()
        self.adopt(common + fork_a)
        self.assertEqual(
            [e["outcome"] for e in db.get_canonical_retractable_events(rid_of(parked))],
            ["parked"])
        self.reorg_to(fork_b)
        self.assertEqual(db.get_canonical_retractable_events(rid_of(parked)), [])

    def test_restart_equals_a_node_that_followed_the_winner(self):
        common, fork_a, fork_b, parked = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        after = self.state()

        self.restart()
        self.assertEqual(self.state(), after)

        self.fresh_node()
        self.adopt(common + fork_b)
        self.assertEqual(self.state(), after)

    def test_the_orphaned_park_is_readmitted(self):
        common, fork_a, fork_b, parked = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        self.assertIsNotNone(db.get_mempool_entry(compute_tx_hash(parked)))


class TestReleaseOnADiscardedBranch(RetractableReorgTestCase):
    """Time kind: height cannot make a longer branch less mature, a timestamp can."""

    def build(self):
        parked = park(at_time=RELEASE_TIME, expiration_time=BASE_TS + 500)
        common = self.blocks(self.genesis_hash, [(1, [funding()]), (2, [parked])])
        fork_a = self.blocks(common[-1], [(RELEASE_TIME - BASE_TS + 1, [])])
        fork_b = self.blocks(common[-1], [(10, []), (20, [])])
        return common, fork_a, fork_b, parked

    def test_open_on_the_winner_after_a_release_on_the_loser(self):
        common, fork_a, fork_b, parked = self.build()
        self.adopt(common + fork_a)
        released = self.state()
        self.assertState(released, escrow=0, open={})
        self.assertEqual(released["balances"][ADDR2], AMOUNT)
        self.assertEqual(released["resolved"][0], 1)
        self.assertEqual(self.disk_rows(), [])

        self.reorg_to(fork_b)

        after = self.state()
        self.assertEqual(after["escrow"], AMOUNT)
        self.assertEqual(list(after["open"]), [bytes.fromhex(rid_of(parked))])
        self.assertEqual(after["resolved"], (0, bytes(32)))
        self.assertNotIn(ADDR2, after["balances"])
        self.assertEqual(after["balances"][SENDER], FUNDED - AMOUNT)
        self.assertEqual(self.disk_rows(), [rid_of(parked)])
        self.assertEqual(
            [e["outcome"] for e in db.get_canonical_retractable_events(rid_of(parked))],
            ["parked"])

    def test_restart_equals_a_node_that_followed_the_winner(self):
        common, fork_a, fork_b, _ = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        after = self.state()

        self.restart()
        self.assertEqual(self.state(), after)

        self.fresh_node()
        self.adopt(common + fork_b)
        self.assertEqual(self.state(), after)


class TestRetractOnADiscardedBranch(RetractableReorgTestCase):
    def build(self):
        parked = park(at_time=RELEASE_TIME, expiration_time=BASE_TS + 500)
        rid = rid_of(parked)
        retracted = retract(rid, seq=1)
        common = self.blocks(self.genesis_hash, [(1, [funding()]), (2, [parked])])
        fork_a = self.blocks(common[-1], [(10, [retracted])])
        fork_b = self.blocks(common[-1], [(11, []), (RELEASE_TIME - BASE_TS + 1, [])])
        return common, fork_a, fork_b, rid, retracted

    def test_released_on_the_winner_after_a_retract_on_the_loser(self):
        common, fork_a, fork_b, rid, _ = self.build()
        self.adopt(common + fork_a)
        loser = self.state()
        self.assertEqual(loser["balances"][SENDER], FUNDED)
        self.assertEqual(loser["sequences"][SENDER], 2)
        self.assertNotIn(ADDR2, loser["balances"])

        self.reorg_to(fork_b)

        after = self.state()
        self.assertState(after, escrow=0, open={})
        self.assertEqual(after["balances"][ADDR2], AMOUNT)
        self.assertEqual(after["balances"][SENDER], FUNDED - AMOUNT)
        self.assertEqual(after["sequences"][SENDER], 1, "the discarded retract's sequence is free again")
        self.assertEqual(after["resolved"][0], 1)
        self.assertNotEqual(after["resolved"], loser["resolved"],
                            "released and retracted fold different outcome bytes")
        self.assertEqual(self.disk_rows(), [])
        self.assertEqual(
            [e["outcome"] for e in db.get_canonical_retractable_events(rid)],
            ["parked", "released"])

    def test_restart_equals_a_node_that_followed_the_winner(self):
        common, fork_a, fork_b, _, _ = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        after = self.state()

        self.restart()
        self.assertEqual(self.state(), after)

        self.fresh_node()
        self.adopt(common + fork_b)
        self.assertEqual(self.state(), after)

    def test_the_orphaned_retract_is_not_readmitted_once_released(self):
        common, fork_a, fork_b, rid, retracted = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        self.assertIsNone(db.get_mempool_entry(compute_tx_hash(retracted)))


class TestOrphanedRetractIsReadmitted(RetractableReorgTestCase):
    def test_a_retract_whose_entry_is_still_open_returns_to_the_mempool(self):
        parked = park(at_height=50)
        rid = rid_of(parked)
        retracted = retract(rid, seq=1)
        common = self.blocks(self.genesis_hash, [(1, [funding()]), (2, [parked])])
        fork_a = self.blocks(common[-1], [(3, [retracted])])
        fork_b = self.blocks(common[-1], [(3, []), (4, [])])

        self.adopt(common + fork_a)
        self.assertEqual(self.state()["escrow"], 0)

        self.reorg_to(fork_b)

        self.assertEqual(self.state()["escrow"], AMOUNT)
        self.assertEqual(self.disk_rows(), [rid])
        self.assertIsNotNone(db.get_mempool_entry(compute_tx_hash(retracted)))
        self.assertIsNone(db.get_mempool_entry(compute_tx_hash(parked)),
                          "the park is on the winner and must not be queued again")

    def test_both_orphaned_return_in_sequence_order(self):
        parked = park(at_height=50)
        retracted = retract(rid_of(parked), seq=1)
        common = self.blocks(self.genesis_hash, [(1, [funding()])])
        fork_a = self.blocks(common[-1], [(2, [parked]), (3, [retracted])])
        fork_b = self.blocks(common[-1], [(2, []), (3, []), (4, [])])

        self.adopt(common + fork_a)
        self.reorg_to(fork_b)

        self.assertEqual(self.state()["escrow"], 0)
        self.assertIsNotNone(db.get_mempool_entry(compute_tx_hash(parked)))
        # The retract names an entry that no longer exists on the winner: it
        # cannot be re-admitted until its park is mined again.
        self.assertIsNone(db.get_mempool_entry(compute_tx_hash(retracted)))
