"""A block's body must be what its header's merkle_root commits to: the block
hash covers only the header, so an unchecked body can be edited under it."""
import contextlib
import io
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
import db
import chain_state
import tau_authority
import tau_manager
from chain_state import GENESIS_ADDRESS, GENESIS_BALANCE
from block import Block, BlockHeader, compute_merkle_root, compute_tx_hash, sha256_hex
from consensus.engine import TauConsensusEngine

SENDER = "a" * 96
RECIPIENT = "b" * 96
PROPOSER = "c" * 96
BASE_TS = 1_700_000_000

CANONICAL_GENESIS_PATH = os.path.join(project_root, "networks", "tau-testnet-v2", "genesis.json")
NODE_GENESIS_PATH = os.path.join(project_root, "data", "genesis.json")


def _tx(seq, amount=1):
    return {
        "sender_pubkey": SENDER,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "operations": {"1": [[SENDER, RECIPIENT, str(amount)]]},
        "fee_limit": "0",
        "signature": "dummy_signature_for_testing",
    }


def _txs(count):
    return [_tx(seq) for seq in range(count)]


def _block(txs, number=1, previous_hash="11" * 32):
    return Block.create(
        block_number=number, previous_hash=previous_hash, transactions=txs,
        proposer_pubkey=PROPOSER, timestamp=BASE_TS + number,
    )


def _wire(block):
    """The block as a peer sends it: through JSON, free to be edited."""
    return json.loads(json.dumps(block.to_dict()))


def _restamp(payload):
    """Recompute `tx_ids` from the (edited) transactions; the header stays as it was."""
    payload["tx_ids"] = [compute_tx_hash(tx) for tx in payload["transactions"]]
    return payload


def _unchecked(payload):
    """A Block built from a payload without `from_dict`'s verification."""
    return Block(
        header=BlockHeader(**payload["header"]),
        transactions=payload["transactions"],
        block_hash=payload["block_hash"],
        consensus_proof=payload.get("consensus_proof"),
        tx_ids=payload.get("tx_ids", []),
    )


def _grow_last(payload):
    """[a, b, c] -> [a, b, c, c], with `tx_ids` recomputed to match."""
    payload["transactions"].append(dict(payload["transactions"][-1]))
    return _restamp(payload)


@contextlib.contextmanager
def quiet():
    """Swallow the rebuild's per-block prints."""
    with contextlib.redirect_stdout(io.StringIO()):
        yield


class TestHonestBodiesAreAccepted(unittest.TestCase):
    def test_blocks_with_three_and_four_transactions(self):
        for count in (3, 4):
            with self.subTest(transactions=count):
                block = _block(_txs(count))
                self.assertEqual(block.verify_body(), (True, ""))
                self.assertEqual(Block.from_dict(block.to_dict()).block_hash, block.block_hash)

    def test_empty_block(self):
        block = _block([])
        self.assertEqual(block.header.merkle_root, compute_merkle_root([]))
        self.assertEqual(block.verify_body(), (True, ""))
        self.assertEqual(Block.from_dict(block.to_dict()).tx_ids, [])

    def test_to_dict_round_trip_keeps_the_body(self):
        block = _block(_txs(3))
        again = Block.from_dict(block.to_dict())
        self.assertEqual(again.transactions, block.transactions)
        self.assertEqual(again.tx_ids, block.tx_ids)
        self.assertEqual(again.header, block.header)

    def test_json_round_trip(self):
        block = _block(_txs(4))
        again = Block.from_dict(json.loads(json.dumps(block.to_dict())))
        self.assertEqual(again.tx_ids, block.tx_ids)
        self.assertEqual(again.verify_body(), (True, ""))

    def test_payload_without_tx_ids_gets_them_computed(self):
        block = _block(_txs(3))
        for label, edit in (("absent", lambda p: p.pop("tx_ids")),
                            ("null", lambda p: p.update(tx_ids=None))):
            with self.subTest(tx_ids=label):
                payload = _wire(block)
                edit(payload)
                again = Block.from_dict(payload)
                self.assertEqual(again.tx_ids, block.tx_ids)
                self.assertEqual(again.verify_body(), (True, ""))

    def test_genesis_style_block_zero(self):
        payload = {
            "header": {
                "block_number": 0, "previous_hash": "0" * 64, "timestamp": 0,
                "merkle_root": "0" * 64, "state_hash": "0" * 64, "proposer_pubkey": "0" * 96,
            },
            "transactions": [],
            "consensus_proof": {},
            "hash": "ab" * 32,
        }
        block = Block.from_dict(payload)
        self.assertEqual(block.verify_body(), (True, ""))
        self.assertEqual(block.tx_ids, [])

    def test_block_zero_keeps_its_lenient_tx_ids_handling(self):
        payload = {
            "header": {
                "block_number": 0, "previous_hash": "0" * 64, "timestamp": 0,
                "merkle_root": "0" * 64, "state_hash": "0" * 64, "proposer_pubkey": "0" * 96,
            },
            "transactions": [],
            "tx_ids": "not a list",
            "hash": "ab" * 32,
        }
        self.assertEqual(Block.from_dict(payload).tx_ids, [])

    def test_real_genesis_block_zero(self):
        paths = [p for p in (CANONICAL_GENESIS_PATH, NODE_GENESIS_PATH) if os.path.exists(p)]
        self.assertTrue(paths, "the committed genesis artifact must exist")
        for path in paths:
            with self.subTest(path=os.path.relpath(path, project_root)):
                with open(path, "r", encoding="utf-8") as f:
                    block_0 = json.load(f)["block_0"]
                block = Block.from_dict(block_0)
                self.assertEqual(block.block_hash, block_0["hash"])
                self.assertEqual(block.verify_body(), (True, ""))


class TestTamperedBodiesAreRejected(unittest.TestCase):
    def setUp(self):
        self.honest = _block(_txs(3))

    def assertRejected(self, payload, reason_fragment):
        with self.assertRaises(ValueError) as ctx:
            Block.from_dict(payload)
        self.assertIn("body mismatch", str(ctx.exception))
        self.assertIn("block_number 1", str(ctx.exception))
        ok, reason = _unchecked(payload).verify_body()
        self.assertFalse(ok)
        self.assertIn(reason_fragment, reason)

    def test_extra_transaction_appended(self):
        # a sequence number apply would reject; the relayer needs no valid tx
        payload = _wire(self.honest)
        payload["transactions"].append(_tx(999))
        self.assertRejected(payload, "tx_ids")

        self.assertRejected(_restamp(payload), "merkle_root")

    def test_transaction_dropped(self):
        payload = _wire(self.honest)
        del payload["transactions"][1]
        self.assertRejected(payload, "tx_ids")

        self.assertRejected(_restamp(payload), "merkle_root")

    def test_transactions_reordered(self):
        payload = _wire(self.honest)
        txs = payload["transactions"]
        txs[0], txs[1] = txs[1], txs[0]
        self.assertRejected(payload, "tx_ids")

        self.assertRejected(_restamp(payload), "merkle_root")

    def test_transaction_replaced(self):
        payload = _wire(self.honest)
        payload["transactions"][2] = _tx(2, amount=999)
        self.assertRejected(payload, "tx_ids")

        self.assertRejected(_restamp(payload), "merkle_root")

    def test_forged_tx_ids_with_intact_body(self):
        ids = self.honest.tx_ids
        forgeries = {
            "one id altered": [ids[0], "f" * 64, ids[2]],
            "an id the block does not hold": ids + ["f" * 64],
            "an id removed": ids[:-1],
            "ids reordered": list(reversed(ids)),
            "ids emptied": [],
        }
        for label, forged in forgeries.items():
            with self.subTest(forgery=label):
                payload = _wire(self.honest)
                payload["tx_ids"] = forged
                self.assertRejected(payload, "tx_ids")

    def test_malformed_tx_ids(self):
        malformed = {
            "a string": "".join(self.honest.tx_ids),
            "an empty string": "",
            "ints": [1, 2, 3],
            "a mix": [self.honest.tx_ids[0], 7, self.honest.tx_ids[2]],
            "a dict": {"0": self.honest.tx_ids[0]},
        }
        for label, junk in malformed.items():
            with self.subTest(tx_ids=label):
                payload = _wire(self.honest)
                payload["tx_ids"] = junk
                self.assertRejected(payload, "tx_ids")

    def test_header_root_replaced_with_a_consistent_hash(self):
        # The hash is honestly recomputed over the lying header; only the body can tell.
        payload = _wire(self.honest)
        payload["header"]["merkle_root"] = compute_merkle_root([])
        payload["block_hash"] = sha256_hex(BlockHeader(**payload["header"]).canonical_bytes())
        self.assertRejected(payload, "merkle_root")

    def test_header_root_edited_without_rehashing_is_a_hash_mismatch(self):
        payload = _wire(self.honest)
        payload["header"]["merkle_root"] = compute_merkle_root([])
        with self.assertRaises(ValueError) as ctx:
            Block.from_dict(payload)
        self.assertIn("hash mismatch", str(ctx.exception))

    def test_root_must_be_the_exact_lowercase_digest(self):
        # bytes.fromhex ignores case, so the hash does not change
        payload = _wire(self.honest)
        payload["header"]["merkle_root"] = payload["header"]["merkle_root"].upper()
        self.assertEqual(
            sha256_hex(BlockHeader(**payload["header"]).canonical_bytes()), payload["block_hash"])
        self.assertRejected(payload, "merkle_root")

    def test_rejection_does_not_poison_the_honest_copy(self):
        payload = _wire(self.honest)
        payload["transactions"].append(_tx(999))
        with self.assertRaises(ValueError):
            Block.from_dict(payload)
        again = Block.from_dict(_wire(self.honest))
        self.assertEqual(again.block_hash, self.honest.block_hash)


class TestDuplicateTransactions(unittest.TestCase):
    def test_duplicated_last_transaction_shares_the_root_but_is_rejected(self):
        honest = _block(_txs(3))
        payload = _grow_last(_wire(honest))

        # The ambiguity: an odd level repeats its last node, so the roots are equal.
        self.assertEqual(compute_merkle_root(payload["tx_ids"]), honest.header.merkle_root)
        self.assertEqual(payload["block_hash"], honest.block_hash)

        with self.assertRaises(ValueError) as ctx:
            Block.from_dict(payload)
        self.assertIn("duplicate", str(ctx.exception))
        ok, reason = _unchecked(payload).verify_body()
        self.assertFalse(ok)
        self.assertIn("duplicate", reason)

    def test_inner_duplication_shares_the_root_but_is_rejected(self):
        honest = _block(_txs(6))
        payload = _wire(honest)
        txs = payload["transactions"]
        txs.extend([dict(txs[4]), dict(txs[5])])
        _restamp(payload)

        self.assertEqual(compute_merkle_root(payload["tx_ids"]), honest.header.merkle_root)

        with self.assertRaises(ValueError) as ctx:
            Block.from_dict(payload)
        self.assertIn("duplicate", str(ctx.exception))
        ok, reason = _unchecked(payload).verify_body()
        self.assertFalse(ok)
        self.assertIn("duplicate", reason)

    def test_the_same_transaction_twice_in_a_created_block_is_rejected(self):
        block = _block([_tx(0), _tx(0)])
        ok, reason = block.verify_body()
        self.assertFalse(ok)
        self.assertIn("duplicate", reason)

    def test_the_honest_original_of_a_duplicated_block_is_still_accepted(self):
        honest = _block(_txs(3))
        with self.assertRaises(ValueError):
            Block.from_dict(_grow_last(_wire(honest)))
        self.assertEqual(Block.from_dict(_wire(honest)).block_hash, honest.block_hash)


class TestVerifyBodyNeverRaises(unittest.TestCase):
    def test_unhashable_transactions(self):
        circular = {}
        circular["self"] = circular
        junk = {
            "not json": [{"a": {1, 2}}],
            "circular": [circular],
            "not a list": None,
        }
        for label, transactions in junk.items():
            with self.subTest(transactions=label):
                block = _block([])
                block.transactions = transactions
                ok, reason = block.verify_body()
                self.assertFalse(ok)
                self.assertIn("cannot be hashed", reason)

    def test_any_hashing_failure_is_a_rejection(self):
        block = _block(_txs(2))
        for exc in (TypeError("x"), ValueError("x"), RecursionError("x"), OverflowError("x")):
            with self.subTest(exception=type(exc).__name__), \
                    patch("block.compute_tx_hash", side_effect=exc):
                ok, reason = block.verify_body()
                self.assertFalse(ok)
                self.assertIn("cannot be hashed", reason)

    def test_non_list_tx_ids(self):
        block = _block(_txs(2))
        for junk in (None, "abc", 7, {"a": 1}, tuple(block.tx_ids)):
            with self.subTest(tx_ids=junk):
                block.tx_ids = junk
                self.assertFalse(block.verify_body()[0])


class ChainTestCase(unittest.TestCase):
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
        self.verify_mock = self.verify_patch.start()
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

    def head(self):
        return db.get_canonical_head()['block_hash']

    def make(self, number, txs, previous_hash=None, proposer=SENDER):
        return Block.create(
            block_number=number, previous_hash=previous_hash or self.genesis_hash,
            transactions=txs, proposer_pubkey=proposer, timestamp=BASE_TS + number,
        )

    def tampered_copy(self, block):
        """The same block as a relayer would alter it: an extra transaction, header
        and hash untouched."""
        payload = _wire(block)
        payload["transactions"].append(_tx(999))
        return _unchecked(payload)

    def adopt(self, blocks):
        for blk in blocks:
            self.assertEqual(chain_state.ingest_block(blk).status, 'added')
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), blocks[-1].block_hash)

    def rewrite_stored(self, block_hash, edit):
        """Alter a stored block row in place, as a database written by a node that
        did not verify bodies would hold it."""
        data = db.get_block_by_hash(block_hash)
        edit(data)
        with db._db_lock:
            db._db_conn.execute(
                "UPDATE blocks SET block_data = ? WHERE block_hash = ?",
                (json.dumps(data), block_hash))
            db._db_conn.commit()


class TestIngestBlock(ChainTestCase):
    def test_tampered_body_is_refused_before_header_verification(self):
        honest = self.make(1, _txs(3))
        tampered = self.tampered_copy(honest)
        self.assertEqual(tampered.block_hash, honest.block_hash)

        with self.assertLogs('chain_state', level='WARNING') as logs:
            result = chain_state.ingest_block(tampered)

        self.assertEqual(result.status, 'invalid')
        self.assertIn("body", result.message)
        self.assertIn("tx_ids", result.message)
        self.verify_mock.assert_not_called()
        self.assertIsNone(db.get_block_by_hash(honest.block_hash))
        self.assertIn("not ingested", logs.output[0])

    def test_tampered_body_is_not_stored_as_an_orphan_either(self):
        honest = self.make(5, _txs(3), previous_hash="e" * 64)
        result = chain_state.ingest_block(self.tampered_copy(honest))
        self.assertEqual(result.status, 'invalid')
        self.assertIsNone(db.get_block_by_hash(honest.block_hash))
        self.assertEqual(db.get_tx_block_locations(compute_tx_hash(_tx(999))), [])

    def test_forged_tx_ids_cannot_confirm_a_transaction(self):
        honest = self.make(1, _txs(3))
        payload = _wire(honest)
        fake_id = compute_tx_hash(_tx(999))
        payload["tx_ids"].append(fake_id)

        self.assertEqual(chain_state.ingest_block(_unchecked(payload)).status, 'invalid')
        self.assertEqual(db.get_tx_block_locations(fake_id), [])

    def test_the_honest_copy_of_a_refused_block_is_still_accepted(self):
        honest = self.make(1, _txs(3))
        self.assertEqual(chain_state.ingest_block(self.tampered_copy(honest)).status, 'invalid')

        result = chain_state.ingest_block(honest)

        self.assertEqual(result.status, 'added')
        self.assertEqual(db.get_block_by_hash(honest.block_hash)["tx_ids"], honest.tx_ids)
        self.assertEqual(chain_state.ingest_block(self.tampered_copy(honest)).status, 'invalid')
        self.assertEqual(chain_state.ingest_block(honest).status, 'known')


class TestProcessNewBlock(ChainTestCase):
    def setUp(self):
        super().setUp()
        # The mock engine's state hash never equals the header's default; an empty
        # state_hash skips that invariant, as test_block_timestamp_validation.py does.
        self.honest = self.make(1, [], proposer=config.MINER_PUBKEY)
        self.honest.header.state_hash = ""

    def test_tampered_body_is_rejected_before_any_evaluation(self):
        tampered = self.tampered_copy(self.honest)
        head_before = self.head()

        with patch.object(TauConsensusEngine, 'apply_block') as apply_block, \
                self.assertLogs('chain_state', level='ERROR') as logs:
            self.assertFalse(chain_state.process_new_block(tampered))

        self.verify_mock.assert_not_called()
        apply_block.assert_not_called()
        self.assertEqual(self.head(), head_before)
        self.assertEqual(chain_state._canonical_head_hash, head_before)
        self.assertIsNone(db.get_block_by_hash(self.honest.block_hash))
        self.assertIn("body does not match its header", logs.output[0])

    def test_the_honest_copy_of_a_rejected_block_is_still_accepted(self):
        self.assertFalse(chain_state.process_new_block(self.tampered_copy(self.honest)))

        self.assertTrue(chain_state.process_new_block(self.honest))

        self.assertEqual(self.head(), self.honest.block_hash)

    def test_a_tampered_block_that_does_not_extend_the_head_is_rejected_too(self):
        side = self.make(1, [], previous_hash="e" * 64)
        self.assertFalse(chain_state.process_new_block(self.tampered_copy(side)))
        self.assertIsNone(db.get_block_by_hash(side.block_hash))


class TestStoredTamperedBodies(ChainTestCase):
    def setUp(self):
        super().setUp()
        self.chain = []
        prev = self.genesis_hash
        for n in (1, 2, 3):
            blk = self.make(n, [], previous_hash=prev)
            self.chain.append(blk)
            prev = blk.block_hash
        self.adopt(self.chain)

    def test_rebuild_stops_at_the_tampered_row(self):
        target = self.chain[1]
        self.rewrite_stored(target.block_hash, lambda d: d["transactions"].append(_tx(999)))

        with quiet():
            result = chain_state.rebuild_state_from_blockchain()

        self.assertFalse(result.ok)
        self.assertEqual(result.stopped_at_block, 2)
        self.assertIn("body mismatch", result.reason)
        self.assertEqual(chain_state._canonical_head_hash, self.chain[0].block_hash)

    def test_rebuild_of_the_untouched_chain_succeeds(self):
        with quiet():
            result = chain_state.rebuild_state_from_blockchain()
        self.assertTrue(result.ok)
        self.assertEqual(chain_state._canonical_head_hash, self.chain[-1].block_hash)

    def test_a_forged_tx_ids_row_stops_the_rebuild_too(self):
        target = self.chain[0]
        self.rewrite_stored(target.block_hash, lambda d: d["tx_ids"].append("f" * 64))

        with quiet():
            result = chain_state.rebuild_state_from_blockchain()

        self.assertFalse(result.ok)
        self.assertEqual(result.stopped_at_block, 1)

    def test_extension_stops_at_a_stored_tampered_block_without_raising(self):
        tip = self.make(4, [], previous_hash=self.chain[-1].block_hash)
        db.add_block(self.tampered_copy(tip))

        with patch.object(chain_state, '_process_new_block_locked') as process, \
                self.assertLogs('chain_state', level='ERROR') as logs:
            extended = chain_state._extend_through_commit_protocol([tip.block_hash], tip.block_hash)

        self.assertFalse(extended)
        process.assert_not_called()
        self.assertEqual(self.head(), self.chain[-1].block_hash)
        self.assertIn("not a valid block", logs.output[0])

    def test_reorg_onto_a_stored_tampered_block_keeps_the_head(self):
        tip = self.make(4, [], previous_hash=self.chain[-1].block_hash)
        db.add_block(self.tampered_copy(tip))
        owner = type("Owner", (), {"enabled": True})()

        with patch.object(tau_authority, "owner", return_value=owner), \
                self.assertLogs('chain_state', level='ERROR'):
            self.assertFalse(chain_state.reorg_to(tip.block_hash))

        self.assertEqual(self.head(), self.chain[-1].block_hash)


class TestMinedBlocksReverify(ChainTestCase):
    """The block createblock persists is the one every peer and every restart reads
    back, so its stored body must still match its header."""

    def setUp(self):
        super().setUp()
        self.original_miner_privkey = config.MINER_PRIVKEY
        config.MINER_PRIVKEY = "11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09"
        # Whatever validator the genesis in use names; header proofs are patched.
        validators = sorted(chain_state._lifecycle_manager.active_validators)
        self.original_miner_pubkey = config.MINER_PUBKEY
        if validators:
            config.MINER_PUBKEY = validators[0]
        self.mock_tau = MagicMock()
        self.mock_tau.tau_ready.is_set.return_value = True
        self.mock_tau.communicate_with_tau.return_value = "100"
        self.mock_tau.communicate_with_tau_multi.return_value = {1: "100"}
        self.patches = [
            patch('commands.createblock.tau_manager', self.mock_tau),
            patch('consensus.engine.tau_manager', self.mock_tau),
            patch('chain_state.tau_manager', self.mock_tau),
            patch('commands.createblock._validate_signature', return_value=True),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        config.MINER_PRIVKEY = self.original_miner_privkey
        config.MINER_PUBKEY = self.original_miner_pubkey
        super().tearDown()

    def test_mined_block_reverifies_from_its_stored_row(self):
        from commands import createblock

        sent = [
            {"sender_pubkey": sender * 96, "recipient": "b", "amount": 10,
             "operations": {"1": []}, "sequence_number": 0, "fee_limit": "0", "signature": "sig"}
            for sender in "acd"
        ]
        for n, tx in enumerate(sent):
            db.add_mempool_tx(json.dumps(tx), compute_tx_hash(tx), 1000 + n)

        mined = createblock.create_block_from_mempool()
        self.assertIn("block_hash", mined, mined)

        stored = db.get_canonical_head()
        self.assertEqual(stored["block_hash"], mined["block_hash"])
        self.assertEqual(stored["header"]["block_number"], 1)
        self.assertEqual(len(stored["transactions"]), 3)
        self.assertEqual(stored["tx_ids"], [compute_tx_hash(tx) for tx in sent])
        again = Block.from_dict(stored)
        self.assertEqual(again.verify_body(), (True, ""))

        from scripts import verify_block_bodies
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(verify_block_bodies.main([self.temp_db_path]), 0)


class TestDHTBlockRecords(unittest.TestCase):
    def setUp(self):
        from network.dht_manager import DHTManager
        from network.config import NetworkConfig

        self.dht_manager = DHTManager(MagicMock(spec=NetworkConfig))
        self.honest = _block(_txs(3))
        self.key = f"block:{self.honest.block_hash}".encode("ascii")

    def validate(self, payload):
        return self.dht_manager._validate_block_record(
            self.key, json.dumps(payload).encode("utf-8"))

    def test_honest_block_is_accepted(self):
        self.assertTrue(self.validate(_wire(self.honest)))

    def test_tampered_body_is_rejected(self):
        payload = _wire(self.honest)
        payload["transactions"].append(_tx(999))
        self.assertFalse(self.validate(payload))
        self.assertFalse(self.validate(_restamp(payload)))

    def test_forged_tx_ids_are_rejected(self):
        payload = _wire(self.honest)
        payload["tx_ids"].append("f" * 64)
        self.assertFalse(self.validate(payload))


class TestVerifyBlockBodiesScript(ChainTestCase):
    def run_scan(self):
        from scripts import verify_block_bodies

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = verify_block_bodies.main([self.temp_db_path])
        return code, out.getvalue(), err.getvalue()

    def test_clean_database_exits_zero(self):
        self.adopt([self.make(1, _txs(3))])

        code, out, _ = self.run_scan()

        self.assertEqual(code, 0, out)
        self.assertIn("2 ok, 0 failed", out)

    def test_tampered_row_exits_one_and_is_named(self):
        honest = self.make(1, _txs(3))
        tampered = self.make(2, _txs(2), previous_hash=honest.block_hash)
        self.adopt([honest, tampered])
        self.rewrite_stored(tampered.block_hash, lambda d: d["transactions"].append(_tx(999)))

        code, out, _ = self.run_scan()

        self.assertEqual(code, 1)
        self.assertIn(f"block #2 {tampered.block_hash[:16]}", out)
        self.assertNotIn(f"block #1 {honest.block_hash[:16]}", out)
        self.assertIn("tx_ids do not match", out)
        self.assertIn("2 ok, 1 failed", out)

    def test_row_stored_under_another_hash_is_reported(self):
        block = self.make(1, _txs(3))
        self.adopt([block])
        with db._db_lock:
            db._db_conn.execute(
                "UPDATE blocks SET block_hash = ? WHERE block_hash = ?",
                ("d" * 64, block.block_hash))
            db._db_conn.commit()

        code, out, _ = self.run_scan()

        self.assertEqual(code, 1)
        self.assertIn("is stored under", out)

    def test_unreadable_row_is_reported_not_fatal(self):
        block = self.make(1, _txs(3))
        self.adopt([block])
        with db._db_lock:
            db._db_conn.execute(
                "UPDATE blocks SET block_data = ? WHERE block_hash = ?",
                ("{not json", block.block_hash))
            db._db_conn.commit()

        code, out, _ = self.run_scan()

        self.assertEqual(code, 1)
        self.assertIn("1 failed", out)

    def test_scan_leaves_the_database_untouched(self):
        self.adopt([self.make(1, _txs(3))])
        with db._db_lock:
            before = list(db._db_conn.execute(
                "SELECT block_hash, block_data FROM blocks ORDER BY block_hash"))

        self.run_scan()

        with db._db_lock:
            after = list(db._db_conn.execute(
                "SELECT block_hash, block_data FROM blocks ORDER BY block_hash"))
        self.assertEqual(before, after)

    def test_missing_database_is_an_error_and_is_not_created(self):
        from scripts import verify_block_bodies

        missing = self.temp_db_path + ".missing"
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = verify_block_bodies.main([missing])

        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(missing))
        self.assertIn("cannot read", err.getvalue())

    def test_database_without_a_blocks_table_is_an_error(self):
        from scripts import verify_block_bodies

        empty = self.temp_db_path + ".empty"
        conn = sqlite3.connect(empty)
        conn.execute("CREATE TABLE unrelated (x)")
        conn.commit()
        conn.close()
        try:
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                code = verify_block_bodies.main([empty])
            self.assertEqual(code, 1)
        finally:
            os.remove(empty)


if __name__ == '__main__':
    unittest.main()
