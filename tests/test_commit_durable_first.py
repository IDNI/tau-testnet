"""A live commit is durable before memory moves.

The non-authority path used to insert the block, publish the child into
memory, and only then write the canonical rows. A failure of that second
write left memory at a head disk does not have. The same window exists in
``reorg_to`` after the replay and before ``save_canonical_state_atomically``.

The fault calls the real canonical write and then raises, so the assertions
cover a rollback of rows that were actually staged, not only a failure that
happens before any write.
"""
import contextlib
import io
import json
import os
import sqlite3
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
import tau_authority
import tau_manager
from block import Block, compute_tx_hash

ADDR2 = "893c8134a31379c394b4ed31e67daf9565b1d2022aa96d83ca88d013bc208672bcf73dae5cc105da1e277109584239b2"
ADDR3 = "aabbccddee1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
TEST_MINER_PRIVKEY = "11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09"
BLOCK_TS = 1_700_000_100


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


def _memory():
    lm = chain_state._lifecycle_manager
    return {
        "balances": {k: int(v) for k, v in chain_state._balances.items()},
        "sequences": {k: int(v) for k, v in chain_state._sequence_numbers.items()},
        "last_transfer_ts": {k: int(v) for k, v in chain_state._last_transfer_ts.items()},
        "head": chain_state._canonical_head_hash,
        "tau_hash": chain_state._tau_engine_state_hash,
        "app_rules": chain_state._application_rules_state,
        "cons_rules": chain_state._consensus_rules_state,
        "active_consensus_id": chain_state._active_consensus_id,
        "lifecycle": lm,
        "meta": lm.consensus_meta_hash(),
    }


def _position(snap):
    """Chain position that a disk reload can reproduce.

    ``load_state_from_db`` builds a new lifecycle manager and clears the
    engine hash, and it stores a sequence of 0 for an account that exists
    only in the balance map. Missing and zero are the same account state.
    """
    balances = snap["balances"]
    sequences = snap["sequences"]
    keys = set(balances) | set(sequences)
    return {
        "balances": {k: int(balances.get(k, 0)) for k in keys},
        "sequences": {k: int(sequences.get(k, 0)) for k in keys},
        "last_transfer_ts": {
            k: int(v) for k, v in snap["last_transfer_ts"].items() if int(v)
        },
        "head": snap["head"],
        "app_rules": snap["app_rules"],
        "cons_rules": snap["cons_rules"],
        "meta": snap["meta"],
    }


@contextlib.contextmanager
def _quiet():
    with contextlib.redirect_stdout(io.StringIO()):
        yield


class CanonicalWriteFault:
    """Run the real canonical-row write, then raise a disk error."""

    def __init__(self):
        self.calls = 0
        self._real = None

    def __enter__(self):
        self._real = db._write_canonical_state_rows

        def boom(*args, **kwargs):
            self.calls += 1
            self._real(*args, **kwargs)
            raise sqlite3.OperationalError("disk I/O error")

        db._write_canonical_state_rows = boom
        return self

    def __exit__(self, exc_type, exc, tb):
        db._write_canonical_state_rows = self._real
        return False


class DurableFirstTestBase(unittest.TestCase):
    def setUp(self):
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(self.temp_db_fd)
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.temp_db_path)

        self._saved_balances = dict(chain_state._balances)
        self._saved_sequences = dict(chain_state._sequence_numbers)
        self._saved_lts = dict(chain_state._last_transfer_ts)
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._last_transfer_ts.clear()

        self._owner = tau_authority.owner()
        self._owner_enabled = self._owner.enabled
        self._owner.enabled = False

        self._tau_test_mode = tau_manager.tau_test_mode
        self._tau_ready = tau_manager.tau_ready.is_set()
        tau_manager.tau_test_mode = True
        tau_manager.tau_ready.set()

        self.original_auto_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False
        self.original_miner_privkey = config.MINER_PRIVKEY
        self.original_miner_pubkey = config.MINER_PUBKEY
        config.MINER_PRIVKEY = TEST_MINER_PRIVKEY

        db._db_conn = None
        db.init_db()
        db.clear_mempool()
        with _quiet():
            chain_state.load_genesis("data/genesis.json")

        self.verify_patch = patch(
            'consensus.engine.TauConsensusEngine.verify_block_header', return_value=True)
        self.verify_patch.start()
        self.os_env_patch = patch.dict("os.environ", {"TAU_FORCE_TEST": "1", "TAU_ENV": "test"})
        self.os_env_patch.start()

        funded = max(chain_state._balances.items(), key=lambda kv: int(kv[1]))
        self.sender = funded[0]
        self.funded = int(funded[1])
        self.genesis_hash = db.get_canonical_head()['block_hash']
        # createblock refuses to propose unless the configured key is in the
        # active set. Header proofs are patched, so any genesis validator works.
        validators = sorted(chain_state._lifecycle_manager.active_validators)
        if validators:
            config.MINER_PUBKEY = validators[0]

    def tearDown(self):
        self.verify_patch.stop()
        self.os_env_patch.stop()
        config.TESTNET_AUTO_FAUCET = self.original_auto_faucet
        config.MINER_PRIVKEY = self.original_miner_privkey
        config.MINER_PUBKEY = self.original_miner_pubkey
        tau_manager.tau_test_mode = self._tau_test_mode
        if self._tau_ready:
            tau_manager.tau_ready.set()
        else:
            tau_manager.tau_ready.clear()
        self._owner.enabled = self._owner_enabled
        chain_state._balances.clear()
        chain_state._balances.update(self._saved_balances)
        chain_state._sequence_numbers.clear()
        chain_state._sequence_numbers.update(self._saved_sequences)
        chain_state._last_transfer_ts.clear()
        chain_state._last_transfer_ts.update(self._saved_lts)
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)
        config.set_database_path(self.original_db_path)

    def _extending_block(self, transfers, timestamp=BLOCK_TS, proposer="a" * 96):
        block = Block.create(
            block_number=1,
            previous_hash=self.genesis_hash,
            transactions=[_tx(self.sender, 0, transfers)],
            proposer_pubkey=proposer,
            timestamp=timestamp,
        )
        # Empty skips the state-hash check. The transfer still moves balances,
        # sequences and last_transfer_ts inside the snapshot that would be
        # published.
        block.header.state_hash = ""
        return block

    def assert_memory_unchanged(self, before):
        after = _memory()
        self.assertIs(after["lifecycle"], before["lifecycle"])
        self.assertEqual(after["meta"], before["meta"])
        for key in (
            "balances", "sequences", "last_transfer_ts", "head", "tau_hash",
            "app_rules", "cons_rules", "active_consensus_id",
        ):
            self.assertEqual(after[key], before[key], key)

    def assert_disk_is_genesis(self):
        head = db.get_canonical_head()
        self.assertIsNotNone(head)
        self.assertEqual(head['block_hash'], self.genesis_hash)
        self.assertEqual(head['header']['block_number'], 0)

    def assert_reload_matches_memory(self):
        live = _position(_memory())
        with _quiet():
            loaded = chain_state.load_state_from_db()
        self.assertTrue(loaded)
        self.assertEqual(_position(_memory()), live)


class TestProcessNewBlockDurableFirst(DurableFirstTestBase):
    def test_failed_canonical_write_keeps_parent_then_retries_clean(self):
        block = self._extending_block([[self.sender, ADDR2, "5"]])
        tx_hash = compute_tx_hash(block.transactions[0])
        before = _memory()

        fault = CanonicalWriteFault()
        with fault, _quiet():
            accepted = chain_state.process_new_block(block)

        self.assertGreaterEqual(fault.calls, 1, "the canonical write was never attempted")
        self.assertFalse(accepted)
        self.assert_memory_unchanged(before)
        self.assert_disk_is_genesis()
        self.assertIsNone(db.get_block_by_hash(block.block_hash))
        self.assertEqual(db.get_tx_block_locations(tx_hash), [])
        self.assert_reload_matches_memory()

        with _quiet():
            accepted = chain_state.process_new_block(block)
        self.assertTrue(accepted)
        self.assertEqual(chain_state._canonical_head_hash, block.block_hash)
        self.assertEqual(db.get_canonical_head()['block_hash'], block.block_hash)
        self.assertIsNotNone(db.get_block_by_hash(block.block_hash))
        self.assertEqual(chain_state.get_balance(self.sender), self.funded - 5)
        self.assertEqual(chain_state.get_balance(ADDR2), 5)
        self.assertEqual(chain_state.get_sequence_number(self.sender), 1)
        self.assertEqual(chain_state._last_transfer_ts.get(self.sender), BLOCK_TS)
        self.assertEqual(db.get_tx_block_locations(tx_hash)[0]["block_hash"], block.block_hash)
        self.assert_reload_matches_memory()


class TestCreateBlockDurableFirst(DurableFirstTestBase):
    def test_failed_persist_returns_the_batch_then_mines_it(self):
        from commands import createblock

        tx = _tx(self.sender, 0, [[self.sender, ADDR2, "5"]])
        tx_hash = compute_tx_hash(tx)
        db.add_mempool_tx(json.dumps(tx), tx_hash, 1_700_000_000_000)
        before = _memory()

        fault = CanonicalWriteFault()
        with fault, _quiet():
            failed = createblock.create_block_from_mempool()

        self.assertGreaterEqual(
            fault.calls, 1, "createblock never reached the canonical write: %r" % (failed,))
        self.assertIn("error", failed)
        self.assert_memory_unchanged(before)
        self.assert_disk_is_genesis()
        self.assertEqual(db.get_tx_block_locations(tx_hash), [])
        entry = db.get_mempool_entry(tx_hash)
        self.assertIsNotNone(entry, "the transaction was dropped instead of returned")
        self.assertEqual(entry["status"], "pending")
        with db._db_lock:
            dropped = db._db_conn.execute(
                "SELECT 1 FROM mempool_dropped WHERE tx_hash = ?", (tx_hash,)
            ).fetchone()
        self.assertIsNone(dropped)

        with _quiet():
            mined = createblock.create_block_from_mempool()
        self.assertIn("block_hash", mined, mined)
        self.assertEqual(len(mined["transactions"]), 1)
        self.assertEqual(mined["transactions"][0]["sender_pubkey"], self.sender)
        self.assertEqual(db.get_canonical_head()['block_hash'], mined["block_hash"])
        self.assertEqual(chain_state._canonical_head_hash, mined["block_hash"])
        self.assertEqual(chain_state.get_balance(self.sender), self.funded - 5)
        self.assertEqual(chain_state.get_sequence_number(self.sender), 1)
        self.assertIsNone(db.get_mempool_entry(tx_hash))
        self.assert_reload_matches_memory()


class TestReorgDurableFirst(DurableFirstTestBase):
    def test_failed_phase4_save_restores_the_prior_head(self):
        a1 = self._extending_block(
            [[self.sender, ADDR2, "5"]], timestamp=BLOCK_TS, proposer="a" * 96)
        b1 = self._extending_block(
            [[self.sender, ADDR3, "7"]], timestamp=BLOCK_TS + 100, proposer="b" * 96)
        # Rebuild skips a hash of "" or 64 zeros, and these blocks must replay
        # cleanly so the failure under test is the canonical save, not the replay.
        a1.header.state_hash = "0" * 64
        b1.header.state_hash = "0" * 64

        db.add_block(a1)
        db.add_block(b1)
        with _quiet():
            self.assertTrue(chain_state.reorg_to(a1.block_hash))
        self.assertEqual(db.get_canonical_head()['block_hash'], a1.block_hash)
        self.assertEqual(chain_state.get_balance(ADDR2), 5)
        self.assertEqual(chain_state.get_balance(ADDR3), 0)
        at_a1 = _memory()

        fault = CanonicalWriteFault()
        with fault, _quiet():
            advanced = chain_state.reorg_to(b1.block_hash)

        self.assertGreaterEqual(fault.calls, 1, "the Phase 4 save was never attempted")
        self.assertFalse(advanced)
        after = _memory()
        self.assertEqual(after["meta"], at_a1["meta"])
        for key in (
            "balances", "sequences", "last_transfer_ts", "head", "tau_hash",
            "app_rules", "cons_rules", "active_consensus_id",
        ):
            self.assertEqual(after[key], at_a1[key], key)
        self.assertEqual(db.get_canonical_head()['block_hash'], a1.block_hash)
        self.assertEqual(chain_state.get_balance(ADDR2), 5)
        self.assertEqual(chain_state.get_balance(ADDR3), 0)
        self.assertEqual(chain_state.get_balance(self.sender), self.funded - 5)


if __name__ == '__main__':
    unittest.main()
