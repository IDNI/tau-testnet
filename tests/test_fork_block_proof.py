"""A fork block must carry a valid proposer signature before it can be adopted.

Fork choice is the higher chain, then the lower hash. Peers deliver blocks through
`ingest_block`, and a fork that is not a pure extension of the head is adopted by a
state rebuild. A peer without the validator's key must not be able to publish a
longer fork that names the validator as proposer.

Mock engine; o6 is fed back as i10 (the shipped consensus rule is `o6 = i10`), so
the proof verdict the host computes is the only thing deciding block validity.
"""
import os
import subprocess
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
from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, pubkey_hex, sign_header

VALIDATOR_SK = SK_ALICE
VALIDATOR = pubkey_hex(VALIDATOR_SK)
BASE_TS = 1_700_000_000
JUNK_PROOF = "ab" * 96


def _consensus_tau(**kwargs):
    return str(kwargs["input_stream_values"][10])


def _consensus_tau_multi(**kwargs):
    return {6: str(kwargs["input_stream_values"][10]), 7: "#x0001"}


class ForkBlockProofTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.genesis_dir = tempfile.TemporaryDirectory()
        cls.genesis_path = os.path.join(cls.genesis_dir.name, "genesis.json")
        subprocess.run(
            [sys.executable, os.path.join(project_root, "scripts", "gen_genesis.py"),
             "--validator-privkey", f"{VALIDATOR_SK:064x}", "--out", cls.genesis_path],
            check=True, capture_output=True, cwd=project_root,
        )

    @classmethod
    def tearDownClass(cls):
        cls.genesis_dir.cleanup()

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(fd)
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.db_path)
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db._db_conn = None
        db.init_db()
        db.clear_mempool()
        chain_state.load_genesis(self.genesis_path)
        self.original_auto_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False
        self.patches = [
            patch.object(tau_manager, "communicate_with_tau", _consensus_tau),
            patch.object(tau_manager, "communicate_with_tau_multi", _consensus_tau_multi),
            patch.object(tau_manager.tau_ready, "is_set", return_value=True),
            patch.object(tau_manager.tau_ready, "wait", return_value=True),
        ]
        for p in self.patches:
            p.start()
        self.genesis_hash = db.get_genesis_hash()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        config.TESTNET_AUTO_FAUCET = self.original_auto_faucet
        config.set_database_path(self.original_db_path)
        if getattr(db, '_db_conn', None) is not None:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def head(self):
        return db.get_canonical_head()['block_hash']

    def block(self, number, previous_hash, proof_key, offset=0):
        blk = Block.create(
            block_number=number, previous_hash=previous_hash, transactions=[],
            proposer_pubkey=VALIDATOR, timestamp=BASE_TS + number + offset,
        )
        blk.consensus_proof = sign_header(blk.header, proof_key) if proof_key else JUNK_PROOF
        return blk

    def adopt_canonical_block(self):
        a1 = self.block(1, self.genesis_hash, VALIDATOR_SK)
        self.assertEqual(chain_state.ingest_block(a1).status, 'added')
        self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), a1.block_hash)
        return a1

    def forged_fork(self, proof_key_1, proof_key_2):
        b1 = self.block(1, self.genesis_hash, proof_key_1, offset=7)
        b2 = self.block(2, b1.block_hash, proof_key_2, offset=7)
        return b1, b2

    def assert_fork_is_refused(self, proof_key_1, proof_key_2):
        a1 = self.adopt_canonical_block()
        b1, b2 = self.forged_fork(proof_key_1, proof_key_2)
        results = [chain_state.ingest_block(b).status for b in (b1, b2)]
        chain_state.maybe_update_canonical_head()
        self.assertEqual(self.head(), a1.block_hash, "the forged fork became canonical")
        for key, status in zip((proof_key_1, proof_key_2), results):
            if key != VALIDATOR_SK:
                self.assertEqual(status, 'invalid')
        self.assertIsNone(db.get_block_by_hash(b2.block_hash))

    def test_fork_signed_by_a_different_key_is_not_adopted(self):
        self.assert_fork_is_refused(SK_MALLORY, SK_BOB)

    def test_fork_with_a_junk_proof_is_not_adopted(self):
        self.assert_fork_is_refused(None, None)

    def test_a_fork_with_a_forged_tip_only_is_not_adopted(self):
        self.assert_fork_is_refused(VALIDATOR_SK, SK_MALLORY)

    def test_a_properly_signed_longer_fork_is_adopted(self):
        self.adopt_canonical_block()
        b1, b2 = self.forged_fork(VALIDATOR_SK, VALIDATOR_SK)
        for b in (b1, b2):
            self.assertEqual(chain_state.ingest_block(b).status, 'added')
        self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), b2.block_hash)
