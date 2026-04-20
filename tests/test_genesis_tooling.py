"""
Phase 6 — Genesis Tooling Tests

Golden-vector tests verifying deterministic hash generation from genesis.json,
trusted replay onto an empty DB, and fatal startup abort on DB mismatch.
"""
import json
import os
import sys
import tempfile
import unittest

# Ensure project root is importable
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
import db
import chain_state
from block import Block, BlockHeader, sha256_hex
from chain_state import compute_accounts_hash
from consensus.serialization import compute_consensus_meta_hash as cmh_serial
from consensus.state import compute_consensus_state_hash

GENESIS_PATH = os.path.join(project_root, "data", "genesis.json")

# ─── Golden Vectors (computed deterministically from data/genesis.json) ───
EXPECTED_BLOCK_HASH = "8642ab23996ec679def10e3267ab0b12f8eedfa7440317e6bb3f09506fd0a2e5"
EXPECTED_STATE_HASH = "d7373c0d2ab9b51315d022ad89f871fd3727c1be85a07bae9605b0b56ad50c93"
EXPECTED_ACCOUNTS_HASH = "e357576a464b7cd08de768c8edfaaf226b6e142cccbb743c62c5e0ea4e590790"
EXPECTED_META_HASH = "8ac08c336fe0a5fe7bf0b24631bc8e88e0a8111dd920aa9b803f293212cecf75"


def _load_genesis():
    with open(GENESIS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


class TestGoldenVectors(unittest.TestCase):
    """Verify that genesis.json hashes are cross-platform deterministic."""

    @classmethod
    def setUpClass(cls):
        cls.genesis = _load_genesis()

    def test_block_hash(self):
        """Block 0 hash derives deterministically from canonical header bytes."""
        block = Block.from_dict(self.genesis["block_0"])
        self.assertEqual(block.block_hash, EXPECTED_BLOCK_HASH)

    def test_block_hash_matches_artifact(self):
        """genesis.json's embedded hash field matches the computed block hash."""
        block = Block.from_dict(self.genesis["block_0"])
        self.assertEqual(block.block_hash, self.genesis["block_0"]["hash"])

    def test_state_hash(self):
        """state_hash derives deterministically from the four committed domains."""
        g = self.genesis
        validator_key = g["consensus_meta"]["active_validators"][0]
        validator_bytes = bytes.fromhex(validator_key)

        accts = g["accounts_state"]
        seqs = {addr: 0 for addr in accts}
        accounts_hash = compute_accounts_hash(accts, seqs)

        host_contract = {
            "proof_scheme": "bls_header_sig",
            "fork_choice_scheme": "height_then_hash",
            "input_contract_version": 1,
        }
        meta_hash = cmh_serial(
            host_contract=host_contract,
            active_validators=[validator_bytes],
            pending_updates=[],
            vote_records=[],
            activation_schedule=[],
            checkpoint_references=[],
            mechanism_specific_metadata={},
        )

        state_hash = compute_consensus_state_hash(
            g["consensus_rules"].encode("utf-8"),
            g["application_rules"].encode("utf-8"),
            accounts_hash,
            meta_hash,
        )

        self.assertEqual(state_hash, EXPECTED_STATE_HASH)

    def test_accounts_hash(self):
        """accounts_hash matches expected golden vector."""
        g = self.genesis
        accts = g["accounts_state"]
        seqs = {addr: 0 for addr in accts}
        accounts_hash = compute_accounts_hash(accts, seqs)
        self.assertEqual(accounts_hash.hex(), EXPECTED_ACCOUNTS_HASH)

    def test_consensus_meta_hash(self):
        """consensus_meta_hash matches expected golden vector."""
        g = self.genesis
        validator_key = g["consensus_meta"]["active_validators"][0]
        validator_bytes = bytes.fromhex(validator_key)

        host_contract = {
            "proof_scheme": "bls_header_sig",
            "fork_choice_scheme": "height_then_hash",
            "input_contract_version": 1,
        }
        meta_hash = cmh_serial(
            host_contract=host_contract,
            active_validators=[validator_bytes],
            pending_updates=[],
            vote_records=[],
            activation_schedule=[],
            checkpoint_references=[],
            mechanism_specific_metadata={},
        )
        self.assertEqual(meta_hash.hex(), EXPECTED_META_HASH)

    def test_header_state_hash_consistency(self):
        """Block 0 header's state_hash matches the independently computed state_hash."""
        self.assertEqual(
            self.genesis["block_0"]["header"]["state_hash"],
            EXPECTED_STATE_HASH,
        )


class TestGenesisReplay(unittest.TestCase):
    """Verify that loading genesis.json into an empty DB produces the correct state."""

    def setUp(self):
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self._tmpfile.close()
        self.db_path = self._tmpfile.name

        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.db_path)

        # Clear any previous in-memory state
        if getattr(db, "_db_conn", None):
            db._db_conn.close()
        db._db_conn = None
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._application_rules_state = ""
        chain_state._consensus_rules_state = ""
        chain_state._canonical_head_hash = ""

    def tearDown(self):
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(self.original_db_path)
        try:
            os.remove(self.db_path)
        except OSError:
            pass

    def test_empty_db_provisions_genesis(self):
        """load_genesis on empty DB creates Block 0 and seeds accounts."""
        genesis = _load_genesis()
        chain_state.load_genesis(GENESIS_PATH)

        # DB now has Block 0
        head = db.get_canonical_head_block()
        self.assertIsNotNone(head)
        self.assertEqual(head["header"]["block_number"], 0)
        self.assertEqual(head["block_hash"], EXPECTED_BLOCK_HASH)

        # Genesis hash is retrievable
        self.assertEqual(db.get_genesis_hash(), EXPECTED_BLOCK_HASH)

    def test_genesis_accounts_seeded(self):
        """After genesis load, in-memory balances match genesis.json accounts_state."""
        genesis = _load_genesis()
        chain_state.load_genesis(GENESIS_PATH)

        for addr, balance in genesis["accounts_state"].items():
            self.assertEqual(chain_state.get_balance(addr), balance)
            self.assertEqual(chain_state.get_sequence_number(addr), 0)

    def test_genesis_rules_seeded(self):
        """After genesis load, application and consensus rules match genesis.json."""
        genesis = _load_genesis()
        chain_state.load_genesis(GENESIS_PATH)

        self.assertEqual(chain_state.get_application_rules_state(), genesis["application_rules"])
        self.assertEqual(chain_state.get_consensus_rules_state(), genesis["consensus_rules"])

    def test_canonical_head_is_genesis(self):
        """After genesis load, canonical head hash points to Block 0."""
        chain_state.load_genesis(GENESIS_PATH)
        self.assertEqual(chain_state._canonical_head_hash, EXPECTED_BLOCK_HASH)

    def test_idempotent_reload(self):
        """Calling load_genesis twice on an already-seeded DB is safe and consistent."""
        chain_state.load_genesis(GENESIS_PATH)
        head1 = db.get_canonical_head_block()

        # Second call should detect non-empty DB and just verify
        chain_state.load_genesis(GENESIS_PATH)
        head2 = db.get_canonical_head_block()

        self.assertEqual(head1["block_hash"], head2["block_hash"])
        self.assertEqual(head1["block_hash"], EXPECTED_BLOCK_HASH)

    def test_legacy_genesis_sentinel_is_normalized(self):
        """Older DBs that stored block 0 as 'GENESIS' are rewritten to canonical hash."""
        genesis = _load_genesis()
        legacy_block = dict(genesis["block_0"])
        legacy_block["block_hash"] = "GENESIS"
        if "hash" in legacy_block:
            legacy_block["hash"] = "GENESIS"

        db.init_db()
        with db._db_lock:
            db._db_conn.execute(
                """
                INSERT INTO blocks (block_hash, block_number, previous_hash, timestamp, block_data)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "GENESIS",
                    0,
                    legacy_block["header"]["previous_hash"],
                    legacy_block["header"]["timestamp"],
                    json.dumps(legacy_block),
                ),
            )
            db._db_conn.execute(
                "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_hash', ?)",
                ("GENESIS",),
            )
            db._db_conn.commit()
            db._db_conn.close()
            db._db_conn = None

        chain_state.load_genesis(GENESIS_PATH)

        self.assertEqual(db.get_genesis_hash(), EXPECTED_BLOCK_HASH)
        head = db.get_canonical_head_block()
        self.assertIsNotNone(head)
        self.assertEqual(head["block_hash"], EXPECTED_BLOCK_HASH)


class TestGenesisMismatchFatal(unittest.TestCase):
    """Verify that DB/genesis.json mismatches are fatal startup errors."""

    def setUp(self):
        self._tmpfile = tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False)
        self._tmpfile.close()
        self.db_path = self._tmpfile.name

        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.db_path)

        if getattr(db, "_db_conn", None):
            db._db_conn.close()
        db._db_conn = None
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._canonical_head_hash = ""

    def tearDown(self):
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(self.original_db_path)
        try:
            os.remove(self.db_path)
        except OSError:
            pass

    def test_wrong_genesis_hash_is_fatal(self):
        """If DB has Block 0 with a different hash than genesis.json, load_genesis raises."""
        # First: seed the DB normally
        chain_state.load_genesis(GENESIS_PATH)

        # Now tamper: create a fake genesis.json with a different block hash
        genesis = _load_genesis()
        genesis["block_0"]["hash"] = "ff" * 32  # wrong hash
        tampered_path = os.path.join(os.path.dirname(self.db_path), "tampered_genesis.json")
        with open(tampered_path, "w") as f:
            json.dump(genesis, f)

        # Reset in-memory state to simulate fresh startup
        chain_state._canonical_head_hash = ""
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()

        # Attempting to load with mismatched genesis must be fatal
        with self.assertRaises(ValueError) as ctx:
            chain_state.load_genesis(tampered_path)

        self.assertIn("FATAL", str(ctx.exception))

        os.remove(tampered_path)

    def test_missing_genesis_file_raises(self):
        """If genesis.json does not exist, load_genesis raises FileNotFoundError."""
        with self.assertRaises(FileNotFoundError):
            chain_state.load_genesis("/nonexistent/path/genesis.json")


if __name__ == "__main__":
    unittest.main()
