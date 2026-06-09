import unittest
from unittest.mock import MagicMock, patch
import hashlib
import json
from typing import Dict, Optional


class _InMemoryValueStore:
    """
    Minimal in-memory value store that matches the interface expected by
    network.dht_manager.DHTManager._setup_dht_validators().
    """

    def __init__(self) -> None:
        self._store: Dict[bytes, bytes] = {}

    def put(self, key: bytes, value: bytes, validity: float = 0.0):  # noqa: ARG002 - interface compatibility
        self._store[key] = value

    def get(self, key: bytes) -> Optional[bytes]:
        return self._store.get(key)


class TestDHTFormula(unittest.TestCase):
    def setUp(self):
        from network.dht_manager import DHTManager
        from network.config import NetworkConfig
        
        self.DHTManager = DHTManager
        self.NetworkConfig = NetworkConfig

        self.config = MagicMock(spec=self.NetworkConfig)
        self.dht_manager = self.DHTManager(self.config)
        # Mock DHT + an in-memory value store so we can validate put/get locally.
        mock_dht = MagicMock()
        mock_dht.value_store = _InMemoryValueStore()
        self.dht_manager._dht = mock_dht
        self.dht_manager._setup_dht_validators()

    def tearDown(self):
        pass

    def test_validate_formula_record(self):
        formula = b"some formula content"
        formula_hash = hashlib.sha256(formula).hexdigest()
        
        # Valid key
        key = f"formula:{formula_hash}".encode("ascii")
        self.assertTrue(self.dht_manager._validate_formula_record(key, formula))
        
        # Invalid hash
        wrong_key = f"formula:{'a'*64}".encode("ascii")
        self.assertFalse(self.dht_manager._validate_formula_record(wrong_key, formula))
        
        # Invalid namespace
        wrong_ns = f"other:{formula_hash}".encode("ascii")
        self.assertFalse(self.dht_manager._validate_formula_record(wrong_ns, formula))

    def test_validate_block_record_uses_real_block_hash_verification(self):
        from block import Block

        block = Block.create(
            block_number=1,
            previous_hash="0" * 64,
            transactions=[],
            proposer_pubkey="a" * 96,
            timestamp=1234567890,
        )
        key = f"block:{block.block_hash}".encode("ascii")
        noncanonical_json = json.dumps(block.to_dict(), sort_keys=False, indent=2).encode("utf-8")

        self.assertTrue(self.dht_manager._validate_block_record(key, noncanonical_json))

    def test_validate_block_record_rejects_tampered_block_payload(self):
        from block import Block

        block = Block.create(
            block_number=1,
            previous_hash="0" * 64,
            transactions=[],
            proposer_pubkey="a" * 96,
            timestamp=1234567890,
        )
        tampered = block.to_dict()
        tampered["header"]["timestamp"] = 1234567891
        key = f"block:{block.block_hash}".encode("ascii")
        payload = json.dumps(tampered, separators=(",", ":")).encode("utf-8")

        self.assertFalse(self.dht_manager._validate_block_record(key, payload))

    def test_validate_tx_record_uses_canonical_transaction_hash(self):
        from block import compute_tx_hash

        payload = {
            "signature": "0" * 192,
            "sender_pubkey": "b" * 96,
            "operations": {"1": [["b" * 96, "c" * 96, "1"]]},
            "expiration_time": 9999999999,
            "fee_limit": "0",
            "sequence_number": 1,
        }
        tx_id = compute_tx_hash(payload)
        noncanonical_json = json.dumps(payload, sort_keys=False, indent=2).encode("utf-8")
        key = f"tx:{tx_id}".encode("ascii")

        self.assertTrue(self.dht_manager._validate_tx_record(key, noncanonical_json))

    def test_validate_tx_record_rejects_hash_mismatch(self):
        payload = {
            "sender_pubkey": "b" * 96,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": {"1": [["b" * 96, "c" * 96, "1"]]},
            "fee_limit": "0",
            "signature": "0" * 192,
        }
        key = f"tx:{'0' * 64}".encode("ascii")
        canonical_json = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        self.assertFalse(self.dht_manager._validate_tx_record(key, canonical_json))

    def test_tau_state_storage_and_retrieval(self):
        """
        Tau/rules snapshots are stored under `state:<blake3>` with the raw spec bytes as value.
        """
        from consensus.state import compute_state_hash

        tau_spec = b"always (o5[t] = { 1 }:bv)."
        state_hash = compute_state_hash(tau_spec)
        key = f"state:{state_hash}".encode("ascii")

        ok = self.dht_manager.put_record_sync(key, tau_spec)
        self.assertTrue(ok)

        retrieved = self.dht_manager.get_record_sync(key)
        self.assertEqual(retrieved, tau_spec)

    def test_tau_state_rejects_hash_mismatch(self):
        from consensus.state import compute_state_hash

        tau_spec = b"always (o6[t] = { 0 }:bv)."
        correct_hash = compute_state_hash(tau_spec)
        wrong_key = f"state:{'0'*64}".encode("ascii")
        self.assertNotEqual(wrong_key, f"state:{correct_hash}".encode("ascii"))

        ok = self.dht_manager.put_record_sync(wrong_key, tau_spec)
        self.assertFalse(ok, "Expected DHTManager.put_record_sync to reject mismatched state hash")

        # And it should not be retrievable under the wrong key.
        self.assertIsNone(self.dht_manager.get_record_sync(wrong_key))

    def test_validator_registration(self):
        # Check if formula and state validators are registered
        self.assertIn("formula", self.dht_manager._dht_validators)
        self.assertEqual(
            self.dht_manager._dht_validators["formula"], 
            self.dht_manager._validate_formula_record
        )
        self.assertIn("state", self.dht_manager._dht_validators)
        self.assertEqual(
            self.dht_manager._dht_validators["state"],
            self.dht_manager._validate_state_record,
        )

    def test_put_record_sync_registers_provider_after_network_publish_failure(self):
        """
        Even if network publish fails, state/tau_state records should still register
        local provider metadata so peers can discover us during handshake.
        """
        self.dht_manager._trio_token = object()
        self.dht_manager._host = MagicMock()
        self.dht_manager._host.get_addrs.return_value = []
        self.dht_manager._host.get_id.return_value = "self-peer"
        self.dht_manager._dht.peer_id = "self-peer"

        state_hash = "fallback-head"
        key = f"state:{state_hash}".encode("ascii")
        payload = json.dumps({"block_hash": state_hash, "accounts": {}}).encode("utf-8")

        with patch("trio.from_thread.run", side_effect=ValueError("simulated network failure")):
            ok = self.dht_manager.put_record_sync(key, payload)

        self.assertTrue(ok)
        # `_dht_provider_add` holds the original provider_store.add_provider callable.
        self.assertTrue(self.dht_manager._dht_provider_add.called)

if __name__ == "__main__":
    unittest.main()
