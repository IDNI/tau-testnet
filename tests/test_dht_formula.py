import unittest
from unittest.mock import MagicMock
import hashlib
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

    def test_tau_state_storage_and_retrieval(self):
        """
        Tau/rules snapshots are stored under `state:<blake3>` with the raw spec bytes as value.
        """
        from poa.state import compute_state_hash

        tau_spec = b"always (o5[t] = { #b1 }:bv)."
        state_hash = compute_state_hash(tau_spec)
        key = f"state:{state_hash}".encode("ascii")

        ok = self.dht_manager.put_record_sync(key, tau_spec)
        self.assertTrue(ok)

        retrieved = self.dht_manager.get_record_sync(key)
        self.assertEqual(retrieved, tau_spec)

    def test_tau_state_rejects_hash_mismatch(self):
        from poa.state import compute_state_hash

        tau_spec = b"always (o6[t] = { #b0 }:bv)."
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

if __name__ == "__main__":
    unittest.main()
