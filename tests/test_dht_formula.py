import unittest
from unittest.mock import MagicMock, patch
import hashlib
import sys

class TestDHTFormula(unittest.TestCase):
    def setUp(self):
        from network.dht_manager import DHTManager
        from network.config import NetworkConfig
        
        self.DHTManager = DHTManager
        self.NetworkConfig = NetworkConfig

        self.config = MagicMock(spec=self.NetworkConfig)
        self.dht_manager = self.DHTManager(self.config)
        # Mock DHT
        self.dht_manager._dht = MagicMock()
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

    def test_validator_registration(self):
        # Check if formula validator is registered
        self.assertIn("formula", self.dht_manager._dht_validators)
        self.assertEqual(
            self.dht_manager._dht_validators["formula"], 
            self.dht_manager._validate_formula_record
        )

if __name__ == "__main__":
    unittest.main()
