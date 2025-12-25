import unittest
from unittest.mock import MagicMock, patch
import sys
import hashlib
import importlib

class TestChainDHTIntegration(unittest.TestCase):
    def setUp(self):
        # Save original chain_state if present
        self.original_chain_state = sys.modules.get("chain_state")
        
        # Mock dependencies using patch.dict
        self.modules_patcher = patch.dict(sys.modules, {
            "db": MagicMock(),
            "tau_manager": MagicMock(),
            "poa": MagicMock(),
            "block": MagicMock(),
        })
        self.modules_patcher.start()
        
        # Ensure we get a fresh import of chain_state with mocked dependencies
        if "chain_state" in sys.modules:
            del sys.modules["chain_state"]
            
        import chain_state
        self.chain_state = chain_state

        # Ensure state hash computation is deterministic for assertions.
        # chain_state imports compute_state_hash from poa.state; with our patched sys.modules,
        # it's a MagicMock unless we give it a return value.
        try:
            self.chain_state.compute_state_hash.return_value = "deadbeef"
        except Exception:
            pass
        
        # Reset chain state
        self.chain_state._current_rules_state = ""
        self.chain_state._dht_client = None
        
        # Mock DHT Client
        self.mock_dht_client = MagicMock()
        self.mock_dht = MagicMock()
        self.mock_value_store = MagicMock()
        
        # Setup value store to act like a dict
        self.store_data = {}
        
        def put_side_effect(key, value):
            self.store_data[key] = value
            
        def get_side_effect(key):
            return self.store_data.get(key)
            
        self.mock_value_store.put.side_effect = put_side_effect
        self.mock_value_store.get.side_effect = get_side_effect
        
        self.mock_dht.value_store = self.mock_value_store
        self.mock_dht.value_store = self.mock_value_store
        self.mock_dht_client.dht = self.mock_dht
        
        # Configure get_record_sync to behave like the real one (checking local store)
        # Since chain_state now prefers this method, we must ensure it relies on our mocked data.
        # We wrap it to ignore extra kwargs like timeout if they were passed, though currently they aren't.
        def get_record_sync_mock(key, **kwargs):
            return self.mock_value_store.get(key)
            
        self.mock_dht_client.get_record_sync.side_effect = get_record_sync_mock
        
    def tearDown(self):
        self.modules_patcher.stop()
        # Restore original chain_state
        if "chain_state" in sys.modules:
            del sys.modules["chain_state"]
        
        if self.original_chain_state:
            sys.modules["chain_state"] = self.original_chain_state

    def test_store_and_retrieve_formula(self):
        # 1. Set DHT client
        self.chain_state.set_dht_client(self.mock_dht_client)
        
        # 2. Save rules state (simulates receiving new rules from Tau)
        formula_content = "test formula content"
        self.chain_state.save_rules_state(formula_content)
        
        # 3. Verify it was stored in DHT
        expected_hash = hashlib.sha256(formula_content.encode('utf-8')).hexdigest()
        expected_key = f"formula:{expected_hash}".encode('ascii')

        # chain_state.save_rules_state stores two entries when a DHT client is set:
        # - state:<state_hash> -> rules bytes (primary snapshot)
        # - formula:<sha256>   -> rules bytes (compat lookup)
        expected_state_key = f"{self.chain_state.config.STATE_LOCATOR_NAMESPACE}:deadbeef".encode("ascii")

        calls = self.mock_value_store.put.call_args_list
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].args[0], expected_state_key)
        self.assertEqual(calls[0].args[1], formula_content.encode("utf-8"))
        self.assertEqual(calls[1].args[0], expected_key)
        self.assertEqual(calls[1].args[1], formula_content.encode("utf-8"))
        
        # 4. Verify retrieval
        retrieved_content = self.chain_state.fetch_formula_from_dht(expected_hash)
        self.assertEqual(retrieved_content, formula_content)
        
    def test_retrieve_missing_formula(self):
        self.chain_state.set_dht_client(self.mock_dht_client)
        
        # Try to retrieve non-existent formula
        result = self.chain_state.fetch_formula_from_dht("nonexistenthash")
        self.assertIsNone(result)

if __name__ == "__main__":
    unittest.main()
