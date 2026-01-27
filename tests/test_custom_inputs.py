
import unittest
from unittest.mock import MagicMock, patch
import json
import logging
import sys
import os

# Assume dependencies exist in the environment (as seen in user logs).
# If not, we should install them, but mocking sys.modules globally is dangerous.

from commands import sendtx
from poa.engine import PoATauEngine
from poa.state import TauStateSnapshot
import chain_state
import tau_manager

class TestCustomInputs(unittest.TestCase):

    def setUp(self):
        # Patch tau_manager.communicate_with_tau specific to this test instance
        self.comm_patcher = patch('tau_manager.communicate_with_tau', return_value="x1001")
        self.mock_communicate = self.comm_patcher.start()
        
        self.ready_patcher = patch('tau_manager.tau_ready')
        self.mock_tau_ready = self.ready_patcher.start()
        self.mock_tau_ready.is_set.return_value = True

        # Ensure we clean up patches
        self.addCleanup(self.comm_patcher.stop)
        self.addCleanup(self.ready_patcher.stop)
        
        # Patch other dependencies safely
        self.crypto_patcher = patch('commands.sendtx._PY_ECC_AVAILABLE', False)
        self.crypto_patcher.start()
        self.addCleanup(self.crypto_patcher.stop)
        
    def test_sendtx_reject_reserved_keys(self):
        """Test that sendtx rejects reserved keys 2, 3, 4."""
        # 0 and 1 are allowed (Rules, Transfers)
        # 2, 3, 4 are reserved inputs
        for key in ["2", "3", "4"]:
            payload = {
                "sender_pubkey": "a" * 96,
                "sequence_number": 1,
                "expiration_time": 9999999999,
                "operations": {key: "val"},
                "fee_limit": 100,
                "signature": "sig"
            }
            json_blob = json.dumps(payload)
            with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
                with patch('commands.sendtx.db.add_mempool_tx'):
                    result = sendtx.queue_transaction(json_blob, propagate=False)
            self.assertIn("FAILURE", result)
            self.assertIn(f"Stream {key} is reserved", result)

    def test_sendtx_accept_custom_keys(self):
        """Test that sendtx accepts keys >= 5 and normalizes values."""
        
        payload = {
            "sender_pubkey": "A" * 96,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": {
                "100": "42",
                "200": ["a", 1]
            },
            "fee_limit": 100,
            "signature": "sig",
            "sender_pubkey": "a" * 96 # Valid-ish hex
        }
        
        # Mock validators to pass structure checks
        with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
             with patch('commands.sendtx.db.add_mempool_tx'):
                result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        
        self.assertIn("SUCCESS", result)
        
        # Check call arguments to tau_manager
        # operations["0"] is missing, so only one call to communicate_with_tau expected (Step 2)
        self.mock_communicate.assert_called_once()
        args, kwargs = self.mock_communicate.call_args
        
        # In sendtx logic: 
        # rule_text=None, target_output_stream_index=0, input_stream_values=custom_tau_inputs
        self.assertIsNone(kwargs['rule_text'])
        self.assertEqual(kwargs['target_output_stream_index'], 0)
        inputs = kwargs['input_stream_values']
        self.assertIn(100, inputs)
        self.assertEqual(inputs[100], ["42"]) # Normalized to list of str
        self.assertIn(200, inputs)
        self.assertEqual(inputs[200], ["a", "1"]) # Normalized

    def test_sendtx_two_step_validation(self):
        """Test that sendtx performs two-step validation when rules AND custom inputs exist."""
        payload = {
            "sender_pubkey": "a" * 96,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": {
                "0": "some rule",
                "100": "42"
            },
            "fee_limit": 100,
            "signature": "sig"
        }

        with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
             with patch('commands.sendtx.db.add_mempool_tx'):
                 with patch('tau_manager.reset_tau_state'): # Mock cleanup
                    result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        
        self.assertIn("SUCCESS", result)
        
        # Should be called twice
        # 1. Rule (stream 0)
        # 2. Custom Inputs (stream 100)
        self.assertEqual(self.mock_communicate.call_count, 2)
        
        # Check first call (Rule)
        args1, kwargs1 = self.mock_communicate.call_args_list[0]
        self.assertEqual(kwargs1['rule_text'], "some rule")
        self.assertNotIn('input_stream_values', kwargs1) # Ensure input values NOT sent with rule in step 1 if separated
        
        # Check second call (Custom)
        args2, kwargs2 = self.mock_communicate.call_args_list[1]
        self.assertIsNone(kwargs2['rule_text'])
        self.assertEqual(kwargs2['input_stream_values'][100], ["42"])

    def test_engine_apply_execution_order(self):
        """Test PoATauEngine.apply executes Rule then Custom Inputs and captures receipts."""
        
        mock_store = MagicMock()
        mock_store.commit.return_value = TauStateSnapshot(b"", b"", {}) 
        engine = PoATauEngine(state_store=mock_store)
        
        snapshot = TauStateSnapshot(b"hash", b"rules", {})
        tx = {
            "tx_id": "tx1",
            "operations": {
                "0": "new rule",
                "100": "99"
            }
        }
        
        # Mock communicate_with_tau to return distinct outputs
        self.mock_communicate.side_effect = ["output_rule", "output_custom"]
        
        result = engine.apply(snapshot, [tx])
        
        receipt = result.receipts["tx1"]
        logs = receipt["logs"]
        
        # Verify call order and logs
        self.assertEqual(self.mock_communicate.call_count, 2)
        
        # Call 1: Rule
        args1, kwargs1 = self.mock_communicate.call_args_list[0]
        self.assertEqual(kwargs1['rule_text'], "new rule")
        self.assertEqual(kwargs1['apply_rules_update'], True)
        self.assertIn("Tau(rule) o0: output_rule", logs)
        
        # Call 2: Custom
        args2, kwargs2 = self.mock_communicate.call_args_list[1]
        self.assertIsNone(kwargs2['rule_text'])
        self.assertEqual(kwargs2['input_stream_values'][100], ["99"])
        self.assertEqual(kwargs2['apply_rules_update'], True)
        self.assertIn("Tau(custom) o0: output_custom", logs)
        
        self.assertIn("Rule applied", logs)
        
    def test_engine_apply_tau_error_on_custom_input(self):
        """Test PoATauEngine.apply fails transaction if Tau returns explicit Error on custom input."""
        mock_store = MagicMock()
        mock_store.commit.return_value = TauStateSnapshot(b"", b"", {}) 
        engine = PoATauEngine(state_store=mock_store)
        
        snapshot = TauStateSnapshot(b"hash", b"rules", {})
        tx = {
            "tx_id": "tx_fail",
            "operations": {
                "100": "bad_input"
            }
        }
        
        # Mock communicate_with_tau to return Error
        self.mock_communicate.return_value = "(Error) Invalid input"
        
        result = engine.apply(snapshot, [tx])
        
        # New behavior: Tx execution fails on Tau Error, but is accepted into block (nonce consumed)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(len(result.rejected_transactions), 0)
        
        receipt = result.receipts["tx_fail"]
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("Tau rejected custom inputs: (Error) Invalid input", receipt["logs"])

if __name__ == '__main__':
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
