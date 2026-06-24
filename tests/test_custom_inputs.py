
import unittest
from unittest.mock import MagicMock, patch
import json
import logging
import sys
import os

# Assume dependencies exist in the environment (as seen in user logs).
# If not, we should install them, but mocking sys.modules globally is dangerous.

from commands import sendtx
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot
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

        self.env_patcher = patch.dict('os.environ', {'TAU_FORCE_TEST': '0'})
        self.env_patcher.start()

        # tau_test_mode may be left True by other test modules that ran a
        # TAU_FORCE_TEST tau_manager loop; force it off so sendtx takes the
        # isolated-compile validation path this test asserts on.
        self.test_mode_patcher = patch.object(tau_manager, 'tau_test_mode', False)
        self.test_mode_patcher.start()

        # Rule validation now runs through the isolated subprocess compile.
        # Mock it so the test is deterministic and does not spawn a child / need
        # a native tau build. None == validated OK.
        self.isolated_patcher = patch(
            'tau_native.compile_revisions_isolated_subprocess', return_value=None
        )
        self.mock_isolated = self.isolated_patcher.start()

        # Ensure we clean up patches
        self.addCleanup(self.comm_patcher.stop)
        self.addCleanup(self.ready_patcher.stop)
        self.addCleanup(self.env_patcher.stop)
        self.addCleanup(self.test_mode_patcher.stop)
        self.addCleanup(self.isolated_patcher.stop)

        # Crypto is mandatory now: mock signature verification instead of disabling it.
        self.crypto_patcher = patch('commands.sendtx.G2Basic')
        mock_bls = self.crypto_patcher.start()
        mock_bls.Verify.return_value = True
        self.addCleanup(self.crypto_patcher.stop)
        self.seq_patcher = patch('commands.sendtx.chain_state.get_sequence_number', return_value=1)
        self.seq_patcher.start()
        self.addCleanup(self.seq_patcher.stop)
        self.pending_seq_patcher = patch('commands.sendtx.db.get_pending_sequence', return_value=None)
        self.pending_seq_patcher.start()
        self.addCleanup(self.pending_seq_patcher.stop)
        
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
                "signature": "00" * 48
            }
            json_blob = json.dumps(payload)
            with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
                with patch('commands.sendtx.db.add_mempool_tx'):
                    result = sendtx.queue_transaction(json_blob, propagate=False)
            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "TX_INVALID")
            self.assertIn(f"Stream {key} is reserved", result["message"])

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
            "signature": "00" * 48,
            "sender_pubkey": "a" * 96 # Valid-ish hex
        }
        
        # Mock validators to pass structure checks
        with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
             with patch('commands.sendtx.db.add_mempool_tx'):
                result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        
        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")
        
        # Check call arguments to tau_manager
        # operations["0"] is missing, so only one call to communicate_with_tau expected (Step 2)
        self.mock_communicate.assert_called_once()
        args, kwargs = self.mock_communicate.call_args
        
        # In sendtx logic: 
        # rule_text=None, target_output_stream_index=0, input_stream_values=custom_tau_inputs
        self.assertIsNone(kwargs['rule_text'])
        self.assertEqual(kwargs['target_output_stream_index'], 0)
        self.assertEqual(kwargs['source'], payload['sender_pubkey'])
        inputs = kwargs['input_stream_values']
        self.assertIn(100, inputs)
        self.assertEqual(inputs[100], ["42"]) # Normalized to list of str
        self.assertIn(200, inputs)
        self.assertEqual(inputs[200], ["a", "1"]) # Normalized

    def test_sendtx_two_step_validation(self):
        """Rules are validated by the isolated compile; custom inputs by the live
        path. The rule no longer goes through communicate_with_tau, and the live
        validate-then-restore is skipped entirely on the isolated path."""
        payload = {
            "sender_pubkey": "a" * 96,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": {
                "0": "some rule",
                "100": "42"
            },
            "fee_limit": 100,
            "signature": "00" * 48
        }

        with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
             with patch('commands.sendtx.db.add_mempool_tx'):
                 with patch('tau_manager.reset_tau_state') as mock_reset:
                    result = sendtx.queue_transaction(json.dumps(payload), propagate=False)

        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")

        # Rule validated via isolated subprocess compile (once, with the rule).
        self.mock_isolated.assert_called_once()
        iso_args, _iso_kwargs = self.mock_isolated.call_args
        self.assertEqual(iso_args[1], ["some rule"])

        # communicate_with_tau is now used only for the custom-input step.
        self.assertEqual(self.mock_communicate.call_count, 1)
        _, kwargs = self.mock_communicate.call_args
        self.assertIsNone(kwargs['rule_text'])
        self.assertEqual(kwargs['input_stream_values'][100], ["42"])
        self.assertEqual(kwargs['source'], payload['sender_pubkey'])

        # Isolated path never mutates live state, so no restore is performed.
        mock_reset.assert_not_called()

    def test_engine_apply_execution_order(self):
        """Test TauConsensusEngine.apply executes Rule then Custom Inputs and captures receipts."""
        
        mock_store = MagicMock()
        mock_store.commit.return_value = TauStateSnapshot(b"", b"", {}) 
        engine = TauConsensusEngine(state_store=mock_store)
        
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
        
        result = engine.apply(snapshot, [tx], 1700000000)
        
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
        self.assertNotIn('rule_text', kwargs2)
        self.assertEqual(kwargs2['input_stream_values'][100], ["99"])
        self.assertEqual(kwargs2['apply_rules_update'], False)
        self.assertIn("Tau(custom_unified) o0: output_custom", logs)
        
        self.assertIn("Rule applied", logs)
        
    def test_engine_apply_tau_error_on_custom_input(self):
        """Test TauConsensusEngine.apply fails transaction if Tau returns explicit Error on custom input."""
        mock_store = MagicMock()
        mock_store.commit.return_value = TauStateSnapshot(b"", b"", {}) 
        engine = TauConsensusEngine(state_store=mock_store)
        
        snapshot = TauStateSnapshot(b"hash", b"rules", {})
        tx = {
            "tx_id": "tx_fail",
            "operations": {
                "100": "bad_input"
            }
        }
        
        # Mock communicate_with_tau to return Error
        self.mock_communicate.return_value = "(Error) Invalid input"
        
        result = engine.apply(snapshot, [tx], 1700000000)
        
        # New behavior: Tx execution fails on Tau Error, but is accepted into block (nonce consumed)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(len(result.rejected_transactions), 0)
        
        receipt = result.receipts["tx_fail"]
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("Custom logic error: (Error) Invalid input", receipt["logs"])

if __name__ == '__main__':
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
