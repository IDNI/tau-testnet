
import os
import sys
import unittest
from unittest.mock import MagicMock, patch
import importlib

# Add project root to path
sys.path.append(os.getcwd())

import tau_manager

import commands.sendtx
from errors import TauCommunicationError

class TestInvalidRuleRegression(unittest.TestCase):
    def setUp(self):
        # Reset global state where possible
        tau_manager.tau_process = MagicMock()
        tau_manager.tau_process_ready.set()
        tau_manager.tau_test_mode = False

    def tearDown(self):
        pass

    @patch('tau_manager.communicate_with_tau')
    def test_sendtx_with_invalid_rule_fails(self, mock_comm):
        # We need to patch sys.modules locally context to avoid polluting other tests
        # We mock dependencies that might trigger DB/Network activity or are missing
        with patch.dict(sys.modules, {
            'chain_state': MagicMock(),
            'network': MagicMock(),
            'network.bus': MagicMock(),
            'db': MagicMock(),
            'py_ecc': MagicMock(),
            'py_ecc.bls': MagicMock()
        }):
            # Re-import commands.sendtx to ensure it uses the MOCKED modules
            import commands.sendtx
            importlib.reload(commands.sendtx)
            
            with patch.dict('os.environ', {'TAU_FORCE_TEST': '0'}):
                # Simulate communicate_with_tau raising the error as per the fix
                mock_comm.side_effect = TauCommunicationError("Tau failed: (Error) Syntax Error")
            
                # Construct a payload with a rule
                payload = {
                    "sender_pubkey": "a" * 96, 
                    "sequence_number": 0,
                    "expiration_time": 9999999999,
                    "operations": {
                        "0": "invalid rule here"
                    },
                    "fee_limit": "0",
                    "signature": "a" * 192 
                }
                
                # Mock internal validations of sendtx
                # Since sendtx is reloaded, we must patch the reloaded object or its imports?
                # commands.sendtx uses 'import chain_state' etc. 
                # Since sys.modules['chain_state'] is now a Mock, sendtx will use that Mock.
                
                # However, we need to ensure validations pass to reach the Tau communication part.
                # sendtx.py: _validate_bls...
                
                # We can use 'patch' on the reloaded module functions if needed.
                # But the 'chain_state' inside sendtx is already the Mock.
                # checking sendtx.py: calls chain_state.get_sequence_number
                sys.modules['chain_state'].get_sequence_number.return_value = 0
                
                # Must also mock get_pending_sequence to avoid MagicMock comparison TypeError
                sys.modules['db'].get_pending_sequence.return_value = None
                
                # Mock get_rules_state so it returns None instead of a Truthy MagicMock
                # This prevents the test from hanging for 60+ seconds in reset_tau_state's wait_for_ready loop
                sys.modules['chain_state'].get_rules_state.return_value = None
                
                # We also need to patch _validate_bls12_381_pubkey inside sendtx
                # But wait, sendtx imports G2Basic from py_ecc.bls.
                # sys.modules['py_ecc.bls'] is a Mock.
                # So G2Basic is a Mock. Verify is a Mock.
                sys.modules['py_ecc.bls'].G2Basic.Verify.return_value = True
                
                # We also need to patch _validate_bls12_381_pubkey function in sendtx module
                # Since we reloaded it, we can patch `commands.sendtx._validate_bls12_381_pubkey`
                
                with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
                     import json
                     json_blob = json.dumps(payload)
                     
                     result = commands.sendtx.queue_transaction(json_blob, propagate=False)
                     
                     print(f"Result: {result}")
                     self.assertIn("FAILURE", result)
                     self.assertIn("Transaction rejected by Tau", result)

if __name__ == '__main__':
    unittest.main()
