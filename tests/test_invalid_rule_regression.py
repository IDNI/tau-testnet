
import os
import sys
import json
import unittest
from unittest.mock import MagicMock, patch
import importlib

# Add project root to path
sys.path.append(os.getcwd())

import tau_manager

import commands.sendtx


class TestInvalidRuleRegression(unittest.TestCase):
    def setUp(self):
        # Drive the op-"0" isolated-subprocess validation path: engine ready,
        # not in test mode. (Rule validation runs only via that killable
        # subprocess -- there is no in-process live fallback.)
        tau_manager.tau_process = MagicMock()
        tau_manager.tau_process_ready.set()
        tau_manager.tau_ready.set()
        tau_manager.tau_test_mode = False

    def tearDown(self):
        # Don't leak the global readiness events into other tests.
        tau_manager.tau_ready.clear()
        tau_manager.tau_process_ready.clear()

    def test_sendtx_with_invalid_rule_fails(self):
        # Mock dependencies that would otherwise trigger DB/Network/crypto work.
        with patch.dict(sys.modules, {
            'chain_state': MagicMock(),
            'network': MagicMock(),
            'network.bus': MagicMock(),
            'db': MagicMock(),
            'py_ecc': MagicMock(),
            'py_ecc.bls': MagicMock()
        }):
            # Re-import commands.sendtx so it binds the MOCKED modules.
            import commands.sendtx
            importlib.reload(commands.sendtx)

            with patch.dict('os.environ', {'TAU_FORCE_TEST': '0'}):
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

                sys.modules['chain_state'].get_sequence_number.return_value = 0
                sys.modules['db'].get_pending_sequence.return_value = None
                sys.modules['chain_state'].get_rules_state.return_value = None
                sys.modules['py_ecc.bls'].G2Basic.Verify.return_value = True

                import tau_native
                # The isolated compile reports the rule as invalid (non-None
                # error string) -> queue_transaction returns TX_REJECTED.
                with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)), \
                     patch.object(
                         tau_native,
                         'compile_revisions_isolated_subprocess',
                         return_value="(Error) Syntax Error",
                     ):
                    result = commands.sendtx.queue_transaction(
                        json.dumps(payload), propagate=False
                    )

                    print(f"Result: {result}")
                    self.assertFalse(result["ok"])
                    self.assertEqual(result["code"], "TX_REJECTED")
                    self.assertIn("Transaction rejected by Tau", result["message"])


if __name__ == '__main__':
    unittest.main()
