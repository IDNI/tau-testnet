
import unittest
from unittest.mock import MagicMock, patch
import json
import builtins
import sys
import os

# Ensure we can import wallet
sys.path.append(os.getcwd())
import wallet

class TestWalletConsole(unittest.TestCase):
    def setUp(self):
        # Mock basics
        self.mock_args = MagicMock()
        self.mock_args.host = "localhost"
        self.mock_args.port = 65432
        self.mock_args.fee = 100
        self.mock_args.expiry = 10
        
        # Valid key for signing
        # Int: 1
        self.priv_int = 1
        self.priv_hex = "00"*31 + "01"
        self.mock_args.privkey = self.priv_hex
        self.sender_pk = "a491..." # checking logic doesn't require actual PK unless we validate sig

    @patch('wallet.rpc_command')
    @patch('wallet.G2Basic.Sign')
    def test_cmd_send_with_custom_inputs(self, mock_sign, mock_rpc):
        # Setup specific args for this test
        self.mock_args.to = None
        self.mock_args.amount = None
        self.mock_args.rule = None
        self.mock_args.transfer = None
        self.mock_args.operation = ["100:test_val", "200:test_val_2"]
        self.mock_args.operations_json = None
        
        mock_rpc.return_value = "SUCCESS" # Mock sequence fetch and send result
        # Note: rpc_command is called twice: getsequence, then sendtx
        # We need to handle that.
        
        def rpc_side_effect(cmd, host, port):
            if "getsequence" in cmd:
                return "SEQUENCE: 5"
            if "sendtx" in cmd:
                return "SUCCESS: txid"
            return "ERROR"
        
        mock_rpc.side_effect = rpc_side_effect
        mock_sign.return_value = b"\x00"*96 # Mock signature
        
        # Capture print output to verify payload logging
        with patch('builtins.print') as mock_print:
            wallet.cmd_send(self.mock_args)
            
            # Verify rpc called with correct payload
            # The second call to rpc_command is the sendtx one
            self.assertEqual(mock_rpc.call_count, 2)
            
            # Get variable args from second call
            call_args = mock_rpc.call_args_list[1]
            cmd_sent = call_args[0][0] # first arg is cmd string "sendtx '{...}'\r\n"
            
            # Extract JSON
            # Format: sendtx '{JSON}'\r\n
            # Remove "sendtx '" offset 8 (7 for "sendtx " + 1 for "'")
            # And remove trailing "'\r\n"
            start_idx = cmd_sent.find("'{") + 1
            end_idx = cmd_sent.rfind("}'") + 1
            if start_idx == 0 or end_idx == 0:
                 # Fallback/Debug
                 print(f"DEBUG: cmd_sent={cmd_sent}")
                 json_part = cmd_sent[8:-3] # rough guess: sendtx '...'\r\n
            else:
                 json_part = cmd_sent[start_idx:end_idx]
            
            data = json.loads(json_part)
            
            ops = data["operations"]
            self.assertIn("100", ops)
            self.assertEqual(ops["100"], "test_val")
            self.assertIn("200", ops)
            self.assertEqual(ops["200"], "test_val_2")
            self.assertEqual(data["sequence_number"], 5)

if __name__ == '__main__':
    unittest.main()
