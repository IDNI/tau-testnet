import unittest
from unittest.mock import MagicMock, patch
import json
import sys
import importlib

class TestPoATauEngine(unittest.TestCase):
    def setUp(self):
        from poa.engine import PoATauEngine
        from poa.state import TauStateSnapshot
        from block import Block, BlockHeader
        
        self.PoATauEngine = PoATauEngine
        self.TauStateSnapshot = TauStateSnapshot
        self.Block = Block
        self.BlockHeader = BlockHeader
        
        self.engine = self.PoATauEngine()
        self.snapshot = self.TauStateSnapshot(
            state_hash="0"*64,
            tau_bytes=b"",
            metadata={}
        )

    def tearDown(self):
        pass

    @patch("poa.engine.config")
    def test_verify_block_signature(self, mock_config):
        # Mock config to have a specific miner key
        mock_config.MINER_PUBKEY = "00"*48 # Mock pubkey
        
        # Mock block
        block = MagicMock(spec=self.Block)
        block.header = MagicMock(spec=self.BlockHeader)
        block.header.block_number = 1
        block.block_signature = "sig"
        
        # Case 1: Signature valid
        block.verify_signature.return_value = True
        self.assertTrue(self.engine.verify_block(block))
        
        # Case 2: Signature invalid
        block.verify_signature.return_value = False
        self.assertFalse(self.engine.verify_block(block))
        
        # Case 3: No signature
        block.block_signature = None
        self.assertFalse(self.engine.verify_block(block))

    @patch("poa.engine.tau_manager")
    def test_apply_transactions(self, mock_tau_manager):
        # Mock chain_state
        mock_chain_state = MagicMock()
        mock_chain_state.update_balances_after_transfer.return_value = True
        mock_chain_state.get_sequence_number.return_value = 0
        
        with patch.dict(sys.modules, {'chain_state': mock_chain_state}):
            # Setup mocks
            mock_tau_manager.tau_ready.is_set.return_value = True
            mock_tau_manager.communicate_with_tau.return_value = "x1001" # Success
            
            # Create transactions
            txs = [
                {
                    "tx_id": "tx1",
                    "sender_pubkey": "sender1",
                    "sequence_number": 0,
                    "operations": {
                        "0": "rule1", # Rule
                        "1": [["sender1", "receiver1", "100"]] # Transfer
                    }
                }
            ]
            
            # Apply
            result = self.engine.apply(self.snapshot, txs)
            
            # Verify
            self.assertEqual(len(result.accepted_transactions), 1)
            self.assertEqual(len(result.rejected_transactions), 0)
            
            # Check calls
            mock_tau_manager.communicate_with_tau.assert_called_with(rule_text="rule1", target_output_stream_index=0)
            mock_chain_state.update_balances_after_transfer.assert_called_with("sender1", "receiver1", 100)
            mock_chain_state.increment_sequence_number.assert_called_with("sender1")
            
            # Check snapshot update (accumulated bytes)
            self.assertEqual(result.snapshot.tau_bytes, b"rule1")

    @patch("poa.engine.tau_manager")
    def test_apply_failed_transfer(self, mock_tau_manager):
        # Mock chain_state
        mock_chain_state = MagicMock()
        mock_chain_state.update_balances_after_transfer.return_value = False # Fail
        mock_chain_state.get_sequence_number.return_value = 0
        
        with patch.dict(sys.modules, {'chain_state': mock_chain_state}):
            # Setup mocks
            mock_tau_manager.tau_ready.is_set.return_value = True
            
            txs = [
                {
                    "tx_id": "tx1",
                    "sender_pubkey": "sender1",
                    "sequence_number": 0,
                    "operations": {
                        "1": [["sender1", "receiver1", "100"]]
                    }
                }
            ]
            
            result = self.engine.apply(self.snapshot, txs)
            
            self.assertEqual(len(result.accepted_transactions), 0)
            self.assertEqual(len(result.rejected_transactions), 1)

if __name__ == "__main__":
    unittest.main()
