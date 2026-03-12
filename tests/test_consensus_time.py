import unittest, os, sys, json, time
from unittest.mock import patch, MagicMock

# Add project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
from commands import sendtx, createblock
from poa.engine import PoATauEngine
import chain_state, db, block, tau_defs

class TestConsensusTime(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_consensus_time_db.sqlite"
        self.original_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.init_chain_state()
        db.clear_mempool()
        sendtx._PY_ECC_AVAILABLE = False
        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()
        patch('commands.createblock._BLS_AVAILABLE', True).start()
        patch('commands.createblock._validate_signature', return_value=True).start()
        patch('block.bls_signing_available', return_value=True).start()
        patch('block.Block.verify_signature', return_value=True).start()

    def tearDown(self):
        patch.stopall()
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        config.set_database_path(self.original_db)

    def test_mempool_rejects_reserved_streams(self):
        """Test that sendtx rejects transactions attempting to use reserved stream 5."""
        tx = {
            "sender_pubkey": chain_state.GENESIS_ADDRESS,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {
                "5": "1234567890"  # Attempting to inject consensus time!
            },
            "fee_limit": "0",
            "signature": "SIG"
        }
        res = sendtx.queue_transaction(json.dumps(tx))
        self.assertTrue(res.startswith("FAILURE: Invalid operation key '5'"), f"Got: {res}")
        self.assertEqual(len(db.get_mempool_txs()), 0)

    @patch('tau_manager.communicate_with_tau_multi')
    @patch('tau_manager.communicate_with_tau')
    @patch('tau_manager.tau_ready')
    @patch('chain_state.get_rules_state', return_value="rules")
    def test_createblock_injects_timestamp(self, mock_get_rules, mock_ready, mock_tau, mock_tau_multi):
        """Test that createblock.execute_batch dynamically injects the block_timestamp into the Tau evaluation maps."""
        mock_ready.is_set.return_value = True
        mock_tau.return_value = "1" # Success output for transfers
        mock_tau_multi.return_value = {1: "1"} # Success output for transfers multi
        
        tx = {
            "sender_pubkey": chain_state.GENESIS_ADDRESS,
            "sequence_number": chain_state.get_sequence_number(chain_state.GENESIS_ADDRESS),
            "expiration_time": int(time.time()) + 1000,
            "operations": {
                "1": [[chain_state.GENESIS_ADDRESS, "some_addr", "1"]],
                "7": "custom_data"
            },
            "fee_limit": "0",
            "signature": "SIG"
        }
        
        # Give Genesis some funds
        chain_state._balances[chain_state.GENESIS_ADDRESS] = 100
        
        block_timestamp = int(time.time())
        final_txs, final_reserved_ids, final_rules, final_balances, final_sequences = createblock.execute_batch([tx], [1], block_timestamp)
        
        self.assertEqual(len(final_txs), 1)
        # Verify the call to tau_manager.communicate_with_tau_multi
        # It should have been called with input_stream_values containing i5
        mock_tau_multi.assert_called()
        call_kwargs = mock_tau_multi.call_args.kwargs
        input_args = call_kwargs.get("input_stream_values", {})
        
        # Verify custom payload (stream 7) was injected
        self.assertIn(7, input_args)
        self.assertEqual(input_args[7], ["custom_data"])
        
        # Verify unified injection of block timestamp (stream 5)
        self.assertIn(5, input_args)
        self.assertEqual(input_args[5], str(block_timestamp))
        
    @patch('tau_manager.communicate_with_tau')
    @patch('tau_manager.tau_ready')
    def test_poa_engine_injects_timestamp(self, mock_ready, mock_tau):
        """Test that poa.engine.apply dynamically injects the block.header.timestamp exactly like mining."""
        mock_ready.is_set.return_value = True
        mock_tau.return_value = "1"
        
        engine = PoATauEngine()
        timestamp = 1700000000
        
        tx = {
            "sender_pubkey": chain_state.GENESIS_ADDRESS,
            "sequence_number": chain_state.get_sequence_number(chain_state.GENESIS_ADDRESS),
            "operations": {
                "1": [[chain_state.GENESIS_ADDRESS, "some_addr", "1"]],
                "7": "custom_data"
            },
            "signature": "SIG"
        }
        
        snap = chain_state.TauStateSnapshot(
            state_hash="0"*64,
            tau_bytes=b"rules",
            metadata={}
        )
        
        chain_state._balances[chain_state.GENESIS_ADDRESS] = 100
        chain_state._sequence_numbers[chain_state.GENESIS_ADDRESS] = 0
        
        # Apply replay transaction
        engine.apply(snap, [tx], timestamp)
        
        # Verify communicate_with_tau was called to validate semantic parity
        mock_tau.assert_called()
        call_kwargs = mock_tau.call_args.kwargs
        input_args = call_kwargs.get("input_stream_values", {})
        
        self.assertIn(7, input_args)
        self.assertEqual(input_args[7], ["custom_data"])
        
        # Replay must exactly use the passed-in block timestamp
        self.assertIn(5, input_args)
        self.assertEqual(input_args[5], str(timestamp))

    def test_complex_rule_temporary_spending_limit(self):
        """Test the 'Temporary Spending Limit' example from app.js."""
        import tempfile
        import os
        from tau_native import TauInterface
        
        rule = """always (
  (i3[t] = {#x1111}:bv[16]) ->
  (
    (i5[t] < {1800000000}:bv[64] && i1[t] > {5000}:bv[16] ? o5[t] = {0}:bv[16] :
      (!(i5[t] < {1800000000}:bv[64]) && i1[t] > {500}:bv[16] ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]))
  )
)."""
        
        fd, path = tempfile.mkstemp(suffix=".tau")
        with os.fdopen(fd, 'w') as f:
            f.write(rule)
            
        try:
            interface = TauInterface(path)
            
            # Phase 1: timestamp < 1800000000, amt = 4000 (Should Pass)
            res = interface.communicate(
                target_output_stream_index=5,
                input_stream_values={3: ["#x1111"], 5: ["1700000000"], 1: ["4000"]}
            )
            self.assertNotIn("0", res.split())
            
            # Phase 1: timestamp < 1800000000, amt = 6000 (Should Block)
            res = interface.communicate(
                target_output_stream_index=5,
                input_stream_values={3: ["#x1111"], 5: ["1700000000"], 1: ["6000"]}
            )
            self.assertIn("0", res.split())
    
            # Phase 2: timestamp >= 1800000000, amt = 600 (Should Block)
            res = interface.communicate(
                target_output_stream_index=5,
                input_stream_values={3: ["#x1111"], 5: ["1900000000"], 1: ["600"]}
            )
            self.assertIn("0", res.split())
    
            # Phase 2: timestamp >= 1800000000, amt = 400 (Should Pass)
            res = interface.communicate(
                target_output_stream_index=5,
                input_stream_values={3: ["#x1111"], 5: ["1900000000"], 1: ["400"]}
            )
            self.assertNotIn("0", res.split())
        finally:
            os.remove(path)

    def test_complex_rule_time_decaying_multisig(self):
        """Test the 'Time-Decaying Multi-Signature Vault' example from app.js."""
        import tempfile
        import os
        from tau_native import TauInterface
        
        rule = """always (
  (i3[t] = {#x1111}:bv[16] 
   && i5[t] < {1800000000}:bv[64]
   && !(i6[t] = {#x2222}:bv[16])) 
  ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16]
)."""
        # Note: Using :bv[16] for 3 and 6 to fit quick test compilation instead of 384
        
        fd, path = tempfile.mkstemp(suffix=".tau")
        with os.fdopen(fd, 'w') as f:
            f.write(rule)
            
        try:
            interface = TauInterface(path)
            
            # Phase 1: Before expiration, lacking cosigner (Should Block)
            res = interface.communicate(
                target_output_stream_index=5,
                input_stream_values={3: ["#x1111"], 5: ["1700000000"], 6: ["#x3333"]} # Wrong cosigner
            )
            self.assertIn("0", res.split())
            
            # Phase 1: Before expiration, WITH cosigner (Should Pass)
            res = interface.communicate(
                target_output_stream_index=5,
                input_stream_values={3: ["#x1111"], 5: ["1700000000"], 6: ["#x2222"]} # Correct cosigner
            )
            self.assertNotIn("0", res.split())
            
            # Phase 2: AFTER expiration, lacking cosigner (Should Pass)
            res = interface.communicate(
                target_output_stream_index=5,
                input_stream_values={3: ["#x1111"], 5: ["1900000000"], 6: ["#x0000"]} # No cosigner
            )
            self.assertNotIn("0", res.split())
        finally:
            os.remove(path)

if __name__ == '__main__':
    unittest.main()
