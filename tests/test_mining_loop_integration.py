
import unittest
import time
import threading
import os
import shutil
import json
import config
import db
import chain_state
from miner.service import SoleMiner
from poa.mempool import load_transactions

class TestMiningLoopIntegration(unittest.TestCase):
    def setUp(self):
        self.db_path = "test_mining_loop.sqlite"
        config.set_database_path(self.db_path)
        db.init_db()
        chain_state.init_chain_state()
        
        # Explicit state cleanup
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._current_rules_state = ""
        chain_state._tau_engine_state_hash = ""
        
        # Ensure we have a valid miner key
        self.original_key = config.MINER_PRIVKEY
        config.MINER_PRIVKEY = "1" * 64 # Dummy hex key
        
        # Mock tau_manager readiness and communication
        import tau_manager
        tau_manager.tau_ready.set()
        self.original_communicate = tau_manager.communicate_with_tau
        tau_manager.communicate_with_tau = lambda **kwargs: ""
        
        # Mock validation to accept dummy signature
        from commands import createblock
        self.original_validate = createblock._validate_signature
        createblock._validate_signature = lambda p: True
        # Also mock BLS availability check if needed, but the loop checks availability.
        # If BLS is improperly installed, it fails.
        # Let's force _BLS_AVAILABLE to be True in createblock?
        # Or just patch the check in execute_batch?
        # createblock.py imports _BLS_AVAILABLE. We can patch it.
        createblock._BLS_AVAILABLE = True

    def tearDown(self):
        if hasattr(self, 'miner'):
            self.miner.stop()
        
        # Restore tau_manager
        import tau_manager
        tau_manager.communicate_with_tau = self.original_communicate
        tau_manager.tau_ready.clear()

        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        config.MINER_PRIVKEY = self.original_key

    def test_mining_loop_automines(self):
        """Verify that the background thread mines a block when threshold is met."""
        # Setup miner with low threshold for testing
        self.miner = SoleMiner(threshold=1, max_block_interval=10.0)
        self.miner.start()
        
        # Verify initial state
        self.assertIsNone(db.get_latest_block())
        
        # Add a valid-looking transaction
        sender_pubkey = "a" * 96
        # Valid structure for sendtx/createblock validation
        tx = {
            "sender_pubkey": sender_pubkey,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 3600,
            "operations": {"1": []}, # Empty transfer list is valid
            "fee_limit": 1000,
            "signature": "b" * 192, # Dummy signature
        }
        # In test env, BLS might not be available or mocked, but structure is checked.
        # queue_transaction in sendtx.py validates BLS if available. 
        # But we are injecting directly into DB mempool, bypassing queue_transaction logic?
        # No, createblock re-validates! So we need to ensure createblock accepts it.
        # If BLS is missing in test env, it logs warning but accepts?
        # createblock.py: _validate_signature returns False if BLS avail but checks fail.
        # If no BLS lib, it returns False? No wait.
        # createblock.py line 37: if not _BLS_AVAILABLE: return False.
        # WAIT. If BLS is NOT available, _validate_signature returns False?
        # Then createblock loop: if not _BLS_AVAILABLE: print ERROR... continue.
        # So we NEED BLS available OR we need to patch createblock to think it's not needed?
        # Actually, let's look at createblock.py again.
        # Line 107: if not _BLS_AVAILABLE: print ERROR... continue.
        # So mining REQUIRES BLS in the current code unless strictly disabled?
        # But we are in a test environment. 
        # Let's mock createblock._validate_signature to return True.
        
        tx_blob = json.dumps(tx)
        db.add_mempool_tx(tx_blob, "msg_id_1", int(time.time()*1000))
        
        # Wait for miner loop (loop sleeps 0.1s, plus processing)
        # Give it 2 seconds to be safe
        for _ in range(20):
            if db.get_latest_block():
                break
            time.sleep(0.1)
            
        # Check result
        latest = db.get_latest_block()
        self.assertIsNotNone(latest, "Miner failed to produce block automatically")
        self.assertEqual(len(latest['transactions']), 1)
        print("Block created automatically:", latest['block_hash'])

    def test_mining_loop_time_threshold(self):
        """Verify that miner triggers on time interval even if threshold is not met."""
        # Setup miner with HIGH threshold (10) but LOW interval (1.0s)
        self.miner = SoleMiner(threshold=10, max_block_interval=1.0)
        self.miner.start()
        
        self.assertIsNone(db.get_latest_block())
        
        # Add just 1 transaction (valid structure)
        sender_pubkey = "c" * 96
        tx = {
            "sender_pubkey": sender_pubkey,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 3600,
            "operations": {}, 
            "fee_limit": 1000,
            "signature": "d" * 192,
        }
        tx_blob = json.dumps(tx)
        db.add_mempool_tx(tx_blob, "msg_id_time", int(time.time()*1000))
        
        # Wait 0.5s - should NOT mine yet
        time.sleep(0.5)
        self.assertIsNone(db.get_latest_block(), "Mined too early! Should wait for time interval.")
        
        # Wait another 1.0s (total 1.5s > 1.0s interval)
        # Give loop a moment to react
        for _ in range(20):
            if db.get_latest_block():
                break
            time.sleep(0.1)
            
        latest = db.get_latest_block()
        self.assertIsNotNone(latest, "Failed to mine after time interval exceeded")
        self.assertEqual(len(latest['transactions']), 1)
        print("Block created by time threshold:", latest['block_hash'])

if __name__ == '__main__':
    unittest.main()
