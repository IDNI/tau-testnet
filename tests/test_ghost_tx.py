import unittest
import os
import json
import time
import sys

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db

# Mock blake3 if missing (for test environment)
# try:
import blake3
# except ImportError:
#     from unittest.mock import MagicMock
#     mock_blake3 = MagicMock()
#     mock_hasher = MagicMock()
#     mock_hasher.digest.return_value = b'\x00' * 32
#     mock_hasher.hexdigest.return_value = "0" * 64
#     # mock blake3.blake3(data).digest()
#     mock_blake3.blake3.return_value = mock_hasher
#     sys.modules["blake3"] = mock_blake3
#     print("[TEST] Mocked blake3 module")

class TestGhostTx(unittest.TestCase):
    def setUp(self):
        # Use a temporary DB
        self.test_db = "test_ghost_tx.db"
        config.STRING_DB_PATH = self.test_db
        db._db_conn = None # Force re-init
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        db.init_db()

    def tearDown(self):
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_mempool_reservation_isolation(self):
        print("\n[TEST] Verifying Mempool Reservation Isolation (Ghost TX Fix)...")
        
        # 1. Add Initial Transaction (TX A)
        payload_a = json.dumps({"id": "tx_a", "sender": "Alice"})
        db.add_mempool_tx(payload_a, "hash_a", 1000)
        print("[TEST] Added TX A")

        # 2. Miner: Reserve Transactions (Snapshot)
        reserved = db.reserve_mempool_txs(limit=10)
        print(f"[TEST] Miner reserved {len(reserved)} transactions")
        
        self.assertEqual(len(reserved), 1, "Should have reserved 1 transaction")
        self.assertEqual(reserved[0]['tx_hash'], "hash_a", "Reserved TX should be A")
        
        # 3. Simulate "Ghost Transaction" Arrival (TX B)
        # This occurs while Miner is "working" (has reserved A)
        payload_b = json.dumps({"id": "tx_b", "sender": "Bob"})
        db.add_mempool_tx(payload_b, "hash_b", 2000)
        print("[TEST] Added TX B (Ghost Candidate) during mining window")

        # 4. Verify TX B is Pending (Not Reserved)
        cur = db._db_conn.cursor()
        cur.execute("SELECT status FROM mempool WHERE tx_hash='hash_b'")
        status_b = cur.fetchone()[0]
        self.assertEqual(status_b, "pending", "TX B must remain 'pending' and not be affected by current mining batch")
        
        # 5. Simulate Miner Cleanup (Atomic Commit)
        # Miner deletes ONLY what it processed (TX A)
        ids_to_remove = [r['id'] for r in reserved]
        db.remove_transactions(ids_to_remove)
        print(f"[TEST] Miner removed processed IDs: {ids_to_remove}")

        # 6. Verify State Safety
        # TX A should be gone (mined)
        cur.execute("SELECT count(*) FROM mempool WHERE tx_hash='hash_a'")
        count_a = cur.fetchone()[0]
        self.assertEqual(count_a, 0, "TX A should be removed after mining")
        
        # TX B should REMAIN (Safe from data loss)
        cur.execute("SELECT count(*) FROM mempool WHERE tx_hash='hash_b'")
        count_b = cur.fetchone()[0]
        self.assertEqual(count_b, 1, "TX B must survive the mining process")
        
        print("[TEST] SUCCESS: Ghost TX B was preserved!")



from unittest.mock import MagicMock, patch
from commands import createblock

class TestGhostTxIntegration(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_ghost_integration.db"
        config.DB_PATH = self.test_db
        config.STRING_DB_PATH = self.test_db # Ensure db.py uses this
        config.TESTNET_AUTO_FAUCET = True # Allow funding
        
        # Reset DB connection
        db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        db.init_db()
        
        # Reset Chain State (Important for isolation)
        import chain_state
        chain_state._balances = {}
        chain_state._sequence_numbers = {}
        chain_state._current_rules_state = ""
        
    def tearDown(self):
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    @patch('commands.createblock.tau_manager')
    @patch('commands.createblock._validate_signature')
    def test_rule_change_and_rejection(self, mock_sig, mock_tau):
        # Mock Tau Manager
        mock_tau.tau_ready.is_set.return_value = True
        mock_tau.communicate_with_tau.return_value = "Success"
        
        # Mock Sig Validation (Always valid for this test)
        mock_sig.return_value = True
        
        print("\n[TEST] Verifying Rule Changes & Rejection Logic (Integration)...")
        
        # 1. Test Rule Application
        # Insert TX with Rule
        payload_rule = json.dumps({
            "sender_pubkey": "UserRule",
            "sequence_number": 0,
            "expiration_time": int(time.time() + 3600),
            "operations": {"0": "rule X"}
        })
        db.add_mempool_tx(payload_rule, "hash_rule", 1000)
        
        # Run Mining
        block_res = createblock.create_block_from_mempool()
        
        # Verify Block
        self.assertEqual(len(block_res['transactions']), 1)
        self.assertNotEqual(block_res['header']['state_hash'], "", "State hash must be set")
        
        # Verify Global State (simulating next block effect)
        # Note: createblock updates the global chain_state object in Phase 6
        import chain_state
        self.assertEqual(chain_state._current_rules_state, "rule X")
        
        print("[TEST] Rule correctly applied and state hash updated.")
        
        # 2. Test Rejection (Bad Sequence)
        # Insert TX with bad sequence (100 vs expected 0 for new user)
        payload_bad = json.dumps({
            "sender_pubkey": "UserBad",
            "sequence_number": 100, 
            "expiration_time": int(time.time() + 3600),
            "operations": {"1": [["UserBad", "UserX", "10"]]}
        })
        db.add_mempool_tx(payload_bad, "hash_bad", 2000)
        
        # Run Mining
        block_res = createblock.create_block_from_mempool()
        
        # Verify Block (Should be empty or contain message)
        # Our logic returns dict with "message" if empty block is created/skipped
        if "transactions" in block_res:
             self.assertEqual(len(block_res['transactions']), 0, "Bad TX should be rejected")
        else:
             self.assertIn("message", block_res)
             
        # Verify Mempool is clean (Rejected TX should be removed)
        cur = db._db_conn.cursor()
        cur.execute("SELECT count(*) FROM mempool")
        count = cur.fetchone()[0]
        self.assertEqual(count, 0, "Rejected TX should be removed from mempool")
        
        print("[TEST] Rejected TX was correctly removed.")

if __name__ == '__main__':
    unittest.main()
