
import unittest
import os
import json
import time
import sys
from unittest.mock import MagicMock, patch

# --- MOCKING PRE-SETUP ---
# Inject mocks BEFORE any project imports can trigger dependencies
mock_blake3 = MagicMock()
mock_hasher = MagicMock()
mock_hasher.digest.return_value = b'\x00' * 32
mock_hasher.hexdigest.return_value = "0" * 64

# FIX: poa/state.py calls `blake3(data).hexdigest()`
# This means `mock_blake3(data)` must return `mock_hasher`.
# `mock_blake3` IS the module. So `mock_blake3.blake3` is the class/function.
mock_blake3.blake3.return_value = mock_hasher
mock_blake3.blake3.side_effect = None # Remove lambda, return_value is enough for constructor

# ALSO: In case `from blake3 import blake3` happens:
# Then the imported `blake3` IS `mock_blake3.blake3`.
# So calling `blake3(data)` calls `mock_blake3.blake3(data)`.
# This returns `mock_hasher`.
# `mock_hasher.hexdigest()` returns string.

# sys.modules["blake3"] = mock_blake3
# 
# # Mock py_ecc
# mock_py_ecc = MagicMock()
# # If imported as 'from py_ecc.bls import G2Basic', and we set sys.modules['py_ecc.bls']=mock_py_ecc,
# # then G2Basic is mock_py_ecc.G2Basic.
# mock_py_ecc.G2Basic.Verify.return_value = True
# mock_py_ecc.G2Basic.Sign.return_value = b'\x00' * 48
# 
# # If accessed as py_ecc.bls.G2Basic (via parent module)
# mock_py_ecc.bls.G2Basic.Verify.return_value = True
# mock_py_ecc.bls.G2Basic.Sign.return_value = b'\x00' * 48
# 
# # sys.modules["py_ecc"] = mock_py_ecc
# # sys.modules["py_ecc.bls"] = mock_py_ecc

# Remove debug patch
if hasattr(json, 'dumps') and getattr(json.dumps, '__name__', '') == 'debug_dumps':
    json.dumps = original_dumps
# -------------------------

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config
import db
import chain_state
from commands import createblock

class TestMinerHardening(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_hardening.db"
        config.STRING_DB_PATH = self.test_db
        db._db_conn = None 
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        db.init_db()
        
        # Reset Chain State
        chain_state._balances = {}
        chain_state._sequence_numbers = {}
        chain_state._current_rules_state = ""
        
        # Disable auto-faucet for strict balance testing
        config.TESTNET_AUTO_FAUCET = False
        
        # Pre-seed UserOverspend balance
        chain_state._balances["UserOverspend"] = 100

    def tearDown(self):
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_stale_reservation_release(self):
        print("\n[TEST] Verifying Stale Mempool Reservation Release...")
        

        # 1. Add TX
        tx_hash = "stale_tx"
        db.add_mempool_tx(json.dumps({"id": "stale"}), tx_hash, int(time.time()*1000))
        
        # 2. Reserve it
        res1 = db.reserve_mempool_txs(limit=1)
        self.assertEqual(len(res1), 1)
        
        # 3. Hack: set reserved_at to 2 hours ago
        stale_time = int((time.time() - 7200) * 1000)
        with db._db_lock:
             db._db_conn.execute("UPDATE mempool SET reserved_at = ? WHERE tx_hash = ?", (stale_time, tx_hash))
             db._db_conn.commit()
             
        # 4. Reserve again (should pick up the stale one)
        res2 = db.reserve_mempool_txs(limit=1, max_age_seconds=60)
        
        self.assertEqual(len(res2), 1, "Should pick up stale transaction")
        self.assertEqual(res2[0]['tx_hash'], tx_hash)
        
        print("[TEST] Stale reservation released and re-reserved.")

    @patch('commands.createblock._validate_signature')
    @patch('commands.createblock.tau_manager')
    def test_intra_transaction_overspend(self, mock_tau, mock_sig):
        print("\n[TEST] Verifying Intra-Transaction Overspend Rejection...")
        mock_tau.tau_ready.is_set.return_value = True
        
        # Side effect to handle transfer validation (must return amount)
        def tau_side_effect(**kwargs):
            if kwargs.get('target_output_stream_index') == 1:
                vals = kwargs.get('input_stream_values', {})
                return vals.get(1, "0") 
            return "Success"
        mock_tau.communicate_with_tau.side_effect = tau_side_effect
        
        mock_sig.return_value = True
        
        # Setup: Account with 100 coins (done in setUp)
        
        # Create TX with 2 transfers: 60 + 50 = 110 (> 100)
        payload = json.dumps({
            "sender_pubkey": "UserOverspend",
            "sequence_number": 0,
            "expiration_time": int(time.time() + 3600),
            "operations": {
                "1": [
                    ["UserOverspend", "Alice", "60"],
                    ["UserOverspend", "Bob", "50"]
                ]
            }
        })
        db.add_mempool_tx(payload, "hash_overspend", 1000)
        
        # Run CreateBlock
        res = createblock.create_block_from_mempool()
        
        # Verify Rejection
        if "transactions" in res:
             self.assertEqual(len(res["transactions"]), 0, "Should have rejected overspend tx")
        else:
             self.assertIn("message", res)
             
        # Balances should remain 100
        self.assertEqual(chain_state._balances.get("UserOverspend"), 100)
        
        print("[TEST] Intra-TX overspend rejected.")

    def test_strict_bls_enforcement(self):
        print("\n[TEST] Verifying Strict BLS Enforcement...")
        
        # We need to UN-MOCK _BLS_AVAILABLE in createblock if it was imported as True
        # But wait, createblock imports it at module level.
        # We can patch `commands.createblock._BLS_AVAILABLE` to False.
        
        with patch('commands.createblock._BLS_AVAILABLE', False):
            # Add TX
            tx = json.dumps({"sender_pubkey": "UserBLS", "sequence_number": 0, "expiration_time": int(time.time()+999)})
            db.add_mempool_tx(tx, "hash_bls", 1000)
            
            # Run CreateBlock
            res = createblock.create_block_from_mempool()
            
            # Should reject
            passed_txs = res.get("transactions", [])
            self.assertEqual(len(passed_txs), 0, "Should reject all TXs if BLS missing")
        
        print("[TEST] Strict BLS passed (refused to mine).")

    @patch('commands.createblock._validate_signature')
    @patch('commands.createblock.tau_manager')
    def test_faucet_safety_no_negative_balance(self, mock_tau, mock_sig):
        print("\n[TEST] Verifying Faucet Safety (No Negative Balance)...")
        # Ensure auto-faucet is ON for this test
        config.TESTNET_AUTO_FAUCET = True
        
        # Configure mock_tau to distinguish calls
        # 1. Rule validation (stream 0) -> "Success"
        # 2. Transfer validation (stream 1) -> "10000" (the amount)
        def tau_side_effect(**kwargs):
            if kwargs.get('target_output_stream_index') == 1:
                # Validating transfer, echo amount
                # Input args usually in input_stream_values
                vals = kwargs.get('input_stream_values', {})
                return vals.get(1, "10000") 
            return "Success"
            
        mock_tau.communicate_with_tau.side_effect = tau_side_effect
        mock_tau.tau_ready.is_set.return_value = True
        
        mock_sig.return_value = True
        
        # User is NEW (not in balances)
        if "UserNew" in chain_state._balances:
            del chain_state._balances["UserNew"]
            
        # Send 10,000 (valid if faucet gives 100,000)
        payload = json.dumps({
            "sender_pubkey": "UserNew",
            "sequence_number": 0,
            "expiration_time": int(time.time() + 3600),
            "operations": {
                "1": [["UserNew", "Bob", "10000"]]
            }
        })
        db.add_mempool_tx(payload, "hash_faucet", 1000)
        
        # Run Mining
        try:
            res = createblock.create_block_from_mempool()
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.fail(f"Block creation crashed: {e}")
        
        # Should ACCEPT
        if "transactions" not in res or len(res["transactions"]) != 1:
             print(f"DEBUG: Block creation result: {res}")
             
        self.assertEqual(len(res.get("transactions", [])), 1)
        
        # VERIFY STATE: Balance should be 100,000 - 10,000 = 90,000
        # If bug exists (commit uses 0), balance would be -10,000
        final_bal = chain_state._balances.get("UserNew")
        self.assertEqual(final_bal, 90000, f"Faucet balance incorrect. Got {final_bal}, expected 90000")
        
        print("[TEST] Faucet safety passed (Balance initialized correctly).")

if __name__ == '__main__':
    unittest.main()
