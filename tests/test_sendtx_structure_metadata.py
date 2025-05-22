import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
import time
import hashlib

# Add the project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

TEST_DB_PATH = "test_tau_string_db_structure.sqlite" 
os.environ["TAU_DB_PATH"] = TEST_DB_PATH

from commands import sendtx
import chain_state
import db
import sbf_defs # Though not directly used, imported by sendtx
import utils
from commands.sendtx import _get_signing_message_bytes # Needed for _create_tx_json
import py_ecc.bls as _bls_module # Needed for _create_tx_json if sender_privkey is used
from py_ecc.bls import G2Basic as bls # Needed for _create_tx_json if sender_privkey is used

# --- Helper Addresses ---
GENESIS_ADDR = chain_state.GENESIS_ADDRESS
ADDR_A = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a"
ADDR_B = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b"

class MockTauManager:
    def __init__(self):
        self.mode = "echo"
        self.sbf_input_received = None
        self.tau_call_count = 0

    def communicate_with_tau(self, sbf_input_str):
        self.tau_call_count += 1
        self.sbf_input_received = sbf_input_str
        # For structure tests, Tau's detailed SBF logic is less critical.
        # We mostly care that it's called or not, or echoes for simple cases.
        if self.mode == "echo":
            return sbf_input_str
        elif hasattr(sbf_defs, self.mode):
            return getattr(sbf_defs, self.mode)
        return sbf_input_str # Default echo

class TestSendTxStructureMetadata(unittest.TestCase):
    def _cleanup_db(self):
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)
        if db._db_conn:
            db._db_conn.close()
        db._db_conn = None

    def setUp(self):
        print(f"\n--- Test: {self.id()} ---")
        self._cleanup_db()
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.STRING_DB_PATH = TEST_DB_PATH
        db.init_db()
        chain_state.init_chain_state()

        self.mock_tau_manager_instance = MockTauManager()
        self.patcher_tau_comm = patch('commands.sendtx.tau_manager.communicate_with_tau', 
                                      self.mock_tau_manager_instance.communicate_with_tau)
        self.mock_tau_comm = self.patcher_tau_comm.start()

        self.patcher_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None))
        self.mock_validate_pubkey = self.patcher_validate_pubkey.start()
        
        sendtx._PY_ECC_AVAILABLE = False # Crypto aspects tested separately
        print(f"[SETUP] Patched tau_manager and _validate_bls12_381_pubkey.")

    def tearDown(self):
        self.patcher_tau_comm.stop()
        self.patcher_validate_pubkey.stop()
        self._cleanup_db()
        print(f"[TEARDOWN] Test {self.id()} finished.")

    def _create_tx_json(self, operations_or_transfers, expiration_time=None, sequence_number=None, sender_privkey=None, signature=None, sender_pubkey=None, fee_limit="0"):
        if isinstance(operations_or_transfers, list):
            ops = {"1": operations_or_transfers}
        else:
            ops = operations_or_transfers
        
        exp_time = expiration_time
        if exp_time is None:
            exp_time = int(time.time()) + 1000

        pk_hex_to_use = sender_pubkey
        if sender_privkey is not None:
            privkey_int = sender_privkey
            pubkey_bytes = bls.SkToPk(privkey_int)
            pk_hex_to_use = pubkey_bytes.hex()
        elif pk_hex_to_use is None:
            pk_hex_to_use = GENESIS_ADDR

        seq = sequence_number
        if seq is None:
            # Default to 0 for structure tests if not testing sequence numbers specifically
            # or if _PY_ECC_AVAILABLE is False (where sequence numbers aren't strictly enforced)
            seq = chain_state.get_sequence_number(pk_hex_to_use) if sendtx._PY_ECC_AVAILABLE else 0

        tx_dict = {
            "sender_pubkey": pk_hex_to_use,
            "sequence_number": seq, # Will be int
            "expiration_time": exp_time, # Will be int
            "operations": ops,
            "fee_limit": fee_limit, # String or int
        }

        # Signature handling (can be omitted for some structure tests by passing signature=None)
        if sender_privkey is not None:
            msg_bytes = _get_signing_message_bytes(tx_dict) # Requires all fields to be present in tx_dict
            msg_hash = hashlib.sha256(msg_bytes).digest()
            sig_bytes = bls.Sign(sender_privkey, msg_hash)
            tx_dict["signature"] = sig_bytes.hex()
        elif signature is not None: # Allow explicit signature string
            tx_dict["signature"] = signature
        # If signature is None and sender_privkey is None, "signature" field might be missing
        # queue_transaction will raise ValueError if 'signature' is missing from payload

        return json.dumps(tx_dict)

    def test_expired_transaction(self):
        print("[TEST_CASE] Fail: Transaction expired")
        expired_time = int(time.time()) - 10
        # _create_tx_json needs a signature field, even if dummy, to not break _get_signing_message_bytes if used
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, "1"]], expiration_time=expired_time, signature="DUMMY_SIG_FOR_EXPIRY_TEST")
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction expired at"), f"Unexpected: {result}")
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_from_address_mismatch_sender_pubkey(self):
        print("[TEST_CASE] Fail: Transfer 'from' address not matching sender_pubkey")
        self.mock_tau_manager_instance.mode = "auto"
        # ADDR_B is the sender, but transfer is from GENESIS_ADDR
        invalid_transfer = [GENESIS_ADDR, ADDR_A, "1"]
        tx_json = self._create_tx_json(
            operations_or_transfers=[invalid_transfer], 
            sender_pubkey=ADDR_B, # Explicitly set sender_pubkey
            signature="DUMMY_SIG" # Dummy sig for structure test
        )
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Res: {result}")
        self.assertIn(f"Transfer #1 'from' address {GENESIS_ADDR} does not match sender_pubkey {ADDR_B}", result)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_missing_sender_pubkey(self):
        print("[TEST_CASE] Fail: Missing sender_pubkey field")
        tx_dict = {
            # "sender_pubkey": GENESIS_ADDR, # Missing
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, # from will be GENESIS_ADDR
            "fee_limit": "0",
            "signature": "SIG_MISSING_SENDER_PUBKEY"
        }
        tx_json = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "Missing 'sender_pubkey' in transaction."):
            sendtx.queue_transaction(tx_json)

    def test_missing_sequence_number(self):
        print("[TEST_CASE] Fail: Missing sequence_number field")
        tx_dict = {
            "sender_pubkey": GENESIS_ADDR,
            # "sequence_number": 0, # Missing
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, 
            "fee_limit": "0",
            "signature": "SIG_MISSING_SEQ"
        }
        tx_json = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "Missing 'sequence_number' in transaction."):
            sendtx.queue_transaction(tx_json)

    def test_missing_expiration_time(self):
        print("[TEST_CASE] Fail: Missing expiration_time field")
        tx_dict = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": 0,
            # "expiration_time": int(time.time()) + 1000, # Missing
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, 
            "fee_limit": "0",
            "signature": "SIG_MISSING_EXP_TIME"
        }
        tx_json = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "Missing 'expiration_time' in transaction."):
            sendtx.queue_transaction(tx_json)

    def test_missing_operations(self):
        print("[TEST_CASE] Fail: Missing operations field")
        tx_dict = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            # "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, # Missing
            "fee_limit": "0",
            "signature": "SIG_MISSING_OPS"
        }
        tx_json = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "Missing or invalid 'operations' in transaction."):
            sendtx.queue_transaction(tx_json)
    
    def test_invalid_operations_type(self):
        print("[TEST_CASE] Fail: Invalid operations field type (not dict)")
        tx_dict = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": "not_a_dict", # Invalid type
            "fee_limit": "0",
            "signature": "SIG_INVALID_OPS_TYPE"
        }
        tx_json = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "Missing or invalid 'operations' in transaction."):
            sendtx.queue_transaction(tx_json)

    def test_missing_fee_limit(self):
        print("[TEST_CASE] Fail: Missing fee_limit field")
        tx_dict = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, 
            # "fee_limit": "0", # Missing
            "signature": "SIG_MISSING_FEE_LIMIT"
        }
        tx_json = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "Missing 'fee_limit' in transaction."):
            sendtx.queue_transaction(tx_json)

    def test_missing_signature_field(self):
        print("[TEST_CASE] Fail: Missing signature field")
        # Note: _create_tx_json normally adds a signature if sender_privkey or signature arg is provided.
        # To test missing signature, we construct the dict manually.
        tx_dict_missing_sig = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, 
            "fee_limit": "0"
            # "signature" field is omitted
        }
        tx_json = json.dumps(tx_dict_missing_sig)
        with self.assertRaisesRegex(ValueError, "Missing 'signature' in transaction."):
            sendtx.queue_transaction(tx_json)
    
    def test_invalid_sequence_number_type(self):
        print("[TEST_CASE] Fail: Invalid sequence_number type (not int)")
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, "1"]], sequence_number="not_an_int", signature="DUMMY_SIG")
        # The _create_tx_json might convert it if not careful, so construct manually for robustness
        tx_dict = json.loads(tx_json)
        tx_dict["sequence_number"] = "WRONG_TYPE"
        tx_json_manual = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "'sequence_number' must be an integer. Got str"):
            sendtx.queue_transaction(tx_json_manual)

    def test_invalid_expiration_time_type(self):
        print("[TEST_CASE] Fail: Invalid expiration_time type (not int)")
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, "1"]], expiration_time="not_an_int", signature="DUMMY_SIG")
        tx_dict = json.loads(tx_json)
        tx_dict["expiration_time"] = "WRONG_TYPE"
        tx_json_manual = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "'expiration_time' must be an integer. Got str"):
            sendtx.queue_transaction(tx_json_manual)

    def test_invalid_fee_limit_type(self):
        print("[TEST_CASE] Fail: Invalid fee_limit type (not string or int)")
        # Our _create_tx_json uses string "0" by default.
        # Let's try creating one with a float which is invalid.
        tx_dict = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, 
            "fee_limit": 0.5, # Invalid type
            "signature": "SIG_INVALID_FEE_TYPE"
        }
        tx_json_manual = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "'fee_limit' must be a string or integer. Got float"):
            sendtx.queue_transaction(tx_json_manual)

    def test_invalid_signature_type(self):
        print("[TEST_CASE] Fail: Invalid signature type (not str)")
        tx_dict = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]}, 
            "fee_limit": "0",
            "signature": 12345 # Invalid type
        }
        tx_json_manual = json.dumps(tx_dict)
        with self.assertRaisesRegex(ValueError, "'signature' must be a string. Got int"):
            sendtx.queue_transaction(tx_json_manual)

    def test_invalid_transfers_list_type(self):
        print("[TEST_CASE] Fail: Invalid transfers (key '1') type, not a list")
        tx_json = self._create_tx_json(operations_or_transfers={"1": "not_a_list"}, signature="DUMMY_SIG")
        with self.assertRaisesRegex(ValueError, "Transfers \(key '1'\) must be a list"):
            sendtx.queue_transaction(tx_json)

    def test_invalid_transfer_entry_format_in_list(self):
        print("[TEST_CASE] Fail: Invalid format for an entry in transfers list")
        # Transfer entry should be [from, to, amount], here it's just a string
        tx_json = self._create_tx_json(operations_or_transfers=[[GENESIS_ADDR, ADDR_A, "5"], "invalid_entry_format"], signature="DUMMY_SIG")
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid. Transfer #2 has invalid format"), f"Res: {result}")


if __name__ == '__main__':
    unittest.main(verbosity=2) 