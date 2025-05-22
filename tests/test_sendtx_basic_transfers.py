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

TEST_DB_PATH = "test_tau_string_db_basic.sqlite" # Use a different DB for this test suite
os.environ["TAU_DB_PATH"] = TEST_DB_PATH

from commands import sendtx
import chain_state
import db
import sbf_defs
import utils # For sbf_atom_to_bits, bits_to_sbf_atom, decimal_to_8bit_binary
from commands.sendtx import _get_signing_message_bytes # Needed for _create_tx_json
import py_ecc.bls as _bls_module # Needed for _create_tx_json if sender_privkey is used
from py_ecc.bls import G2Basic as bls # Needed for _create_tx_json if sender_privkey is used

# --- Helper Addresses (copied from original test_sendtx.py) ---
GENESIS_ADDR = chain_state.GENESIS_ADDRESS
ADDR_A = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a"
ADDR_B = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b"
ADDR_C = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c"
INVALID_ADDR_SHORT = "short"
INVALID_ADDR_NON_HEX = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000g"

def sbf_to_int_array(sbf_atom, num_bits_per_field):
    """
    Converts an SBF atom into an array of integers.
    Simplified: assumes direct bit concatenation for fields.
    num_bits_per_field: list of bit lengths for each field, e.g., [3, 3, 8, 8]
    """
    if not hasattr(utils, 'sbf_atom_to_bits'):
        raise NotImplementedError("utils.sbf_atom_to_bits is needed for this mock helper")
    
    bits = utils.sbf_atom_to_bits(sbf_atom)
    if bits is None:
        raise ValueError(f"Could not convert SBF atom {sbf_atom} to bits.")

    values = []
    current_pos = 0
    expected_total_bits = sum(num_bits_per_field)
    if len(bits) != expected_total_bits:
        print(f"[WARN][MockHelper] Bit length mismatch: expected {expected_total_bits}, got {len(bits)} for SBF {sbf_atom}. Will try to parse.")
        if len(bits) < expected_total_bits:
             raise ValueError(f"SBF {sbf_atom} converted to {len(bits)} bits, less than expected {expected_total_bits}")

    for length in num_bits_per_field:
        field_bits = bits[current_pos : current_pos + length]
        if len(field_bits) != length:
            raise ValueError(f"Error parsing SBF: Not enough bits for field. Expected {length}, got {len(field_bits)}")
        values.append(int(field_bits, 2))
        current_pos += length
    return values

class MockTauManager:
    def __init__(self):
        self.mode = "echo"
        self.sbf_input_received = None
        self.tau_call_count = 0

    def communicate_with_tau(self, sbf_input_str):
        self.tau_call_count += 1
        self.sbf_input_received = sbf_input_str
        print(f"\n[MOCK_TAU][{self.tau_call_count}] Received SBF Input: {sbf_input_str}")
        try:
            fields = sbf_to_int_array(sbf_input_str, [4, 4, 4, 4])
            amount_val, balance_val, _from_id_val, _to_id_val = fields
            print(f"[MOCK_TAU] Parsed SBF: Amount={amount_val} (4b), BalanceForTau={balance_val} (4b), FromID={_from_id_val} (4b), ToID={_to_id_val} (4b)")
        except Exception as e:
            print(f"[MOCK_TAU] Error parsing SBF input '{sbf_input_str}' for detailed checks: {e}. Defaulting to echo or preset mode.")
            if self.mode == "echo":
                print(f"[MOCK_TAU] Output: {sbf_input_str} (echo due to parse error or mode)")
                return sbf_input_str
            elif hasattr(sbf_defs, self.mode):
                sbf_code = getattr(sbf_defs, self.mode)
                print(f"[MOCK_TAU] Output: {sbf_code} (mode: {self.mode})")
                return sbf_code
            else:
                print(f"[MOCK_TAU] CRITICAL: Unknown mode '{self.mode}' and SBF parse error. Echoing.")
                return sbf_input_str

        if self.mode == "force_insufficient_funds":
            print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF} (mode: force_insufficient_funds)")
            return sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF
        if self.mode == "force_src_eq_dest":
            print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_SRC_EQ_DEST_SBF} (mode: force_src_eq_dest)")
            return sbf_defs.FAIL_SRC_EQ_DEST_SBF
        if self.mode == "force_zero_amount":
            print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_ZERO_AMOUNT_SBF} (mode: force_zero_amount)")
            return sbf_defs.FAIL_ZERO_AMOUNT_SBF
        
        if self.mode == "auto" or self.mode == "echo":
            if amount_val > balance_val:
                print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF} (auto: amount {amount_val} > balance_for_tau {balance_val})")
                return sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF
            if _from_id_val == _to_id_val:
                print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_SRC_EQ_DEST_SBF} (auto: from_id {_from_id_val} == to_id {_to_id_val})")
                return sbf_defs.FAIL_SRC_EQ_DEST_SBF
            if amount_val == 0:
                print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_ZERO_AMOUNT_SBF} (auto: amount_val is {amount_val})")
                return sbf_defs.FAIL_ZERO_AMOUNT_SBF
            
            print(f"[MOCK_TAU] Output: {sbf_input_str} (auto: all checks passed)")
            return sbf_input_str

        if hasattr(sbf_defs, self.mode):
            sbf_code = getattr(sbf_defs, self.mode)
            print(f"[MOCK_TAU] Output: {sbf_code} (mode: {self.mode})")
            return sbf_code

        print(f"[MOCK_TAU] WARN: Unhandled mock mode '{self.mode}'. Echoing SBF.")
        return sbf_input_str

class TestSendTxBasicTransfers(unittest.TestCase):
    
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
        # Ensure db path is set before init_db
        db.STRING_DB_PATH = TEST_DB_PATH # Explicitly set for this test module instance
        db.init_db() # This will use the TEST_DB_PATH from os.environ or the one we just set
        chain_state.init_chain_state()

        self.mock_tau_manager_instance = MockTauManager()
        self.patcher_tau_comm = patch('commands.sendtx.tau_manager.communicate_with_tau', 
                                      self.mock_tau_manager_instance.communicate_with_tau)
        self.mock_tau_comm = self.patcher_tau_comm.start()

        self.patcher_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None))
        self.mock_validate_pubkey = self.patcher_validate_pubkey.start()
        
        sendtx._PY_ECC_AVAILABLE = False # Default to no crypto for basic tests
        print(f"[SETUP] Patched tau_manager and _validate_bls12_381_pubkey. Initial Genesis Balance: {chain_state.get_balance(GENESIS_ADDR)}")

    def tearDown(self):
        self.patcher_tau_comm.stop()
        self.patcher_validate_pubkey.stop()
        self._cleanup_db()
        print(f"[TEARDOWN] Test {self.id()} finished.")

    def _create_tx_json(self, operations_or_transfers, expiration_time=None, sequence_number=None, sender_privkey=None, signature=None, sender_pubkey=None):
        if isinstance(operations_or_transfers, list):
            ops = {"1": operations_or_transfers}
        else:
            ops = operations_or_transfers
        exp_time = expiration_time if expiration_time is not None else int(time.time()) + 1000
        
        pk_hex_to_use = sender_pubkey
        if sender_privkey is not None:
            # Ensure bls is available if sender_privkey is used, even if _PY_ECC_AVAILABLE is False for sendtx module
            privkey_int = sender_privkey 
            pubkey_bytes = bls.SkToPk(privkey_int)
            pk_hex_to_use = pubkey_bytes.hex()
        elif pk_hex_to_use is None:
             pk_hex_to_use = GENESIS_ADDR # Default to Genesis if no key info provided

        seq = sequence_number if sequence_number is not None else chain_state.get_sequence_number(pk_hex_to_use)
        
        tx_dict = {
            "sender_pubkey": pk_hex_to_use,
            "sequence_number": seq,
            "expiration_time": exp_time,
            "operations": ops,
            "fee_limit": "0",
        }

        if sender_privkey is not None:
            # Signing logic (requires _get_signing_message_bytes, hashlib, bls)
            msg_bytes = _get_signing_message_bytes(tx_dict)
            msg_hash = hashlib.sha256(msg_bytes).digest()
            sig_bytes = bls.Sign(sender_privkey, msg_hash)
            tx_dict["signature"] = sig_bytes.hex()
        elif signature is not None:
            tx_dict["signature"] = signature
        else:
            tx_dict["signature"] = "SIG_FOR_BASIC_TESTS" # Dummy signature for basic tests
        return json.dumps(tx_dict)

    def test_successful_single_transfer(self):
        print("[TEST_CASE] Successful single transfer: Genesis -> ADDR_A, 10 AGRS")
        self.mock_tau_manager_instance.mode = "auto"
        
        initial_genesis_balance = chain_state.get_balance(GENESIS_ADDR)
        initial_addr_a_balance = chain_state.get_balance(ADDR_A)
        amount = 10

        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount)]])
        result = sendtx.queue_transaction(tx_json)

        self.assertTrue(result.startswith("SUCCESS: Transaction queued"), f"Unexpected result: {result}")
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), initial_genesis_balance - amount)
        self.assertEqual(chain_state.get_balance(ADDR_A), initial_addr_a_balance + amount)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)

    def test_successful_multiple_transfers(self):
        print("[TEST_CASE] Successful multiple transfers: G->A (10), G->B (5)")
        self.mock_tau_manager_instance.mode = "auto"

        initial_genesis_balance = chain_state.get_balance(GENESIS_ADDR)
        amount1 = 10
        amount2 = 5

        tx_list = [
            [GENESIS_ADDR, ADDR_A, str(amount1)],
            [GENESIS_ADDR, ADDR_B, str(amount2)]
        ]
        tx_json = self._create_tx_json(tx_list)
        result = sendtx.queue_transaction(tx_json)

        self.assertTrue(result.startswith("SUCCESS: Transaction queued"), f"Unexpected result: {result}")
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), initial_genesis_balance - amount1 - amount2)
        self.assertEqual(chain_state.get_balance(ADDR_A), amount1)
        self.assertEqual(chain_state.get_balance(ADDR_B), amount2)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 2)

    def test_fail_insufficient_funds_actual_balance_tau_rejection(self):
        print("[TEST_CASE] Fail: Insufficient actual funds (Tau Rejection - 4bit amount/balance)")
        chain_state._balances[GENESIS_ADDR] = 10
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), 10)

        self.mock_tau_manager_instance.mode = "auto" 
        amount_to_send = 12
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount_to_send)]])
        result = sendtx.queue_transaction(tx_json)
        
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn("rejected by tau logic", result.lower())
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), 10) # Balance unchanged
        self.assertEqual(chain_state.get_balance(ADDR_A), 0)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_amount_too_large_for_sbf_python(self):
        print("[TEST_CASE] Fail: Amount > 15 (Python util validation for 4-bit SBF encoding)")
        self.mock_tau_manager_instance.mode = "auto"
        amount_to_send = 16
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount_to_send)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("ERROR: Could not process transfer #1"), f"Unexpected result: {result}")
        self.assertIn("Invalid amount '16': Must be a number between 0 and 15", result)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE) # Unchanged
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_fail_src_eq_dest_tau_rejection(self):
        print("[TEST_CASE] Fail: Source == Destination (Tau Rejection)")
        self.mock_tau_manager_instance.mode = "auto" 
        amount = 10
        tx_json = self._create_tx_json([[GENESIS_ADDR, GENESIS_ADDR, str(amount)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn("rejected by Tau logic", result)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE) # Unchanged
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_zero_amount_tau_rejection(self):
        print("[TEST_CASE] Fail: Zero Amount (Tau Rejection)")
        self.mock_tau_manager_instance.mode = "auto" 
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, "0"]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn("rejected by tau logic", result.lower())
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE) # Unchanged
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_insufficient_funds_tau_rejection_forced_code(self):
        print("[TEST_CASE] Fail: Insufficient Funds (Tau Rejection - FORCED SBF CODE)")
        self.mock_tau_manager_instance.mode = "force_insufficient_funds"
        amount = 10
        self.assertTrue(chain_state.get_balance(GENESIS_ADDR) >= amount, "Test setup error: Genesis needs enough for this test variant")
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn("rejected by Tau logic", result)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE) # Unchanged
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_invalid_from_address_format_python(self):
        print("[TEST_CASE] Fail: Invalid 'from' address format (Python encoding phase)")
        # This test relies on _validate_bls12_381_pubkey mock returning (False, "some error")
        # To test the specific path in queue_transaction for invalid from_addr_key in a transfer
        self.patcher_validate_pubkey.stop() # Stop the default True mock
        def mock_validate_key_selectively(key_hex, key_name):
            if key_hex == INVALID_ADDR_SHORT and "transfer #1 'from' address" in key_name:
                return False, f"Invalid {key_name}: Must be a 96-character hex BLS12-381 public key: {key_hex}"
            return True, None # Pass for other keys like sender_pubkey or to_addr_key
        
        self.mock_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', side_effect=mock_validate_key_selectively).start()
        sendtx._PY_ECC_AVAILABLE = False # Ensure no crypto for this specific check path

        self.mock_tau_manager_instance.mode = "auto"
        tx_json = self._create_tx_json(
            operations_or_transfers=[[INVALID_ADDR_SHORT, ADDR_A, "10"]],
            sender_pubkey=GENESIS_ADDR # Valid sender_pubkey to pass initial checks
        )
        result = sendtx.queue_transaction(tx_json)
        # The error message will be about sender_pubkey if sender_pubkey is INVALID_ADDR_SHORT.
        # If sender_pubkey is GENESIS_ADDR, then the error should be about the transfer's from_addr.
        # queue_transaction first validates sender_pubkey.
        # Then it validates from_addr_key in transfers.
        #
        # Correction: The `_create_tx_json` uses GENESIS_ADDR as default sender_pubkey.
        # The error is now specific to the transfer's 'from' address after sender_pubkey validation passes.
        # The check `if from_addr_key != sender_pubkey:` is also important.
        # For this test, we want from_addr_key to be INVALID_ADDR_SHORT and sender_pubkey to be something valid.
        # The current _create_tx_json uses GENESIS_ADDR as sender if not specified.
        # So we need INVALID_ADDR_SHORT != GENESIS_ADDR.
        #
        # If sender_pubkey is GENESIS_ADDR, and from_addr_key in transfer is INVALID_ADDR_SHORT,
        # it will first fail `from_addr_key != sender_pubkey`
        # Let's set sender_pubkey to INVALID_ADDR_SHORT for the outer check to fail first.
        #
        # Re-think: We want to test the path where `_validate_bls12_381_pubkey` for `from_addr_key` fails.
        # So, `sender_pubkey` should be valid, and `from_addr_key` in transfer should be `sender_pubkey` but invalid format.
        
        self.patcher_validate_pubkey.stop()
        def selective_validation_for_from(key_hex, key_name):
            if key_hex == INVALID_ADDR_SHORT and "sender_pubkey" in key_name: # sender_pubkey itself is invalid
                return False, f"Invalid {key_name}: Specific test error for sender {key_hex}"
            if key_hex == INVALID_ADDR_SHORT and "transfer #1 'from' address" in key_name: # from address in transfer is invalid
                return False, f"Invalid {key_name}: Specific test error for from {key_hex}"
            return True, None
        self.mock_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', side_effect=selective_validation_for_from).start()

        tx_dict_manual = {
            "sender_pubkey": INVALID_ADDR_SHORT, # This will fail first
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[INVALID_ADDR_SHORT, ADDR_A, "10"]]}, # from_addr also invalid
            "fee_limit": "0",
            "signature": "SIG"
        }
        tx_json_manual = json.dumps(tx_dict_manual)
        result = sendtx.queue_transaction(tx_json_manual)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Result: {result}")
        self.assertIn(f"Specific test error for sender {INVALID_ADDR_SHORT}", result)

        # Test case where sender_pubkey is valid, but from_addr in transfer is invalid format AND matches sender_pubkey
        self.patcher_validate_pubkey.stop()
        def selective_validation_for_transfer_from(key_hex, key_name):
            if key_hex == INVALID_ADDR_SHORT: # General invalid format for this key
                 return False, f"Invalid {key_name}: Format error for {key_hex}"
            return True, None # Other keys are fine
        self.mock_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', side_effect=selective_validation_for_transfer_from).start()

        tx_dict_manual_2 = {
            "sender_pubkey": INVALID_ADDR_SHORT, # This should be invalid
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[INVALID_ADDR_SHORT, ADDR_A, "10"]]}, # from_addr matches, also invalid
            "fee_limit": "0",
            "signature": "SIG"
        }
        tx_json_manual_2 = json.dumps(tx_dict_manual_2)
        result2 = sendtx.queue_transaction(tx_json_manual_2)
        self.assertTrue(result2.startswith("FAILURE: Transaction invalid."), f"Result2: {result2}")
        self.assertIn(f"Format error for {INVALID_ADDR_SHORT}", result2) # Error from sender_pubkey validation
        self.assertNotIn("transfer #1", result2) # Should fail on sender_pubkey first

        # Test case where sender_pubkey is valid, but from_addr in transfer is an invalid format and IS sender_pubkey
        # This means the _validate_bls12_381_pubkey for sender_pubkey must return True for the invalid format key!
        # This is tricky. The _validate_bls12_381_pubkey is called first for sender_pubkey.
        # Then for from_addr_key.
        # Let's assume sender_pubkey passes validation (even if it's INVALID_ADDR_SHORT due to a test setup quirk).
        # Then, the from_addr_key (which is the same INVALID_ADDR_SHORT) is validated again.

        self.patcher_validate_pubkey.stop()
        _call_count_validate = 0
        def validate_first_pass_then_fail(key_hex, key_name):
            nonlocal _call_count_validate
            _call_count_validate += 1
            if key_hex == INVALID_ADDR_SHORT:
                if "sender_pubkey" in key_name and _call_count_validate == 1: # First call for sender_pubkey
                    return True, None # Allow invalid key to pass as sender_pubkey for testing this path
                if "transfer #1 'from' address" in key_name: # Second call for from_address in transfer
                    return False, f"Invalid {key_name}: Format error for transfer from {key_hex}"
            return True, None
        self.mock_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', side_effect=validate_first_pass_then_fail).start()

        tx_dict_manual_3 = {
            "sender_pubkey": INVALID_ADDR_SHORT,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[INVALID_ADDR_SHORT, ADDR_A, "10"]]}, # from_addr matches sender_pubkey
            "fee_limit": "0",
            "signature": "SIG"
        }
        tx_json_manual_3 = json.dumps(tx_dict_manual_3)
        result3 = sendtx.queue_transaction(tx_json_manual_3)
        self.assertTrue(result3.startswith("FAILURE: Transaction invalid."), f"Result3: {result3}")
        self.assertIn(f"Format error for transfer from {INVALID_ADDR_SHORT}", result3)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)


    def test_fail_invalid_to_address_format_python(self):
        print("[TEST_CASE] Fail: Invalid 'to' address format (Python validation in transfer)")
        # Mock _validate_bls12_381_pubkey to fail for INVALID_ADDR_NON_HEX when it's a 'to' address
        self.patcher_validate_pubkey.stop()
        def mock_validate_to_addr(key_hex, key_name):
            if key_hex == GENESIS_ADDR and ("sender_pubkey" in key_name or "from" in key_name) : # Valid sender/from
                return True, None
            if key_hex == INVALID_ADDR_NON_HEX and "to" in key_name:
                return False, f"Invalid {key_name}: Must be a 96-character hex BLS12-381 public key: {key_hex}"
            return True, None # Default pass
        self.mock_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', side_effect=mock_validate_to_addr).start()
        sendtx._PY_ECC_AVAILABLE = False

        self.mock_tau_manager_instance.mode = "auto"
        tx_json = self._create_tx_json([[GENESIS_ADDR, INVALID_ADDR_NON_HEX, "10"]])
        result = sendtx.queue_transaction(tx_json)
        
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn(f"Invalid transfer #1 'to' address: Must be a 96-character hex BLS12-381 public key: {INVALID_ADDR_NON_HEX}", result)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_no_transfers_key_success(self):
        print("[TEST_CASE] Success: No '1' key in JSON payload (other ops)")
        self.mock_tau_manager_instance.mode = "auto" # Mock Tau will be called for other ops
        tx_json = self._create_tx_json({"0": "some_other_op_data"})
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"), f"Unexpected result: {result}")
        self.assertIn("no transfers to validate", result)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)
        # Tau should be called once if dynamic_sbf_input is generated and not empty.
        # utils.build_tau_input({"0":"some_other_op_data"}) might produce "yN" for "some_other_op_data"
        # Let's assume it does.
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)


    def test_empty_transfers_list_success(self):
        print("[TEST_CASE] Success: Empty list for transfers payload '1': []")
        self.mock_tau_manager_instance.mode = "auto"
        tx_json = self._create_tx_json([]) 
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"), f"Unexpected result: {result}")
        self.assertIn("empty transfer list", result)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0) # No Tau calls for empty transfer list


if __name__ == '__main__':
    unittest.main(verbosity=2) 