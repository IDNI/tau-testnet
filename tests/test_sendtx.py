import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys

# Add the project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

TEST_DB_PATH = "test_tau_string_db.sqlite"
os.environ["TAU_DB_PATH"] = TEST_DB_PATH

from commands import sendtx
import chain_state
import db
import sbf_defs
import utils # For sbf_atom_to_bits, bits_to_sbf_atom, decimal_to_8bit_binary
import time

# Test Cases:
# 1. Successful single transfer.
# 2. Successful multiple transfers in one transaction.
# 3. Failure due to insufficient actual funds (Tau Rejection).
# 4. Failure due to amount too large for SBF Python validation.
# 5. Failure due to source == destination address (Tau Rejection).
# 6. Failure due to zero amount (Tau Rejection).
# 7. Failure due to invalid 'from' address format (Python validation).
# 8. Failure due to invalid 'to' address format (Python validation).
# 9. Success with no '1' key in JSON payload.
# 10. Success with empty transfers list.
# 11. Failure due to expired transaction.
# 12. Failure due to transfer from address not matching sender_pubkey.
# 13. Failure due to missing sequence_number field.
# 14. Failure due to missing signature field.
# 15. Valid signature and correct sequence number increment.
# 16. Invalid signature rejection (tampered signature).
# 17. Invalid signature: signature of wrong data.
# 18. Invalid signature: signed with wrong private key.
# 19. Invalid sequence number after valid signature.
# 20. Signature verification fails on tampered transaction data.
# 21. Skip signature verification and sequence enforcement when BLS disabled.
# --- Test Configuration ---
CONFIG_MODULE_PATH = "config" # For patching STRING_DB_PATH

# --- Helper Addresses ---
GENESIS_ADDR = chain_state.GENESIS_ADDRESS
ADDR_A = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a"
ADDR_B = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b"
ADDR_C = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c"
INVALID_ADDR_SHORT = "short"
INVALID_ADDR_NON_HEX = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000g"
import hashlib
import py_ecc.bls as _bls_module
from py_ecc.bls import G2Basic as bls
from commands.sendtx import _get_signing_message_bytes


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
        # This can happen if sbf_atom_to_bits doesn't return fixed length based on sbf input type,
        # or if the SBF atom itself implies a different length than expected.
        # For test mock, we proceed if it's at least the expected length.
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
        self.mode = "echo"  # Default: success
        self.sbf_input_received = None
        self.tau_call_count = 0

    def communicate_with_tau(self, sbf_input_str):
        self.tau_call_count += 1
        self.sbf_input_received = sbf_input_str
        print(f"\n[MOCK_TAU][{self.tau_call_count}] Received SBF Input: {sbf_input_str}")

        # Expected SBF structure: amount(4), balance_from_tau(4), from(4), to(4) -> 16 bits
        # For example: x0-x3 (amount), x4-x7 (balance), x8-x11 (from), x12-x15 (to)
        try:
            # We need utils.sbf_atom_to_bits to be robust here
            # If utils cannot be imported or sbf_atom_to_bits is not available, this will fail.
            # This parsing is crucial for the mock to behave like the Tau code.
            fields = sbf_to_int_array(sbf_input_str, [4, 4, 4, 4]) # New order & size: amount(4), balance(4), from(4), to(4)
            amount_val, balance_val, _from_id_val, _to_id_val = fields
            print(f"[MOCK_TAU] Parsed SBF: Amount={amount_val} (4b), BalanceForTau={balance_val} (4b), FromID={_from_id_val} (4b), ToID={_to_id_val} (4b)")
        except Exception as e:
            print(f"[MOCK_TAU] Error parsing SBF input '{sbf_input_str}' for detailed checks: {e}. Defaulting to echo or preset mode.")
            # Fallback if parsing fails, rely on simple mode
            if self.mode == "echo":
                print(f"[MOCK_TAU] Output: {sbf_input_str} (echo due to parse error or mode)")
                return sbf_input_str
            elif hasattr(sbf_defs, self.mode): # e.g. self.mode = "FAIL_INSUFFICIENT_FUNDS_SBF"
                sbf_code = getattr(sbf_defs, self.mode)
                print(f"[MOCK_TAU] Output: {sbf_code} (mode: {self.mode})")
                return sbf_code
            else:
                print(f"[MOCK_TAU] CRITICAL: Unknown mode '{self.mode}' and SBF parse error. Echoing.")
                return sbf_input_str

        # Simulate tool_code.tau logic based on parsed values
        # Order of checks in tool_code.tau:
        # 1. Insufficient Funds (Amount > Sender Balance for Tau)
        # 2. Source Address == Destination Address
        # 3. Amount is Zero

        if self.mode == "force_insufficient_funds": # Test specific return code handling
            print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF} (mode: force_insufficient_funds)")
            return sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF
        if self.mode == "force_src_eq_dest":
            print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_SRC_EQ_DEST_SBF} (mode: force_src_eq_dest)")
            return sbf_defs.FAIL_SRC_EQ_DEST_SBF
        if self.mode == "force_zero_amount":
            print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_ZERO_AMOUNT_SBF} (mode: force_zero_amount)")
            return sbf_defs.FAIL_ZERO_AMOUNT_SBF
        
        # Default "auto" mode based on parsed SBF (simulates Tau logic)
        if self.mode == "auto" or self.mode == "echo": # "echo" becomes "auto" if parse successful
            if amount_val > balance_val: # Simulating the (Amount > Balance_for_Tau) check
                print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF} (auto: amount {amount_val} > balance_for_tau {balance_val})")
                return sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF
            if _from_id_val == _to_id_val:
                # Note: db.get_string_id for the same address will yield the same yN, so IDs will match.
                print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_SRC_EQ_DEST_SBF} (auto: from_id {_from_id_val} == to_id {_to_id_val})")
                return sbf_defs.FAIL_SRC_EQ_DEST_SBF
            if amount_val == 0:
                print(f"[MOCK_TAU] Output: {sbf_defs.FAIL_ZERO_AMOUNT_SBF} (auto: amount_val is {amount_val})")
                return sbf_defs.FAIL_ZERO_AMOUNT_SBF
            
            print(f"[MOCK_TAU] Output: {sbf_input_str} (auto: all checks passed)")
            return sbf_input_str # Echo input if all checks pass

        # If a specific failure SBF constant name was set as mode
        if hasattr(sbf_defs, self.mode):
            sbf_code = getattr(sbf_defs, self.mode)
            print(f"[MOCK_TAU] Output: {sbf_code} (mode: {self.mode})")
            return sbf_code

        print(f"[MOCK_TAU] WARN: Unhandled mock mode '{self.mode}'. Echoing SBF.")
        return sbf_input_str


class TestSendTx(unittest.TestCase):
    
    def _cleanup_db(self):
        if os.path.exists(TEST_DB_PATH): # Use the variable directly
            os.remove(TEST_DB_PATH)
        if db._db_conn: # Better to have a db.close_db() function
            db._db_conn.close()
        db._db_conn = None

    def setUp(self):
        print(f"\n--- Test: {self.id()} ---")
        self._cleanup_db()
        # Reset in-memory chain state for isolated tests
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.init_chain_state()

        self.mock_tau_manager_instance = MockTauManager()
        self.patcher_tau_comm = patch('commands.sendtx.tau_manager.communicate_with_tau', 
                                      self.mock_tau_manager_instance.communicate_with_tau)
        self.mock_tau_comm = self.patcher_tau_comm.start()

        # Mock _validate_bls12_381_pubkey to bypass py_ecc issues for these tests
        self.patcher_validate_pubkey = patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None))
        self.mock_validate_pubkey = self.patcher_validate_pubkey.start()
        
        # Disable BLS signature verification and sequence enforcement by default
        sendtx._PY_ECC_AVAILABLE = False
        print(f"[SETUP] Patched tau_manager and _validate_bls12_381_pubkey. Initial Genesis Balance: {chain_state.get_balance(GENESIS_ADDR)}")

    def tearDown(self):
        self.patcher_tau_comm.stop()
        self.patcher_validate_pubkey.stop() # Stop the pubkey validation patch
        self._cleanup_db()
        print(f"[TEARDOWN] Test {self.id()} finished.")

    def _create_tx_json(self, operations_or_transfers, expiration_time=None, sequence_number=None, sender_privkey=None, signature=None, sender_pubkey=None):
        # Build operations dict from list or dict
        if isinstance(operations_or_transfers, list):
            ops = {"1": operations_or_transfers}
        else:
            ops = operations_or_transfers
        exp_time = expiration_time if expiration_time is not None else int(time.time()) + 1000
        if sender_privkey is not None:
            privkey = sender_privkey
            pubkey_bytes = bls.SkToPk(privkey)
            pk_hex = pubkey_bytes.hex()
        else:
            pk_hex = sender_pubkey or GENESIS_ADDR
        seq = sequence_number if sequence_number is not None else chain_state.get_sequence_number(pk_hex)
        tx_dict = {
            "sender_pubkey": pk_hex,
            "sequence_number": seq,
            "expiration_time": exp_time,
            "operations": ops,
            "fee_limit": "0",
        }
        if sender_privkey is not None:
            msg_bytes = _get_signing_message_bytes(tx_dict)
            msg_hash = hashlib.sha256(msg_bytes).digest()
            sig_bytes = bls.Sign(privkey, msg_hash)
            tx_dict["signature"] = sig_bytes.hex()
        elif signature is not None:
            tx_dict["signature"] = signature
        else:
            # Default dummy signature for tests not focused on signature verification
            tx_dict["signature"] = "SIG"
        return json.dumps(tx_dict)

    def test_successful_single_transfer(self):
        print("[TEST_CASE] Successful single transfer: Genesis -> ADDR_A, 10 AGRS")
        self.mock_tau_manager_instance.mode = "auto" # Tau mock will simulate success
        
        initial_genesis_balance = chain_state.get_balance(GENESIS_ADDR)
        initial_addr_a_balance = chain_state.get_balance(ADDR_A)
        amount = 10 # Corrected: Was 100, now 10 for 4-bit compatibility

        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount)]])
        result = sendtx.queue_transaction(tx_json)

        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), initial_genesis_balance - amount)
        self.assertEqual(chain_state.get_balance(ADDR_A), initial_addr_a_balance + amount)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        # Compare with the original tx_json string, which is what add_mempool_tx gets (after stripping quotes)
        self.assertEqual(mempool[0], "json:" + tx_json)

    def test_successful_multiple_transfers(self):
        print("[TEST_CASE] Successful multiple transfers: G->A (10), G->B (5)")
        self.mock_tau_manager_instance.mode = "auto"

        initial_genesis_balance = chain_state.get_balance(GENESIS_ADDR)
        amount1 = 10 # Corrected: Was 100, now 10
        amount2 = 5  # Corrected: Was 50, now 5

        tx_list = [
            [GENESIS_ADDR, ADDR_A, str(amount1)],
            [GENESIS_ADDR, ADDR_B, str(amount2)]
        ]
        tx_json = self._create_tx_json(tx_list)
        result = sendtx.queue_transaction(tx_json)

        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), initial_genesis_balance - amount1 - amount2)
        self.assertEqual(chain_state.get_balance(ADDR_A), amount1)
        self.assertEqual(chain_state.get_balance(ADDR_B), amount2)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 2) # Tau called for each transfer

    def test_fail_insufficient_funds_actual_balance_tau_rejection(self):
        print("[TEST_CASE] Fail: Insufficient actual funds (Tau Rejection - 4bit amount/balance)")
        # Tau will check its 4-bit amount vs 4-bit capped balance.
        # Scenario: Genesis has 10. Wants to send 12. Both <= 15.
        # actual_sender_balance = 10, amount_int = 12.
        # sender_balance_for_tau = min(10, 15) = 10.
        # SBF to Tau: amount=12, balance_for_tau=10.
        # Mock Tau (auto): amount_val (12) > balance_val (10) -> TRUE. Returns FAIL_INSUFFICIENT_FUNDS_SBF.
        
        # Setup: Give Genesis a smaller balance for this test
        chain_state._balances[GENESIS_ADDR] = 10
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), 10)

        self.mock_tau_manager_instance.mode = "auto" 
        amount_to_send = 12 # Amount is > balance (10) but <= 15
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount_to_send)]])
        result = sendtx.queue_transaction(tx_json)
        
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."))
        self.assertIn("rejected by tau logic", result.lower())
        # Check that sendtx._decode_single_transfer_output logged the specific Tau error
        # (this would require capturing logs or checking stdout if verbose)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), 10)
        self.assertEqual(chain_state.get_balance(ADDR_A), 0)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_amount_too_large_for_sbf_python(self):
        print("[TEST_CASE] Fail: Amount > 15 (Python util validation for 4-bit SBF encoding)")
        self.mock_tau_manager_instance.mode = "auto"
        amount_to_send = 16 # Max for 4-bit is 15. So 16 is invalid.
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount_to_send)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("ERROR: Could not process transfer #1"), f"Unexpected result: {result}")
        self.assertIn("Invalid amount '16': Must be a number between 0 and 15", result)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_fail_src_eq_dest_tau_rejection(self):
        print("[TEST_CASE] Fail: Source == Destination (Tau Rejection)")
        self.mock_tau_manager_instance.mode = "auto" 
        amount = 10 # Valid amount within 4-bit range
        tx_json = self._create_tx_json([[GENESIS_ADDR, GENESIS_ADDR, str(amount)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn("rejected by Tau logic", result)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_zero_amount_tau_rejection(self):
        print("[TEST_CASE] Fail: Zero Amount (Tau Rejection)")
        self.mock_tau_manager_instance.mode = "auto" 
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, "0"]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn("rejected by tau logic", result.lower())
        print(f"    Note: Tau is now responsible for the zero amount check.")
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_insufficient_funds_tau_rejection_forced_code(self):
        print("[TEST_CASE] Fail: Insufficient Funds (Tau Rejection - FORCED SBF CODE)")
        print("    This test forces FAIL_INSUFFICIENT_FUNDS_SBF from Tau mock to test sendtx.py's decoder.")
        self.mock_tau_manager_instance.mode = "force_insufficient_funds"
        amount = 10 # Adjusted from 50 to be within 4-bit range
        self.assertTrue(chain_state.get_balance(GENESIS_ADDR) >= amount, "Test setup error: Genesis needs enough for this test variant")
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, str(amount)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."), f"Unexpected result: {result}")
        self.assertIn("rejected by Tau logic", result)
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), chain_state.GENESIS_BALANCE)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_fail_invalid_from_address_format_python(self):
        print("[TEST_CASE] Fail: Invalid 'from' address format (Python encoding phase)")
        self.mock_tau_manager_instance.mode = "auto"
        tx = {
            "sender_pubkey": INVALID_ADDR_SHORT,
            "sequence_number": chain_state.get_sequence_number(INVALID_ADDR_SHORT),
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[INVALID_ADDR_SHORT, ADDR_A, "10"]]},
            "fee_limit": "0",
            "signature": "SIG"
        }
        tx_json = json.dumps(tx)
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("ERROR: Could not process transfer #1"), f"Unexpected result: {result}")
        self.assertIn("Invalid 'from' address: Must be a 96-character hex BLS12-381 public key: short", result)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_fail_invalid_to_address_format_python(self):
        print("[TEST_CASE] Fail: Invalid 'to' address format (Python encoding phase)")
        self.mock_tau_manager_instance.mode = "auto"
        tx_json = self._create_tx_json([[GENESIS_ADDR, INVALID_ADDR_NON_HEX, "10"]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("ERROR: Could not process transfer #1"), f"Unexpected result: {result}")
        self.assertIn("Invalid 'to' address: Must be a 96-character hex BLS12-381 public key: 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000g", result)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_no_transfers_key_success(self):
        print("[TEST_CASE] Success: No '1' key in JSON payload")
        self.mock_tau_manager_instance.mode = "auto"
        tx_json = self._create_tx_json({"0": "some_other_op_data"})
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertIn("no transfers to validate", result)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json) # Compare with tx_json string
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 1)

    def test_empty_transfers_list_success(self):
        print("[TEST_CASE] Success: Empty list for transfers payload '1': []")
        self.mock_tau_manager_instance.mode = "auto"
        tx_json = self._create_tx_json([]) # tx_json is already a string here
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertIn("empty transfer list", result)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json) # Compare with tx_json string
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_expired_transaction(self):
        print("[TEST_CASE] Fail: Transaction expired")
        expired_time = int(time.time()) - 10
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, "1"]], expiration_time=expired_time)
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction expired at"))
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_from_address_mismatch(self):
        print("[TEST_CASE] Fail: Transfer from address not matching sender_pubkey")
        self.mock_tau_manager_instance.mode = "auto"
        invalid_transfer = [ADDR_B, ADDR_A, "1"]
        tx_json = self._create_tx_json([invalid_transfer])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."))
        self.assertIn("does not match sender_pubkey", result)
        self.assertEqual(len(db.get_mempool_txs()), 0)
        self.assertEqual(self.mock_tau_manager_instance.tau_call_count, 0)

    def test_missing_sequence_number(self):
        print("[TEST_CASE] Fail: Missing sequence_number field")
        tx = {
            "sender_pubkey": GENESIS_ADDR,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]},
            "fee_limit": "0",
            "signature": "SIG"
        }
        tx_json = json.dumps(tx)
        with self.assertRaises(ValueError) as cm:
            sendtx.queue_transaction(tx_json)
        self.assertIn("Missing 'sequence_number'", str(cm.exception))

    def test_missing_signature(self):
        print("[TEST_CASE] Fail: Missing signature field")
        tx = {
            "sender_pubkey": GENESIS_ADDR,
            "sequence_number": chain_state.get_sequence_number(GENESIS_ADDR),
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS_ADDR, ADDR_A, "1"]]},
            "fee_limit": "0"
        }
        tx_json = json.dumps(tx)
        with self.assertRaises(ValueError) as cm:
            sendtx.queue_transaction(tx_json)
        self.assertIn("Missing 'signature'", str(cm.exception))

    def test_valid_signature_and_sequence_increment(self):
        print("[TEST_CASE] Valid signature and correct sequence number increment")
        self.mock_tau_manager_instance.mode = "auto"
        # Generate a BLS key pair and initial sequence for this key
        privkey = bls.KeyGen(b"test_seed_1")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        initial_seq = chain_state.get_sequence_number(pk_hex)
        # Fund new account so it has enough balance for the transfer
        amount = 3
        chain_state._balances[pk_hex] = amount
        # Build and sign the transaction
        ops = {"1": [[pk_hex, ADDR_A, str(amount)]]}
        tx_json = self._create_tx_json(ops, sequence_number=initial_seq, sender_privkey=privkey)
        # Enable BLS signature verification
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        # Sequence number should have incremented by 1
        self.assertEqual(chain_state.get_sequence_number(pk_hex), initial_seq + 1)

    def test_invalid_signature_rejected(self):
        print("[TEST_CASE] Invalid signature rejection (tampered signature)")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_2")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        seq = chain_state.get_sequence_number(pk_hex)
        ops = {"1": [[pk_hex, ADDR_A, "2"]]}
        # Create transaction with invalid signature of correct length
        bad_sig = "00" * 96
        tx_json = self._create_tx_json(ops, sequence_number=seq, signature=bad_sig, sender_pubkey=pk_hex)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"), f"Unexpected result: {result}")

    def test_invalid_signature_wrong_data(self):
        print("[TEST_CASE] Invalid signature: signature of wrong data")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_3")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        seq = chain_state.get_sequence_number(pk_hex)
        ops = {"1": [[pk_hex, ADDR_A, "3"]]}
        wrong_ops = {"1": [[pk_hex, ADDR_A, "4"]]}
        msg_bytes = _get_signing_message_bytes({
            "sender_pubkey": pk_hex,
            "sequence_number": seq,
            "expiration_time": int(time.time()) + 1000,
            "operations": wrong_ops,
            "fee_limit": "0"
        })
        msg_hash = hashlib.sha256(msg_bytes).digest()
        sig = bls.Sign(privkey, msg_hash).hex()
        tx_json = self._create_tx_json(ops, sequence_number=seq, signature=sig, sender_pubkey=pk_hex)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"))

    def test_invalid_signature_wrong_private_key(self):
        print("[TEST_CASE] Invalid signature: signed with wrong private key")
        self.mock_tau_manager_instance.mode = "auto"
        privkey1 = bls.KeyGen(b"test_seed_4")
        pubkey1 = bls.SkToPk(privkey1)
        pk_hex = pubkey1.hex()
        privkey2 = bls.KeyGen(b"test_seed_5")
        seq = chain_state.get_sequence_number(pk_hex)
        ops = {"1": [[pk_hex, ADDR_A, "5"]]}
        msg_bytes = _get_signing_message_bytes({
            "sender_pubkey": pk_hex,
            "sequence_number": seq,
            "expiration_time": int(time.time()) + 1000,
            "operations": ops,
            "fee_limit": "0"
        })
        msg_hash = hashlib.sha256(msg_bytes).digest()
        sig = bls.Sign(privkey2, msg_hash).hex()
        tx_json = self._create_tx_json(ops, sequence_number=seq, signature=sig, sender_pubkey=pk_hex)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"))

    def test_invalid_sequence_number_after_signature(self):
        print("[TEST_CASE] Invalid sequence number after valid signature")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_6")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        initial_seq = chain_state.get_sequence_number(pk_hex)
        wrong_seq = initial_seq + 1
        ops = {"1": [[pk_hex, ADDR_A, "7"]]}
        # Sign with mismatched sequence number
        tx_json = self._create_tx_json(ops, sequence_number=wrong_seq, sender_privkey=privkey)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid sequence number"), f"Unexpected result: {result}")

    def test_signature_verification_fails_on_tampered_data(self):
        print("[TEST_CASE] Signature verification fails on tampered transaction data")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_7")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        seq = chain_state.get_sequence_number(pk_hex)
        ops = {"1": [[pk_hex, ADDR_A, "8"]]}
        tx_json = self._create_tx_json(ops, sequence_number=seq, sender_privkey=privkey)
        # Tamper the amount in the payload after signing
        tx_dict = json.loads(tx_json)
        tx_dict["operations"]["1"][0][2] = "9"
        tx_json_tampered = json.dumps(tx_dict)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json_tampered)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"))

    def test_skip_signature_verification_when_disabled(self):
        print("[TEST_CASE] Skip signature verification and sequence enforcement when BLS disabled")
        self.mock_tau_manager_instance.mode = "auto"
        # Use genesis account for sufficient balance
        initial_seq = chain_state.get_sequence_number(GENESIS_ADDR)
        initial_gen_balance = chain_state.get_balance(GENESIS_ADDR)
        initial_a_balance = chain_state.get_balance(ADDR_A)
        tx_json = self._create_tx_json([[GENESIS_ADDR, ADDR_A, "5"]], signature="00")
        sendtx._PY_ECC_AVAILABLE = False
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        # Sequence number should remain unchanged
        self.assertEqual(chain_state.get_sequence_number(GENESIS_ADDR), initial_seq)
        # Balances should update despite skipped signature enforcement
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), initial_gen_balance - 5)
        self.assertEqual(chain_state.get_balance(ADDR_A), initial_a_balance + 5)

if __name__ == '__main__':
    print("Running SendTx Tests...")
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSendTx)
    unittest.TextTestRunner(verbosity=2).run(suite) 