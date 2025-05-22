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

    # All test methods below this line were moved to other files.
    # test_successful_single_transfer (MOVED to test_sendtx_basic_transfers.py)
    # test_successful_multiple_transfers (MOVED to test_sendtx_basic_transfers.py)
    # test_fail_insufficient_funds_actual_balance_tau_rejection (MOVED to test_sendtx_basic_transfers.py)
    # test_fail_amount_too_large_for_sbf_python (MOVED to test_sendtx_basic_transfers.py)
    # test_fail_src_eq_dest_tau_rejection (MOVED to test_sendtx_basic_transfers.py)
    # test_fail_zero_amount_tau_rejection (MOVED to test_sendtx_basic_transfers.py)
    # test_fail_insufficient_funds_tau_rejection_forced_code (MOVED to test_sendtx_basic_transfers.py)
    # test_fail_invalid_from_address_format_python (MOVED to test_sendtx_basic_transfers.py)
    # test_fail_invalid_to_address_format_python (MOVED to test_sendtx_basic_transfers.py)
    # test_no_transfers_key_success (MOVED to test_sendtx_basic_transfers.py)
    # test_empty_transfers_list_success (MOVED to test_sendtx_basic_transfers.py)
    # test_expired_transaction (MOVED to test_sendtx_structure_metadata.py)
    # test_from_address_mismatch (MOVED to test_sendtx_structure_metadata.py)
    # test_missing_sequence_number (MOVED to test_sendtx_structure_metadata.py or covered)
    # test_missing_signature (MOVED to test_sendtx_structure_metadata.py or covered)
    # test_valid_signature_and_sequence_increment (MOVED to test_sendtx_crypto.py)
    # test_invalid_signature_rejected (MOVED to test_sendtx_crypto.py)
    # test_invalid_signature_wrong_data (MOVED to test_sendtx_crypto.py)
    # test_invalid_signature_wrong_private_key (MOVED to test_sendtx_crypto.py)
    # test_invalid_sequence_number_after_signature (MOVED to test_sendtx_crypto.py)
    # test_signature_verification_fails_on_tampered_data (MOVED to test_sendtx_crypto.py)
    # test_skip_signature_verification_when_disabled (MOVED to test_sendtx_crypto.py)

if __name__ == '__main__':
    print("Running SendTx Tests (Original File - Most tests moved)...")
    # This will run any remaining tests in this file, if any.
    # For now, it should find no tests if all are moved.
    # Consider creating a base test class if common setup/teardown is extensive.
    
    # To run all tests from all new files, you'd typically use:
    # python -m unittest discover tests
    # Or run them individually:
    # python tests/test_sendtx_basic_transfers.py
    # python tests/test_sendtx_structure_metadata.py
    # python tests/test_sendtx_crypto.py
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestSendTx)
    unittest.TextTestRunner(verbosity=2).run(suite) 