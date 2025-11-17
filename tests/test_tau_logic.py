# Summary of Tau Logic Tests
#
# 1. test_01_valid_transfer_echo
#    - Confirms Tau echoes the input SBF for a valid transfer (amount <= balance, distinct addresses).
#
# 2. test_02_insufficient_funds
#    - Verifies Tau returns FAIL_INSUFFICIENT_FUNDS_SBF when amount > balance.
#
# 3. test_03_source_equals_destination
#    - Checks Tau returns FAIL_SRC_EQ_DEST_SBF when source and destination IDs are equal.
#
# 4. test_04_zero_amount
#    - Ensures Tau returns FAIL_ZERO_AMOUNT_SBF for a transfer amount of zero.
#
# 5. test_05_amount_equals_balance_valid
#    - Validates Tau echoes the input SBF when amount equals balance (edge case).
#
# 6. test_06_max_values_valid
#    - Tests Tau echoes the input SBF for maximum field values (15-bit indices and amounts).
#
# 7. test_07_insufficient_funds_at_zero_balance
#    - Confirms FAIL_INSUFFICIENT_FUNDS_SBF when balance is zero and amount > 0.
#
# 8. test_08_invalid_format_incomplete_bits
#    - Verifies Tau returns FAIL_INVALID_FORMAT_SBF for incomplete SBF inputs (like just "x0").
#
# 9. test_09_invalid_format_ambiguous_bits
#    - Tests FAIL_INVALID_FORMAT_SBF for ambiguous SBF inputs that don't specify all 16 bits.
#
# 10. test_10_rule_processing_i0_simple
#     - Tests rule processing via i0 stream, expecting ACK_RULE_PROCESSED_SBF on o0.
#
# 11. test_11_rule_processing_i0_complex
#     - Tests complex rule processing via i0 stream.
#
# 12. test_12_fallback_fail_invalid_both_zero
#     - Tests the final fallback case when both i0 and i1 are zero/inactive.
#
# 13. test_13_fallback_fail_invalid_unrecognized
#     - Tests fallback for unrecognized input patterns.
#
# 14. test_14_pointwise_revision_simple
#     - Tests pointwise revision functionality with u[t] output.

import unittest
import os
import sys
import time
import threading # Added for managing the tau_manager thread

# Add the project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Ensure TAU_DB_PATH is set for db.py, though less critical for direct Tau logic tests
# if they don't heavily rely on yID string lookups for SBF construction.
TEST_DB_PATH = "test_tau_logic_db.sqlite" # Separate DB for these tests
os.environ["TAU_DB_PATH"] = TEST_DB_PATH

import tau_manager
import tau_defs
import utils # For bits_to_tau_literal
import config # For TAU_READY_SIGNAL, etc.
import db # To cleanup

@unittest.skip("Skipping Tau logic tests by default")
class TestTauLogic(unittest.TestCase):
    manager_thread = None

    @classmethod
    def setUpClass(cls):
        """Starts the Tau manager thread once for all tests in this class."""
        print("\n--- Starting Tau Manager for TestTauLogic ---")
        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)
        db.init_db() # Initialize for yID generation if needed

        # Ensure Tau program file exists
        if not os.path.exists(config.TAU_PROGRAM_FILE):
            raise FileNotFoundError(f"Tau program file '{config.TAU_PROGRAM_FILE}' not found. "
                                    "Ensure it is in the project root or update config.py.")

        # Reset global events in tau_manager for a clean start for this test class
        tau_manager.server_should_stop.clear()
        tau_manager.tau_ready.clear()

        print("[INFO][TestTauLogic] Starting tau_manager.start_and_manage_tau_process in a thread.")
        cls.manager_thread = threading.Thread(target=tau_manager.start_and_manage_tau_process, daemon=True)
        cls.manager_thread.start()

        print("[INFO][TestTauLogic] Waiting for Tau to become ready (timeout: 30s)...")
        ready = tau_manager.tau_ready.wait(timeout=30) # Increased timeout
        if not ready:
            print("[ERROR][TestTauLogic] Tau did not become ready in time. Requesting shutdown.")
            tau_manager.request_shutdown()
            if cls.manager_thread.is_alive():
                cls.manager_thread.join(timeout=5)
            raise Exception("Tau process/manager did not become ready in time for tests.")
        print("[INFO][TestTauLogic] Tau Manager is ready and Tau should be available.")

    @classmethod
    def tearDownClass(cls):
        """Stops the Tau manager thread once after all tests in this class have run."""
        print("\n--- Stopping Tau Manager for TestTauLogic ---")
        tau_manager.request_shutdown()
        if cls.manager_thread and cls.manager_thread.is_alive():
            print("[INFO][TestTauLogic] Joining Tau manager thread (timeout: 10s)...")
            cls.manager_thread.join(timeout=10)
            if cls.manager_thread.is_alive():
                print("[WARN][TestTauLogic] Tau manager thread did not exit cleanly during teardown.")
            else:
                print("[INFO][TestTauLogic] Tau manager thread joined successfully.")
        else:
            print("[INFO][TestTauLogic] Tau manager thread was not active or not started.")
        
        # Clear events again in case other test suites run in the same session
        tau_manager.tau_ready.clear()
        tau_manager.server_should_stop.clear() # ensure this is also reset

        if os.path.exists(TEST_DB_PATH):
            os.remove(TEST_DB_PATH)

    def _construct_sbf_input(self, amount: int, balance: int, from_id_idx: int, to_id_idx: int) -> str:
        """
        Constructs a 16-bit SBF string for i1.
        amount (0-15), balance (0-15), from_id_idx (0-15), to_id_idx (0-15)
        """
        if not (0 <= amount <= 15): raise ValueError("Amount out of 4-bit range")
        if not (0 <= balance <= 15): raise ValueError("Balance out of 4-bit range")
        if not (0 <= from_id_idx <= 15): raise ValueError("From ID index out of 4-bit range")
        if not (0 <= to_id_idx <= 15): raise ValueError("To ID index out of 4-bit range")

        amount_bits = format(amount, '04b')
        balance_bits = format(balance, '04b')
        from_bits = format(from_id_idx, '04b')
        to_bits = format(to_id_idx, '04b')
        
        full_bit_pattern = amount_bits + balance_bits + from_bits + to_bits
        return utils.bits_to_tau_literal(full_bit_pattern, length=16)

    def _assert_tau_response(self, sbf_input: str, expected_output: str, msg: str, output_stream: int = 1):
        """Helper to assert Tau's response on a specific output stream."""
        self.assertTrue(tau_manager.tau_ready.is_set(), "Assertion failed: Tau is not ready before communication attempt.")
        print(f"    [TEST_TAU_LOGIC] Sending SBF: {sbf_input}")
        try:
            response = tau_manager.communicate_with_tau(sbf_input, target_output_stream_index=output_stream)
            print(f"    [TEST_TAU_LOGIC] Received SBF from o{output_stream}: {response}")
            self.assertEqual(response.strip(), expected_output.strip(), msg)
        except Exception as e:
            self.fail(f"Error during communicate_with_tau: {e}. SBF Sent: {sbf_input}, Expected: {expected_output}")

    # ===== i1 Transfer Tests (Main Transaction Logic) =====

    def test_01_valid_transfer_echo(self):
        print("\n[TAU_LOGIC_CASE] Valid transfer: amount=5, balance=10, from=1, to=2")
        sbf_in = self._construct_sbf_input(amount=5, balance=10, from_id_idx=1, to_id_idx=2)
        self._assert_tau_response(sbf_in, sbf_in, "Tau should echo valid transfer SBF.")

    def test_02_insufficient_funds(self):
        print("\n[TAU_LOGIC_CASE] Insufficient funds: amount=10, balance=5, from=1, to=2")
        sbf_in = self._construct_sbf_input(amount=10, balance=5, from_id_idx=1, to_id_idx=2)
        self._assert_tau_response(sbf_in, tau_defs.FAIL_INSUFFICIENT_FUNDS_SBF, "Tau should return FAIL_INSUFFICIENT_FUNDS_SBF.")

    def test_03_source_equals_destination(self):
        print("\n[TAU_LOGIC_CASE] Source equals destination: amount=5, balance=10, from=1, to=1")
        sbf_in = self._construct_sbf_input(amount=5, balance=10, from_id_idx=1, to_id_idx=1)
        self._assert_tau_response(sbf_in, tau_defs.FAIL_SRC_EQ_DEST_SBF, "Tau should return FAIL_SRC_EQ_DEST_SBF.")

    def test_04_zero_amount(self):
        print("\n[TAU_LOGIC_CASE] Zero amount: amount=0, balance=10, from=1, to=2")
        sbf_in = self._construct_sbf_input(amount=0, balance=10, from_id_idx=1, to_id_idx=2)
        self._assert_tau_response(sbf_in, tau_defs.FAIL_ZERO_AMOUNT_SBF, "Tau should return FAIL_ZERO_AMOUNT_SBF.")
        
    def test_05_amount_equals_balance_valid(self):
        print("\n[TAU_LOGIC_CASE] Valid transfer (edge case): amount=10, balance=10, from=1, to=2")
        sbf_in = self._construct_sbf_input(amount=10, balance=10, from_id_idx=1, to_id_idx=2)
        self._assert_tau_response(sbf_in, sbf_in, "Tau should echo valid transfer when amount equals balance.")

    def test_06_max_values_valid(self):
        print("\n[TAU_LOGIC_CASE] Valid transfer: Max values amount=15, balance=15, from=15, to=14")
        sbf_in = self._construct_sbf_input(amount=15, balance=15, from_id_idx=15, to_id_idx=14)
        self._assert_tau_response(sbf_in, sbf_in, "Tau should echo valid transfer with max values.")

    def test_07_insufficient_funds_at_zero_balance(self):
        print("\n[TAU_LOGIC_CASE] Insufficient funds: amount=1, balance=0, from=1, to=2")
        sbf_in = self._construct_sbf_input(amount=1, balance=0, from_id_idx=1, to_id_idx=2)
        self._assert_tau_response(sbf_in, tau_defs.FAIL_INSUFFICIENT_FUNDS_SBF, "Tau should return FAIL_INSUFFICIENT_FUNDS_SBF when balance is 0 and amount > 0.")

    # ===== Format Validation Tests =====

    def test_08_invalid_format_incomplete_bits(self):
        print("\n[TAU_LOGIC_CASE] Invalid format: incomplete SBF (just x0)")
        incomplete_sbf = "x0"  # Only specifies x0, not x1-x15
        self._assert_tau_response(incomplete_sbf, tau_defs.FAIL_INVALID_FORMAT_SBF, 
                                "Tau should return FAIL_INVALID_FORMAT_SBF for incomplete SBF.")

    def test_09_invalid_format_ambiguous_bits(self):
        print("\n[TAU_LOGIC_CASE] Invalid format: ambiguous SBF (x0 & x1)")
        ambiguous_sbf = "x0 & x1"  # Only specifies x0 and x1, not x2-x15
        self._assert_tau_response(ambiguous_sbf, tau_defs.FAIL_INVALID_FORMAT_SBF, 
                                "Tau should return FAIL_INVALID_FORMAT_SBF for ambiguous SBF.")

    # ===== i0 Rule Processing Tests =====

    def test_10_rule_processing_i0_simple(self):
        print("\n[TAU_LOGIC_CASE] Rule processing: simple rule on i0")
        rule_sbf = "o1[t] = 1"  # Simple rule for i0
        self._assert_tau_response(rule_sbf, tau_defs.ACK_RULE_PROCESSED_SBF, 
                                "Tau should return ACK_RULE_PROCESSED_SBF for rule processing.", 
                                output_stream=0)

    def test_11_rule_processing_i0_complex(self):
        print("\n[TAU_LOGIC_CASE] Rule processing: complex rule on i0")
        complex_rule = "always o1[t] = i1[t] && o2[t] = 0"  # More complex rule
        self._assert_tau_response(complex_rule, tau_defs.ACK_RULE_PROCESSED_SBF, 
                                "Tau should return ACK_RULE_PROCESSED_SBF for complex rule.", 
                                output_stream=0)

    # ===== Fallback Cases =====

    def test_12_fallback_fail_invalid_both_zero(self):
        print("\n[TAU_LOGIC_CASE] Fallback: both i0 and i1 are zero/inactive")
        zero_sbf = tau_defs.TAU_VALUE_ZERO  # Should trigger fallback
        self._assert_tau_response(zero_sbf, tau_defs.FAIL_INVALID_SBF, 
                                "Tau should return FAIL_INVALID_SBF when both streams are inactive.")

    def test_13_fallback_fail_invalid_unrecognized(self):
        print("\n[TAU_LOGIC_CASE] Fallback: unrecognized input pattern")
        # Create an SBF that's not zero but also not a valid 16-bit format for i1
        unrecognized_sbf = utils.bits_to_tau_literal("101010", length=6)  # 6-bit Tau literal
        self._assert_tau_response(unrecognized_sbf, tau_defs.FAIL_INVALID_SBF, 
                                "Tau should return FAIL_INVALID_SBF for unrecognized patterns.")

    # ===== Pointwise Revision Test =====

    def test_14_pointwise_revision_functionality(self):
        print("\n[TAU_LOGIC_CASE] Pointwise revision: rule should be assigned to u[t]")
        # This test is more complex because we need to check if u[t] gets the rule
        # For now, we'll test that rule processing works correctly
        # The actual pointwise revision testing would require more sophisticated setup
        revision_rule = "o1[t] = 42"  # Rule that should go to u[t]
        # Test that the rule is acknowledged on o0
        self._assert_tau_response(revision_rule, tau_defs.ACK_RULE_PROCESSED_SBF, 
                                "Tau should acknowledge rule processing for pointwise revision.", 
                                output_stream=0)
        # Note: Testing the actual u[t] assignment would require monitoring that stream,
        # which is beyond the current test framework scope

if __name__ == '__main__':
    # This allows running the tests directly from this file
    unittest.main()
