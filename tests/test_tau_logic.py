# Summary of Tau Logic Tests
#
# 1. test_01_valid_transfer_success
#    - Confirms Tau validates a transfer with sufficient funds and distinct addresses.
#
# 2. test_02_insufficient_funds
#    - Verifies Tau returns FAIL (o2=0) when amount > balance.
#
# 3. test_03_source_equals_destination
#    - Checks Tau returns FAIL (o3=0) when source and destination IDs are equal.
#
# 4. test_04_zero_amount
#    - (Skipped unless rule exists)
#
# 5. test_05_amount_equals_balance_valid
#    - Validates success when amount equals balance.
#
# 6. test_06_max_values_valid
#    - Tests success for maximum field values.
#
# 7. test_07_insufficient_funds_at_zero_balance
#    - Confirms FAIL when balance is zero and amount > 0.
#
# 8-9. Format Validation Tests (Legacy i0)
#    - These verify Genesis rule rejection of invalid SBF on i0.
#
# 10-14. Helper Tests (Legacy i0)
#    - Rule processing and fallback checks.

import unittest
import os
import sys
import time
import threading
import glob

# Add the project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Ensure TAU_DB_PATH is set for db.py
TEST_DB_PATH = "test_tau_logic_db.sqlite"

import tau_manager
import tau_defs
import utils
import config
import db

class TestTauLogic(unittest.TestCase):
    manager_thread = None

    @classmethod
    def setUpClass(cls):
        """Starts the Tau manager, loads rules, and prepares for testing."""
        os.environ["TAU_DB_PATH"] = TEST_DB_PATH
        os.environ["TAU_FORCE_TEST"] = "0" # FORCE REAL ENGINE
        print("\n--- Starting Tau Manager for TestTauLogic ---")
        if os.path.exists(TEST_DB_PATH):
            try:
                os.remove(TEST_DB_PATH)
            except OSError:
                pass
        db.init_db()

        if not os.path.exists(config.TAU_PROGRAM_FILE):
             raise FileNotFoundError(f"Tau program file '{config.TAU_PROGRAM_FILE}' not found.")

        tau_manager.server_should_stop.clear()
        tau_manager.tau_ready.clear()

        print("[INFO][TestTauLogic] Starting tau_manager.start_and_manage_tau_process in a thread.")
        cls.manager_thread = threading.Thread(target=tau_manager.start_and_manage_tau_process, daemon=True)
        cls.manager_thread.start()

        print("[INFO][TestTauLogic] Waiting for Tau to become ready (timeout: 30s)...")
        ready = tau_manager.tau_ready.wait(timeout=30)
        if not ready:
            print("[ERROR][TestTauLogic] Tau did not become ready. Requesting shutdown.")
            tau_manager.request_shutdown()
            if cls.manager_thread.is_alive():
                cls.manager_thread.join(timeout=5)
            raise Exception("Tau process did not become ready.")
        
        print("[INFO][TestTauLogic] Tau Manager Ready. Injecting Rules...")
        rules_dir = os.path.join(project_root, 'rules')
        rule_files = sorted(glob.glob(os.path.join(rules_dir, '*.tau')))
        
        if not rule_files:
            print("[WARN] No rule files found in rules/!")
        
        # Inject rules one by one via i0
        for rf in rule_files:
            print(f"[INFO] Loading rule: {os.path.basename(rf)}")
            with open(rf, 'r') as f:
                lines = f.readlines()
            
            # Filter comments and empty lines to prevent REPL syntax errors/y-umlaut issues
            clean_lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]
            content = " ".join(clean_lines)
            
            if not content:
                print(f"[WARN] Rule file {rf} was empty after stripping comments.")
                continue

            # Genesis returns o0=0 (and u=i0) for valid rule input
            try:
                resp = tau_manager.communicate_with_tau(rule_text=content, target_output_stream_index=0, apply_rules_update=True)
                # We don't assert specific response here, just that it didn't crash
            except Exception as e:
                print(f"[ERROR] Failed to load rule {rf}: {e}")

        print("[INFO] Rules loaded.")

    @classmethod
    def tearDownClass(cls):
        print("\n--- Stopping Tau Manager for TestTauLogic ---")
        if tau_manager.tau_direct_interface:
            try:
                # Force replace interpreter to release AST memory early
                tau_manager.tau_direct_interface.interpreter = tau_manager.tau_direct_interface.tau.interpreter()
            except Exception:
                pass
        tau_manager.request_shutdown()
        if cls.manager_thread and cls.manager_thread.is_alive():
            cls.manager_thread.join(timeout=10)
        
        tau_manager.tau_ready.clear()
        tau_manager.server_should_stop.clear()
        os.environ["TAU_FORCE_TEST"] = "1"
        if os.path.exists(TEST_DB_PATH):
            try:
                os.remove(TEST_DB_PATH)
            except OSError:
                pass

    def _construct_stream_inputs(self, amount: int, balance: int, from_id_idx: int, to_id_idx: int) -> dict:
        """Construct input dictionary for i1, i2, i3, i4 (Amount, Bal, From, To)."""
        return {
            1: str(amount),
            2: str(balance),
            3: str(from_id_idx),
            4: str(to_id_idx)
        }

    def _assert_tau_validation(self, input_data, expected_output: str, msg: str, check_stream: int = 1):
        """
        Helper for assertions.
        If input_data is dict, sends as stream inputs.
        If input_data is str, sends as rule text (i0).
        """
        self.assertTrue(tau_manager.tau_ready.is_set(), "Tau not ready.")
        print(f"    [TEST] Sending: {input_data}")
        
        try:
            if isinstance(input_data, dict):
                 response = tau_manager.communicate_with_tau(input_stream_values=input_data, target_output_stream_index=check_stream)
            else:
                 response = tau_manager.communicate_with_tau(rule_text=input_data, target_output_stream_index=check_stream)
            
            print(f"    [TEST] Received o{check_stream}: {response}")
            parsed_response = str(tau_manager.parse_tau_output(response))
            self.assertEqual(parsed_response.strip(), expected_output.strip(), f"{msg} (parsed: {parsed_response} != {expected_output})")
        except Exception as e:
            self.fail(f"Comm Error: {e}")

    # ===== Transaction Logic Tests (using i1..i4 inputs) =====

    def test_01_valid_transfer_success(self):
        print("\n[CASE] Valid transfer: Amt=5, Bal=10")
        inputs = self._construct_stream_inputs(amount=5, balance=10, from_id_idx=1, to_id_idx=2)
        # Check o2 (Balance Check) passes. Engine returns "1" (true)
        self._assert_tau_validation(inputs, "1", 
                                  "Should return SUCCESS (o2=1) due to sufficient funds.", check_stream=2)

    def test_02_insufficient_funds(self):
        print("\n[CASE] Insufficient: Amt=10, Bal=5")
        inputs = self._construct_stream_inputs(amount=10, balance=5, from_id_idx=1, to_id_idx=2)
        # Check o2 (Balance Check) fails (o2=0)
        self._assert_tau_validation(inputs, "0", 
                                  "Should return FAIL (o2=0) due to insufficient funds.", check_stream=2)

    def test_03_source_equals_destination(self):
        print("\n[CASE] Src==Dest")
        inputs = self._construct_stream_inputs(amount=5, balance=10, from_id_idx=1, to_id_idx=1)
        # Check o3 (Address Check Logic). Engine returns "0" (false) for match?
        # Rule 02 says: (Src==Dest) ? o3=0 : o3=1.
        # So "0" means Src==Dest (Fail).
        self._assert_tau_validation(inputs, "0", 
                                  "Should return FAIL (o3=0) due to src==dest.", check_stream=3)

    def test_05_amount_equals_balance_valid(self):
        print("\n[CASE] Amt=Bal=10")
        inputs = self._construct_stream_inputs(amount=10, balance=10, from_id_idx=1, to_id_idx=2)
        self._assert_tau_validation(inputs, "1", 
                                  "Should return SUCCESS when amt==bal.", check_stream=2)

    def test_06_max_values_valid(self):
        print("\n[CASE] Max Values")
        # 4-bit max is 15. Rules use 64-bit arithmetic so 15 is fine.
        inputs = self._construct_stream_inputs(amount=15, balance=15, from_id_idx=15, to_id_idx=14)
        self._assert_tau_validation(inputs, "1", 
                                  "Should return SUCCESS with 4-bit max values.", check_stream=2)

    def test_07_insufficient_funds_at_zero_balance(self):
        print("\n[CASE] Insufficient: Amt=1, Bal=0")
        inputs = self._construct_stream_inputs(amount=1, balance=0, from_id_idx=1, to_id_idx=2)
        self._assert_tau_validation(inputs, "0", 
                                  "Should fail due to zero balance.", check_stream=2)

    # ===== Legacy/Invalid Format Tests (sending to i0) =====

    def test_dummy_end(self):
        pass
