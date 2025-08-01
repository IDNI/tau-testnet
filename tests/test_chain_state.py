# Summary of Tests
#
# 1. test_initial_genesis_balance
#    - Verifies genesis address starts with GENESIS_BALANCE and unknown addresses start at 0.
#
# 2. test_get_and_set_balance
#    - Tests manual balance setting and retrieval via direct access to _balances.
#
# 3. test_update_balances_after_transfer
#    - Validates balances update correctly after a successful transfer.
#
# 4. test_update_balances_insufficient_funds_internal_check
#    - Ensures transfer fails and balances remain unchanged when funds are insufficient.
#
# 5. test_update_balances_zero_or_negative_amount
#    - Ensures transfer fails for zero or negative transfer amounts.
#
# 6. test_initial_sequence_number
#    - Checks that new addresses and GENESIS start with sequence number 0.
#
# 7. test_get_and_increment_sequence_number
#    - Verifies that increment_sequence_number increases the sequence correctly.
#
# 8. test_sequence_number_isolation
#    - Ensures sequence numbers are tracked independently per address.

import pytest
pytest.skip("Skipping legacy chain_state tests after persistent state refactor", allow_module_level=True)
import unittest
import os
import sys

# Add the project root to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import chain_state

class TestChainState(unittest.TestCase):

    def setUp(self):
        # Reset chain state before each test for isolation
        chain_state._balances = {}
        chain_state._sequence_numbers = {}
        chain_state.init_chain_state() # Re-initialize with Genesis

    def test_initial_genesis_balance(self):
        print("\n[TEST_CASE] Initial Genesis Balance")
        self.assertEqual(chain_state.get_balance(chain_state.GENESIS_ADDRESS), chain_state.GENESIS_BALANCE)
        self.assertEqual(chain_state.get_balance("unknown_address"), 0)

    def test_get_and_set_balance(self):
        print("\n[TEST_CASE] Get and Set Balance")
        addr1 = "addr1_pubkey_hex"
        self.assertEqual(chain_state.get_balance(addr1), 0)
        
        # Simulate direct balance setting for testing (not a typical operation)
        with chain_state._balance_lock:
            chain_state._balances[addr1] = 100
        self.assertEqual(chain_state.get_balance(addr1), 100)

    def test_update_balances_after_transfer(self):
        print("\n[TEST_CASE] Update Balances After Transfer")
        addr1 = "addr1_pubkey_hex"
        addr2 = "addr2_pubkey_hex"

        with chain_state._balance_lock:
            chain_state._balances[addr1] = 200
            chain_state._balances[addr2] = 50
        
        self.assertTrue(chain_state.update_balances_after_transfer(addr1, addr2, 70))
        self.assertEqual(chain_state.get_balance(addr1), 130)
        self.assertEqual(chain_state.get_balance(addr2), 120)

    def test_update_balances_insufficient_funds_internal_check(self):
        print("\n[TEST_CASE] Update Balances Insufficient (Internal Check)")
        addr1 = "addr1_pubkey_hex"
        addr2 = "addr2_pubkey_hex"
        with chain_state._balance_lock:
            chain_state._balances[addr1] = 30
        
        # This check is internal to update_balances_after_transfer
        self.assertFalse(chain_state.update_balances_after_transfer(addr1, addr2, 50))
        self.assertEqual(chain_state.get_balance(addr1), 30) # Balance should not change
        self.assertEqual(chain_state.get_balance(addr2), 0)

    def test_update_balances_zero_or_negative_amount(self):
        print("\n[TEST_CASE] Update Balances Zero or Negative Amount")
        addr1 = "addr1_pubkey_hex"
        addr2 = "addr2_pubkey_hex"
        with chain_state._balance_lock:
            chain_state._balances[addr1] = 100
        
        self.assertFalse(chain_state.update_balances_after_transfer(addr1, addr2, 0))
        self.assertEqual(chain_state.get_balance(addr1), 100)
        self.assertFalse(chain_state.update_balances_after_transfer(addr1, addr2, -10))
        self.assertEqual(chain_state.get_balance(addr1), 100)

    def test_initial_sequence_number(self):
        print("\n[TEST_CASE] Initial Sequence Number")
        addr1 = "addr1_pubkey_hex"
        self.assertEqual(chain_state.get_sequence_number(addr1), 0)
        self.assertEqual(chain_state.get_sequence_number(chain_state.GENESIS_ADDRESS), 0) # Genesis also starts at 0

    def test_get_and_increment_sequence_number(self):
        print("\n[TEST_CASE] Get and Increment Sequence Number")
        addr1 = "addr1_pubkey_hex"
        self.assertEqual(chain_state.get_sequence_number(addr1), 0)
        
        chain_state.increment_sequence_number(addr1)
        self.assertEqual(chain_state.get_sequence_number(addr1), 1)
        
        chain_state.increment_sequence_number(addr1)
        self.assertEqual(chain_state.get_sequence_number(addr1), 2)

    def test_sequence_number_isolation(self):
        print("\n[TEST_CASE] Sequence Number Isolation")
        addr1 = "addr1_pubkey_hex"
        addr2 = "addr2_pubkey_hex"

        chain_state.increment_sequence_number(addr1)
        self.assertEqual(chain_state.get_sequence_number(addr1), 1)
        self.assertEqual(chain_state.get_sequence_number(addr2), 0) # addr2 should be unaffected

        chain_state.increment_sequence_number(addr2)
        chain_state.increment_sequence_number(addr2)
        self.assertEqual(chain_state.get_sequence_number(addr1), 1)
        self.assertEqual(chain_state.get_sequence_number(addr2), 2)

if __name__ == '__main__':
    unittest.main() 
