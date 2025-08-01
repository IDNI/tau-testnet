import unittest
import os
import json
import tempfile
import sys

import threading
import tau_manager
import sbf_defs
import random

# Ensure project root is on sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from chain_state import rebuild_state_from_blockchain, get_balance, get_sequence_number, GENESIS_ADDRESS, GENESIS_BALANCE
from block import Block
from db import init_db, add_block, clear_mempool
import config
import chain_state


class TestStateReconstruction(unittest.TestCase):
    
    def start_tau(self):
        """Start Tau process via tau_manager in a background thread and wait until it's ready."""
        self.tau_thread = threading.Thread(target=tau_manager.start_and_manage_tau_process, daemon=True)
        self.tau_thread.start()
        ready = tau_manager.tau_ready.wait(timeout=60)
        if not ready:
            self.fail("Tau process failed to become ready within 60 seconds.")

    def stop_tau(self):
        """Request Tau shutdown and wait for the background thread to exit."""
        tau_manager.request_shutdown()
        if hasattr(self, 'tau_thread'):
            self.tau_thread.join(timeout=10)
    def setUp(self):
        """Set up a temporary database for testing state reconstruction."""
        # Create a temporary database file
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(self.temp_db_fd)  # Close the file descriptor, but keep the path
        
        # Configure the database path for testing
        self.original_db_path = config.STRING_DB_PATH
        config.STRING_DB_PATH = self.temp_db_path
        
        # Clear any existing module state
        if hasattr(chain_state, '_balances'):
            chain_state._balances.clear()
        if hasattr(chain_state, '_sequence_numbers'):
            chain_state._sequence_numbers.clear()
        
        # Initialize fresh database
        init_db()
        clear_mempool()
        
        # Sample addresses for testing
        self.addr1 = "91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6"  # Genesis
        self.addr2 = "893c8134a31379c394b4ed31e67daf9565b1d2022aa96d83ca88d013bc208672bcf73dae5cc105da1e277109584239b2"
        self.addr3 = "aabbccddee1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
    
    def tearDown(self):
        """Clean up the temporary database."""
        # Ensure Tau process is stopped between tests
        if tau_manager.tau_ready.is_set():
            try:
                tau_manager.request_shutdown()
            except Exception:
                pass
        # Restore original database path
        config.STRING_DB_PATH = self.original_db_path
        
        # Close database connections if they exist
        import db
        if hasattr(db, '_db_conn') and db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        
        # Remove temporary database file
        if os.path.exists(self.temp_db_path):
            os.remove(self.temp_db_path)
    
    def create_test_transaction(self, sender_pubkey, sequence_number, transfers=None, rules=None):
        """Helper to create a test transaction."""
        operations = {}
        if rules:
            operations["0"] = rules
        if transfers:
            operations["1"] = transfers
        
        return {
            "sender_pubkey": sender_pubkey,
            "sequence_number": sequence_number,
            "expiration_time": 9999999999,  # Far in the future
            "operations": operations,
            "fee_limit": "0",
            "signature": "dummy_signature_for_testing"
        }
    
    def test_reconstruction_empty_blockchain(self):
        """Test state reconstruction when no blocks exist."""
        print("\n=== Testing state reconstruction with empty blockchain ===")
        
        # Rebuild state (should only have genesis)
        rebuild_state_from_blockchain()
        
        # Verify genesis state
        self.assertEqual(get_balance(GENESIS_ADDRESS), GENESIS_BALANCE)
        self.assertEqual(get_sequence_number(GENESIS_ADDRESS), 0)
        
        # Verify no other balances
        self.assertEqual(get_balance(self.addr2), 0)
        self.assertEqual(get_balance(self.addr3), 0)
    
    def test_reconstruction_single_block(self):
        """Test state reconstruction with a single block containing transfers."""
        print("\n=== Testing state reconstruction with single block ===")
        
        # Create a block with one transaction containing transfers
        tx1 = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=0,
            transfers=[
                [self.addr1, self.addr2, "5"],
                [self.addr1, self.addr3, "3"]
            ]
        )
        
        block_0 = Block.create(
            block_number=0,
            previous_hash="0" * 64,
            transactions=[tx1]
        )
        
        # Add block to database
        add_block(block_0)
        
        # Rebuild state
        rebuild_state_from_blockchain()
        
        # Verify final balances
        self.assertEqual(get_balance(self.addr1), GENESIS_BALANCE - 5 - 3)  # 15 - 8 = 7
        self.assertEqual(get_balance(self.addr2), 5)
        self.assertEqual(get_balance(self.addr3), 3)
        
        # Verify sequence numbers
        self.assertEqual(get_sequence_number(self.addr1), 1)  # Incremented after tx
        self.assertEqual(get_sequence_number(self.addr2), 0)
        self.assertEqual(get_sequence_number(self.addr3), 0)
    
    def test_reconstruction_multiple_blocks(self):
        """Test state reconstruction with multiple blocks, each tx has a rule + transfer
        and **every rule is actively confirmed by Tau before reconstruction**."""
        print("\n=== Testing state reconstruction with multiple blocks + Tau confirmations ===")

        # --- Start Tau once for the whole test ---
        self.start_tau()
        try:
            # Use locally defined patterns and pick one at random each time
            BASE_PATTERNS = [
                "(x3 & x7')",
                # "(((x3 & x7) | (x3' & x7')) & x2 & x6')",
                # "(((x3 & x7) | (x3' & x7')) & ((x2 & x6) | (x2' & x6')) & x1 & x5')",
                # "(((x3 & x7) | (x3' & x7')) & ((x2 & x6) | (x2' & x6')) & ((x1 & x5) | (x1' & x5')) & x0 & x4')",
            ]
            random.seed(42)

            def random_pattern() -> str:
                """Return a random pattern from BASE_PATTERNS."""
                return random.choice(BASE_PATTERNS)
            all_rules = []  # keep track for Tau confirmations

            # Simple helper to build a unique rule for index i
            def rule_for(i: int) -> str:
                pat = random_pattern()
                return f"always ((i1[t] <= {{{pat}}}:sbf)? o1[t] ={{x0}}:sbf:o1[t] = i1[t])."

            # -------- Block 0  (sender = addr1) --------
            tx1 = self.create_test_transaction(
                sender_pubkey=self.addr1,
                sequence_number=0,
                transfers=[[self.addr1, self.addr2, "4"]],
                rules=rule_for(0)
            ); all_rules.append(tx1["operations"]["0"])
            tx2 = self.create_test_transaction(
                sender_pubkey=self.addr1,
                sequence_number=1,
                transfers=[[self.addr1, self.addr3, "3"]],
                rules=rule_for(1)
            ); all_rules.append(tx2["operations"]["0"])
            tx3 = self.create_test_transaction(
                sender_pubkey=self.addr1,
                sequence_number=2,
                transfers=[[self.addr1, self.addr2, "3"]],
                rules=rule_for(2)
            ); all_rules.append(tx3["operations"]["0"])
            block_0 = Block.create(
                block_number=0,
                previous_hash="0" * 64,
                transactions=[tx1, tx2, tx3]
            )
            add_block(block_0)

            # -------- Block 1  (sender = addr2) --------
            tx4 = self.create_test_transaction(
                sender_pubkey=self.addr2,
                sequence_number=0,
                transfers=[[self.addr2, self.addr3, "2"]],
                rules=rule_for(3)
            ); all_rules.append(tx4["operations"]["0"])
            tx5 = self.create_test_transaction(
                sender_pubkey=self.addr2,
                sequence_number=1,
                transfers=[[self.addr2, self.addr1, "1"]],
                rules=rule_for(4)
            ); all_rules.append(tx5["operations"]["0"])
            tx6 = self.create_test_transaction(
                sender_pubkey=self.addr2,
                sequence_number=2,
                transfers=[[self.addr2, self.addr3, "3"]],
                rules=rule_for(5)
            ); all_rules.append(tx6["operations"]["0"])
            block_1 = Block.create(
                block_number=1,
                previous_hash=block_0.block_hash,
                transactions=[tx4, tx5, tx6]
            )
            add_block(block_1)

            # -------- Block 2  (sender = addr3) --------
            tx7 = self.create_test_transaction(
                sender_pubkey=self.addr3,
                sequence_number=0,
                transfers=[[self.addr3, self.addr1, "2"]],
                rules=rule_for(6)
            ); all_rules.append(tx7["operations"]["0"])
            tx8 = self.create_test_transaction(
                sender_pubkey=self.addr3,
                sequence_number=1,
                transfers=[[self.addr3, self.addr2, "2"]],
                rules=rule_for(7)
            ); all_rules.append(tx8["operations"]["0"])
            tx9 = self.create_test_transaction(
                sender_pubkey=self.addr3,
                sequence_number=2,
                transfers=[[self.addr3, self.addr1, "1"]],
                rules=rule_for(8)
            ); all_rules.append(tx9["operations"]["0"])
            block_2 = Block.create(
                block_number=2,
                previous_hash=block_1.block_hash,
                transactions=[tx7, tx8, tx9]
            )
            add_block(block_2)

            # --- Send EVERY rule to Tau and expect non‑zero confirmations ---
            for idx, rule in enumerate(all_rules, start=1):
                confirmation = tau_manager.communicate_with_tau(rule, target_output_stream_index=0)
                self.assertNotEqual(
                    confirmation, sbf_defs.SBF_LOGICAL_ZERO,
                    f"Tau confirmation for rule #{idx} should not be logical zero. Got: {confirmation}"
                )

            # -------- Rebuild & Assertions --------
            rebuild_state_from_blockchain()

            # Expected balances after all transactions:
            #   addr1: 15 - (4+3+3) + 1 + (2+1) = 9
            #   addr2: 0  + (4+3) - (2+1+3) + 2 = 3
            #   addr3: 0  + 3 + (2+3) - (2+2+1) = 3
            self.assertEqual(get_balance(self.addr1), 9)
            self.assertEqual(get_balance(self.addr2), 3)
            self.assertEqual(get_balance(self.addr3), 3)

            # Each address sent exactly 3 tx, so sequence # should be 3
            self.assertEqual(get_sequence_number(self.addr1), 3)
            self.assertEqual(get_sequence_number(self.addr2), 3)
            self.assertEqual(get_sequence_number(self.addr3), 3)
        finally:
            # Ensure Tau is shut down even if assertions fail
            self.stop_tau()
    
    def test_reconstruction_with_invalid_transactions(self):
        """Test state reconstruction handles invalid transactions gracefully."""
        print("\n=== Testing state reconstruction with invalid transactions ===")
        
        # Create a block with valid and invalid transactions
        valid_tx = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=0,
            transfers=[[self.addr1, self.addr2, "5"]]
        )
        
        # Invalid transaction: insufficient funds
        invalid_tx = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=1,
            transfers=[[self.addr1, self.addr3, "20"]]  # More than genesis balance
        )
        
        # Transaction with invalid amount format
        invalid_amount_tx = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=2,
            transfers=[[self.addr1, self.addr3, "invalid_amount"]]
        )
        
        block_0 = Block.create(
            block_number=0,
            previous_hash="0" * 64,
            transactions=[valid_tx, invalid_tx, invalid_amount_tx]
        )
        add_block(block_0)
        
        # Rebuild state
        rebuild_state_from_blockchain()
        
        # Only the valid transaction should have been processed
        self.assertEqual(get_balance(self.addr1), GENESIS_BALANCE - 5)  # 10
        self.assertEqual(get_balance(self.addr2), 5)
        self.assertEqual(get_balance(self.addr3), 0)  # Invalid transfers should be ignored
        
        # All sequence numbers should be incremented (even for failed transactions)
        self.assertEqual(get_sequence_number(self.addr1), 3)  # All 3 transactions attempted
    
    def test_reconstruction_preserves_state_consistency(self):
        """Test that reconstruction produces the same state as live processing."""
        print("\n=== Testing state consistency between live and reconstructed state ===")
        
        # Set up initial state manually (simulating live processing)
        chain_state._balances[self.addr1] = 8
        chain_state._balances[self.addr2] = 4
        chain_state._balances[self.addr3] = 3
        chain_state._sequence_numbers[self.addr1] = 2
        chain_state._sequence_numbers[self.addr2] = 1
        
        # Store expected state
        expected_balances = dict(chain_state._balances)
        expected_sequences = dict(chain_state._sequence_numbers)
        
        # Create blocks that would result in this state
        tx1 = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=0,
            transfers=[[self.addr1, self.addr2, "4"]]
        )
        tx2 = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=1,
            transfers=[[self.addr1, self.addr3, "3"]]
        )
        tx3 = self.create_test_transaction(
            sender_pubkey=self.addr2,
            sequence_number=0,
            transfers=[]  # Empty transfer list
        )
        
        block_0 = Block.create(
            block_number=0,
            previous_hash="0" * 64,
            transactions=[tx1, tx2, tx3]
        )
        add_block(block_0)
        
        # Rebuild state from blockchain
        rebuild_state_from_blockchain()
        
        # Verify reconstructed state matches expected state
        self.assertEqual(get_balance(self.addr1), expected_balances[self.addr1])
        self.assertEqual(get_balance(self.addr2), expected_balances[self.addr2])
        self.assertEqual(get_balance(self.addr3), expected_balances[self.addr3])
        self.assertEqual(get_sequence_number(self.addr1), expected_sequences[self.addr1])
        self.assertEqual(get_sequence_number(self.addr2), expected_sequences[self.addr2])
    
    def test_reconstruction_with_rules_and_transfers(self):
        """Test state reconstruction with both rules and transfers in the same transaction."""
        print("\n=== Testing state reconstruction with rules and transfers (Tau integration) ===")

        # --- Start Tau ---
        self.start_tau()
        try:
            rule_text = "o1[t] = {x1}:sbf"

            # Create a transaction containing both the rule and a transfer
            tx1 = self.create_test_transaction(
                sender_pubkey=self.addr1,
                sequence_number=0,
                transfers=[[self.addr1, self.addr2, "8"]],
                rules=rule_text
            )

            # Build and add the block to the chain DB
            block_0 = Block.create(
                block_number=0,
                previous_hash="0" * 64,
                transactions=[tx1]
            )
            add_block(block_0)

            # --- Send rule to Tau and expect a non‑zero confirmation ---
            confirmation = tau_manager.communicate_with_tau(rule_text, target_output_stream_index=0)
            self.assertNotEqual(
                confirmation, sbf_defs.SBF_LOGICAL_ZERO,
                f"Tau confirmation should not be logical zero. Got: {confirmation}"
            )

            # --- Rebuild state from blockchain ---
            rebuild_state_from_blockchain()

            # Verify balances (transfer must be applied)
            self.assertEqual(get_balance(self.addr1), GENESIS_BALANCE - 8)  # 7
            self.assertEqual(get_balance(self.addr2), 8)

            # Verify sequence number
            self.assertEqual(get_sequence_number(self.addr1), 1)
        finally:
            # Ensure Tau is shut down even if assertions fail
            self.stop_tau()
    
    def test_reconstruction_rule_processing_without_tau(self):
        """Test that rule processing fails gracefully when Tau is not available."""
        print("\n=== Testing rule processing without Tau available ===")
        
        # Create a transaction with only rules (no transfers)
        tx1 = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=0,
            rules="test_rule_for_tau_processing"
        )
        
        block_0 = Block.create(
            block_number=0,
            previous_hash="0" * 64,
            transactions=[tx1]
        )
        add_block(block_0)
        
        # Rebuild state - this should handle Tau not being available gracefully
        try:
            rebuild_state_from_blockchain()
            
            # Even if rule processing fails, sequence number should still be updated
            self.assertEqual(get_sequence_number(self.addr1), 1)
            # Balance should remain unchanged (no transfers)
            self.assertEqual(get_balance(self.addr1), GENESIS_BALANCE)
            
        except Exception as e:
            self.fail(f"State reconstruction should not fail due to Tau unavailability: {e}")
    
    def test_reconstruction_with_unknown_operations(self):
        """Test state reconstruction handles unknown operation types gracefully."""
        print("\n=== Testing state reconstruction with unknown operations ===")
        
        # Create a transaction with unknown operation types
        tx1 = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=0,
            transfers=[
                [self.addr1, self.addr2, "3"]
            ]
        )
        # Add unknown operations manually
        tx1["operations"]["99"] = "unknown_operation_data"
        tx1["operations"]["custom"] = {"some": "data"}
        
        block_0 = Block.create(
            block_number=0,
            previous_hash="0" * 64,
            transactions=[tx1]
        )
        add_block(block_0)
        
        # Rebuild state (should process known operations and skip unknown ones)
        rebuild_state_from_blockchain()
        
        # Verify that known operations (transfers) were still processed
        self.assertEqual(get_balance(self.addr1), GENESIS_BALANCE - 3)  # 12
        self.assertEqual(get_balance(self.addr2), 3)
        self.assertEqual(get_sequence_number(self.addr1), 1)
    
    def test_reconstruction_empty_operations(self):
        """Test state reconstruction with transactions that have empty operations."""
        print("\n=== Testing state reconstruction with empty operations ===")
        
        # Create transactions with various empty operation scenarios
        tx1 = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=0,
            transfers=[],  # Empty transfer list
            rules=""       # Empty rule
        )
        
        tx2 = self.create_test_transaction(
            sender_pubkey=self.addr1,
            sequence_number=1
            # No operations at all
        )
        
        block_0 = Block.create(
            block_number=0,
            previous_hash="0" * 64,
            transactions=[tx1, tx2]
        )
        add_block(block_0)
        
        # Rebuild state
        rebuild_state_from_blockchain()
        
        # Verify state: no transfers should have occurred, but sequence numbers should be incremented
        self.assertEqual(get_balance(self.addr1), GENESIS_BALANCE)  # No change
        self.assertEqual(get_balance(self.addr2), 0)
        self.assertEqual(get_sequence_number(self.addr1), 2)  # Both transactions processed


if __name__ == '__main__':
    unittest.main() 