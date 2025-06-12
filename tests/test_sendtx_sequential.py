#!/usr/bin/env python3

"""
Test script for sequential multi-operation sendtx functionality.
"""

import sys
import os
import json
import time
import argparse
from unittest.mock import patch, MagicMock

# Add the parent directory to sys.path to import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import commands.sendtx as sendtx_module # So we can patch its internals
from commands.sendtx import queue_transaction, _get_signing_message_bytes
import chain_state
import db
import sbf_defs
from py_ecc.bls import G2Basic
import hashlib

# --- Mocking Setup ---
class MockTauManagerSequential:
    def __init__(self):
        self.tau_call_history = []
        self.responses = [] # List of responses to return for each call
        self.current_call_idx = 0

    def set_responses(self, responses):
        self.responses = responses
        self.current_call_idx = 0

    def communicate_with_tau(self, sbf_input_str):
        self.tau_call_history.append(sbf_input_str)
        print(f"  [MOCK_TAU] Received Input:\n{sbf_input_str}")
        if self.current_call_idx < len(self.responses):
            response = self.responses[self.current_call_idx]
            self.current_call_idx += 1
            print(f"  [MOCK_TAU] Returning: {response}")
            return response
        print("  [MOCK_TAU] WARN: No more pre-set responses. Returning SBF_LOGICAL_ONE by default.")
        return sbf_defs.SBF_LOGICAL_ONE # Default success if not specified

# --- Test Helper ---
def _create_signed_tx_json(sender_privkey_int, operations, seq_num, expiration_offset=1000):
    sender_sk_bytes = sender_privkey_int.to_bytes(32, 'big').rjust(48, b'\x00')
    sender_pk_hex = G2Basic.SkToPk(sender_sk_bytes).hex()
    
    payload_for_sig = {
        "sender_pubkey": sender_pk_hex,
        "sequence_number": seq_num,
        "expiration_time": int(time.time()) + expiration_offset,
        "operations": operations,
        "fee_limit": "0",
    }
    msg_bytes = _get_signing_message_bytes(payload_for_sig)
    msg_hash = hashlib.sha256(msg_bytes).digest()
    sig_bytes = G2Basic.Sign(sender_sk_bytes, msg_hash)
    
    payload_for_sig["signature"] = sig_bytes.hex()
    return json.dumps(payload_for_sig)

# --- Test Cases ---
def run_test_sequential_ops():
    print("\n=== Testing Sequential Multi-Operation SendTX ===\n")
    
    # Setup Mocks and Test Environment
    if os.path.exists("test_sequential_sendtx.sqlite"): os.remove("test_sequential_sendtx.sqlite")
    db.STRING_DB_PATH = "test_sequential_sendtx.sqlite"
    db.init_db()
    chain_state.init_chain_state()
    sendtx_module._PY_ECC_AVAILABLE = True # Enable crypto for these tests
    
    mock_tau_manager = MockTauManagerSequential()
    patcher_tau = patch('commands.sendtx.tau_manager', mock_tau_manager)
    patcher_tau.start()

    # Test Keys
    sender_priv_key = 12345 # Example private key as int
    sender_pub_key = G2Basic.SkToPk(sender_priv_key.to_bytes(32, 'big').rjust(48, b'\x00')).hex()
    recipient_pub_key = G2Basic.SkToPk((67890).to_bytes(32, 'big').rjust(48, b'\x00')).hex()
    
    # Give sender some balance and set initial sequence number
    chain_state._balances[sender_pub_key] = 100 
    chain_state._sequence_numbers[sender_pub_key] = 0

    # --- Test Case 1: Rule (Op 0) + Transfer (Op 1) --- 
    print("\n--- Test Case 1: Rule (Op 0) + Transfer (Op 1) ---")
    mock_tau_manager.set_responses([
        sbf_defs.ACK_RULE_PROCESSED_SBF, # Response for Op 0 (rule)
        sendtx_module._encode_single_transfer_sbf( # Response for Op 1 (transfer) - echo SBF
            [sender_pub_key, recipient_pub_key, "5"], 
            min(chain_state.get_balance(sender_pub_key), 15) # Correct balance_for_tau
        ) 
    ])
    operations1 = {
        "0": "o2[t]=i1[t]",
        "1": [[sender_pub_key, recipient_pub_key, "5"]]
    }
    tx_json1 = _create_signed_tx_json(sender_priv_key, operations1, 0)
    result1 = queue_transaction(tx_json1)
    print(f"Result1: {result1}")
    assert "SUCCESS" in result1
    assert len(mock_tau_manager.tau_call_history) == 2
    assert mock_tau_manager.tau_call_history[0] == "o2[t]=i1[t]"
    # Second call should be F \n <transfer_sbf>
    assert mock_tau_manager.tau_call_history[1].startswith("F\n")
    assert chain_state.get_balance(recipient_pub_key) == 5
    assert chain_state.get_sequence_number(sender_pub_key) == 1

    mock_tau_manager.tau_call_history.clear()
    # Reset for next test
    chain_state._balances[sender_pub_key] = 100
    chain_state._balances[recipient_pub_key] = 0 
    chain_state._sequence_numbers[sender_pub_key] = 1 # Next sequence number

    # --- Test Case 2: Op 0 (Rule) fails --- 
    print("\n--- Test Case 2: Op 0 (Rule) Fails ---")
    mock_tau_manager.set_responses([sbf_defs.SBF_LOGICAL_ZERO]) # Op 0 fails
    operations2 = {"0": "bad_rule"}
    tx_json2 = _create_signed_tx_json(sender_priv_key, operations2, 1)
    result2 = queue_transaction(tx_json2)
    print(f"Result2: {result2}")
    assert "FAILURE" in result2
    assert "operation index 0" in result2
    assert len(mock_tau_manager.tau_call_history) == 1
    assert chain_state.get_balance(recipient_pub_key) == 0 # No changes
    assert chain_state.get_sequence_number(sender_pub_key) == 1 # Seq not incremented

    mock_tau_manager.tau_call_history.clear()
    # Sequence number remains 1 for next attempt

    # --- Test Case 3: Op 1 (Transfer) fails after Op 0 (Rule) succeeds --- 
    print("\n--- Test Case 3: Op 1 (Transfer) Fails ---")
    mock_tau_manager.set_responses([
        sbf_defs.ACK_RULE_PROCESSED_SBF, # Op 0 (rule) succeeds
        sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF # Op 1 (transfer) fails
    ])
    operations3 = {
        "0": "o2[t]=i1[t]",
        "1": [[sender_pub_key, recipient_pub_key, "50"]]
    }
    tx_json3 = _create_signed_tx_json(sender_priv_key, operations3, 1)
    result3 = queue_transaction(tx_json3)
    print(f"Result3: {result3}")
    assert "FAILURE" in result3
    assert "Invalid amount '50'" in result3 
    assert len(mock_tau_manager.tau_call_history) == 0 # Should fail before any Tau call for Op 1
    assert chain_state.get_balance(recipient_pub_key) == 0 # No changes
    assert chain_state.get_sequence_number(sender_pub_key) == 1 # Seq not incremented

    mock_tau_manager.tau_call_history.clear()

    # --- Test Case 4: Operations 0, 2, 4 (gaps) --- 
    print("\n--- Test Case 4: Operations 0, 2, 4 (with gaps) ---")
    mock_tau_manager.set_responses([
        sbf_defs.ACK_RULE_PROCESSED_SBF,    # Op 0 (rule)
        sbf_defs.SBF_LOGICAL_ONE,           # Op 1 (implicit F, Tau sees F\nF)
        sbf_defs.SBF_LOGICAL_ONE,           # Op 2 (custom, Tau sees F\nF\n<custom_sbf>)
        sbf_defs.SBF_LOGICAL_ONE,           # Op 3 (implicit F, Tau sees F\nF\nF\nF)
        sbf_defs.SBF_LOGICAL_ONE            # Op 4 (custom, Tau sees F\nF\nF\nF\n<custom_sbf>)
    ])
    operations4 = {
        "0": "a_rule",
        "2": "custom_op_data_for_2", # Will be encoded to F by placeholder _encode_operation_to_sbf
        "4": "custom_op_data_for_4"
    }
    tx_json4 = _create_signed_tx_json(sender_priv_key, operations4, 1)
    result4 = queue_transaction(tx_json4)
    print(f"Result4: {result4}")
    assert "SUCCESS" in result4
    assert len(mock_tau_manager.tau_call_history) == 5 # 0, 1, 2, 3, 4
    assert mock_tau_manager.tau_call_history[0] == "a_rule"
    assert mock_tau_manager.tau_call_history[1] == "F\nF"
    assert mock_tau_manager.tau_call_history[2] == "F\nF\nF" # Custom ops are F for now
    assert mock_tau_manager.tau_call_history[3] == "F\nF\nF\nF"
    assert mock_tau_manager.tau_call_history[4] == "F\nF\nF\nF\nF"
    assert chain_state.get_sequence_number(sender_pub_key) == 2

    patcher_tau.stop()
    if os.path.exists("test_sequential_sendtx.sqlite"): os.remove("test_sequential_sendtx.sqlite")
    print("\nSequential Multi-Op SendTX tests finished.")

if __name__ == "__main__":
    run_test_sequential_ops() 