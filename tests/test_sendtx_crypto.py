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

TEST_DB_PATH = "test_tau_string_db_crypto.sqlite"
os.environ["TAU_DB_PATH"] = TEST_DB_PATH

from commands import sendtx
import chain_state
import db
import sbf_defs # Though not directly used, imported by sendtx
import utils # For _get_signing_message_bytes
from commands.sendtx import _get_signing_message_bytes # Explicit import
import py_ecc.bls as _bls_module # For BLS operations
from py_ecc.bls import G2Basic as bls # For BLS operations

# --- Helper Addresses ---
GENESIS_ADDR = chain_state.GENESIS_ADDRESS
ADDR_A = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a"
ADDR_B = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000b"

# Minimal MockTauManager for crypto tests, as Tau interaction is not the focus
class MockTauManager:
    def __init__(self):
        self.mode = "echo"
        self.tau_call_count = 0
    def communicate_with_tau(self, sbf_input_str):
        self.tau_call_count += 1
        if self.mode == "echo": return sbf_input_str
        return sbf_input_str

class TestSendTxCrypto(unittest.TestCase):
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

        # For crypto tests, we often want real pubkey validation, so don't mock _validate_bls12_381_pubkey by default
        # It will be controlled per test if needed, or we'll rely on its actual behavior.
        # However, ensure py_ecc is seen as available for these tests.
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls # Ensure the bls module is assigned in sendtx
        print(f"[SETUP] Patched tau_manager. py_ecc.bls is enabled for sendtx.")

    def tearDown(self):
        self.patcher_tau_comm.stop()
        # Ensure _PY_ECC_AVAILABLE is reset if changed by a test
        sendtx._PY_ECC_AVAILABLE = False 
        sendtx._PY_ECC_BLS = None
        self._cleanup_db()
        print(f"[TEARDOWN] Test {self.id()} finished.")

    def _create_tx_dict(self, operations_or_transfers, expiration_time=None, sequence_number=None, sender_pubkey=None, fee_limit="0"):
        if isinstance(operations_or_transfers, list):
            ops = {"1": operations_or_transfers}
        else:
            ops = operations_or_transfers
        exp_time = expiration_time if expiration_time is not None else int(time.time()) + 1000
        pk_hex_to_use = sender_pubkey or GENESIS_ADDR
        # For crypto tests, sequence number needs to be accurate if PY_ECC_AVAILABLE is True
        seq = sequence_number if sequence_number is not None else chain_state.get_sequence_number(pk_hex_to_use)

        return {
            "sender_pubkey": pk_hex_to_use,
            "sequence_number": seq,
            "expiration_time": exp_time,
            "operations": ops,
            "fee_limit": fee_limit,
        }

    def _sign_tx_dict(self, tx_dict, sender_privkey):
        # This helper assumes tx_dict already has all necessary fields for signing except "signature"
        msg_bytes = _get_signing_message_bytes(tx_dict)
        msg_hash = hashlib.sha256(msg_bytes).digest()
        sig_bytes = bls.Sign(sender_privkey, msg_hash)
        tx_dict["signature"] = sig_bytes.hex()
        return tx_dict

    def _create_signed_tx_json(self, operations_or_transfers, sender_privkey, expiration_time=None, sequence_number=None, sender_pubkey=None, fee_limit="0"):
        # Determine public key from private key if not provided
        actual_sender_pubkey = sender_pubkey
        if actual_sender_pubkey is None:
            actual_sender_pubkey = bls.SkToPk(sender_privkey).hex()

        tx_dict_unsigned = self._create_tx_dict(operations_or_transfers, expiration_time, sequence_number, actual_sender_pubkey, fee_limit)
        tx_dict_signed = self._sign_tx_dict(tx_dict_unsigned, sender_privkey)
        return json.dumps(tx_dict_signed)

    def test_valid_signature_and_sequence_increment(self):
        print("[TEST_CASE] Crypto: Valid signature and correct sequence number increment")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_crypto_1")
        pk_hex = bls.SkToPk(privkey).hex()
        initial_seq = chain_state.get_sequence_number(pk_hex) # Should be 0
        amount = 3
        chain_state._balances[pk_hex] = amount # Fund the new account

        tx_json = self._create_signed_tx_json(
            operations_or_transfers=[[pk_hex, ADDR_A, str(amount)]],
            sender_privkey=privkey,
            sequence_number=initial_seq # Explicitly pass current sequence number
        )
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"), f"Unexpected: {result}")
        self.assertEqual(chain_state.get_sequence_number(pk_hex), initial_seq + 1)

    def test_invalid_signature_tampered(self):
        print("[TEST_CASE] Crypto: Invalid signature rejection (tampered signature)")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_crypto_2")
        pk_hex = bls.SkToPk(privkey).hex()
        chain_state._balances[pk_hex] = 5 # Fund account
        seq = chain_state.get_sequence_number(pk_hex)

        tx_dict_unsigned = self._create_tx_dict(
            operations_or_transfers=[[pk_hex, ADDR_A, "2"]],
            sender_pubkey=pk_hex,
            sequence_number=seq
        )
        # Valid signature initially
        tx_dict_signed = self._sign_tx_dict(tx_dict_unsigned, privkey)
        # Tamper the signature
        original_sig = tx_dict_signed["signature"]
        tampered_sig = list(original_sig)
        tampered_sig[5] = 'F' if tampered_sig[5] != 'F' else 'E' # Flip a char
        tx_dict_signed["signature"] = "".join(tampered_sig)
        tx_json_tampered_sig = json.dumps(tx_dict_signed)

        result = sendtx.queue_transaction(tx_json_tampered_sig)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"), f"Unexpected result: {result}")
        self.assertEqual(chain_state.get_sequence_number(pk_hex), seq) # Sequence not incremented

    def test_invalid_signature_wrong_data(self):
        print("[TEST_CASE] Crypto: Invalid signature (signature of wrong data)")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_crypto_3")
        pk_hex = bls.SkToPk(privkey).hex()
        chain_state._balances[pk_hex] = 5 # Fund account
        seq = chain_state.get_sequence_number(pk_hex)

        # Data for actual transaction
        ops_actual = [[pk_hex, ADDR_A, "3"]]
        tx_dict_actual_unsigned = self._create_tx_dict(ops_actual, sender_pubkey=pk_hex, sequence_number=seq)

        # Data that will be signed (different operations)
        ops_for_signing = [[pk_hex, ADDR_A, "4"]]
        tx_dict_for_signing = self._create_tx_dict(ops_for_signing, sender_pubkey=pk_hex, sequence_number=seq)
        signed_wrong_data_dict = self._sign_tx_dict(tx_dict_for_signing, privkey)

        # Use signature from wrongly signed data with actual transaction data
        tx_dict_actual_unsigned["signature"] = signed_wrong_data_dict["signature"]
        tx_json_final = json.dumps(tx_dict_actual_unsigned)

        result = sendtx.queue_transaction(tx_json_final)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"), f"Res: {result}")
        self.assertEqual(chain_state.get_sequence_number(pk_hex), seq)

    def test_invalid_signature_wrong_private_key(self):
        print("[TEST_CASE] Crypto: Invalid signature (signed with wrong private key)")
        self.mock_tau_manager_instance.mode = "auto"
        privkey_sender = bls.KeyGen(b"test_seed_crypto_sender")
        pk_hex_sender = bls.SkToPk(privkey_sender).hex()
        privkey_signer = bls.KeyGen(b"test_seed_crypto_signer") # Different key
        chain_state._balances[pk_hex_sender] = 5 # Fund sender account
        seq = chain_state.get_sequence_number(pk_hex_sender)

        ops = [[pk_hex_sender, ADDR_A, "5"]]
        tx_dict_unsigned = self._create_tx_dict(ops, sender_pubkey=pk_hex_sender, sequence_number=seq)
        # Sign with the wrong private key
        tx_dict_signed_wrong_key = self._sign_tx_dict(tx_dict_unsigned, privkey_signer)
        tx_json = json.dumps(tx_dict_signed_wrong_key)

        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"), f"Res: {result}")
        self.assertEqual(chain_state.get_sequence_number(pk_hex_sender), seq)

    def test_invalid_sequence_number_after_valid_signature(self):
        print("[TEST_CASE] Crypto: Invalid sequence number (after valid signature)")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_crypto_6")
        pk_hex = bls.SkToPk(privkey).hex()
        chain_state._balances[pk_hex] = 10 # Fund
        initial_seq = chain_state.get_sequence_number(pk_hex) # e.g., 0
        wrong_seq = initial_seq + 1 # This would be for the *next* tx

        # Create and sign the transaction with the WRONG sequence number
        tx_json = self._create_signed_tx_json(
            operations_or_transfers=[[pk_hex, ADDR_A, "7"]],
            sender_privkey=privkey,
            sequence_number=wrong_seq # Using future sequence number
        )
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid sequence number"), f"Res: {result}")
        self.assertIn(f"expected {initial_seq}, got {wrong_seq}", result)
        self.assertEqual(chain_state.get_sequence_number(pk_hex), initial_seq) # Sequence not incremented

    def test_signature_verification_fails_on_tampered_data_after_signing(self):
        print("[TEST_CASE] Crypto: Sig verification fails on data tampered after signing")
        self.mock_tau_manager_instance.mode = "auto"
        privkey = bls.KeyGen(b"test_seed_crypto_7")
        pk_hex = bls.SkToPk(privkey).hex()
        chain_state._balances[pk_hex] = 10 # Fund
        seq = chain_state.get_sequence_number(pk_hex)

        ops = [[pk_hex, ADDR_A, "8"]]
        tx_json_signed_correctly = self._create_signed_tx_json(ops, privkey, sequence_number=seq)

        # Tamper the amount in the payload AFTER signing
        tx_dict_loaded = json.loads(tx_json_signed_correctly)
        tx_dict_loaded["operations"]["1"][0][2] = "9" # Change amount from "8" to "9"
        tx_json_tampered_data = json.dumps(tx_dict_loaded)

        result = sendtx.queue_transaction(tx_json_tampered_data)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"), f"Res: {result}")
        self.assertEqual(chain_state.get_sequence_number(pk_hex), seq)

    def test_skip_signature_verification_and_sequence_when_PY_ECC_DISABLED(self):
        print("[TEST_CASE] Crypto: Skip sig verify & seq enforcement when PY_ECC_AVAILABLE=False")
        # Temporarily disable PY_ECC for this test in sendtx module
        original_py_ecc_available = sendtx._PY_ECC_AVAILABLE
        sendtx._PY_ECC_AVAILABLE = False
        self.addCleanup(setattr, sendtx, '_PY_ECC_AVAILABLE', original_py_ecc_available)

        self.mock_tau_manager_instance.mode = "auto"
        initial_seq_genesis = chain_state.get_sequence_number(GENESIS_ADDR)
        initial_gen_balance = chain_state.get_balance(GENESIS_ADDR)
        initial_a_balance = chain_state.get_balance(ADDR_A)
        amount_to_send = 5

        # Create a transaction with a clearly invalid signature and potentially wrong sequence
        tx_dict = self._create_tx_dict(
            operations_or_transfers=[[GENESIS_ADDR, ADDR_A, str(amount_to_send)]],
            sender_pubkey=GENESIS_ADDR,
            sequence_number=initial_seq_genesis + 5 # Intentionally wrong sequence
        )
        tx_dict["signature"] = "OBVIOUSLY_INVALID_SIGNATURE_BUT_PYECC_IS_OFF"
        tx_json = json.dumps(tx_dict)

        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"), f"Res: {result}")
        
        # Sequence number should NOT have been incremented because PY_ECC_AVAILABLE is false
        self.assertEqual(chain_state.get_sequence_number(GENESIS_ADDR), initial_seq_genesis)
        
        # Balances should update because the transaction (despite bad sig/seq) is processed without those checks
        self.assertEqual(chain_state.get_balance(GENESIS_ADDR), initial_gen_balance - amount_to_send)
        self.assertEqual(chain_state.get_balance(ADDR_A), initial_a_balance + amount_to_send)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)

if __name__ == '__main__':
    unittest.main(verbosity=2) 