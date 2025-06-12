

import unittest, os, sys, json, time, hashlib
from unittest.mock import patch
from py_ecc.bls import G2Basic as bls

# Add project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
os.environ["TAU_DB_PATH"] = "test_tau_string_db.sqlite"

from commands import sendtx
import chain_state, db, sbf_defs, utils
from commands.sendtx import _get_signing_message_bytes

GENESIS = chain_state.GENESIS_ADDRESS
# Use stub BLS keys for test addresses
ADDR_A = bls.SkToPk(bls.KeyGen(b"crypto_seed_A")).hex()
ADDR_B = bls.SkToPk(bls.KeyGen(b"crypto_seed_B")).hex()

class TestSendTxCrypto(unittest.TestCase):
    def setUp(self):
        if os.path.exists("test_tau_string_db.sqlite"):
            os.remove("test_tau_string_db.sqlite")
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        chain_state._balances.clear(); chain_state._sequence_numbers.clear()
        db.init_db(); chain_state.init_chain_state()
        def mock_tau_response(input_sbf, target_output_stream_index=1):
            # For crypto tests, simulate proper tau behavior
            if target_output_stream_index == 0:
                return "OK"  # Non-failure response for rule processing
            else:
                # Extract and echo the appropriate stream
                lines = input_sbf.strip().split('\n')
                if len(lines) > target_output_stream_index:
                    return lines[target_output_stream_index]
                else:
                    return lines[-1] if lines else "F"
        self.mock_tau = patch('commands.sendtx.tau_manager.communicate_with_tau', mock_tau_response).start()

    def tearDown(self):
        patch.stopall()

    def _create_tx(self, transfers, expiration=None, sequence=None, sender_privkey=None, signature=None, sender_pubkey=None):
        ops = {"1": transfers}
        exp_time = expiration if expiration is not None else int(time.time()) + 1000
        pk_hex = sender_pubkey or (bls.SkToPk(sender_privkey).hex() if sender_privkey else GENESIS)
        seq = sequence if sequence is not None else chain_state.get_sequence_number(pk_hex)
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
            sig_bytes = bls.Sign(sender_privkey, msg_hash)
            tx_dict["signature"] = sig_bytes.hex()
        elif signature is not None:
            tx_dict["signature"] = signature
        else:
            tx_dict["signature"] = "SIG"
        return json.dumps(tx_dict)

    def test_valid_signature_and_sequence_increment(self):
        privkey = bls.KeyGen(b"test_seed_1")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        initial_seq = chain_state.get_sequence_number(pk_hex)
        amount = 3
        chain_state._balances[pk_hex] = amount
        ops = {"1": [[pk_hex, ADDR_A, str(amount)]]}
        tx_json = self._create_tx([[pk_hex, ADDR_A, str(amount)]], sequence=initial_seq, sender_privkey=privkey)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertEqual(chain_state.get_sequence_number(pk_hex), initial_seq + 1)

    def test_invalid_signature_rejected(self):
        privkey = bls.KeyGen(b"test_seed_2")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        seq = chain_state.get_sequence_number(pk_hex)
        bad_sig = "00" * 96
        tx_json = self._create_tx([[pk_hex, ADDR_A, "2"]], sequence=seq, signature=bad_sig, sender_pubkey=pk_hex)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"))

    def test_invalid_signature_wrong_data(self):
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
        tx_json = self._create_tx([[pk_hex, ADDR_A, "3"]], sequence=seq, signature=sig, sender_pubkey=pk_hex)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"))

    def test_invalid_signature_wrong_private_key(self):
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
        tx_json = self._create_tx([[pk_hex, ADDR_A, "5"]], sequence=seq, signature=sig, sender_pubkey=pk_hex)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"))

    def test_invalid_sequence_number_after_signature(self):
        privkey = bls.KeyGen(b"test_seed_6")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        initial_seq = chain_state.get_sequence_number(pk_hex)
        wrong_seq = initial_seq + 1
        tx_json = self._create_tx([[pk_hex, ADDR_A, "7"]], sequence=wrong_seq, sender_privkey=privkey)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Invalid sequence number"))

    def test_signature_verification_fails_on_tampered_data(self):
        privkey = bls.KeyGen(b"test_seed_7")
        pubkey = bls.SkToPk(privkey)
        pk_hex = pubkey.hex()
        seq = chain_state.get_sequence_number(pk_hex)
        tx_json = self._create_tx([[pk_hex, ADDR_A, "8"]], sequence=seq, sender_privkey=privkey)
        tx_dict = json.loads(tx_json)
        tx_dict["operations"]["1"][0][2] = "9"
        tx_json_tampered = json.dumps(tx_dict)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(tx_json_tampered)
        self.assertTrue(result.startswith("FAILURE: Invalid signature"))

    def test_skip_signature_verification_when_disabled(self):
        initial_seq = chain_state.get_sequence_number(GENESIS)
        initial_gen_balance = chain_state.get_balance(GENESIS)
        initial_a_balance = chain_state.get_balance(ADDR_A)
        tx_json = self._create_tx([[GENESIS, ADDR_A, "5"]], signature="00")
        sendtx._PY_ECC_AVAILABLE = False
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertEqual(chain_state.get_sequence_number(GENESIS), initial_seq)
        self.assertEqual(chain_state.get_balance(GENESIS), initial_gen_balance - 5)
        self.assertEqual(chain_state.get_balance(ADDR_A), initial_a_balance + 5)