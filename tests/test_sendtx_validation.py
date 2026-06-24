

import unittest, os, sys, json, time, hashlib, importlib
from unittest.mock import patch
from py_ecc.bls import G2Basic as bls

# Add project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Removed os.environ["TAU_DB_PATH"] override to prevent global pollution

import config
from commands import sendtx
import chain_state, db, tau_defs, utils
from commands.sendtx import _get_signing_message_bytes

GENESIS = chain_state.GENESIS_ADDRESS
# Use stub BLS keys for test addresses
ADDR_A = bls.SkToPk(bls.KeyGen(b"validation_seed_A")).hex()
ADDR_B = bls.SkToPk(bls.KeyGen(b"validation_seed_B")).hex()
# Real signing key for the default sender (signatures are verified for real now).
SK_SENDER = bls.KeyGen(b"validation_sender")
SENDER = bls.SkToPk(SK_SENDER).hex()
INVALID_ADDR_SHORT = "short"
INVALID_ADDR_NON_HEX = "000...g"


def _sign_tx(tx_dict, sk=SK_SENDER):
    """Sign a tx dict in place with a real BLS signature and return its JSON."""
    msg_hash = hashlib.sha256(_get_signing_message_bytes(tx_dict)).digest()
    tx_dict["signature"] = bls.Sign(sk, msg_hash).hex()
    return json.dumps(tx_dict)

class TestSendTxValidation(unittest.TestCase):
    def setUp(self):
        importlib.reload(sendtx)
        self.test_db = "test_tau_string_db.sqlite"
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        chain_state._balances.clear(); chain_state._sequence_numbers.clear()
        db.init_db(); chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()  # Clear mempool for test isolation
        def mock_tau_response(rule_text, target_output_stream_index=1, input_stream_values=None, **kwargs):
            # New bitvector model: return boolean on o1
            if target_output_stream_index == 0:
                return tau_defs.ACK_RULE_PROCESSED
            parts = rule_text.strip().split('\n') if rule_text else []

            def _resolve(idx, default):
                value_str = None
                if input_stream_values and idx in input_stream_values:
                    stream_value = input_stream_values[idx]
                    if isinstance(stream_value, (list, tuple)):
                        stream_value = stream_value[0] if stream_value else None
                    if stream_value is not None:
                        value_str = str(stream_value)
                elif len(parts) >= idx:
                    value_str = parts[idx - 1]
                if value_str is None or value_str == "":
                    return default
                return int(value_str)

            try:
                amount = _resolve(1, 0)
                balance = _resolve(2, 0)
                from_id = _resolve(3, -1)
                to_id = _resolve(4, -2)
            except (TypeError, ValueError):
                return tau_defs.TAU_VALUE_ZERO
            if amount <= 0:
                return tau_defs.TAU_VALUE_ZERO
            if from_id == to_id:
                return tau_defs.TAU_VALUE_ZERO
            if amount > balance:
                return tau_defs.TAU_VALUE_ZERO
            return tau_defs.TAU_VALUE_ONE
        self.mock_tau = patch('commands.sendtx.tau_manager.communicate_with_tau', mock_tau_response).start()
        # Multi-output mock wraps the same logic but returns dict[int, str]
        def mock_tau_multi(input_stream_values=None, **kwargs):
            o1_val = mock_tau_response(input_stream_values=input_stream_values, target_output_stream_index=1)
            return {1: o1_val}
        patch('commands.sendtx.tau_manager.communicate_with_tau_multi', side_effect=mock_tau_multi).start()
        # Signatures are verified for real; fund the signing sender.
        chain_state._balances[SENDER] = 1000
        # Patch pubkey validation to bypass format checks for basic validation tests
        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()

    def tearDown(self):
        patch.stopall()
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        config.set_database_path(self.original_db_path)

    def _create_tx(self, transfers, sender_pubkey=None):
        ops = {"1": transfers}
        pk_hex = sender_pubkey or SENDER
        tx_dict = {
            "tx_type": "user_tx",
            "sender_pubkey": pk_hex,
            "sequence_number": chain_state.get_sequence_number(pk_hex),
            "expiration_time": int(time.time()) + 1000,
            "operations": ops,
            "fee_limit": "0",
        }
        return _sign_tx(tx_dict)

    def test_fail_amount_too_large_python(self):
        chain_state._balances[SENDER] = 10
        amount_to_send = 16
        tx_json = self._create_tx([[SENDER, ADDR_A, str(amount_to_send)]])
        # Temporarily enable validation by patching os.environ
        with patch.dict(os.environ, {"TAU_FORCE_TEST": "0"}):
             result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"], f"Expected failure, got: {result}")
        self.assertEqual(chain_state.get_balance(SENDER), 10)
        self.assertEqual(len(db.get_mempool_txs()), 0)

    def test_fail_invalid_from_address_format_python(self):
        # Sender signs validly; the transfer's from-address is malformed.
        tx_json = self._create_tx([[INVALID_ADDR_SHORT, ADDR_A, "10"]])
        result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_INVALID")
        self.assertIn("Transaction invalid.", result["message"])

    def test_fail_invalid_to_address_format_python(self):
        tx_json = self._create_tx([[SENDER, INVALID_ADDR_NON_HEX, "10"]])
        result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_INVALID")

    def test_no_transfers_key_success(self):
        tx = {
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": chain_state.get_sequence_number(SENDER),
            "expiration_time": int(time.time()) + 1000,
            "operations": {"0": "some_other_op_data"},
            "fee_limit": "0",
        }
        tx_json = _sign_tx(tx)
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(json.loads(mempool[0]), json.loads(tx_json))

    def test_empty_transfers_list_success(self):
        tx_json = self._create_tx([])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")
        # self.assertIn("empty transfer list", result) # Doesn't necessarily return this message
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(json.loads(mempool[0]), json.loads(tx_json))

    def test_fail_non_string_rule_operation_returns_clean_failure(self):
        """Regression: a non-string at operations['0'] used to raise
        AttributeError ('list' object has no attribute 'strip') because the
        rule branch called .strip() unconditionally. It should now return a
        FAILURE message identifying the offending key.
        """
        tx = {
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": chain_state.get_sequence_number(SENDER),
            "expiration_time": int(time.time()) + 1000,
            # operations['0'] is a list — invalid; the server must not crash.
            "operations": {"0": ["always."]},
            "fee_limit": "0",
        }
        tx_json = _sign_tx(tx)
        result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"], f"expected failure, got {result!r}")
        self.assertEqual(result["code"], "TX_INVALID")
        self.assertIn("operation '0'", result["message"])
        self.assertIn("string", result["message"])
