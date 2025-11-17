

import unittest, os, sys, json, time, hashlib
from unittest.mock import patch
from py_ecc.bls import G2Basic as bls

# Add project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
os.environ["TAU_DB_PATH"] = "test_tau_string_db.sqlite"

from commands import sendtx
import chain_state, db, tau_defs, utils
from commands.sendtx import _get_signing_message_bytes

GENESIS = chain_state.GENESIS_ADDRESS
# Use stub BLS keys for test addresses
ADDR_A = bls.SkToPk(bls.KeyGen(b"validation_seed_A")).hex()
ADDR_B = bls.SkToPk(bls.KeyGen(b"validation_seed_B")).hex()
INVALID_ADDR_SHORT = "short"
INVALID_ADDR_NON_HEX = "000...g"

class TestSendTxValidation(unittest.TestCase):
    def setUp(self):
        if os.path.exists("test_tau_string_db.sqlite"):
            os.remove("test_tau_string_db.sqlite")
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        chain_state._balances.clear(); chain_state._sequence_numbers.clear()
        db.init_db(); chain_state.init_chain_state()
        db.clear_mempool()  # Clear mempool for test isolation
        def mock_tau_response(rule_text, target_output_stream_index=1, input_stream_values=None):
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
        sendtx._PY_ECC_AVAILABLE = False
        # Patch pubkey validation to bypass format checks for basic validation tests
        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()

    def tearDown(self):
        patch.stopall()

    def _create_tx(self, transfers, signature="SIG", sender_pubkey=None):
        ops = {"1": transfers}
        pk_hex = sender_pubkey or GENESIS
        tx_dict = {
            "sender_pubkey": pk_hex,
            "sequence_number": chain_state.get_sequence_number(pk_hex),
            "expiration_time": int(time.time()) + 1000,
            "operations": ops,
            "fee_limit": "0",
            "signature": signature,
        }
        return json.dumps(tx_dict)

    def test_fail_amount_too_large_python(self):
        chain_state._balances[GENESIS] = 10
        amount_to_send = 16
        tx_json = self._create_tx([[GENESIS, ADDR_A, str(amount_to_send)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE:"))
        self.assertEqual(chain_state.get_balance(GENESIS), 10)
        self.assertEqual(len(db.get_mempool_txs()), 0)

    def test_fail_invalid_from_address_format_python(self):
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
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."))

    def test_fail_invalid_to_address_format_python(self):
        tx_json = self._create_tx([[GENESIS, INVALID_ADDR_NON_HEX, "10"]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid."))

    def test_no_transfers_key_success(self):
        tx = {
            "sender_pubkey": GENESIS,
            "sequence_number": chain_state.get_sequence_number(GENESIS),
            "expiration_time": int(time.time()) + 1000,
            "operations": {"0": "some_other_op_data"},
            "fee_limit": "0",
            "signature": "SIG"
        }
        tx_json = json.dumps(tx)
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)

    def test_empty_transfers_list_success(self):
        tx_json = self._create_tx([])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertIn("empty transfer list", result)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)
