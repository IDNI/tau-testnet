

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
        self.mock_tau = patch('commands.sendtx.tau_manager.communicate_with_tau',
                              lambda full: full.split(':=', 1)[1].strip() if ':=' in full else full).start()
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

    def test_fail_amount_too_large_for_sbf_python(self):
        amount_to_send = 16
        tx_json = self._create_tx([[GENESIS, ADDR_A, str(amount_to_send)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("ERROR: Could not process transfer #1"))
        self.assertIn("Invalid amount '16': Must be a number between 0 and 15", result)
        self.assertEqual(chain_state.get_balance(GENESIS), chain_state.GENESIS_BALANCE)
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
        self.assertTrue(result.startswith("ERROR: Could not process transfer #1"))
        self.assertIn("Invalid 'from' address: Must be a 96-character hex BLS12-381 public key", result)

    def test_fail_invalid_to_address_format_python(self):
        tx_json = self._create_tx([[GENESIS, INVALID_ADDR_NON_HEX, "10"]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("ERROR: Could not process transfer #1"))
        self.assertIn("Invalid 'to' address: Must be a 96-character hex BLS12-381 public key", result)

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
        self.assertIn("no transfers to validate", result)
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