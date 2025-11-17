

import unittest, os, sys, json, time, hashlib
from unittest.mock import Mock, patch
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
ADDR_A = bls.SkToPk(bls.KeyGen(b"basic_seed_A")).hex()
ADDR_B = bls.SkToPk(bls.KeyGen(b"basic_seed_B")).hex()

class TestSendTxBasic(unittest.TestCase):
    def setUp(self):
        # cleanup and init
        if os.path.exists("test_tau_string_db.sqlite"):
            os.remove("test_tau_string_db.sqlite")
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        chain_state._balances.clear(); chain_state._sequence_numbers.clear()
        db.init_db(); chain_state.init_chain_state()
        db.clear_mempool()  # Clear mempool for test isolation
        # patch Tau and disable signature verification/sequence enforcement for basic tests
        def mock_tau_response(rule_text, target_output_stream_index=1, input_stream_values=None):
            # Tau returns echoed amount on success, 0 on failure
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

            # Expect amount, balance, from_id, to_id
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
            return str(amount)
        self.mock_tau = patch('commands.sendtx.tau_manager.communicate_with_tau', mock_tau_response).start()
        sendtx._PY_ECC_AVAILABLE = False
        # Patch pubkey validation to bypass format checks for basic tests
        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()
        # Disable BLS signature verification for basic tests
        sendtx._PY_ECC_AVAILABLE = False

    def tearDown(self):
        patch.stopall()

    def _create_tx(self, transfers, expiration=None, sequence=None, signature="SIG", sender_pubkey=None):
        # copy helper logic verbatim from original _create_tx_json
        ops = {"1": transfers}
        exp_time = expiration if expiration is not None else int(time.time()) + 1000
        pk_hex = sender_pubkey or GENESIS
        seq = sequence if sequence is not None else chain_state.get_sequence_number(pk_hex)
        tx_dict = {
            "sender_pubkey": pk_hex,
            "sequence_number": seq,
            "expiration_time": exp_time,
            "operations": ops,
            "fee_limit": "0",
            "signature": signature,
        }
        return json.dumps(tx_dict)

    def test_successful_single_transfer(self):
        initial_genesis_balance = chain_state.get_balance(GENESIS)
        initial_addr_a_balance = chain_state.get_balance(ADDR_A)
        amount = 10
        tx_json = self._create_tx([[GENESIS, ADDR_A, str(amount)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertEqual(chain_state.get_balance(GENESIS), initial_genesis_balance - amount)
        self.assertEqual(chain_state.get_balance(ADDR_A), initial_addr_a_balance + amount)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)

    def test_successful_multiple_transfers(self):
        initial_genesis_balance = chain_state.get_balance(GENESIS)
        amount1 = 10
        amount2 = 5
        tx_list = [
            [GENESIS, ADDR_A, str(amount1)],
            [GENESIS, ADDR_B, str(amount2)]
        ]
        tx_json = self._create_tx(tx_list)
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        self.assertEqual(chain_state.get_balance(GENESIS), initial_genesis_balance - amount1 - amount2)
        self.assertEqual(chain_state.get_balance(ADDR_A), amount1)
        self.assertEqual(chain_state.get_balance(ADDR_B), amount2)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(mempool[0], "json:" + tx_json)

    def test_fail_insufficient_funds_tau(self):
        # Simulate sender has 10, tries to send 12
        chain_state._balances[GENESIS] = 10
        self.assertEqual(chain_state.get_balance(GENESIS), 10)
        amount_to_send = 12
        tx_json = self._create_tx([[GENESIS, ADDR_A, str(amount_to_send)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("FAILURE: Transaction invalid.") or result.startswith("FAILURE: Transaction rejected by Tau") or "rejected by tau logic" in result.lower())
        self.assertEqual(chain_state.get_balance(GENESIS), 10)
        self.assertEqual(chain_state.get_balance(ADDR_A), 0)
        self.assertEqual(len(db.get_mempool_txs()), 0)

    def test_queue_transaction_notifies_network_bus(self):
        tx_json = self._create_tx([[GENESIS, ADDR_A, "1"]])
        canonical = json.dumps(json.loads(tx_json), sort_keys=True, separators=(",", ":"))

        mock_service = Mock()
        with patch('commands.sendtx.network_bus.get', return_value=mock_service):
            result = sendtx.queue_transaction(tx_json)

        self.assertTrue(result.startswith("SUCCESS"))
        self.assertTrue(mock_service.broadcast_transaction.called)
        args, kwargs = mock_service.broadcast_transaction.call_args
        self.assertEqual(len(args), 2)
        payload_arg, message_id_arg = args
        self.assertEqual(payload_arg, canonical)
        self.assertIsInstance(message_id_arg, str)
        self.assertEqual(len(message_id_arg), 64)
