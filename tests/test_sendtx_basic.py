

import unittest, os, sys, json, time, hashlib, importlib
from unittest.mock import Mock, patch
from py_ecc.bls import G2Basic as bls

# Add project root
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
from commands import sendtx
import chain_state, db, tau_defs, utils
from commands.sendtx import _get_signing_message_bytes

GENESIS = chain_state.GENESIS_ADDRESS
# Use stub BLS keys for test addresses
ADDR_A = bls.SkToPk(bls.KeyGen(b"basic_seed_A")).hex()
ADDR_B = bls.SkToPk(bls.KeyGen(b"basic_seed_B")).hex()

class TestSendTxBasic(unittest.TestCase):
    def setUp(self):
        importlib.reload(sendtx)
        # cleanup and init
        self.test_db = "test_tau_string_db.sqlite"
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
            
        chain_state._balances.clear(); chain_state._sequence_numbers.clear()
        db.init_db(); chain_state.init_chain_state()
        db.clear_mempool()  # Clear mempool for test isolation
        # patch Tau and disable signature verification/sequence enforcement for basic tests
        def mock_tau_response(rule_text=None, target_output_stream_index=1, input_stream_values=None, **kwargs):
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
            
        self.mock_tau = patch('tau_manager.communicate_with_tau', side_effect=mock_tau_response).start()
        sendtx._PY_ECC_AVAILABLE = False
        # Patch pubkey validation to bypass format checks for basic tests
        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()
        # Disable BLS signature verification for basic tests
        sendtx._PY_ECC_AVAILABLE = False

    def tearDown(self):
        patch.stopall()
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        config.set_database_path(self.original_db_path)
        
        # Reset globals that might affect other tests
        if hasattr(sendtx, '_PY_ECC_AVAILABLE'):
            # Re-detect or set to default
            try:
                import py_ecc.bls
                sendtx._PY_ECC_AVAILABLE = True
                sendtx._PY_ECC_BLS = py_ecc.bls
            except ImportError:
                sendtx._PY_ECC_AVAILABLE = False
                sendtx._PY_ECC_BLS = None

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
        amount = 10
        tx_json = self._create_tx([[GENESIS, ADDR_A, str(amount)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(json.loads(mempool[0]), json.loads(tx_json))

    def test_successful_multiple_transfers(self):
        amount1 = 10
        amount2 = 5
        tx_list = [
            [GENESIS, ADDR_A, str(amount1)],
            [GENESIS, ADDR_B, str(amount2)]
        ]
        tx_json = self._create_tx(tx_list)
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result.startswith("SUCCESS: Transaction queued"))
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(json.loads(mempool[0]), json.loads(tx_json))

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
