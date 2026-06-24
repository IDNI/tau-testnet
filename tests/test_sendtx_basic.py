

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
# Real signing key for the default sender (signatures are verified for real now).
SK_SENDER = bls.KeyGen(b"basic_sender")
SENDER = bls.SkToPk(SK_SENDER).hex()


def _sign_tx(tx_dict, sk=SK_SENDER):
    """Sign a tx dict in place with a real BLS signature and return its JSON."""
    msg_hash = hashlib.sha256(_get_signing_message_bytes(tx_dict)).digest()
    tx_dict["signature"] = bls.Sign(sk, msg_hash).hex()
    return json.dumps(tx_dict)

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
        db.init_db(); chain_state.load_genesis("data/genesis.json")
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
        # Multi-output mock wraps the same logic but returns dict[int, str]
        def mock_tau_multi(input_stream_values=None, **kwargs):
            o1_val = mock_tau_response(input_stream_values=input_stream_values, target_output_stream_index=1)
            return {1: o1_val}
        patch('tau_manager.communicate_with_tau_multi', side_effect=mock_tau_multi).start()
        # Signatures are verified for real; fund the signing sender.
        chain_state._balances[SENDER] = 1000
        # Patch pubkey validation to bypass format checks for basic tests
        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()

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

    def _create_tx(self, transfers, expiration=None, sequence=None, sender_pubkey=None):
        ops = {"1": transfers}
        exp_time = expiration if expiration is not None else int(time.time()) + 1000
        pk_hex = sender_pubkey or SENDER
        seq = sequence if sequence is not None else chain_state.get_sequence_number(pk_hex)
        tx_dict = {
            "tx_type": "user_tx",
            "sender_pubkey": pk_hex,
            "sequence_number": seq,
            "expiration_time": exp_time,
            "operations": ops,
            "fee_limit": "0",
        }
        return _sign_tx(tx_dict)

    def test_successful_single_transfer(self):
        amount = 10
        tx_json = self._create_tx([[SENDER, ADDR_A, str(amount)]])
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")
        self.assertIn("tx_hash", result)
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(json.loads(mempool[0]), json.loads(tx_json))

    def test_successful_multiple_transfers(self):
        amount1 = 10
        amount2 = 5
        tx_list = [
            [SENDER, ADDR_A, str(amount1)],
            [SENDER, ADDR_B, str(amount2)]
        ]
        tx_json = self._create_tx(tx_list)
        result = sendtx.queue_transaction(tx_json)
        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")
        mempool = db.get_mempool_txs()
        self.assertEqual(len(mempool), 1)
        self.assertEqual(json.loads(mempool[0]), json.loads(tx_json))

    def test_queue_transaction_notifies_network_bus(self):
        tx_json = self._create_tx([[SENDER, ADDR_A, "1"]])
        canonical = json.dumps(json.loads(tx_json), sort_keys=True, separators=(",", ":"))

        mock_service = Mock()
        with patch('commands.sendtx.network_bus.get', return_value=mock_service):
            result = sendtx.queue_transaction(tx_json)

        self.assertTrue(result["ok"])
        self.assertTrue(mock_service.broadcast_transaction.called)
        args, kwargs = mock_service.broadcast_transaction.call_args
        self.assertEqual(len(args), 2)
        payload_arg, message_id_arg = args
        self.assertEqual(payload_arg, canonical)
        self.assertIsInstance(message_id_arg, str)
        self.assertEqual(len(message_id_arg), 64)

    def test_mempool_full_rejected(self):
        original_limit = config.MAX_MEMPOOL_TXS
        config.MAX_MEMPOOL_TXS = 2
        try:
            # Real signatures are enforced; sequences must be consecutive from 0
            # (pending-aware), and the signing SENDER is funded in setUp.
            tx1 = self._create_tx([[SENDER, ADDR_A, "10"]], sequence=0)
            tx2 = self._create_tx([[SENDER, ADDR_A, "10"]], sequence=1)
            tx3 = self._create_tx([[SENDER, ADDR_A, "10"]], sequence=2)

            # First two should succeed
            res1 = sendtx.queue_transaction(tx1)
            res2 = sendtx.queue_transaction(tx2)
            self.assertTrue(res1["ok"], msg=res1)
            self.assertTrue(res2["ok"], msg=res2)

            # Third should fail with MEMPOOL_FULL
            res3 = sendtx.queue_transaction(tx3)
            self.assertFalse(res3["ok"])
            self.assertEqual(res3["code"], "MEMPOOL_FULL")
            self.assertIn("Mempool is full", res3["message"])
        finally:
            config.MAX_MEMPOOL_TXS = original_limit
