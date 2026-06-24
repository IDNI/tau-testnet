

import unittest, os, sys, json, time, hashlib, importlib
from unittest.mock import patch
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
ADDR_A = bls.SkToPk(bls.KeyGen(b"meta_seed_A")).hex()
ADDR_B = bls.SkToPk(bls.KeyGen(b"meta_seed_B")).hex()
# Real signing key for the default sender (signatures are verified for real now).
SK_SENDER = bls.KeyGen(b"meta_sender")
SENDER = bls.SkToPk(SK_SENDER).hex()

class TestSendTxTxMeta(unittest.TestCase):
    def setUp(self):
        importlib.reload(sendtx)
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
        chain_state._balances.clear(); chain_state._sequence_numbers.clear()
        db.init_db(); chain_state.load_genesis("data/genesis.json")
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
        # Multi-output mock wraps the same logic but returns dict[int, str]
        def mock_tau_multi(input_stream_values=None, **kwargs):
            o1_val = mock_tau_response(input_stream_values=input_stream_values, target_output_stream_index=1)
            return {1: o1_val}
        patch('commands.sendtx.tau_manager.communicate_with_tau_multi', side_effect=mock_tau_multi).start()
        # Signatures are verified for real; fund the signing sender.
        chain_state._balances[SENDER] = 1000
        # Patch pubkey validation to bypass format checks for meta tests
        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()

    def tearDown(self):
        patch.stopall()
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        config.set_database_path(self.original_db_path)

    def _create_tx(self, transfers, expiration=None, sequence=None, signature=None, sender_pubkey=None):
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
        if signature is not None:
            tx_dict["signature"] = signature
        else:
            msg_hash = hashlib.sha256(_get_signing_message_bytes(tx_dict)).digest()
            tx_dict["signature"] = bls.Sign(SK_SENDER, msg_hash).hex()
        return json.dumps(tx_dict)

    def test_expired_transaction(self):
        expired_time = int(time.time()) - 10
        tx_json = self._create_tx([[GENESIS, ADDR_A, "1"]], expiration=expired_time)
        result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_EXPIRED")
        self.assertEqual(result["details"]["expires_at"], expired_time)
        self.assertEqual(len(db.get_mempool_txs()), 0)

    def test_from_address_mismatch(self):
        invalid_transfer = [ADDR_B, ADDR_A, "1"]
        tx_json = self._create_tx([invalid_transfer])
        result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"])
        self.assertIn("does not match sender_pubkey", result["message"])
        self.assertEqual(len(db.get_mempool_txs()), 0)

    def test_missing_sequence_number(self):
        tx = {
            "sender_pubkey": GENESIS,
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS, ADDR_A, "1"]]},
            "fee_limit": "0",
            "signature": "SIG"
        }
        tx_json = json.dumps(tx)
        result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_PARAMS")
        self.assertIn("sequence_number", result["message"])

    def test_missing_signature(self):
        tx = {
            "sender_pubkey": GENESIS,
            "sequence_number": chain_state.get_sequence_number(GENESIS),
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[GENESIS, ADDR_A, "1"]]},
            "fee_limit": "0"
        }
        tx_json = json.dumps(tx)
        result = sendtx.queue_transaction(tx_json)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_PARAMS")
        self.assertIn("signature", result["message"])
