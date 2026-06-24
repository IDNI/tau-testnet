"""Maps every queue_transaction() / sendtx.execute() return path to its
expected envelope code. Locks in the schema documented in
api_response.py + commands/sendtx.py."""

from __future__ import annotations

import json
import os
import sys
import time
import unittest
from unittest.mock import patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import importlib

import config
import db
import chain_state
import tau_defs
from commands import sendtx


GENESIS = chain_state.GENESIS_ADDRESS

# Real signing key for the default sender (signatures are verified for real now).
from py_ecc.bls import G2Basic as _bls
import hashlib as _hashlib
SK_SENDER = _bls.KeyGen(b"mapping_sender")
SENDER = _bls.SkToPk(SK_SENDER).hex()


def _mock_tau_ok(*args, **kwargs):
    target = kwargs.get("target_output_stream_index", 1)
    if target == 0:
        return tau_defs.ACK_RULE_PROCESSED
    return tau_defs.TAU_VALUE_ONE


def _mock_tau_multi_ok(*args, **kwargs):
    return {1: tau_defs.TAU_VALUE_ONE}


class TestSendTxMapping(unittest.TestCase):
    def setUp(self):
        importlib.reload(sendtx)
        self.test_db = "test_tau_mapping.sqlite"
        self.old_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()
        patch("commands.sendtx._validate_bls12_381_pubkey", return_value=(True, None)).start()
        patch("commands.sendtx.tau_manager.communicate_with_tau", _mock_tau_ok).start()
        patch("commands.sendtx.tau_manager.communicate_with_tau_multi", _mock_tau_multi_ok).start()
        # Signatures are verified for real; fund the signing sender.
        chain_state._balances[SENDER] = 1000

    def tearDown(self):
        patch.stopall()
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        config.set_database_path(self.old_db)

    def _base_tx(self, **overrides):
        tx = {
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": chain_state.get_sequence_number(SENDER),
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": []},
            "fee_limit": "0",
        }
        explicit_signature = "signature" in overrides
        tx.update(overrides)
        if not explicit_signature:
            msg = sendtx._get_signing_message_bytes(tx)
            tx["signature"] = _bls.Sign(SK_SENDER, _hashlib.sha256(msg).digest()).hex()
        return tx

    # 1. Success
    def test_success_returns_ok_with_tx_hash(self):
        result = sendtx.queue_transaction(json.dumps(self._base_tx()))
        self.assertTrue(result["ok"], msg=str(result))
        self.assertEqual(len(result["tx_hash"]), 64)

    # 2. Invalid signature
    def test_invalid_signature(self):
        from py_ecc.bls import G2Basic as bls
        sk = bls.KeyGen(b"mapping_seed_2")
        pk_hex = bls.SkToPk(sk).hex()
        tx = self._base_tx(sender_pubkey=pk_hex, signature="00" * 96)
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(json.dumps(tx))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_SIGNATURE")

    # 3. Invalid sequence
    def test_invalid_sequence(self):
        from py_ecc.bls import G2Basic as bls
        import hashlib
        sk = bls.KeyGen(b"mapping_seed_3")
        pk_hex = bls.SkToPk(sk).hex()
        seq = chain_state.get_sequence_number(pk_hex)
        tx = self._base_tx(sender_pubkey=pk_hex, sequence_number=seq + 5)
        msg = sendtx._get_signing_message_bytes(tx)
        tx["signature"] = bls.Sign(sk, hashlib.sha256(msg).digest()).hex()
        sendtx._PY_ECC_AVAILABLE = True
        sendtx._PY_ECC_BLS = bls
        result = sendtx.queue_transaction(json.dumps(tx))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_SEQUENCE")
        self.assertEqual(result["details"]["expected"], seq)
        self.assertEqual(result["details"]["received"], seq + 5)

    # 4. Expired
    def test_expired(self):
        expired = int(time.time()) - 1
        tx = self._base_tx(expiration_time=expired)
        result = sendtx.queue_transaction(json.dumps(tx))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_EXPIRED")
        self.assertEqual(result["details"]["expires_at"], expired)

    # 5. Tau rejection (rule validation)
    def test_tau_rejection(self):
        def reject(*args, **kwargs):
            return "Error: rejected"
        patch("commands.sendtx.tau_manager.communicate_with_tau", reject).start()
        tx = self._base_tx(operations={"0": "broken_rule."})
        with patch.dict(os.environ, {"TAU_FORCE_TEST": "0"}):
            result = sendtx.queue_transaction(json.dumps(tx))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_REJECTED")

    # 6. Structural (TX_INVALID)
    def test_structural_invalid_rule_type(self):
        tx = self._base_tx(operations={"0": ["not_a_string"]})
        result = sendtx.queue_transaction(json.dumps(tx))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_INVALID")
        self.assertIn("operation '0'", result["message"])

    # 7. Invalid sendtx format at execute() level
    def test_execute_invalid_prefix(self):
        env = sendtx.execute("notsendtx foo", None)
        parsed = json.loads(env)
        self.assertEqual(parsed["status"], "error")
        self.assertEqual(parsed["error"]["code"], "INVALID_PARAMS")

    # 8. JSON-decode failure
    def test_parse_error(self):
        result = sendtx.queue_transaction("not-json")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "PARSE_ERROR")

    # 9. BLS unavailable
    def test_bls_unavailable(self):
        prev = sendtx._PY_ECC_AVAILABLE
        sendtx._PY_ECC_AVAILABLE = False
        try:
            env = sendtx.execute("sendtx {}", None)
            parsed = json.loads(env)
            self.assertEqual(parsed["status"], "error")
            self.assertEqual(parsed["error"]["code"], "BLS_UNAVAILABLE")
        finally:
            sendtx._PY_ECC_AVAILABLE = prev

    # 10. Unexpected exception in queue_transaction (caught by outer try)
    def test_internal_error_on_unexpected_exception(self):
        def boom(*args, **kwargs):
            raise RuntimeError("synthetic boom")
        patch("commands.sendtx.tau_manager.communicate_with_tau", boom).start()
        tx = self._base_tx(operations={"0": "some_rule."})
        # Disable TAU_FORCE_TEST so the patched call is actually exercised.
        with patch.dict(os.environ, {"TAU_FORCE_TEST": "0"}):
            result = sendtx.queue_transaction(json.dumps(tx))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INTERNAL_ERROR")


if __name__ == "__main__":
    unittest.main()
