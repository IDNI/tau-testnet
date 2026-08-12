"""checktx: read-only admission dry-run (issue #26).

The command's value is that its verdict is byte-identical to what sendtx would
have returned, so most of these assert parity rather than specific codes. The
rest assert the two purity invariants: nothing enters the mempool, and nothing
is broadcast.
"""
from __future__ import annotations

import hashlib as _hashlib
import importlib
import json
import os
import sys
import time
import unittest
from unittest.mock import patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import chain_state
import config
import db
import tau_defs
from commands import checktx, sendtx

from py_ecc.bls import G2Basic as _bls

SK_SENDER = _bls.KeyGen(b"checktx_sender")
SENDER = _bls.SkToPk(SK_SENDER).hex()
RECIPIENT = "c" * 96


def _mock_tau_multi_ok(*args, **kwargs):
    return {1: tau_defs.TAU_VALUE_ONE}


class TestChecktx(unittest.TestCase):
    def setUp(self):
        importlib.reload(sendtx)
        self.test_db = "test_checktx.sqlite"
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
        patch("commands.sendtx.tau_manager.communicate_with_tau_multi", _mock_tau_multi_ok).start()
        chain_state._balances[SENDER] = 1000

    def tearDown(self):
        patch.stopall()
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        config.set_database_path(self.old_db)

    def _tx(self, **overrides):
        tx = {
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": chain_state.get_sequence_number(SENDER),
            "expiration_time": int(time.time()) + 1000,
            "operations": {"1": [[SENDER, RECIPIENT, "100"]]},
            "fee_limit": "50",
        }
        explicit_sig = "signature" in overrides
        tx.update(overrides)
        if not explicit_sig:
            msg = sendtx._get_signing_message_bytes(tx)
            tx["signature"] = _bls.Sign(SK_SENDER, _hashlib.sha256(msg).digest()).hex()
        return tx

    def _check(self, tx):
        return json.loads(checktx.execute(f"checktx {json.dumps(tx)}", None))

    # --- purity ----------------------------------------------------------
    def test_valid_tx_is_admissible_and_never_enters_the_mempool(self):
        before = db.count_mempool_txs()
        env = self._check(self._tx())
        self.assertEqual(env["status"], "ok", msg=env)
        self.assertTrue(env["data"]["admissible"])
        self.assertEqual(len(env["data"]["tx_hash"]), 64)
        self.assertEqual(db.count_mempool_txs(), before)

    def test_repeated_checks_never_accumulate_state(self):
        for _ in range(25):
            self._check(self._tx())
        self.assertEqual(db.count_mempool_txs(), 0)

    def test_nothing_is_broadcast(self):
        with patch("network.bus.get") as bus_get:
            self._check(self._tx())
            bus_get.assert_not_called()

    def test_balance_and_sequence_are_untouched(self):
        seq_before = chain_state.get_sequence_number(SENDER)
        bal_before = chain_state.get_balance(SENDER)
        self._check(self._tx())
        self.assertEqual(chain_state.get_sequence_number(SENDER), seq_before)
        self.assertEqual(chain_state.get_balance(SENDER), bal_before)

    def test_tau_evaluation_is_reported_as_not_performed(self):
        """Never claim a policy verdict that was not computed."""
        env = self._check(self._tx())
        self.assertFalse(env["data"]["tau_evaluated"])
        self.assertIn("tau_eval", env["data"]["checks_skipped"])

    def test_no_estimated_fee_is_offered(self):
        """Emitting "0" while the fee streams were never evaluated would hand a
        wallet a number it would use as a fee_limit and then have rejected."""
        env = self._check(self._tx())
        self.assertNotIn("estimated_fee", env["data"])

    # --- verdict parity with sendtx --------------------------------------
    def _codes_for(self, tx):
        """Same payload through both paths; returns (checktx_code, sendtx_code)."""
        check_env = self._check(tx)
        check_code = check_env.get("error", {}).get("code") if check_env["status"] == "error" else None
        send = sendtx.queue_transaction(json.dumps(tx), propagate=False)
        send_code = None if send.get("ok") else send.get("code")
        return check_code, send_code

    def test_parity_bad_json(self):
        env = json.loads(checktx.execute("checktx {not json", None))
        self.assertEqual(env["error"]["code"], "PARSE_ERROR")

    def test_parity_missing_usage(self):
        env = json.loads(checktx.execute("checktx", None))
        self.assertEqual(env["error"]["code"], "INVALID_PARAMS")

    def test_parity_invalid_signature(self):
        c, s = self._codes_for(self._tx(signature="00" * 96))
        self.assertEqual(c, "INVALID_SIGNATURE")
        self.assertEqual(c, s)

    def test_parity_bad_sequence(self):
        c, s = self._codes_for(self._tx(sequence_number=999))
        self.assertEqual(c, "INVALID_SEQUENCE")
        self.assertEqual(c, s)

    def test_parity_expired(self):
        c, s = self._codes_for(self._tx(expiration_time=int(time.time()) - 1))
        self.assertEqual(c, "TX_EXPIRED")
        self.assertEqual(c, s)

    def test_parity_reserved_operation_key(self):
        # Reserved consensus-ABI stream. Whichever screen fires first, both paths
        # must agree — that agreement is the contract, not the specific code.
        c, s = self._codes_for(self._tx(operations={"1": [], "6": "x"}))
        self.assertIsNotNone(c, "reserved stream was admitted")
        self.assertEqual(c, s)

    def test_parity_unscoped_policy_rule(self):
        """The #24 sender-scope screen reaches checktx too, so a wallet learns
        before signing rather than at submit."""
        tx = self._tx(operations={"0": "always (o5[t]:bv[24] = { #x000000 }:bv[24])."})
        c, s = self._codes_for(tx)
        self.assertEqual(c, "UNSCOPED_USER_RULE")
        self.assertEqual(c, s)

    def test_parity_insufficient_funds(self):
        chain_state._balances[SENDER] = 5
        c, s = self._codes_for(self._tx())
        self.assertEqual(c, "INSUFFICIENT_FUNDS")
        self.assertEqual(c, s)

    def test_rejection_details_say_tau_was_not_evaluated(self):
        env = self._check(self._tx(sequence_number=999))
        self.assertFalse(env["error"]["details"]["tau_evaluated"])

    def test_mempool_full_is_never_reported(self):
        """A capacity fact about the node, not a verdict about this tx."""
        old = config.MAX_MEMPOOL_TXS
        config.MAX_MEMPOOL_TXS = 0
        try:
            env = self._check(self._tx())
            self.assertEqual(env["status"], "ok", msg=env)
        finally:
            config.MAX_MEMPOOL_TXS = old

    def test_registered_in_the_dispatcher(self):
        from app.container import ServiceContainer
        import inspect
        src = inspect.getsource(ServiceContainer.build)
        self.assertIn('"checktx"', src)


if __name__ == "__main__":
    unittest.main()
