"""Bounty 01, FIX 5 (due_retry): a signed retry term in clause form, on
the native engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the proof steps a REAL Tau clause through the real
policy-evaluation path, which needs the native bindings the mock job
does not have. The skip is environment-driven, exactly as the other
Bounty 01 native suites.

The competitor's #160 commit 7722a42 adds a signed `due_retry` term:
a due point refused because the account holds less than the rule pays
is run again in each later block. FIX 5 answers it in clause form, on
the standing payment's end-of-block sweep. This file proves, with the
real evaluator (no mock anywhere in this file):

1. A short due point is discovered and owed: the payer holds 300
   against a clause that pays its 500 cap in full, so an executor's
   transaction is refused at admission — and even force-queued and
   mined, it settles nothing. The block's own sweep then owes the
   retry, with the real clause's legs as the evidence.
2. The retry settles in a later block once funded: a real transfer
   lands 300 on the payer, and the same block's sweep runs the retry
   and pays exactly 500 — the payer's balance after is 300 + 300 -
   500, with no fee on the retry itself.
3. Discovery never settles a payable due point: a funded payer's due
   point is left alone by the sweep — settling un-attempted due
   points is the node sweep's job (FIX 3, awaiting the o5 decision),
   not the retry's.
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    import tau_native
    tau_native.load_tau_module()
    _NATIVE_TAU = True
except Exception:
    _NATIVE_TAU = False

import config
import chain_state
import db
import tau_manager
from errors import TauEngineCrash
from bls_keys import (
    SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_payload,
)
from commands import sendtx, createblock
from consensus.standing_payments import (
    FORM_TAU_CLAUSE,
    SCHEDULE_DAILY,
    StandingPaymentEntry,
)

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

PAYER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
EXTRA = pubkey_hex(SK_MALLORY)

DAY = 86_400
AMOUNT = 500
RETRY_WEEK = 7 * DAY

PAY_FULL_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = i1[t]:bv[64]))"
)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestStandingDueRetryNative(unittest.TestCase):
    """Full pipeline with a live Tau interpreter (the fee-native pattern)."""

    def setUp(self):
        try:
            iface = tau_native.TauInterface(GENESIS_TAU)
        except TauEngineCrash:
            self.skipTest(
                "native interpreter unavailable in this process (polluted by an "
                "earlier in-process interpreter); run this file on its own"
            )
        self._tmpdir = tempfile.mkdtemp()
        self.test_db = os.path.join(self._tmpdir, "test_due_retry_native_db.sqlite")
        self.original_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if not config.MINER_PRIVKEY:
            _priv = config._load_miner_privkey_from_path(
                os.path.join(config.DATA_LOCAL_DIR, "test_miner.key"))
            _pub = config._load_miner_pubkey_from_path(
                os.path.join(config.DATA_LOCAL_DIR, "test_miner.pub"))
            if not _priv or not _pub:
                self.skipTest(
                    "data_local/test_miner.key absent; local miner identity required "
                    "for real PoA mining (see config.DATA_LOCAL_DIR)"
                )
            config.MINER_PRIVKEY = _priv
            config.MINER_PUBKEY = _pub
        if db._db_conn:
            db._db_conn.close()
        db._db_conn = None

        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()

        chain_state._balances[PAYER] = 100000
        chain_state._balances[RECIPIENT] = 1000
        chain_state._balances[EXECUTOR] = 1000
        chain_state._balances[EXTRA] = 1000
        chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
        chain_state._lifecycle_manager.recompute_approval_threshold()

        tau_manager.tau_direct_interface = iface
        tau_manager.tau_ready.set()
        self._seed_rule(open(TRANSFER_RULE_PATH).read(), "transfer-rule")
        self._seed_rule(
            chain_state._preprocess_tau_spec_text(
                json.load(open("data/genesis.json"))["consensus_rules"]
            ),
            "genesis-consensus",
        )
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
        patch("commands.createblock._BLS_AVAILABLE", True).start()
        patch("block.bls_signing_available", return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.verify_block_header", return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.query_eligibility", return_value=True).start()

    def tearDown(self):
        patch.stopall()
        tau_manager.tau_ready.clear()
        tau_manager.tau_direct_interface = None
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        config.set_database_path(self.original_db)

    def _seed_rule(self, rule_text, label):
        out = tau_manager.communicate_with_tau(
            rule_text=rule_text,
            target_output_stream_index=0,
            apply_rules_update=False,
            source=f"seed-{label}",
        )
        self.assertNotIn("error", str(out).lower(), f"seeding {label} failed: {out}")

    def _mine(self):
        out = createblock.create_block_from_mempool()
        self.assertNotIn("error", out, out)
        return out

    def _force_queue(self, blob):
        payload = json.loads(blob)
        tx_hash, raw = sendtx._compute_transaction_message_id(payload)
        db.add_mempool_tx(raw, tx_hash, int(time.time() * 1000))
        return tx_hash

    def _included(self, tx_hash):
        head = db.get_canonical_head_block() or {}
        return tx_hash in (head.get("tx_ids") or [])

    def _balances(self, *pks):
        return {pk: chain_state._balances.get(pk, 0) for pk in pks}

    def _book(self):
        return chain_state._lifecycle_manager.standing_payments

    def _install_retry_auth(self, payer_balance):
        """A daily clause-form authorization, period 0 already due, the
        payer holding `payer_balance` against a 500 period."""
        now = int(time.time())
        chain_state._balances[PAYER] = payer_balance
        entry = StandingPaymentEntry(
            PAYER, RECIPIENT, AMOUNT, SCHEDULE_DAILY, 0, now - 100,
            3600, 0, 1, 0, 0, 0, False, 1,
            form=FORM_TAU_CLAUSE, clause_text=PAY_FULL_CLAUSE,
            due_retry_seconds=RETRY_WEEK,
        )
        self._book().create(entry, now)
        return entry

    def _execute_tx(self, auth_id):
        return json.dumps(sign_payload({
            "sender_pubkey": EXECUTOR,
            "tx_type": "execute_standing_payment",
            "sequence_number": chain_state.get_sequence_number(EXECUTOR),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "standing_auth_id": auth_id.hex(),
            "fee_limit": "50",
        }, SK_CAROL))

    def _transfer(self, sender_pk, sender_sk, to, amount):
        return json.dumps(sign_payload({
            "sender_pubkey": sender_pk,
            "sequence_number": chain_state.get_sequence_number(sender_pk),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[sender_pk, to, str(amount)]]},
            "fee_limit": "50",
        }, sender_sk))

    # (1) a short due point is discovered and owed ----------------------------

    def test_short_due_point_discovered_then_settled_by_the_retry(self):
        entry = self._install_retry_auth(payer_balance=300)
        blob = self._execute_tx(entry.auth_id)
        before = self._balances(PAYER, RECIPIENT)
        res = sendtx.queue_transaction(blob, propagate=False)
        self.assertFalse(res["ok"], f"short execution admitted: {res}")
        # Force it in anyway, beside a real transfer so the block is
        # non-empty and the sweep runs: the execution still settles
        # nothing, and the sweep owes the retry on the real clause.
        forced = self._force_queue(blob)
        transfer = self._transfer(EXECUTOR, SK_CAROL, RECIPIENT, 10)
        res = sendtx.queue_transaction(transfer, propagate=False)
        self.assertTrue(res["ok"], f"transfer rejected: {res}")
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion settled a short due point")
        after = self._balances(PAYER, RECIPIENT)
        self.assertEqual(after[PAYER], before[PAYER])
        self.assertEqual(after[RECIPIENT], before[RECIPIENT] + 10)
        owed = self._book().owed_retries()
        self.assertEqual(len(owed), 1)
        self.assertEqual(owed[0].auth_id, entry.auth_id)
        self.assertEqual(owed[0].period_index, 0)
        self.assertEqual(self._book().total_executed(entry.auth_id), (0, 0))

        # A real transfer lands 300 on the payer; the same block's
        # sweep runs the retry and pays exactly 500, fee-free.
        fund = self._transfer(EXTRA, SK_MALLORY, PAYER, 300)
        res = sendtx.queue_transaction(fund, propagate=False)
        self.assertTrue(res["ok"], f"funding transfer rejected: {res}")
        self._mine()
        after = self._balances(PAYER, RECIPIENT)
        self.assertEqual(after[PAYER], 300 + 300 - AMOUNT)
        self.assertEqual(after[RECIPIENT], before[RECIPIENT] + 10 + AMOUNT)
        self.assertEqual(self._book().owed_retries(), [])
        self.assertEqual(self._book().total_executed(entry.auth_id), (1, AMOUNT))

    # (3) discovery never settles a payable due point --------------------------

    def test_payable_due_point_is_left_alone_by_the_sweep(self):
        entry = self._install_retry_auth(payer_balance=100000)
        transfer = self._transfer(EXECUTOR, SK_CAROL, RECIPIENT, 10)
        res = sendtx.queue_transaction(transfer, propagate=False)
        self.assertTrue(res["ok"], f"transfer rejected: {res}")
        before = self._balances(PAYER, RECIPIENT)
        self._mine()
        after = self._balances(PAYER, RECIPIENT)
        self.assertEqual(after[PAYER], before[PAYER])
        self.assertEqual(after[RECIPIENT], before[RECIPIENT] + 10)
        self.assertEqual(self._book().owed_retries(), [])
        self.assertEqual(self._book().total_executed(entry.auth_id), (0, 0))
