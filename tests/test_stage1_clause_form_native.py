"""Bounty 01, stage 1 (FIX 2): standing payments + receive routes in
Tau clause form, on the native engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the proof steps REAL Tau clauses through the real
policy-evaluation path, which needs the native bindings the mock job
does not have. The skip is environment-driven, exactly as the other
Bounty 01 native suites. The byte-for-byte goldens live in a class
WITHOUT the native skip: they pin the declared forms' consensus
values in every job.

The scenarios (the FIX 2 proof list):

1. A monthly day-31 standing payment as a clause. The calendar pins
   are unconditional: anchored 2026-01-31, period 1 falls due
   2026-02-28 (clamped) and period 2 on 2026-03-31 (returned) — the
   book's own due_ts, computed here against the real calendar. The
   settlement half anchors the executed authorization at the latest
   month-end at or before the run's wall clock, with a 28-day window:
   on the ~96% of days when that window is live, a third party's
   execution settles exactly the signed 500 (the clause pays its i1
   cap in full) and a second execution is refused at admission —
   at most once per period. On the remaining days the window has
   lapsed by construction, and the test pins exactly that instead:
   admission refuses, and the book's next due date is the coming
   month-end. Which branch ran is a fact about the calendar, stated
   here rather than hidden.
2. A receive route as a clause: a 101 credit splits 81/20 under the
   clause's own fifth-of-gross arithmetic, and the routed 20 does NOT
   re-trigger the destination's own clause route (single-hop), while
   a direct credit to the destination splits under its route as the
   control.
3. The byte-for-byte pin (goldens below, measured on the base tree
   before the clause form existed): a declared entry's id, record
   bytes and book root are exactly what the pre-clause code computed.
4. The G4 pins, ported to stage 1: a clause leg naming a candidate
   outside the set, or an amount above the cap, settles zero — at
   admission AND at inclusion with admission bypassed (standing);
   for routes the same legs leave the credit whole and the transfer
   accepted (a route is an optimization on a credit, never a gate).
"""
import calendar
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
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
from consensus.receive_routes import (
    FORM_TAU_CLAUSE as ROUTE_FORM_TAU_CLAUSE,
    ReceiveRouteEntry,
)
from consensus.serialization import (
    encode_receive_route_entry,
    encode_standing_payment_record,
)
from consensus.standing_payments import (
    FORM_TAU_CLAUSE,
    SCHEDULE_DAILY,
    SCHEDULE_MONTHLY,
    StandingPaymentBook,
    StandingPaymentEntry,
    due_ts,
)
from consensus.receive_routes import ReceiveRouteBook

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

PAYER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
EXTRA = pubkey_hex(SK_MALLORY)

DAY = 86_400
AMOUNT = 500

PAY_FULL_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = i1[t]:bv[64]))"
)
FIFTH_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = (i1[t]:bv[64] / { 5 }:bv[64])))"
)
HALF_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = (i1[t]:bv[64] / { 2 }:bv[64])))"
)
OUT_OF_SET_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 10 }:bv[64]))"
)
OVER_CAP_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 600 }:bv[64]))"
)
ROUTE_OVER_CAP_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 95 }:bv[64]))"
)


def _ts(year, month, day):
    return calendar.timegm((year, month, day, 0, 0, 0, 0, 0, 0))


def _latest_month_end(now):
    """The most recent month-end day (00:00 UTC) at or before `now`:
    the first of this month minus one day, unless today IS a
    month-end, in which case today."""
    dt = datetime.fromtimestamp(now, tz=timezone.utc)
    first = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if dt.day == calendar.monthrange(dt.year, dt.month)[1]:
        return int(dt.replace(
            hour=0, minute=0, second=0, microsecond=0).timestamp())
    return int(first.timestamp()) - DAY


# --- (3) the byte-for-byte pin, in every job --------------------------------------

_G_PAYER = "aa" * 48
_G_RECIPIENT = "bb" * 48
_G_DEST = "cc" * 48
_G_ANCHOR = 1_769_817_600  # 2026-01-31 00:00 UTC


def _u64(value):
    return int(value).to_bytes(8, "big").hex()


class TestStage1DeclaredGoldens(unittest.TestCase):
    """Goldens measured on the base tree (18410d7b) BEFORE the clause
    form existed. If the clause form's arrival moved any declared
    value, these fail — that is the pin."""

    def test_standing_declared_goldens(self):
        entry = StandingPaymentEntry(
            _G_PAYER, _G_RECIPIENT, 500, SCHEDULE_MONTHLY, 31, _G_ANCHOR,
            28 * DAY, 0, 12, 0, 0, 0, False, 1,
        )
        self.assertEqual(
            entry.auth_id.hex(),
            "746df97e702971776b20c3ef43092703328991fb5aa4e62702cd36cfbf16f36c")
        book = StandingPaymentBook()
        book.create(entry, _G_ANCHOR)
        self.assertEqual(
            book.root().hex(),
            "63fa1d9a39b1bd53f2cb2469824ff36fc405096b8531d407147fa55eb515a1a6")
        book.execute(entry.auth_id, _G_ANCHOR, 10_000)
        self.assertEqual(
            book.root().hex(),
            "531e86b76a36349842c0e9251c0af3ad0eb273377ec106dd02d8ba20b65ab2c9")
        expected_record = (
            "746df97e702971776b20c3ef43092703328991fb5aa4e62702cd36cfbf16f36c"
            + _G_PAYER + _G_RECIPIENT
            + _u64(500) + _u64(3) + _u64(31) + _u64(_G_ANCHOR)
            + _u64(28 * DAY) + _u64(0) + _u64(12) + _u64(0) + _u64(0)
            + _u64(0) + _u64(0) + _u64(1)
            + (1).to_bytes(4, "big").hex() + _u64(0)
            + _u64(500) + _u64(_G_ANCHOR) + _u64(0) + _u64(0)
        )
        self.assertEqual(
            encode_standing_payment_record(*book.rows()[0]).hex(),
            expected_record)

    def test_route_declared_goldens(self):
        entry = ReceiveRouteEntry(_G_PAYER, _G_DEST, 2000, 0, 0, 0, 0, 1)
        self.assertEqual(
            entry.route_id.hex(),
            "ef7fa348dbac84636c712832e71b31ecdde41dd4006ceb21b34db98f85d93477")
        book = ReceiveRouteBook()
        book.install(entry, 1000)
        self.assertEqual(
            book.root().hex(),
            "a8dbe0196757f73ae75db86d1ec93ab7db651d233fb2943ceb7fd623f57fc722")
        expected_entry = (
            "ef7fa348dbac84636c712832e71b31ecdde41dd4006ceb21b34db98f85d93477"
            + _G_PAYER + _G_DEST
            + _u64(2000) + _u64(0) + _u64(0) + _u64(0) + _u64(0) + _u64(1)
        )
        self.assertEqual(
            encode_receive_route_entry(*book.rows()[0]).hex(), expected_entry)


# --- the native scenarios ------------------------------------------------------------


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestStage1ClauseFormNative(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_stage1_clause_native_db.sqlite")
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

    def _transfer(self, to, amount):
        tx = json.dumps(sign_payload({
            "sender_pubkey": PAYER,
            "sequence_number": chain_state.get_sequence_number(PAYER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[PAYER, to, str(amount)]]},
            "fee_limit": "50",
        }, SK_ALICE))
        res = sendtx.queue_transaction(tx, propagate=False)
        self.assertTrue(res["ok"], f"transfer rejected: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)

    # (1) monthly day-31 as a clause -------------------------------------------

    def test_monthly_31_standing_as_a_clause(self):
        # The calendar pins, unconditional: clamp into February, return
        # to the 31st in March — the book's own due_ts.
        cal = StandingPaymentEntry(
            PAYER, RECIPIENT, AMOUNT, SCHEDULE_MONTHLY, 31, _ts(2026, 1, 31),
            28 * DAY, 0, 12, 0, 0, 0, False, 1,
            form=FORM_TAU_CLAUSE, clause_text=PAY_FULL_CLAUSE,
        )
        self.assertEqual(due_ts(cal, 1), _ts(2026, 2, 28))
        self.assertEqual(due_ts(cal, 2), _ts(2026, 3, 31))
        self.assertEqual(due_ts(cal, 3), _ts(2026, 4, 30))

        now = int(time.time())
        anchor = _latest_month_end(now)
        entry = StandingPaymentEntry(
            PAYER, RECIPIENT, AMOUNT, SCHEDULE_MONTHLY, 31, anchor,
            28 * DAY, 0, 12, 0, 0, 0, False, 1,
            form=FORM_TAU_CLAUSE, clause_text=PAY_FULL_CLAUSE,
        )
        chain_state._lifecycle_manager.standing_payments.create(entry, now)
        book = chain_state._lifecycle_manager.standing_payments
        self.assertEqual(book.get(entry.auth_id).form, FORM_TAU_CLAUSE)

        if now - anchor > 28 * DAY - 3600:
            # The window for the current period has lapsed by
            # construction (runs in the last ~1-2 days before a
            # month-end whose previous month-end is 31 days back):
            # admission refuses, and the next due date is the coming
            # month-end — the authorization is live, just not due.
            res = sendtx.queue_transaction(
                self._execute_tx(entry.auth_id), propagate=False)
            self.assertFalse(res["ok"], f"lapsed-window execution admitted: {res}")
            nxt = book.next_due_ts(entry.auth_id, now)
            self.assertIsNotNone(nxt)
            self.assertGreater(nxt, now)
            return

        before = self._balances(PAYER, RECIPIENT, EXECUTOR)
        res = sendtx.queue_transaction(
            self._execute_tx(entry.auth_id), propagate=False)
        self.assertTrue(res["ok"], f"execution rejected at admission: {res}")
        block_res = self._mine()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        after = self._balances(PAYER, RECIPIENT, EXECUTOR)
        # The clause paid its i1 cap in full: exactly the signed 500,
        # once, from the payer to the recipient.
        self.assertEqual(after[RECIPIENT] - before[RECIPIENT], AMOUNT)
        self.assertEqual(after[PAYER] - before[PAYER], -AMOUNT)
        self.assertLess(after[EXECUTOR], before[EXECUTOR])  # the fee

        book = chain_state._lifecycle_manager.standing_payments
        self.assertEqual(book.total_executed(entry.auth_id), (1, AMOUNT))
        (fact,) = book.facts_for(entry.auth_id)
        self.assertEqual(fact.amount, AMOUNT)

        # At most once per period: a second trigger is refused at
        # admission, before it can reach a block.
        res = sendtx.queue_transaction(
            self._execute_tx(entry.auth_id), propagate=False)
        self.assertFalse(res["ok"], f"second execution admitted: {res}")

    # (2) route 101 at 20% as a clause, no re-trigger ---------------------------

    def test_route_101_at_20pct_as_a_clause_no_retrigger(self):
        # Touch both accounts first so any creation-time grant lands
        # before the measurement (the declared suite's pattern).
        self._transfer(RECIPIENT, 1)
        self._transfer(EXECUTOR, 1)
        mgr = chain_state._lifecycle_manager
        mgr.receive_routes.install(ReceiveRouteEntry(
            RECIPIENT, EXECUTOR, 0, 0, 0, 0, 0, 1,
            form=ROUTE_FORM_TAU_CLAUSE, clause_text=FIFTH_CLAUSE,
        ), int(time.time()))
        # The destination's own clause route (50% back to the payer)
        # must NOT fire on the routed share.
        mgr.receive_routes.install(ReceiveRouteEntry(
            EXECUTOR, PAYER, 0, 0, 0, 0, 0, 1,
            form=ROUTE_FORM_TAU_CLAUSE, clause_text=HALF_CLAUSE,
        ), int(time.time()))

        before = self._balances(PAYER, RECIPIENT, EXECUTOR)
        self._transfer(RECIPIENT, 101)
        after = self._balances(PAYER, RECIPIENT, EXECUTOR)
        self.assertEqual(after[RECIPIENT] - before[RECIPIENT], 81)
        self.assertEqual(after[EXECUTOR] - before[EXECUTOR], 20)
        # No re-trigger: had the routed 20 fired the destination's own
        # 50% route, 10 would have come back to the payer. The payer
        # only lost — the 101 and its fee, nothing returned.
        self.assertLessEqual(after[PAYER] - before[PAYER], -101)

        # Control: a direct 100 credit to the destination DOES split
        # under its own clause route — 50 kept, 50 routed back to the
        # payer (so the payer's net loss is 50 plus its fee, not 100
        # plus its fee).
        before = self._balances(PAYER, EXECUTOR)
        self._transfer(EXECUTOR, 100)
        after = self._balances(PAYER, EXECUTOR)
        self.assertEqual(after[EXECUTOR] - before[EXECUTOR], 50)
        self.assertGreater(after[PAYER] - before[PAYER], -100)
        self.assertLessEqual(after[PAYER] - before[PAYER], -50)

    # (4) the cap / candidate pins at admission and inclusion ---------------------

    def _daily_clause_auth(self, clause):
        now = int(time.time())
        entry = StandingPaymentEntry(
            PAYER, RECIPIENT, AMOUNT, SCHEDULE_DAILY, 0, now - 100,
            3600, 0, 1, 0, 0, 0, False, 1,
            form=FORM_TAU_CLAUSE, clause_text=clause,
        )
        chain_state._lifecycle_manager.standing_payments.create(entry, now)
        return entry

    def test_clause_leg_outside_the_set_settles_nothing(self):
        entry = self._daily_clause_auth(OUT_OF_SET_CLAUSE)
        blob = self._execute_tx(entry.auth_id)
        before = self._balances(PAYER, RECIPIENT)
        res = sendtx.queue_transaction(blob, propagate=False)
        self.assertFalse(res["ok"], f"out-of-set execution admitted: {res}")
        forced = self._force_queue(blob)
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion settled a leg outside the declared set")
        after = self._balances(PAYER, RECIPIENT)
        self.assertEqual(after, before)
        book = chain_state._lifecycle_manager.standing_payments
        self.assertEqual(book.total_executed(entry.auth_id), (0, 0))

    def test_clause_leg_above_the_cap_settles_nothing(self):
        entry = self._daily_clause_auth(OVER_CAP_CLAUSE)
        blob = self._execute_tx(entry.auth_id)
        before = self._balances(PAYER, RECIPIENT)
        res = sendtx.queue_transaction(blob, propagate=False)
        self.assertFalse(res["ok"], f"over-cap execution admitted: {res}")
        forced = self._force_queue(blob)
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion settled a leg above the signed cap")
        after = self._balances(PAYER, RECIPIENT)
        self.assertEqual(after, before)
        book = chain_state._lifecycle_manager.standing_payments
        self.assertEqual(book.total_executed(entry.auth_id), (0, 0))

    def test_route_clause_pins_leave_the_credit_whole(self):
        mgr = chain_state._lifecycle_manager
        # Out-of-set leg on the recipient's route.
        mgr.receive_routes.install(ReceiveRouteEntry(
            RECIPIENT, EXECUTOR, 0, 0, 0, 0, 0, 1,
            form=ROUTE_FORM_TAU_CLAUSE, clause_text=OUT_OF_SET_CLAUSE,
        ), int(time.time()))
        # Over-cap leg (95 > floor(101 * 0.9) = 90) on the executor's.
        mgr.receive_routes.install(ReceiveRouteEntry(
            EXECUTOR, EXTRA, 0, 0, 0, 0, 0, 1,
            form=ROUTE_FORM_TAU_CLAUSE, clause_text=ROUTE_OVER_CAP_CLAUSE,
        ), int(time.time()))

        before = self._balances(RECIPIENT, EXECUTOR, EXTRA)
        self._transfer(RECIPIENT, 101)
        self._transfer(EXECUTOR, 101)
        after = self._balances(RECIPIENT, EXECUTOR, EXTRA)
        self.assertEqual(after[RECIPIENT] - before[RECIPIENT], 101)
        self.assertEqual(after[EXECUTOR] - before[EXECUTOR], 101)
        self.assertEqual(after[EXTRA] - before[EXTRA], 0)


if __name__ == "__main__":
    unittest.main()
