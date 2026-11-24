"""Bounty 01, FIX 10 (stage 2, S-3): a deciding-rule payout rule on
the native engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the proof steps REAL Tau clauses through the real
policy-evaluation path, which needs the native bindings the mock job
does not have. The skip is environment-driven, exactly as the other
Bounty 01 native suites.

The stage-1 counterpart (test_payout_tau_rule_native.py) proved the
maintainer's grant shape as a Tau payout rule whose clause computes
the legs while the book decides whether they run. This file proves
the stage-2 split with the real evaluator (no mock anywhere):

1. The release schedule is the clause's verdict: a deciding rule
   releases 500 a week against the period-paid fact (i26) — two
   draws of 500 settle in week two, and the third is refused at
   admission because the CLAUSE, reading the book's fact, declines
   (o29 = 0), not because a Python cap fired: the rule carries no
   per-period cap at all.
2. The shared-cap room is a fact the clause reads: of two deciding
   rules sharing a 900 cap, the second pays only while the room fact
   (i32) covers its leg; after the first rule pays 500, the second's
   clause sees 400 of room and declines — refused at admission, the
   group total unmoved.
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
from consensus.payout_rules import FORM_TAU_DECIDING_RULE, PayoutRuleEntry

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

FUNDER = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
OWNER = pubkey_hex(SK_MALLORY)  # the account holding the funds

WEEK = 604_800
TOTAL = 5000


def _pay(amount_expr):
    return (
        "((o29[t]:bv[64] = { 1 }:bv[64]) "
        "&& (o30[t]:bv[64] = { 1 }:bv[64]) "
        "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
        f"&& (o32[t]:bv[64] = {amount_expr}))"
    )


def _decline():
    return (
        "((o29[t]:bv[64] = { 0 }:bv[64]) "
        "&& (o30[t]:bv[64] = { 0 }:bv[64]) "
        "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
        "&& (o32[t]:bv[64] = { 0 }:bv[64]))"
    )


def _release_clause(anchor):
    """500 a week cumulative release, decided over the i26 fact.

    Every branch assigns all four outputs (o29 verdict, o30 count,
    o31 candidate, o32 amount), so the step is fully determined on
    every path — the native-suite discipline.
    """
    a1 = anchor + WEEK
    a2 = anchor + 2 * WEEK
    deadline = anchor + 3 * WEEK

    def draw(release):
        return (
            f"((i26[t]:bv[64] < {{ {release} }}:bv[64]) "
            f"? ((i1[t]:bv[64] <= ({{ {release} }}:bv[64] - i26[t]:bv[64])) "
            f"? {_pay('i1[t]:bv[64]')} "
            f": {_pay(f'({{ {release} }}:bv[64] - i26[t]:bv[64])')}) "
            f": {_decline()})"
        )

    return (
        f"((i5[t]:bv[64] < {{ {a1} }}:bv[64]) "
        f"? {draw(500)} "
        f": ((i5[t]:bv[64] < {{ {a2} }}:bv[64]) "
        f"? {draw(1000)} "
        f": ((i5[t]:bv[64] < {{ {deadline} }}:bv[64]) "
        f"? {draw(1500)} "
        f": {_decline()})))"
    )


# Pays a fixed 500 whenever the shared cap's room fact covers it.
ROOM_CLAUSE = (
    f"((i32[t]:bv[64] < {{ 500 }}:bv[64]) "
    f"? {_decline()} : {_pay('{ 500 }')})"
)

# Pays a fixed 500 unconditionally (the verdict is always yes).
ALWAYS_CLAUSE = _pay("{ 500 }")


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestPayoutDecidingRuleNative(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_payout_deciding_native_db.sqlite")
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

        chain_state._balances[OWNER] = TOTAL
        chain_state._balances[EXECUTOR] = 1000
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

    def _execute_tx(self, rule_id, settlement_id, base):
        return json.dumps(sign_payload({
            "sender_pubkey": EXECUTOR,
            "tx_type": "execute_payout_rule",
            "sequence_number": chain_state.get_sequence_number(EXECUTOR),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "payout_rule_id": rule_id.hex(),
            "payout_settlement_id": settlement_id,
            "payout_base_amount": base,
            "fee_limit": "50",
        }, SK_CAROL))

    def _book(self):
        return chain_state._lifecycle_manager.payout_rules

    # (1) the release schedule is the clause's verdict -----------------------

    def test_the_release_schedule_is_the_clauses_verdict(self):
        now = int(time.time())
        anchor = now - WEEK - 60  # week two: 1,000 released in all
        entry = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(BOB,), legs=(),
            max_per_execution=0, max_per_period=0,
            period_seconds=4 * WEEK, period_anchor_ts=anchor, version=1,
            form=FORM_TAU_DECIDING_RULE,
            clause_text=_release_clause(anchor),
        )
        self._book().install(entry, now)

        for k, sid in enumerate(("11" * 32, "22" * 32)):
            before = chain_state._balances.get(BOB, 0)
            res = sendtx.queue_transaction(
                self._execute_tx(entry.rule_id, sid, 500), propagate=False)
            self.assertTrue(res["ok"], f"draw {k + 1} rejected: {res}")
            self._mine()
            self.assertEqual(
                chain_state._balances.get(BOB, 0) - before, 500)

        # The release is exhausted (1,000 of 1,000): the clause reads
        # i26 = 1000 and declines. The rule carries NO caps, so under
        # stage 1 nothing in the book would have stopped a third leg
        # the clause computed — the refusal is the clause's decision.
        res = sendtx.queue_transaction(
            self._execute_tx(entry.rule_id, "33" * 32, 500),
            propagate=False)
        self.assertFalse(res["ok"], f"third draw admitted: {res}")
        self.assertEqual(self._book().period_total(entry.rule_id, 0), 1000)

    # (2) the shared-cap room is a fact the clause reads ---------------------

    def test_the_shared_cap_room_fact_decides(self):
        now = int(time.time())
        anchor = now - 60
        first = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(BOB,), legs=(),
            max_per_execution=0, max_per_period=0,
            period_seconds=WEEK, period_anchor_ts=anchor, version=1,
            form=FORM_TAU_DECIDING_RULE, clause_text=ALWAYS_CLAUSE,
            rule_index=0, shared_cap_id="grp", shared_cap_amount=900,
        )
        second = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(BOB,), legs=(),
            max_per_execution=0, max_per_period=0,
            period_seconds=WEEK, period_anchor_ts=anchor, version=1,
            form=FORM_TAU_DECIDING_RULE, clause_text=ROOM_CLAUSE,
            rule_index=1, shared_cap_id="grp", shared_cap_amount=900,
        )
        book = self._book()
        book.install(first, now)
        book.install(second, now)

        res = sendtx.queue_transaction(
            self._execute_tx(first.rule_id, "11" * 32, 500),
            propagate=False)
        self.assertTrue(res["ok"], f"first execution rejected: {res}")
        self._mine()
        self.assertEqual(chain_state._balances.get(BOB, 0), 500)

        # Room left is 400: the second rule's clause declines over the
        # i32 fact, before any cap arithmetic of the book's is reached
        # (its leg of 500 would also break the cap — the recorded
        # refusal is the rule's own answer, and nothing settles).
        res = sendtx.queue_transaction(
            self._execute_tx(second.rule_id, "22" * 32, 500),
            propagate=False)
        self.assertFalse(res["ok"], f"roomless execution admitted: {res}")
        self.assertEqual(self._book().period_total(second.rule_id, 0), 0)
        self.assertEqual(chain_state._balances.get(BOB, 0), 500)
