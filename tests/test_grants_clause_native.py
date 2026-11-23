"""Bounty 01, FIX 5: grants in Tau clause form, on the native engine.

The clause form stepped for real: a clause-form grant is created
and drawn on a live chain, and the clause's own Tau arithmetic —
not a scripted mock — names the released amount from the signed
periods_from anchor. The byte-for-byte pin lives in
tests/test_grants_clause_bounty01.py, in every job; this file runs
only where the native bindings exist, exactly as the other Bounty 01
native suites.

Covered: a clause-form grant created by a real transaction and
drawn under a third party (the clause steps i1/i2/i3/i4/i5/i27 and
its o30 releases exactly the signed 500); a clause naming more than
the declared schedule releases settles nothing — at admission AND
at inclusion with admission bypassed; a clause with no o30 output
settles nothing the same way; the release boundaries follow the
signed periods_from, not the install day (a grant installed now
with an anchor two weeks back releases 1500, one with an anchor a
week ahead releases 0).
"""
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
from consensus.grants import (
    FORM_TAU_CLAUSE,
    SCHEDULE_WEEKLY,
    GrantBook,
    GrantEntry,
    parse_create_grant,
)

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

FUNDER = pubkey_hex(SK_ALICE)
BENEFICIARY = pubkey_hex(SK_BOB)
SUBMITTER = pubkey_hex(SK_CAROL)
EXTRA = pubkey_hex(SK_MALLORY)

WEEK = 604_800
DAY = 86_400
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())


def _grant_clause(anchor, release=500, total=5000, weeks=8):
    """The canonical grants clause (same text as the book and engine
    suites): band k names min(total, release*k) for ts in
    [anchor+(k-1)W, anchor+kW), 0 before the anchor, the total at and
    after anchor+8W."""
    def rel(amount):
        return f"((o30[t]:bv[64] = {{ {amount} }}:bv[64]))"

    clause = rel(total)
    for k in range(weeks, 0, -1):
        clause = (
            f"((i5[t]:bv[64] < {{ {anchor + k * WEEK} }}:bv[64]) "
            f"? {rel(min(total, release * k))} : {clause})"
        )
    return (
        f"((i5[t]:bv[64] < {{ {anchor} }}:bv[64]) "
        f"? {rel(0)} : {clause})"
    )


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestGrantsClauseNative(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_grants_clause_native_db.sqlite")
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

        chain_state._balances[FUNDER] = 100000
        chain_state._balances[BENEFICIARY] = 1000
        chain_state._balances[SUBMITTER] = 1000
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
        # Block apply forks the lifecycle manager: re-read the book
        # from the canonical manager after every block.
        return chain_state._lifecycle_manager.grants

    def _seed_clause_grant(self, anchor, clause=None, release=500,
                           total=5000, start_ts=None):
        now = int(time.time())
        entry = GrantEntry(
            funder_pubkey=FUNDER, beneficiary_pubkey=BENEFICIARY,
            total_amount=total, release_per_period=release,
            schedule_kind=SCHEDULE_WEEKLY, signed_day=0,
            start_ts=start_ts if start_ts is not None else anchor,
            deadline_ts=now + 8 * WEEK,
            locked_until_ts=0, window_start_ts=0, window_end_ts=0,
            inactivity_seconds=0, version=1,
            form=FORM_TAU_CLAUSE,
            clause_text=clause if clause is not None
            else _grant_clause(anchor, release=release, total=total),
            periods_from_ts=anchor,
        )
        self._book().create(entry, now)
        return entry

    def _create_tx(self, anchor, clause=None):
        now = int(time.time())
        return json.dumps(sign_payload({
            "sender_pubkey": FUNDER,
            "tx_type": "create_grant",
            "sequence_number": chain_state.get_sequence_number(FUNDER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "fee_limit": "50",
            "grant_beneficiary_pubkey": BENEFICIARY,
            "grant_total_amount": 5000,
            "grant_release_per_period": 500,
            "grant_schedule": "weekly",
            "grant_signed_day": 0,
            "grant_start_ts": anchor,
            "grant_deadline_ts": now + 8 * WEEK,
            "grant_locked_until_ts": 0,
            "grant_window_start_ts": 0,
            "grant_window_end_ts": 0,
            "grant_inactivity_seconds": 0,
            "grant_version": 1,
            "grant_form": FORM_TAU_CLAUSE,
            "grant_clause": clause if clause is not None
            else _grant_clause(anchor),
            "grant_periods_from_ts": anchor,
        }, SK_ALICE))

    def _draw_tx(self, grant_id, amount=500):
        return json.dumps(sign_payload({
            "sender_pubkey": SUBMITTER,
            "tx_type": "draw_grant",
            "sequence_number": chain_state.get_sequence_number(SUBMITTER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "grant_id": grant_id.hex(),
            "grant_draw_amount": amount,
            "fee_limit": "50",
        }, SK_CAROL))

    # --- the full path: created by a real transaction, drawn by a third party ---

    def test_clause_grant_created_by_tx_and_drawn_under_the_real_clause(self):
        now = int(time.time())
        anchor = now - 100  # period 1 is live at draw time
        create = self._create_tx(anchor)
        grant_id = parse_create_grant(json.loads(create)).grant_id

        before = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        res = sendtx.queue_transaction(create, propagate=False)
        self.assertTrue(res["ok"], f"clause grant rejected at admission: {res}")
        block_res = self._mine()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        entry = self._book().get(grant_id)
        self.assertIsNotNone(entry)
        self.assertEqual(entry.form, FORM_TAU_CLAUSE)
        self.assertEqual(entry.clause_text, _grant_clause(anchor))
        self.assertEqual(entry.periods_from_ts, anchor)
        after = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        # The funder escrowed exactly 5000 (plus its fee) and nothing
        # reached the beneficiary yet.
        self.assertGreaterEqual(before[FUNDER] - after[FUNDER], 5000)
        self.assertEqual(self._book().held_total(), 5000)
        self.assertEqual(after[BENEFICIARY] - before[BENEFICIARY], 0)

        # The draw: a third party submits it; the clause's own Tau
        # arithmetic names 500 released for this week, and exactly 500
        # reaches the beneficiary.
        before = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        res = sendtx.queue_transaction(
            self._draw_tx(grant_id), propagate=False)
        self.assertTrue(res["ok"], f"clause draw rejected at admission: {res}")
        block_res = self._mine()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        after = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        self.assertEqual(after[BENEFICIARY] - before[BENEFICIARY], 500)
        self.assertLess(after[SUBMITTER], before[SUBMITTER])  # the fee
        self.assertEqual(self._book().accounting(grant_id)["drawn"], 500)

        # The week's release is spent: a second draw is refused at
        # admission, before it can reach a block.
        res = sendtx.queue_transaction(
            self._draw_tx(grant_id), propagate=False)
        self.assertFalse(res["ok"], f"second draw admitted: {res}")

    # --- the cap pins, at admission and inclusion ---------------------------------

    def test_clause_grant_over_schedule_cap_settles_nothing(self):
        now = int(time.time())
        anchor = now - 100
        # The clause names 2000 released in period 1; the declared
        # schedule caps the release at 500. The book refuses. The
        # entry's own terms stay 500/week — the clause's 2000 is the
        # over-cap claim, not the schedule (passing release=2000 here
        # would raise the declared cap to 2000 and the draw would
        # rightly be admitted).
        entry = self._seed_clause_grant(
            anchor,
            clause=_grant_clause(anchor, release=2000))
        blob = self._draw_tx(entry.grant_id)
        before = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        res = sendtx.queue_transaction(blob, propagate=False)
        self.assertFalse(res["ok"], f"over-cap draw admitted: {res}")
        forced = self._force_queue(blob)
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion settled a release above the schedule cap")
        after = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        self.assertEqual(after, before)
        self.assertEqual(self._book().accounting(entry.grant_id)["drawn"], 0)

    def test_clause_grant_with_no_released_output_settles_nothing(self):
        now = int(time.time())
        anchor = now - 100
        # A clause that writes o5 and nothing else has no o30 for the
        # book to read: the draw is refused, not guessed at.
        entry = self._seed_clause_grant(
            anchor,
            clause="((o5[t]:bv[24] = { #x000001 }:bv[24]))")
        blob = self._draw_tx(entry.grant_id)
        before = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        res = sendtx.queue_transaction(blob, propagate=False)
        self.assertFalse(res["ok"], f"no-o30 draw admitted: {res}")
        forced = self._force_queue(blob)
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion settled a draw with no released output")
        after = self._balances(FUNDER, BENEFICIARY, SUBMITTER)
        self.assertEqual(after, before)
        self.assertEqual(self._book().accounting(entry.grant_id)["drawn"], 0)

    # --- the anchor, not the install day --------------------------------------------

    def test_clause_grant_periods_from_anchor_is_not_the_install_day(self):
        now = int(time.time())
        # Installed now, anchored two weeks back: period 3 is live, so
        # 1500 is released and a 500 draw settles.
        past = self._seed_clause_grant(now - 2 * WEEK)
        res = sendtx.queue_transaction(
            self._draw_tx(past.grant_id), propagate=False)
        self.assertTrue(res["ok"], f"past-anchored draw rejected: {res}")
        self._mine()
        self.assertEqual(self._book().accounting(past.grant_id)["drawn"], 500)
        # Installed now, anchored a week ahead: nothing is released
        # yet, so the draw is refused at admission.
        future = self._seed_clause_grant(now + WEEK)
        res = sendtx.queue_transaction(
            self._draw_tx(future.grant_id), propagate=False)
        self.assertFalse(res["ok"], f"future-anchored draw admitted: {res}")
        self.assertEqual(
            self._book().accounting(future.grant_id)["drawn"], 0)


if __name__ == "__main__":
    unittest.main()
