"""Bounty 01, FIX 9 (S-4): the named grant case with the exact numbers,
in the shape the maintainer's case 5 and #178's conditional-grant
example share.

The differential audit AUDIT-178-DUE-FIX8-2026-11-24 marked case 5
SERI-thin: #178 has a measured escrow -> draw -> refund example in
exactly the case's shape (install 5,000, draw 1,200, refund 3,800 at
the deadline), while this line's named case 5 (in
tests/test_grants_bounty01.py and test_grants_engine_bounty01.py) draws
500 in each of three weeks — 1,500 spent, 3,500 refunded. This file
closes that evidence gap on this line's own mechanism (grants as
rules: a signed total custodied by the book, a signed release
schedule, the refund as the book's invariant total - spent):

- at book level (mock): a 5,000 grant releasing 500/week; ONE draw of
  1,200 — deliberately NOT a multiple of the 500 release, the
  fractional case — lands once three weeks of releases have opened
  2,000; a draw AT the deadline is refused (the refund wins); the
  deadline refund returns exactly 3,800, proven from the book's own
  accounting (principal == drawn + held + refunded at every step) and
  through a restore, whose invariant check re-verifies
  refunded == total - spent;
- on the native engine: the same numbers through the real sendtx /
  createblock path — a third party draws 1,200 on the live grant, the
  same block's sweep refunds the expired grant's 3,800 to the funder,
  and a later draw on the refunded grant is refused at admission.
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

from consensus.grants import GrantBook, GrantEntry, released_by
from consensus.standing_payments import SCHEDULE_WEEKLY

FUNDER = "aa" * 48
BOB = "bb" * 48
WEEK = 604_800
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
DEADLINE = DEC1 + 8 * WEEK


def _entry(**kw):
    fields = dict(
        funder_pubkey=FUNDER, beneficiary_pubkey=BOB, total_amount=5000,
        release_per_period=500, schedule_kind=SCHEDULE_WEEKLY,
        signed_day=0, start_ts=DEC1, deadline_ts=DEADLINE,
        locked_until_ts=0, window_start_ts=0, window_end_ts=0,
        inactivity_seconds=0, version=1,
    )
    fields.update(kw)
    return GrantEntry(**fields)


def test_named_grant_case_5000_draw_1200_refund_3800_at_book_level():
    book = GrantBook()
    entry = _entry()
    book.create(entry, DEC1 - 100)
    assert book.accounting(entry.grant_id) == {
        "principal": 5000, "drawn": 0, "held": 5000, "refunded": 0}

    # Three weeks in, the schedule has released 2,000 (four weekly
    # releases of 500 have begun); a single draw of 1,200 — not a
    # multiple of the release — is inside it.
    draw_ts = DEC1 + 3 * WEEK + 60
    assert released_by(entry, draw_ts) == 2000
    decision = book.draw(entry.grant_id, 1200, draw_ts)
    assert decision.drawn and decision.amount == 1200
    assert book.accounting(entry.grant_id) == {
        "principal": 5000, "drawn": 1200, "held": 3800, "refunded": 0}

    # A draw AT the deadline is refused: at the deadline the refund
    # wins, even though 800 of released funds were never drawn.
    decision = book.evaluate_draw(entry.grant_id, 100, DEADLINE)
    assert not decision.drawn and "refund wins" in decision.reason

    # The deadline refund returns exactly total - spent = 3,800: the
    # 300 released-but-undrawn remainder of the drawn-against releases
    # and the 3,500 never released, to the unit.
    refunded = book.settle_expiry_refund(entry.grant_id, DEADLINE)
    assert refunded == 3800
    assert book.accounting(entry.grant_id) == {
        "principal": 5000, "drawn": 1200, "held": 0, "refunded": 3800}
    assert book.status(entry.grant_id, DEADLINE) == "refunded"

    # The refund is an invariant, not a number the caller supplied:
    # a restore re-verifies refunded == total - spent from the rows.
    clone = GrantBook.restore(book.rows(), book.shared_cap_rows())
    assert clone.root() == book.root()
    assert clone.accounting(entry.grant_id) == book.accounting(entry.grant_id)


# --- the same numbers on the native engine --------------------------------------

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
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from commands import sendtx, createblock

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

N_FUNDER = pubkey_hex(SK_ALICE)
N_BENEFICIARY = pubkey_hex(SK_BOB)
N_SUBMITTER = pubkey_hex(SK_CAROL)
DAY = 86_400


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestGrant5000Native(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_grant5000_native_db.sqlite")
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

        chain_state._balances[N_FUNDER] = 100000
        chain_state._balances[N_SUBMITTER] = 1000
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

    def _seed_grants(self):
        now = int(time.time())
        book = chain_state._lifecycle_manager.grants
        live = GrantEntry(
            funder_pubkey=N_FUNDER, beneficiary_pubkey=N_BENEFICIARY,
            total_amount=5000, release_per_period=500,
            schedule_kind=SCHEDULE_WEEKLY, signed_day=0,
            start_ts=now - 3 * WEEK - 100, deadline_ts=now + 30 * DAY,
            locked_until_ts=0, window_start_ts=0, window_end_ts=0,
            inactivity_seconds=0, version=1,
        )
        book.create(live, live.start_ts)
        expired = GrantEntry(
            funder_pubkey=N_FUNDER, beneficiary_pubkey=N_BENEFICIARY,
            total_amount=5000, release_per_period=500,
            schedule_kind=SCHEDULE_WEEKLY, signed_day=0,
            start_ts=now - 6 * WEEK, deadline_ts=now - 3600,
            locked_until_ts=0, window_start_ts=0, window_end_ts=0,
            inactivity_seconds=0, version=1,
        )
        book.create(expired, expired.start_ts)
        # 1,200 of the expired grant was drawn while it was live (at a
        # moment when 2,000 had been released); 3,800 remains held.
        drawn = book.draw(
            expired.grant_id, 1200, expired.start_ts + 3 * WEEK + 10)
        assert drawn.drawn, drawn.reason
        return live, expired

    def _draw_tx(self, grant_id, amount):
        return json.dumps(sign_payload({
            "sender_pubkey": N_SUBMITTER,
            "tx_type": "draw_grant",
            "sequence_number": chain_state.get_sequence_number(N_SUBMITTER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "grant_id": grant_id.hex(),
            "grant_draw_amount": amount,
            "fee_limit": "50",
        }, SK_CAROL))

    def test_grant_5000_draw_1200_refund_3800_on_the_native_engine(self):
        live, expired = self._seed_grants()
        before = {pk: chain_state._balances.get(pk, 0)
                  for pk in (N_FUNDER, N_BENEFICIARY, N_SUBMITTER)}
        res = sendtx.queue_transaction(self._draw_tx(live.grant_id, 1200), propagate=False)
        self.assertTrue(res["ok"], f"draw rejected at admission: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        after = {pk: chain_state._balances.get(pk, 0)
                 for pk in (N_FUNDER, N_BENEFICIARY, N_SUBMITTER)}

        # The draw moved exactly 1,200 to the beneficiary; the same
        # block's sweep refunded the expired grant's remainder —
        # exactly 3,800 — to the funder.
        self.assertEqual(after[N_BENEFICIARY] - before[N_BENEFICIARY], 1200)
        self.assertEqual(after[N_FUNDER] - before[N_FUNDER], 3800)

        # Proven from the book's own accounting, not only balances.
        book = chain_state._lifecycle_manager.grants
        self.assertEqual(book.accounting(live.grant_id), {
            "principal": 5000, "drawn": 1200, "held": 3800, "refunded": 0})
        self.assertEqual(book.accounting(expired.grant_id), {
            "principal": 5000, "drawn": 1200, "held": 0, "refunded": 3800})

        # The refunded grant is closed: a draw on it is refused at
        # admission, before it can reach a block.
        res = sendtx.queue_transaction(self._draw_tx(expired.grant_id, 100), propagate=False)
        self.assertFalse(res["ok"], f"draw on refunded grant admitted: {res}")


if __name__ == "__main__":
    unittest.main()
