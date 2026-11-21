"""Bounty 01, stages 2-5: grants on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the seam proof needs the native bindings, which the mock test job
does not have. The skip is environment-driven — in the real-Tau job's
image the bindings are present (its preflight imports them) and the job
preamble generates the miner identity and genesis this harness needs, so
the skip lifts and the proof runs for real. Everywhere else it skips,
exactly as the issue-#42 native probe does.

The scenario: two grants are seeded directly into the node's lifecycle
manager (the consensus state the seam consults) — grant A, live, 5000
releasing 500/week; grant B, already past its deadline with 500 of its
2000 drawn. A THIRD PARTY submits a 500 draw on grant A through the real
sendtx path, the real createblock path mines it, and that one block must
show both movements: the beneficiary up by exactly 500 (the draw), and
the funder up by exactly 1500 — grant B's unspent remainder, refunded by
the block's sweep, fee-free and in full. The book must then show A's
draw recorded and B's refund settled, and a second draw on A must be
refused at admission: the week's release settles at most once.
Assertions are deltas around the measured block, so faucet grants at
account creation cannot pollute them.
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
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from commands import sendtx, createblock
from consensus.grants import GrantEntry
from consensus.standing_payments import SCHEDULE_WEEKLY

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

FUNDER = pubkey_hex(SK_ALICE)
BENEFICIARY = pubkey_hex(SK_BOB)
SUBMITTER = pubkey_hex(SK_CAROL)
WEEK = 604_800
DAY = 86_400


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestGrantsNativeE2E(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_grants_native_db.sqlite")
        self.original_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if not config.MINER_PRIVKEY:
            # The CI job's config profile leaves MINER_PRIVKEY unset (the
            # key loaders return None in that environment — see config.py),
            # which made this gate skip the suite in exactly the job it
            # exists for. The job preamble generates the miner identity
            # into data_local/ before pytest runs, so load it with
            # config's own loaders and install it where createblock reads
            # it at call time; skip only when the identity genuinely does
            # not exist.
            # Placement matters: this runs after set_database_path, whose
            # legacy-export re-sync from the profile would wipe it otherwise.
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
        chain_state._balances[SUBMITTER] = 1000
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
            funder_pubkey=FUNDER, beneficiary_pubkey=BENEFICIARY,
            total_amount=5000, release_per_period=500,
            schedule_kind=SCHEDULE_WEEKLY, signed_day=0,
            start_ts=now - 100, deadline_ts=now + 30 * DAY,
            locked_until_ts=0, window_start_ts=0, window_end_ts=0,
            inactivity_seconds=0, version=1,
        )
        book.create(live, now - 100)
        expired = GrantEntry(
            funder_pubkey=FUNDER, beneficiary_pubkey=BENEFICIARY,
            total_amount=2000, release_per_period=500,
            schedule_kind=SCHEDULE_WEEKLY, signed_day=0,
            start_ts=now - 40 * DAY, deadline_ts=now - 3600,
            locked_until_ts=0, window_start_ts=0, window_end_ts=0,
            inactivity_seconds=0, version=1,
        )
        book.create(expired, now - 40 * DAY)
        # 500 of grant B was drawn while it was live; 1500 remains held.
        drawn = book.draw(expired.grant_id, 500, expired.start_ts + 10)
        assert drawn.drawn, drawn.reason
        return live, expired

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

    def test_draw_and_sweep_refund_on_the_native_engine(self):
        live, expired = self._seed_grants()

        before = {pk: chain_state._balances.get(pk, 0)
                  for pk in (FUNDER, BENEFICIARY, SUBMITTER)}
        res = sendtx.queue_transaction(self._draw_tx(live.grant_id), propagate=False)
        self.assertTrue(res["ok"], f"draw rejected at admission: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        after = {pk: chain_state._balances.get(pk, 0)
                 for pk in (FUNDER, BENEFICIARY, SUBMITTER)}
        # Re-read the book from the canonical manager: block apply forks
        # the lifecycle manager, so the pre-block object is not the state
        # the draw and the refund landed in.
        book = chain_state._lifecycle_manager.grants

        # The draw: the beneficiary is up by exactly the drawn amount, and
        # the submitter paid the fee.
        self.assertEqual(after[BENEFICIARY] - before[BENEFICIARY], 500)
        self.assertLess(after[SUBMITTER], before[SUBMITTER])
        # The same block's sweep refunded grant B's remainder to the
        # funder: exactly 1500, fee-free (the funder submitted nothing).
        self.assertEqual(after[FUNDER] - before[FUNDER], 1500)

        acct_a = book.accounting(live.grant_id)
        self.assertEqual(acct_a["drawn"], 500)
        self.assertEqual(acct_a["held"], 4500)
        acct_b = book.accounting(expired.grant_id)
        self.assertEqual(acct_b["drawn"], 500)
        self.assertEqual(acct_b["refunded"], 1500)
        self.assertEqual(acct_b["held"], 0)
        self.assertEqual(book.status(expired.grant_id, int(time.time())), "refunded")

        # The week's release is spent: a second draw is refused at
        # admission, before it can reach a block.
        res = sendtx.queue_transaction(self._draw_tx(live.grant_id), propagate=False)
        self.assertFalse(res["ok"], f"second draw admitted: {res}")


if __name__ == "__main__":
    unittest.main()
