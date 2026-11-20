"""Bounty 01, issue #34 (W5): the paid-for-period fact, read by a real rule.

Kept in its own file so the real-Tau CI job can register exactly this
file: the proof needs the native bindings, which the mock test job does
not have. The skip is environment-driven — in the real-Tau job's image
the bindings are present (its preflight imports them) and the job
preamble generates the miner identity and genesis this harness needs,
so the skip lifts and the proof runs for real. Everywhere else it
skips, exactly as the other Bounty 01 native suites do.

The scenario is gmikeyg's W5 made concrete — a membership rule that
depends on the "paid for this period" fact. The payer registers an o5
clause that allows a transfer only when the standing-paid stream
(i17, tau_defs.STANDING_PAID_STREAM_INDEX) is 1, with one exception:
the standing settlement itself (its recipient is the authorization's
recipient — the dues collector is the one payee an unpaid member may
still pay, which is also what lets the period settle at all under the
clause). While the period is unpaid, a plain transfer to a fourth
account is refused — at admission, and again at inclusion when the
admission gate is bypassed. A third party then triggers the standing
execution through the real sendtx path; the settlement passes the
clause through its recipient exception and writes the fact. The same
plain transfer now settles, because the clause reads i17 = 1 from the
node's own feed. Assertions are deltas around the measured blocks, so
faucet grants at account creation cannot pollute them.
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
import tau_defs
import tau_manager
from errors import TauEngineCrash
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_payload
from commands import sendtx, createblock
from consensus.standing_payments import SCHEDULE_DAILY, StandingPaymentEntry

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

PAYER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
DEST = pubkey_hex(SK_MALLORY)
AMOUNT = 250

# The membership clause: allow only when the standing-paid stream is 1,
# or when the transfer is the standing settlement itself (recipient =
# the authorization's recipient).
MEMBERSHIP_RULE = (
    "always ( ((i17[t]:bv[64] = { 1 }:bv[64]) || "
    "(i4[t]:bv[384] = { #x" + RECIPIENT + " }:bv[384])) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestPaidFactNativeE2E(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_paid_fact_native_db.sqlite")
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

        chain_state._balances[PAYER] = 100000
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

    def _install_authorization(self):
        now = int(time.time())
        entry = StandingPaymentEntry(
            payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=AMOUNT,
            schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=now - 100,
            window_seconds=3600, final_ts=0, max_occurrences=1, max_total=0,
            fee_limit=0, policy_version_ref=0, allow_catch_up=False, version=1,
        )
        chain_state._lifecycle_manager.standing_payments.create(entry, now)
        return entry

    def _user_tx(self, sk, sender, operations):
        return json.dumps(sign_payload({
            "sender_pubkey": sender,
            "tx_type": "user_tx",
            "sequence_number": chain_state.get_sequence_number(sender),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": operations,
            "fee_limit": "1000",
        }, sk))

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

    def _mine(self):
        out = createblock.create_block_from_mempool()
        self.assertNotIn("error", out, out)
        return out

    def _force_queue(self, blob):
        """Put a signed tx in the mempool WITHOUT admission, to ask what
        inclusion does with it on its own (the isolation-suite pattern)."""
        payload = json.loads(blob)
        tx_hash, raw = sendtx._compute_transaction_message_id(payload)
        db.add_mempool_tx(raw, tx_hash, int(time.time() * 1000))
        return tx_hash

    def _included(self, tx_hash):
        head = db.get_canonical_head_block() or {}
        return tx_hash in (head.get("tx_ids") or [])

    def test_membership_clause_follows_the_standing_paid_stream(self):
        entry = self._install_authorization()

        # The payer registers the membership clause.
        res = sendtx.queue_transaction(
            self._user_tx(SK_ALICE, PAYER, {"0": MEMBERSHIP_RULE}),
            propagate=False)
        self.assertTrue(res["ok"], f"clause registration rejected: {res}")
        self._mine()
        clause = chain_state._lifecycle_manager.rule_offers.clause_for(
            PAYER, tau_defs.USER_POLICY_STREAM_INDEX)
        self.assertIsNotNone(clause, "the membership clause did not register")

        transfer = lambda: self._user_tx(
            SK_ALICE, PAYER, {"1": [[PAYER, DEST, "10"]]})

        # Before the period settles the stream is 0: admission refuses...
        dest_before = chain_state._balances.get(DEST, 0)
        res = sendtx.queue_transaction(transfer(), propagate=False)
        self.assertFalse(res["ok"], f"unpaid transfer admitted: {res}")
        self.assertIn("own policy clause", res.get("message", ""), res)
        # ...and inclusion refuses it too, with the admission gate bypassed.
        forced = self._force_queue(transfer())
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion let through a transfer the clause blocks")
        self.assertEqual(chain_state._balances.get(DEST, 0), dest_before)

        # A third party triggers the standing execution; the settlement
        # passes the clause through its recipient exception.
        recip_before = chain_state._balances.get(RECIPIENT, 0)
        res = sendtx.queue_transaction(self._execute_tx(entry.auth_id),
                                       propagate=False)
        self.assertTrue(res["ok"], f"execution rejected at admission: {res}")
        self._mine()
        self.assertEqual(
            chain_state._balances.get(RECIPIENT, 0) - recip_before, AMOUNT)
        book = chain_state._lifecycle_manager.standing_payments
        self.assertEqual(len(book.facts_for(entry.auth_id)), 1)

        # The period is now recorded paid, the stream reads 1, and the
        # same plain transfer settles.
        res = sendtx.queue_transaction(transfer(), propagate=False)
        self.assertTrue(res["ok"], f"paid transfer rejected: {res}")
        self._mine()
        self.assertEqual(chain_state._balances.get(DEST, 0) - dest_before, 10)


if __name__ == "__main__":
    unittest.main()
