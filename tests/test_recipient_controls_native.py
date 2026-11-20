"""Bounty 03, issues #47 + #76: recipient controls on the native tau-lang
engine.

Kept in its own file so the real-Tau CI job can register exactly this file:
the recipient gate's clause verdicts must come from the real PolicyEvaluator,
which the mock test job does not have. The skip is environment-driven — in
the real-Tau job's image the bindings are present (its preflight imports
them) and the job preamble generates the miner identity and genesis this
harness needs, so the skip lifts and the proof runs for real. Everywhere
else it skips, exactly as the Bounty 01 native suites do.

The recipient's clause is installed in the node's lifecycle manager (the
consensus state the gate consults, persisted to the clause registry the
admission view reads) and recipient controls are activated on it — the
same direct-install pattern the receive-routes native suite uses for its
book. Transfers and parks are then admitted by the real sendtx path and
mined by the real createblock path. Assertions are deltas around the
measured block, so faucet grants at account creation cannot pollute them.
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
from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, pubkey_hex, sign_payload
from commands import createblock, getrecipientpolicy, sendtx
from tau_testnet_cli import tx as cli_tx

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
STRANGER = pubkey_hex(SK_MALLORY)

# The mock suite's canonical clause bodies (tests/test_recipient_controls.py),
# evaluated here by the real engine instead of a scripted verdict: the
# allow-list admits only SENDER inbound (the outgoing branch, context 0, is
# untouched); the cap body caps time parks at 600 seconds and height parks
# at 100 blocks, each in the park's own unit.
ALLOWLIST_BODY = (
    "(i16[t]:bv[64] = { #x0000 }:bv[64] || "
    "i3[t]:bv[384] = { #x" + SENDER + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
)

CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0258 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestRecipientControlsNativeE2E(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_recipient_native_db.sqlite")
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

        chain_state._balances[SENDER] = 100000
        chain_state._balances[STRANGER] = 100000
        chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
        chain_state._lifecycle_manager.recompute_approval_threshold()
        # Recipient controls on, through the manager's own one-way switch —
        # the state both the admission view and the apply seam read.
        chain_state._lifecycle_manager.activate_recipient_policy()

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

    def _install_clause(self, recipient, body):
        """Register `body` as the recipient's o5 clause in the node's own
        registry: the lifecycle manager's accepted clauses (the apply
        seam's source) and the persisted registry rows (the admission
        view's source) — the two surfaces a real accepted offer lands on."""
        lm = chain_state._lifecycle_manager
        lm.rule_offers.accepted_clauses[(recipient.lower(), 5)] = body
        with db._db_lock:
            db._insert_clause_rows([{
                "acceptor_pubkey": recipient.lower(),
                "target_stream": 5,
                "clause_body": body,
            }])
            db._db_conn.commit()

    def _head(self):
        head = db.get_canonical_head_block()
        return int(head["header"]["block_number"]) if head else 0

    def _queue_transfer(self, sender, to, amount, sk):
        tx = json.dumps(sign_payload({
            "sender_pubkey": sender,
            "sequence_number": chain_state.get_sequence_number(sender),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[sender, to, str(amount)]]},
            "fee_limit": "50",
        }, sk))
        return sendtx.queue_transaction(tx, propagate=False)

    def _transfer(self, sender, to, amount, sk):
        res = self._queue_transfer(sender, to, amount, sk)
        self.assertTrue(res["ok"], f"transfer rejected: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)

    def _park(self, sender, to, amount, sk, **release):
        payload = cli_tx.build_retractable_transfer_tx(
            sender_pubkey=sender,
            sequence_number=chain_state.get_sequence_number(sender),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=self._head() + 50,
            recipient_pubkey=to, amount=amount, fee_limit="1000", **release)
        return sendtx.queue_transaction(
            json.dumps(sign_payload(payload, sk)), propagate=False)

    def test_allowlisted_inbound_transfer_settles_on_the_native_engine(self):
        """#47.1 on the real engine: the recipient's clause admits the
        listed payer, and the payment settles in a mined block."""
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        # Touch the recipient first so any creation-time grant lands before
        # the measurement, then read the baseline.
        self._transfer(SENDER, RECIPIENT, 1, SK_ALICE)
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(SENDER, RECIPIENT, 101, SK_ALICE)
        after = chain_state._balances.get(RECIPIENT, 0)
        self.assertEqual(after - before, 101)

    def test_refused_inbound_transfer_costs_no_fee_on_the_native_engine(self):
        """#47.1's other half, and the issues' fee answer: a payer the
        recipient's clause does not list is refused at admission — no fee,
        no sequence consumed, nothing queued, nothing moved."""
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        bal_before = chain_state._balances.get(STRANGER, 0)
        recip_before = chain_state._balances.get(RECIPIENT, 0)
        seq_before = chain_state.get_sequence_number(STRANGER)

        res = self._queue_transfer(STRANGER, RECIPIENT, 100, SK_MALLORY)

        self.assertFalse(res["ok"], f"unlisted payer admitted: {res}")
        self.assertIn("recipient", str(res).lower())
        self.assertEqual(chain_state._balances.get(STRANGER, 0), bal_before)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0), recip_before)
        self.assertEqual(chain_state.get_sequence_number(STRANGER), seq_before)
        self.assertEqual(db.get_mempool_txs(), [])

    def test_park_hold_is_measured_in_its_native_unit_on_the_native_engine(self):
        """#76.2 + the unit guarantee: a time park inside the 600-second
        cap settles into escrow, while a 500-BLOCK park is refused by the
        100-block cap — had the height park been measured in seconds
        against the 600 cap, it would have been admitted."""
        self._install_clause(RECIPIENT, CAP_BODY)
        # Warm the tip (a block timestamp near the wall clock) and touch
        # the recipient; a plain transfer is context "final", which the
        # cap body leaves alone.
        self._transfer(SENDER, RECIPIENT, 1, SK_ALICE)

        def escrow_total():
            # Re-fetched per read: a block commit replaces the book object,
            # so a handle taken before mining goes stale (the pattern
            # test_retractable_native's book() helper exists for).
            return chain_state._lifecycle_manager.retractable_transfers.escrow_total()

        escrow_before = escrow_total()
        recip_before = chain_state._balances.get(RECIPIENT, 0)
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 540)
        self.assertTrue(res["ok"], f"in-cap time park refused: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        self.assertEqual(escrow_total() - escrow_before, 100)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0), recip_before,
                         "a park escrows; it does not pay the recipient yet")

        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_height=self._head() + 500)
        self.assertFalse(res["ok"], f"over-cap height park admitted: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        self.assertIn("blocks", str(res))

    def test_reported_cap_matches_the_payers_actual_evaluation_on_the_native_engine(self):
        """#76.5: the cap the pre-flight reports for this payer (verified
        against his own evaluation: 600 admitted, 601 refused) is the cap
        the real refusal of his over-cap park carries."""
        self._install_clause(RECIPIENT, CAP_BODY)
        self._transfer(SENDER, RECIPIENT, 1, SK_ALICE)

        pre = json.loads(getrecipientpolicy.execute(
            f"getrecipientpolicy {RECIPIENT} {SENDER} 100 3600 seconds", None))
        self.assertEqual(pre["status"], "ok", pre)
        evaluation = pre["data"]["evaluation"]
        self.assertFalse(evaluation["admitted"], evaluation)
        self.assertEqual(evaluation["cap_kind"], "threshold", evaluation)
        self.assertEqual(evaluation["max_hold_seconds"], 600, evaluation)

        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 3600)
        self.assertFalse(res["ok"], f"over-cap park admitted: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        self.assertEqual(
            res["details"]["recipient_policy"]["max_hold_seconds"],
            evaluation["max_hold_seconds"])


if __name__ == "__main__":
    unittest.main()
