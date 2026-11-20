"""Bounty 01, issue #63: payout rules on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this file:
the seam proof needs the native bindings, which the mock test job does not
have. The skip is environment-driven — in the real-Tau job's image the
bindings are present (its preflight imports them) and the job preamble
generates the miner identity and genesis this harness needs, so the skip
lifts and the proof runs for real. Everywhere else it skips, exactly as the
issue-#42 native probe does.

The scenario is named case 2 at settlement level: a 5% royalty rule is
installed directly in the node's lifecycle manager (the consensus state
the seam consults), a THIRD PARTY submits an execution with base 101
through the real sendtx path, the real createblock path mines it, and the
balances must show the settlement — the artist up by exactly 5, the owner
down by exactly 5, the executor paying the fee. The book must then show
the settlement recorded under its settlement id, and a second execution
carrying the same settlement id must be refused at admission: the royalty
pays 5, once. Assertions are deltas around the measured block, so faucet
grants at account creation cannot pollute them.
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
from consensus.payout_rules import LEG_BPS_OF_BASE, PayoutLeg, PayoutRuleEntry

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

OWNER = pubkey_hex(SK_ALICE)
ARTIST = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
SETTLEMENT_ID = "11" * 32


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestPayoutRulesNativeE2E(unittest.TestCase):
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
        self.test_db = os.path.join(self._tmpdir, "test_payout_native_db.sqlite")
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

        chain_state._balances[OWNER] = 100000
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

    def _install_rule(self):
        now = int(time.time())
        entry = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(ARTIST,),
            legs=(PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 500),),
            max_per_execution=0, max_per_period=0,
            period_seconds=604800, period_anchor_ts=now - 100, version=1,
        )
        chain_state._lifecycle_manager.payout_rules.install(entry, now)
        return entry

    def _execute_tx(self, rule_id, settlement_id=SETTLEMENT_ID):
        return json.dumps(sign_payload({
            "sender_pubkey": EXECUTOR,
            "tx_type": "execute_payout_rule",
            "sequence_number": chain_state.get_sequence_number(EXECUTOR),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "payout_rule_id": rule_id.hex(),
            "payout_settlement_id": settlement_id,
            "payout_base_amount": 101,
            "fee_limit": "50",
        }, SK_CAROL))

    def test_royalty_pays_5_once_on_the_native_engine(self):
        entry = self._install_rule()

        before = {pk: chain_state._balances.get(pk, 0)
                  for pk in (OWNER, ARTIST, EXECUTOR)}
        res = sendtx.queue_transaction(self._execute_tx(entry.rule_id), propagate=False)
        self.assertTrue(res["ok"], f"execution rejected at admission: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        after = {pk: chain_state._balances.get(pk, 0)
                 for pk in (OWNER, ARTIST, EXECUTOR)}
        # Re-read the book from the canonical manager: block apply forks
        # the lifecycle manager, so the pre-block object is not the state
        # the settlement landed in.
        book = chain_state._lifecycle_manager.payout_rules

        self.assertEqual(after[ARTIST] - before[ARTIST], 5)
        self.assertEqual(after[OWNER] - before[OWNER], -5)
        # The executor paid the fee (one leg through the seam).
        self.assertLess(after[EXECUTOR], before[EXECUTOR])

        settlement_id = bytes.fromhex(SETTLEMENT_ID)
        self.assertTrue(book.is_settled(entry.rule_id, settlement_id))
        record = book.settlement(entry.rule_id, settlement_id)
        self.assertEqual(record.total, 5)
        self.assertEqual(record.base_amount, 101)

        # The settlement is spent: the same settlement id is refused at
        # admission, before it can reach a block — it pays 5, once.
        res = sendtx.queue_transaction(self._execute_tx(entry.rule_id), propagate=False)
        self.assertFalse(res["ok"], f"repeat execution admitted: {res}")


if __name__ == "__main__":
    unittest.main()
