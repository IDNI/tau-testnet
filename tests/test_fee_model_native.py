"""
Fee model end-to-end on the REAL Tau interpreter (no TAU_FORCE_TEST, no
Tau mocks): consensus fee rule (o9) and user custom fee rule (o8) are
seeded into a live interpreter via i0 updates; transactions flow through
the real sendtx admission (Tau transfer validation + fee estimation),
real createblock (engine charging), and real process_new_block (state
hash invariant verified, NOT patched).

Requires the native tau module (tau-lang python bindings). Skipped when
unavailable — run with e.g.:
  PYTHONPATH=../tau-lang/build-Release/bindings/python/nanobind pytest tests/test_fee_model_native.py
"""
import json
import os
import sys
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
from commands import sendtx, createblock

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

FEE_RULE_10 = "always (o9[t]:bv[16] = { #x000a }:bv[16])."
FEE_RULE_20 = "always (o9[t]:bv[16] = { #x0014 }:bv[16])."
CUSTOM_FEE_RULE_5 = "always (o8[t]:bv[16] = { #x0005 }:bv[16])."

RECIPIENT = "c" * 96


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestFeeModelNativeE2E(unittest.TestCase):
    """Full pipeline with a live Tau interpreter."""

    def setUp(self):
        self.test_db = "test_fee_native_db.sqlite"
        self.original_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        if db._db_conn:
            db._db_conn.close()
        db._db_conn = None

        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()

        self.sender = chain_state.GENESIS_ADDRESS
        chain_state._balances[self.sender] = 100000
        self.original_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False

        # Live interpreter from the real genesis program; rules arrive the
        # same way they do in production: as i0 pointwise updates.
        tau_manager.tau_direct_interface = tau_native.TauInterface(GENESIS_TAU)
        tau_manager.tau_ready.set()
        self._seed_rule(open(TRANSFER_RULE_PATH).read(), "transfer-rule")

        # The point of this suite: NO TAU_FORCE_TEST — all Tau evaluation
        # is real (conftest defaults it to "1" for the legacy suite).
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()

        # Signature plumbing is out of scope here (covered elsewhere);
        # everything Tau/fee related runs for real.
        sendtx._PY_ECC_AVAILABLE = False
        patch("commands.sendtx._validate_bls12_381_pubkey", return_value=(True, None)).start()
        patch("commands.createblock._BLS_AVAILABLE", True).start()
        patch("commands.createblock._validate_signature", return_value=True).start()
        patch("block.bls_signing_available", return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.verify_block_header", return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.query_eligibility", return_value=True).start()

    def tearDown(self):
        patch.stopall()
        tau_manager.tau_ready.clear()
        tau_manager.tau_direct_interface = None
        config.TESTNET_AUTO_FAUCET = self.original_faucet
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        config.set_database_path(self.original_db)

    def _seed_rule(self, rule_text, label):
        out = tau_manager.communicate_with_tau(
            rule_text=rule_text,
            target_output_stream_index=0,
            apply_rules_update=False,
            source=f"seed-{label}",
        )
        self.assertNotIn("error", str(out).lower(), f"seeding {label} failed: {out}")

    def _tx(self, amount, fee_limit, seq=None):
        return json.dumps({
            "sender_pubkey": self.sender,
            "sequence_number": seq if seq is not None
            else chain_state.get_sequence_number(self.sender),
            "expiration_time": int(time.time()) + 3600,
            "operations": {"1": [[self.sender, RECIPIENT, str(amount)]]},
            "fee_limit": str(fee_limit),
            "signature": "SIG",
        })

    def test_fee_inactive_without_o9_rule(self):
        """No fee rule seeded -> real Tau emits no o9 -> legacy behavior."""
        start = chain_state.get_balance(self.sender)
        res = sendtx.queue_transaction(self._tx(100, 0), propagate=False)
        self.assertTrue(res["ok"], f"queue failed: {res}")

        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        self.assertEqual(chain_state.get_balance(self.sender), start - 100)
        self.assertEqual(chain_state.get_balance(RECIPIENT), 100)
        self.assertEqual(chain_state.get_balance(config.MINER_PUBKEY), 0)

    def test_consensus_fee_charged_end_to_end(self):
        """o9=10 rule live: sender pays amount+10, proposer credited 10,
        state hash invariant (process_new_block re-execution) holds."""
        self._seed_rule(FEE_RULE_10, "fee-10")
        start = chain_state.get_balance(self.sender)

        res = sendtx.queue_transaction(self._tx(100, 50), propagate=False)
        self.assertTrue(res["ok"], f"queue failed: {res}")
        # Admission stored the real-Tau fee estimate.
        entries = db.get_mempool_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["estimated_fee"], 10)
        self.assertEqual(entries[0]["fee_limit"], 50)

        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)

        self.assertEqual(chain_state.get_balance(self.sender), start - 100 - 10)
        self.assertEqual(chain_state.get_balance(RECIPIENT), 100)
        self.assertEqual(chain_state.get_balance(config.MINER_PUBKEY), 10)
        self.assertEqual(len(db.get_mempool_txs()), 0)

    def test_fee_limit_below_real_fee_rejected_at_admission(self):
        self._seed_rule(FEE_RULE_10, "fee-10")
        res = sendtx.queue_transaction(self._tx(100, 5), propagate=False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "FEE_LIMIT_TOO_LOW")
        self.assertEqual(res["details"]["required_fee"], 10)

    def test_custom_o8_fee_added_on_top(self):
        """User custom fee rule (o8=5) + consensus fee (o9=10) -> 15."""
        self._seed_rule(FEE_RULE_10, "fee-10")
        self._seed_rule(CUSTOM_FEE_RULE_5, "custom-fee-5")
        start = chain_state.get_balance(self.sender)

        res = sendtx.queue_transaction(self._tx(100, 50), propagate=False)
        self.assertTrue(res["ok"], f"queue failed: {res}")
        self.assertEqual(db.get_mempool_entries()[0]["estimated_fee"], 15)

        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        self.assertEqual(chain_state.get_balance(self.sender), start - 100 - 15)
        self.assertEqual(chain_state.get_balance(config.MINER_PUBKEY), 15)

    def test_governance_style_fee_change_between_blocks(self):
        """Fee rule replaced live (o9: 10 -> 20); next block charges 20."""
        self._seed_rule(FEE_RULE_10, "fee-10")
        start = chain_state.get_balance(self.sender)

        res = sendtx.queue_transaction(self._tx(100, 50), propagate=False)
        self.assertTrue(res["ok"], f"queue failed: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        self.assertEqual(chain_state.get_balance(config.MINER_PUBKEY), 10)

        # Vote in the new fee (same i0 revision path governance activation uses).
        self._seed_rule(FEE_RULE_20, "fee-20")
        res = sendtx.queue_transaction(self._tx(100, 50), propagate=False)
        self.assertTrue(res["ok"], f"queue failed: {res}")
        self.assertEqual(db.get_mempool_entries()[0]["estimated_fee"], 20)
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)

        self.assertEqual(chain_state.get_balance(config.MINER_PUBKEY), 30)  # 10 + 20
        self.assertEqual(chain_state.get_balance(self.sender), start - 200 - 30)

    def test_insufficient_for_amount_plus_fee_real_tau(self):
        """Balance covers the amount but not amount+fee -> rejected, state intact."""
        self._seed_rule(FEE_RULE_10, "fee-10")
        poor = "d" * 96
        chain_state._balances[poor] = 100
        tx = json.dumps({
            "sender_pubkey": poor,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 3600,
            "operations": {"1": [[poor, RECIPIENT, "100"]]},
            "fee_limit": "50",
            "signature": "SIG",
        })
        res = sendtx.queue_transaction(tx, propagate=False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "INSUFFICIENT_FUNDS")
        self.assertEqual(chain_state.get_balance(poor), 100)


if __name__ == "__main__":
    unittest.main()
