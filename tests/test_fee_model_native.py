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

FEE_RULE_10 = "always (o9[t]:bv[24] = { #x00000a }:bv[24])."
FEE_RULE_20 = "always (o9[t]:bv[24] = { #x000014 }:bv[24])."
CUSTOM_FEE_RULE_5 = "always (o8[t]:bv[24] = { #x000005 }:bv[24])."

RECIPIENT = "c" * 96


class _NativeFeeE2EBase(unittest.TestCase):
    """Shared live-interpreter harness (no test methods)."""

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

@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestFeeModelNativeE2E(_NativeFeeE2EBase):
    """Full pipeline with a live Tau interpreter."""

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


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestGovernanceFeeChangeE2E(_NativeFeeE2EBase):
    """Fee changed through the REAL governance pipeline: consensus_rule_update
    proposal -> validator vote -> height activation -> new o9 fee charged.
    Inherits the live-interpreter setUp; the genesis consensus rules (which
    include the o9 fee term since gen_genesis --base-fee) are seeded as one
    i0 update, exactly like the startup restore plan does."""

    def _mine(self, expect_txs):
        block_res = createblock.create_block_from_mempool()
        self.assertNotIn("error", block_res, block_res)
        self.assertEqual(len(block_res.get("transactions", [])), expect_txs, block_res)
        return block_res

    def test_full_governance_fee_change(self):
        validator = next(iter(chain_state._lifecycle_manager.active_validators))
        if isinstance(validator, (bytes, bytearray)):
            validator = validator.hex()
        chain_state._balances.setdefault(validator, 0)

        # Seed the live interpreter with the actual genesis consensus rules
        # (single i0 update, like the startup restore plan) — fee 10 is in.
        # Read from the genesis artifact: the in-memory consensus_rules_state
        # gets rewritten with snapshot provenance after the first block.
        genesis_consensus = json.load(open("data/genesis.json"))["consensus_rules"]
        genesis_spec = chain_state._preprocess_tau_spec_text(genesis_consensus)
        self.assertIn("o9", genesis_spec)
        self._seed_rule(genesis_spec, "genesis-consensus")

        start = chain_state.get_balance(self.sender)

        # Block 1: user tx pays the genesis fee (10).
        res = sendtx.queue_transaction(self._tx(100, 50), propagate=False)
        self.assertTrue(res["ok"], f"queue failed: {res}")
        self.assertEqual(db.get_mempool_entries()[0]["estimated_fee"], 10)
        self._mine(expect_txs=1)
        self.assertEqual(chain_state.get_balance(config.MINER_PUBKEY), 10)

        # Block 2: governance proposal — full new consensus spec, o9 doubled.
        new_spec = genesis_consensus.replace("#x00000a", "#x000014")
        self.assertNotEqual(new_spec, genesis_consensus)
        activate_at = 4
        update_tx = json.dumps({
            "tx_type": "consensus_rule_update",
            "sender_pubkey": validator,
            "sequence_number": chain_state.get_sequence_number(validator),
            "expiration_time": int(time.time()) + 3600,
            "rule_revisions": [new_spec],
            "activate_at_height": activate_at,
            "host_contract_patch": {},
            "fee_limit": "0",
            "signature": "SIG",
        })
        res = sendtx.queue_transaction(update_tx, propagate=False)
        self.assertTrue(res["ok"], f"proposal rejected: {res}")
        self._mine(expect_txs=1)
        pending = list(chain_state._lifecycle_manager.pending_updates)
        self.assertEqual(len(pending), 1)
        update_id_hex = pending[0][1].hex() if isinstance(pending[0], tuple) else (
            pending[0].update_id.hex() if hasattr(pending[0], "update_id") else pending[0].hex()
        )

        # Block 3: validator vote reaches threshold (1 of 1) -> scheduled.
        vote_tx = json.dumps({
            "tx_type": "consensus_rule_vote",
            "sender_pubkey": validator,
            "sequence_number": chain_state.get_sequence_number(validator),
            "expiration_time": int(time.time()) + 3600,
            "update_id": update_id_hex,
            "approve": True,
            "fee_limit": "0",
            "signature": "SIG",
        })
        res = sendtx.queue_transaction(vote_tx, propagate=False)
        self.assertTrue(res["ok"], f"vote rejected: {res}")
        self._mine(expect_txs=1)
        self.assertTrue(chain_state._lifecycle_manager.scheduled_updates,
                        "vote did not schedule the update")

        # Block 4: empty block crosses the activation height — the engine
        # pushes the new spec into the LIVE interpreter via i0.
        self._mine(expect_txs=0)
        self.assertIn("#x000014", chain_state.get_consensus_rules_state())

        # Block 5: user tx now pays the governance-voted fee (20).
        res = sendtx.queue_transaction(self._tx(100, 50), propagate=False)
        self.assertTrue(res["ok"], f"queue failed: {res}")
        self.assertEqual(db.get_mempool_entries()[0]["estimated_fee"], 20,
                         "admission estimate did not follow the voted fee")
        self._mine(expect_txs=1)

        self.assertEqual(chain_state.get_balance(config.MINER_PUBKEY), 30)  # 10 + 20
        self.assertEqual(chain_state.get_balance(self.sender), start - 200 - 30)
        self.assertEqual(chain_state.get_balance(RECIPIENT), 200)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestGenesisGenO9Tests(_NativeFeeE2EBase):
    def test_gen_genesis_o9_parses_on_real_tau(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = os.path.join(tmpdir, "genesis.json")
            validator_key = "a" * 96
            # Run the generator as a SUBPROCESS: gen_genesis.main() ends in
            # os._exit(0) (native-binding segfault workaround), which would
            # terminate the pytest process if called in-process.
            import subprocess
            script_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), "..", "scripts", "gen_genesis.py")
            )
            test_argv = [
                "--validator-key", validator_key,
                "--genesis-rules-path", "genesis.tau",
                "--genesis-consensus-path", "genesis_consensus.tau",
                "--out", out_json,
                "--base-fee", "10",
            ]
            result = subprocess.run(
                [sys.executable, script_path] + test_argv,
                capture_output=True, text=True, env=os.environ,
            )
            self.assertEqual(result.returncode, 0, f"gen_genesis failed: {result.stderr}")


            self.assertTrue(os.path.exists(out_json))
            with open(out_json, "r") as f:
                genesis_data = json.load(f)
            
            consensus_rules = genesis_data.get("consensus_rules", "")
            preprocessed_rules = chain_state._preprocess_tau_spec_text(consensus_rules)
            
            self._seed_rule(preprocessed_rules, "test-gen-genesis-fee")
            
            inputs = {
                1: ["0"],
                2: ["0"],
                3: ["0"],
                4: ["0"],
                5: ["0"],
            }
            outputs = tau_manager.communicate_with_tau_multi(
                input_stream_values=inputs,
                apply_rules_update=False
            )
            
            self.assertIn(9, outputs)
            fee_val = tau_manager.parse_tau_output(outputs[9])
            self.assertEqual(fee_val, 10)


if __name__ == "__main__":
    unittest.main()
