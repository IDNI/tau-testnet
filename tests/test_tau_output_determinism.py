import os
import sys
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
import tau_defs
from commands import sendtx

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")


class _TauDeterminismBase(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_determinism_db.sqlite"
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

        # Live interpreter from the real genesis program
        tau_manager.tau_direct_interface = tau_native.TauInterface(GENESIS_TAU)
        tau_manager.tau_ready.set()
        self._seed_rule(open(TRANSFER_RULE_PATH).read(), "transfer-rule")

        # Force NO TAU_FORCE_TEST
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()

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


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestTauOutputDeterminism(_TauDeterminismBase):

    def test_determinism_same_instance_repeated_inputs(self):
        rule = "always (o1[t] = i1[t] > i2[t])."
        self._seed_rule(rule, "same-instance-det")

        # target_output_stream_index=1 is o1
        inputs = {1: ["100"], 2: ["50"]}
        tau_manager.tau_ready.set()
        
        result1 = tau_manager.communicate_with_tau(
            rule_text=None,
            target_output_stream_index=1,
            input_stream_values=inputs,
            apply_rules_update=False
        )
        result2 = tau_manager.communicate_with_tau(
            rule_text=None,
            target_output_stream_index=1,
            input_stream_values=inputs,
            apply_rules_update=False
        )
        self.assertEqual(result1, result2)

    def test_determinism_fresh_instances_identical_inputs(self):
        rule = "always (o1[t] = i1[t] > i2[t])."
        
        interface1 = tau_native.TauInterface(GENESIS_TAU)
        interface2 = tau_native.TauInterface(GENESIS_TAU)
        
        # Preprocess rule
        prep_rule = interface1.preprocess_spec_text(rule)
        
        # Seed both interfaces
        interface1.communicate(rule_text=prep_rule, target_output_stream_index=0, apply_rules_update=False)
        interface2.communicate(rule_text=prep_rule, target_output_stream_index=0, apply_rules_update=False)
        
        inputs = {1: ["100"], 2: ["50"]}
        result1 = interface1.communicate_multi(rule_text=None, input_stream_values=inputs, apply_rules_update=False)
        result2 = interface2.communicate_multi(rule_text=None, input_stream_values=inputs, apply_rules_update=False)
        
        self.assertEqual(result1, result2)

    def test_determinism_o5_user_policy(self):
        # o5 is index 5
        rule = "always ((i3[t] = {#x0011}:bv[16] && i1[t] > {1000}:bv[16]) ? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16])."
        
        interface1 = tau_native.TauInterface(GENESIS_TAU)
        interface2 = tau_native.TauInterface(GENESIS_TAU)
        
        prep_rule = interface1.preprocess_spec_text(rule)
        interface1.communicate(rule_text=prep_rule, target_output_stream_index=0, apply_rules_update=False)
        interface2.communicate(rule_text=prep_rule, target_output_stream_index=0, apply_rules_update=False)
        
        inputs = {
            1: ["2000"],
            3: ["#x0011"]
        }
        result1 = interface1.communicate_multi(rule_text=None, input_stream_values=inputs, apply_rules_update=False)
        result2 = interface2.communicate_multi(rule_text=None, input_stream_values=inputs, apply_rules_update=False)
        
        self.assertEqual(result1.get(5), result2.get(5))

    def test_determinism_o9_consensus_fee(self):
        # o9 is index 9
        rule = "always (o9[t]:bv[16] = { #x000a }:bv[16])."
        
        interface1 = tau_native.TauInterface(GENESIS_TAU)
        interface2 = tau_native.TauInterface(GENESIS_TAU)
        
        prep_rule = interface1.preprocess_spec_text(rule)
        interface1.communicate(rule_text=prep_rule, target_output_stream_index=0, apply_rules_update=False)
        interface2.communicate(rule_text=prep_rule, target_output_stream_index=0, apply_rules_update=False)
        
        inputs = {
            1: ["100"],
            5: ["1700000000"]
        }
        result1 = interface1.communicate_multi(rule_text=None, input_stream_values=inputs, apply_rules_update=False)
        result2 = interface2.communicate_multi(rule_text=None, input_stream_values=inputs, apply_rules_update=False)
        
        self.assertEqual(result1.get(9), result2.get(9))
