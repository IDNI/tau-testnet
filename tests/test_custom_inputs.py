
import unittest
from unittest.mock import MagicMock, patch
import json
import logging
import sys
import os

# Assume dependencies exist in the environment (as seen in user logs).
# If not, we should install them, but mocking sys.modules globally is dangerous.

from commands import sendtx
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot
import chain_state
import tau_manager

class TestCustomInputs(unittest.TestCase):

    def setUp(self):
        # Patch tau_manager.communicate_with_tau specific to this test instance
        self.comm_patcher = patch('tau_manager.communicate_with_tau', return_value="x1001")
        self.mock_communicate = self.comm_patcher.start()
        
        self.ready_patcher = patch('tau_manager.tau_ready')
        self.mock_tau_ready = self.ready_patcher.start()
        self.mock_tau_ready.is_set.return_value = True

        self.env_patcher = patch.dict('os.environ', {'TAU_FORCE_TEST': '0'})
        self.env_patcher.start()

        # tau_test_mode may be left True by other test modules that ran a
        # TAU_FORCE_TEST tau_manager loop; force it off so sendtx takes the
        # isolated-compile validation path this test asserts on.
        self.test_mode_patcher = patch.object(tau_manager, 'tau_test_mode', False)
        self.test_mode_patcher.start()

        # Rule validation now runs through the isolated subprocess compile.
        # Mock it so the test is deterministic and does not spawn a child / need
        # a native tau build. None == validated OK.
        self.isolated_patcher = patch(
            'tau_native.compile_revisions_isolated_subprocess', return_value=None
        )
        self.mock_isolated = self.isolated_patcher.start()

        # Ensure we clean up patches
        self.addCleanup(self.comm_patcher.stop)
        self.addCleanup(self.ready_patcher.stop)
        self.addCleanup(self.env_patcher.stop)
        self.addCleanup(self.test_mode_patcher.stop)
        self.addCleanup(self.isolated_patcher.stop)

        # Crypto is mandatory now: mock signature verification instead of disabling it.
        self.crypto_patcher = patch('commands.sendtx.G2Basic')
        mock_bls = self.crypto_patcher.start()
        mock_bls.Verify.return_value = True
        self.addCleanup(self.crypto_patcher.stop)
        self.seq_patcher = patch('commands.sendtx.chain_state.get_sequence_number', return_value=1)
        self.seq_patcher.start()
        self.addCleanup(self.seq_patcher.stop)
        self.pending_seq_patcher = patch('commands.sendtx.db.get_pending_sequence', return_value=None)
        self.pending_seq_patcher.start()
        self.addCleanup(self.pending_seq_patcher.stop)
        
    def test_sendtx_reject_reserved_keys(self):
        """Test that sendtx rejects reserved keys 2, 3, 4 (custom-parse, TX_INVALID)."""
        # 0 and 1 are allowed (Rules, Transfers). 2-4 pass admission then get
        # rejected by the sendtx custom-input parse.
        for key in ["2", "3", "4"]:
            payload = {
                "sender_pubkey": "a" * 96,
                "sequence_number": 1,
                "expiration_time": 9999999999,
                "operations": {key: "val"},
                "fee_limit": 100,
                "signature": "00" * 48
            }
            json_blob = json.dumps(payload)
            with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
                with patch('commands.sendtx.db.add_mempool_tx'):
                    result = sendtx.queue_transaction(json_blob, propagate=False)
            self.assertFalse(result["ok"])
            self.assertEqual(result["code"], "TX_INVALID")
            self.assertIn(f"Stream {key} is reserved", result["message"])

    def test_sendtx_reject_key_12_spoof(self):
        """operations["12"] (sender-pubkey stream) is rejected at the authoritative
        admission gate before it can reach the custom-input merge and spoof i12."""
        payload = {
            "sender_pubkey": "a" * 96,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": {"12": "deadbeef"},
            "fee_limit": 100,
            "signature": "00" * 48,
        }
        with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
            with patch('commands.sendtx.db.add_mempool_tx'):
                result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        self.assertFalse(result["ok"])
        self.assertIn("12", result["message"])

    def test_sendtx_reject_keys_14_15_stake_mode(self):
        """operations["14"]/["15"] (consensus stake/mode inputs) are rejected at
        admission before they can pin a conflicting bv width process-wide."""
        for key in ("14", "15"):
            payload = {
                "sender_pubkey": "a" * 96,
                "sequence_number": 1,
                "expiration_time": 9999999999,
                "operations": {key: "5"},
                "fee_limit": 100,
                "signature": "00" * 48,
            }
            with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
                with patch('commands.sendtx.db.add_mempool_tx'):
                    result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
            self.assertFalse(result["ok"], msg=f"key {key} accepted")
            self.assertIn(key, result["message"])

    def test_engine_apply_rejects_reserved_stake_stream(self):
        """Apply-time defense: operations["14"]/["15"] are hard-rejected in
        engine.apply so it agrees with the sendtx/admission gate."""
        for key in ("14", "15"):
            mock_store = MagicMock()
            mock_store.commit.return_value = TauStateSnapshot(b"", b"", {})
            engine = TauConsensusEngine(state_store=mock_store)
            snapshot = TauStateSnapshot(b"hash", b"rules", {})
            tx = {"tx_id": f"tx_{key}", "operations": {key: "5"}}
            result = engine.apply(snapshot, [tx], 1700000000)
            self.assertEqual(len(result.rejected_transactions), 1, msg=f"key {key} not rejected")
            receipt = result.receipts[f"tx_{key}"]
            self.assertEqual(receipt["status"], "failed")
            self.assertIn(f"reserved stream {key}", " ".join(receipt["logs"]))

    def test_sendtx_accept_custom_keys(self):
        """Test that sendtx accepts keys >= 5 and normalizes values."""
        
        payload = {
            "sender_pubkey": "A" * 96,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": {
                "100": "42",
                "200": ["a", 1]
            },
            "fee_limit": 100,
            "signature": "00" * 48,
            "sender_pubkey": "a" * 96 # Valid-ish hex
        }
        
        # Mock validators to pass structure checks
        with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
             with patch('commands.sendtx.db.add_mempool_tx'):
                result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        
        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")
        
        # Check call arguments to tau_manager
        # operations["0"] is missing, so only one call to communicate_with_tau expected (Step 2)
        self.mock_communicate.assert_called_once()
        args, kwargs = self.mock_communicate.call_args
        
        # In sendtx logic: 
        # rule_text=None, target_output_stream_index=0, input_stream_values=custom_tau_inputs
        self.assertIsNone(kwargs['rule_text'])
        self.assertEqual(kwargs['target_output_stream_index'], 0)
        self.assertEqual(kwargs['source'], payload['sender_pubkey'])
        inputs = kwargs['input_stream_values']
        self.assertIn(100, inputs)
        self.assertEqual(inputs[100], ["42"]) # Normalized to list of str
        self.assertIn(200, inputs)
        self.assertEqual(inputs[200], ["a", "1"]) # Normalized

    def test_sendtx_two_step_validation(self):
        """Rules are validated by the isolated compile; custom inputs by the live
        path. The rule no longer goes through communicate_with_tau, and the live
        validate-then-restore is skipped entirely on the isolated path."""
        payload = {
            "sender_pubkey": "a" * 96,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": {
                "0": "some rule",
                "100": "42"
            },
            "fee_limit": 100,
            "signature": "00" * 48
        }

        with patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)):
             with patch('commands.sendtx.db.add_mempool_tx'):
                 with patch('tau_manager.reset_tau_state') as mock_reset:
                    result = sendtx.queue_transaction(json.dumps(payload), propagate=False)

        self.assertTrue(result["ok"], msg=f"queue_transaction failed: {result}")

        # Rule validated via isolated subprocess compile (once, with the rule).
        self.mock_isolated.assert_called_once()
        iso_args, _iso_kwargs = self.mock_isolated.call_args
        self.assertEqual(iso_args[1], ["some rule"])

        # communicate_with_tau is now used only for the custom-input step.
        self.assertEqual(self.mock_communicate.call_count, 1)
        _, kwargs = self.mock_communicate.call_args
        self.assertIsNone(kwargs['rule_text'])
        self.assertEqual(kwargs['input_stream_values'][100], ["42"])
        self.assertEqual(kwargs['source'], payload['sender_pubkey'])

        # Isolated path never mutates live state, so no restore is performed.
        mock_reset.assert_not_called()

    def test_engine_apply_execution_order(self):
        """Test TauConsensusEngine.apply executes Rule then Custom Inputs and captures receipts."""
        
        mock_store = MagicMock()
        mock_store.commit.return_value = TauStateSnapshot(b"", b"", {}) 
        engine = TauConsensusEngine(state_store=mock_store)
        
        snapshot = TauStateSnapshot(b"hash", b"rules", {})
        tx = {
            "tx_id": "tx1",
            "operations": {
                "0": "new rule",
                "100": "99"
            }
        }
        
        # Mock communicate_with_tau to return distinct outputs
        self.mock_communicate.side_effect = ["output_rule", "output_custom"]
        
        result = engine.apply(snapshot, [tx], 1700000000)
        
        receipt = result.receipts["tx1"]
        logs = receipt["logs"]
        
        # Verify call order and logs
        self.assertEqual(self.mock_communicate.call_count, 2)
        
        # Call 1: Rule
        args1, kwargs1 = self.mock_communicate.call_args_list[0]
        self.assertEqual(kwargs1['rule_text'], "new rule")
        self.assertEqual(kwargs1['apply_rules_update'], True)
        self.assertIn("Tau(rule) o0: output_rule", logs)
        
        # Call 2: Custom
        args2, kwargs2 = self.mock_communicate.call_args_list[1]
        self.assertNotIn('rule_text', kwargs2)
        self.assertEqual(kwargs2['input_stream_values'][100], ["99"])
        self.assertEqual(kwargs2['apply_rules_update'], False)
        self.assertIn("Tau(custom_unified) o0: output_custom", logs)
        
        self.assertIn("Rule applied", logs)
        
    def test_engine_apply_tau_error_on_custom_input(self):
        """Test TauConsensusEngine.apply fails transaction if Tau returns explicit Error on custom input."""
        mock_store = MagicMock()
        mock_store.commit.return_value = TauStateSnapshot(b"", b"", {}) 
        engine = TauConsensusEngine(state_store=mock_store)
        
        snapshot = TauStateSnapshot(b"hash", b"rules", {})
        tx = {
            "tx_id": "tx_fail",
            "operations": {
                "100": "bad_input"
            }
        }
        
        # Mock communicate_with_tau to return Error
        self.mock_communicate.return_value = "(Error) Invalid input"
        
        result = engine.apply(snapshot, [tx], 1700000000)
        
        # New behavior: Tx execution fails on Tau Error, but is accepted into block (nonce consumed)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(len(result.rejected_transactions), 0)
        
        receipt = result.receipts["tx_fail"]
        self.assertEqual(receipt["status"], "failed")
        self.assertIn("Custom logic error: (Error) Invalid input", receipt["logs"])

class TestCustomInputUnification(unittest.TestCase):
    """Issue #16: custom input streams (i13+) are merged into the SAME per-transfer
    Tau step as the transfer at sendtx admission, so a rule combining a custom
    stream with the transfer fields gates `sendtx`, not just block apply."""

    def setUp(self):
        import importlib, hashlib
        importlib.reload(sendtx)
        import config, db, tau_defs
        from py_ecc.bls import G2Basic as bls
        from commands.sendtx import _get_signing_message_bytes

        self._bls = bls
        self._tau_defs = tau_defs
        self._db = db
        self._config = config
        self._sk = bls.KeyGen(b"unify_sender")
        self._sender = bls.SkToPk(self._sk).hex()
        self._addr_a = bls.SkToPk(bls.KeyGen(b"unify_A")).hex()

        self.test_db = "test_custom_unify_db.sqlite"
        self._orig_db_path = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if db._db_conn:
            db._db_conn.close(); db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        chain_state._balances.clear(); chain_state._sequence_numbers.clear()
        db.init_db(); chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()
        chain_state._balances[self._sender] = 1000

        def _sign(tx_dict):
            msg_hash = hashlib.sha256(_get_signing_message_bytes(tx_dict)).digest()
            tx_dict["signature"] = bls.Sign(self._sk, msg_hash).hex()
            return json.dumps(tx_dict)
        self._sign = _sign

        patch('commands.sendtx._validate_bls12_381_pubkey', return_value=(True, None)).start()
        # Rule (op "0") validation goes through the isolated compile; None == OK.
        patch('tau_native.compile_revisions_isolated_subprocess', return_value=None).start()
        # Other test modules can leave TAU_FORCE_TEST / tau_test_mode on, which
        # would skip the transfer validation this class asserts on. Force off.
        patch.dict('os.environ', {'TAU_FORCE_TEST': '0'}).start()
        patch.object(tau_manager, 'tau_test_mode', False).start()
        self.addCleanup(patch.stopall)

    def tearDown(self):
        if self._db._db_conn:
            self._db._db_conn.close(); self._db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self._config.set_database_path(self._orig_db_path)

    def _tx(self, transfers, custom=None):
        ops = {"1": transfers}
        if custom:
            ops.update(custom)
        return self._sign({
            "tx_type": "user_tx",
            "sender_pubkey": self._sender,
            "sequence_number": chain_state.get_sequence_number(self._sender),
            "expiration_time": 9999999999,
            "operations": ops,
            "fee_limit": "0",
        })

    def test_custom_input_merged_into_transfer_step(self):
        """A transfer tx carrying operations["13"] feeds i13 into the SAME
        communicate_with_tau_multi call as the transfer fields, and the separate
        custom-only step (communicate_with_tau) is NOT run."""
        captured = []

        def mock_multi(input_stream_values=None, **kwargs):
            captured.append(dict(input_stream_values or {}))
            return {1: self._tau_defs.TAU_VALUE_ONE}
        single = patch('tau_manager.communicate_with_tau', return_value="x1001").start()
        patch('tau_manager.communicate_with_tau_multi', side_effect=mock_multi).start()
        patch('tau_manager.tau_ready').start().is_set.return_value = True

        tx = self._tx([[self._sender, self._addr_a, "10"]], custom={"13": "7"})
        result = sendtx.queue_transaction(tx, propagate=False)

        self.assertTrue(result["ok"], msg=f"queue failed: {result}")
        self.assertEqual(len(captured), 1, "one transfer -> one multi call")
        inputs = captured[0]
        # Custom stream present alongside the transfer/context streams.
        self.assertEqual(inputs.get(13), ["7"])
        for reserved in (1, 2, 3, 4, 5, 12):
            self.assertIn(reserved, inputs, f"transfer step must set i{reserved}")
        # Transfer tx must NOT run the separate custom-only validation step.
        single.assert_not_called()

    def test_custom_input_merged_every_transfer(self):
        """Multi-transfer tx: i13 is present in every per-transfer eval."""
        captured = []

        def mock_multi(input_stream_values=None, **kwargs):
            captured.append(dict(input_stream_values or {}))
            return {1: self._tau_defs.TAU_VALUE_ONE}
        patch('tau_manager.communicate_with_tau', return_value="x1001").start()
        patch('tau_manager.communicate_with_tau_multi', side_effect=mock_multi).start()
        patch('tau_manager.tau_ready').start().is_set.return_value = True

        tx = self._tx(
            [[self._sender, self._addr_a, "10"], [self._sender, self._addr_a, "5"]],
            custom={"13": "7"},
        )
        result = sendtx.queue_transaction(tx, propagate=False)
        self.assertTrue(result["ok"], msg=f"queue failed: {result}")
        self.assertEqual(len(captured), 2)
        for inputs in captured:
            self.assertEqual(inputs.get(13), ["7"])

    def test_policy_block_driven_by_custom_input(self):
        """o5 block (driven by a custom-input-dependent rule) rejects the tx at
        admission — reachable only because i13 is in the transfer step."""
        def mock_multi(input_stream_values=None, **kwargs):
            # Emulate a rule that blocks (o5=0) when i13 is present.
            if (input_stream_values or {}).get(13):
                return {1: self._tau_defs.TAU_VALUE_ONE,
                        self._tau_defs.USER_POLICY_STREAM_INDEX: "0"}
            return {1: self._tau_defs.TAU_VALUE_ONE}
        patch('tau_manager.communicate_with_tau', return_value="x1001").start()
        patch('tau_manager.communicate_with_tau_multi', side_effect=mock_multi).start()
        patch('tau_manager.tau_ready').start().is_set.return_value = True

        tx = self._tx([[self._sender, self._addr_a, "10"]], custom={"13": "7"})
        result = sendtx.queue_transaction(tx, propagate=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_REJECTED")
        self.assertIn("user policy", result["message"].lower())

    def test_garbage_custom_input_on_transfer_tx_rejected(self):
        """A Tau failure while evaluating the merged transfer+custom step rejects
        the tx rather than silently admitting it."""
        def mock_multi(input_stream_values=None, **kwargs):
            raise tau_manager.TauCommunicationError("bad custom stream")
        patch('tau_manager.communicate_with_tau', return_value="x1001").start()
        patch('tau_manager.communicate_with_tau_multi', side_effect=mock_multi).start()
        patch('tau_manager.tau_ready').start().is_set.return_value = True

        tx = self._tx([[self._sender, self._addr_a, "10"]], custom={"13": "7"})
        result = sendtx.queue_transaction(tx, propagate=False)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "TX_REJECTED")


class TestKey12Rejection(unittest.TestCase):
    """Issue #16 hardening: operations["12"] (sender-pubkey stream) is rejected on
    every path so it cannot spoof the i12 policy stream at apply."""

    def test_admission_rejects_key_12(self):
        from consensus import admission
        tx = {"tx_type": "user_tx", "operations": {"1": [], "12": "deadbeef"}}
        res = admission.validate_user_tx_reserved_domains(tx, None)
        self.assertFalse(res.is_valid)
        self.assertIn("12", res.error)

    def test_engine_apply_rejects_key_12(self):
        mock_store = MagicMock()
        mock_store.commit.return_value = TauStateSnapshot(b"", b"", {})
        engine = TauConsensusEngine(state_store=mock_store)
        snapshot = TauStateSnapshot(b"hash", b"rules", {})
        tx = {"tx_id": "tx_spoof", "operations": {"12": "deadbeef"}}
        result = engine.apply(snapshot, [tx], 1700000000)
        receipt = result.receipts["tx_spoof"]
        self.assertIn("Error", " ".join(receipt["logs"]))
        # Hard-rejected: lands in rejected_transactions, not accepted.
        self.assertIn(tx, result.rejected_transactions)
        self.assertNotIn(tx, result.accepted_transactions)


if __name__ == '__main__':
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
