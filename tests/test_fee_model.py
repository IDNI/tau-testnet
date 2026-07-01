"""
Fee model tests: parsing helpers, engine charging/receipts/staging,
admission checks, mempool priority and migration, createblock ordering.

Fee source is Tau: consensus rules emit the network fee on o9 (strict),
user rules may add a custom fee on o8 (lenient). Tests inject both via
communicate_with_tau_multi mocks.
"""
import json
import os
import sqlite3
import unittest
from unittest.mock import MagicMock, patch

import pytest

import config
import chain_state
import db
import tau_defs
from consensus import fees
from consensus.engine import TauConsensusEngine
from consensus.fees import FeeRuleError
from consensus.state import TauStateSnapshot

SENDER = "a" * 96
RECIPIENT = "c" * 96
PROPOSER = "b" * 96


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------

class TestFeeParsers(unittest.TestCase):
    def test_parse_fee_limit_variants(self):
        self.assertEqual(fees.parse_fee_limit("10"), 10)
        self.assertEqual(fees.parse_fee_limit(10), 10)
        self.assertEqual(fees.parse_fee_limit("0"), 0)
        self.assertEqual(fees.parse_fee_limit("+7"), 7)
        self.assertIsNone(fees.parse_fee_limit("-1"))
        self.assertIsNone(fees.parse_fee_limit(-1))
        self.assertIsNone(fees.parse_fee_limit("abc"))
        self.assertIsNone(fees.parse_fee_limit("1.5"))
        self.assertIsNone(fees.parse_fee_limit(True))
        self.assertIsNone(fees.parse_fee_limit(None))
        self.assertIsNone(fees.parse_fee_limit(2 ** 63))
        self.assertEqual(fees.parse_fee_limit(2 ** 63 - 1), 2 ** 63 - 1)
        self.assertIsNone(fees.parse_fee_limit(""))
        self.assertIsNone(fees.parse_fee_limit([10]))

    def test_parse_consensus_fee_strict(self):
        self.assertEqual(fees.parse_consensus_fee(None), 0)  # absent = inactive
        self.assertEqual(fees.parse_consensus_fee("10"), 10)
        self.assertEqual(fees.parse_consensus_fee("{ #x0a }:bv[24]"), 10)
        self.assertEqual(fees.parse_consensus_fee("#b101"), 5)
        self.assertEqual(fees.parse_consensus_fee("result: 3"), 3)
        with self.assertRaises(FeeRuleError):
            fees.parse_consensus_fee("garbage")
        with self.assertRaises(FeeRuleError):
            fees.parse_consensus_fee("-4")
        with self.assertRaises(FeeRuleError):
            fees.parse_consensus_fee(str(2 ** 64))
        with self.assertRaises(FeeRuleError):
            fees.parse_consensus_fee("")

    def test_parse_custom_fee_lenient(self):
        self.assertEqual(fees.parse_custom_fee(None), 0)  # absent, silent
        self.assertEqual(fees.parse_custom_fee("7"), 7)
        self.assertEqual(fees.parse_custom_fee("{ #x07 }:bv[64]"), 7)
        # Garbage / negative / overflow normalize to 0 with a warning.
        with self.assertLogs("consensus.fees", level="WARNING"):
            self.assertEqual(fees.parse_custom_fee("junk"), 0)
        with self.assertLogs("consensus.fees", level="WARNING"):
            self.assertEqual(fees.parse_custom_fee("-4"), 0)
        with self.assertLogs("consensus.fees", level="WARNING"):
            self.assertEqual(fees.parse_custom_fee(str(2 ** 64)), 0)


# ---------------------------------------------------------------------------
# Engine charging
# ---------------------------------------------------------------------------

class EngineFeeBase(unittest.TestCase):
    """Direct engine.apply() harness with mocked Tau."""

    def setUp(self):
        self.ready_patcher = patch("tau_manager.tau_ready")
        self.mock_ready = self.ready_patcher.start()
        self.mock_ready.is_set.return_value = True
        self.addCleanup(self.ready_patcher.stop)

        self.multi_patcher = patch(
            "tau_manager.communicate_with_tau_multi", return_value={1: "1"}
        )
        self.mock_multi = self.multi_patcher.start()
        self.addCleanup(self.multi_patcher.stop)

        self.comm_patcher = patch(
            "tau_manager.communicate_with_tau", return_value="ok"
        )
        self.mock_comm = self.comm_patcher.start()
        self.addCleanup(self.comm_patcher.stop)

        # Fee settlement reads plain balances; the faucet shim would mask
        # insufficiency cases.
        self.original_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False
        self.addCleanup(lambda: setattr(config, "TESTNET_AUTO_FAUCET", self.original_faucet))

        mock_store = MagicMock()
        mock_store.commit.side_effect = lambda snap: snap
        self.engine = TauConsensusEngine(state_store=mock_store)
        self.snapshot = TauStateSnapshot(b"hash", b"rules", {})

    def transfer_tx(self, amount=100, fee_limit="50", seq=0, sender=SENDER,
                    recipient=RECIPIENT, tx_id="tx1", transfers=None):
        return {
            "tx_id": tx_id,
            "tx_type": "user_tx",
            "sender_pubkey": sender,
            "sequence_number": seq,
            "fee_limit": fee_limit,
            "operations": {"1": transfers if transfers is not None
                           else [[sender, recipient, amount]]},
        }

    def apply(self, txs, balances, seqs=None, proposer=PROPOSER, height=1,
              replay_mode=False):
        return self.engine.apply(
            self.snapshot, txs, 1700000000,
            target_balances=balances,
            target_sequences=seqs if seqs is not None else {},
            replay_mode=replay_mode,
            proposer_pubkey=proposer,
            block_height=height,
        )


class TestEngineFeeCharging(EngineFeeBase):
    def test_consensus_fee_deducted_and_proposer_credited(self):
        self.mock_multi.return_value = {1: "1", 9: "10"}
        balances = {SENDER: 1000}
        seqs = {}
        result = self.apply([self.transfer_tx()], balances, seqs)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 1000 - 100 - 10)
        self.assertEqual(balances[RECIPIENT], 100)
        self.assertEqual(balances[PROPOSER], 10)
        self.assertEqual(seqs[SENDER], 1)
        self.assertEqual(result.receipts["tx1"]["fee_charged"], 10)

    def test_o9_absent_zero_fee_legacy_identical(self):
        self.mock_multi.return_value = {1: "1"}
        balances = {SENDER: 1000}
        result = self.apply([self.transfer_tx()], balances)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 900)
        self.assertEqual(balances[RECIPIENT], 100)
        self.assertNotIn(PROPOSER, balances)
        self.assertNotIn("fee_charged", result.receipts["tx1"])

    def test_custom_o8_added_to_consensus_o9(self):
        self.mock_multi.return_value = {1: "1", 8: "5", 9: "10"}
        balances = {SENDER: 1000}
        result = self.apply([self.transfer_tx(fee_limit="20")], balances)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 1000 - 100 - 15)
        self.assertEqual(balances[PROPOSER], 15)
        self.assertEqual(result.receipts["tx1"]["fee_charged"], 15)

    def test_multi_transfer_fee_summed_per_step(self):
        # Tiered rule: o9 varies with i1 per step.
        def tiered(**kwargs):
            amount = int(kwargs["input_stream_values"][1])
            return {1: "1", 9: "20" if amount > 50 else "10"}
        self.mock_multi.side_effect = tiered
        balances = {SENDER: 1000}
        tx = self.transfer_tx(
            fee_limit="100",
            transfers=[[SENDER, RECIPIENT, 60], [SENDER, RECIPIENT, 40]],
        )
        result = self.apply([tx], balances)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 1000 - 100 - 30)  # 20 + 10
        self.assertEqual(balances[PROPOSER], 30)
        self.assertEqual(result.receipts["tx1"]["fee_charged"], 30)

    def test_fee_cap_exceeded_rejected_without_charging(self):
        self.mock_multi.return_value = {1: "1", 8: "50"}
        balances = {SENDER: 1000}
        seqs = {}
        result = self.apply([self.transfer_tx(fee_limit="10")], balances, seqs)
        self.assertEqual(len(result.rejected_transactions), 1)
        receipt = result.receipts["tx1"]
        self.assertEqual(receipt["status"], "failed")
        self.assertEqual(receipt["reason"], "fee_limit_exceeded")
        self.assertEqual(receipt["fee_charged"], 0)
        # Zero writes: no transfer, no fee, no sequence increment.
        self.assertEqual(balances, {SENDER: 1000})
        self.assertEqual(seqs, {})

    def test_insufficient_for_fee_rejected_no_pollution(self):
        self.mock_multi.return_value = {1: "1", 9: "10"}
        balances = {SENDER: 100}
        result = self.apply([self.transfer_tx(amount=100)], balances)
        self.assertEqual(len(result.rejected_transactions), 1)
        receipt = result.receipts["tx1"]
        self.assertEqual(receipt["reason"], "insufficient_funds_for_fee")
        self.assertEqual(receipt["fee_charged"], 0)
        self.assertEqual(balances, {SENDER: 100})

    def test_mid_tx_transfer_failure_no_pollution(self):
        self.mock_multi.return_value = {1: "1"}
        balances = {SENDER: 100}
        tx = self.transfer_tx(
            transfers=[[SENDER, RECIPIENT, 60], [SENDER, RECIPIENT, 60]],
        )
        result = self.apply([tx], balances)
        self.assertEqual(len(result.rejected_transactions), 1)
        self.assertEqual(balances, {SENDER: 100})

    def test_malformed_fee_limit_rejected(self):
        balances = {SENDER: 1000}
        for bad in ("abc", "-5"):
            result = self.apply(
                [self.transfer_tx(fee_limit=bad, tx_id=f"tx_{bad}")], balances
            )
            receipt = result.receipts[f"tx_{bad}"]
            self.assertEqual(receipt["reason"], "invalid_fee_limit")
            self.assertEqual(receipt["fee_charged"], 0)
            self.assertEqual(balances, {SENDER: 1000})

    def test_fee_cap_failure_does_not_increment_sequence(self):
        self.mock_multi.return_value = {1: "1", 9: "100"}
        balances = {SENDER: 1000}
        seqs = {SENDER: 5}
        result = self.apply(
            [self.transfer_tx(fee_limit="10", seq=5)], balances, seqs
        )
        self.assertEqual(len(result.rejected_transactions), 1)
        self.assertEqual(seqs, {SENDER: 5})

    def test_governance_tx_exempt(self):
        self.mock_multi.return_value = {1: "1", 9: "10"}
        lifecycle = MagicMock()
        lifecycle.can_admit_vote.return_value = True
        lifecycle.submit_vote.return_value = True
        balances = {}  # zero-balance validator
        tx = {
            "tx_id": "gov1",
            "tx_type": "consensus_rule_vote",
            "sender_pubkey": SENDER,
            "fee_limit": "0",
            "update_id": "ab" * 32,
            "approve": True,
        }
        result = self.engine.apply(
            self.snapshot, [tx], 1700000000,
            target_balances=balances,
            target_sequences={},
            target_lifecycle=lifecycle,
            proposer_pubkey=PROPOSER,
            block_height=1,
        )
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances, {})  # no fee writes

    def test_sender_equals_proposer_nets_zero(self):
        self.mock_multi.return_value = {1: "1", 9: "10"}
        balances = {SENDER: 1000}
        result = self.apply([self.transfer_tx()], balances, proposer=SENDER)
        self.assertEqual(len(result.accepted_transactions), 1)
        # Fee nets to zero; only the transfer amount moves.
        self.assertEqual(balances[SENDER], 900)
        self.assertEqual(balances[RECIPIENT], 100)
        self.assertEqual(result.receipts["tx1"]["fee_charged"], 10)

    def test_transfer_less_tx_charged_via_fee_query(self):
        self.mock_multi.return_value = {9: "7"}
        balances = {SENDER: 1000}
        tx = {
            "tx_id": "tx_norule",
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": 0,
            "fee_limit": "10",
            "operations": {"100": "42"},
        }
        result = self.apply([tx], balances)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 993)
        self.assertEqual(balances[PROPOSER], 7)
        self.assertEqual(result.receipts["tx_norule"]["fee_charged"], 7)
        # Canonical mocked transfer inputs on the fee-query step.
        _, kwargs = self.mock_multi.call_args
        inputs = kwargs["input_stream_values"]
        self.assertEqual(inputs[1], "0")
        self.assertEqual(inputs[2], "0")
        self.assertIn("#x" + SENDER, inputs[12])

    def test_o8_garbage_charges_consensus_fee_only(self):
        self.mock_multi.return_value = {1: "1", 8: "junk", 9: "10"}
        balances = {SENDER: 1000}
        result = self.apply([self.transfer_tx(fee_limit="20")], balances)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(result.receipts["tx1"]["fee_charged"], 10)

    def test_o9_garbage_raises_fee_rule_error(self):
        self.mock_multi.return_value = {1: "1", 9: "garbage"}
        with self.assertRaises(FeeRuleError):
            self.apply([self.transfer_tx()], {SENDER: 1000})

    def test_tau_down_mid_apply_raises(self):
        self.mock_ready.is_set.return_value = False
        self.mock_ready.wait.return_value = False
        with self.assertRaises(FeeRuleError):
            self.apply([self.transfer_tx()], {SENDER: 1000})

    def test_replay_mode_tau_down_fee_zero(self):
        self.mock_ready.is_set.return_value = False
        self.mock_ready.wait.return_value = False
        balances = {SENDER: 1000}
        result = self.apply([self.transfer_tx()], balances, replay_mode=True)
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 900)
        self.assertNotIn(PROPOSER, balances)

    def test_replay_mode_soft_fails_fee_violations(self):
        self.mock_multi.return_value = {1: "1", 9: "100"}
        balances = {SENDER: 1000}
        result = self.apply(
            [self.transfer_tx(fee_limit="10")], balances, replay_mode=True
        )
        # Stored block is canonical: tx stays accepted, fee skipped.
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 900)
        self.assertNotIn(PROPOSER, balances)

    def test_legacy_apply_without_new_kwargs_unchanged(self):
        self.mock_multi.return_value = {1: "1", 9: "10"}
        balances = {SENDER: 1000}
        result = self.engine.apply(
            self.snapshot, [self.transfer_tx()], 1700000000,
            target_balances=balances, target_sequences={},
        )
        self.assertEqual(len(result.accepted_transactions), 1)
        self.assertEqual(balances[SENDER], 900)
        self.assertNotIn(PROPOSER, balances)


# ---------------------------------------------------------------------------
# Admission (sendtx)
# ---------------------------------------------------------------------------

class TestAdmissionFees(unittest.TestCase):
    def setUp(self):
        from commands import sendtx  # noqa: F401  (import check)
        self.ready_patcher = patch("tau_manager.tau_ready")
        self.mock_ready = self.ready_patcher.start()
        self.mock_ready.is_set.return_value = True
        self.addCleanup(self.ready_patcher.stop)

        self.comm_patcher = patch(
            "tau_manager.communicate_with_tau", return_value="x1001"
        )
        self.comm_patcher.start()
        self.addCleanup(self.comm_patcher.stop)

        self.multi_patcher = patch(
            "tau_manager.communicate_with_tau_multi", return_value={}
        )
        self.mock_multi = self.multi_patcher.start()
        self.addCleanup(self.multi_patcher.stop)

        self.iso_patcher = patch(
            "tau_native.compile_revisions_isolated_subprocess", return_value=None
        )
        self.iso_patcher.start()
        self.addCleanup(self.iso_patcher.stop)

        # Crypto is mandatory now: mock signature verification instead of disabling it.
        self.crypto_patcher = patch("commands.sendtx.G2Basic")
        mock_bls = self.crypto_patcher.start()
        mock_bls.Verify.return_value = True
        self.addCleanup(self.crypto_patcher.stop)

        # Sequence enforcement is on; pin the sender's expected sequence to match
        # the payload (sequence_number=1) and fund the sender (no auto-faucet).
        self.seq_patcher = patch(
            "commands.sendtx.chain_state.get_sequence_number", return_value=1
        )
        self.seq_patcher.start()
        self.addCleanup(self.seq_patcher.stop)
        self.pending_seq_patcher = patch(
            "commands.sendtx.db.get_pending_sequence", return_value=None
        )
        self.pending_seq_patcher.start()
        self.addCleanup(self.pending_seq_patcher.stop)
        import chain_state as _cs
        _cs._balances[SENDER] = 1_000_000

        self.pub_patcher = patch(
            "commands.sendtx._validate_bls12_381_pubkey", return_value=(True, None)
        )
        self.pub_patcher.start()
        self.addCleanup(self.pub_patcher.stop)

        self.env_patcher = patch.dict("os.environ", {"TAU_FORCE_TEST": "0"})
        self.env_patcher.start()
        self.addCleanup(self.env_patcher.stop)

    def queue(self, payload):
        from commands import sendtx
        with patch("commands.sendtx.db.add_mempool_tx") as mock_add:
            result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        return result, mock_add

    def payload(self, fee_limit="100", operations=None, tx_type="user_tx", **extra):
        p = {
            "sender_pubkey": SENDER,
            "sequence_number": 1,
            "expiration_time": 9999999999,
            "operations": operations if operations is not None else {"100": "42"},
            "fee_limit": fee_limit,
            "signature": "00" * 48,
        }
        if tx_type != "user_tx":
            p["tx_type"] = tx_type
            p.pop("operations")
        p.update(extra)
        return p

    def test_missing_fee_limit_rejected(self):
        p = self.payload()
        del p["fee_limit"]
        result, _ = self.queue(p)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_PARAMS")

    def test_malformed_fee_limit_rejected_user_and_gov(self):
        for bad in ("abc", "-1", 1.5):
            result, _ = self.queue(self.payload(fee_limit=bad))
            self.assertFalse(result["ok"], msg=f"fee_limit={bad!r}")
            self.assertEqual(result["code"], "INVALID_PARAMS")
        gov = self.payload(fee_limit="abc", tx_type="consensus_rule_vote",
                           update_id="ab" * 32, approve=True)
        result, _ = self.queue(gov)
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INVALID_PARAMS")

    def test_estimate_over_cap_rejected_with_required_fee(self):
        # Transfer-less fee query emits o9=50 + o8=7.
        self.mock_multi.return_value = {8: "7", 9: "50"}
        result, _ = self.queue(self.payload(fee_limit="10"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "FEE_LIMIT_TOO_LOW")
        self.assertEqual(result["details"]["required_fee"], 57)
        self.assertEqual(result["details"]["fee_limit"], 10)

    def test_adequate_fee_queued_with_estimate(self):
        self.mock_multi.return_value = {9: "50"}
        result, mock_add = self.queue(self.payload(fee_limit="100"))
        self.assertTrue(result["ok"], msg=f"queue failed: {result}")
        _, kwargs = mock_add.call_args
        self.assertEqual(kwargs["fee_limit"], 100)
        self.assertEqual(kwargs["estimated_fee"], 50)

    def test_insufficient_funds_rejected(self):
        self.mock_multi.return_value = {9: "50"}
        with patch("chain_state.get_balance", return_value=10):
            result, _ = self.queue(self.payload(fee_limit="100"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "INSUFFICIENT_FUNDS")
        self.assertEqual(result["details"]["balance"], 10)
        self.assertEqual(result["details"]["required"], 50)

    def test_o9_garbage_at_admission_rejected(self):
        self.mock_multi.return_value = {9: "garbage"}
        result, _ = self.queue(self.payload(fee_limit="100"))
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], "FEE_RULE_ERROR")

    def test_user_rule_text_writing_consensus_streams_rejected(self):
        for stream in ("o6", "o7", "o9"):
            rule = f"always ({stream}[t]:bv[16] = {{ #x0001 }}:bv[16])."
            result, _ = self.queue(
                self.payload(operations={"0": rule})
            )
            self.assertFalse(result["ok"], msg=f"stream {stream} not screened")
            self.assertIn(stream, result["message"])

    def test_benign_rule_text_passes_screen(self):
        rule = "always (o5[t]:bv[16] = { #x0001 }:bv[16])."
        result, _ = self.queue(self.payload(operations={"0": rule}))
        self.assertTrue(result["ok"], msg=f"benign rule rejected: {result}")

    def test_user_rule_reading_apply_mocked_streams_rejected(self):
        # Only i2 (balance) is mocked to "0" at block apply, so a fee rule
        # reading it emits a different fee at admission than at inclusion ->
        # hard-reject at admission (consensus/admission.py
        # APPLY_MOCKED_INPUT_STREAMS).
        rule = "always (o8[t]:bv[24] = i2[t]:bv[24])."
        result, _ = self.queue(self.payload(operations={"0": rule}))
        self.assertFalse(result["ok"], msg="stream i2 not screened")
        self.assertIn("i2", result["message"])

    def test_user_rule_reading_recipient_streams_allowed(self):
        # i3/i4 (from/to pubkeys) are real at both admission and block apply, so
        # recipient-aware fee/policy rules are deterministic across both and are
        # permitted (o5 recipient whitelist; commit 09d54d4). They must pass the
        # admission screen even though they read input streams.
        for stream in ("i3", "i4"):
            rule = f"always (o8[t]:bv[24] = {stream}[t]:bv[24])."
            result, _ = self.queue(self.payload(operations={"0": rule}))
            self.assertTrue(result["ok"], msg=f"stream {stream} wrongly screened: {result}")

    def test_flat_fee_and_ladder_rules_pass_screen(self):
        flat = "always (o8[t]:bv[24] = { #x000003 }:bv[24])."
        # Comparison-ladder tier keyed on the real amount stream i1.
        ladder = (
            "always ((i1[t]:bv[24] > { #x0003e8 }:bv[24] && o8[t]:bv[24] = { #x000005 }:bv[24]) "
            "|| (i1[t]:bv[24] <= { #x0003e8 }:bv[24] && o8[t]:bv[24] = { #x000001 }:bv[24]))."
        )
        for rule in (flat, ladder):
            result, _ = self.queue(self.payload(operations={"0": rule}))
            self.assertTrue(result["ok"], msg=f"benign fee rule rejected: {rule} -> {result}")


# ---------------------------------------------------------------------------
# Mempool priority + migration
# ---------------------------------------------------------------------------

class TestMempoolFeePriority(unittest.TestCase):
    def setUp(self):
        self.test_db_path = "test_fee_mempool.sqlite"
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.test_db_path)
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        db.init_db()

    def tearDown(self):
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db_path):
            os.remove(self.test_db_path)
        config.set_database_path(self.original_db_path)

    def test_priority_by_estimated_fee(self):
        db.add_mempool_tx("p1", "h1", 1000, fee_limit=5, estimated_fee=5)
        db.add_mempool_tx("p2", "h2", 1001, fee_limit=50, estimated_fee=50)
        db.add_mempool_tx("p3", "h3", 1002, fee_limit=20, estimated_fee=20)
        rows = db.reserve_mempool_txs()
        self.assertEqual([r["payload"] for r in rows], ["p2", "p3", "p1"])

    def test_inflated_fee_limit_does_not_jump_queue(self):
        db.add_mempool_tx("honest", "h1", 1000, fee_limit=20, estimated_fee=20)
        db.add_mempool_tx("inflated", "h2", 999, fee_limit=10 ** 9, estimated_fee=0)
        rows = db.reserve_mempool_txs()
        self.assertEqual([r["payload"] for r in rows], ["honest", "inflated"])

    def test_equal_estimates_tiebreak_fee_limit_then_fifo(self):
        db.add_mempool_tx("later_highlimit", "h1", 2000, fee_limit=99, estimated_fee=10)
        db.add_mempool_tx("early", "h2", 1000, fee_limit=10, estimated_fee=10)
        db.add_mempool_tx("late", "h3", 3000, fee_limit=10, estimated_fee=10)
        rows = db.reserve_mempool_txs()
        self.assertEqual(
            [r["payload"] for r in rows], ["later_highlimit", "early", "late"]
        )

    def test_migration_adds_fee_columns(self):
        # Recreate the pre-fee mempool DDL in a fresh file, then init_db().
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        os.remove(self.test_db_path)
        conn = sqlite3.connect(self.test_db_path)
        conn.execute('''
            CREATE TABLE mempool (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_hash     TEXT    NOT NULL UNIQUE,
                payload     TEXT    NOT NULL,
                received_at INTEGER NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'pending',
                reserved_at INTEGER NOT NULL DEFAULT 0,
                batch_id    TEXT
            );
        ''')
        conn.execute(
            "INSERT INTO mempool (tx_hash, payload, received_at) VALUES ('h_old', 'p_old', 1)"
        )
        conn.commit()
        conn.close()

        db.init_db()
        cur = db._db_conn.execute("PRAGMA table_info(mempool);")
        cols = {row[1] for row in cur.fetchall()}
        self.assertIn("fee_limit", cols)
        self.assertIn("estimated_fee", cols)
        cur = db._db_conn.execute(
            "SELECT fee_limit, estimated_fee FROM mempool WHERE tx_hash='h_old'"
        )
        self.assertEqual(cur.fetchone(), (0, 0))


# ---------------------------------------------------------------------------
# createblock per-sender sequence re-sort
# ---------------------------------------------------------------------------

class TestPerSenderSequenceOrder(unittest.TestCase):
    def test_restores_ascending_sequence_within_sender_slots(self):
        from commands.createblock import _restore_per_sender_sequence_order
        tx_a6 = {"sender_pubkey": "A", "sequence_number": 6}
        tx_b1 = {"sender_pubkey": "B", "sequence_number": 1}
        tx_a5 = {"sender_pubkey": "A", "sequence_number": 5}
        transactions = [tx_a6, tx_b1, tx_a5]
        execution = ["ea6", "eb1", "ea5"]
        reserved = [16, 11, 15]
        _restore_per_sender_sequence_order(transactions, execution, reserved)
        # A's txs swap into ascending order within A's slots; B untouched.
        self.assertEqual(transactions, [tx_a5, tx_b1, tx_a6])
        self.assertEqual(execution, ["ea5", "eb1", "ea6"])
        self.assertEqual(reserved, [15, 11, 16])

    def test_single_tx_senders_untouched(self):
        from commands.createblock import _restore_per_sender_sequence_order
        txs = [{"sender_pubkey": "A", "sequence_number": 9},
               {"sender_pubkey": "B", "sequence_number": 0}]
        execution = ["a", "b"]
        reserved = [1, 2]
        _restore_per_sender_sequence_order(txs, execution, reserved)
        self.assertEqual(reserved, [1, 2])


# ---------------------------------------------------------------------------
# apply_block end-to-end: state-hash stability + replay determinism
# ---------------------------------------------------------------------------

class TestApplyBlockFeeE2E(unittest.TestCase):
    def setUp(self):
        self.ready_patcher = patch("tau_manager.tau_ready")
        self.mock_ready = self.ready_patcher.start()
        self.mock_ready.is_set.return_value = True
        self.addCleanup(self.ready_patcher.stop)

        self.multi_patcher = patch(
            "tau_manager.communicate_with_tau_multi",
            return_value={1: "1", 9: "10"},
        )
        self.mock_multi = self.multi_patcher.start()
        self.addCleanup(self.multi_patcher.stop)

        self.comm_patcher = patch(
            "tau_manager.communicate_with_tau", return_value="ok"
        )
        self.comm_patcher.start()
        self.addCleanup(self.comm_patcher.stop)

        self.original_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False
        self.addCleanup(lambda: setattr(config, "TESTNET_AUTO_FAUCET", self.original_faucet))

    def _parent_snapshot(self, balances):
        from consensus.governance import ConsensusLifecycleManager
        from consensus.state import (
            compute_consensus_meta_hash, compute_consensus_state_hash,
        )
        from chain_state import compute_accounts_hash
        lm = ConsensusLifecycleManager()
        lm.active_validators = [PROPOSER]
        acc_hash = compute_accounts_hash(balances, {})
        meta_hash = compute_consensus_meta_hash(
            host_contract={}, active_validators=[PROPOSER],
            pending_updates=[], vote_records=[],
            activation_schedule=[], checkpoint_references=[],
        )
        state_hash = compute_consensus_state_hash(b"", b"", acc_hash, meta_hash)
        return TauStateSnapshot(
            state_hash=state_hash,
            tau_bytes=b"",
            metadata={
                "balances": dict(balances),
                "sequence_numbers": {},
                "lifecycle_manager": lm,
                "active_consensus_id": "tau_poa_v1",
            },
        )

    def _block(self, txs, block_number=1):
        import block as block_mod
        return block_mod.Block.create(
            block_number=block_number,
            previous_hash="0" * 64,
            transactions=txs,
            proposer_pubkey=PROPOSER,
            timestamp=1700000000,
        )

    def test_state_hash_stable_across_normal_and_replay(self):
        engine = TauConsensusEngine()
        tx = {
            "tx_id": "tx1",
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": 0,
            "fee_limit": "50",
            "operations": {"1": [[SENDER, RECIPIENT, 100]]},
        }
        parent = self._parent_snapshot({SENDER: 1000})
        active_view = engine.derive_active_consensus(parent, 1)
        blk = self._block([tx])

        result1 = engine.apply_block(active_view, blk, parent)
        balances1 = result1.next_snapshot.metadata["balances"]
        self.assertEqual(balances1[SENDER], 890)
        self.assertEqual(balances1[RECIPIENT], 100)
        self.assertEqual(balances1[PROPOSER], 10)

        # Re-apply in replay mode from a fresh identical parent.
        parent2 = self._parent_snapshot({SENDER: 1000})
        result2 = engine.apply_block(active_view, blk, parent2, replay_mode=True)
        self.assertEqual(
            result1.next_snapshot.state_hash, result2.next_snapshot.state_hash
        )

    def test_governance_fee_change_between_blocks(self):
        # Fee source is the live consensus rules: when governance activates
        # a new fee rule the o9 emission changes. Simulated here by
        # switching the Tau mock between blocks; charging must follow.
        engine = TauConsensusEngine()

        def make_tx(seq, tx_id):
            return {
                "tx_id": tx_id,
                "tx_type": "user_tx",
                "sender_pubkey": SENDER,
                "sequence_number": seq,
                "fee_limit": "50",
                "operations": {"1": [[SENDER, RECIPIENT, 100]]},
            }

        parent = self._parent_snapshot({SENDER: 1000})
        active_view = engine.derive_active_consensus(parent, 1)
        result1 = engine.apply_block(active_view, self._block([make_tx(0, "t1")]), parent)
        self.assertEqual(result1.next_snapshot.metadata["balances"][PROPOSER], 10)

        # "Governance" doubles the fee (new rules emit o9=20).
        self.mock_multi.return_value = {1: "1", 9: "20"}
        parent2 = result1.next_snapshot
        view2 = engine.derive_active_consensus(parent2, 2)
        result2 = engine.apply_block(
            view2, self._block([make_tx(1, "t2")], block_number=2), parent2
        )
        balances = result2.next_snapshot.metadata["balances"]
        self.assertEqual(balances[PROPOSER], 30)  # 10 + 20
        self.assertEqual(balances[SENDER], 1000 - 200 - 10 - 20)

    def test_o9_garbage_propagates_out_of_apply_block(self):
        engine = TauConsensusEngine()
        tx = {
            "tx_id": "tx1",
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": 0,
            "fee_limit": "50",
            "operations": {"1": [[SENDER, RECIPIENT, 100]]},
        }
        self.mock_multi.return_value = {1: "1", 9: "garbage"}
        parent = self._parent_snapshot({SENDER: 1000})
        active_view = engine.derive_active_consensus(parent, 1)
        with self.assertRaises(FeeRuleError):
            engine.apply_block(active_view, self._block([tx]), parent)


# ---------------------------------------------------------------------------
# Tau-down guards (proposal abort / validation defer)
# ---------------------------------------------------------------------------

class TestTauDownGuards(unittest.TestCase):
    def test_createblock_aborts_round_when_tau_down(self):
        from commands import createblock
        user_tx = json.dumps({
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": 0,
            "fee_limit": "10",
            "operations": {},
            "signature": "sig",
        })
        reserved = [{"id": 1, "tx_hash": "h1", "payload": user_tx}]
        mock_tau = MagicMock()
        mock_tau.tau_ready.wait.return_value = False  # Tau down
        with patch.object(createblock, "tau_manager", mock_tau), \
             patch.object(createblock.config, "MINER_PRIVKEY", "1" * 64), \
             patch.object(createblock.db, "reserve_mempool_txs", return_value=reserved), \
             patch.object(createblock.db, "unreserve_mempool_txs") as mock_unreserve, \
             patch.object(createblock.db, "get_canonical_head_block",
                          return_value={"block_hash": "0" * 64,
                                        "header": {"block_number": 0}}), \
             patch.object(TauConsensusEngine, "query_eligibility", return_value=True):
            result = createblock.create_block_from_mempool()
        self.assertIn("error", result)
        self.assertIn("Tau unavailable", result["error"])
        mock_unreserve.assert_called_once_with([1])

    def test_process_new_block_defers_when_tau_down(self):
        import block as block_mod
        user_tx = {
            "tx_type": "user_tx",
            "sender_pubkey": SENDER,
            "sequence_number": 0,
            "fee_limit": "10",
            "operations": {"1": [[SENDER, RECIPIENT, 1]]},
        }
        blk = block_mod.Block.create(
            block_number=1,
            previous_hash="aa" * 32,
            transactions=[user_tx],
            proposer_pubkey=PROPOSER,
            timestamp=1700000000,
        )
        mock_tau = MagicMock()
        mock_tau.tau_ready.wait.return_value = False  # Tau down
        # Force the fast path far enough to hit the guard.
        with patch.object(chain_state, "tau_manager", mock_tau), \
             patch("db.get_canonical_head",
                   return_value={"block_hash": blk.header.previous_hash}), \
             patch.object(TauConsensusEngine, "verify_block_header", return_value=True), \
             patch.object(block_mod.Block, "verify_consensus_proof", return_value=True, create=True), \
             patch.object(TauConsensusEngine, "apply_block") as mock_apply:
            ok = chain_state.process_new_block(blk)
        self.assertFalse(ok)
        mock_apply.assert_not_called()


if __name__ == "__main__":
    unittest.main()
