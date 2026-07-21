"""Consensus-enforcement of user policy (o5) at block apply, plus real i3/i4/i5.

These cover the behavior added when o5 became consensus-binding:
  * o5 is read from the SAME communicate_with_tau_multi result at apply (no
    second roundtrip), mirroring mempool admission.
  * o5 == BLOCK (0) rejects the WHOLE user_tx; staged writes never commit
    (multi-transfer atomicity). Malformed/absent o5 handling.
  * i3/i4 (from/to pubkeys) are fed real at apply so recipient-aware rules work.

The apply-path tests mock communicate_with_tau_multi to drive o5 deterministically
(unit-level: exercises the enforcement wiring). One real-engine test compiles an
i4 recipient-whitelist rule to prove a real rule emits o5=block for a
non-whitelisted recipient.
"""
import os
import sys
import unittest
from unittest.mock import patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import pytest

import chain_state
import tau_defs
from consensus.engine import TauConsensusEngine


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


SENDER = "11" * 48      # 96 hex chars == bv[384]
RECIPIENT = "22" * 48
PROPOSER = "33" * 48


def _snap():
    return chain_state.TauStateSnapshot(state_hash="0" * 64, tau_bytes=b"rules", metadata={})


def _transfer_tx(transfers):
    return {
        "tx_id": "tx_test",
        "sender_pubkey": SENDER,
        "sequence_number": 0,
        "tx_type": "user_tx",
        "operations": {"1": transfers},
        "fee_limit": "1000",
        "signature": "00" * 48,
    }


class TestUserPolicyApplyEnforcement(unittest.TestCase):
    """o5 enforced in the fee-era apply loop (proposer + target_balances)."""

    def _apply(self, tx, balances):
        engine = TauConsensusEngine()
        t_bals = dict(balances)
        t_seqs = {SENDER: 0}
        result = engine.apply(
            _snap(), [tx], 1_700_000_000,
            target_balances=t_bals,
            target_sequences=t_seqs,
            proposer_pubkey=PROPOSER,
        )
        return result, t_bals

    @patch("tau_manager.tau_ready")
    @patch("tau_manager.communicate_with_tau_multi")
    def test_o5_block_rejects_transfer_at_apply(self, mock_multi, mock_ready):
        mock_ready.is_set.return_value = True
        mock_multi.return_value = {1: "10", 5: "0"}  # o1 ok, o5 BLOCK
        tx = _transfer_tx([[SENDER, RECIPIENT, "10"]])
        result, bals = self._apply(tx, {SENDER: 100000})
        self.assertIn(tx, result.rejected_transactions)
        self.assertNotIn(tx, result.accepted_transactions)
        self.assertEqual(bals.get(SENDER), 100000, "sender debited despite policy block")
        self.assertNotIn(RECIPIENT, bals, "recipient credited despite policy block")

    @patch("tau_manager.tau_ready")
    @patch("tau_manager.communicate_with_tau_multi")
    def test_o5_allow_commits_transfer_at_apply(self, mock_multi, mock_ready):
        mock_ready.is_set.return_value = True
        mock_multi.return_value = {1: "10", 5: "1"}  # o1 ok, o5 ALLOW
        tx = _transfer_tx([[SENDER, RECIPIENT, "10"]])
        result, bals = self._apply(tx, {SENDER: 100000})
        self.assertIn(tx, result.accepted_transactions)
        self.assertEqual(bals.get(SENDER), 100000 - 10)
        self.assertEqual(bals.get(RECIPIENT), 10)

    @patch("tau_manager.tau_ready")
    @patch("tau_manager.communicate_with_tau_multi")
    def test_o5_absent_allows_at_apply(self, mock_multi, mock_ready):
        mock_ready.is_set.return_value = True
        mock_multi.return_value = {1: "10"}  # no o5 key -> allow
        tx = _transfer_tx([[SENDER, RECIPIENT, "10"]])
        result, bals = self._apply(tx, {SENDER: 100000})
        self.assertIn(tx, result.accepted_transactions)
        self.assertEqual(bals.get(RECIPIENT), 10)

    @patch("tau_manager.tau_ready")
    @patch("tau_manager.communicate_with_tau_multi")
    def test_o5_malformed_fails_closed_at_apply(self, mock_multi, mock_ready):
        mock_ready.is_set.return_value = True
        mock_multi.return_value = {1: "10", 5: "not-a-number"}  # parse -> 0 -> BLOCK
        tx = _transfer_tx([[SENDER, RECIPIENT, "10"]])
        result, bals = self._apply(tx, {SENDER: 100000})
        self.assertIn(tx, result.rejected_transactions)
        self.assertEqual(bals.get(SENDER), 100000)
        self.assertNotIn(RECIPIENT, bals)

    @patch("tau_manager.tau_ready")
    @patch("tau_manager.communicate_with_tau_multi")
    def test_multi_transfer_atomic_on_o5_block(self, mock_multi, mock_ready):
        """First transfer allowed, second blocked -> NEITHER commits."""
        mock_ready.is_set.return_value = True
        mock_multi.side_effect = [
            {1: "10", 5: "1"},   # transfer #1: allow
            {1: "20", 5: "0"},   # transfer #2: BLOCK
        ]
        recip_b = "44" * 48
        tx = _transfer_tx([[SENDER, RECIPIENT, "10"], [SENDER, recip_b, "20"]])
        result, bals = self._apply(tx, {SENDER: 100000})
        self.assertIn(tx, result.rejected_transactions)
        self.assertEqual(bals.get(SENDER), 100000, "sender changed despite atomic reject")
        self.assertNotIn(RECIPIENT, bals, "transfer #1 committed despite tx-level reject")
        self.assertNotIn(recip_b, bals)

    @patch("tau_manager.tau_ready")
    @patch("tau_manager.communicate_with_tau_multi")
    def test_o5_read_uses_single_roundtrip(self, mock_multi, mock_ready):
        """o5 comes from the same multi result as o1/o8/o9 — one call per transfer."""
        mock_ready.is_set.return_value = True
        mock_multi.return_value = {1: "10", 5: "1"}
        tx = _transfer_tx([[SENDER, RECIPIENT, "10"]])
        self._apply(tx, {SENDER: 100000})
        self.assertEqual(mock_multi.call_count, 1, "o5 read triggered an extra Tau roundtrip")

    @patch("tau_manager.tau_ready")
    @patch("tau_manager.communicate_with_tau_multi")
    def test_apply_feeds_real_i3_i4(self, mock_multi, mock_ready):
        """The fee-era loop feeds the real from/to pubkeys on i3/i4 (not '0')."""
        mock_ready.is_set.return_value = True
        mock_multi.return_value = {1: "10", 5: "1"}
        tx = _transfer_tx([[SENDER, RECIPIENT, "10"]])
        self._apply(tx, {SENDER: 100000})
        inputs = mock_multi.call_args.kwargs["input_stream_values"]
        self.assertEqual(inputs[3], "{ #x" + SENDER + " }:bv[384]")
        self.assertEqual(inputs[4], "{ #x" + RECIPIENT + " }:bv[384]")
        self.assertEqual(inputs[2], "0", "balance i2 should stay mocked")


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
class TestRecipientWhitelistRealEngine(unittest.TestCase):
    """Real native engine: an i4 recipient-whitelist rule emits o5=block/allow."""

    def test_recipient_whitelist_rule_blocks_non_whitelisted(self):
        import tempfile
        from tau_native import TauInterface

        # Allow only recipient #x2222; block everyone else. bv[16] for fast compile.
        rule = (
            "always ( (i4[t] = {#x2222}:bv[16]) "
            "? o5[t] = {1}:bv[16] : o5[t] = {0}:bv[16] )."
        )
        fd, path = tempfile.mkstemp(suffix=".tau")
        with os.fdopen(fd, "w") as f:
            f.write(rule)
        try:
            iface = TauInterface(path)
            # Whitelisted recipient -> allow (o5 != 0)
            res = iface.communicate(
                target_output_stream_index=5,
                input_stream_values={4: ["#x2222"]},
            )
            self.assertNotIn("0", res.split())
            # Non-whitelisted recipient -> block (o5 == 0)
            res = iface.communicate(
                target_output_stream_index=5,
                input_stream_values={4: ["#x9999"]},
            )
            self.assertIn("0", res.split())
        finally:
            os.remove(path)

    def test_custom_input_combined_with_amount_gates_o5(self):
        """Issue #16: a rule combining a custom stream (i13) with the transfer
        amount (i1) emits o5=allow/block in ONE evaluation step — the same step
        sendtx now feeds i13 into at admission. Proves passphrase/2FA-class rules
        are enforceable, not just theoretically wired."""
        import tempfile
        from tau_native import TauInterface

        # Allow only when the passphrase i13 == #x002a AND a non-zero amount is
        # sent; block otherwise. i13 as bv[16] (fast compile), i1 as bv[24] amount.
        rule = (
            "always ( (i13[t] = {#x002a}:bv[16] && i1[t] > {0}:bv[24]) "
            "? o5[t] = {1}:bv[16] : o5[t] = {0}:bv[16] )."
        )
        fd, path = tempfile.mkstemp(suffix=".tau")
        with os.fdopen(fd, "w") as f:
            f.write(rule)
        try:
            iface = TauInterface(path)
            # Correct passphrase + non-zero amount -> allow (o5 != 0).
            res = iface.communicate(
                target_output_stream_index=5,
                input_stream_values={13: ["#x002a"], 1: ["10"]},
            )
            self.assertNotIn("0", res.split())
            # Wrong passphrase -> block (o5 == 0), even with a valid amount.
            res = iface.communicate(
                target_output_stream_index=5,
                input_stream_values={13: ["#x0000"], 1: ["10"]},
            )
            self.assertIn("0", res.split())
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main()
