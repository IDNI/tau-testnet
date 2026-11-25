"""Cooldown / recipient mutual exclusion on i16 (issues #21 + #47/#76).

i16 is designated for the cooldown feed (seconds since the sender's last
transfer, issue #21) and carries the recipient context tag while recipient
controls are active. PR #140 originally only DISCLOSED that the two
activations are mutually exclusive; these tests pin the enforcement:

  (a) recipient activation is refused while the cooldown feed is live —
      at the patch validator (which admission and block apply share), at
      the governance apply site itself, and as a backstop inside
      `activate_recipient_policy`, which replay/restore/genesis paths
      reach without the validator. `reserved_operation_keys` raises if
      the two are ever live together, so i16 is never silently reserved
      for both. The older half of (a) stays pinned too: a live spec
      already carrying an i16 rule refuses activation through the
      collision audit.

  (b) while recipient controls are active, the engine never feeds the
      cooldown seconds value under i16 — the recipient context tag is
      what every Tau step sees. The control case (gate off, feed on)
      proves the harness sees the seconds value when it IS fed, so the
      exclusion assertion is not vacuous.
"""
from unittest.mock import patch

import pytest

import tau_defs
from consensus.approvals import audit_recipient_stream_collisions
from consensus.governance import (
    ConsensusLifecycleManager,
    validate_recipient_policy_active,
)
from test_fee_model import EngineFeeBase, PROPOSER, SENDER


def test_cooldown_mutual_exclusion_activation_refused_while_cooldown_live():
    # Control: with the feed off, True is a legal patch value.
    assert validate_recipient_policy_active(True) is None
    with patch.object(tau_defs, "COOLDOWN_STREAM_ACTIVE", True):
        err = validate_recipient_policy_active(True)
    assert err is not None and "cooldown" in err and "i16" in err


def test_cooldown_mutual_exclusion_patch_apply_raises_while_cooldown_live():
    lm = ConsensusLifecycleManager(
        active_validators=[bytes.fromhex(SENDER)]
    )
    with patch.object(tau_defs, "COOLDOWN_STREAM_ACTIVE", True):
        with pytest.raises(ValueError, match="cooldown"):
            lm.apply_host_contract_patch(
                {"recipient_policy_active": True}, effective_spec_texts=[]
            )
    assert lm.recipient_policy_active is False


def test_cooldown_mutual_exclusion_activate_backstop():
    lm = ConsensusLifecycleManager()
    with patch.object(tau_defs, "COOLDOWN_STREAM_ACTIVE", True):
        with pytest.raises(ValueError, match="cooldown"):
            lm.activate_recipient_policy()
    assert lm.recipient_policy_active is False
    lm.activate_recipient_policy()  # control: feed off -> activates
    assert lm.recipient_policy_active is True


def test_cooldown_mutual_exclusion_reserved_keys_guard():
    # Neither live: i16 stays an ordinary custom stream.
    assert 16 not in tau_defs.reserved_operation_keys("")
    with patch.object(tau_defs, "COOLDOWN_STREAM_ACTIVE", True):
        # Cooldown alone: i16 reserved exactly once.
        assert tau_defs.reserved_operation_keys("").count(16) == 1
        # Both live: refused outright, never a silent double reservation.
        with pytest.raises(ValueError, match="mutually exclusive"):
            tau_defs.reserved_operation_keys("", recipient_policy_active=True)
    # Recipient alone: i17 and i16 reserved, once each.
    keys = tau_defs.reserved_operation_keys("", recipient_policy_active=True)
    assert keys.count(16) == 1 and keys.count(17) == 1


def test_cooldown_mutual_exclusion_live_spec_audit_still_refuses():
    findings = audit_recipient_stream_collisions(
        [("application_rules", "always i16[t]:bv[64] > 5.")]
    )
    assert findings and "i16" in findings[0]


class TestCooldownMutualExclusionEngineFeed(EngineFeeBase):
    """Direction (b) at the engine surface, on TestCooldownStream's
    recorded-input-map harness (test_fee_model)."""

    def _apply_with_lm(self, lm, parent_lts):
        self.mock_multi.return_value = {1: "1"}
        return self.engine.apply(
            self.snapshot, [self.transfer_tx(fee_limit="0")], 1700000000,
            target_balances={SENDER: 1000}, target_sequences={},
            proposer_pubkey=PROPOSER, block_height=1,
            parent_balances={SENDER: 1000},
            parent_last_transfer_ts=parent_lts,
            target_last_transfer_ts={},
            target_lifecycle=lm,
        )

    def _fed16(self):
        return [c.kwargs["input_stream_values"][16]
                for c in self.mock_multi.call_args_list
                if 16 in c.kwargs.get("input_stream_values", {})]

    def test_cooldown_mutual_exclusion_engine_feed(self):
        lm = ConsensusLifecycleManager()
        lm.activate_recipient_policy()
        with patch.object(tau_defs, "COOLDOWN_STREAM_ACTIVE", True):
            self._apply_with_lm(lm, {SENDER: 1699999100})
        fed = self._fed16()
        # The tag is fed (the assertion is not vacuous), the seconds
        # value (900) never is, while recipient controls are active.
        self.assertTrue(fed)
        self.assertNotIn("900", fed)
        self.assertEqual(set(fed), {"0"})

    def test_cooldown_feed_still_live_without_recipient_controls(self):
        # Control with teeth: same harness, gate off -> the seconds
        # value IS fed under i16.
        lm = ConsensusLifecycleManager()
        with patch.object(tau_defs, "COOLDOWN_STREAM_ACTIVE", True):
            self._apply_with_lm(lm, {SENDER: 1699999100})
        self.assertIn("900", self._fed16())
