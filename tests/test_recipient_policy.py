"""Recipient-side o5 policy (issue #47) and recipient max-hold cap (issue #76).

A transfer to R passes only if the sender's policy AND R's policy allow it,
at admission AND block apply. #76 adds the hold length (i17) to the inputs,
so R can cap how long a payment to it may be held.

Coverage map -- acceptance cases from the issues to tests:

  #47 (1) R "allow incoming only from A": A->R passes, B->R refused with the
          recipient reason, A's own send policy untouched:
          TestAdmissionGate.test_inbound_allow_list_*, TestRecipientApply.test_inbound_allow_list_*
  #47 (2) R deploys nothing: everyone can pay R:
          TestAdmissionGate.test_no_recipient_policy_allows, TestRecipientApply.test_no_recipient_policy_allows
  #47 (3) batch A->{R,S} where S refuses A fails as one tx, no partial apply:
          TestAdmissionGate.test_batch_fails_as_one_tx, TestRecipientApply.test_batch_fails_as_one_tx
  #47 (4) R's inbound rule + outbound whitelist in one policy unit, both enforce:
          TestRecipientApply.test_inbound_and_outbound_in_one_unit
  #47 (5) node reports whether recipient-side policy is active; a node without
          it rejects an inbound-only rule at deploy with a clear reason:
          TestCapabilities, TestHoldStreamScreens.test_i17_rule_refused_when_inactive
  #76 (1) cap 0: plain A->R passes admission+apply, any park refused at
          admission with RECIPIENT_MAX_HOLD carrying R's cap, A's send policy
          untouched: TestAdmissionGate.test_cap_zero_*, TestRecipientApply.test_cap_zero_*
  #76 (2) cap 600s: 10-minute park passes, 1-hour park refused with reason:
          TestAdmissionGate.test_cap_600_seconds, TestRecipientApply.test_cap_600_seconds
  #76 (3) R deploys nothing: parks of any length pass:
          TestRecipientApply.test_no_policy_parks_of_any_length_pass
  #76 (4) A's retract of an open park to R admitted regardless of cap:
          TestRecipientApply.test_retract_never_gated
  #76 (5) refusal message carries R's cap: TestAdmissionGate.test_cap_refusal_carries_cap,
          TestRecipientApply.test_cap_refusal_carries_cap
  #76 (6) node reports whether the cap is active; a node without it refuses
          the rule at deploy: TestCapabilities, TestHoldStreamScreens

Plus: admission-apply parity (TestAdmissionApplyParity), boundary hold == cap
vs cap+1 (TestRecipientApply.test_hold_boundary_blocks), replay determinism
(TestRecipientApply.test_replay_reproduces_recipient_gate_exactly and
test_replay_of_a_refusal_is_deterministic_with_itself -- note the documented
pre-existing normal-vs-replay divergence for policy-blocked txs), the fee
model (TestRecipientApply.test_refused_park_charges_no_fee), rule_offer /
approval requests not gated (TestNotTransfersNotGated), wallet-template
regression (TestWalletTemplateRegression), and the single-roundtrip regression
(TestRecipientApply.test_no_recipient_guard_means_one_roundtrip).

Pure unittest (no pytest import) so it runs under the real suite and under the
local runner. The guarded-mode steps are driven by a scripted evaluator;
TestRecipientPolicyNativeEngine additionally verifies the core mechanism --
a guarded unit discriminating the recipient pass, and an i17 cap -- against
the real engine when the native bindings are available (they are not in this
sandbox, so those tests skip here and run in CI).
"""
import hashlib
import itertools
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import tau_defs
from bls_keys import pubkey_hex, sign_payload
from consensus import recipient_policy, sender_policy
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import KIND_HEIGHT, KIND_TIME

# --- identities ---------------------------------------------------------------
# Distinct small secrets, so every key is a real 96-hex-char BLS pubkey.
SK_A, SK_B, SK_R, SK_S = 0xA1, 0xB2, 0xC3, 0xD4
A, B, R, S = (pubkey_hex(sk) for sk in (SK_A, SK_B, SK_R, SK_S))
PROPOSER = "d4" * 48


def _lit(pubkey):
    """The bv[384] literal the transfer path feeds for a pubkey."""
    return "{ #x" + str(pubkey).lower() + " }:bv[384]"


def _guarded_allow_list(owner, allowed):
    """A guarded unit: `owner` allows incoming only from `allowed`.

    In the recipient pass i12 is the owner and i3 is the sender, so the
    guard matches and the inner condition reads the counterparty.
    """
    return (
        "always ( (i12[t]:bv[384] = { #x" + owner + " }:bv[384]) "
        "? ( (i3[t]:bv[384] = { #x" + allowed + " }:bv[384]) "
        "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000000 }:bv[24]) ) "
        ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )


def _guarded_cap(owner, cap):
    """A guarded unit: `owner` caps the hold at `cap` (seconds or blocks,
    following the park's release kind)."""
    return (
        "always ( (i12[t]:bv[384] = { #x" + owner + " }:bv[384]) "
        "? ( (i17[t]:bv[64] <= { #x%016x }:bv[64]) "
        "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000000 }:bv[24]) ) "
        ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )." % cap
    )


def _clause_cap(cap):
    """An UNGUARDED o5 clause body: cap the hold at `cap`."""
    return (
        "( (i17[t]:bv[64] <= { #x%016x }:bv[64]) "
        "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )" % cap
    )


def _clause_allow_from(allowed):
    """An UNGUARDED o5 clause body: allow incoming only from `allowed`."""
    return (
        "( (i3[t]:bv[384] = { #x" + allowed + " }:bv[384]) "
        "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )"
    )


# --- unit tests: consensus/recipient_policy.py ---------------------------------

class TestHoldLength(unittest.TestCase):
    def test_time_park_measures_seconds(self):
        hold, unit = recipient_policy.hold_length_for_park(
            KIND_TIME, 1_700_003_600, height=20, timestamp=1_700_000_000)
        self.assertEqual((hold, unit), (3600, "seconds"))

    def test_height_park_measures_blocks(self):
        hold, unit = recipient_policy.hold_length_for_park(
            KIND_HEIGHT, 30, height=20, timestamp=1_700_000_000)
        self.assertEqual((hold, unit), (10, "blocks"))

    def test_hold_clamps_at_zero(self):
        # The admission and apply clocks can differ by a second at the
        # boundary; a negative hold is meaningless.
        hold, unit = recipient_policy.hold_length_for_park(
            KIND_TIME, 1_700_000_000, height=20, timestamp=1_700_000_001)
        self.assertEqual((hold, unit), (0, "seconds"))

    def test_unknown_kind_is_instant(self):
        self.assertEqual(
            recipient_policy.hold_length_for_park(99, 123, height=20, timestamp=0),
            (0, "seconds"))

    def test_cap_detail_field(self):
        self.assertEqual(recipient_policy.cap_detail_field("seconds"), "max_hold_seconds")
        self.assertEqual(recipient_policy.cap_detail_field("blocks"), "max_hold_blocks")


class TestCapExtraction(unittest.TestCase):
    def test_exceeds_forms(self):
        self.assertEqual(
            recipient_policy.extract_hold_cap(
                "always ( (i17[t]:bv[64] > { #x0000000000000258 }:bv[64]) "
                "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
                ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."),
            600)
        self.assertEqual(
            recipient_policy.extract_hold_cap(
                "(i17[t]:bv[64] >= { #x0000000000000259 }:bv[64])"),
            600)  # >= 601 blocks holds of 601+, so the cap is 600

    def test_flipped_exceeds_forms(self):
        self.assertEqual(
            recipient_policy.extract_hold_cap(
                "({ #x0000000000000258 }:bv[64] < i17[t]:bv[64])"),
            600)
        self.assertEqual(
            recipient_policy.extract_hold_cap(
                "({ #x0000000000000259 }:bv[64] <= i17[t]:bv[64])"),
            600)

    def test_allow_ternary_forms(self):
        self.assertEqual(
            recipient_policy.extract_hold_cap(
                "(i17[t]:bv[64] <= { #x0000000000000258 }:bv[64]) "
                "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
                ": (o5[t]:bv[24] = { #x000000 }:bv[24])"),
            600)
        self.assertEqual(
            recipient_policy.extract_hold_cap(
                "(i17[t]:bv[64] < { #x0000000000000259 }:bv[64]) "
                "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
                ": (o5[t]:bv[24] = { #x000000 }:bv[24])"),
            600)

    def test_decimal_literals(self):
        self.assertEqual(
            recipient_policy.extract_hold_cap("(i17[t]:bv[64] > { 600 }:bv[64])"),
            600)

    def test_no_cap_returns_none(self):
        self.assertIsNone(recipient_policy.extract_hold_cap(
            "(o5[t]:bv[24] = { #x000001 }:bv[24])"))
        self.assertIsNone(recipient_policy.extract_hold_cap(""))
        # A minimum-hold shape (block when the hold is SHORT) is not a cap.
        self.assertIsNone(recipient_policy.extract_hold_cap(
            "(i17[t]:bv[64] <= { #x0000000000000258 }:bv[64]) "
            "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24])"))

    def test_guarded_scoping_reports_the_owners_cap(self):
        spec = _guarded_cap(A, 100) + "\n" + _guarded_cap(R, 600)
        self.assertEqual(
            recipient_policy.extract_hold_cap(spec, owner_pubkey=R), 600)
        self.assertEqual(
            recipient_policy.extract_hold_cap(spec, owner_pubkey=A), 100)
        self.assertIsNone(
            recipient_policy.extract_hold_cap(spec, owner_pubkey=B))

    def test_comments_do_not_count(self):
        # Tau comments start with '#', not '//'.
        self.assertIsNone(recipient_policy.extract_hold_cap(
            "# (i17[t]:bv[64] > { #x0000000000000258 }:bv[64])\n"
            "(o5[t]:bv[24] = { #x000001 }:bv[24])"))


class TestGuardDetection(unittest.TestCase):
    def test_key_present(self):
        self.assertTrue(recipient_policy.recipient_may_have_guarded_policy(
            _guarded_allow_list(R, A), R))

    def test_key_absent(self):
        self.assertFalse(recipient_policy.recipient_may_have_guarded_policy(
            _guarded_allow_list(R, A), B))

    def test_case_insensitive(self):
        self.assertTrue(recipient_policy.recipient_may_have_guarded_policy(
            _guarded_allow_list(R, A), R.upper()))

    def test_empty_spec(self):
        self.assertFalse(recipient_policy.recipient_may_have_guarded_policy("", R))
        self.assertFalse(recipient_policy.recipient_may_have_guarded_policy(None, R))


class TestInputMaps(unittest.TestCase):
    def test_recipient_pass_only_changes_i12(self):
        values = {1: "10", 2: "0", 17: "600", 3: _lit(A), 4: _lit(R),
                  12: _lit(A), 5: "1700000000"}
        out = recipient_policy.recipient_pass_inputs(values, R)
        self.assertEqual(out[12], _lit(R))
        for key in (1, 2, 17, 3, 4, 5):
            self.assertEqual(out[key], values[key])
        self.assertEqual(values[12], _lit(A), "the caller's map must not change")

    def test_instant_inputs_only_zeroes_i17(self):
        values = {1: "10", 17: "3600", 12: _lit(R)}
        out = recipient_policy.instant_inputs(values)
        self.assertEqual(out[17], "0")
        self.assertEqual(out[1], "10")
        self.assertEqual(out[12], _lit(R))
        self.assertEqual(values[17], "3600", "the caller's map must not change")


class TestCapRefusalText(unittest.TestCase):
    def test_carries_cap_and_hold(self):
        text = recipient_policy.cap_refusal_text(R, 3600, "seconds", 600)
        self.assertIn("RECIPIENT_MAX_HOLD", text)
        self.assertIn("max_hold_seconds=600", text)
        self.assertIn("3600 seconds", text)

    def test_blocks_unit(self):
        text = recipient_policy.cap_refusal_text(R, 50, "blocks", 10)
        self.assertIn("max_hold_blocks=10", text)
        self.assertIn("50 blocks", text)

    def test_unknown_cap_still_names_the_reason(self):
        text = recipient_policy.cap_refusal_text(R, 3600, "seconds", None)
        self.assertIn("RECIPIENT_MAX_HOLD", text)
        self.assertIn("3600 seconds", text)

    def test_policy_refusal_text(self):
        text = recipient_policy.policy_refusal_text(R)
        self.assertIn("rejected by recipient policy (o5)", text)


class TestEvaluateRecipientClause(unittest.TestCase):
    def setUp(self):
        self.evaluator = MockPolicyEvaluator(pool="admission")
        sender_policy.set_evaluator("admission", self.evaluator)

    def tearDown(self):
        sender_policy.set_evaluator("admission", None)

    def _values(self, hold=0, sender=A, recipient=R, amount="10"):
        return {1: amount, 2: "0", 17: str(hold), 3: _lit(sender),
                4: _lit(recipient), 12: _lit(sender), 5: "1700000000"}

    def test_no_clause_allows(self):
        verdict, cap, _ = recipient_policy.evaluate_recipient_clause(
            None, self._values(), pool="admission", timeout=None, hold=0)
        self.assertEqual((verdict, cap), ("allow", None))

    def test_clause_allows(self):
        body = _clause_allow_from(A)
        self.evaluator.set_verdict(body, "1")
        verdict, cap, _ = recipient_policy.evaluate_recipient_clause(
            body, self._values(), pool="admission", timeout=None, hold=0)
        self.assertEqual((verdict, cap), ("allow", None))

    def test_clause_blocks_plain_transfer_is_policy_block(self):
        body = _clause_allow_from(A)
        self.evaluator.set_verdict(body, "0")
        verdict, cap, _ = recipient_policy.evaluate_recipient_clause(
            body, self._values(sender=B), pool="admission", timeout=None, hold=0)
        self.assertEqual((verdict, cap), ("policy_block", None))
        # No discriminator step for a plain transfer: hold is already 0.
        self.assertEqual(len(self.evaluator.verdict_calls), 1)

    def test_clause_blocks_park_but_allows_instant_is_cap_block(self):
        body = _clause_cap(600)
        self.evaluator.set_verdict(
            body, lambda inputs: "0" if int(inputs.get("i17", "0")) > 600 else "1")
        verdict, cap, _ = recipient_policy.evaluate_recipient_clause(
            body, self._values(hold=3600), pool="admission", timeout=None, hold=3600)
        self.assertEqual((verdict, cap), ("cap_block", 600))
        # The discriminator re-ran the clause with hold forced to 0.
        self.assertEqual(len(self.evaluator.verdict_calls), 2)
        self.assertEqual(self.evaluator.verdict_calls[1][1].get("i17"), "0")

    def test_clause_blocks_park_and_instant_is_policy_block(self):
        body = _clause_allow_from(A)
        self.evaluator.set_verdict(body, "0")
        verdict, cap, _ = recipient_policy.evaluate_recipient_clause(
            body, self._values(hold=3600, sender=B), pool="admission",
            timeout=None, hold=3600)
        self.assertEqual((verdict, cap), ("policy_block", None))

    def test_cap_block_without_extractable_cap(self):
        # A cap stated in an undocumented form still gets the cap verdict;
        # only the cap value is missing from the message.
        body = "( (i17[t]:bv[64] * { #x0002 }:bv[64] > { #x04b0 }:bv[64]) ? block : allow )"
        self.evaluator.set_verdict(
            body, lambda inputs: "0" if int(inputs.get("i17", "0")) > 600 else "1")
        verdict, cap, _ = recipient_policy.evaluate_recipient_clause(
            body, self._values(hold=3600), pool="admission", timeout=None, hold=3600)
        self.assertEqual((verdict, cap), ("cap_block", None))


# --- deploy screens: the i17 stream -------------------------------------------

class TestHoldStreamScreens(unittest.TestCase):
    def test_i17_rule_passes_when_active(self):
        from consensus.admission import screen_user_rule_text
        result = screen_user_rule_text(_guarded_cap(R, 600), "", False)
        self.assertIsNone(result, "an i17 rule must pass while the feature is active")

    def test_i17_rule_refused_when_inactive(self):
        from consensus.admission import screen_user_rule_text
        with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
            result = screen_user_rule_text(_guarded_cap(R, 600), "", False)
        self.assertIsNotNone(result, "an i17 rule must not be silently admitted")
        self.assertIn("i17", result.error)
        self.assertIn("recipient-side policy is not active", result.error)
        self.assertEqual(result.code, "RECIPIENT_POLICY_INACTIVE")

    def test_i17_clause_refused_when_inactive(self):
        # The clause path (a rule that writes o5) gets the same clear refusal.
        from consensus.admission import validate_o5_clause_routing
        rule = "always ( %s )." % _clause_cap(600)
        tip_view = MagicMock()
        tip_view.clause_for.return_value = None
        with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
            result = validate_o5_clause_routing(
                {"tx_type": "user_tx", "sender_pubkey": R, "operations": {"0": rule}},
                tip_view, rule)
        self.assertIsNotNone(result)
        self.assertFalse(result.is_valid, result)
        self.assertIn("i17", result.error)
        self.assertIn("recipient-side policy is not active", result.error)

    def test_i17_clause_routes_when_active(self):
        from consensus.admission import validate_o5_clause_routing
        rule = "always ( %s )." % _clause_cap(600)
        tip_view = MagicMock()
        tip_view.clause_for.return_value = None
        result = validate_o5_clause_routing(
            {"tx_type": "user_tx", "sender_pubkey": R, "operations": {"0": rule}},
            tip_view, rule)
        self.assertIsNotNone(result)
        self.assertTrue(result.is_valid, getattr(result, "error", None))
        self.assertEqual(result.data["o5_clause_action"], "declare")

    def test_i17_wrong_width_refused(self):
        from consensus.admission import screen_user_rule_text
        result = screen_user_rule_text(
            "always ( (i17[t]:bv[32] > { #x00000258 }:bv[32]) "
            "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) ).", "", False)
        self.assertIsNotNone(result)
        self.assertEqual(result.code, "WIDTH_MISMATCH")
        self.assertIn("bv[64]", result.error)

    def test_i17_untyped_refused(self):
        from consensus.admission import screen_user_rule_text
        result = screen_user_rule_text(
            "always ( (i17[t] > { 600 }) "
            "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) ).", "", False)
        self.assertIsNotNone(result)
        self.assertIn("i17", result.error)

    def test_fee_rule_reading_i17_refused(self):
        # i17 is advisory at admission and authoritative at apply, so a FEE
        # rule reading it would be quoted on one hold and charged on another.
        from consensus.admission import screen_user_rule_text
        result = screen_user_rule_text(
            "always ( (i17[t]:bv[64] > { #x0000000000000258 }:bv[64]) "
            "? (o8[t]:bv[24] = { #x000005 }:bv[24]) "
            ": (o8[t]:bv[24] = { #x000001 }:bv[24]) ).", "", False)
        self.assertIsNotNone(result)
        self.assertEqual(result.reason, "fee_reads_hold_length")
        self.assertIn("i17", result.error)

    def test_policy_rule_reading_i17_and_i2_allowed(self):
        # POLICY rules may read both apply-mocked streams; only fee rules
        # are screened.
        from consensus.admission import screen_user_rule_text
        result = screen_user_rule_text(
            "always ( (i17[t]:bv[64] <= { #x0000000000000258 }:bv[64] && "
            "i2[t]:bv[24] > { #x000000 }:bv[24]) "
            "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000000 }:bv[24]) ).", "", False)
        self.assertIsNone(result, "a policy rule may read i17 and i2")

    def test_screen_hold_widths_direct(self):
        from consensus.approvals import screen_hold_widths
        self.assertIsNone(screen_hold_widths(
            "(i17[t]:bv[64] <= { #x0000000000000258 }:bv[64])"))
        self.assertIn("bv[64]", screen_hold_widths(
            "(i17[t]:bv[32] <= { #x00000258 }:bv[32])"))
        self.assertIn("bv[64]", screen_hold_widths("(i17[t] <= { 600 })"))
        # i17 named only in a comment is not a typing hazard.
        # (Tau comments start with '#', not '//'.)
        self.assertIsNone(screen_hold_widths(
            "# i17[t] holds the hold length\n(o5[t]:bv[24] = { #x000001 }:bv[24])"))

    def test_i17_is_a_reserved_operation_key_when_active(self):
        self.assertIn(17, tau_defs.reserved_operation_keys())
        with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
            self.assertNotIn(17, tau_defs.reserved_operation_keys())

    def test_i17_custom_input_rejected_at_admission(self):
        # A sender cannot pre-fill the hold-length stream.
        from consensus.admission import validate_user_tx_reserved_domains
        tip_view = MagicMock()
        tip_view.eligibility_mode = ""
        tip_view.approval_slots_active = False
        tx = {"tx_type": "user_tx", "sender_pubkey": A,
              "operations": {"17": "0"}}
        result = validate_user_tx_reserved_domains(tx, tip_view)
        self.assertFalse(result.is_valid, result)
        self.assertIn("17", result.error)


class TestWalletTemplateRegression(unittest.TestCase):
    """Templates already in circulation (docs/approvals.md, WALLET_USAGE.md)
    must keep passing the admission screens: none of them uses i17, and the
    new stream must not disturb them."""

    TEMPLATES = {
        # Recipient whitelist on i4.
        "whitelist": (
            "always ( (i4[t]:bv[384] = { #x" + R + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
        ),
        # Escrow / arbiter flag on i13.
        "escrow": (
            "always ( (i13[t]:bv[384] = { #x" + A + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
        ),
        # Co-signature approval slot i18.
        "approval_slot": (
            "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && "
            "!(i18[t]:bv[384] = { #x" + A + " }:bv[384])) "
            "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
        ),
        # Passphrase on a custom input i26.
        "passphrase": (
            "always ( (i26[t]:bv[24] = { #x00002a }:bv[24]) "
            "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
        ),
    }

    def test_templates_pass_user_rule_screen(self):
        from consensus.admission import screen_user_rule_text
        for name, rule in self.TEMPLATES.items():
            with self.subTest(template=name):
                result = screen_user_rule_text(rule, "", False)
                self.assertIsNone(result, f"{name}: {result}")

    def test_templates_route_as_clauses(self):
        # All templates except escrow route as clauses. Escrow reads i13
        # (the proposer pubkey), which a clause cannot read -- it is an
        # accumulated-rule template, covered by the screen test above.
        from consensus.admission import validate_o5_clause_routing
        tip_view = MagicMock()
        tip_view.clause_for.return_value = None
        for name, rule in self.TEMPLATES.items():
            if name == "escrow":
                continue
            with self.subTest(template=name):
                result = validate_o5_clause_routing(
                    {"tx_type": "user_tx", "sender_pubkey": A,
                     "operations": {"0": rule}},
                    tip_view, rule)
                self.assertIsNotNone(result)
                self.assertTrue(result.is_valid, getattr(result, "error", None))
                self.assertEqual(result.data["o5_clause_action"], "declare")


class TestCapabilities(unittest.TestCase):
    def test_node_capabilities_active(self):
        self.assertEqual(
            tau_defs.node_capabilities(),
            {"recipient_policy": True, "recipient_max_hold": True})

    def test_node_capabilities_inactive(self):
        with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
            self.assertEqual(
                tau_defs.node_capabilities(),
                {"recipient_policy": False, "recipient_max_hold": False})

    def test_gettaustate_reports_capabilities(self):
        import chain_state
        from commands import gettaustate
        from types import SimpleNamespace
        container = SimpleNamespace(chain_state=chain_state)
        env = json.loads(gettaustate.execute("gettaustate", container))
        self.assertEqual(env["status"], "ok")
        self.assertEqual(
            env["data"]["capabilities"],
            {"recipient_policy": True, "recipient_max_hold": True})


# --- the admission gate, unit-tested with scripted fakes ----------------------

class _FakeAdmissionTau:
    """Scripts the guarded-mode Tau steps by (i12, i17)."""

    def __init__(self, decide):
        self.decide = decide  # (inputs) -> o5 raw value or None (absent)
        self.budget = None
        self.calls = []

    def step_multi(self, inputs, *, source):
        self.calls.append((dict(inputs), source))
        o5 = self.decide(inputs)
        return {1: "10", 5: o5} if o5 is not None else {1: "10"}


class TestAdmissionGate(unittest.TestCase):
    """_recipient_gate_refusal: the admission side of #47/#76, in isolation."""

    def setUp(self):
        self.evaluator = MockPolicyEvaluator(pool="admission")
        sender_policy.set_evaluator("admission", self.evaluator)

    def tearDown(self):
        sender_policy.set_evaluator("admission", None)

    def _gate(self, tau, tip_view, spec_text, values, sender=A, recipient=R,
              hold=0, hold_unit="seconds"):
        from commands.sendtx import _recipient_gate_refusal
        return _recipient_gate_refusal(
            tau, tip_view, spec_text, values, sender, recipient,
            hold, hold_unit, 1, (sender, recipient, 10))

    def _values(self, sender=A, recipient=R, hold=0, amount="10"):
        return {1: amount, 2: "0", 17: str(hold), 3: _lit(sender),
                4: _lit(recipient), 12: _lit(sender), 5: "1700000000"}

    def _tip_view(self, clauses=None):
        view = MagicMock()
        view.clause_for.side_effect = lambda pk, stream: (clauses or {}).get(pk)
        return view

    def test_no_recipient_policy_allows(self):
        # #47 (2): R deploys nothing -- no guarded unit, no clause -- so the
        # gate costs no step at all and allows.
        tau = _FakeAdmissionTau(lambda inputs: "0")
        result = self._gate(tau, self._tip_view(), "", self._values())
        self.assertIsNone(result)
        self.assertEqual(tau.calls, [], "no recipient policy means no extra step")

    def test_inbound_allow_list_admits_allowed_sender(self):
        # #47 (1): R allows incoming only from A; A->R passes.
        spec = _guarded_allow_list(R, A)

        def decide(inputs):
            if inputs.get(12) == _lit(R):
                return "1" if inputs.get(3) == _lit(A) else "0"
            return "1"

        result = self._gate(_FakeAdmissionTau(decide), self._tip_view(),
                            spec, self._values(sender=A))
        self.assertIsNone(result)

    def test_inbound_allow_list_refuses_other_sender(self):
        # #47 (1): B->R is refused with the recipient reason, not the
        # sender's o5 reason.
        spec = _guarded_allow_list(R, A)

        def decide(inputs):
            if inputs.get(12) == _lit(R):
                return "1" if inputs.get(3) == _lit(A) else "0"
            return "1"

        result = self._gate(_FakeAdmissionTau(decide), self._tip_view(),
                            spec, self._values(sender=B))
        self.assertIsNotNone(result)
        self.assertEqual(result["code"], "RECIPIENT_POLICY_BLOCK")
        self.assertIn("rejected by recipient policy (o5)", result["message"])
        self.assertEqual(result["details"]["recipient"], R)
        self.assertEqual(result["details"]["transfer_index"], 1)

    def test_sender_policy_untouched_by_recipient_block(self):
        # #47 (1) / #76 (1): the refusal is the RECIPIENT's verdict. The
        # sender's own step (i12 = sender) still allows -- A can pay
        # anyone else; only R refuses B.
        spec = _guarded_allow_list(R, A)
        seen = []

        def decide(inputs):
            seen.append(inputs.get(12))
            if inputs.get(12) == _lit(R):
                return "0"
            return "1"

        tau = _FakeAdmissionTau(decide)
        result = self._gate(tau, self._tip_view(), spec, self._values(sender=B))
        self.assertIsNotNone(result)
        self.assertEqual(result["code"], "RECIPIENT_POLICY_BLOCK")
        # The gate ran exactly one step, with i12 = the recipient: the
        # sender's own step (i12 = sender) is the caller's, not this gate's,
        # and it still allows.
        self.assertEqual([c[0].get(12) for c in tau.calls], [_lit(R)])

    def test_recipient_step_ignores_fee_outputs(self):
        # The recipient step's o8/o9 are never read: fees come from the
        # sender's step alone. (Here the fake returns no fee keys at all;
        # the gate must not fail on their absence.)
        spec = _guarded_allow_list(R, A)
        result = self._gate(_FakeAdmissionTau(lambda inputs: "1"),
                            self._tip_view(), spec, self._values())
        self.assertIsNone(result)

    def test_cap_zero_refuses_park_admits_plain(self):
        # #76 (1): cap 0 admits a plain transfer and refuses any park.
        spec = _guarded_cap(R, 0)

        def decide(inputs):
            if inputs.get(12) == _lit(R):
                return "1" if int(inputs.get(17, "0")) <= 0 else "0"
            return "1"

        tau = _FakeAdmissionTau(decide)
        plain = self._gate(tau, self._tip_view(), spec,
                           self._values(hold=0), hold=0)
        self.assertIsNone(plain, "cap 0 admits a plain transfer")
        park = self._gate(tau, self._tip_view(), spec,
                          self._values(hold=3600), hold=3600)
        self.assertIsNotNone(park)
        self.assertEqual(park["code"], "RECIPIENT_MAX_HOLD")
        self.assertEqual(park["details"]["max_hold_seconds"], 0)
        self.assertIn("max_hold_seconds=0", park["message"])

    def test_cap_600_seconds(self):
        # #76 (2): a 10-minute park passes, a 1-hour park is refused.
        spec = _guarded_cap(R, 600)

        def decide(inputs):
            if inputs.get(12) == _lit(R):
                return "1" if int(inputs.get(17, "0")) <= 600 else "0"
            return "1"

        tau = _FakeAdmissionTau(decide)
        short = self._gate(tau, self._tip_view(), spec,
                           self._values(hold=600), hold=600)
        self.assertIsNone(short, "a 10-minute park is within the 600s cap")
        long = self._gate(tau, self._tip_view(), spec,
                          self._values(hold=3600), hold=3600)
        self.assertIsNotNone(long)
        self.assertEqual(long["code"], "RECIPIENT_MAX_HOLD")
        self.assertEqual(long["details"]["max_hold_seconds"], 600)

    def test_cap_refusal_carries_cap(self):
        # #76 (5): the refusal message carries R's cap.
        spec = _guarded_cap(R, 600)

        def decide(inputs):
            if inputs.get(12) == _lit(R):
                return "1" if int(inputs.get(17, "0")) <= 600 else "0"
            return "1"

        result = self._gate(_FakeAdmissionTau(decide), self._tip_view(),
                            spec, self._values(hold=3600), hold=3600)
        self.assertIn("max_hold_seconds=600", result["message"])
        self.assertIn("3600 seconds", result["message"])

    def test_hold_boundary_is_inclusive(self):
        # hold == cap is admitted; cap + 1 is refused.
        spec = _guarded_cap(R, 600)

        def decide(inputs):
            if inputs.get(12) == _lit(R):
                return "1" if int(inputs.get(17, "0")) <= 600 else "0"
            return "1"

        tau = _FakeAdmissionTau(decide)
        self.assertIsNone(self._gate(tau, self._tip_view(), spec,
                                     self._values(hold=600), hold=600))
        refused = self._gate(tau, self._tip_view(), spec,
                             self._values(hold=601), hold=601)
        self.assertIsNotNone(refused)
        self.assertEqual(refused["code"], "RECIPIENT_MAX_HOLD")

    def test_clause_mode_allow_list(self):
        # #47 (1) in clause mode: R's clause allows A, refuses B.
        body = _clause_allow_from(A)
        # Clause inputs arrive bare: i3 is "#x<sender>" without the bv wrapper.
        self.evaluator.set_verdict(
            body, lambda inputs: "1" if inputs.get("i3") == "#x" + A else "0")
        tip_view = self._tip_view({R: body})
        tau = _FakeAdmissionTau(lambda inputs: "1")
        self.assertIsNone(self._gate(
            tau, tip_view, "", self._values(sender=A)))
        refused = self._gate(tau, tip_view, "", self._values(sender=B))
        self.assertIsNotNone(refused)
        self.assertEqual(refused["code"], "RECIPIENT_POLICY_BLOCK")
        # The clause ran, and the guarded pass did not (no spec text).
        self.assertEqual(tau.calls, [])

    def test_clause_mode_cap(self):
        # #76 (2) in clause mode.
        body = _clause_cap(600)
        self.evaluator.set_verdict(
            body, lambda inputs: "0" if int(inputs.get("i17", "0")) > 600 else "1")
        tip_view = self._tip_view({R: body})
        tau = _FakeAdmissionTau(lambda inputs: "1")
        self.assertIsNone(self._gate(
            tau, tip_view, "", self._values(hold=600), hold=600))
        refused = self._gate(tau, tip_view, "", self._values(hold=3600), hold=3600)
        self.assertIsNotNone(refused)
        self.assertEqual(refused["code"], "RECIPIENT_MAX_HOLD")
        self.assertEqual(refused["details"]["max_hold_seconds"], 600)

    def test_gate_disabled_when_flag_off(self):
        # The gate is inert while the feature is off: a recipient policy
        # that would block is not evaluated at all.
        spec = _guarded_allow_list(R, A)
        tau = _FakeAdmissionTau(lambda inputs: "0")
        with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
            result = self._gate(tau, self._tip_view(), spec,
                                self._values(sender=B))
        self.assertIsNone(result)
        self.assertEqual(tau.calls, [])

    def test_discriminator_runs_only_on_a_blocked_park(self):
        # The third step (hold 0) runs only when the recipient pass already
        # blocked a park -- never for a plain transfer, never on allow.
        spec = _guarded_cap(R, 600)

        def decide(inputs):
            if inputs.get(12) == _lit(R):
                return "1" if int(inputs.get(17, "0")) <= 600 else "0"
            return "1"

        tau = _FakeAdmissionTau(decide)
        self._gate(tau, self._tip_view(), spec, self._values(hold=0), hold=0)
        self.assertEqual(len(tau.calls), 1, "plain transfer: recipient pass only")
        tau.calls.clear()
        self._gate(tau, self._tip_view(), spec, self._values(hold=600), hold=600)
        self.assertEqual(len(tau.calls), 1, "allowed park: recipient pass only")
        tau.calls.clear()
        self._gate(tau, self._tip_view(), spec, self._values(hold=3600), hold=3600)
        self.assertEqual(len(tau.calls), 2, "blocked park: recipient pass + discriminator")
        self.assertEqual(tau.calls[1][0].get(17), "0")
        self.assertEqual(tau.calls[1][0].get(12), _lit(R))


# --- block apply ---------------------------------------------------------------

HEIGHT = 20
TS = 1_700_000_000
FAR = 9_999_999_999

_TX_SEQ = itertools.count()


def _base(tx_type, sender, seq, fee_limit="100"):
    return {
        "tx_id": "%s-%d" % (tx_type, next(_TX_SEQ)),
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
    }


def _transfer_tx(sk, sender, transfers, seq=0):
    tx = _base("user_tx", sender, seq)
    tx["operations"] = {"1": transfers}
    return sign_payload(tx, sk)


def _rule_tx(sk, sender, rule, seq=0):
    tx = _base("user_tx", sender, seq)
    tx["operations"] = {"0": rule}
    return sign_payload(tx, sk)


def _park_tx(sk, sender, recipient, amount, seq=0, *,
             at_height=None, at_time=None):
    tx = _base("retractable_transfer", sender, seq)
    tx["recipient_pubkey"] = recipient
    tx["amount"] = amount
    if at_time is not None:
        tx["release_at_time"] = at_time
    elif at_height is not None:
        tx["release_at_height"] = at_height
    return sign_payload(tx, sk)


def _retract_tx(sk, sender, rid_hex, seq=1):
    tx = _base("retract_transfer", sender, seq, fee_limit="0")
    tx["retractable_id"] = rid_hex
    return sign_payload(tx, sk)


def _allow_list_policy(owner, allowed):
    """Scripted evaluator: `owner`'s guarded unit allows incoming only from
    `allowed`. Any other i12 (sender pass, fee query) allows."""

    def policy(inputs):
        if inputs.get(12) == _lit(owner):
            return "1" if inputs.get(3) == _lit(allowed) else "0"
        return "1"

    return policy


def _cap_policy(owner, cap):
    """Scripted evaluator: `owner`'s guarded unit caps the hold at `cap`."""

    def policy(inputs):
        if inputs.get(12) == _lit(owner):
            return "1" if int(inputs.get(17, "0")) <= cap else "0"
        return "1"

    return policy


class Chain:
    """Applies blocks through the real engine with a scripted evaluator.

    `policy` decides o5 from the step's inputs (the guarded-mode unit);
    `spec_text` is the evaluated spec the guard detector reads. Clause
    verdicts come from the MockPolicyEvaluator installed on the "apply" pool.
    """

    def __init__(self, balances, *, fee=0, spec_text="", policy=None):
        from consensus.engine import ActiveConsensusView, TauConsensusEngine
        from consensus.governance import ConsensusLifecycleManager
        from consensus.state import TauStateSnapshot
        self._imports = (ActiveConsensusView, TauConsensusEngine,
                         ConsensusLifecycleManager, TauStateSnapshot)
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[A])
        self.lm.activate_approval_slots()
        self.fee = fee
        self.spec_text = spec_text
        self.policy = policy
        self.calls = []
        self.history = []
        self.last = None

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        self.calls.append(dict(vals))
        amount = str(vals.get(1, "0"))
        o5 = self.policy(vals) if self.policy else "1"
        return {1: amount, 8: "0", 9: str(self.fee), 5: o5}

    def block(self, txs, height=HEIGHT, ts=TS, *, replay=False, proposer=PROPOSER):
        from block import Block
        ActiveConsensusView, TauConsensusEngine, _, TauStateSnapshot = self._imports
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.bal),
                "sequence_numbers": dict(self.seq),
                "last_transfer_ts": dict(self.lts),
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(A)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        blk = Block.create(
            block_number=height, previous_hash="00" * 32, transactions=txs,
            proposer_pubkey=proposer, timestamp=ts,
        )
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=self._multi), \
             patch("chain_state.get_application_rules_state",
                   return_value=self.spec_text), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, blk, parent, replay_mode=replay)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.history.append((txs, height, ts, proposer, self.fee, self.spec_text,
                             result.next_snapshot.state_hash))
        self.last = result
        return result

    @property
    def book(self):
        return self.lm.retractable_transfers

    def clause(self, pubkey):
        return self.lm.rule_offers.clause_for(pubkey, tau_defs.USER_POLICY_STREAM_INDEX)

    @staticmethod
    def outcome(result, tx):
        """The TransactionOutcome for `tx` in an apply_block result."""
        matches = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
        assert len(matches) == 1, (tx["tx_id"], result.outcomes)
        return matches[0]

    def snapshot(self):
        nonzero = {k: v for k, v in self.bal.items() if v}
        return (nonzero, dict(self.seq), dict(self.lts), self.book.root(),
                self.book.escrow_total(), frozenset(self.book.open))


def _balances():
    return {A: 1_000_000, B: 1_000_000, R: 1_000_000, S: 1_000_000}


class TestRecipientApply(unittest.TestCase):
    def setUp(self):
        self.evaluator = MockPolicyEvaluator(pool="apply")
        sender_policy.set_evaluator("apply", self.evaluator)

    def tearDown(self):
        sender_policy.set_evaluator("apply", None)

    def test_inbound_allow_list_admits_allowed_sender(self):
        # #47 (1), apply side: A->R passes when R allows incoming only from A.
        chain = Chain(_balances(), spec_text=_guarded_allow_list(R, A),
                      policy=_allow_list_policy(R, A))
        tx = _transfer_tx(SK_A, A, [[A, R, "10"]], seq=0)
        result = chain.block([tx])
        self.assertEqual(Chain.outcome(result, tx).status, "applied")
        self.assertEqual(chain.bal[R], 1_000_010)
        self.assertEqual(chain.bal[A], 1_000_000 - 10)

    def test_inbound_allow_list_refuses_other_sender(self):
        # #47 (1), apply side: B->R is refused with the recipient reason,
        # and nothing moves.
        chain = Chain(_balances(), spec_text=_guarded_allow_list(R, A),
                      policy=_allow_list_policy(R, A))
        tx = _transfer_tx(SK_B, B, [[B, R, "10"]], seq=0)
        result = chain.block([tx])
        self.assertEqual(Chain.outcome(result, tx).status, "invalid")
        self.assertEqual(Chain.outcome(result, tx).reason,
                         "recipient_policy_block")
        self.assertEqual(chain.bal[B], 1_000_000)
        self.assertEqual(chain.bal[R], 1_000_000)
        self.assertEqual(chain.seq.get(B, 0), 0, "a refused tx advances no sequence")

    def test_no_recipient_policy_allows(self):
        # #47 (2), apply side: R deploys nothing, everyone can pay R.
        chain = Chain(_balances())
        tx_a = _transfer_tx(SK_A, A, [[A, R, "10"]], seq=0)
        tx_b = _transfer_tx(SK_B, B, [[B, R, "20"]], seq=0)
        result = chain.block([tx_a, tx_b])
        self.assertEqual(Chain.outcome(result, tx_a).status, "applied")
        self.assertEqual(Chain.outcome(result, tx_b).status, "applied")
        self.assertEqual(chain.bal[R], 1_000_030)

    def test_no_recipient_guard_means_one_roundtrip(self):
        # Regression: with no recipient policy, a transfer still costs one
        # Tau step -- the recipient gate adds no roundtrip.
        chain = Chain(_balances())
        tx = _transfer_tx(SK_A, A, [[A, R, "10"]], seq=0)
        chain.block([tx])
        self.assertEqual(len(chain.calls), 1)

    def test_batch_fails_as_one_tx(self):
        # #47 (3): A->{R,S} where S refuses A fails as one tx; the R leg
        # does not partially apply.
        spec = _guarded_allow_list(S, B)  # S allows incoming only from B
        chain = Chain(_balances(), spec_text=spec,
                      policy=_allow_list_policy(S, B))
        tx = _transfer_tx(SK_A, A, [[A, R, "10"], [A, S, "20"]], seq=0)
        result = chain.block([tx])
        self.assertEqual(Chain.outcome(result, tx).status, "invalid")
        self.assertEqual(Chain.outcome(result, tx).reason,
                         "recipient_policy_block")
        self.assertEqual(chain.bal[A], 1_000_000)
        self.assertEqual(chain.bal.get(R), 1_000_000, "the R leg must not commit")
        self.assertEqual(chain.bal.get(S), 1_000_000)

    def test_inbound_and_outbound_in_one_unit(self):
        # #47 (4): R's inbound rule + outbound whitelist in one policy unit,
        # both enforced. The unit: incoming only from A, outgoing only to S.
        spec = (
            "always ( (i12[t]:bv[384] = { #x" + R + " }:bv[384]) "
            "? ( (i4[t]:bv[384] = { #x" + R + " }:bv[384]) "
            "? ( (i3[t]:bv[384] = { #x" + A + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000000 }:bv[24]) ) "
            ": ( (i4[t]:bv[384] = { #x" + S + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000000 }:bv[24]) ) ) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
        )

        def policy(inputs):
            if inputs.get(12) != _lit(R):
                return "1"
            if inputs.get(4) == _lit(R) and inputs.get(3) != _lit(R):
                return "1" if inputs.get(3) == _lit(A) else "0"
            if inputs.get(3) == _lit(R):
                return "1" if inputs.get(4) == _lit(S) else "0"
            return "1"

        chain = Chain(_balances(), spec_text=spec, policy=policy)
        # Inbound: A->R passes, B->R refused by the recipient gate.
        tx_ok = _transfer_tx(SK_A, A, [[A, R, "10"]], seq=0)
        result = chain.block([tx_ok])
        self.assertEqual(Chain.outcome(result, tx_ok).status, "applied")
        tx_bad = _transfer_tx(SK_B, B, [[B, R, "10"]], seq=0)
        result = chain.block([tx_bad], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, tx_bad).status, "invalid")
        self.assertEqual(Chain.outcome(result, tx_bad).reason,
                         "recipient_policy_block")
        # Outbound: R->S passes, R->B refused by R's own (sender) policy.
        tx_out_ok = _transfer_tx(SK_R, R, [[R, S, "10"]], seq=0)
        result = chain.block([tx_out_ok], height=HEIGHT + 2)
        self.assertEqual(Chain.outcome(result, tx_out_ok).status, "applied")
        tx_out_bad = _transfer_tx(SK_R, R, [[R, B, "10"]], seq=1)
        result = chain.block([tx_out_bad], height=HEIGHT + 3)
        self.assertEqual(Chain.outcome(result, tx_out_bad).status, "invalid")
        self.assertEqual(Chain.outcome(result, tx_out_bad).reason,
                         "user_policy_block")

    def test_clause_mode_allow_list(self):
        # #47 (1) in clause mode: R registers an unguarded clause, then
        # A->R passes and B->R is refused at apply.
        from consensus.rule_offers import clause_body_v1
        rule = "always ( %s )." % _clause_allow_from(A)
        body = clause_body_v1(rule)
        self.evaluator.set_verdict(
            body, lambda inputs: "1" if inputs.get("i3") == "#x" + A else "0")
        chain = Chain(_balances())
        reg = _rule_tx(SK_R, R, rule, seq=0)
        result = chain.block([reg])
        self.assertEqual(Chain.outcome(result, reg).status, "applied")
        self.assertEqual(chain.clause(R), body)
        tx_ok = _transfer_tx(SK_A, A, [[A, R, "10"]], seq=0)
        result = chain.block([tx_ok], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, tx_ok).status, "applied")
        tx_bad = _transfer_tx(SK_B, B, [[B, R, "10"]], seq=0)
        result = chain.block([tx_bad], height=HEIGHT + 2)
        self.assertEqual(Chain.outcome(result, tx_bad).status, "invalid")
        self.assertEqual(Chain.outcome(result, tx_bad).reason,
                         "recipient_policy_block")

    def test_cap_zero_plain_passes_park_refused(self):
        # #76 (1), apply side: cap 0 admits a plain transfer, refuses a park.
        chain = Chain(_balances(), spec_text=_guarded_cap(R, 0),
                      policy=_cap_policy(R, 0))
        plain = _transfer_tx(SK_A, A, [[A, R, "10"]], seq=0)
        result = chain.block([plain])
        self.assertEqual(Chain.outcome(result, plain).status, "applied")
        park = _park_tx(SK_A, A, R, 100, seq=1, at_time=TS + 3600)
        result = chain.block([park], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, park).status, "invalid")
        self.assertEqual(Chain.outcome(result, park).reason,
                         "recipient_max_hold")
        self.assertEqual(chain.book.escrow_total(), 0, "no escrow was booked")
        self.assertEqual(chain.bal[A], 1_000_000 - 10, "only the plain transfer moved")

    def test_cap_600_seconds(self):
        # #76 (2), apply side: a 10-minute park passes, a 1-hour park is refused.
        chain = Chain(_balances(), spec_text=_guarded_cap(R, 600),
                      policy=_cap_policy(R, 600))
        short = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 600)
        result = chain.block([short])
        self.assertEqual(Chain.outcome(result, short).status, "applied")
        self.assertEqual(chain.book.escrow_total(), 100)
        long = _park_tx(SK_A, A, R, 100, seq=1, at_time=TS + 3600)
        result = chain.block([long], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, long).status, "invalid")
        self.assertEqual(Chain.outcome(result, long).reason,
                         "recipient_max_hold")
        self.assertEqual(chain.book.escrow_total(), 100, "only the short park booked")

    def test_hold_boundary_blocks(self):
        # hold == cap is admitted; cap + 1 is refused. Height parks make
        # the boundary exact: at height 20, release 30 is a 10-block hold.
        chain = Chain(_balances(), spec_text=_guarded_cap(R, 10),
                      policy=_cap_policy(R, 10))
        at_cap = _park_tx(SK_A, A, R, 100, seq=0, at_height=HEIGHT + 10)
        result = chain.block([at_cap])
        self.assertEqual(Chain.outcome(result, at_cap).status, "applied")
        # The second block is one height higher, so the release must be one
        # further out to keep the hold at cap + 1 = 11 blocks.
        over_cap = _park_tx(SK_A, A, R, 100, seq=1, at_height=HEIGHT + 12)
        result = chain.block([over_cap], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, over_cap).status, "invalid")
        self.assertEqual(Chain.outcome(result, over_cap).reason,
                         "recipient_max_hold")

    def test_cap_refusal_carries_cap(self):
        # #76 (5), apply side: the receipt log carries R's cap.
        chain = Chain(_balances(), spec_text=_guarded_cap(R, 600),
                      policy=_cap_policy(R, 600))
        park = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 3600)
        result = chain.block([park])
        outcome = Chain.outcome(result, park)
        self.assertEqual(outcome.reason, "recipient_max_hold")
        logs = " ".join(outcome.receipt_logs or [])
        self.assertIn("max_hold_seconds=600", logs)
        self.assertIn("3600 seconds", logs)

    def test_no_policy_parks_of_any_length_pass(self):
        # #76 (3): R deploys nothing; parks of any length pass.
        chain = Chain(_balances())
        park = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 7_776_000)
        result = chain.block([park])
        self.assertEqual(Chain.outcome(result, park).status, "applied")
        self.assertEqual(chain.book.escrow_total(), 100)

    def test_retract_never_gated(self):
        # #76 (4): A's retract of an open park to R is admitted regardless
        # of the cap -- even a cap that would have refused the park.
        from consensus.retractable import parse_retractable_transfer
        from consensus.rule_offers import clause_body_v1
        rule = "always ( %s )." % _clause_cap(0)
        body = clause_body_v1(rule)
        self.evaluator.set_verdict(
            body, lambda inputs: "0" if int(inputs.get("i17", "0")) > 0 else "1")
        chain = Chain(_balances())
        # Block 1: park while R has no policy.
        park = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 3600)
        result = chain.block([park])
        self.assertEqual(Chain.outcome(result, park).status, "applied")
        rid = parse_retractable_transfer(park).retractable_id.hex()
        # Block 2: R registers a cap-0 clause.
        reg = _rule_tx(SK_R, R, rule, seq=0)
        result = chain.block([reg], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, reg).status, "applied")
        self.assertEqual(chain.clause(R), body)
        # Block 3: the retract is admitted despite the cap.
        retract = _retract_tx(SK_A, A, rid, seq=1)
        result = chain.block([retract], height=HEIGHT + 2)
        self.assertEqual(Chain.outcome(result, retract).status, "applied")
        self.assertEqual(chain.book.escrow_total(), 0)
        self.assertEqual(chain.bal[A], 1_000_000, "the escrow was refunded")

    def test_refused_park_charges_no_fee(self):
        # The fee model: a park refused at apply charges no fee -- exactly
        # like a sender-o5 block today. An accepted park does pay.
        chain = Chain(_balances(), fee=5, spec_text=_guarded_cap(R, 0),
                      policy=_cap_policy(R, 0))
        park = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 3600)
        result = chain.block([park])
        self.assertEqual(Chain.outcome(result, park).status, "invalid")
        self.assertEqual(chain.bal[A], 1_000_000, "no fee on a refused park")
        self.assertEqual(chain.bal.get(PROPOSER, 0), 0)
        # Control: a plain transfer from the same sender DOES pay the fee.
        plain = _transfer_tx(SK_A, A, [[A, R, "10"]], seq=0)
        result = chain.block([plain], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, plain).status, "applied")
        self.assertEqual(chain.bal[A], 1_000_000 - 10 - 5)
        self.assertEqual(chain.bal[PROPOSER], 5)

    def test_recipient_step_receives_hold_on_i17(self):
        # The recipient pass sees the park's hold on i17, measured against
        # this block's clock (release TS+3600 at block TS => 3600).
        chain = Chain(_balances(), spec_text=_guarded_cap(R, 600),
                      policy=_cap_policy(R, 600))
        park = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 3600)
        chain.block([park])
        recipient_steps = [c for c in chain.calls if c.get(12) == _lit(R)]
        self.assertEqual(len(recipient_steps), 2, "recipient pass + discriminator")
        self.assertEqual(recipient_steps[0].get(17), "3600")
        self.assertEqual(recipient_steps[1].get(17), "0", "the discriminator forces hold 0")
        self.assertEqual(recipient_steps[0].get(3), _lit(A), "the counterparty is readable")
        self.assertEqual(recipient_steps[0].get(1), "100", "the amount is readable")

    def test_gate_disabled_when_flag_off(self):
        # While the feature is off, apply ignores the recipient policy.
        chain = Chain(_balances(), spec_text=_guarded_cap(R, 0),
                      policy=_cap_policy(R, 0))
        park = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 3600)
        with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
            result = chain.block([park])
        self.assertEqual(Chain.outcome(result, park).status, "applied")
        self.assertEqual(chain.book.escrow_total(), 100)

    def test_replay_reproduces_recipient_gate_exactly(self):
        # Determinism: replaying a history the recipient gate allows
        # reproduces the state hash exactly, block by block.
        chain = Chain(_balances(), fee=6, spec_text=_guarded_cap(R, 600),
                      policy=_cap_policy(R, 600))
        good = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 600)
        chain.block([good])
        spend = _transfer_tx(SK_B, B, [[B, S, "50"]], seq=0)
        chain.block([spend], height=HEIGHT + 1)

        twin = Chain(_balances(), fee=6, spec_text=_guarded_cap(R, 600),
                     policy=_cap_policy(R, 600))
        for txs, height, ts, proposer, fee, spec, state_hash in chain.history:
            twin.fee = fee
            twin.spec_text = spec
            twin.block(txs, height, ts, replay=True, proposer=proposer)
            self.assertEqual(twin.history[-1][-1], state_hash)
        self.assertEqual(twin.snapshot(), chain.snapshot())

    def test_replay_of_a_refusal_is_deterministic_with_itself(self):
        # A policy-blocked tx is counted "applied (failed)" in replay mode
        # and "invalid" normally -- pre-existing engine behavior, identical
        # for a sender-o5 block (the `if not replay_mode` guards in
        # _execute_fee_era_transfer), so normal-vs-replay hashes diverge
        # for refusals. What replay must guarantee is determinism with
        # itself: two replays of the same refused history agree exactly.
        chain = Chain(_balances(), fee=6, spec_text=_guarded_cap(R, 600),
                      policy=_cap_policy(R, 600))
        good = _park_tx(SK_A, A, R, 100, seq=0, at_time=TS + 600)
        chain.block([good])
        bad = _park_tx(SK_A, A, R, 100, seq=1, at_time=TS + 3600)
        result = chain.block([bad], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, bad).status, "invalid")

        twins = []
        for _ in range(2):
            twin = Chain(_balances(), fee=6, spec_text=_guarded_cap(R, 600),
                         policy=_cap_policy(R, 600))
            for txs, height, ts, proposer, fee, spec, _ in chain.history:
                twin.fee = fee
                twin.spec_text = spec
                twin.block(txs, height, ts, replay=True, proposer=proposer)
            twins.append(twin)
        self.assertEqual(twins[0].history[-1][-1], twins[1].history[-1][-1])
        self.assertEqual(twins[0].snapshot(), twins[1].snapshot())


# --- admission end to end (queue_transaction) -----------------------------------

class TestAdmissionFullPath(unittest.TestCase):
    """queue_transaction as a wallet sees it: the gate, the codes, the details."""

    def setUp(self):
        import importlib
        import shutil

        import chain_state
        import config
        import db
        from commands import sendtx

        importlib.reload(sendtx)
        self.sendtx = sendtx
        self._tmpdir = tempfile.mkdtemp()
        self.test_db = os.path.join(self._tmpdir, "test_recipient.sqlite")
        self.old_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state.save_application_rules_state("")
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()
        # Real admission, not the mock validator: Step 3 must run.
        self._old_force = os.environ.get("TAU_FORCE_TEST")
        os.environ["TAU_FORCE_TEST"] = "0"
        patch("commands.sendtx.validate_bls_pubkey", return_value=None).start()
        patch("commands.sendtx.tau_manager.communicate_with_tau_multi",
              side_effect=self._mock_multi).start()
        chain_state._balances[A] = 100000
        chain_state._balances[B] = 100000
        self.policy = None  # (inputs) -> o5, for the guarded steps
        self.calls = []
        self._shutil = shutil

    def tearDown(self):
        patch.stopall()
        import chain_state
        import config
        import db

        if self._old_force is None:
            os.environ.pop("TAU_FORCE_TEST", None)
        else:
            os.environ["TAU_FORCE_TEST"] = self._old_force
        chain_state.save_application_rules_state("")
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        self._shutil.rmtree(self._tmpdir, ignore_errors=True)
        config.set_database_path(self.old_db)

    def _mock_multi(self, *args, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        self.calls.append(dict(vals))
        o5 = self.policy(vals) if self.policy else "1"
        return {1: "1", 5: o5}

    def _submit(self, tx):
        return self.sendtx.queue_transaction(
            json.dumps(tx), propagate=False, dry_run=True)

    def _transfer(self, sk, sender, transfers, seq=0):
        tx = {
            "tx_id": "adm-%d" % next(_TX_SEQ),
            "tx_type": "user_tx",
            "sender_pubkey": sender,
            "sequence_number": seq,
            "expiration_time": FAR,
            "expire_at_height": 5000,
            "operations": {"1": transfers},
            "fee_limit": "1000",
        }
        return sign_payload(tx, sk)

    def _park(self, sk, sender, recipient, amount, seq=0, *, at_time=None,
              at_height=None):
        tx = {
            "tx_id": "adm-%d" % next(_TX_SEQ),
            "tx_type": "retractable_transfer",
            "sender_pubkey": sender,
            "sequence_number": seq,
            "expiration_time": FAR,
            "expire_at_height": 5000,
            "fee_limit": "1000",
            "recipient_pubkey": recipient,
            "amount": amount,
        }
        # Admission refuses a park whose tx deadline is at/after its release
        # (DEADLINE_AFTER_RELEASE): the deadline must precede the release.
        if at_time is not None:
            tx["release_at_time"] = at_time
            tx["expiration_time"] = at_time - 1
        elif at_height is not None:
            tx["release_at_height"] = at_height
            tx["expire_at_height"] = at_height
        return sign_payload(tx, sk)

    def _set_spec(self, spec_text):
        import chain_state
        chain_state.save_application_rules_state(spec_text)

    def test_inbound_allow_list_admits_allowed_sender(self):
        # #47 (1), admission side: A->R passes when R allows incoming only
        # from A.
        self._set_spec(_guarded_allow_list(R, A))
        self.policy = _allow_list_policy(R, A)
        result = self._submit(self._transfer(SK_A, A, [[A, R, "10"]]))
        self.assertTrue(result.get("ok"), result)

    def test_inbound_allow_list_refuses_other_sender(self):
        # #47 (1), admission side: B->R is refused with the recipient code.
        self._set_spec(_guarded_allow_list(R, A))
        self.policy = _allow_list_policy(R, A)
        result = self._submit(self._transfer(SK_B, B, [[B, R, "10"]]))
        self.assertFalse(result.get("ok"), result)
        self.assertEqual(result.get("code"), "RECIPIENT_POLICY_BLOCK")
        self.assertIn("rejected by recipient policy (o5)", result.get("message", ""))
        self.assertEqual(result.get("details", {}).get("recipient"), R)

    def test_no_recipient_policy_allows(self):
        # #47 (2), admission side: R deploys nothing, everyone can pay R.
        self.assertTrue(self._submit(self._transfer(SK_A, A, [[A, R, "10"]])).get("ok"))
        self.assertTrue(self._submit(self._transfer(SK_B, B, [[B, R, "10"]])).get("ok"))

    def test_batch_fails_as_one_tx(self):
        # #47 (3), admission side: A->{R,S} where S refuses A fails as one tx.
        self._set_spec(_guarded_allow_list(S, B))
        self.policy = _allow_list_policy(S, B)
        result = self._submit(
            self._transfer(SK_A, A, [[A, R, "10"], [A, S, "20"]]))
        self.assertFalse(result.get("ok"), result)
        self.assertEqual(result.get("code"), "RECIPIENT_POLICY_BLOCK")
        self.assertEqual(result.get("details", {}).get("transfer_index"), 2)

    def test_cap_zero_plain_passes_park_refused(self):
        # #76 (1), admission side: cap 0 admits a plain transfer, refuses a park
        # with RECIPIENT_MAX_HOLD carrying R's cap (0).
        self._set_spec(_guarded_cap(R, 0))
        self.policy = _cap_policy(R, 0)
        plain = self._submit(self._transfer(SK_A, A, [[A, R, "10"]]))
        self.assertTrue(plain.get("ok"), plain)
        now = self.sendtx._admission_timestamp()
        park = self._submit(self._park(SK_A, A, R, 100, at_time=now + 3600))
        self.assertFalse(park.get("ok"), park)
        self.assertEqual(park.get("code"), "RECIPIENT_MAX_HOLD")
        self.assertEqual(park.get("details", {}).get("max_hold_seconds"), 0)
        self.assertIn("max_hold_seconds=0", park.get("message", ""))

    def test_cap_600_seconds(self):
        # #76 (2), admission side: a 10-minute park passes, a 1-hour park is
        # refused with the cap.
        self._set_spec(_guarded_cap(R, 600))
        self.policy = _cap_policy(R, 600)
        now = self.sendtx._admission_timestamp()
        short = self._submit(self._park(SK_A, A, R, 100, at_time=now + 600))
        self.assertTrue(short.get("ok"), short)
        long = self._submit(self._park(SK_A, A, R, 100, at_time=now + 3600))
        self.assertFalse(long.get("ok"), long)
        self.assertEqual(long.get("code"), "RECIPIENT_MAX_HOLD")
        self.assertEqual(long.get("details", {}).get("max_hold_seconds"), 600)

    def test_checktx_reports_capabilities(self):
        # #47 (5) / #76 (6): checktx success data reports the capabilities.
        from commands import checktx
        env = json.loads(checktx.execute(
            "checktx %s" % json.dumps(self._transfer(SK_A, A, [[A, R, "10"]])), None))
        self.assertEqual(env["status"], "ok", env)
        self.assertEqual(
            env["data"]["capabilities"],
            {"recipient_policy": True, "recipient_max_hold": True})

    def test_i17_rule_refused_at_deploy_when_inactive(self):
        # #47 (5) / #76 (6): a node without the feature refuses an inbound
        # rule at deploy with a clear reason and code, not a silent admit.
        rule = "always ( %s )." % _clause_cap(600)
        tx = {
            "tx_id": "adm-%d" % next(_TX_SEQ),
            "tx_type": "user_tx",
            "sender_pubkey": R,
            "sequence_number": 0,
            "expiration_time": FAR,
            "expire_at_height": 5000,
            "operations": {"0": rule},
            "fee_limit": "1000",
        }
        sign_payload(tx, SK_R)
        with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
            result = self._submit(tx)
        self.assertFalse(result.get("ok"), result)
        self.assertEqual(result.get("code"), "RECIPIENT_POLICY_INACTIVE")
        self.assertIn("i17", result.get("message", ""))
        self.assertIn("recipient-side policy is not active", result.get("message", ""))


# --- admission-apply parity ---------------------------------------------------

class TestAdmissionApplyParity(unittest.TestCase):
    """The same policy, the same verdict, at admission and at apply.

    The full-path admission tests above and the apply tests in
    TestRecipientApply run the same scenarios through both paths; this class
    pins the shared inputs that make the two paths agree: the hold on i17 is
    fed in the same position, and the refusal codes/reasons line up.
    """

    def test_codes_and_reasons_line_up(self):
        self.assertEqual(recipient_policy.RECIPIENT_POLICY_CODE,
                         "RECIPIENT_POLICY_BLOCK")
        self.assertEqual(recipient_policy.RECIPIENT_MAX_HOLD_CODE,
                         "RECIPIENT_MAX_HOLD")
        self.assertEqual(recipient_policy.RECIPIENT_POLICY_REASON,
                         "recipient_policy_block")
        self.assertEqual(recipient_policy.RECIPIENT_MAX_HOLD_REASON,
                         "recipient_max_hold")

    def test_admission_and_apply_measure_the_same_hold(self):
        # One helper, both clocks: admission feeds next-block, apply feeds
        # the block itself. At the same clock they agree exactly.
        self.assertEqual(
            recipient_policy.hold_length_for_park(
                KIND_TIME, TS + 3600, height=20, timestamp=TS),
            (3600, "seconds"))
        self.assertEqual(
            recipient_policy.hold_length_for_park(
                KIND_HEIGHT, 30, height=20, timestamp=TS),
            (10, "blocks"))


# --- what is NOT gated ----------------------------------------------------------

class TestNotTransfersNotGated(unittest.TestCase):
    """rule_offer and approval requests are NOT transfers: the recipient
    gate never runs for them, even when the recipient's policy would refuse
    a transfer from the same sender."""

    def setUp(self):
        self.evaluator = MockPolicyEvaluator(pool="apply")
        sender_policy.set_evaluator("apply", self.evaluator)

    def tearDown(self):
        sender_policy.set_evaluator("apply", None)

    def test_rule_offer_to_blocking_recipient_registers(self):
        # R blocks all incoming transfers from B, but a rule_offer TO R
        # still registers at apply: it is not a transfer.
        chain = Chain(_balances(), spec_text=_guarded_allow_list(R, A),
                      policy=_allow_list_policy(R, A))
        tx = _base("rule_offer", B, 0)
        tx["recipient_pubkey"] = R
        # Offers only accept o5 rules; this one is B's (valid) policy offer.
        tx["rule_text"] = "always ( %s )." % _clause_allow_from(A)
        tx["expire_at_height"] = 5000
        sign_payload(tx, SK_B)
        result = chain.block([tx])
        self.assertEqual(Chain.outcome(result, tx).status, "applied")
        self.assertIn("Offer submitted",
                      " ".join(Chain.outcome(result, tx).receipt_logs or []))
        # And a transfer from B to R is still refused in the same state.
        spend = _transfer_tx(SK_B, B, [[B, R, "10"]], seq=1)
        result = chain.block([spend], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, spend).status, "invalid")
        self.assertEqual(Chain.outcome(result, spend).reason,
                         "recipient_policy_block")

    def test_approval_request_to_blocking_recipient_parks(self):
        # B's own policy blocks the transfer without votes (so the request
        # is worth parking), and R's policy refuses B's transfers -- but
        # the approval request itself is not a transfer, so it parks.
        def policy(inputs):
            if inputs.get(12) == _lit(B):
                return "0"  # B's tier rule: needs an approver's vote
            if inputs.get(12) == _lit(R):
                return "0"  # R refuses B
            return "1"

        chain = Chain(_balances(), spec_text=_guarded_allow_list(R, A),
                      policy=policy)
        tx = _base("approval_request", B, 0)
        tx.update({
            "recipient_pubkey": R,
            "amount": 5000,
            "expire_at_height": 5000,
            "approvers": {"18": A, "19": S},
            "custom_inputs": {},
        })
        sign_payload(tx, SK_B)
        result = chain.block([tx])
        self.assertEqual(Chain.outcome(result, tx).status, "applied")
        self.assertIn("Approval request parked",
                      " ".join(Chain.outcome(result, tx).receipt_logs or []))
        # The parked transfer itself is still refused when it is attempted
        # as an ordinary transfer.
        spend = _transfer_tx(SK_B, B, [[B, R, "10"]], seq=1)
        result = chain.block([spend], height=HEIGHT + 1)
        self.assertEqual(Chain.outcome(result, spend).status, "invalid")


# --- real native engine (skipped where the bindings are unavailable) ----------

def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


@unittest.skipUnless(_native_available(), "native tau module not built")
class TestRecipientPolicyNativeEngine(unittest.TestCase):
    """The core mechanism against the real engine: a guarded unit that tells
    the recipient pass from the sender pass, and an i17 cap. Short bv[16]
    keys keep the compile fast, as in test_user_policy_enforcement.py."""

    def _iface(self, rule):
        import tempfile
        from tau_native import TauInterface

        fd, path = tempfile.mkstemp(suffix=".tau")
        with os.fdopen(fd, "w") as f:
            f.write(rule)
        self.addCleanup(os.remove, path)
        return TauInterface(path)

    def test_guarded_unit_discriminates_recipient_pass(self):
        # R (#x2222) allows incoming only from A (#x1111). In the recipient
        # pass i12 is R, so the guard matches and i3 (the sender) decides;
        # in the sender pass i12 is A, so the guard does not match and the
        # unit allows.
        rule = (
            "always ( (i12[t] = {#x2222}:bv[16]) "
            "? ( (i3[t] = {#x1111}:bv[16]) "
            "? o5[t] = {1}:bv[16] : o5[t] = {0}:bv[16] ) "
            ": o5[t] = {1}:bv[16] )."
        )
        iface = self._iface(rule)
        # Recipient pass, whitelisted sender -> allow (o5 != 0).
        res = iface.communicate(
            target_output_stream_index=5,
            input_stream_values={12: ["#x2222"], 3: ["#x1111"]},
        )
        self.assertNotIn("0", res.split())
        # Recipient pass, other sender -> block (o5 == 0).
        res = iface.communicate(
            target_output_stream_index=5,
            input_stream_values={12: ["#x2222"], 3: ["#x9999"]},
        )
        self.assertIn("0", res.split())
        # Sender pass (i12 = A): the guard does not match -> allow.
        res = iface.communicate(
            target_output_stream_index=5,
            input_stream_values={12: ["#x1111"], 3: ["#x9999"]},
        )
        self.assertNotIn("0", res.split())

    def test_hold_length_stream_gates_o5(self):
        # Cap 600: a hold of 600 allows, 601 blocks.
        rule = (
            "always ( (i17[t] > {#x0258}:bv[16]) "
            "? o5[t] = {0}:bv[16] : o5[t] = {1}:bv[16] )."
        )
        iface = self._iface(rule)
        res = iface.communicate(
            target_output_stream_index=5,
            input_stream_values={17: ["#x0258"]},
        )
        self.assertNotIn("0", res.split())
        res = iface.communicate(
            target_output_stream_index=5,
            input_stream_values={17: ["#x0259"]},
        )
        self.assertIn("0", res.split())


if __name__ == "__main__":
    unittest.main()
