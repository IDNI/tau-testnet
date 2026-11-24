"""Issue #42, ask 3 on the #151 line (B02-6, audit §6.2): the incident
unit cannot happen here, measured -- not assumed.

The incident (#42, 2026-09-06, block 29): a user submitted a total-form
o5 unit guarded on their own i12 while the shared spec already held
ANOTHER account's total-form o5 unit; the pointwise engine dropped the
unit as a no-op and the sender was charged a fee for nothing. Ask 3 is
the refusal of that outcome: no fee for a no-op.

Measured on this line (these tests pin the measurement):

  * The incident's precondition cannot be constructed via user_tx at
    all. A rule that writes o5 NEVER enters the shared spec in any
    form: admission's routing screen (`validate_o5_clause_routing`,
    decided first inside `validate_user_tx_reserved_domains`) refuses
    the old i12-guarded form by shape (CLAUSE_SHAPE), and the
    unguarded total form is routed to the sender's OWN clause-registry
    slot instead of the spec.
  * Forced past admission, apply hard-rejects the same unit
    (`_apply_o5_clause_routing` mirrors the screen): the transaction
    is invalid with the machine-readable reason `rule_not_applied`,
    the rejected receipt carries fee_charged 0, nothing is recorded
    as a rule outcome, and nothing accumulates.
  * The unguarded form -- the shape the refusal message itself tells
    the wallet to submit -- registers the sender's clause and records
    the registry outcome this line serves through gettxstatus
    (evidence: clause_registry, the stored-text hash pinning the exact
    body), still without touching the shared spec.

The governance path (`consensus_rule_update` carrying a total-form
unit) is a different submission channel with its own guards; it is
out of scope for these tests, as it was for the incident.

The apply-path cases drive the real apply_block through the mock
harness of tests/test_active_rules_view.py (imported, the pattern of
PR #180's ask-3 file importing its apply harness): the Tau seam is
stubbed, the routing and recording code under test is the node's own.
"""
import hashlib
from unittest.mock import MagicMock

import db
import test_active_rules_view as v
from consensus import sender_policy
from consensus.admission import (
    validate_o5_clause_routing,
    validate_user_tx_reserved_domains,
)
from consensus.facade import TipAdmissionView
from consensus.policy_mock import MockPolicyEvaluator

ALICE = v.ALICE

# The incident unit shape: a total-form o5 policy guarded on the
# sender's own i12, in the bv[24] typing for o5. (On the incident chain
# the spec already held another account's unit of this shape; on this
# line that precondition cannot arise -- see the module docstring.)
INCIDENT_UNIT = (
    "always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
# The same policy written the way clauses require it: unguarded (a
# clause is evaluated only for its owner).
UNGUARDED_TOTAL_FORM_O5 = (
    "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def _tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.clause_for.return_value = None
    return view


def _incident_tx():
    return {"tx_type": "user_tx", "sender_pubkey": ALICE,
            "operations": {"0": INCIDENT_UNIT}}


def test_incident_unit_is_refused_at_admission():
    """Both the routing screen itself and the public reserved-domains
    screen that decides it first refuse the incident unit by shape:
    CLAUSE_SHAPE, naming the i12 guard and the unguarded remedy. The
    unit is not admitted as a shared-spec rule, and it is not admitted
    as a clause either -- it is refused, full stop."""
    routing = validate_o5_clause_routing(
        _incident_tx(), _tip_view(), INCIDENT_UNIT)
    assert routing is not None
    assert routing.is_valid is False
    assert routing.code == "CLAUSE_SHAPE"
    assert "i12" in routing.error
    assert "UNGUARDED" in routing.error

    screened = validate_user_tx_reserved_domains(
        _incident_tx(), _tip_view())
    assert screened.is_valid is False
    assert screened.code == "CLAUSE_SHAPE"


def test_incident_unit_is_hard_rejected_at_apply_with_no_fee_and_no_effect(
        temp_database, tmp_path):
    """Forced into a block (a proposer that never ran admission), the
    incident unit is hard-rejected by the apply-side mirror of the
    routing screen: invalid, reason `rule_not_applied`, the 'o5 clause
    ignored' log line, no fee taken, no rule outcome recorded, no
    snapshot taken, and the unit never accumulates -- the exact
    opposite of the incident's charged no-op."""
    sender_policy.set_evaluator("apply", MockPolicyEvaluator(pool="apply"))
    try:
        node = v._Node(tmp_path / "node.sqlite")
        result, block_obj = node.apply_and_commit(
            [v._rule_tx("incident-1", INCIDENT_UNIT, seq=0)])

        assert result.accepted_tx_ids == []
        assert result.invalid_tx_ids == ["incident-1"]
        (outcome,) = result.outcomes
        assert outcome.status == "invalid"
        assert outcome.reason == "rule_not_applied"
        assert "o5 clause ignored" in " | ".join(outcome.receipt_logs)
        assert "i12" in " | ".join(outcome.receipt_logs)

        # No fee: the sender's balance is exactly what it was (the
        # rejected receipt in consensus/engine.py carries
        # fee_charged 0 for this reason; the balance is the effect).
        assert result.next_snapshot.metadata["balances"][ALICE] == 100000
        # No effect: nothing recorded, nothing accumulated, no revision.
        assert result.next_snapshot.metadata["rule_outcomes"] == []
        assert db.get_rule_outcome(
            block_obj.tx_ids[0], block_obj.block_hash) is None
        assert node.fake.accumulation == []
        assert db.get_latest_spec_snapshot() is None
    finally:
        sender_policy.set_evaluator("apply", None)


def test_unguarded_total_form_o5_registers_a_clause_and_never_accumulates(
        temp_database, tmp_path):
    """The shape the refusal prescribes: the unguarded total form is
    accepted -- as the sender's own registry clause, never as spec
    text. Its confirmed outcome is the registry record this line
    serves (CLAUSE_REGISTERED, evidence marked, the stored-text hash
    pinning the clause body), and no spec snapshot exists for it."""
    sender_policy.set_evaluator("apply", MockPolicyEvaluator(pool="apply"))
    try:
        node = v._Node(tmp_path / "node.sqlite")
        result, block_obj = node.apply_and_commit(
            [v._rule_tx("clause-1", UNGUARDED_TOTAL_FORM_O5, seq=0)])
        assert result.accepted_tx_ids == ["clause-1"]

        outcome = v._status(block_obj.tx_ids[0])["rule_outcome"]
        assert outcome["outcome"] == "CLAUSE_REGISTERED"
        assert outcome["evidence"] == "clause_registry"
        assert outcome["account"] == ALICE.lower()
        assert outcome["stream"] == 5
        assert "spec_revision_after" not in outcome

        from consensus.rule_offers import clause_body_v1

        body_sha = hashlib.sha256(
            clause_body_v1(UNGUARDED_TOTAL_FORM_O5).encode("utf-8")
        ).hexdigest()
        assert outcome["stored_text_sha256"] == body_sha

        # The unit itself never entered the shared spec.
        assert node.fake.accumulation == []
        assert db.get_latest_spec_snapshot() is None
    finally:
        sender_policy.set_evaluator("apply", None)
