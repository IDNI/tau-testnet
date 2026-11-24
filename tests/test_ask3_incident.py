"""Issue #42, ask 3: a user unit dropped because the spec already holds
another account's total-form o5 unit must be refused at admission (same class
as UNSCOPED_USER_RULE), not charged a fee for a no-op.

Measured outcome on this branch (see docs/design-42-rules-in-force.md,
"Ask 3"): the incident unit shape cannot reach the shared specification at
all. A total-form o5 unit is routed to the per-account clause registry; the
old i12-guarded form the incident used is refused at admission (CLAUSE_SHAPE)
and hard-rejected at apply, with no fee and nothing accumulated. These tests
pin that end-to-end outcome, so a future change to the routing cannot
silently reopen the incident.
"""
from unittest.mock import MagicMock

import test_approval_apply as ap
from consensus.admission import (
    TipAdmissionView,
    validate_user_tx_reserved_domains,
)

B = ap.BOB

# The incident unit (#42, 2026-09-06, block 29): a total-form o5 unit guarded
# on the sender's i12, in the harness's bv[24] typing for o5. The spec already
# held another account's total-form o5 unit (owner 93da919a...).
INCIDENT_UNIT = (
    "always ( (i12[t]:bv[384] = { #x" + B + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
# The same policy written the way clauses require it: unguarded (a clause is
# evaluated only for its owner).
UNGUARDED_TOTAL_FORM_O5 = (
    "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def _tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {ap.ALICE}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = True
    view.clause_for.return_value = None
    return view


def _fed_units():
    """Unit texts the apply path fed to the engine for accumulation."""
    return [c.get("rule_text") for c in ap._apply.single_calls
            if c.get("apply_rules_update")]


def test_incident_unit_is_refused_at_admission():
    tx = {"tx_type": "user_tx", "sender_pubkey": B,
          "operations": {"0": INCIDENT_UNIT}}
    result = validate_user_tx_reserved_domains(tx, _tip_view())
    assert result.is_valid is False
    assert result.code == "CLAUSE_SHAPE"
    assert "i12" in result.error


def test_incident_unit_is_hard_rejected_at_apply_with_no_fee_and_no_effect():
    result, post, _ = ap._apply(
        [ap.rule_tx(INCIDENT_UNIT, sk=ap.SK_BOB, sender=B)])
    (row,) = result.next_snapshot.metadata["tx_outcomes"]
    assert row["status"] == "rejected", row
    assert row["reason"] == "rule_not_applied", row
    assert row["fee_charged"] == 0, row
    assert "o5 clause ignored" in " | ".join(row["logs"])
    assert post.rule_offers.clause_for(B, 5) is None
    assert INCIDENT_UNIT not in _fed_units()
    assert ap._balances(result)[B] == 0


def test_unguarded_total_form_o5_registers_a_clause_and_never_accumulates():
    result, post, _ = ap._apply(
        [ap.rule_tx(UNGUARDED_TOTAL_FORM_O5, sk=ap.SK_BOB, sender=B)])
    (row,) = result.next_snapshot.metadata["tx_outcomes"]
    assert row["status"] == "applied", row
    assert post.rule_offers.clause_for(B, 5) is not None
    assert UNGUARDED_TOTAL_FORM_O5 not in _fed_units()
    (effect,) = row["rule_effects"]
    assert effect["account"] == B
    assert effect["kind"] == "clause"
    assert effect["stream"] == 5
    assert effect["action"] == "registered"
    assert len(effect["sha256"]) == 64
