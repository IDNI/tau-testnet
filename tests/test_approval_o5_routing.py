"""An o5 policy rule is always a registered clause, never accumulated text.

Accumulated rules share one spec, and two rules on a shared stream either
conjoin to unsatisfiable or let the second one supersede the first. A clause is
evaluated only for its owner, so it carries no `i12` guard and the error for a
guarded rule has to say so.
"""
import pytest
from unittest.mock import MagicMock

import tau_defs
from consensus.admission import (
    TipAdmissionView,
    validate_o5_clause_routing,
    validate_user_tx_reserved_domains,
)
from consensus.rule_offers import NEUTRAL_O5_CLAUSE_BODY

A = "1a" * 48
B = "2b" * 48
AUTH = "aa" * 48
EXISTING_CLAUSE = "(o5[t]:bv[24] = { #x000000 }:bv[24])"

TIER_RULE = (
    "always ( ( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && "
    "!(i18[t]:bv[384] = { #x" + AUTH + " }:bv[384])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) ) )."
)
GUARDED_RULE = (
    "always ( (i12[t]:bv[384] = { #x" + A + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
UNGUARDED_RULE = (
    "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
NEUTRAL_RULE = "always ( %s )." % NEUTRAL_O5_CLAUSE_BODY
NON_POLICY_RULE = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
MIXED_RULE = (
    "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) && "
    "(o8[t]:bv[24] = { #x000003 }:bv[24]) )."
)


@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {A}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = True
    view.clause_for.return_value = None
    return view


def _tx(rule, transfers=None, sender=A):
    ops = {"0": rule}
    if transfers is not None:
        ops["1"] = transfers
    return {"tx_type": "user_tx", "sender_pubkey": sender, "operations": ops}


def _route(tx, tip_view):
    return validate_o5_clause_routing(tx, tip_view, tx["operations"]["0"])


# --- when routing does and does not apply ------------------------------------

@pytest.mark.parametrize("slots", [False, True])
def test_routing_does_not_depend_on_approval_slots(tip_view, slots):
    tip_view.approval_slots_active = slots
    result = _route(_tx(UNGUARDED_RULE), tip_view)
    assert result is not None and result.is_valid is True, getattr(result, "error", None)
    assert result.data["o5_clause_action"] == "declare"


def test_a_non_policy_rule_is_not_routed(tip_view):
    assert _route(_tx(NON_POLICY_RULE), tip_view) is None


def test_an_unguarded_policy_rule_is_registered(tip_view):
    result = _route(_tx(TIER_RULE), tip_view)
    assert result is not None and result.is_valid is True, getattr(result, "error", None)
    assert result.data["o5_clause_action"] == "declare"
    assert "i18[t]:bv[384]" in result.data["o5_clause_body"]
    assert "i12" not in result.data["o5_clause_body"]


# --- the guard inversion -----------------------------------------------------

def test_the_old_guarded_form_is_refused_with_guidance(tip_view):
    result = _route(_tx(GUARDED_RULE), tip_view)
    assert result.is_valid is False
    assert result.code == "CLAUSE_SHAPE"
    assert "UNGUARDED" in result.error
    assert "i12" in result.error, "the error must name what to remove"


@pytest.mark.parametrize("slots", [False, True])
def test_a_guarded_rule_is_refused_whatever_the_slot_setting(tip_view, slots):
    tip_view.approval_slots_active = slots
    result = validate_user_tx_reserved_domains(_tx(GUARDED_RULE), tip_view)
    assert result.is_valid is False
    assert result.code == "CLAUSE_SHAPE"


# --- shapes a clause cannot have --------------------------------------------

def test_a_rule_writing_o5_and_o8_is_refused(tip_view):
    result = _route(_tx(MIXED_RULE), tip_view)
    assert result.is_valid is False and result.code == "MIXED_OUTPUT_RULE"


def test_a_policy_rule_may_not_share_a_tx_with_transfers(tip_view):
    """Admission compiles the rule separately and judges transfers against the
    EXISTING live policy, i.e. the one being replaced."""
    result = _route(_tx(TIER_RULE, transfers=[[A, B, "5"]]), tip_view)
    assert result.is_valid is False and result.code == "RULE_WITH_TRANSFERS"


def test_an_empty_transfer_list_is_not_treated_as_transfers(tip_view):
    result = _route(_tx(TIER_RULE, transfers=[]), tip_view)
    assert result.is_valid is True


def test_a_mistyped_slot_is_refused(tip_view):
    """One clause typing i18 bv[384] and another bv[24] makes get_interpreter
    fail for everyone -- process-global and sticky."""
    result = _route(_tx(TIER_RULE.replace("i18[t]:bv[384]", "i18[t]:bv[24]")), tip_view)
    assert result.is_valid is False
    assert "bv[384]" in result.error


def test_an_untyped_slot_is_refused(tip_view):
    result = _route(_tx(TIER_RULE.replace("i18[t]:bv[384]", "i18[t]")), tip_view)
    assert result.is_valid is False


# --- revocation ------------------------------------------

def test_the_neutral_body_revokes(tip_view):
    result = _route(_tx(NEUTRAL_RULE), tip_view)
    assert result.is_valid is True
    assert result.data["o5_clause_action"] == "revoke"


def test_an_existing_author_may_replace_their_clause(tip_view):
    tip_view.clause_for.return_value = EXISTING_CLAUSE
    result = _route(_tx(TIER_RULE), tip_view)
    assert result.is_valid is True
    assert result.data["o5_clause_action"] == "declare"


def test_a_new_author_is_admitted_however_many_clauses_exist(tip_view):
    tip_view.clauses_for_stream.return_value = {
        format(i, "096x"): EXISTING_CLAUSE for i in range(200)
    }
    result = _route(_tx(TIER_RULE), tip_view)
    assert result.is_valid is True
    assert result.data["o5_clause_action"] == "declare"


# --- the per-block budget ---------------------------------------------------

def test_a_routed_rule_counts_against_the_block_budget():
    """Each o5 rule builds a clause, so it costs what an offer costs."""
    from consensus.engine import TauConsensusEngine as E

    plain = {"tx_type": "user_tx", "operations": {"1": [[A, B, "5"]]}}
    other_stream = _tx(NON_POLICY_RULE)
    offer = {"tx_type": "rule_offer"}

    assert E._counts_against_rule_budget(_tx(TIER_RULE)) is True
    assert E._counts_against_rule_budget(_tx(UNGUARDED_RULE)) is True
    assert E._counts_against_rule_budget(_tx(NEUTRAL_RULE)) is True
    assert E._counts_against_rule_budget(offer) is True, "always counted"
    assert E._counts_against_rule_budget(plain) is False
    assert E._counts_against_rule_budget(other_stream) is False


def test_a_whitespace_only_rule_does_not_count():
    from consensus.engine import TauConsensusEngine as E

    assert E._counts_against_rule_budget(
        {"tx_type": "user_tx", "operations": {"0": "   "}}) is False


# --- the duplicated fee-bearing constant ------------------------------------

def test_the_two_fee_bearing_sets_stay_in_step():
    """They are deliberately duplicated to keep admission free of an engine
    import, so nothing but a test stops them drifting -- and a divergence charges
    a different fee at admission than at inclusion."""
    from commands.sendtx import FEE_BEARING_TX_TYPES as admission_set
    from consensus.engine import FEE_BEARING_TX_TYPES as apply_set

    assert admission_set == apply_set
