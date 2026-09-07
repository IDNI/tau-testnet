"""An o5 policy rule becomes a registered clause instead of raw accumulated text.

WHY
---
`operations["0"]` rules are appended into one accumulated spec, and rule sharing
measured what that does on a shared stream: two guarded total-form rules on o5
conjoin to unsatisfiable, and fed sequentially through i0 the later silently
supersedes the earlier. So the second user to deploy a policy rule knocks out the
first. The accepted-clause registry and its derived composite exist to fix that,
but the only door in was someone else offering you a rule. Routing is the missing
self-service door.

The inversion worth noticing: an accumulated rule MUST carry an `i12` sender
guard (or it applies to everyone), while a registered clause must NOT (the
composite supplies the guard). So the screens swap over at activation, and the
error message has to say which form is wanted.
"""
import pytest
from unittest.mock import MagicMock

import tau_defs
from consensus.admission import (
    TipAdmissionView,
    validate_o5_clause_routing,
    validate_user_tx_reserved_domains,
)
from consensus.approvals import MAX_TIER_AUTHORS
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
    view.clause_author_count.return_value = 0
    return view


def _tx(rule, transfers=None, sender=A):
    ops = {"0": rule}
    if transfers is not None:
        ops["1"] = transfers
    return {"tx_type": "user_tx", "sender_pubkey": sender, "operations": ops}


def _route(tx, tip_view):
    return validate_o5_clause_routing(tx, tip_view, tx["operations"]["0"])


# --- when routing does and does not apply ------------------------------------

def test_inactive_chain_does_not_route(tip_view):
    """Pre-activation behaviour is untouched, which is what makes the cut safe."""
    tip_view.approval_slots_active = False
    assert _route(_tx(TIER_RULE), tip_view) is None


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


def test_an_unguarded_rule_would_be_refused_before_activation(tip_view):
    """The screens really do swap: the same text that is required after
    activation is rejected before it, and vice versa."""
    tip_view.approval_slots_active = False
    result = validate_user_tx_reserved_domains(_tx(TIER_RULE), tip_view)
    assert result.is_valid is False
    assert result.code == "UNSCOPED_USER_RULE"


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
    """One clause typing i18 bv[384] and another bv[24] leaves get_interpreter
    returning None for everyone -- process-global and sticky."""
    result = _route(_tx(TIER_RULE.replace("i18[t]:bv[384]", "i18[t]:bv[24]")), tip_view)
    assert result.is_valid is False
    assert "bv[384]" in result.error


def test_an_untyped_slot_is_refused(tip_view):
    result = _route(_tx(TIER_RULE.replace("i18[t]:bv[384]", "i18[t]")), tip_view)
    assert result.is_valid is False


# --- revocation and the author cap ------------------------------------------

def test_the_neutral_body_revokes(tip_view):
    result = _route(_tx(NEUTRAL_RULE), tip_view)
    assert result.is_valid is True
    assert result.data["o5_clause_action"] == "revoke"


def test_a_new_author_is_refused_when_the_registry_is_full(tip_view):
    tip_view.clause_author_count.return_value = MAX_TIER_AUTHORS
    result = _route(_tx(TIER_RULE), tip_view)
    assert result.is_valid is False and result.code == "CLAUSE_REGISTRY_FULL"
    assert "MEASURED" in result.error, "the cap is a measurement, say so"
    assert NEUTRAL_O5_CLAUSE_BODY in result.error, "tell them how to free a slot"


def test_an_existing_author_may_replace_their_clause_when_full(tip_view):
    """Replacing does not grow the composite, so the cap must not block it."""
    tip_view.clause_author_count.return_value = MAX_TIER_AUTHORS
    tip_view.clause_for.return_value = EXISTING_CLAUSE
    result = _route(_tx(TIER_RULE), tip_view)
    assert result.is_valid is True
    assert result.data["o5_clause_action"] == "declare"


def test_revocation_is_never_capped(tip_view):
    """Otherwise the cap becomes a permanent land-grab by the first authors."""
    tip_view.clause_author_count.return_value = MAX_TIER_AUTHORS
    result = _route(_tx(NEUTRAL_RULE), tip_view)
    assert result.is_valid is True
    assert result.data["o5_clause_action"] == "revoke"


# --- the per-block budget ---------------------------------------------------

def test_a_routed_rule_counts_against_the_block_budget():
    """Not counting it would leave the interpreter flood vector wide open on the
    one path this feature adds."""
    from consensus.engine import TauConsensusEngine as E

    routed = _tx(TIER_RULE)
    legacy = _tx(GUARDED_RULE)
    plain = {"tx_type": "user_tx", "operations": {"1": [[A, B, "5"]]}}
    offer = {"tx_type": "rule_offer"}

    assert E._counts_against_rule_budget(routed, True) is True
    assert E._counts_against_rule_budget(offer, False) is True, "always counted"
    assert E._counts_against_rule_budget(plain, True) is False

    # Before activation nothing about user_tx counting changes: existing chains
    # contain blocks carrying many legacy rules and counting them retroactively
    # would break replay of history.
    assert E._counts_against_rule_budget(routed, False) is False
    assert E._counts_against_rule_budget(legacy, False) is False


def test_a_whitespace_only_rule_does_not_count():
    from consensus.engine import TauConsensusEngine as E

    assert E._counts_against_rule_budget(
        {"tx_type": "user_tx", "operations": {"0": "   "}}, True) is False


# --- the duplicated fee-bearing constant ------------------------------------

def test_the_two_fee_bearing_sets_stay_in_step():
    """They are deliberately duplicated to keep admission free of an engine
    import, so nothing but a test stops them drifting -- and a divergence charges
    a different fee at admission than at inclusion."""
    from commands.sendtx import FEE_BEARING_TX_TYPES as admission_set
    from consensus.engine import FEE_BEARING_TX_TYPES as apply_set

    assert admission_set == apply_set
