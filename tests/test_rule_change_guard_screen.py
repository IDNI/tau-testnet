"""Rule-change guard: input map, domain screen (admission and apply) and the
guarantee that offers never reach the guard registry key."""
import pytest

import tau_defs
from consensus import rule_offers
from consensus.admission import (
    _screen_clause_domains,
    _screen_guard_domains,
    is_rule_fragment_error,
)
from consensus.engine import _clause_domain_rejection
from consensus.rule_offers import (
    ALLOWED_TARGET_STREAMS,
    RuleOffer,
    RuleOfferLifecycleManager,
    RuleOfferDecision,
    RuleOfferShapeError,
)
from consensus.sender_policy import change_inputs

ALICE = format(1, "096x")
BOB = format(2, "096x")
PUBKEY = "{ #x" + "ab" * 48 + " }:bv[384]"

_ON = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
_OFF = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def _cond(condition):
    return f"always ( ({condition}) ? {_ON} : {_OFF} )."


def _body_of(rule):
    return rule[len("always ( "):-len(" ).")]


GOOD = {
    "kind": _cond("i1[t]:bv[24] = { #x000001 }:bv[24]"),
    "timestamp": _cond("i5[t]:bv[24] > { #x000064 }:bv[24]"),
    "slot": _cond("i18[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]"),
    "last_slot": _cond("i25[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]"),
    "mixed": _cond(
        "i1[t]:bv[24] = { #x000004 }:bv[24] && i18[t]:bv[384] = { #x"
        + "ab" * 48 + " }:bv[384]"
    ),
}

BAD = {
    "i2": _cond("i2[t]:bv[24] > { #x000064 }:bv[24]"),
    "i3": _cond("i3[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]"),
    "i12": _cond("i12[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]"),
    "i13": _cond("i13[t]:bv[24] = { #x000001 }:bv[24]"),
    "i26": _cond("i26[t]:bv[24] = { #x000001 }:bv[24]"),
    "slot_bv24": _cond("i18[t]:bv[24] = { #x000001 }:bv[24]"),
    "writes_o8": "always ( o8[t]:bv[24] = { #x000001 }:bv[24] ).",
    "writes_o6": _cond("i1[t]:bv[24] = { #x000001 }:bv[24]").replace("o5", "o6"),
    "also_writes_o9": (
        "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) && "
        "(o9[t]:bv[24] = { #x000001 }:bv[24]) )."
    ),
    "writes_nothing": "always ( i1[t]:bv[24] = { #x000001 }:bv[24] ).",
    "temporal": "always ( o5[t]:bv[24] = i1[t-1]:bv[24] ).",
    "operator_word": "always ( o5[t]:bv[24] = i1[t]:bv[24] && F ( i1[t]:bv[24] = 1 ) ).",
    "time_constraint": "always ( [t > 3] && o5[t]:bv[24] = i1[t]:bv[24] ).",
    "quantifier": "always ( ex x ( o5[t]:bv[24] = i1[t]:bv[24] ) ).",
    "untyped": "always ( o5[t]:bv[24] = i1[t] ).",
}


# --- change_inputs ------------------------------------------------------------

def test_change_inputs_defaults_every_slot_to_zero():
    out = change_inputs(tau_defs.RULE_CHANGE_KIND_SET_GUARD, 1234)
    slots = {f"i{i}": "0" for i in tau_defs.approval_slot_indices()}
    assert out == {"i1": "4", "i5": "1234", **slots}


def test_change_inputs_feeds_slot_values_bare():
    out = change_inputs(1, 7, {18: PUBKEY, 20: "0"})
    assert out["i18"] == "#x" + "ab" * 48
    assert out["i19"] == "0"
    assert out["i1"] == "1" and out["i5"] == "7"


def test_change_inputs_keys_are_the_guard_read_set():
    out = change_inputs(1, 7)
    expected = {f"i{i}" for i in (1, 5, *tau_defs.approval_slot_indices())}
    assert set(out) == expected


def test_kinds_and_guard_index():
    kinds = [
        tau_defs.RULE_CHANGE_KIND_SET_POLICY,
        tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY,
        tau_defs.RULE_CHANGE_KIND_ACCEPT_OFFER,
        tau_defs.RULE_CHANGE_KIND_SET_GUARD,
        tau_defs.RULE_CHANGE_KIND_REVOKE_GUARD,
    ]
    assert kinds == [1, 2, 3, 4, 5]
    assert tau_defs.RULE_CHANGE_GUARD_INDEX == 0xFFFFFFFF


# --- guard domain screen --------------------------------------------------------

@pytest.mark.parametrize("name", GOOD)
def test_guard_screen_accepts(name):
    assert _screen_guard_domains(_body_of(GOOD[name])) is None
    assert _clause_domain_rejection(_body_of(GOOD[name]), guard=True) is None


@pytest.mark.parametrize("name", BAD)
def test_guard_screen_rejects(name):
    assert _screen_guard_domains(_body_of(BAD[name])) is not None


@pytest.mark.parametrize("name", list(GOOD) + list(BAD))
def test_apply_variant_agrees_with_admission(name):
    body = _body_of(GOOD[name] if name in GOOD else BAD[name])
    error = _screen_guard_domains(body)
    rejection = _clause_domain_rejection(body, guard=True)
    assert (rejection is None) == (error is None)
    if rejection is not None:
        assert rejection[0] == error


def test_guard_bodies_may_not_carry_comments():
    body = "# uses i2 and o8 in prose\n" + _body_of(GOOD["kind"])
    assert is_rule_fragment_error(_screen_guard_domains(body))


def test_policy_screen_still_admits_what_the_guard_screen_refuses():
    assert _screen_clause_domains(_body_of(BAD["i2"])) is None
    assert _screen_guard_domains(_body_of(BAD["i2"])) is not None


# --- offers never reach the guard key --------------------------------------------

def test_guard_index_is_not_an_offer_target():
    assert tau_defs.RULE_CHANGE_GUARD_INDEX not in ALLOWED_TARGET_STREAMS


def test_a_guard_shaped_offer_lands_on_o5_not_the_guard_key():
    mgr = RuleOfferLifecycleManager()
    text = GOOD["kind"]
    offer = RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=BOB,
                      rule_text=text, expire_at_height=500)
    assert mgr.submit_offer(offer)
    decision = RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=BOB,
                                 accept=True, rule_text=text)
    assert mgr.submit_decision(decision) == tau_defs.USER_POLICY_STREAM_INDEX
    assert (BOB, tau_defs.USER_POLICY_STREAM_INDEX) in mgr.accepted_clauses
    assert (BOB, tau_defs.RULE_CHANGE_GUARD_INDEX) not in mgr.accepted_clauses


def test_accept_refuses_to_write_the_guard_key(monkeypatch):
    mgr = RuleOfferLifecycleManager()
    text = GOOD["kind"]
    offer = RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=BOB,
                      rule_text=text, expire_at_height=500)
    assert mgr.submit_offer(offer)
    monkeypatch.setattr(
        rule_offers, "normalize_offer_rule_text",
        lambda _t: ("x", tau_defs.RULE_CHANGE_GUARD_INDEX),
    )
    decision = RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=BOB,
                                 accept=True, rule_text=text)
    with pytest.raises(RuleOfferShapeError):
        mgr.submit_decision(decision)
    assert (BOB, tau_defs.RULE_CHANGE_GUARD_INDEX) not in mgr.accepted_clauses
