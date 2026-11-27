"""A fee rule (o8) is admitted only when fenced to its author's own key.

Fee rules from every account join one shared spec, so an unfenced or foreign-keyed
rule would tax other accounts or override their rules. Textual only: no engine.
"""
import pytest

from consensus.admission import (
    TipAdmissionView,
    screen_user_rule_text,
    validate_user_tx_reserved_domains,
)

OWN = "ab" * 48
OTHER = "cd" * 48
FEE5 = "(o8[t]:bv[24] = { #x000005 }:bv[24])"
FEE0 = "(o8[t]:bv[24] = { #x000000 }:bv[24])"


def guard(key, ref="i12"):
    return f"({ref}[t]:bv[384] = {{ #x{key} }}:bv[384])"


def fenced(key, body=FEE5):
    return f"always ( {guard(key)} -> {body} )."


def screen(rule, sender=OWN):
    return screen_user_rule_text(rule, "", False, sender)


def admit(rule, sender=OWN):
    tx = {"operations": {"0": rule}}
    if sender is not None:
        tx["sender_pubkey"] = sender
    return validate_user_tx_reserved_domains(tx, TipAdmissionView())


ACCEPTED = [
    pytest.param(fenced(OWN), id="own-key"),
    pytest.param(fenced(OWN.upper()), id="upper-case-key"),
    pytest.param(f"always ( ({guard(OWN)}) -> ({FEE5}) ).", id="parenthesized-antecedent"),
    pytest.param(f"always ( ({guard(OWN)} -> {FEE5}) ).", id="parenthesized-whole"),
    pytest.param(
        f"always ( {guard(OWN)} -> (i1[t]:bv[24] > {{ #x000010 }}:bv[24] && {FEE5}) || "
        f"(i1[t]:bv[24] <= {{ #x000010 }}:bv[24] && {FEE0}) ).",
        id="ladder-consequent",
    ),
]

REFUSED = [
    pytest.param(fenced(OTHER), "different account", id="another-account"),
    pytest.param(fenced("00" + OWN[2:]), "different account", id="near-miss-key"),
    pytest.param(
        f"always ( ({guard(OWN)} || (i1[t]:bv[24] > {{ #x000000 }}:bv[24])) -> {FEE5} ).",
        "not guarded", id="disjoined-antecedent",
    ),
    pytest.param(
        f"always ( (({guard(OWN)}) || (i1[t]:bv[24] > {{ #x000000 }}:bv[24])) ? {FEE5} : {FEE0} ).",
        "not guarded", id="total-form-ternary-with-tax",
    ),
    pytest.param(
        f"always ( ({guard(OWN)} && (i1[t]:bv[24] > {{ #x000000 }}:bv[24])) ? "
        f"(o8[t]:bv[24] = {{ #x000005 }}:bv[24]) : (o8[t]:bv[24] = {{ #x000000 }}:bv[24]) ).",
        "not guarded", id="total-form-ternary",
    ),
    pytest.param(f"always ( {guard(OWN)} ? {FEE5} : {FEE0} ).", "not guarded", id="own-key-ternary"),
    pytest.param(f"always ( {guard(OWN)} && {FEE5} ).", "not guarded", id="conjunction"),
    pytest.param(f"always ( {FEE5} <- {guard(OWN)} ).", "not guarded", id="reverse-implication"),
    pytest.param(f"always ( {FEE5} ).", "not guarded", id="no-guard"),
    pytest.param(
        f"always ( {guard(OWN, 'i3')} -> {FEE5} ).", "not guarded", id="from-address-guard"
    ),
    pytest.param(
        f"always ( {{ #x{OWN} }}:bv[384] = i12[t]:bv[384] -> {FEE5} ).",
        "not guarded", id="literal-on-the-left",
    ),
    pytest.param(
        f"always ( (i12[t]:bv[384] = {{ {int(OWN, 16)} }}:bv[384]) -> {FEE5} ).",
        "not guarded", id="decimal-literal",
    ),
    pytest.param(
        f"always ( ({guard(OWN)} -> {FEE0}) -> {FEE5} ).", "not guarded", id="nested-antecedent",
    ),
]


@pytest.mark.parametrize("rule", ACCEPTED)
def test_screen_admits_an_own_key_fence(rule):
    assert screen(rule) is None


def test_screen_compares_the_key_by_value():
    assert screen(fenced(OWN), OWN.upper()) is None
    assert screen(fenced(OWN.upper()), OWN) is None


@pytest.mark.parametrize("rule,problem", REFUSED)
def test_screen_refuses_everything_else(rule, problem):
    rejection = screen(rule)
    assert rejection is not None
    assert rejection.reason == "unscoped_user_rule"
    assert rejection.code == "UNSCOPED_USER_RULE"
    assert rejection.details == {"stream": "o8"}
    assert problem in rejection.error
    assert "i12[t]:bv[384]" in rejection.error


@pytest.mark.parametrize("sender", [None, "", "not-hex", "0xab", 12])
def test_screen_refuses_a_missing_or_malformed_sender(sender):
    rejection = screen(fenced(OWN), sender)
    assert rejection is not None
    assert rejection.code == "UNSCOPED_USER_RULE"


def test_the_same_rule_is_foreign_for_another_sender():
    assert screen(fenced(OWN), OWN) is None
    assert screen(fenced(OWN), OTHER) is not None


@pytest.mark.parametrize("rule", [
    "always ( o20[t]:bv[24] = i1[t]:bv[24] ).",
    f"always ( {guard(OTHER)} -> (o20[t]:bv[24] = i1[t]:bv[24]) ).",
    "always ( o50[t]:bv[24] = { #x000001 }:bv[24] ).",
])
def test_rules_that_do_not_write_o8_need_no_fence(rule):
    assert screen(rule, None) is None


def test_earlier_screens_still_speak_first():
    ternary = f"always ( {guard(OWN)} ? (o8[t]:bv[24] = i2[t]:bv[24]) : {FEE0} )."
    assert screen(ternary).reason == "fee_reads_balance"
    history = f"always ( {guard(OWN)} -> (o8[t]:bv[24] = i1[t-1]:bv[24]) )."
    assert screen(history).reason == "temporal_reference"
    reserved = f"always ( {guard(OWN)} -> (o9[t]:bv[24] = {{ #x000001 }}:bv[24]) )."
    assert screen(reserved).reason == "reserved_output_stream"


@pytest.mark.parametrize("rule", [p.values[0] for p in ACCEPTED])
def test_admission_admits_an_own_key_fence(rule):
    result = admit(rule)
    assert result.is_valid, result.error


@pytest.mark.parametrize("rule,problem", REFUSED)
def test_admission_refuses_what_the_screen_refuses(rule, problem):
    result = admit(rule)
    assert not result.is_valid
    assert result.code == "UNSCOPED_USER_RULE"
    assert result.details["stream"] == "o8"


def test_admission_refuses_a_tx_without_a_sender():
    result = admit(fenced(OWN), sender=None)
    assert not result.is_valid
    assert result.code == "UNSCOPED_USER_RULE"
