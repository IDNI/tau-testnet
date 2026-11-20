"""Guarded prescreen, corrected: the pass must step only when the spec
carries a unit scoped on the recipient.

The shipped prescreen was `recipient_key in spec_text` — a raw substring
test. A key that only appears in a COMMENT, or only inside another unit's
body, therefore made the pass step, and whatever the accumulated spec
resolved to became the verdict for the recipient. These cases pin the fix.
"""
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex
from consensus import recipient_policy

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)


def _values(sender, recipient, amount):
    return {1: str(amount), 3: "#x" + sender + ":bv[384]", 4: "#x" + recipient + ":bv[384]"}


def _unit(owner, verdict):
    return ("always ( (i12[t] = { #x" + owner + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x00000" + verdict + " }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) ).")


def _blocking(values):
    return {tau_defs.USER_POLICY_STREAM_INDEX: "0"}


def test_key_only_in_a_comment_does_not_make_the_pass_step():
    stepped = []

    def evaluate(values):
        stepped.append(1)
        return {tau_defs.USER_POLICY_STREAM_INDEX: "0"}

    spec = ("/* owner " + CAROL + " was here */ "
            "always ( o5[t]:bv[24] = { #x000000 }:bv[24] ).")
    blocked, o5 = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(ALICE, CAROL, 100), ALICE, CAROL, spec_text=spec)

    assert not stepped, "no scoped unit: the pass must not step"
    assert blocked is False and o5 is None, "neutral default, not a verdict"


def test_key_inside_another_units_body_is_not_a_scope():
    """ALICE has a unit; CAROL's key appears only inside that unit's body."""
    spec = ("always ( (i12[t] = { #x" + ALICE + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x000000 }:bv[24] "
            ": o5[t]:bv[24] = { #x000001 }:bv[24]) ).")
    assert BOB not in spec
    stepped = []

    def evaluate(values):
        stepped.append(1)
        return {tau_defs.USER_POLICY_STREAM_INDEX: "0"}

    blocked, _ = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(ALICE, CAROL, 100), ALICE, CAROL, spec_text=spec)
    assert not stepped
    assert blocked is False


def test_unit_scoped_on_the_recipient_is_honoured():
    """Control: the ordinary shape must still judge and still block."""
    spec = _unit(CAROL, "0")
    blocked, o5 = recipient_policy.guarded_recipient_blocks(
        _blocking, _values(ALICE, CAROL, 100), ALICE, CAROL, spec_text=spec)
    assert blocked is True and o5 == "0"


def test_recipient_unit_is_picked_out_of_a_multi_unit_spec():
    """CAROL's own unit is chosen, not whichever unit the spec resolves to."""
    spec = _unit(ALICE, "1") + "\n" + _unit(CAROL, "0")
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        _blocking, _values(BOB, CAROL, 100), BOB, CAROL, spec_text=spec)
    assert blocked is True


def test_unpadded_and_upper_case_key_literal_still_scopes():
    """A spec may zero-strip or upcase its key literal; the scope must match."""
    spec = _unit(CAROL.lstrip("0").upper(), "0")
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        _blocking, _values(ALICE, CAROL, 100), ALICE, CAROL, spec_text=spec)
    assert blocked is True
