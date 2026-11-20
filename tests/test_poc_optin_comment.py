"""PoC: the guarded pass stepped on spec *text*, and nothing in it could
tell a unit that scopes the recipient from a key mentioned elsewhere.

Re-measured honestly: the opt-in screen as shipped (re.search r"\\bi3\\s*\\["),
already used a word boundary and already ran on comment-stripped text, so
swapping it for an index read changes no verdict — 360 generated shapes
agree. What follows therefore pins the part that *does* change: the spec is
read as units, and a recipient is judged by her own unit or by nothing,
never by a rule that only talks about her somewhere.

The consequence cases below use the real prescreen and the real unit
splitter, with the session step stubbed — the same call shape
`guarded_recipient_blocks` gives the engine.
"""
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex
from consensus import recipient_policy

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)


def _values(sender, recipient, amount=100):
    return {1: str(amount), 3: "#x" + sender + ":bv[384]",
            4: "#x" + recipient + ":bv[384]"}


def _unit(owner, verdict):
    return ("always ( (i12[t]:bv[384] = { #x" + owner + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x00000" + verdict + " }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) ).")


def _blocking(values):
    return {tau_defs.USER_POLICY_STREAM_INDEX: "0"}


def test_spec_without_units_yields_no_units():
    """A flat spec has nothing to scope on; the old pass still judged it."""
    flat = ("/* owner " + CAROL + " was here */ "
            "always ( o5[t]:bv[24] = { #x000000 }:bv[24] ).")
    assert recipient_policy.spec_units(flat) == []


def test_spec_with_units_splits_into_guard_and_body():
    units = recipient_policy.spec_units(_unit(CAROL, "0"))
    assert len(units) == 1
    guard, body = units[0]
    assert recipient_policy._unit_for_owner(guard, CAROL) == CAROL
    assert "000000" in body


def test_key_only_in_a_comment_does_not_make_the_pass_step():
    stepped = []

    def evaluate(values):
        stepped.append(1)
        return {tau_defs.USER_POLICY_STREAM_INDEX: "0"}

    flat = ("/* owner " + CAROL + " was here */ "
            "always ( o5[t]:bv[24] = { #x000000 }:bv[24] ).")
    blocked, o5 = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(ALICE, CAROL), ALICE, CAROL, spec_text=flat)

    assert stepped == [], "no scoped unit: the pass must not step"
    assert (blocked, o5) == (False, None), "neutral default, not a verdict"


def test_only_the_counterparty_stream_opts_into_the_gate():
    """Index reads, not text: i3/i17/i27 in, i4 and neighbours out."""
    for body, expected in (
        ("(i3[t]:bv[384] = { 1 }:bv[384])", True),
        ("(i17[t]:bv[64] <= { 600 }:bv[64])", True),
        ("(i27[t]:bv[8] < { 5 }:bv[8])", True),
        ("(i4[t]:bv[384] = { 1 }:bv[384])", False),
        ("(i30[t]:bv[8] = { 1 }:bv[8])", False),
        ("(i13[t]:bv[8] = { 1 }:bv[8])", False),
    ):
        assert recipient_policy.clause_is_recipient_relevant(body) is expected, body


def test_the_gate_still_blocks_through_the_recipients_own_unit():
    """Control: a real unit on the recipient still refuses the transfer."""
    blocked, o5 = recipient_policy.guarded_recipient_blocks(
        _blocking, _values(ALICE, CAROL), ALICE, CAROL,
        spec_text=_unit(CAROL, "0"))
    assert blocked is True and o5 == "0"


def test_the_right_unit_wins_when_two_units_are_present():
    """BOB's and CAROL's units coexist; CAROL's must decide for CAROL."""
    spec = _unit(BOB, "1") + "\n" + _unit(CAROL, "0")
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        _blocking, _values(ALICE, CAROL), ALICE, CAROL, spec_text=spec)
    assert blocked is True
