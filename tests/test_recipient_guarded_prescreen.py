"""Guarded-mode prescreen pins: the two PoC shapes PR #133 proved against
PR #126, ported to this gate.

PR #133 (xoepoo) showed that a guarded-mode prescreen doing a raw substring
test (`recipient_key in spec_text`) steps the recipient pass for a recipient
who has no unit of her own whenever her key appears

  (a) only inside a comment in the spec text, or
  (b) only inside another account's unit body,

and whatever the accumulated spec then resolves to under i12 = recipient
becomes her verdict — she is judged by somebody else's unit. The same file's
controls pin the other direction: a unit scoped on the recipient IS
honoured, her unit is picked out of a multi-unit spec, and a zero-stripped
or upper-case key literal still scopes (a substring test misses that one —
a real unit silently unenforced).

The shapes are pinned at the two levels the flaw could live at: the
prescreen helper itself (`sender_policy.spec_mentions_account`), and the
engine's apply pass through the harness from test_recipient_controls, whose
mock session resolves o5 exactly as the spec text under test declares —
by the i12 it is stepped with.
"""
import test_approval_apply as ap
import test_recipient_controls as rc
from consensus import sender_policy

ALICE = ap.ALICE
CAROL = ap.STRANGER  # the recipient with no unit of her own

BALANCES = {ap.ALICE: 100000, ap.AUTH: 10, ap.SCAN: 10, ap.BOB: 0, CAROL: 0}


def _unit(owner, taken, otherwise):
    return (
        "always ( (i12[t]:bv[384] = { #x" + owner + " }:bv[384]) "
        "? (o5[t]:bv[24] = { #x00000" + taken + " }:bv[24]) "
        ": (o5[t]:bv[24] = { #x00000" + otherwise + " }:bv[24]) )."
    )


# ALICE's default-deny unit: her own payments pass, everyone else's are
# blocked — a coherent guarded unit for ALICE. CAROL's key appears ONLY in
# the comment above it.
SPEC_KEY_ONLY_IN_COMMENT = (
    "/* owner " + CAROL + " was here */\n" + _unit(ALICE, "1", "0")
)

# The same unit, with CAROL's key appearing only inside ALICE's unit BODY
# (an i4 comparison in the taken branch); the guard binds i12 to ALICE.
SPEC_KEY_ONLY_IN_ANOTHER_UNITS_BODY = (
    "always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? ((i4[t]:bv[384] = { #x" + CAROL + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)

# CAROL's own unit: she blocks everything inbound.
SPEC_UNIT_ON_CAROL = _unit(CAROL, "0", "1")

# ALICE's unit (never blocks) alongside CAROL's own blocking unit.
SPEC_MULTI_UNIT = _unit(ALICE, "1", "1") + "\n" + _unit(CAROL, "0", "1")

# CAROL's own unit, its guard literal zero-stripped and upper-cased — a
# spec may write its key literal in any padded width or case.
SPEC_UNIT_ON_CAROL_UNPADDED_UPPER = (
    "always ( (i12[t]:bv[384] = { #x" + CAROL.lstrip("0").upper() + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def _resolves_like_alices_unit(vals):
    """The mock session for the two PoC specs: stepped with i12 = ALICE the
    spec allows, stepped with i12 = CAROL it resolves to a block (ALICE's
    default-deny else-branch) — the verdict that must never be attributed
    to CAROL, who has no unit."""
    out = {1: str(vals.get(1, "0") or 0), 8: "0", 9: "7", 5: "1"}
    if CAROL in str(vals.get(12, "")):
        out[5] = "0"
    return out


def _resolves_like_carols_unit(vals):
    """The mock session for the control specs: i12 = CAROL blocks (her own
    unit), anyone else's step allows."""
    out = {1: str(vals.get(1, "0") or 0), 8: "0", 9: "7", 5: "1"}
    if CAROL in str(vals.get(12, "")):
        out[5] = "0"
    return out


def _stepped_for_recipient(calls):
    return any(CAROL in str((c.get("input_stream_values") or {}).get(12, ""))
               for c in calls)


# --- the prescreen helper itself --------------------------------------------

def test_prescreen_key_only_in_a_comment_is_not_a_scope():
    assert sender_policy.spec_mentions_account(
        SPEC_KEY_ONLY_IN_COMMENT, CAROL) is False


def test_prescreen_key_only_in_another_units_body_is_not_a_scope():
    assert sender_policy.spec_mentions_account(
        SPEC_KEY_ONLY_IN_ANOTHER_UNITS_BODY, CAROL) is False


def test_prescreen_unit_scoped_on_the_recipient_is_a_scope():
    assert sender_policy.spec_mentions_account(
        SPEC_UNIT_ON_CAROL, CAROL) is True


def test_prescreen_unpadded_upper_case_literal_still_scopes():
    assert sender_policy.spec_mentions_account(
        SPEC_UNIT_ON_CAROL_UNPADDED_UPPER, CAROL) is True


def test_prescreen_zero_stripped_literal_still_scopes():
    """The width facet of #133's literal control, with a synthetic
    leading-zero key (CAROL's own key has no leading zero to strip): a
    spec that writes the owner's literal zero-stripped must still scope —
    a substring test misses it, leaving a real unit unenforced."""
    owner = "0000" + "ab" * 46  # 96 hex digits, leading zeros present
    spec = _unit(owner.lstrip("0").upper(), "0", "1")
    assert sender_policy.spec_mentions_account(spec, owner) is True


def test_prescreen_other_accounts_unit_is_not_a_scope():
    assert sender_policy.spec_mentions_account(
        _unit(ALICE, "1", "0"), CAROL) is False
    assert sender_policy.spec_mentions_account("", CAROL) is False
    assert sender_policy.spec_mentions_account(SPEC_UNIT_ON_CAROL, "") is False


# --- the engine's apply pass -------------------------------------------------

def test_key_only_in_a_comment_does_not_make_the_pass_step():
    tx = rc._transfer_tx(ALICE, CAROL, 500)
    result, calls = rc._apply_with_spec(
        [tx], spec_text=SPEC_KEY_ONLY_IN_COMMENT,
        multi=_resolves_like_alices_unit, lm=rc._lm_ap(), balances=BALANCES)
    assert not _stepped_for_recipient(calls), \
        "no scoped unit: the recipient pass must not step"
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ap._balances(result)[CAROL] == 500


def test_key_only_in_another_units_body_does_not_make_the_pass_step():
    tx = rc._transfer_tx(ALICE, CAROL, 500)
    result, calls = rc._apply_with_spec(
        [tx], spec_text=SPEC_KEY_ONLY_IN_ANOTHER_UNITS_BODY,
        multi=_resolves_like_alices_unit, lm=rc._lm_ap(), balances=BALANCES)
    assert not _stepped_for_recipient(calls), \
        "a mention inside another unit's body is not a scope"
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ap._balances(result)[CAROL] == 500


def test_unit_scoped_on_the_recipient_is_honoured():
    """Control: the ordinary shape must still judge and still block."""
    tx = rc._transfer_tx(ALICE, CAROL, 500)
    result, calls = rc._apply_with_spec(
        [tx], spec_text=SPEC_UNIT_ON_CAROL,
        multi=_resolves_like_carols_unit, lm=rc._lm_ap(), balances=BALANCES)
    assert _stepped_for_recipient(calls)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert rc._reason(result, tx) == "recipient_policy_block"
    assert ap._balances(result)[CAROL] == 0


def test_recipient_unit_is_picked_out_of_a_multi_unit_spec():
    """Control: CAROL's own unit decides for CAROL, not whichever unit the
    spec happens to resolve to."""
    tx = rc._transfer_tx(ALICE, CAROL, 500)
    result, calls = rc._apply_with_spec(
        [tx], spec_text=SPEC_MULTI_UNIT,
        multi=_resolves_like_carols_unit, lm=rc._lm_ap(), balances=BALANCES)
    assert _stepped_for_recipient(calls)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert rc._reason(result, tx) == "recipient_policy_block"


def test_unpadded_upper_case_literal_still_scopes_at_apply():
    """Control: a spec may zero-strip or upcase its key literal; the scope
    must still match, or the recipient's real unit is silently unenforced."""
    tx = rc._transfer_tx(ALICE, CAROL, 500)
    result, calls = rc._apply_with_spec(
        [tx], spec_text=SPEC_UNIT_ON_CAROL_UNPADDED_UPPER,
        multi=_resolves_like_carols_unit, lm=rc._lm_ap(), balances=BALANCES)
    assert _stepped_for_recipient(calls)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert rc._reason(result, tx) == "recipient_policy_block"
