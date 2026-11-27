"""PoC: #76 acceptance case 5 — the refusal must carry the recipient's cap so
the payer's wallet can print it.

extract_hold_caps only reads two canonical shapes. A cap written a little
differently still ENFORCES (the verdict is the rule's own answer) but the
refusal loses the number, so the wallet prints a generic cap message. The
issue asks for the cap in the reason, and the PR's own docstring admits the
gap — it is simply untested.
"""
import tau_defs
from bls_keys import SK_ALICE, SK_CAROL, pubkey_hex
from consensus import recipient_policy
from consensus.rule_offers import clause_body_v1

ALICE = pubkey_hex(SK_ALICE)
CAROL = pubkey_hex(SK_CAROL)

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
HOLD_SECONDS = tau_defs.HOLD_SECONDS_STREAM_INDEX

# Canonical shape the extractor does read: i17[t] <= 600.
CANONICAL = (
    "always ( (i17[t]:bv[64] <= { #x258 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)

# The same rule with the literal on the LEFT and >= instead of <=.
# Semantically identical: hold of 600 or less passes.
REVERSED = (
    "always ( ({ #x258 }:bv[64] >= i17[t]:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)

# Semantically identical, written through a decimal literal and `<=`.
DECIMAL = (
    "always ( (i17[t]:bv[64] <= { 600 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)


def test_control_canonical_shape_reports_the_cap():
    assert recipient_policy.extract_hold_caps(clause_body_v1(CANONICAL)) == (600, None)


def test_reversed_literal_shape_reports_the_cap():
    caps = recipient_policy.extract_hold_caps(clause_body_v1(REVERSED))
    print("\n[PoC] reversed `literal >= i17` -> extracted caps =", caps)
    assert caps == (600, None)


def test_decimal_literal_shape_reports_the_cap():
    caps = recipient_policy.extract_hold_caps(clause_body_v1(DECIMAL))
    print("[PoC] decimal literal -> extracted caps =", caps)
    assert caps == (600, None)


# The literal without its own type: Tau infers it from the compared stream,
# and the shape is accepted by the engine. The extractor's typed-only match
# used to drop the cap here, so the refusal lost the number the issue's
# acceptance case 5 requires a payer's wallet to print.
UNTYPED_LITERAL = (
    "always ( (i17[t]:bv[64] <= { 600 }) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
UNTYPED_REVERSED = (
    "always ( ({ #x258 } >= i17[t]:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)


def test_untyped_decimal_literal_still_reports_the_cap():
    caps = recipient_policy.extract_hold_caps(clause_body_v1(UNTYPED_LITERAL))
    print("[PoC] untyped decimal literal -> extracted caps =", caps)
    assert caps == (600, None)


def test_untyped_reversed_literal_still_reports_the_cap():
    caps = recipient_policy.extract_hold_caps(clause_body_v1(UNTYPED_REVERSED))
    print("[PoC] untyped reversed literal -> extracted caps =", caps)
    assert caps == (600, None)
