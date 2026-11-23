"""Bounty 01, FIX 5B: the rule-change guard judges the payment-book
kinds 7..12 on the REAL Tau engine.

Kept in its own file so the real-Tau CI job can register exactly this
file (the pattern of the other Bounty 01 native suites): the guard
verdicts below step REAL Tau clauses through the real
policy-evaluation path (sender_policy.rule_change_blocked with a live
PolicyEvaluator), which needs the native bindings the mock job does
not have. The skip is environment-driven.

The clauses are written in the two forms the shipped wallet guard
templates use — a co-signer slot read at bv[384], and kind selection
on i1 at bv[24] (the forms test_rule_change_guard_native.py steps for
kinds 1..6) — spelled out here because the standalone CI image does
not carry web-wallet/app.js, where the template texts live.

What this proves, with no mock anywhere in the file:

1. A co-signer guard ("any change needs co-signer X", and a 2-of-3
   variant) judges every payment kind (7 set payout, 8 update payout,
   9 revoke payout, 10 set standing, 11 update standing, 12 cancel
   standing) exactly as it judges the policy kinds: blocked with no
   co-signer slot filled, released by the named co-signer(s), still
   blocked by a stranger or the right key in the wrong slot.
2. A kind-selective guard can name one payment kind: a clause that
   blocks only i1 = 8 blocks the payout update and lets the install,
   the revoke and every standing kind through — the granularity ST-3
   turns on.
3. A guard that enumerates the kinds it blocks (revokes 2 and 5, the
   shipped weaker template's shape) does NOT block the payment kinds:
   a guard is a program, and it judges the kinds its author named.
   Widening a deployed guard is itself a guarded change (kind 4).
"""
import hashlib
import os
import pathlib

import pytest

import tau_defs
import tau_policy
from consensus import sender_policy
from consensus.rule_offers import clause_body_v1


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = str(pathlib.Path(__file__).resolve().parent.parent)
TIMEOUT = 120.0
TIMESTAMP = 1234567890
PAYMENT_KINDS = (
    tau_defs.RULE_CHANGE_KIND_SET_PAYOUT,
    tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT,
    tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT,
    tau_defs.RULE_CHANGE_KIND_SET_STANDING,
    tau_defs.RULE_CHANGE_KIND_UPDATE_STANDING,
    tau_defs.RULE_CHANGE_KIND_CANCEL_STANDING,
)


def _key(label):
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest() for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


X, Y, Z, OTHER, SENDER = (_key(n) for n in ("x", "y", "z", "other", "sender"))


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def real():
    """A real policy worker behind both consensus pools."""
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, ev)
    yield ev
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    ev.close()


def _bv384(h):
    return "{ #x%s }:bv[384]" % h


def _slot_eq(slot, key):
    return "(i%d[t]:bv[384] = %s)" % (slot, _bv384(key))


def _any_change_body():
    """Blocked unless approval slot 18 holds co-signer X."""
    return clause_body_v1(
        "always ( ((!(%s)) ? (o5[t]:bv[24] = { #x000000 }:bv[24])"
        " : (o5[t]:bv[24] = { #x000001 }:bv[24])) )." % _slot_eq(18, X))


def _two_of_three_body():
    """Blocked unless any two of slots 18/19/20 hold X/Y/Z respectively."""
    pairs = " || ".join(
        "(%s && %s)" % pair
        for pair in (
            (_slot_eq(18, X), _slot_eq(19, Y)),
            (_slot_eq(18, X), _slot_eq(20, Z)),
            (_slot_eq(19, Y), _slot_eq(20, Z)),
        ))
    return clause_body_v1(
        "always ( ((%s) ? (o5[t]:bv[24] = { #x000001 }:bv[24])"
        " : (o5[t]:bv[24] = { #x000000 }:bv[24])) )." % pairs)


def _blocked(body, kind, voted=None):
    blocked, detail = sender_policy.rule_change_blocked(
        lambda who, idx: body, SENDER, kind, TIMESTAMP, pool="apply", voted=voted)
    return blocked


def test_the_guard_forms_build_and_step_for_the_payment_kinds(real):
    for body in (_any_change_body(), _two_of_three_body()):
        result = real.validate(body)
        assert result.ok, result.error
        for kind in PAYMENT_KINDS:
            assert isinstance(_blocked(body, kind), bool)


def test_any_change_needs_the_cosigner_for_every_payment_kind(real):
    body = _any_change_body()
    for kind in PAYMENT_KINDS:
        assert _blocked(body, kind), f"kind {kind} with empty slots"
        assert not _blocked(body, kind, {18: X}), f"kind {kind} with X"
        assert _blocked(body, kind, {18: OTHER}), f"kind {kind} with a stranger"
        assert _blocked(body, kind, {19: X}), f"kind {kind} with X in the wrong slot"


def test_two_of_three_needs_any_two_for_every_payment_kind(real):
    body = _two_of_three_body()
    for kind in PAYMENT_KINDS:
        assert _blocked(body, kind), f"kind {kind} with empty slots"
        for single in ({18: X}, {19: Y}, {20: Z}):
            assert _blocked(body, kind, single), (kind, single)
        for pair in ({18: X, 19: Y}, {18: X, 20: Z}, {19: Y, 20: Z}):
            assert not _blocked(body, kind, pair), (kind, pair)


def test_a_kind_selective_guard_blocks_only_the_payout_update(real):
    # The door tests' kind-selective shape, naming kind 8: block exactly
    # when i1 = 8, allow every other kind.
    body = clause_body_v1(
        "always ( ((i1[t]:bv[24] = { #x000008 }:bv[24]) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])) ).")
    assert real.validate(body).ok
    for kind in PAYMENT_KINDS:
        assert _blocked(body, kind) is (
            kind == tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT), kind
    # And it leaves the policy kinds it does not name alone.
    assert not _blocked(body, tau_defs.RULE_CHANGE_KIND_UPDATE_POLICY)


def test_a_guard_judges_only_the_kinds_it_names(real):
    # The shipped weaker template's shape: block exactly i1 in {2, 5}.
    body = clause_body_v1(
        "always ( (((i1[t]:bv[24] = { #x000002 }:bv[24])"
        " || (i1[t]:bv[24] = { #x000005 }:bv[24])) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])) ).")
    assert real.validate(body).ok
    # Sanity: the kinds it names are blocked.
    assert _blocked(body, tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY)
    assert _blocked(body, tau_defs.RULE_CHANGE_KIND_REVOKE_GUARD)
    # The payment kinds are not named in this guard, so it does not
    # block them: granularity is the guard author's expressed policy.
    for kind in PAYMENT_KINDS:
        assert not _blocked(body, kind), kind
