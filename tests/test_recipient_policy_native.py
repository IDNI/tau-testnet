"""Recipient gate against the REAL Tau engine (issues #47/#76).

Same acceptance cases as tests/test_recipient_policy.py, but the verdicts
come from tau_policy.PolicyEvaluator — the production evaluator the gate
uses on both pools — instead of the mock. This is the test that proves
the hold streams i17/i27 are actually readable by a deployed clause: a
mock can be told anything, the engine cannot.

Skips when the native Tau library is unavailable, like
tests/test_clause_registration_native.py.
"""
import os

import pytest

import tau_defs
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex
from consensus import recipient_policy, sender_policy
from consensus.rule_offers import clause_body_v1

def _native_available():
    try:
        import tau_native

        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built"
)

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)

ALLOWLIST_RULE = (
    "always ( (i3[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
ALLOWLIST_BODY = clause_body_v1(ALLOWLIST_RULE)

HOLD600_RULE = (
    "always ( (i17[t]:bv[64] <= { #x258 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
HOLD600_BODY = clause_body_v1(HOLD600_RULE)

HOLD0_RULE = (
    "always ( (i17[t]:bv[64] <= { #x0 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
HOLD0_BODY = clause_body_v1(HOLD0_RULE)


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module", autouse=True)
def _native_pools():
    import tau_policy

    env = dict(os.environ)
    # Append the repo to the inherited PYTHONPATH (which carries the
    # native bindings dir when the suite runs against a built tau-lang).
    env["PYTHONPATH"] = env.get("PYTHONPATH", "") + os.pathsep + REPO
    evaluators = {}
    for pool in ("apply", "admission"):
        evaluator = tau_policy.PolicyEvaluator(
            pool=pool, cwd=REPO, env=env, timeout=60)
        evaluators[pool] = evaluator
        sender_policy.set_evaluator(pool, evaluator)
    yield
    for pool, evaluator in evaluators.items():
        sender_policy.set_evaluator(pool, None)
        evaluator.close()


def _bv384(pubkey):
    return "{ #x" + pubkey + " }:bv[384]"


def _values(sender, recipient, amount=100):
    return {
        1: str(amount),
        2: "1000000",
        3: _bv384(sender),
        4: _bv384(recipient),
        5: "1700000000",
        12: _bv384(sender),
    }


def _gate(body, sender, recipient, pool="apply", hold=None):
    clause_for = lambda pubkey, stream: body if pubkey == recipient else None
    return recipient_policy.recipient_clause_blocks(
        clause_for, sender, recipient, _values(sender, recipient),
        pool=pool, hold=hold,
    )


def test_native_allowlist_verdicts():
    blocked, _, _ = _gate(ALLOWLIST_BODY, ALICE, CAROL)
    assert blocked is False
    blocked, _, refusal = _gate(ALLOWLIST_BODY, BOB, CAROL)
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON


def test_native_hold_cap_verdicts():
    # A plain transfer feeds hold 0: admitted under a 600s cap.
    assert _gate(HOLD600_BODY, ALICE, CAROL)[0] is False
    # A park held exactly the cap: admitted.
    assert _gate(HOLD600_BODY, ALICE, CAROL, hold={17: 600, 27: 0})[0] is False
    # One second over: blocked, with the cap on the refusal.
    blocked, _, refusal = _gate(HOLD600_BODY, ALICE, CAROL, hold={17: 601, 27: 0})
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON_MAX_HOLD
    assert refusal.max_hold_seconds == 600


def test_native_hold_cap_zero():
    assert _gate(HOLD0_BODY, ALICE, CAROL, hold={17: 0, 27: 0})[0] is False
    blocked, _, refusal = _gate(HOLD0_BODY, ALICE, CAROL, hold={17: 1, 27: 0})
    assert blocked is True
    assert refusal.max_hold_seconds == 0


def test_native_admission_and_apply_pools_agree():
    for hold, expected in (({17: 600, 27: 0}, False), ({17: 3600, 27: 0}, True)):
        verdicts = {
            _gate(HOLD600_BODY, ALICE, CAROL, pool=pool, hold=hold)[0]
            for pool in ("admission", "apply")
        }
        assert verdicts == {expected}
