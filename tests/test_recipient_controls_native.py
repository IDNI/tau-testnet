"""Recipient controls against the real Tau engine (issues #47/#76).

The mock-suite tests script the policy evaluator; these run the actual
shipped template bodies through the real policy worker, so the Tau text
the CLI installs is proven to build, to read the hold streams at bv[64],
and to produce the verdicts (and the measured cap) the design promises.
Skipped wherever the native module is not built, like every *_native.py.
"""
import hashlib
import os

import pytest

import tau_defs
import tau_policy
from consensus import recipient_policy, sender_policy


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 120.0


def _key(label: str) -> str:
    """96 hex digits that are not all decimal digits (an all-digit key reads
    back as a number and breaks guards on the address streams)."""
    digits = hashlib.sha256(label.encode()).hexdigest() + hashlib.sha256(
        label.encode() + b"x").hexdigest() + hashlib.sha256(
        label.encode() + b"y").hexdigest()
    digits = digits[:96]
    assert not digits.isdigit()
    return digits


OWNER = _key("owner")
FRIEND = _key("friend")
STRANGER = _key("stranger")


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def evaluator():
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    sender_policy.set_evaluator("apply", ev)
    yield ev
    sender_policy.set_evaluator("apply", None)
    ev.close()


def _values(sender, recipient=OWNER, amount="100"):
    return {
        1: amount,
        2: "100000",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
        5: "1700000000",
    }


def _verdict(evaluator, body, sender, **kwargs):
    return recipient_policy.recipient_verdict(
        lambda pubkey, stream: body if pubkey == OWNER else None,
        OWNER, _values(sender), pool="apply", timeout=TIMEOUT,
        sender=sender, **kwargs,
    )


def test_real_allowlist_body_admits_listed_and_refuses_others(evaluator):
    body = recipient_policy.allowlist_clause_body(OWNER, [FRIEND])
    assert _verdict(evaluator, body, FRIEND).blocked is False
    refused = _verdict(evaluator, body, STRANGER)
    assert refused.blocked is True
    assert refused.reason == tau_defs.REASON_RECIPIENT_POLICY_BLOCK


def test_real_instant_only_body_refuses_any_hold(evaluator):
    body = recipient_policy.instant_only_clause_body(OWNER)
    assert _verdict(evaluator, body, STRANGER).blocked is False
    refused = _verdict(evaluator, body, STRANGER, hold_seconds=1)
    assert refused.blocked is True
    assert refused.reason == tau_defs.REASON_RECIPIENT_MAX_HOLD
    assert refused.max_hold == {"max_hold_seconds": 0}


def test_real_cap_body_yields_the_measured_cap(evaluator):
    body = recipient_policy.max_hold_clause_body(OWNER, seconds=600)
    assert _verdict(evaluator, body, STRANGER, hold_seconds=600).blocked is False
    refused = _verdict(evaluator, body, STRANGER, hold_seconds=700)
    assert refused.blocked is True
    assert refused.reason == tau_defs.REASON_RECIPIENT_MAX_HOLD
    assert refused.cap == 600 and refused.cap_unit == "seconds"
    # A height park against a seconds-only cap fails closed, in blocks.
    refused_height = _verdict(evaluator, body, STRANGER, hold_blocks=3)
    assert refused_height.blocked is True
    assert refused_height.reason == tau_defs.REASON_RECIPIENT_MAX_HOLD
    assert refused_height.max_hold == {"max_hold_blocks": 0}
