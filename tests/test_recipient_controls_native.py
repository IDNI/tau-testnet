"""Recipient clauses stepped by the native Tau engine.

The mock suite decides the search. This file checks that the same clauses,
fed the codes the node feeds, get the same verdicts from the engine. Skipped
when the tau module is not built.
"""
import hashlib
import os

import pytest

import tau_policy
from consensus import sender_policy
from consensus.recipient_policy import (
    CODE_PLAIN,
    HEIGHT_CODE_BASE,
    MAX_HOLD,
    POLICY_BLOCK,
    recipient_refusal,
)

def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built",
)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STEP_TIMEOUT = 120.0


def _key(label: str) -> str:
    digits = hashlib.sha256(label.encode()).hexdigest()
    digits += hashlib.sha256(label.encode() + b"x").hexdigest()
    digits += hashlib.sha256(label.encode() + b"y").hexdigest()
    digits = digits[:96]
    assert not digits.isdigit()
    return "#x" + digits


PAYER = _key("payer")
OTHER = _key("other")
COSIGNER = _key("cosigner")


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _over(limit: int) -> str:
    return (
        f"( i17[t]:bv[64] > {{ {limit} }}:bv[64] ) "
        "? ( o5[t]:bv[24] = { 0 }:bv[24] ) "
        ": ( o5[t]:bv[24] = { 1 }:bv[24] )"
    )


def _allow(payer: str) -> str:
    return (
        "( ( i17[t]:bv[64] = { 0 }:bv[64] ) || "
        f"( i3[t]:bv[384] = {{ {payer} }}:bv[384] ) ) "
        "? ( o5[t]:bv[24] = { 1 }:bv[24] ) "
        ": ( o5[t]:bv[24] = { 0 }:bv[24] )"
    )


def _cosigner_blocks(key: str) -> str:
    return (
        "( ( i17[t]:bv[64] > { 0 }:bv[64] ) && "
        f"( i18[t]:bv[384] = {{ {key} }}:bv[384] ) ) "
        "? ( o5[t]:bv[24] = { 0 }:bv[24] ) "
        ": ( o5[t]:bv[24] = { 1 }:bv[24] )"
    )


def _ask(body, values, hold):
    return recipient_refusal(
        body, values, hold, pool="apply", timeout=STEP_TIMEOUT,
    )


@pytest.fixture(scope="module")
def engine():
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=STEP_TIMEOUT)
    sender_policy.set_evaluator("apply", ev)
    try:
        yield ev
    finally:
        sender_policy.set_evaluator("apply", None)
        ev.close()


def test_a_600_second_cap_names_that_cap_when_a_height_park_is_refused(engine):
    body = _over(601)
    assert engine.validate(body, timeout=STEP_TIMEOUT).ok
    assert _ask(body, {}, 601) is None
    hour = _ask(body, {}, 1 + 3600)
    assert hour.code == MAX_HOLD
    assert hour.details == {"max_hold_seconds": 600}
    height = _ask(body, {}, HEIGHT_CODE_BASE + 10)
    assert height.code == MAX_HOLD
    assert height.details == {"max_hold_blocks": 0, "max_hold_seconds": 600}
    assert "straight away" not in height.message


def test_instant_only_names_zero_on_a_time_park_and_on_a_height_park(engine):
    body = _over(1)
    assert engine.validate(body, timeout=STEP_TIMEOUT).ok
    assert _ask(body, {}, CODE_PLAIN) is None
    parked = _ask(body, {}, 1 + 60)
    assert parked.code == MAX_HOLD
    assert parked.details == {"max_hold_seconds": 0}
    assert "straight away" in parked.message
    height = _ask(body, {}, HEIGHT_CODE_BASE + 10)
    assert height.details == {"max_hold_blocks": 0, "max_hold_seconds": 0}
    assert "straight away" in height.message


def test_an_allow_list_blocks_a_stranger_and_does_not_name_a_cap(engine):
    body = _allow(PAYER)
    assert engine.validate(body, timeout=STEP_TIMEOUT).ok
    payer = {3: "{ " + PAYER + " }:bv[384]"}
    stranger = {3: "{ " + OTHER + " }:bv[384]"}
    assert _ask(body, payer, CODE_PLAIN) is None
    assert _ask(body, payer, 1 + 3600) is None
    blocked = _ask(body, stranger, CODE_PLAIN)
    assert blocked.code == POLICY_BLOCK
    assert blocked.details == {}
    parked = _ask(body, stranger, 1 + 60)
    assert parked.code == POLICY_BLOCK
    assert parked.details == {}


def test_a_co_signer_on_the_transfer_does_not_reach_the_recipient_clause(engine):
    body = _cosigner_blocks(COSIGNER)
    assert engine.validate(body, timeout=STEP_TIMEOUT).ok
    direct = engine.verdict(
        body, {"i17": "1", "i18": COSIGNER}, timeout=STEP_TIMEOUT,
    )
    assert direct.blocked
    values = {18: "{ " + COSIGNER + " }:bv[384]"}
    assert _ask(body, values, CODE_PLAIN) is None
    assert values[18] == "{ " + COSIGNER + " }:bv[384]"
