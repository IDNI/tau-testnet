"""Recipient-side policy (issues #47, #76) on the REAL Tau engine.

The shipped inbound wallet templates must build as o5 clauses and give the
verdicts their comments promise, with i17 fed exactly as the node feeds it
(sender_policy.outbound_values / inbound_values) and i3 as a full sender key.
The apply-level tests use a mock evaluator; this is what proves the templates'
Tau text, bv[64] literals included, means what they say.
"""
import os
import pathlib

import pytest

import tau_defs
import tau_policy
from consensus import sender_policy
from consensus.rule_offers import clause_body_v1
from consensus.retractable import MAX_RELEASE_WINDOW_SECONDS
from wallet_templates import shipped_templates


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
TS = 1234567890

ALLOW_LIST = "Accept payments only from approved senders (inbound)"
INSTANT = "Instant payments only, no recall window (inbound)"
CAP_600 = "Hold incoming payments at most 10 minutes (inbound)"
A, B = "1" * 96, "2" * 96            # the template's placeholder senders
OWNER, STRANGER, OTHER = "a" * 96, "c" * 96, "d" * 96


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture(scope="module")
def real():
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, ev)
    yield ev
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    ev.close()


TEMPLATES = shipped_templates()


def _body(name):
    return clause_body_v1(TEMPLATES[name])


def _values(sender, recipient, amount=10):
    return {
        1: str(amount),
        2: "100000",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
        5: str(TS),
    }


def _incoming_blocked(body, sender, hold=0):
    blocked, _ = sender_policy.recipient_clause_blocks(
        lambda who, idx: body, OWNER, _values(sender, OWNER), hold, pool="apply")
    return blocked


def _outgoing_blocked(body, recipient):
    blocked, _ = sender_policy.clause_blocks(
        body, sender_policy.outbound_values(_values(OWNER, recipient), True), pool="apply")
    return blocked


def test_the_three_inbound_templates_are_shipped():
    assert {ALLOW_LIST, INSTANT, CAP_600} <= set(TEMPLATES)


@pytest.mark.parametrize("name", [ALLOW_LIST, INSTANT, CAP_600])
def test_every_inbound_template_builds_and_reads_i17(real, name):
    body = _body(name)
    assert sender_policy.reads_recipient_input(body)
    ok, error = sender_policy.clause_builds(body, pool="apply")
    assert ok, error


def test_the_allow_list_takes_the_approved_senders_and_refuses_the_rest(real):
    body = _body(ALLOW_LIST)
    assert not _incoming_blocked(body, A)
    assert not _incoming_blocked(body, B)
    assert _incoming_blocked(body, STRANGER)


def test_the_allow_list_leaves_the_owners_own_sending_alone(real):
    body = _body(ALLOW_LIST)
    assert not _outgoing_blocked(body, STRANGER)
    assert not _outgoing_blocked(body, OTHER)


def test_instant_only_takes_plain_payments_and_refuses_any_hold(real):
    body = _body(INSTANT)
    assert not _incoming_blocked(body, STRANGER, hold=0)
    assert _incoming_blocked(body, STRANGER, hold=1)
    assert _incoming_blocked(body, STRANGER, hold=MAX_RELEASE_WINDOW_SECONDS)
    assert not _outgoing_blocked(body, STRANGER)


@pytest.mark.parametrize("hold,blocked", [
    (0, False), (599, False), (600, False), (601, True), (3600, True),
    (MAX_RELEASE_WINDOW_SECONDS, True),
])
def test_the_ten_minute_cap_is_exact(real, hold, blocked):
    assert _incoming_blocked(_body(CAP_600), STRANGER, hold=hold) is blocked


def test_the_cap_is_found_by_bisection_on_the_real_clause(real):
    body = _body(CAP_600)
    is_hold, cap = sender_policy.hold_refusal_cap(
        lambda who, idx: body, OWNER, _values(STRANGER, OWNER), 3600, pool="apply")
    assert (is_hold, cap) == (True, 600)


def test_i17_is_fed_at_the_frozen_width(real):
    """Every template types i17 at bv[64]; the width screen agrees."""
    from consensus.approvals import screen_recipient_policy_width

    for name in (ALLOW_LIST, INSTANT, CAP_600):
        assert screen_recipient_policy_width(_body(name)) is None
    assert tau_defs.RECIPIENT_POLICY_BV_WIDTH == 64
