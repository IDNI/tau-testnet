"""The web wallet's o5 templates against the real engine: each one builds as a
clause and steps, and the spend limit, whitelist and time lock give the verdicts
their commentary promises."""
import hashlib
import os

import pytest

import tau_policy
from consensus.rule_offers import clause_body_v1
from wallet_templates import live_rule, shipped_templates, writes


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 120.0

TEMPLATES = {n: t for n, t in shipped_templates().items() if writes(t, "o5")}


def _key(label):
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest() for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def evaluator():
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    yield ev
    ev.close()


def _body(name, **substitutions):
    text = TEMPLATES[name]
    for old, new in substitutions.items():
        assert old in text
        text = text.replace(old, new)
    return clause_body_v1(text)


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_template_builds_and_steps(evaluator, name):
    result = evaluator.validate(clause_body_v1(TEMPLATES[name]))
    assert result.ok, f"{name}: {result.error}\n{live_rule(TEMPLATES[name])}"


def test_spend_limit_blocks_above_the_limit_only(evaluator):
    body = _body("Limit transfers to max 5000")
    assert evaluator.verdict(body, {"i1": "5001"}).blocked
    assert not evaluator.verdict(body, {"i1": "5000"}).blocked
    assert not evaluator.verdict(body, {"i1": "1"}).blocked


def test_recipient_whitelist_allows_only_the_approved_recipient(evaluator):
    approved, other = _key("approved"), _key("other")
    body = _body("Recipient whitelist (only send to approved address)",
                 **{"2" * 96: approved})
    assert not evaluator.verdict(body, {"i4": "#x" + approved}).blocked
    assert evaluator.verdict(body, {"i4": "#x" + other}).blocked


def test_time_lock_blocks_until_the_timestamp(evaluator):
    body = _body("Time-locked (Block transfers before time X)")
    assert evaluator.verdict(body, {"i5": "1704067199"}).blocked
    assert not evaluator.verdict(body, {"i5": "1704067200"}).blocked
    assert not evaluator.verdict(body, {"i5": "1800000000"}).blocked


def test_block_all_blocks_every_valid_amount(evaluator):
    body = _body("Block all transfers")
    for amount in ("1", "5000", "16777215"):
        assert evaluator.verdict(body, {"i1": amount}).blocked


def test_two_factor_needs_the_token_above_the_limit(evaluator):
    body = _body("2FA for High Value Transfers")
    assert evaluator.verdict(body, {"i1": "1001", "i26": "1"}).blocked
    assert not evaluator.verdict(body, {"i1": "1001", "i26": "9999"}).blocked
    assert not evaluator.verdict(body, {"i1": "1000", "i26": "1"}).blocked
