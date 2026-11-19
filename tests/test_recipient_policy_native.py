"""The recipient-side rules against the real engine.

Every other test of the feature answers from the Python models in
`recipient_rules`. This file holds the models to the engine: for each documented
rule and every input on the grid, the engine's verdict must be the model's.
"""
import hashlib
import itertools
import os

import pytest

import tau_defs
import tau_policy
from consensus import recipient_policy, sender_policy

import recipient_rules as rules


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


def _key(label: str) -> str:
    digits = "".join(hashlib.sha256((label + s).encode()).hexdigest() for s in ("", "x", "y"))[:96]
    assert not digits.isdigit()
    return digits


A, B, C = _key("payer"), _key("owner"), _key("shop")

RULES = [
    ("allow-list", rules.allow_list(A), rules.allow_list_model(A)),
    ("allow-list of two", rules.allow_list(A, C), rules.allow_list_model(A, C)),
    ("instant only", rules.max_hold(0), rules.max_hold_model(0)),
    ("held 600 s at most", rules.max_hold(600), rules.max_hold_model(600)),
    ("one unit", rules.one_unit(C, A, 600), rules.one_unit_model(C, A, 600)),
]

RECEIVE_VALUES = [None, 0, 1, 2, 601, 602, 7_776_001, tau_defs.RECEIVE_HOLD_UNBOUNDED]


@pytest.fixture(scope="module")
def evaluator():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=env, timeout=TIMEOUT)
    yield ev
    ev.close()


def _transfer(sender, recipient, amount=25):
    return {
        1: str(amount), 2: "1000",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
        5: "1700000000",
    }


@pytest.mark.parametrize("name, body, model", RULES, ids=[r[0] for r in RULES])
def test_the_engine_decides_what_the_model_decides(evaluator, name, body, model):
    assert evaluator.validate(body).ok, name
    for receive, (sender, recipient) in itertools.product(
            RECEIVE_VALUES, [(A, B), (C, B), (B, C), (B, A)]):
        values = _transfer(sender, recipient)
        if receive is not None:
            values = recipient_policy.receive_inputs(values, receive)
        inputs = sender_policy.clause_inputs(values)
        verdict = evaluator.verdict(body, inputs)
        assert verdict.blocked is (model(inputs) == "0"), (name, receive, sender[:6], recipient[:6])


def test_a_recipient_can_require_a_custom_input_of_the_payer(evaluator):
    """The payer's custom inputs reach the recipient's clause; an input the
    payer did not send reads 0."""
    body, model = rules.needs_reference(30), rules.needs_reference_model(30)
    assert evaluator.validate(body).ok
    for receive, reference in itertools.product([None, 1, 601], [None, "0", "4711"]):
        values = _transfer(A, B)
        if reference is not None:
            values[30] = reference
        if receive is not None:
            values = recipient_policy.receive_inputs(values, receive)
        inputs = sender_policy.clause_inputs(values)
        assert evaluator.verdict(body, inputs).blocked is (model(inputs) == "0"), (receive, reference)


def test_the_documented_rules_share_one_worker_without_a_width_conflict(evaluator):
    """All of them type i17 at bv[64], which is what the width screen enforces."""
    for _name, body, model in RULES * 2:
        inputs = sender_policy.clause_inputs(
            recipient_policy.receive_inputs(_transfer(A, B), 601))
        assert evaluator.verdict(body, inputs).blocked is (model(inputs) == "0")
    assert evaluator.stats()["widths"]["i17"] == tau_defs.RECEIVE_STREAM_BV_WIDTH


def test_an_unfed_receive_stream_reads_as_the_owners_own_payment(evaluator):
    """The sender pass does not feed i17. The worker's default for an unfed
    input is 0, which is RECEIVE_SIDE_SENDER, so the receive part never fires."""
    body = rules.allow_list(A)
    assert evaluator.verdict(body, sender_policy.clause_inputs(_transfer(C, B))).blocked is False
    asked = sender_policy.clause_inputs(recipient_policy.receive_inputs(_transfer(C, B), 1))
    assert evaluator.verdict(body, asked).blocked is True


def test_the_longest_accepted_hold_is_found_on_the_engine(evaluator):
    body = rules.max_hold(600)

    def allows(value):
        inputs = sender_policy.clause_inputs(
            recipient_policy.receive_inputs(_transfer(A, B), value))
        return not evaluator.verdict(body, inputs).blocked

    assert recipient_policy.max_accepted_hold(allows, 3_601, 7_776_000) == 600
    assert recipient_policy.max_accepted_hold(
        allows, tau_defs.RECEIVE_HOLD_UNBOUNDED, 7_776_000) == 600
