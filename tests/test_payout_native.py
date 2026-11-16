"""Payout rules on the REAL Tau engine (#63): the documented example rules build
and step in their own policy pool, and the amounts they write are what
`settle` pays.

Skipped where the native module is not built.
"""
import hashlib
import os
import pathlib

import pytest

import tau_policy
from consensus import sender_policy
from consensus.payout import (
    PayoutBook,
    PayoutExecution,
    POOL_APPLY,
    execution_inputs,
    parse_payout_rule_set,
    screen_payout_body,
    settle,
)


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
HEIGHT, TS = 100, 1_767_225_600


def _key(label):
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest() for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


ACCOUNT, BOB, REVIEWER, STRANGER = (_key(n) for n in ("account", "bob", "reviewer", "x"))

PASSTHROUGH = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
REVIEWED = (
    "always ( (i13[t]:bv[384] = { #x" + REVIEWER + " }:bv[384]) ? "
    "(o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { #x000000 }:bv[24]) )."
)
SPLIT = (
    "always ( (o30[t]:bv[24] = i40[t]:bv[24]) && "
    "(o31[t]:bv[24] = i40[t]:bv[24]) )."
)


@pytest.fixture
def real():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=env, timeout=TIMEOUT)
    sender_policy.set_evaluator(POOL_APPLY, ev)
    yield ev
    sender_policy.set_evaluator(POOL_APPLY, None)
    ev.close()


def _terms(text, slots):
    return parse_payout_rule_set({
        "sender_pubkey": ACCOUNT, "sequence_number": 0, "rule_text": text, "slots": slots,
        "cap_per_execution": 1_000, "cap_per_period": 5_000, "period_blocks": 100,
        "expires_at": HEIGHT + 10_000,
    })


def _run(terms, executor, data, recipients=(), balance=10_000):
    book = PayoutBook()
    book.install(terms, HEIGHT - 1)
    exe = PayoutExecution(executor, ACCOUNT, terms.rule_id, tuple(recipients),
                          tuple(sorted(data.items())))
    rule, state = book.check_execution(exe, HEIGHT, TS)
    values = execution_inputs(rule, state, exe, parent_balance=balance, height=HEIGHT, ts=TS)
    outputs = sender_policy.payout_outputs(rule.body, values, pool=POOL_APPLY)
    return settle(rule, state, exe, outputs, height=HEIGHT, ts=TS, balance=balance)


@pytest.mark.parametrize("text, slots", [
    (PASSTHROUGH, [BOB]), (REVIEWED, [""]), (SPLIT, [BOB, ""]),
])
def test_the_documented_rules_pass_the_screen_and_build(real, text, slots):
    terms = _terms(text, slots)
    assert screen_payout_body(terms.body, len(slots)) is None
    built = real.validate(terms.body)
    assert built.ok, built.error


def test_the_rule_writes_the_amount_it_reads(real):
    legs = _run(_terms(PASSTHROUGH, [BOB]), STRANGER, {0: 250})
    assert legs == [(0, BOB, 250)]


def test_only_the_named_executor_moves_money(real):
    terms = _terms(REVIEWED, [""])
    assert _run(terms, REVIEWER, {0: 300}, recipients=[(0, BOB)]) == [(0, BOB, 300)]
    from consensus.payout import PayoutRefused
    with pytest.raises(PayoutRefused, match="pays nothing"):
        _run(terms, STRANGER, {0: 300}, recipients=[(0, BOB)])


def test_two_slots_are_paid_together(real):
    terms = _terms(SPLIT, [BOB, ""])
    assert _run(terms, STRANGER, {0: 40}, recipients=[(1, REVIEWER)]) == \
        [(0, BOB, 40), (1, REVIEWER, 40)]
