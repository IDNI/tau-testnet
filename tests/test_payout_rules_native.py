"""Payout rules on the REAL Tau engine: a rule builds and steps in the `payout`
policy pool, and the amounts it writes become the legs block apply pays.

Skipped when the native tau module is not built (the mock suite covers the
consensus wiring in tests/test_payout_rules.py).
"""
import pytest

import tau_policy
from consensus.payouts import (
    PAYOUT_POLICY_POOL, legs_from_outputs, parse_payout_install, rule_inputs,
)
from consensus.sender_policy import clause_inputs


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

OWNER, ARTIST, SELLER = "a1" * 48, "b0" * 48, "c0" * 48
ROYALTY = ("(o1[t]:bv[24] = i13[t]:bv[24] / { 20 }:bv[24]) && "
           "(o2[t]:bv[24] = i13[t]:bv[24] - i13[t]:bv[24] / { 20 }:bv[24])")
# Escrow release: pay the worker the escrowed amount (i1, the owner's balance)
# only when the executor reports delivery (i13 = 1), else nothing.
ESCROW = ("(i13[t]:bv[24] = { 1 }:bv[24] -> o1[t]:bv[24] = i1[t]:bv[24]) && "
          "(i13[t]:bv[24] != { 1 }:bv[24] -> o1[t]:bv[24] = { 0 }:bv[24])")


@pytest.fixture(scope="module")
def evaluator():
    ev = tau_policy.PolicyEvaluator(pool=PAYOUT_POLICY_POOL)
    yield ev
    ev.close()


def _terms(rule, recipients):
    return parse_payout_install({"sender_pubkey": OWNER, "rule_text": rule,
                                 "recipients": recipients, "max_per_execution": 1,
                                 "max_per_period": 1, "sequence_number": 0})


def test_the_payout_pool_is_a_known_pool():
    assert PAYOUT_POLICY_POOL in tau_policy.POOL_NAMES


@pytest.mark.parametrize("price,artist,seller", [(1000, 50, 950), (19, 0, 19), (2000, 100, 1900)])
def test_royalty_rule_on_real_tau(evaluator, price, artist, seller):
    assert evaluator.validate(ROYALTY, timeout=300).ok
    outs = evaluator.outputs(ROYALTY, clause_inputs(rule_inputs(10_000, 0, 1, ((13, str(price)),))),
                             timeout=300)
    legs = legs_from_outputs(_terms(ROYALTY, [ARTIST, SELLER]), outs)
    assert dict(legs) == {k: v for k, v in ((ARTIST, artist), (SELLER, seller)) if v}


def test_escrow_release_rule_on_real_tau(evaluator):
    assert evaluator.validate(ESCROW, timeout=300).ok
    terms = _terms(ESCROW, [ARTIST])
    delivered = evaluator.outputs(ESCROW, clause_inputs(rule_inputs(700, 0, 1, ((13, "1"),))),
                                  timeout=300)
    assert legs_from_outputs(terms, delivered) == [(ARTIST, 700)]
    pending = evaluator.outputs(ESCROW, clause_inputs(rule_inputs(700, 0, 1, ((13, "0"),))),
                                timeout=300)
    assert legs_from_outputs(terms, pending) == []


def test_a_rule_that_does_not_parse_is_refused(evaluator):
    assert not evaluator.validate("o1[t]:bv[24] = = 1", timeout=300).ok
