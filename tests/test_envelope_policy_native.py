"""Envelopes and standing payments judged by a REAL o5 clause on the Tau engine.

The apply tests script the verdict; here the engine decides. A clause that blocks
payments above 500 must stop an envelope send above 500, let one at 500 through,
stop the recipient's spend above 500 when the recipient carries the clause, and
leave the recipient's spends alone when only the sender carries it.

Skipped where the native module is not built.
"""
import os

import pytest

import tau_policy
from consensus import sender_policy
from tests.test_envelope_apply import (
    ALICE, BOB, Chain, HEIGHT, TS, _bal, _reason, eid_of, env_spend, send_tx,
)


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ABOVE_500 = ("( i1[t]:bv[24] > { #x0001f4 }:bv[24] ) "
             "? ( o5[t]:bv[24] = { #x000000 }:bv[24] ) : ( o5[t]:bv[24] = { #x000001 }:bv[24] )")


@pytest.fixture
def real():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=env, timeout=120.0)
    sender_policy.set_evaluator("apply", ev)
    yield ev
    sender_policy.set_evaluator("apply", None)
    ev.close()


def test_the_clause_builds(real):
    assert real.validate(ABOVE_500).ok


def test_the_senders_real_clause_judges_the_send(real):
    ch = Chain(_bal())
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = ABOVE_500
    over = send_tx(amount=501)
    assert _reason(ch.block([over]), over) == "user_policy_block"
    ok = send_tx(amount=500, caps=(100,), seq=0)
    result = ch.block([ok])
    assert _reason(result, ok) is None, _reason(result, ok)
    assert ch.bal[ALICE] == _bal()[ALICE] - 500


def test_the_recipients_real_clause_judges_each_spend(real):
    ch = Chain(_bal())
    tx = send_tx(amount=900, caps=(900,))
    ch.block([tx])
    ch.lm.rule_offers.accepted_clauses[(BOB, 5)] = ABOVE_500
    eid = eid_of(tx)
    over = env_spend(eid, 600, 0)
    assert _reason(ch.block([over], height=HEIGHT + 1, ts=TS + 5), over) == "user_policy_block"
    ok = env_spend(eid, 500, 0)
    result = ch.block([ok], height=HEIGHT + 2, ts=TS + 6)
    assert _reason(result, ok) is None, _reason(result, ok)


def test_the_senders_real_clause_does_not_judge_the_spend(real):
    ch = Chain(_bal())
    tx = send_tx(amount=900, caps=(900,))
    ch.block([tx])
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = ABOVE_500
    spend = env_spend(eid_of(tx), 600, 0)
    result = ch.block([spend], height=HEIGHT + 1, ts=TS + 5)
    assert _reason(result, spend) is None, _reason(result, spend)
