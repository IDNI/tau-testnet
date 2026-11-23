"""Payout rules behind a rule-change guard (#63): kinds 6 and 7.

An account with a guard cannot install, replace or revoke its payout rule
directly; it files a rule-change request that releases on co-signatures or after
the time escape, exactly like an o5 change. This is what turns a payout rule
into an escrow: o5 blocks signed transfers, the payout rule decides the
outflows, and the guard keeps both from being swapped by one stolen key.
"""
import json

import pytest

import tau_defs
from consensus import sender_policy
from consensus.approvals import (
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_OPEN,
    parse_rule_change_request,
)
from consensus.payout import payout_rule_body, payout_spec_text
from consensus.policy_mock import MockPolicyEvaluator

from test_rule_change_requests import ALICE, BOB, GUARD_BODY, HEIGHT, _request, _tx
from test_rule_change_release import D, LATE, Chain, _guarded, _vote

KIND_SET_PAYOUT = tau_defs.RULE_CHANGE_KIND_SET_PAYOUT
KIND_REVOKE_PAYOUT = tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT
RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
BODY = payout_rule_body(RULE)
CAROL_KEY = "ab" * 48


def spec(**over):
    fields = {"rule_text": RULE, "slots": [BOB], "cap_per_execution": 100,
              "cap_per_period": 300, "period_blocks": 10, "expires_at": HEIGHT + 5000}
    fields.update(over)
    return payout_spec_text({k: v for k, v in fields.items() if v is not None})


@pytest.fixture(autouse=True)
def evaluators():
    """The guard allows a change only once slot i18 holds a pubkey."""
    evs = {}
    for pool in ("apply", "admission", "payout_apply", "payout_admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _parked(kind, text="", seq=0):
    req = _request(kind, text=text, seq=seq, expire=LATE)
    chain = Chain(_guarded())
    chain.block(_tx(req))
    return chain, req


def _payout_events(result):
    return result.next_snapshot.metadata["payout_events"]


def test_a_request_body_carries_the_spec_and_its_sequence():
    req = parse_rule_change_request(_tx(_request(KIND_SET_PAYOUT, text=spec(), seq=4)))
    assert req is not None
    assert json.loads(req.body)["sequence_number"] == 4
    assert parse_rule_change_request(_tx(_request(KIND_SET_PAYOUT, text="{}"))) is None
    assert parse_rule_change_request(
        _tx(_request(KIND_SET_PAYOUT, text=spec().replace(",", ", ")))) is None


def test_an_install_parks_then_releases_on_the_co_signature():
    chain, req = _parked(KIND_SET_PAYOUT, spec())
    assert chain.entry(req).status == STATUS_OPEN
    assert chain.lm.payout_rules.get(ALICE) is None
    result = chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_EXECUTED
    terms = chain.lm.payout_rules.get(ALICE)
    assert terms is not None and terms.body == BODY and terms.sequence_number == 0
    assert chain.lm.payout_rules.state_of(ALICE, terms.rule_id).anchor == HEIGHT + 1
    assert [e["outcome"] for e in _payout_events(result)] == ["installed"]


def test_an_install_releases_by_the_time_escape():
    chain, req = _parked(KIND_SET_PAYOUT, spec())
    chain.block(height=HEIGHT + D - 1)
    assert chain.lm.payout_rules.get(ALICE) is None
    chain.block(height=HEIGHT + D)
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.lm.payout_rules.get(ALICE) is not None


def test_a_revoke_releases_like_any_change():
    chain, install = _parked(KIND_SET_PAYOUT, spec())
    chain.block(_vote(install.request_id))
    revoke = _request(KIND_REVOKE_PAYOUT, seq=1, expire=LATE)
    chain.block(_tx(revoke))
    assert chain.lm.payout_rules.get(ALICE) is not None
    result = chain.block(_vote(revoke.request_id, seq=1))
    assert chain.entry(revoke).status == STATUS_EXECUTED
    assert chain.lm.payout_rules.get(ALICE) is None
    assert [e["outcome"] for e in _payout_events(result)] == ["revoked"]


def test_a_rule_that_ended_before_release_fails_the_request():
    chain, req = _parked(KIND_SET_PAYOUT, spec(expires_at=HEIGHT + 3))
    chain.block(height=HEIGHT + 5)
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.lm.payout_rules.get(ALICE) is None


def test_a_rule_that_does_not_build_at_release_fails_and_writes_nothing(evaluators):
    chain, req = _parked(KIND_SET_PAYOUT, spec())
    evaluators["payout_apply"].fail_build(BODY, "nope")
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.lm.payout_rules.is_empty()


def test_a_revoke_request_needs_a_rule():
    chain = Chain(_guarded())
    req = _request(KIND_REVOKE_PAYOUT, expire=LATE)
    result = chain.block(_tx(req))
    assert req.request_id.hex() not in str(chain.book.rule_change_requests.keys())
    assert "payout" in " | ".join(str(x) for o in result.outcomes for x in (o.receipt_logs or []))


def test_a_request_outside_the_abi_is_refused_up_front():
    chain = Chain(_guarded())
    bad = spec(rule_text="always ( o30[t]:bv[16] = i40[t]:bv[16] ).")
    req = _request(KIND_SET_PAYOUT, text=bad, expire=LATE)
    chain.block(_tx(req))
    assert chain.book.get_rule_change(req.request_id) is None
