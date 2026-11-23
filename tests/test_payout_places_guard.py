"""Rules in other places behind a rule-change guard: kinds 6 and 7 (#63).

A guarded account installs a rule in another place with a kind 6 request whose
spec carries `rule_index`, and revokes it with a kind 7 request whose rule_text
names the place ("" stays the first rule, so a request from before keeps its
body and its id).
"""
import pytest

import tau_defs
from consensus import sender_policy
from consensus.approvals import (
    STATUS_EXECUTED,
    STATUS_FAILED,
    parse_rule_change_request,
    parse_rule_change_request_checked,
)
from consensus.payout import payout_key, payout_rule_body, payout_spec_text
from consensus.policy_mock import MockPolicyEvaluator
from consensus.serialization import compute_rule_change_body_hash

from test_rule_change_requests import ALICE, BOB, GUARD_BODY, HEIGHT, _request, _tx
from test_rule_change_release import LATE, Chain, _guarded, _vote

KIND_SET_PAYOUT = tau_defs.RULE_CHANGE_KIND_SET_PAYOUT
KIND_REVOKE_PAYOUT = tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT
RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
BODY = payout_rule_body(RULE)


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


def test_a_revoke_request_from_before_keeps_its_body_and_its_id():
    old = parse_rule_change_request(_tx(_request(KIND_REVOKE_PAYOUT, expire=LATE)))
    assert old.body == "" and old.body_hash == compute_rule_change_body_hash("")
    placed = parse_rule_change_request(_tx(_request(KIND_REVOKE_PAYOUT, text="2", expire=LATE)))
    assert placed.body == "2" and placed.request_id != old.request_id


@pytest.mark.parametrize("text", ["0", "8", "02", "x", " 2", "{}"])
def test_a_revoke_request_names_a_place_or_nothing(text):
    req, why = parse_rule_change_request_checked(
        _tx(_request(KIND_REVOKE_PAYOUT, text=text, expire=LATE)))
    assert req is None and why


def test_a_guarded_account_installs_and_revokes_a_rule_in_another_place():
    chain = Chain(_guarded())
    first = _request(KIND_SET_PAYOUT, text=spec(), expire=LATE)
    second = _request(KIND_SET_PAYOUT, text=spec(rule_index=2, cap_per_execution=50), seq=1,
                      expire=LATE)
    for req in (first, second):
        chain.block(_tx(req))
    chain.block(_vote(first.request_id))
    chain.block(_vote(second.request_id, seq=1))
    assert chain.entry(second).status == STATUS_EXECUTED
    book = chain.lm.payout_rules
    assert book.keys_of(ALICE) == [ALICE, payout_key(ALICE, 2)]
    assert book.get(payout_key(ALICE, 2)).cap_per_execution == 50

    missing = _request(KIND_REVOKE_PAYOUT, text="3", seq=2, expire=LATE)
    result = chain.block(_tx(missing))
    assert missing.request_id not in chain.book.rule_change_requests
    assert "no payout rule" in " | ".join(
        str(x) for o in result.outcomes for x in (o.receipt_logs or []))

    revoke = _request(KIND_REVOKE_PAYOUT, text="2", seq=2, expire=LATE)   # the refused one used none
    chain.block(_tx(revoke))
    result = chain.block(_vote(revoke.request_id, seq=2))
    assert chain.entry(revoke).status == STATUS_EXECUTED
    assert chain.lm.payout_rules.keys_of(ALICE) == [ALICE]
    events = result.next_snapshot.metadata["payout_events"]
    assert [(e["outcome"], e.get("rule_index")) for e in events] == [("revoked", 2)]


def test_a_waiting_revoke_of_a_place_fails_once_another_place_is_sealed():
    chain = Chain(_guarded())
    install = _request(KIND_SET_PAYOUT, text=spec(rule_index=1), expire=LATE)
    chain.block(_tx(install))
    chain.block(_vote(install.request_id))
    revoke = _request(KIND_REVOKE_PAYOUT, text="1", seq=1, expire=LATE)
    seal = _request(KIND_SET_PAYOUT, text=spec(sealed=True), seq=2, expire=LATE)
    for req in (revoke, seal):
        chain.block(_tx(req))
    chain.block(_vote(seal.request_id, seq=1))
    assert chain.lm.payout_rules.sealed(ALICE)
    chain.block(_vote(revoke.request_id, seq=2))
    assert chain.entry(revoke).status == STATUS_FAILED
    assert chain.lm.payout_rules.get(payout_key(ALICE, 1)) is not None
