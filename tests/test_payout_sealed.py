"""A sealed payout rule (#63): the key-holder cannot transact while it runs.

The seal is a commitment device: while the rule is sealed, the node refuses
every key-signed transaction from the account -- transfers, replaces,
revokes -- and the seal lifts only when the rule expires. Payout executions
by OTHER executors still pay out: the money keeps flowing, the key-holder
just cannot move it or change the rule.

Moved from tests/test_routes_sealed.py (rules-form pivot, 23 Nov 2026): the
seal lives in the payout rule, not in a receive route.
"""
import pytest

from consensus import sender_policy
from consensus.policy_mock import MockPolicyEvaluator

from tests.test_payout_apply import (
    _events, _executed, _reason, exec_tx, revoke_tx, rid, ridb, set_tx,
)
from tests.chain_harness import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, TS, Chain, Oracle, _logs, spend_tx,
)
from tests.test_payout_apply import evs  # noqa: F401


def _bal():
    return {ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0}


def _sealed(fee=0, **kw):
    ch, oracle = Chain(_bal(), fee=fee), Oracle(_bal())
    tx = set_tx(sealed=True, **kw)
    ch.block([tx])
    oracle.create(tx, fee=fee)
    return ch, oracle, tx


def test_sealed_blocks_the_key_holders_own_transfer(evs):
    ch, oracle, tx = _sealed()
    assert ch.lm.payout_rules.get(ALICE).sealed is True
    assert _events(ch)[0]["outcome"] == "installed"
    spend = spend_tx(ALICE, BOB, 100, 1)
    result = ch.block([spend], height=HEIGHT + 1, ts=TS + 1)
    assert _reason(result, spend) == "account_sealed"
    assert "payout rule is sealed" in _logs(result)
    oracle.check(ch)
    assert ch.bal[ALICE] == 1_000 and ch.bal[BOB] == 0


def test_sealed_blocks_replace_and_revoke_while_it_runs(evs):
    ch, oracle, tx = _sealed()
    again = set_tx(seq=1, sealed=True)
    result = ch.block([again], height=HEIGHT + 1, ts=TS + 1)
    assert _reason(result, again) == "account_sealed"
    rev = revoke_tx(sender=ALICE, seq=1, rule_id=rid(tx))
    result = ch.block([rev], height=HEIGHT + 1, ts=TS + 1)
    assert _reason(result, rev) == "account_sealed"
    oracle.check(ch)
    assert ch.lm.payout_rules.get(ALICE) is not None


def test_executions_by_others_still_pay_out_while_sealed(evs):
    ch, oracle, tx = _sealed()
    ch.fee = 5
    exe = exec_tx(rule_id=rid(tx), data={"0": 40})
    ch.block([exe], height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, fee=5, legs=[(BOB, 40)], ts=TS + 3)
    oracle.check(ch)
    assert ch.lm.payout_rules.state_of(ALICE, ridb(tx)).paid_total == 40


def test_the_seal_lifts_when_the_rule_expires(evs):
    ch, oracle, tx = _sealed(expires_at=HEIGHT + 2)
    spend = spend_tx(ALICE, BOB, 100, 1)
    ch.block([spend], height=HEIGHT + 2, ts=TS + 2)
    oracle.spend(ALICE, BOB, 100, ts=TS + 2)
    oracle.check(ch)
    assert ch.bal[ALICE] == 900 and ch.bal[BOB] == 100
    assert ch.lm.payout_rules.get(ALICE) is None
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                            "outcome": "expired"}]
