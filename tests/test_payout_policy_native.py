"""The account's o5 clause over the payments of a payout rule, on the REAL Tau engine.

The clauses are the web wallet's own o5 templates, as the wallet loads them.
Every payment a payout rule makes is asked of the account's clause like a
transfer the account sends, so each template limits a rule the way it limits
the key:

    spend limit     a rule pays 5,000 a payment and not 5,001
    whitelist       a rule pays the approved address and nobody else, slot by slot
    time lock       a rent is not paid before the lock ends, and is from then on
    block all       stops an execution, a due point and a routed share alike
    co-signer       a payment above the limit needs a signature no run carries
    custom input    a clause that reads one reads 0 for it in a run
    exempt          a rule signed with policy_exempt pays whatever the clause says

Blocks run through the real `apply_block`; the payout rule and the clause are
both built and stepped by the engine, each in its own pool. Skipped where the
native module is not built.
"""
import os

import pytest

import tau_policy
from consensus import sender_policy
from consensus.payout import POOL_APPLY
from consensus.rule_offers import clause_body_v1

from tests.chain_harness import ALICE, BOB, CAROL, HEIGHT, PROPOSER, TS, Chain, _logs, spend_tx
from tests.test_payout_apply import DAVE, TWO, _events, _reason, exec_tx, rid, set_tx
from tests.test_payout_conditions_native import REPO, TIMEOUT, pytestmark  # noqa: F401
from tests.test_payout_triggers import RECURRING, ROUTE, STEP
from tests.wallet_templates import shipped_templates

TEMPLATES = shipped_templates()
BLOCKED = "the account's o5 clause blocks the payment of slot"


def template(name, **substitutions):
    text = TEMPLATES[name]
    for old, new in substitutions.items():
        assert old in text, (name, old)
        text = text.replace(old, new)
    return clause_body_v1(text)


SPEND_LIMIT = template("Limit transfers to max 5000")
WHITELIST = template("Recipient whitelist (only send to approved address)", **{"2" * 96: BOB})
LOCK_ENDS = TS + 100
TIME_LOCK = template("Time-locked (Block transfers before time X)",
                     **{"#x0000000065920080": "#x%016x" % LOCK_ENDS})
BLOCK_ALL = template("Block all transfers")
CO_SIGNER = template("Single co-signer above a limit")
TWO_FACTOR = template("2FA for High Value Transfers")


@pytest.fixture(scope="module")
def real():
    """The engine in both pools: the payout rule's and the o5 clause's."""
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    pools = {pool: tau_policy.pool_evaluator(pool, cwd=REPO, env=env, timeout=TIMEOUT)
             for pool in (POOL_APPLY, "apply")}
    for pool, ev in pools.items():
        sender_policy.set_evaluator(pool, ev)
    yield pools
    for pool, ev in pools.items():
        sender_policy.set_evaluator(pool, None)
        ev.close()


def _chain(clause, **rule):
    """Alice with 20,000, a payout rule and `clause` as her o5 clause."""
    ch = Chain({ALICE: 20_000, BOB: 0, CAROL: 500, PROPOSER: 0})
    rule.setdefault("cap_exec", 10_000)
    rule.setdefault("cap_period", 100_000)
    tx = set_tx(**rule)
    ch.block([tx])
    assert ch.lm.payout_rules.get(ALICE) is not None, _logs(ch.last)
    if clause is not None:
        ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = clause
    return ch, tx


def _execute(ch, tx, height, *, seq=0, **what):
    """Carol sends an execution in the next block: ("paid", {who: amount}) or
    ("refused", the log)."""
    exe = exec_tx(seq=seq, rule_id=rid(tx), **what)
    before = dict(ch.bal)
    result = ch.block([exe], height=HEIGHT + height, ts=TS + height)
    if _reason(result, exe) == "payout_not_executed":
        assert ch.bal == before                # nothing moved, and nobody paid a fee
        return "refused", _logs(result)
    return "paid", {who: held - before.get(who, 0) for who, held in ch.bal.items()
                    if held > before.get(who, 0)}


def test_the_templates_build_as_clauses(real):
    for body in (SPEND_LIMIT, WHITELIST, TIME_LOCK, BLOCK_ALL, CO_SIGNER, TWO_FACTOR):
        built = real["apply"].validate(body)
        assert built.ok, built.error


def test_a_spend_limit_holds_for_each_payment_of_a_rule(real):
    ch, tx = _chain(SPEND_LIMIT)
    outcome, log = _execute(ch, tx, 1, data={"0": 5_001})
    assert outcome == "refused" and BLOCKED + " 0" in log
    assert _execute(ch, tx, 2, data={"0": 5_000}) == ("paid", {BOB: 5_000})
    assert _execute(ch, tx, 3, seq=1, data={"0": 1}) == ("paid", {BOB: 1})


def test_a_whitelist_holds_slot_by_slot_and_one_stranger_stops_the_run(real):
    ch, tx = _chain(WHITELIST, rule=TWO, slots=[BOB, ""])
    outcome, log = _execute(ch, tx, 1, data={"0": 300, "1": 200}, recipients={"1": DAVE})
    assert outcome == "refused" and BLOCKED + " 1" in log
    assert _execute(ch, tx, 2, data={"0": 300}) == ("paid", {BOB: 300})
    assert _execute(ch, tx, 3, seq=1, data={"0": 300, "1": 200}, recipients={"1": BOB}) == (
        "paid", {BOB: 500})


def test_a_time_lock_holds_a_rent_until_it_ends(real):
    ch, tx = _chain(TIME_LOCK, rule=RECURRING, cap_exec=100, cap_period=100,
                    due_at=HEIGHT + 5, due_every=STEP, expires_at=HEIGHT + 5 + 10 * STEP)
    ch.block([], height=HEIGHT + 5, ts=LOCK_ENDS - 1)
    event, = _events(ch)
    assert event["outcome"] == "due_not_paid" and event["reason"] == BLOCKED + " 0"
    assert ch.bal[BOB] == 0
    ch.block([], height=HEIGHT + 5 + STEP, ts=LOCK_ENDS)
    assert [e["outcome"] for e in _events(ch)] == ["executed"] and ch.bal[BOB] == 100


def test_block_all_stops_an_execution_a_due_point_and_a_routed_share(real):
    ch, tx = _chain(BLOCK_ALL)
    outcome, log = _execute(ch, tx, 1, data={"0": 30})
    assert outcome == "refused" and BLOCKED + " 0" in log

    ch, tx = _chain(BLOCK_ALL, rule=RECURRING, cap_exec=100, cap_period=100,
                    due_at=HEIGHT + 5, due_every=STEP, expires_at=HEIGHT + 5 + 10 * STEP)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert [(e["outcome"], e["reason"]) for e in _events(ch)] == [
        ("due_not_paid", BLOCKED + " 0")]

    ch, tx = _chain(BLOCK_ALL, rule=ROUTE, per_sale=True, on_arrival=True)
    ch.block([spend_tx(CAROL, ALICE, 101, 0)], height=HEIGHT + 1, ts=TS + 1)
    assert [(e["outcome"], e["reason"]) for e in _events(ch)] == [
        ("arrival_not_paid", BLOCKED + " 0")]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (20_101, 0)   # the payment arrived; no share left


def test_lifting_the_clause_lets_the_rule_pay_again(real):
    ch, tx = _chain(BLOCK_ALL)
    assert _execute(ch, tx, 1, data={"0": 30})[0] == "refused"
    del ch.lm.rule_offers.accepted_clauses[(ALICE, 5)]
    assert _execute(ch, tx, 2, data={"0": 30}) == ("paid", {BOB: 30})
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = SPEND_LIMIT    # a stricter one, later
    assert _execute(ch, tx, 3, seq=1, data={"0": 5_001})[0] == "refused"


def test_a_payment_above_the_co_signer_limit_is_blocked_for_no_run_is_co_signed(real):
    ch, tx = _chain(CO_SIGNER)
    outcome, log = _execute(ch, tx, 1, data={"0": 1_001})
    assert outcome == "refused" and BLOCKED + " 0" in log
    assert _execute(ch, tx, 2, data={"0": 1_000}) == ("paid", {BOB: 1_000})


def test_a_clause_that_reads_a_custom_input_reads_zero_in_a_run(real):
    ch, tx = _chain(TWO_FACTOR)                # above 1,000 it wants i26 = 9999
    outcome, log = _execute(ch, tx, 1, data={"0": 1_001})
    assert outcome == "refused" and BLOCKED + " 0" in log
    assert _execute(ch, tx, 2, data={"0": 1_000}) == ("paid", {BOB: 1_000})


def test_a_rule_signed_with_policy_exempt_pays_whatever_the_clause_says(real):
    """An escrow: the clause blocks the key, the rule signed with the term pays."""
    ch, tx = _chain(BLOCK_ALL, policy_exempt=True)
    own = spend_tx(ALICE, BOB, 30, 1)
    result = ch.block([own], height=HEIGHT + 1, ts=TS + 1)
    assert _reason(result, own) == "user_policy_block" and ch.bal[BOB] == 0
    assert _execute(ch, tx, 2, data={"0": 30}) == ("paid", {BOB: 30})

    ch, tx = _chain(BLOCK_ALL, rule=RECURRING, cap_exec=100, cap_period=100,
                    due_at=HEIGHT + 5, policy_exempt=True)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert [e["outcome"] for e in _events(ch)] == ["executed"] and ch.bal[BOB] == 100
