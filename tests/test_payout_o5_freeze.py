"""o5-freeze double-pay: a manual execute after an unfreeze must settle the
due point (#178).

Regression for the hole the 6859fd3 guard left open: the guard refuses a
manual re-execution of an already-PAID point, but a point the node could NOT
pay -- here, the payer's o5 clause froze it -- stayed pending, and a manual
execute after a same-block unfreeze paid it without marking it run, so the
node retry paid the same point again after the cap period rolled over
(March paid twice: manual Apr 2 + node retry Apr 4).

The fix: a manual execute that pays a due rule marks the point settled for
the slots it paid (PayoutBook.note_manual_due_payment). The node's due run
then refuses a settled leg ("a due point pays once"), and a second manual
inside the point's window is refused by check_execution. The schedule
itself is untouched: the point stays queued, so the deadline refund -- a run
whose legs are all different slots -- still fires (see the grant-rule
suite, case 5).

Scenario (Marco monthly rule, ALICE 1000 -> BOB, 100/month): Jan 31 + Feb 28
node runs pay; Mar 31 node run fails on the o5 freeze; Apr 2 unfreeze +
manual execute pays; Apr 3 + Apr 4 node retries must pay nothing.
"""
import pytest

from consensus import payout as p
from consensus import sender_policy
from consensus.payout import PayoutBook, parse_payout_rule_set, payout_rule_body
from consensus.policy_mock import MockPolicyEvaluator

from tests.chain_harness import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, Chain, Oracle, _logs,
)
from tests.test_payout_apply import _events, _executed, exec_tx, rid, set_tx

JAN1 = 1767225600   # 2026-01-01 00:00 UTC (install)
JAN31 = 1769817600  # 2026-01-31 00:00 UTC (due point 0)
FEB28 = 1772236800  # 2026-02-28 00:00 UTC (due point 1, clamped)
MAR31 = 1774915200  # 2026-03-31 00:00 UTC (due point 2)
APR02 = MAR31 + 2 * 86400
APR03 = MAR31 + 3 * 86400
APR04 = MAR31 + 4 * 86400  # cap period 3 starts (anchor Jan 1 + 3x31d)
EXPIRES = 1798761600  # 2027-01-01 00:00 UTC
AMOUNT = 100
PERIOD_S = 2678400  # 31 days, cap window for cap_per_period

RULE = ("always ( (i2[t]:bv[24] >= { 100 }:bv[24]) ? "
        "(o30[t]:bv[24] = { 100 }:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).")
BODY = payout_rule_body(RULE)
FREEZE = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


@pytest.fixture
def evs():
    out = {}
    for pool in ("apply", "payout_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    out["payout_apply"].set_outputs(
        BODY, lambda inputs: {"o30": "100" if int(inputs.get("i2", "0")) >= 100 else "0"})
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


def _book(ch, tx):
    terms = ch.lm.payout_rules.get(ALICE, p.parse_payout_rule_set(tx).rule_id)
    st = ch.lm.payout_rules.state_of(ALICE, p.parse_payout_rule_set(tx).rule_id)
    return {"due_index": st.due_index, "next_due": st.next_due(terms),
            "executions": st.executions, "paid_total": st.paid_total,
            "missed": st.missed, "due_done": st.due_done,
            "settled_due": st.settled_due}


def _installed(evs):
    bals = {ALICE: 1000, BOB: 0, CAROL: 500, PROPOSER: 0}
    ch, oracle = Chain(dict(bals), fee=0), Oracle(dict(bals))
    tx = set_tx(rule=RULE, slots=[BOB], cap_exec=AMOUNT, cap_period=AMOUNT,
                clock="period_seconds", period=PERIOD_S,
                due_at=JAN31, due_months=1, expires_at=EXPIRES)
    ch.block([tx], height=HEIGHT, ts=JAN1)
    oracle.create(tx, fee=0)
    # Jan 31 + Feb 28 node runs pay.
    ch.block([], height=HEIGHT + 1, ts=JAN31)
    oracle.pay(ALICE, BOB, 100, ts=JAN31)
    oracle.check(ch)
    ch.block([], height=HEIGHT + 2, ts=FEB28)
    oracle.pay(ALICE, BOB, 100, ts=FEB28)
    oracle.check(ch)
    b = _book(ch, tx)
    assert ch.bal[ALICE] == 800 and ch.bal[BOB] == 200
    assert b["due_index"] == 2 and b["paid_total"] == 200
    return ch, oracle, tx


def test_o5_freeze_manual_settles_the_point_no_double_pay(evs):
    ch, oracle, tx = _installed(evs)
    # F1: freeze ALICE's o5; Mar 31 node run must fail on the freeze.
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = FREEZE
    evs["apply"].set_verdict(FREEZE, lambda inputs: 0)  # blocks every transfer
    ch.block([], height=HEIGHT + 3, ts=MAR31)
    evs_out = _events(ch)
    b = _book(ch, tx)
    assert len(evs_out) == 1 and evs_out[0].get("outcome") == "due_not_paid"
    assert "o5" in str(evs_out[0].get("reason", ""))
    assert ch.bal[ALICE] == 800 and ch.bal[BOB] == 200
    assert b["due_index"] == 2 and b["paid_total"] == 200 and b["executions"] == 2
    # F2: Apr 2 -- unfreeze visible + manual exec in ONE block: the manual pays.
    evs["apply"].set_verdict(FREEZE, lambda inputs: 1)
    exe = exec_tx(executor=CAROL, seq=ch.seq.get(CAROL, 0),
                  account=ALICE, rule_id=rid(tx))
    result = ch.block([exe], height=HEIGHT + 4, ts=APR02)
    _executed(oracle, executor=CAROL, fee=0, account=ALICE,
              legs=[(BOB, 100)], ts=APR02)
    oracle.check(ch)
    evs_out = _events(ch)
    b = _book(ch, tx)
    assert ch.bal[ALICE] == 700 and ch.bal[BOB] == 300
    assert b["paid_total"] == 300 and b["executions"] == 3
    # The manual settled the Mar 31 point for slot 0 ...
    assert b["settled_due"] == frozenset({(2, 0)})
    # ... and the end-of-block retry in the same block paid nothing for it.
    executed = [e for e in evs_out if e.get("outcome") == "executed"]
    assert len(executed) == 1 and executed[0].get("executor_pubkey") is not None
    # The retry is refused by the period cap here, not by the settled
    # check: the manual already spent this period's 100, so the step
    # fails before the settled check is reached. The settled check is
    # the operative guard in the next period (F4 below), where the cap
    # has reset -- that is where the original double-pay happened.
    refused = [e for e in evs_out if e.get("outcome") == "due_not_paid"]
    assert refused and all("over the cap per period" in str(e.get("reason", "")) for e in refused)
    assert "Payout executed: 100" in _logs(result)
    # F3: Apr 3 -- node retry still pays nothing.
    ch.block([], height=HEIGHT + 5, ts=APR03)
    evs_out = _events(ch)
    b = _book(ch, tx)
    assert ch.bal[ALICE] == 700 and ch.bal[BOB] == 300
    assert b["paid_total"] == 300 and b["executions"] == 3
    assert all(e.get("outcome") == "due_not_paid"
               and "over the cap per period" in str(e.get("reason", "")) for e in evs_out)
    # F4: Apr 4, new cap period -- the retry must NOT pay the point again.
    ch.block([], height=HEIGHT + 6, ts=APR04)
    evs_out = _events(ch)
    b = _book(ch, tx)
    assert ch.bal[BOB] == 300 and b["paid_total"] == 300
    assert b["executions"] == 3 and b["due_index"] == 2
    assert all(e.get("outcome") == "due_not_paid"
               and "settled" in str(e.get("reason", "")) for e in evs_out)
    oracle.check(ch)


def test_second_manual_inside_the_window_is_refused(evs):
    ch, oracle, tx = _installed(evs)
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = FREEZE
    evs["apply"].set_verdict(FREEZE, lambda inputs: 0)
    ch.block([], height=HEIGHT + 3, ts=MAR31)
    evs["apply"].set_verdict(FREEZE, lambda inputs: 1)
    exe = exec_tx(executor=CAROL, seq=ch.seq.get(CAROL, 0),
                  account=ALICE, rule_id=rid(tx))
    ch.block([exe], height=HEIGHT + 4, ts=APR02)
    _executed(oracle, executor=CAROL, fee=0, account=ALICE,
              legs=[(BOB, 100)], ts=APR02)
    oracle.check(ch)
    assert ch.bal[BOB] == 300
    # A second manual the next day, still inside the Mar 31 point's window,
    # is refused: the point already settled.
    bal_before = dict(ch.bal)
    exe2 = exec_tx(executor=CAROL, seq=ch.seq.get(CAROL, 0),
                   account=ALICE, rule_id=rid(tx))
    result = ch.block([exe2], height=HEIGHT + 5, ts=APR03)
    assert ch.bal == bal_before
    assert "already settled" in _logs(result)
    assert _book(ch, tx)["executions"] == 3
    oracle.check(ch)


def test_settled_point_survives_a_restore():
    tx = set_tx(rule=RULE, slots=[BOB], cap_exec=AMOUNT, cap_period=AMOUNT,
                clock="period_seconds", period=PERIOD_S,
                due_at=JAN31, due_months=1, expires_at=EXPIRES)
    terms = parse_payout_rule_set(tx)
    book = PayoutBook()
    book.install(terms, HEIGHT)
    book.record(ALICE, terms.rule_id, 100, HEIGHT + 1, JAN31 + 1)
    book.note_manual_due_payment(ALICE, terms.rule_id, [(0, BOB, 100)])
    rows = book.store_rows()
    assert len(rows[0][18]) == 15  # `more` carries the settled pair
    assert rows[0][18][14] == ((0, 0),)
    restored = PayoutBook.restore(rows, *book.resolved_state())
    assert restored.root() == book.root()
    state = restored.state_of(ALICE, terms.rule_id)
    assert state.settled_due == frozenset({(0, 0)})
    assert (state.paid_total, state.executions) == (100, 1)
    # A rule with no manual payment keeps the 14-shape row: its root is
    # the one it always had.
    plain = PayoutBook()
    plain.install(terms, HEIGHT)
    plain.record(ALICE, terms.rule_id, 100, HEIGHT + 1, JAN31 + 1)
    assert len(plain.store_rows()[0][18]) == 14
