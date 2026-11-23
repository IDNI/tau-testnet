"""Payout stage 2, apply level (Bounty 01): the multi-rule book,
the update transaction, the guarded update kind, sealed rules and
the fee cap, against the engine with a scripted evaluator -- the
stage-1 trigger suite's harness. Book-level halves are in
tests/test_payout_stage2_book.py; native evidence in
tests/test_payout_stage2_native.py.
"""

import hashlib
import itertools
import json

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from consensus import periods, sender_policy
from consensus.approvals import STATUS_EXECUTED, STATUS_OPEN
from consensus.payouts import (
    PAYOUT_STREAM_INDEX,
    clock_settlement_id,
    parse_payout_install,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.serialization import canonical_json
from consensus.tx_signing import signing_message_bytes

from test_payout_triggers import (
    Chain,
    FAR,
    JAN1,
    NOW,
    WEEK,
    _key,
    _sign,
    install_tx,
    transfer_tx,
)
from test_rule_change_release import Chain as RCChain, _guarded, _vote
from test_rule_change_requests import (
    ALICE as RC_ALICE,
    BOB as RC_BOB,
    CAROL as RC_CAROL,
    GUARD_BODY,
    _lm,
    _request,
    _tx,
)

SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_DAVE, DAVE = _key(77777)
SK_ERIN, ERIN = _key(88888)
SK_FRANK, FRANK = _key(99999)
SK_GRACE, GRACE = _key(12121)
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()


def _install(ch, owner, sk, *, height, ts=NOW, seq=0, **kw):
    """Install one rule on the harness chain (multi-rule aware)."""
    ch.lm.rule_offers.accepted_clauses[(owner, PAYOUT_STREAM_INDEX)] = (
        "always (o20[t] = 1)."
    )
    tx = install_tx(owner=owner, sk=sk, seq=seq, **kw)
    ch.block([tx], height=height, ts=ts)
    assert ch.accepted(tx), ch.receipt(tx)
    terms = parse_payout_install(tx)
    assert ch.book.get_rule(owner, terms.rule_id) is not None
    return terms


def execute_tx(owner=ALICE, executor=CAROL, sk=SK_CAROL, seq=0,
               settlement_id="s1", gross=0, rule_id=None):
    tx = {
        "tx_id": f"payout-exec-{next(_TX_SEQ)}",
        "tx_type": "payout_execute",
        "sender_pubkey": executor,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "owner": owner,
        "settlement_id": settlement_id,
        "gross": gross,
    }
    if rule_id is not None:
        tx["rule_id"] = rule_id
    return _sign(tx, sk)


def update_tx(terms, rule_id, *, owner=ALICE, sk=SK_ALICE, seq=1):
    tx = {
        "tx_id": f"payout-update-{next(_TX_SEQ)}",
        "tx_type": "payout_rule_update",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "rule_id": rule_id,
        "max_per_execution": terms["max_per_execution"],
        "max_per_period": terms["max_per_period"],
        "recipients": terms["recipients"],
        "period_kind": terms.get("period_kind", periods.PERIOD_WEEK),
        "anchor_ts": terms.get("anchor_ts", JAN1),
        "terms_sequence_number": terms.get("sequence_number", 2),
    }
    for key in ("due", "on_arrival", "end_period_index", "max_fires",
                "max_total", "sealed", "max_fee_per_execution"):
        if key in terms:
            tx[key] = terms[key]
    return _sign(tx, sk)


def remove_tx(rule_id, *, owner=ALICE, sk=SK_ALICE, seq=1):
    tx = {
        "tx_id": f"payout-remove-{next(_TX_SEQ)}",
        "tx_type": "payout_rule_remove",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "rule_id": rule_id,
    }
    return _sign(tx, sk)


def _balances(**kw):
    base = {ALICE: 100_000, BOB: 0, CAROL: 100_000, DAVE: 0, ERIN: 0,
            FRANK: 0, GRACE: 0, PROPOSER: 0}
    base.update(kw)
    return base


# --- F1 at apply -----------------------------------------------------------------


def test_two_rules_on_one_account_pay_independently():
    ch = Chain(_balances())
    big = _install(ch, ALICE, SK_ALICE, height=20,
                   max_per_execution=1000, max_per_period=1500)
    small = _install(ch, ALICE, SK_ALICE, height=21, seq=1,
                     max_per_execution=200, max_per_period=900,
                     sequence_number=2)
    ch.legs = {20: "1", 21: "300", 22: "0"}

    unnamed = execute_tx(settlement_id="sx", seq=0)
    ch.block([unnamed], height=22, ts=NOW)
    assert not ch.accepted(unnamed)
    assert "several rules" in " ".join(ch.receipt(unnamed)["logs"])

    over_small = execute_tx(settlement_id="s-small", seq=0,
                            rule_id=small.rule_id)
    ch.block([over_small], height=23, ts=NOW)
    assert not ch.accepted(over_small)

    ok = execute_tx(settlement_id="s-big", seq=0, rule_id=big.rule_id)
    ch.block([ok], height=24, ts=NOW)
    assert ch.accepted(ok), ch.receipt(ok)
    assert ch.bal[BOB] == 300
    assert ch.book.get_rule(ALICE, big.rule_id).settlements == ["s-big"]
    assert ch.book.get_rule(ALICE, small.rule_id).settlements == []


# --- F2 at apply -------------------------------------------------------------------


def test_an_update_through_the_update_kind():
    ch = Chain(_balances())
    terms = _install(ch, ALICE, SK_ALICE, height=20,
                     max_per_execution=1000, max_per_period=1500,
                     extra={"period_kind": periods.PERIOD_WEEK})
    ch.legs = {20: "1", 21: "300", 22: "0"}
    ex = execute_tx(settlement_id="s1", seq=0)
    ch.block([ex], height=21, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[BOB] == 300

    upd = update_tx(
        {"max_per_execution": 2000, "max_per_period": 2500,
         "recipients": [BOB, CAROL], "sequence_number": 2},
        terms.rule_id, seq=1)
    ch.block([upd], height=22, ts=NOW)
    assert ch.accepted(upd), ch.receipt(upd)
    state = ch.book.get(ALICE)
    assert state.version == 2
    assert state.lineage == [terms.rule_id]
    assert state.spent_in_period == 300
    assert state.settlements == ["s1"]
    new_id = state.terms.rule_id
    assert new_id != terms.rule_id

    replay = execute_tx(settlement_id="s1", seq=1)
    ch.block([replay], height=23, ts=NOW)
    assert not ch.accepted(replay)
    assert ch.bal[BOB] == 300

    # The new caps are live: 1,500 was over the old per-execution
    # cap and is inside the new one.
    ch.legs = {20: "1", 21: "1500", 22: "0"}
    ex2 = execute_tx(settlement_id="s2", seq=1)
    ch.block([ex2], height=24, ts=NOW)
    assert ch.accepted(ex2), ch.receipt(ex2)
    assert ch.bal[BOB] == 300 + 1500


@pytest.fixture()
def guard_evaluators():
    """The seeded guard allows a change only once slot i18 holds a
    pubkey (the rule-change release suite's guard)."""
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY,
            lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _guarded_update_setup(lm):
    """A payout rule with one settled execution, on the
    rule-change harness's lifecycle (its apply clock is fixed)."""
    from consensus.payouts import PayoutTerms

    terms = PayoutTerms(
        owner=RC_ALICE, max_per_execution=1000, max_per_period=1500,
        recipients=(RC_BOB, RC_CAROL),
        period_kind=periods.PERIOD_WEEK, anchor_ts=1234560000,
        sequence_number=1)
    lm.payout_rules.install(terms)
    lm.payout_rules.settle(
        RC_ALICE, "s1", 700, ts=1234567890, rule_id=terms.rule_id)
    body = canonical_json({
        "rule_id": terms.rule_id,
        "max_per_execution": 2000,
        "max_per_period": 2500,
        "recipients": [RC_BOB, RC_CAROL],
        "period_kind": periods.PERIOD_WEEK,
        "anchor_ts": 1234560000,
        "sequence_number": 2,
    }).decode()
    return terms, body


def test_a_guarded_account_updates_through_the_update_kind():
    # No guard clause: the kind-6 request executes in its own
    # block, like every other kind.
    lm = _lm()
    terms, body = _guarded_update_setup(lm)
    req = _request(tau_defs.RULE_CHANGE_KIND_PAYOUT_UPDATE, text=body)
    chain = RCChain(lm)
    chain.block(_tx(req))
    entry = chain.entry(req)
    assert entry.status == STATUS_EXECUTED
    state = chain.lm.payout_rules.get(RC_ALICE)
    assert state.version == 2
    assert state.lineage == [terms.rule_id]
    assert state.settlements == ["s1"]
    assert state.spent_in_period == 700
    assert state.terms.max_per_period == 2500


@pytest.mark.usefixtures("guard_evaluators")
def test_a_guarded_account_updates_only_when_the_guard_allows():
    # With a guard, the same request parks until an approver's
    # vote fills the slot -- the update kind has full request
    # parity, not a revoke-and-reinstall fallback.
    lm = _guarded()
    terms, body = _guarded_update_setup(lm)
    chain = RCChain(lm)
    req = _request(
        tau_defs.RULE_CHANGE_KIND_PAYOUT_UPDATE, text=body, expire=3000)
    chain.block(_tx(req))
    entry = chain.entry(req)
    assert entry.status == STATUS_OPEN
    assert chain.lm.payout_rules.get(RC_ALICE).version == 1
    chain.block(_vote(req.request_id))
    entry = chain.entry(req)
    assert entry.status == STATUS_EXECUTED
    state = chain.lm.payout_rules.get(RC_ALICE)
    assert state.version == 2
    assert state.settlements == ["s1"]
    assert state.spent_in_period == 700


# --- F3 at apply: the six-leg work escrow -----------------------------------------


def _escrow_legs(vals):
    gross = int(vals.get(1, 0))
    shares = [50, 10, 10, 10, 15, 5]
    out = {20: "6"}
    for k, pct in enumerate(shares):
        out[21 + 2 * k] = str(gross * pct // 100)
        out[22 + 2 * k] = str(k)
    return out


def test_the_work_escrow_pays_exactly_the_locked_price():
    ch = Chain(_balances())
    terms = _install(
        ch, ALICE, SK_ALICE, height=20,
        recipients=[BOB, CAROL, DAVE, ERIN, FRANK, GRACE],
        max_per_execution=10000, max_per_period=20000)
    ch.legs_fn = _escrow_legs
    ex = execute_tx(settlement_id="escrow-1", gross=10000, seq=0)
    ch.block([ex], height=21, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[BOB] == 5000
    assert ch.bal[CAROL] == 100_000 + 1000
    assert ch.bal[DAVE] == 1000
    assert ch.bal[ERIN] == 1000
    assert ch.bal[FRANK] == 1500
    assert ch.bal[GRACE] == 500
    assert ch.bal[ALICE] == 100_000 - 10000
    state = ch.book.get_rule(ALICE, terms.rule_id)
    assert state.paid_total == 10000

    # A price the percentages do not divide: every leg floors, the
    # dust stays with the poster, nothing rounds up.
    ex2 = execute_tx(settlement_id="escrow-2", gross=999, seq=1)
    ch.block([ex2], height=22, ts=NOW)
    assert ch.accepted(ex2), ch.receipt(ex2)
    assert ch.bal[BOB] == 5000 + 499
    assert ch.bal[GRACE] == 500 + 49
    assert ch.bal[ALICE] == 100_000 - 10000 - 994


# --- F4 at apply: sealed rules -------------------------------------------------------


def test_a_sealed_rule_locks_the_account_until_it_ends():
    ch = Chain(_balances())
    terms = _install(
        ch, ALICE, SK_ALICE, height=20, ts=JAN1 - 3600,
        recipients=[BOB], extra={"due": True, "end_period_index": 2,
                                 "sealed": True,
                                 "period_kind": periods.PERIOD_WEEK})
    # The owner's own transfer is refused while the seal holds.
    tx = transfer_tx(BOB, 10, SK_ALICE, sender=ALICE, seq=1)
    ch.block([tx], height=21, ts=JAN1 + 60)
    assert not ch.accepted(tx)
    assert ch.receipt(tx)["reason"] == "payout_rule_sealed"
    assert ch.bal[BOB] == 0
    # Removal and in-place replacement are refused too.
    rm = remove_tx(terms.rule_id, seq=1)
    ch.block([rm], height=22, ts=JAN1 + 60)
    assert not ch.accepted(rm)
    assert ch.book.get_rule(ALICE, terms.rule_id) is not None
    # Past the final period the seal lifts and the account moves.
    tx2 = transfer_tx(BOB, 10, SK_ALICE, sender=ALICE, seq=1)
    ch.block([tx2], height=23, ts=JAN1 + 3 * WEEK + 60)
    assert ch.accepted(tx2), ch.receipt(tx2)
    assert ch.bal[BOB] == 10


# --- F5 at apply: the fee cap ---------------------------------------------------------


def test_an_execution_over_the_rules_fee_cap_is_refused():
    ch = Chain(_balances(), fee=7)
    _install(ch, ALICE, SK_ALICE, height=20,
             extra={"max_fee_per_execution": 3})
    ch.legs = {20: "1", 21: "100", 22: "0"}
    ex = execute_tx(settlement_id="s1", seq=0)
    ch.block([ex], height=21, ts=NOW)
    assert not ch.accepted(ex)
    assert ch.receipt(ex)["reason"] == "payout_fee_cap_exceeded"
    assert ch.bal[BOB] == 0
    assert ch.book.get(ALICE).settlements == []

    ch2 = Chain(_balances(), fee=7)
    _install(ch2, ALICE, SK_ALICE, height=20,
             extra={"max_fee_per_execution": 7})
    ch2.legs = {20: "1", 21: "100", 22: "0"}
    ex2 = execute_tx(settlement_id="s1", seq=0)
    ch2.block([ex2], height=21, ts=NOW)
    assert ch2.accepted(ex2), ch2.receipt(ex2)
    assert ch2.bal[BOB] == 100


# --- F6 at apply: sweep cap and missed periods -----------------------------------------


def test_clock_sweep_settles_at_most_sixteen_due_rules():
    owners = []
    balances = {CAROL: 0, PROPOSER: 0}
    for i in range(17):
        sk, pk = _key(20000 + i)
        owners.append((sk, pk))
        balances[pk] = 10_000
    ch = Chain(balances)
    anchor = NOW + WEEK
    rule_ids = {}
    for i, (sk, pk) in enumerate(owners):
        terms = _install(
            ch, pk, sk, height=20 + i, ts=NOW, recipients=[CAROL],
            anchor_ts=anchor, max_per_execution=1000,
            max_per_period=1500,
            extra={"due": True, "max_fires": 5,
                   "period_kind": periods.PERIOD_WEEK})
        rule_ids[pk] = terms.rule_id
    ch.legs = {20: "1", 21: "100", 22: "0"}
    ch.block([], height=40, ts=anchor + 60)
    fired = [pk for pk in balances
             if pk in rule_ids
             and ch.book.get_rule(pk, rule_ids[pk]).fires == 1]
    assert len(fired) == 16
    assert ch.bal[CAROL] == 1600
    # Earliest-due-first with the (owner, rule id) tiebreak: the
    # one left due is the largest owner key.
    left = [pk for pk in rule_ids if pk not in fired]
    assert left == [max(rule_ids)]
    ch.block([], height=41, ts=anchor + 120)
    assert ch.book.get_rule(left[0], rule_ids[left[0]]).fires == 1
    assert ch.bal[CAROL] == 1700


def test_missed_periods_are_counted_by_the_sweep():
    ch = Chain(_balances())
    terms = _install(
        ch, ALICE, SK_ALICE, height=20, ts=JAN1 - 3600,
        recipients=[BOB], extra={"due": True, "max_fires": 10,
                                 "period_kind": periods.PERIOD_WEEK})
    ch.legs = {20: "1", 21: "100", 22: "0"}
    ch.block([], height=21, ts=JAN1 + 60)
    state = ch.book.get_rule(ALICE, terms.rule_id)
    assert state.fires == 1
    assert state.missed_periods == 0
    # No block lands in periods 1 or 2; the next block is in
    # period 3, which fires -- and the two closed periods are
    # counted as missed, never caught up.
    ch.block([], height=22, ts=JAN1 + 3 * WEEK + 60)
    state = ch.book.get_rule(ALICE, terms.rule_id)
    assert state.missed_periods == 2
    assert state.fires == 2
    assert state.settlements == [
        clock_settlement_id(terms.rule_id, 0),
        clock_settlement_id(terms.rule_id, 3),
    ]
    assert ch.bal[BOB] == 200
