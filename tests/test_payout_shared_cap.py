"""Shared caps: several payout rules draw on one limit (#34, #178).

A rule names a shared cap with `shared_cap_id` and `shared_cap_amount`
(the limit, the same on every rule that draws on the cap). The book keeps
one spent total per (account, cap id): each settled run counts exactly once
across every rule that draws on it, a run that would pass the limit is
refused with no debt and no completion, and the room frees when a rule
leaves the book -- revoked, expired, superseded, or refunded at a grant
deadline. The ledger is rebuilt from the open rules' paid totals on
restore, so it can never disagree with the stored rows.

Part A is book-level (no engine). Part B runs the real `apply_block` with
a scripted interpreter and mock policy evaluators, comparing the FULL
balance map against an oracle.
"""
import pytest

import tau_defs
from consensus import payout as p
from consensus.payout import (
    PayoutBook, PayoutExecution, PayoutRefused,
    parse_payout_rule_set, parse_payout_spec, payout_spec_text,
    validate_terms_shape,
)

from tests.test_payout_apply import (
    _executed, _logs, evs, exec_tx, rid, ridb, set_tx,
)
from tests.chain_harness import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, TS, Chain, Oracle,
)

AKEY = "a" * 96
BKEY = "b" * 96
CKEY = "c" * 96
BODY = "o30[t]:bv[24] = min({ 500 }:bv[24], i2[t]:bv[24])"
RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."


def _terms(account, seq, body=BODY, slots=(BKEY,), **kw):
    d = dict(account_pubkey=account, sequence_number=seq, body=body,
             slots=slots, cap_per_execution=1000, cap_per_period=10000,
             kind=p.KIND_BLOCKS, period=1000, expires_at=100000)
    d.update(kw)
    return p.PayoutTerms(**d)


def _cap(account, seq, cap_id="rent", amount=1000, **kw):
    kw["shared_cap_id"] = cap_id
    kw.setdefault("shared_cap_amount", amount)
    return _terms(account, seq, **kw)


def _pay(book, terms, amount, height=100, ts=0, balance=100_000):
    """Settle + record one execution of `terms` for `amount` through the
    book's own shared-cap spent, as the engine does."""
    state = book.state_of(terms.account_pubkey, terms.rule_id)
    exe = PayoutExecution("", terms.account_pubkey, terms.rule_id, (), ())
    legs = p.settle(terms, state, exe, {"o30": str(amount)}, height=height,
                    ts=ts, balance=balance,
                    shared_spent=book.shared_spent_for(terms))
    assert legs == [(0, terms.slots[0], amount)]
    return book.record(terms.account_pubkey, terms.rule_id, amount, height, ts)


# --- Part A: the book ------------------------------------------------------------


def test_shared_cap_counts_each_settled_run_once_across_rules():
    book = PayoutBook()
    a = _cap(AKEY, 1)
    b = _cap(AKEY, 2, body="o30[t]:bv[24] = min({ 700 }:bv[24], i2[t]:bv[24])",
             slots=(CKEY,))
    book.install(a, anchor=10)
    book.install(b, anchor=10)
    assert book.shared_cap_limit(AKEY, "rent") == 1000
    assert book.shared_spent_for(a) == 0
    _pay(book, a, 600)
    assert book.shared_spent_for(a) == 600
    assert book.shared_spent_for(b) == 600
    # B asks 500: 600 already spent under the cap, so 1100 > 1000 refuses.
    state_b = book.state_of(AKEY, b.rule_id)
    exe = PayoutExecution("", AKEY, b.rule_id, (), ())
    with pytest.raises(PayoutRefused, match="shared cap"):
        p.settle(b, state_b, exe, {"o30": "500"}, height=100, ts=0,
                 balance=100_000, shared_spent=book.shared_spent_for(b))
    # B asks 400: exactly the 400 left, pays.
    _pay(book, b, 400)
    assert book.shared_spent_for(a) == 1000
    # The cap is exhausted: one more coin from either rule refuses.
    with pytest.raises(PayoutRefused, match="shared cap"):
        p.settle(a, book.state_of(AKEY, a.rule_id), exe, {"o30": "1"},
                 height=100, ts=0, balance=100_000,
                 shared_spent=book.shared_spent_for(a))


def test_a_refused_run_leaves_no_debt_and_stays_in_the_retry_window():
    book = PayoutBook()
    a = _cap(AKEY, 1)
    due = _cap(AKEY, 2, due_at=1000, due_every=256)
    book.install(a, anchor=10)
    book.install(due, anchor=10)
    _pay(book, a, 1000)  # the cap is spent out by the other rule
    state = book.state_of(AKEY, due.rule_id)
    exe = PayoutExecution("", AKEY, due.rule_id, (), ())
    with pytest.raises(PayoutRefused, match="shared cap"):
        p.settle(due, state, exe, {"o30": "500"}, height=1000, ts=0,
                 balance=100_000, shared_spent=book.shared_spent_for(due))
    # Nothing moved, nothing completed: no execution, no paid total.
    state = book.state_of(AKEY, due.rule_id)
    assert (state.executions, state.paid_total) == (0, 0)
    # The due point stays open: the run is retried while its window is open.
    book.due_ran(AKEY, due.rule_id, 1000, paid=False)
    assert (AKEY, due.rule_id) in book.due(1001, 0)
    # Free the cap and the same point pays.
    book.revoke(AKEY, a.rule_id)
    assert book.shared_spent_for(due) == 0
    _pay(book, due, 500, height=1001)
    assert book.state_of(AKEY, due.rule_id).paid_total == 500


def test_shared_cap_frees_on_revoke_and_forgets_a_dead_cap():
    book = PayoutBook()
    a = _cap(AKEY, 1)
    b = _cap(AKEY, 2)
    book.install(a, anchor=10)
    book.install(b, anchor=10)
    _pay(book, a, 600)
    _pay(book, b, 400)
    assert book.shared_spent_for(a) == 1000
    book.revoke(AKEY, a.rule_id)
    assert book.shared_spent_for(b) == 400
    assert book.shared_cap_limit(AKEY, "rent") == 1000
    # B can now pay 600 more: the 600 A used is free again.
    _pay(book, b, 600)
    assert book.shared_spent_for(b) == 1000
    book.revoke(AKEY, b.rule_id)
    assert book.shared_spent_for(b) == 0
    assert book.shared_cap_limit(AKEY, "rent") is None
    # A fresh rule may open the same cap id again, with any limit.
    c = _cap(AKEY, 3, amount=2000)
    ok, _ = book.can_admit_set(c, 10, 0)
    assert ok
    book.install(c, anchor=10)
    assert book.shared_cap_limit(AKEY, "rent") == 2000


def test_shared_cap_frees_on_grant_refund():
    book = PayoutBook()
    grant = _cap(AKEY, 1, grant_amount=5000, grant_deadline=500)
    book.install(grant, anchor=10)
    assert book.shared_spent_for(grant) == 0
    book.record(AKEY, grant.rule_id, 1200, 100, 0)  # a draw out of the escrow
    assert book.shared_spent_for(grant) == 1200
    assert book.escrow_total() == 3800
    gone = book.refund_due(500, 0)
    assert len(gone) == 1 and gone[0][0] == grant
    assert gone[0][1].held == 3800  # the remainder is refunded
    assert book.shared_spent_for(grant) == 0
    assert book.shared_cap_limit(AKEY, "rent") is None


def test_shared_cap_store_restore_round_trips_the_ledger():
    book = PayoutBook()
    a = _cap(AKEY, 1)
    b = _cap(AKEY, 2)
    book.install(a, anchor=10)
    book.install(b, anchor=10)
    _pay(book, a, 600)
    _pay(book, b, 300)
    root = book.root()
    rows = book.store_rows()
    assert len(rows[0][18]) == 16  # `more` carries the shared-cap pair
    restored = PayoutBook.restore(rows, *book.resolved_state())
    assert restored.root() == root
    assert restored.shared_spent_for(a) == 900
    assert restored.shared_cap_limit(AKEY, "rent") == 1000
    assert restored.get(AKEY, a.rule_id).shared_cap_id == "rent"
    assert restored.get(AKEY, a.rule_id).shared_cap_amount == 1000
    # The restored book enforces the cap the same way.
    state = restored.state_of(AKEY, b.rule_id)
    exe = PayoutExecution("", AKEY, b.rule_id, (), ())
    with pytest.raises(PayoutRefused, match="shared cap"):
        p.settle(b, state, exe, {"o30": "101"}, height=100, ts=0,
                 balance=100_000, shared_spent=restored.shared_spent_for(b))
    restored.record(AKEY, b.rule_id, 100, 100, 0)
    assert restored.shared_spent_for(a) == 1000


def test_restore_refuses_one_cap_with_two_limits():
    book1 = PayoutBook()
    book1.install(_cap(AKEY, 1, amount=1000), anchor=10)
    book2 = PayoutBook()
    book2.install(_cap(AKEY, 1, amount=2000), anchor=10)
    rows = book1.store_rows() + book2.store_rows()
    with pytest.raises(ValueError, match="different limit"):
        PayoutBook.restore(rows, 0, bytes(32))


def test_shared_cap_admission_refuses_a_different_limit():
    book = PayoutBook()
    book.install(_cap(AKEY, 1, amount=1000), anchor=10)
    ok, why = book.can_admit_set(_cap(AKEY, 2, amount=2000), 10, 0)
    assert not ok and "already has a limit" in why
    ok, _ = book.can_admit_set(_cap(AKEY, 2, amount=1000), 10, 0)
    assert ok
    # Another account may use the same cap id with its own limit.
    ok, _ = book.can_admit_set(_cap(BKEY, 1, amount=2000, slots=(AKEY,)), 10, 0)
    assert ok


def test_shared_cap_shape_rules():
    assert validate_terms_shape(_cap(AKEY, 1, shared_cap_amount=None),
                                10, 0) is not None  # id without amount
    assert validate_terms_shape(
        _terms(AKEY, 1, shared_cap_id=None, shared_cap_amount=1000),
        10, 0) is not None  # amount without id
    assert validate_terms_shape(_cap(AKEY, 1, amount=0), 10, 0) is not None
    assert validate_terms_shape(
        _cap(AKEY, 1, amount=tau_defs.MAX_TRANSFER_VALUE + 1),
        10, 0) is not None
    assert validate_terms_shape(_cap(AKEY, 1, cap_id=""), 10, 0) is not None
    assert validate_terms_shape(_cap(AKEY, 1, cap_id="x" * 65),
                                10, 0) is not None
    assert validate_terms_shape(_cap(AKEY, 1), 10, 0) is None


def test_shared_cap_spec_text_carries_the_fields():
    tx = {"sender_pubkey": AKEY, "sequence_number": 7, "rule_text": RULE,
          "slots": [BKEY], "cap_per_execution": 1000, "cap_per_period": 10000,
          "period_blocks": 1000, "expires_at": 100000,
          "shared_cap_id": "rent", "shared_cap_amount": 1000}
    terms = parse_payout_rule_set(tx)
    assert terms.shared_cap_id == "rent"
    assert terms.shared_cap_amount == 1000
    # The same terms without the cap are a different rule.
    plain = dict(tx)
    del plain["shared_cap_id"]
    del plain["shared_cap_amount"]
    assert parse_payout_rule_set(plain).rule_id != terms.rule_id
    # The canonical spec text round-trips, with the cap fields in it.
    fields = {k: v for k, v in tx.items()
              if k not in ("sender_pubkey", "sequence_number")}
    spec = payout_spec_text(fields, sequence_number=7)
    assert '"shared_cap_amount":1000' in spec
    assert '"shared_cap_id":"rent"' in spec
    assert parse_payout_spec(spec, AKEY) == terms


def test_an_update_frees_the_old_version_and_the_new_one_counts_fresh():
    from dataclasses import replace as _replace
    book = PayoutBook()
    old = _cap(AKEY, 1)
    book.install(old, anchor=10)
    _pay(book, old, 600)
    new = _cap(AKEY, 2, body="o30[t]:bv[24] = min({ 700 }:bv[24], i2[t]:bv[24])")
    book.update(AKEY, old.rule_id, new, anchor=20)
    # The update resets the rule, as it resets the period caps: the old
    # version's 600 is free, and the new version counts from zero.
    new2 = _replace(new, version=2)
    assert book.shared_spent_for(new2) == 0
    _pay(book, new2, 1000, height=100)
    assert book.shared_spent_for(new2) == 1000


# --- Part B: the engine ----------------------------------------------------------


def _bal2():
    return {ALICE: 10_000, BOB: 0, CAROL: 50, PROPOSER: 0}


def _installed2(ch, oracle, tx):
    ch.block([tx])
    oracle.create(tx, fee=0)
    return tx


def test_two_rules_sharing_a_cap_are_bound_together_end_to_end(evs):
    ch, oracle = Chain(_bal2(), fee=0), Oracle(_bal2())
    a = _installed2(ch, oracle, set_tx(
        seq=0, cap_exec=1000, cap_period=10000,
        shared_cap_id="rent", shared_cap_amount=1000))
    b = _installed2(ch, oracle, set_tx(
        seq=1, cap_exec=1000, cap_period=10000,
        shared_cap_id="rent", shared_cap_amount=1000))
    oracle.check(ch)
    # A pays 600.
    ch.block([exec_tx(seq=0, rule_id=rid(a), data={"0": 600})],
             height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(BOB, 600)], ts=TS + 1)
    oracle.check(ch)
    # B asks 500: 600 already spent under the cap, so the run is refused --
    # no debt, no completion event, the rule stays installed.
    result = ch.block([exec_tx(seq=1, rule_id=rid(b), data={"0": 500})],
                      height=HEIGHT + 2, ts=TS + 2)
    assert result.outcomes[0].reason == "payout_not_executed"
    assert "shared cap" in _logs(result)
    assert ch.lm.payout_rules.state_of(ALICE, ridb(b)).executions == 0
    oracle.check(ch)
    # B asks 400: exactly the 400 left, pays.
    ch.block([exec_tx(seq=1, rule_id=rid(b), data={"0": 400})],
             height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, legs=[(BOB, 400)], ts=TS + 3)
    oracle.check(ch)
    assert ch.lm.payout_rules.shared_spent_for(
        parse_payout_rule_set(b)) == 1000


def test_a_rule_with_a_mismatched_cap_limit_is_not_installed(evs):
    ch, oracle = Chain(_bal2(), fee=0), Oracle(_bal2())
    _installed2(ch, oracle, set_tx(
        seq=0, cap_exec=1000, cap_period=10000,
        shared_cap_id="rent", shared_cap_amount=1000))
    result = ch.block([set_tx(
        seq=1, cap_exec=1000, cap_period=10000,
        shared_cap_id="rent", shared_cap_amount=2000)])
    assert result.outcomes[0].reason == "payout_rule_not_set"
    assert "already has a limit" in _logs(result)
    assert ch.lm.payout_rules.count_for(ALICE) == 1
    oracle.check(ch)
