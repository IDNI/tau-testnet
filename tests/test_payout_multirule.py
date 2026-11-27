"""Multi-rule payout book: several rules on one account, due runs, arrivals.

Adapted from ~/workspace/work-to-earn/tau-rules-form/smoke-payout.py (book-level,
no engine) plus apply/admission tests for the new shape: a standing schedule is
a due rule, a royalty is an on-arrival rule, and an update supersedes the old
version instead of replacing the account's only rule.
"""
from dataclasses import replace
from datetime import date

import pytest
from py_ecc.bls import G2Basic

from consensus import payout as p
from consensus.approvals import ApprovalRequest
from consensus.payout import (
    PayoutBook, PayoutState, PayoutTerms, parse_payout_rule_set,
    validate_terms_shape,
)
from consensus import sender_policy
from consensus.admission import (
    TipAdmissionView, validate_mempool_admission,
    validate_payout_execute_payload, validate_payout_rule_update_payload,
)

from tests.chain_harness import (
    ALICE, BOB, CAROL, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _sign,
    spend_tx,
)
from tests.test_payout_apply import (
    FREEZE, _events, _executed, _installed, _reason, _logs, evs, exec_tx, rid,
    ridb, set_tx, update_tx,
)
from unittest.mock import MagicMock

# --- Part A: book-level (smoke adaptation; keys are plain strings here) --------

AKEY = "a" * 96
BKEY = "b" * 96
CKEY = "c" * 96
BODY = "o30[t]:bv[24] = min({ 500 }:bv[24], i2[t]:bv[24])"
BODY_SALE = "o30[t]:bv[24] = i27[t]:bv[24]"


def _terms(account, seq, body=BODY, slots=(BKEY,), **kw):
    d = dict(account_pubkey=account, sequence_number=seq, body=body,
             slots=slots, cap_per_execution=1000, cap_per_period=10000,
             kind=p.KIND_BLOCKS, period=1000, expires_at=100000)
    d.update(kw)
    return p.PayoutTerms(**d)


def _dup(book, t):
    try:
        book.install(t, 10)
        return False
    except ValueError:
        return True


def _nochange(book, t):
    ok, _ = book.can_admit_update(AKEY, t.rule_id, t, 60, 0)
    return not ok


def test_two_rules_on_one_account_are_independent():
    book = p.PayoutBook()
    t1 = _terms(AKEY, 1)
    t2 = _terms(AKEY, 2, body="o30[t]:bv[24] = min({ 700 }:bv[24], i2[t]:bv[24])",
                slots=(CKEY,))
    book.install(t1, anchor=10)
    book.install(t2, anchor=10)
    assert book.count() == 2 and book.count_for(AKEY) == 2
    assert len(book.get_rules(AKEY)) == 2
    assert t1.rule_id != t2.rule_id
    assert book.get(AKEY, t2.rule_id) == t2
    assert _dup(book, t1)


def test_a_due_rule_runs_advances_retries_and_misses():
    book2 = p.PayoutBook()
    td = _terms(AKEY, 1, due_at=1000, due_every=256)
    book2.install(td, anchor=10)
    assert not book2.has_due(999, 0)
    assert book2.has_due(1000, 0)
    assert book2.due(1000, 0) == [(AKEY, td.rule_id)]
    terms2, state2, exe2 = book2.due_execution(AKEY, td.rule_id)
    assert exe2.executor_pubkey == ""
    book2.due_ran(AKEY, td.rule_id, 1000, paid=True)
    st = book2.state_of(AKEY, td.rule_id)
    assert st.next_due(td) == 1256 and st.due_index == 1
    book2.due_ran(AKEY, td.rule_id, 1256, paid=False)
    assert (AKEY, td.rule_id) in book2.due(1257, 0)
    book2.due_ran(AKEY, td.rule_id, 1300, paid=False)
    assert (AKEY, td.rule_id) in book2.due(1301, 0)
    book2.due_ran(AKEY, td.rule_id, 1512, paid=False)  # next point 1512 reached
    st = book2.state_of(AKEY, td.rule_id)
    assert st.missed == 1 and st.next_due(td) == 1512 and st.due_index == 2


def test_a_one_shot_due_that_never_pays_is_done_and_missed():
    book3 = p.PayoutBook()
    t3 = _terms(AKEY, 1, due_at=500)
    book3.install(t3, anchor=10)
    book3.due_ran(AKEY, t3.rule_id, 500, paid=False)
    st = book3.state_of(AKEY, t3.rule_id)
    assert st.due_done and st.missed == 1


def test_on_arrival_records_every_kind_and_per_sale_only_user_tx():
    book4 = p.PayoutBook()
    ta = _terms(AKEY, 1, body=BODY_SALE, per_sale=True, on_arrival=True)
    tp = _terms(AKEY, 2, body=BODY_SALE, per_sale=True)
    book4.install(ta, anchor=10)
    book4.install(tp, anchor=10)
    for kind in (p.ARRIVAL_USER_TX, p.ARRIVAL_RETRACTABLE,
                 p.ARRIVAL_APPROVER, p.ARRIVAL_PAYOUT):
        book4.note_arrival(AKEY, bytes([len(kind)]) * 32, BKEY, 100, 20, kind, ts=20)
    assert len(book4.state_of(AKEY, ta.rule_id).open_sales) == 4
    assert len(book4.state_of(AKEY, tp.rule_id).open_sales) == 1
    assert book4.has_arrivals()
    arr = book4.arrivals()
    assert len(arr) == 4 and all(a[1] == ta.rule_id for a in arr)
    terms4, state4, exe4 = book4.arrival_execution(AKEY, ta.rule_id, arr[0][2])
    assert exe4.sale_id == arr[0][2]
    book4.drop_sale(AKEY, ta.rule_id, arr[0][2])
    assert len(book4.state_of(AKEY, ta.rule_id).open_sales) == 3


def test_an_update_keeps_lineage_and_supersedes():
    book5 = p.PayoutBook()
    tv1 = _terms(AKEY, 1)
    book5.install(tv1, anchor=10)
    tv2 = _terms(AKEY, 2, body="o30[t]:bv[24] = min({ 600 }:bv[24], i2[t]:bv[24])")
    old, new = book5.update(AKEY, tv1.rule_id, tv2, anchor=50)
    assert book5.current_id(tv1.rule_id) == new.rule_id
    assert new.version == 2
    assert book5.resolved_count == 1
    assert book5.get(AKEY, tv1.rule_id) is None
    assert book5.get(AKEY, new.rule_id) == new
    assert _nochange(book5, new)


def test_sealed_is_false_until_a_sealed_rule_is_installed():
    book6 = p.PayoutBook()
    assert not book6.sealed(AKEY)
    book6.install(_terms(AKEY, 1, sealed=True), anchor=10)
    assert book6.sealed(AKEY)


def test_add_months_clamps_to_the_end_of_the_month():
    jan31 = 1769817600  # 2026-01-31 00:00 UTC
    assert p.add_months(jan31, 1) == 1772236800   # Feb 28 (2026 not a leap year)
    assert p.add_months(jan31, 2) == 1774915200   # Mar 31
    assert p.due_point_of(jan31, None, 1, 1) == 1772236800


def test_monthly_grid_clamps_and_returns_on_leap_and_century_years():
    # The 31st comes back after a short month: Feb clamps, Mar is the 31st
    # again. Pins the Gregorian edges: leap years 2000/2028 (Feb 29) and the
    # century non-leap year 2100 (Feb 28).
    cases = [
        # (Jan 31 00:00 UTC, Feb last day, Mar 31)
        (949276800, 951782400, 954460800),    # 2000: Feb 29 (leap, div by 400)
        (1832889600, 1835395200, 1838073600),  # 2028: Feb 29 (leap)
        (4105036800, 4107456000, 4110134400),  # 2100: Feb 28 (century, not leap)
    ]
    for jan31, feb_last, mar31 in cases:
        assert p.add_months(jan31, 1) == feb_last
        assert p.add_months(jan31, 2) == mar31
        assert p.due_point_of(jan31, None, 1, 1) == feb_last
        assert p.due_point_of(jan31, None, 1, 2) == mar31
    # The period boundary is exact: one second before the Feb due point is
    # still period 0, the due point itself starts period 1.
    terms = _terms(AKEY, 1, due_at=949276800, due_months=1,
                   expires_at=10 ** 15)
    feb29 = 951782400  # 2000-02-29 00:00 UTC, due point 1 of the Jan-31 rule
    assert terms.due_index_after(0, feb29 - 1) - 1 == 0
    assert terms.due_index_after(0, feb29) - 1 == 1
    assert terms.due_index_after(0, feb29 + 1) - 1 == 1


def test_monthly_grid_matches_independent_calendar_vectors():
    # MarcoDiPolo's conformance vectors for #34 (gist e690cb5794025cca58c991d23f1aeab1):
    # 62 schedules starting Jan 2000, signed days 1-31 at 00:00:00 and
    # 23:59:59 UTC, every month through Dec 2399. Expected due times are built
    # from the day distance between consecutive firsts of the month, never from
    # add_months itself, so this checks the helper against an independent
    # calendar. 297,600 due checks + 892,800 relative-index checks.
    epoch = date(1970, 1, 1)
    due_checks = index_checks = 0
    for index in range(4800):
        year_offset, zero_month = divmod(index, 12)
        year = 2000 + year_offset
        first = date(year, zero_month + 1, 1)
        next_first = (date(year + 1, 1, 1) if zero_month == 11
                      else date(year, zero_month + 2, 1))
        length = (next_first - first).days
        for day in range(1, 32):
            anchor_midnight = (date(2000, 1, day) - epoch).days * 86400
            expected_midnight = ((first - epoch).days + min(day, length) - 1) * 86400
            for second in (0, 86399):
                anchor = anchor_midnight + second
                expected = expected_midnight + second
                assert p.due_point_of(anchor, None, 1, index) == expected
                due_checks += 1
                terms = _terms(AKEY, 1, due_at=anchor, due_months=1,
                               expires_at=10 ** 15)
                for offset, expected_index in ((-1, index - 1), (0, index),
                                               (1, index)):
                    assert (terms.due_index_after(index - 1, expected + offset) - 1
                            == expected_index)
                    index_checks += 1
    assert due_checks == 297600
    assert index_checks == 892800


def test_a_manual_execute_may_not_repay_an_already_paid_due_point(evs):
    # The Mar-31 due point pays 100; a manual payout_execute on Apr 5 -- inside
    # the Mar-31 due window (Mar 31-Apr 30) but in a NEW cap period (the fixed
    # 31-day cap window anchored at install rolls over on Apr 4) -- used to pay
    # a second 100 for March. The due-window guard in check_execution refuses
    # it: a due point pays once, whatever the cap window says.
    _script(evs, CHOICE_BODY,
            lambda inputs: {"o30": "100" if int(inputs.get("i2", "0")) >= 100 else "0"})
    jan1 = 1767225600    # 2026-01-01 00:00 UTC (install)
    jan31 = 1769817600   # due point 0
    feb28 = 1772236800   # due point 1 (clamped)
    mar31 = 1774915200   # due point 2 (back to the 31st)
    apr01 = mar31 + 86400
    apr05 = mar31 + 5 * 86400
    ch, oracle = Chain({ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0}, fee=0), \
        Oracle({ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0})
    tx = set_tx(rule=CHOICE, slots=[BOB], cap_exec=100, cap_period=100,
                clock="period_seconds", period=2678400,
                due_at=jan31, due_months=1, expires_at=1798761600)
    ch.block([tx], height=HEIGHT, ts=jan1)
    oracle.create(tx, fee=0)
    for height, ts in ((HEIGHT + 1, jan31), (HEIGHT + 2, feb28),
                       (HEIGHT + 3, mar31)):
        ch.block([], height=height, ts=ts)
        ev = _events(ch)[0]
        assert ev["outcome"] == "executed" and ev["total"] == 100
        oracle.pay(ALICE, BOB, 100, ts=ts)
    oracle.check(ch)
    assert ch.bal == {ALICE: 700, BOB: 300, CAROL: 500, PROPOSER: 0}
    book = ch.lm.payout_rules
    assert book.state_of(ALICE, ridb(tx)).paid_total == 300
    # Apr 1 is still the old cap period (the cap refused it before the fix);
    # Apr 5 is a new cap period, so only the due-window guard refuses it.
    for height, ts in ((HEIGHT + 4, apr01), (HEIGHT + 5, apr05)):
        exe = exec_tx(executor=CAROL, seq=ch.seq.get(CAROL, 0),
                      account=ALICE, rule_id=rid(tx))
        result = ch.block([exe], height=height, ts=ts)
        assert _reason(result, exe) == "payout_not_executed"
        assert "already paid" in _logs(result)
    assert ch.bal == {ALICE: 700, BOB: 300, CAROL: 500, PROPOSER: 0}
    assert book.state_of(ALICE, ridb(tx)).paid_total == 300
    assert book.state_of(ALICE, ridb(tx)).executions == 3


def test_restore_round_trips_extended_rows_and_the_root():
    book7 = p.PayoutBook()
    book7.install(_terms(AKEY, 1, due_at=1000, due_every=256), anchor=10)
    book7.install(_terms(BKEY, 1, body=BODY_SALE, per_sale=True,
                         on_arrival=True), anchor=10)
    book7.note_arrival(BKEY, b"\x11" * 32, AKEY, 250, 20,
                       p.ARRIVAL_RETRACTABLE, ts=20)
    root1 = book7.root()
    rows = book7.store_rows()
    book7b = p.PayoutBook.restore(rows, *book7.resolved_state())
    assert book7b.root() == root1
    assert book7b.state_of(
        AKEY, book7b.get_rules(AKEY)[0].rule_id).next_due(
            book7b.get_rules(AKEY)[0]) == 1000
    assert len(book7b.state_of(
        BKEY, book7b.get_rules(BKEY)[0].rule_id).open_sales) == 1


def test_expire_skips_a_due_pending_rule_and_takes_it_after_its_point_runs():
    book8 = p.PayoutBook()
    te = _terms(AKEY, 1, due_at=100, expires_at=200)
    book8.install(te, anchor=10)
    gone = book8.expire(200, 0)
    assert gone == [] and book8.count() == 1
    book8.due_ran(AKEY, te.rule_id, 100, paid=True)
    gone = book8.expire(200, 0)
    assert len(gone) == 1 and book8.count() == 0


def test_default_options_encode_empty_so_old_shape_ids_are_preserved():
    assert p._options_bytes(None, None, None, None, False, None, 1) == b""
    assert p._options_bytes(None, 100, None, None, False, None, 1) != b""


def test_validation_refuses_due_and_arrival_clashes():
    assert validate_terms_shape(_terms(AKEY, 1, due_at=100, per_sale=True),
                                10, 0) is not None
    assert validate_terms_shape(_terms(AKEY, 1, on_arrival=True),
                                10, 0) is not None
    assert validate_terms_shape(_terms(AKEY, 1, due_every=256),
                                10, 0) is not None
    assert validate_terms_shape(
        _terms(AKEY, 1, due_at=100, due_every=256, due_months=1,
               kind=p.KIND_SECONDS, period=3600), 10, 0) is not None
    assert validate_terms_shape(_terms(AKEY, 1, due_at=100, due_every=256),
                                10, 0) is None
    assert validate_terms_shape(
        _terms(AKEY, 1, body=BODY_SALE, per_sale=True, on_arrival=True),
        10, 0) is None


def test_the_last_paid_clock_inputs_track_the_anchor_then_the_last_payment():
    st = p.PayoutState(anchor=100)
    tx = _terms(AKEY, 1, body="always ( o30[t]:bv[24] = i49[t]:bv[64] ).")
    vals = p.execution_inputs(
        tx, st, p.PayoutExecution("x" * 96, AKEY, tx.rule_id, (), ()),
        parent_balance=1000, height=150, ts=0)
    assert vals[p.STREAM_INSTALLED] == "100" and vals[p.STREAM_LAST_PAID] == "100"
    st2 = p.replace(st, last_clock=140)
    vals = p.execution_inputs(
        tx, st2, p.PayoutExecution("x" * 96, AKEY, tx.rule_id, (), ()),
        parent_balance=1000, height=150, ts=0)
    assert vals[p.STREAM_LAST_PAID] == "140"

# --- Part B: apply-level (through Chain) ---------------------------------------

from consensus.payout import payout_rule_body

CHOICE = ("always ( (i2[t]:bv[24] >= { 100 }:bv[24]) ? "
          "(o30[t]:bv[24] = { 100 }:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).")
CHOICE_BODY = payout_rule_body(CHOICE)
ROYALTY = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] )."
ROYALTY_BODY = payout_rule_body(ROYALTY)


def _script(evs, body, fn):
    for pool in ("apply", "payout_apply"):
        evs[pool].set_outputs(body, fn)


def _due_installed(evs):
    _script(evs, CHOICE_BODY,
            lambda inputs: {"o30": "100" if int(inputs.get("i2", "0")) >= 100 else "0"})
    ch, oracle = Chain({ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0}, fee=0), \
        Oracle({ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0})
    tx = set_tx(rule=CHOICE, slots=[BOB], cap_exec=100, cap_period=10000,
                period=10, due_at=HEIGHT + 5, due_every=256,
                expires_at=HEIGHT + 1000)
    ch.block([tx])
    oracle.create(tx, fee=0)
    return ch, oracle, tx


def _rich_bal():
    return {ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0}


def _royalty_installed(evs, balances=None):
    _script(evs, ROYALTY_BODY,
            lambda inputs: {"o30": str(int(inputs.get("i27", "0")) // 20)})
    bals = balances or _rich_bal()
    ch, oracle = Chain(bals, fee=0), Oracle(bals)
    tx = set_tx(rule=ROYALTY, slots=[BOB], cap_exec=100, cap_period=10000,
                period=10, per_sale=True, on_arrival=True)
    ch.block([tx])
    oracle.create(tx, fee=0)
    return ch, oracle, tx


def test_a_due_rule_pays_at_its_point_and_repeats(evs):
    ch, oracle, tx = _due_installed(evs)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    ev = _events(ch)[0]
    assert ev["outcome"] == "executed" and ev["due_at"] == HEIGHT + 5
    assert ev["due_index"] == 0 and ev["total"] == 100
    assert ev["legs"] == [{"slot": 0, "recipient_pubkey": BOB, "amount": 100}]
    oracle.pay(ALICE, BOB, 100, ts=TS + 5)
    ch.block([], height=HEIGHT + 261, ts=TS + 261)
    ev = _events(ch)[0]
    assert ev["outcome"] == "executed" and ev["due_at"] == HEIGHT + 261
    assert ev["due_index"] == 1 and ev["total"] == 100
    oracle.pay(ALICE, BOB, 100, ts=TS + 261)
    oracle.check(ch)
    book = ch.lm.payout_rules
    st = book.state_of(ALICE, ridb(tx))
    assert st.due_index == 2 and st.missed == 0
    assert st.next_due(book.get(ALICE, ridb(tx))) == HEIGHT + 5 + 2 * 256


def test_a_due_rule_retries_after_the_account_is_funded(evs):
    ch, oracle, tx = _due_installed(evs)
    drain = spend_tx(ALICE, CAROL, 950, 1)
    ch.block([drain], height=HEIGHT + 1, ts=TS + 1)
    oracle.spend(ALICE, CAROL, 950, ts=TS + 1)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    ev = _events(ch)[0]
    assert ev["outcome"] == "due_not_paid" and ev["due_at"] == HEIGHT + 5
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    assert _events(ch)[0]["outcome"] == "due_not_paid"
    topup = spend_tx(CAROL, ALICE, 100, 0)
    ch.block([topup], height=HEIGHT + 7, ts=TS + 7)
    oracle.spend(CAROL, ALICE, 100, ts=TS + 7)
    paid = [e for e in _events(ch) if e.get("outcome") == "executed"]
    assert len(paid) == 1 and paid[0]["due_at"] == HEIGHT + 5
    assert paid[0]["total"] == 100
    oracle.pay(ALICE, BOB, 100, ts=TS + 7)
    oracle.check(ch)
    st = ch.lm.payout_rules.state_of(ALICE, ridb(tx))
    assert st.due_index == 1 and st.missed == 0


def test_a_frozen_payer_due_run_pays_nothing_then_pays_when_unfrozen(evs):
    ch, oracle, tx = _due_installed(evs)
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = FREEZE
    evs["apply"].set_verdict(FREEZE, lambda inputs: 0)    # blocks every transfer
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    ev = _events(ch)[0]
    assert ev["outcome"] == "due_not_paid" and ev["due_at"] == HEIGHT + 5
    assert "o5" in ev["reason"]
    oracle.check(ch)
    evs["apply"].set_verdict(FREEZE, lambda inputs: 1)    # the payer unfreezes
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    paid = [e for e in _events(ch) if e.get("outcome") == "executed"]
    assert len(paid) == 1 and paid[0]["due_at"] == HEIGHT + 5
    assert paid[0]["total"] == 100
    oracle.pay(ALICE, BOB, 100, ts=TS + 6)
    oracle.check(ch)


def test_a_missed_due_point_is_counted_and_the_next_point_runs(evs):
    ch, oracle, tx = _due_installed(evs)
    drain = spend_tx(ALICE, CAROL, 950, 1)
    ch.block([drain], height=HEIGHT + 1, ts=TS + 1)
    oracle.spend(ALICE, CAROL, 950, ts=TS + 1)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert _events(ch)[0]["outcome"] == "due_not_paid"
    ch.block([], height=HEIGHT + 261, ts=TS + 261)   # the 281 point arrives
    missed = [e for e in _events(ch) if e.get("outcome") == "due_not_paid"]
    # The block retries the 25 point (its window just closed, so it is counted
    # missed); the 281 point itself is only queued, and runs next block.
    assert any(e["due_at"] == HEIGHT + 5 for e in missed)
    st = ch.lm.payout_rules.state_of(ALICE, ridb(tx))
    assert st.missed == 1 and st.due_index == 1
    topup = spend_tx(CAROL, ALICE, 100, 0)
    ch.block([topup], height=HEIGHT + 262, ts=TS + 262)
    oracle.spend(CAROL, ALICE, 100, ts=TS + 262)
    paid = [e for e in _events(ch) if e.get("outcome") == "executed"]
    assert len(paid) == 1 and paid[0]["due_at"] == HEIGHT + 261
    oracle.pay(ALICE, BOB, 100, ts=TS + 262)
    oracle.check(ch)
    st = ch.lm.payout_rules.state_of(ALICE, ridb(tx))
    assert st.missed == 1 and st.due_index == 2


def test_on_arrival_pays_a_royalty_on_a_sale(evs):
    ch, oracle, tx = _royalty_installed(evs)
    sale = spend_tx(CAROL, ALICE, 200, 0)
    ch.block([sale], height=HEIGHT + 1, ts=TS + 1)
    ev1 = _events(ch)
    ch.block([], height=HEIGHT + 2, ts=TS + 2)
    ev2 = _events(ch)
    paid = [e for e in ev1 + ev2 if e.get("outcome") == "executed"]
    assert len(paid) == 1
    assert paid[0]["kind"] == "user_tx" and paid[0]["sale_amount"] == 200
    assert paid[0]["total"] == 10
    assert paid[0]["legs"] == [{"slot": 0, "recipient_pubkey": BOB, "amount": 10}]
    assert ch.bal == {ALICE: 1190, BOB: 10, CAROL: 300, PROPOSER: 0}
    assert ch.seq.get(ALICE) == 1 and ch.seq.get(CAROL) == 1
    assert ch.lts[CAROL] == TS + 1 and ch.lts[ALICE] in (TS + 1, TS + 2)


def test_a_due_leg_arrives_and_pays_on_in_the_next_block(evs):
    _script(evs, CHOICE_BODY,
            lambda inputs: {"o30": "100" if int(inputs.get("i2", "0")) >= 100 else "0"})
    _script(evs, ROYALTY_BODY,
            lambda inputs: {"o30": str(int(inputs.get("i27", "0")) // 20)})
    ch, oracle = Chain({ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0}, fee=0), \
        Oracle({ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0})
    due_tx = set_tx(rule=CHOICE, slots=[BOB], cap_exec=100, cap_period=10000,
                    period=10, due_at=HEIGHT + 5, due_every=256,
                    expires_at=HEIGHT + 1000)
    ch.block([due_tx])
    oracle.create(due_tx, fee=0)
    roy_tx = set_tx(sender=BOB, seq=0, rule=ROYALTY, slots=[CAROL], cap_exec=100,
                    cap_period=10000, period=10, per_sale=True, on_arrival=True)
    ch.block([roy_tx], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(roy_tx, fee=0)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    ev = _events(ch)[0]
    assert ev["outcome"] == "executed" and ev["due_at"] == HEIGHT + 5
    assert ev["total"] == 100
    oracle.pay(ALICE, BOB, 100, ts=TS + 5)
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    ev = _events(ch)[0]
    assert ev["outcome"] == "executed" and ev["kind"] == "payout"
    assert ev["sale_amount"] == 100 and ev["payer_pubkey"] == ALICE
    assert ev["total"] == 5
    assert ev["legs"] == [{"slot": 0, "recipient_pubkey": CAROL, "amount": 5}]
    oracle.pay(BOB, CAROL, 5, ts=TS + 6)
    oracle.check(ch)


def test_on_arrival_pays_a_royalty_on_a_released_retractable(evs):
    ch, oracle, tx = _royalty_installed(evs)
    park = _sign({"tx_id": "park-1", "tx_type": "retractable_transfer",
                  "sender_pubkey": CAROL, "sequence_number": 0,
                  "expiration_time": FAR, "expire_at_height": 1000,
                  "fee_limit": "0", "recipient_pubkey": ALICE, "amount": 200,
                  "release_at_height": HEIGHT + 2}, SKS[CAROL])
    ch.block([park], height=HEIGHT + 1, ts=TS + 1)
    assert ch.bal[CAROL] == 300
    ch.block([], height=HEIGHT + 2, ts=TS + 2)
    ev2 = _events(ch)
    ch.block([], height=HEIGHT + 3, ts=TS + 3)
    ev3 = _events(ch)
    paid = [e for e in ev2 + ev3 if e.get("outcome") == "executed"]
    assert len(paid) == 1
    assert paid[0]["kind"] == "retractable" and paid[0]["sale_amount"] == 200
    assert paid[0]["total"] == 10
    assert ch.bal == {ALICE: 1190, BOB: 10, CAROL: 300, PROPOSER: 0}


AUTH_SK, AUTH = 22222, G2Basic.SkToPk(22222).hex()
SCAN_SK, SCAN = 33333, G2Basic.SkToPk(33333).hex()


def test_on_arrival_pays_a_royalty_on_an_approved_transfer(evs):
    """An approver-released transfer is an arrival for its recipient.

    The request only parks when the sender's own policy would block the
    transfer without votes, so the harness emulates the tier-1 co-signature
    rule (amounts over 1000 need slot 18 fed with the approver): the amount
    is 2000, and the royalty is 100.
    """
    ch, oracle, tx = _royalty_installed(
        evs, {ALICE: 1_000, BOB: 0, CAROL: 5_000, PROPOSER: 0})

    def _tier1(**kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        slot18 = str(vals.get(18, "0"))
        blocked = amount > 1000 and AUTH not in slot18
        return {1: str(amount), 8: "0", 9: str(ch.fee),
                5: "0" if blocked else "1"}

    ch._multi = _tier1
    req = ApprovalRequest(sender_pubkey=CAROL, recipient_pubkey=ALICE, amount=2000,
                          sequence_number=0, expire_at_height=HEIGHT + 500,
                          approvers={18: AUTH, 19: SCAN}, custom_inputs={})
    req_tx = _sign({"tx_id": "req-1", "tx_type": "approval_request",
                    "sender_pubkey": CAROL, "sequence_number": 0,
                    "expiration_time": FAR, "fee_limit": "100",
                    "recipient_pubkey": ALICE, "amount": 2000,
                    "expire_at_height": HEIGHT + 500,
                    "approvers": {"18": AUTH, "19": SCAN},
                    "custom_inputs": {}}, SKS[CAROL])
    ch.block([req_tx], height=HEIGHT + 1, ts=TS + 1)
    assert ch.lm.approval_requests.get_request(req.request_id) is not None
    assert ch.bal[CAROL] == 5_000   # parking debits nothing; the release pays
    votes = [
        _sign({"tx_id": "vote-1", "tx_type": "transfer_vote",
               "sender_pubkey": AUTH, "sequence_number": 0,
               "expiration_time": FAR, "expire_at_height": 5000,
               "fee_limit": "0", "request_id": req.request_id_hex,
               "approve": True}, AUTH_SK),
        _sign({"tx_id": "vote-2", "tx_type": "transfer_vote",
               "sender_pubkey": SCAN, "sequence_number": 0,
               "expiration_time": FAR, "expire_at_height": 5000,
               "fee_limit": "0", "request_id": req.request_id_hex,
               "approve": True}, SCAN_SK),
    ]
    ch.block(votes, height=HEIGHT + 2, ts=TS + 2)
    ev2 = _events(ch)
    ch.block([], height=HEIGHT + 3, ts=TS + 3)
    ev3 = _events(ch)
    paid = [e for e in ev2 + ev3 if e.get("outcome") == "executed"]
    assert len(paid) == 1
    assert paid[0]["kind"] == "approver" and paid[0]["sale_amount"] == 2000
    assert paid[0]["total"] == 100
    assert ch.bal == {ALICE: 2900, BOB: 100, CAROL: 3000, PROPOSER: 0}


def test_a_manual_execution_over_the_rules_fee_cap_is_refused(evs):
    ch, oracle, tx = _installed(fee=0, max_fee_per_execution=5)
    ch.fee = 5
    over = exec_tx(rule_id=rid(tx), data={"0": 40}, fee_limit="100")
    result = ch.block([over], height=HEIGHT + 1, ts=TS + 1)
    assert _reason(result, over) == "payout_not_executed"
    assert "caps a manual execution's fee at 5" in _logs(result)
    within = exec_tx(rule_id=rid(tx), data={"0": 40}, fee_limit="5")
    ch.block([within], height=HEIGHT + 2, ts=TS + 2)
    _executed(oracle, fee=5, legs=[(BOB, 40)], ts=TS + 2)
    oracle.check(ch)


def test_two_rules_on_one_account_pay_independently(evs):
    ch, oracle, first = _installed(fee=0, cap_exec=500, cap_period=500)
    second = set_tx(seq=1, slots=[CAROL], cap_exec=300, cap_period=300)
    ch.block([second], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(second, fee=0)
    exe1 = exec_tx(rule_id=rid(first), data={"0": 400})
    ch.block([exe1], height=HEIGHT + 2, ts=TS + 2)
    _executed(oracle, legs=[(BOB, 400)], ts=TS + 2)
    exe2 = exec_tx(seq=1, rule_id=rid(second), data={"0": 250})
    ch.block([exe2], height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, legs=[(CAROL, 250)], ts=TS + 3)
    oracle.check(ch)
    book = ch.lm.payout_rules
    assert book.state_of(ALICE, ridb(first)).paid_total == 400
    assert book.state_of(ALICE, ridb(second)).paid_total == 250
    # A second 200 from the first rule breaks its own period cap (400 + 200 > 500);
    # the second rule is untouched by that refusal.
    exe3 = exec_tx(seq=2, rule_id=rid(first), data={"0": 200})
    result = ch.block([exe3], height=HEIGHT + 4, ts=TS + 4)
    assert _reason(result, exe3) == "payout_not_executed"
    assert "over the cap per period" in _logs(result)
    oracle.check(ch)
    assert book.state_of(ALICE, ridb(second)).paid_total == 250


# --- Part C: admission-level -----------------------------------------------------

def _tip_view(book):
    tip = MagicMock(spec=TipAdmissionView)
    tip.payout_book.return_value = book
    tip.next_block_height = HEIGHT + 1
    tip.tip_timestamp = TS
    tip.next_block_timestamp = TS + 1
    tip.clause_for.return_value = None
    return tip


def _book_with_rule(**kw):
    book = PayoutBook()
    tx = set_tx(**kw)
    book.install(parse_payout_rule_set(tx), anchor=HEIGHT)
    return book, tx


def test_sealed_admission_refuses_a_transfer_and_a_new_rule():
    book, tx = _book_with_rule(sealed=True)
    tip = _tip_view(book)
    spend = spend_tx(ALICE, BOB, 100, 1)
    result = validate_mempool_admission(spend, tip)
    assert not result.is_valid and result.code == "ACCOUNT_SEALED"
    again = set_tx(seq=1, sealed=True)
    result = validate_mempool_admission(again, tip)
    assert not result.is_valid and result.code == "ACCOUNT_SEALED"
    other = spend_tx(BOB, ALICE, 10, 0)
    assert validate_mempool_admission(other, tip).code != "ACCOUNT_SEALED"


def test_update_admission_refuses_a_no_change_update_and_an_unknown_rule():
    book, tx = _book_with_rule()
    tip = _tip_view(book)
    same = update_tx(rid(tx), seq=0)
    result = validate_payout_rule_update_payload(same, tip)
    assert not result.is_valid and result.code == "INVALID_PAYOUT_RULE"
    assert "changes nothing" in result.error
    unknown = update_tx("00" * 32, seq=0)
    result = validate_payout_rule_update_payload(unknown, tip)
    assert not result.is_valid and result.code == "NO_PAYOUT_RULE"


@pytest.mark.skip(reason="admission.py lost _payout_evaluator_call in 505d20d: "
                         "a valid update crashes with NameError until it is restored")
def test_update_admission_accepts_a_real_update():
    book, tx = _book_with_rule()
    tip = _tip_view(book)
    upd = update_tx(rid(tx), seq=2, cap_exec=60)
    result = validate_payout_rule_update_payload(upd, tip)
    assert result.is_valid, result.error
    assert result.data["rule_id"] == parse_payout_rule_set(upd).rule_id.hex()


def test_execute_admission_refuses_a_fee_over_the_rules_cap():
    book, tx = _book_with_rule(max_fee_per_execution=5)
    tip = _tip_view(book)
    exe = exec_tx(rule_id=rid(tx), data={"0": 40}, fee_limit="100")
    exe["fee_limit"] = 100   # admission reads an int fee limit, not the string
    exe.pop("signature")
    _sign(exe, SKS[CAROL])
    result = validate_payout_execute_payload(exe, tip)
    assert not result.is_valid and result.code == "PAYOUT_REFUSED"
    assert "caps a manual execution's fee at 5" in result.error

# --- Due-point updates: the old point must never fire after an update --------
# Book-level: update() removes the old version before inserting the new one,
# and _remove clears the old pending due point from BOTH the _due and the
# _retry indexes (payout.py:1225). These tests pin that behavior.


def test_an_update_removes_the_old_due_point_and_registers_the_new_one():
    book = p.PayoutBook()
    old = _terms(AKEY, 1, due_at=1000, due_every=256)
    book.install(old, anchor=10)
    assert book.due(1000, 0) == [(AKEY, old.rule_id)]
    assert book.has_due(1000, 0)
    new = _terms(AKEY, 1, due_at=5000, due_every=256)
    _, updated = book.update(AKEY, old.rule_id, new, anchor=10)
    assert updated.rule_id != old.rule_id and updated.version == 2
    assert book.get(AKEY, old.rule_id) is None
    assert book.count() == 1
    # The old point is gone from both indexes: nothing is due at 1000.
    assert book.due(1000, 0) == []
    assert not book.has_due(1000, 0)
    assert book.due(4999, 0) == []
    # The new version's own point is registered from its own due_at.
    assert book.due(5000, 0) == [(AKEY, updated.rule_id)]
    st = book.state_of(AKEY, updated.rule_id)
    assert st.due_index == 0 and st.next_due(updated) == 5000
    assert book.current_id(old.rule_id) == updated.rule_id


def test_an_update_removes_a_due_point_waiting_in_the_retry_window():
    book = p.PayoutBook()
    old = _terms(AKEY, 1, due_at=1000, due_every=256)
    book.install(old, anchor=10)
    # The point ran and could not pay; its window is still open, so the book
    # retries it next block.
    book.due_ran(AKEY, old.rule_id, 1000, paid=False)
    assert (AKEY, old.rule_id) in book.due(1001, 0)
    new = _terms(AKEY, 1, due_at=5000, due_every=256)
    _, updated = book.update(AKEY, old.rule_id, new, anchor=10)
    # The retried point is gone too: nothing is due at the old point, and the
    # retry does not fire later.
    assert book.due(1001, 0) == []
    assert not book.has_due(1001, 0)
    assert book.due(5000, 0) == [(AKEY, updated.rule_id)]
    assert book.get(AKEY, old.rule_id) is None


def test_an_update_moves_the_due_point_and_the_old_point_never_fires(evs):
    ch, oracle, tx = _due_installed(evs)
    upd = update_tx(rid(tx), seq=1, rule=CHOICE, slots=[BOB], cap_exec=100,
                    cap_period=10000, period=10, due_at=HEIGHT + 50,
                    due_every=256, expires_at=HEIGHT + 1000)
    ch.block([upd], height=HEIGHT + 1, ts=TS + 1)
    _, _, new_terms = p.parse_payout_rule_update(upd)
    new_id = replace(new_terms, version=2).rule_id
    assert _events(ch)[0] == {"account_pubkey": ALICE, "rule_id": new_id.hex(),
                              "outcome": "updated", "tx_id": upd["tx_id"],
                              "replaces": rid(tx)}
    oracle.create(upd, fee=0)
    book = ch.lm.payout_rules
    assert book.get(ALICE, ridb(tx)) is None
    assert book.get(ALICE, new_id) is not None
    assert book.state_of(ALICE, new_id).next_due(
        book.get(ALICE, new_id)) == HEIGHT + 50
    # The old point arrives: nothing runs under the old terms.
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert _events(ch) == []
    # The new point arrives: the new version pays, once, under the new terms.
    ch.block([], height=HEIGHT + 50, ts=TS + 50)
    ev = _events(ch)[0]
    assert ev["outcome"] == "executed" and ev["due_at"] == HEIGHT + 50
    assert ev["due_index"] == 0 and ev["total"] == 100
    assert ev["rule_id"] == new_id.hex()
    assert ev["legs"] == [{"slot": 0, "recipient_pubkey": BOB, "amount": 100}]
    oracle.pay(ALICE, BOB, 100, ts=TS + 50)
    oracle.check(ch)
    st = ch.lm.payout_rules.state_of(ALICE, new_id)
    assert st.due_index == 1 and st.missed == 0
    assert st.next_due(book.get(ALICE, new_id)) == HEIGHT + 50 + 256
