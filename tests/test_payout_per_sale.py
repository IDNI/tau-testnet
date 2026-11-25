"""Payout per-sale rules: stage 3 (Bounty 01, #34/#35, axis 10).

A rule installed with `per_sale` settles only against sales the
chain recorded. The book-level halves pin the sale bookkeeping --
recording, the age bound, the ledger marker, update carry-over --
and the apply-level halves run the engine with the stage-1
harness's scripted evaluator: a credit records a sale, an
execution names it and pays from the RECORDED amount (never the
executor's claimed gross), a paid sale cannot be paid twice, and
a rule that is also `on_arrival` has its sale closed by the
node's own settlement.
"""

import itertools

import pytest
from py_ecc.bls import G2Basic

from consensus import periods
from consensus.payouts import (
    MAX_OPEN_SALES,
    PAYOUT_STREAM_INDEX,
    PayoutBook,
    PayoutShapeError,
    PayoutTerms,
    Sale,
    parse_payout_execute,
    parse_payout_install,
    sale_settlement_id,
    validate_payout_shape,
)

from test_payout_triggers import (
    Chain,
    FAR,
    JAN1,
    NOW,
    _key,
    _pct,
    _sign,
    install_tx,
    transfer_tx,
)

SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_DAVE, DAVE = _key(77777)
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()


def _terms(**kw):
    base = dict(
        owner=ALICE, max_per_execution=1000, max_per_period=1500,
        recipients=(BOB, CAROL), period_kind=periods.PERIOD_WEEK,
        anchor_ts=JAN1, sequence_number=1,
    )
    base.update(kw)
    return PayoutTerms(**base)


def execute_tx(owner=BOB, executor=CAROL, sk=SK_CAROL, seq=0,
               settlement_id="s1", gross=0, rule_id=None, sale_id=None):
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
    if sale_id is not None:
        tx["sale_id"] = sale_id
    return _sign(tx, sk)


def _install(ch, owner, sk, *, height, ts=NOW, seq=0, **kw):
    ch.lm.rule_offers.accepted_clauses[(owner, PAYOUT_STREAM_INDEX)] = (
        "always (o20[t] = 1)."
    )
    tx = install_tx(owner=owner, sk=sk, seq=seq, **kw)
    ch.block([tx], height=height, ts=ts)
    assert ch.accepted(tx), ch.receipt(tx)
    terms = parse_payout_install(tx)
    assert ch.book.get_rule(owner, terms.rule_id) is not None
    return terms


# --- book level: terms, identity, shape ---------------------------------------


def test_per_sale_terms_extend_the_rule_id_and_legacy_is_unchanged():
    plain = _terms()
    sale = _terms(per_sale=True)
    assert sale.rule_id != plain.rule_id
    # A rule that does not declare the flag recomputes the very id
    # it had before stage 3 existed.
    assert _terms().rule_id == plain.rule_id
    assert _terms(per_sale=False).rule_id == plain.rule_id


def test_a_per_sale_rule_cannot_carry_the_clock_trigger():
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(
            _terms(per_sale=True, due=True, max_fires=3), now_ts=NOW)
    # The same terms without the clock trigger are well-formed.
    validate_payout_shape(_terms(per_sale=True), now_ts=NOW)
    validate_payout_shape(
        _terms(per_sale=True, on_arrival=True), now_ts=NOW)


def test_parse_install_and_execute_carry_the_sale_fields():
    tx = install_tx(owner=ALICE, sk=SK_ALICE, extra={"per_sale": True})
    terms = parse_payout_install(tx)
    assert terms.per_sale is True
    owner, sid, gross, rule_id, sale_id = parse_payout_execute(
        {"owner": ALICE, "settlement_id": "s1", "gross": 5,
         "sale_id": "credit-9"})
    assert (owner, sid, gross, rule_id, sale_id) == (
        ALICE, "s1", 5, None, "credit-9")
    with pytest.raises(PayoutShapeError):
        parse_payout_execute(
            {"owner": ALICE, "settlement_id": "s1", "sale_id": ""})
    with pytest.raises(PayoutShapeError):
        parse_payout_execute(
            {"owner": ALICE, "settlement_id": "s1", "sale_id": 7})


# --- book level: recording, bound, settling ------------------------------------


def test_recording_bound_evicts_the_oldest_and_counts_it_missed():
    book = PayoutBook()
    terms = _terms(per_sale=True)
    state = book.install(terms)
    for n in range(MAX_OPEN_SALES + 1):
        book.note_sale(
            ALICE, Sale(f"tx-{n}", BOB, 10 + n, 20 + n),
            rule_id=terms.rule_id)
    assert len(state.sales) == MAX_OPEN_SALES
    assert state.sales[0].sale_id == "tx-1"
    assert state.sales_missed == 1
    # A sale id is a transaction id: the same credit never records
    # twice, and re-recording it evicts nothing.
    book.note_sale(ALICE, Sale("tx-1", BOB, 11, 21), rule_id=terms.rule_id)
    assert len(state.sales) == MAX_OPEN_SALES
    assert state.sales_missed == 1


def test_settling_a_sale_marks_the_ledger_and_closes_it():
    book = PayoutBook()
    terms = _terms(per_sale=True)
    state = book.install(terms)
    book.note_sale(ALICE, Sale("tx-1", BOB, 101, 20), rule_id=terms.rule_id)
    total = book.check_execution(
        ALICE, "royalty-1", [(BOB, 5)], ts=JAN1,
        rule_id=terms.rule_id, sale_id="tx-1")
    book.settle(ALICE, "royalty-1", total, ts=JAN1,
                rule_id=terms.rule_id, sale_id="tx-1")
    assert state.sales == []
    marker = sale_settlement_id(terms.rule_id, "tx-1")
    assert state.settlements == ["royalty-1", marker]
    assert state.sale_already_settled("tx-1")
    # The marker carries no spend of its own.
    assert state.spent_in_period == 5
    assert state.executions == 1
    # A second check against the paid sale is refused: not open.
    with pytest.raises(PayoutShapeError):
        book.check_execution(
            ALICE, "royalty-2", [(BOB, 5)], ts=JAN1,
            rule_id=terms.rule_id, sale_id="tx-1")


def test_sales_survive_snapshot_restore_and_update():
    book = PayoutBook()
    terms = _terms(per_sale=True)
    book.install(terms)
    book.note_sale(ALICE, Sale("tx-1", BOB, 101, 20), rule_id=terms.rule_id)
    book.note_sale(ALICE, Sale("tx-2", CAROL, 50, 21), rule_id=terms.rule_id)
    restored = PayoutBook.restore(book.snapshot_rows())
    state = restored.get_rule(ALICE, terms.rule_id)
    assert [s.sale_id for s in state.sales] == ["tx-1", "tx-2"]
    assert restored.root() == book.root()

    new_terms = _terms(per_sale=True, max_per_execution=900,
                       sequence_number=2)
    updated = book.update(ALICE, terms.rule_id, new_terms, ts=JAN1)
    assert [s.sale_id for s in updated.sales] == ["tx-1", "tx-2"]
    assert updated.sales_missed == 0
    # And the carried-over sales still settle under the new version.
    total = book.check_execution(
        ALICE, "after-update", [(BOB, 5)], ts=JAN1,
        rule_id=new_terms.rule_id, sale_id="tx-2")
    book.settle(ALICE, "after-update", total, ts=JAN1,
                rule_id=new_terms.rule_id, sale_id="tx-2")
    assert updated.open_sale("tx-2") is None


# --- apply level: recording -----------------------------------------------------


def _balances(**kw):
    base = {ALICE: 100_000, BOB: 0, CAROL: 100_000, DAVE: 0,
            PROPOSER: 0}
    base.update(kw)
    return base


def test_a_credit_records_a_sale_with_payer_amount_and_height():
    ch = Chain(_balances())
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     extra={"per_sale": True})
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    state = ch.book.get_rule(BOB, terms.rule_id)
    assert state.sales == [
        Sale(sale_id=tx["tx_id"], payer=ALICE, amount=101, height=21)]
    # Nothing settled: a per-sale rule without on_arrival waits to
    # be executed.
    assert ch.bal[BOB] == 101
    assert ch.bal[CAROL] == 100_000
    assert state.settlements == []


def test_a_credit_from_the_account_itself_is_no_sale():
    # The transfer layer itself refuses a leg whose recipient is
    # its sender, so a self-credit can never reach the recording
    # step at all; the recording step additionally skips any
    # credit whose transaction sender is the credited account
    # (defence in depth). Pin the observable half: the refusal,
    # and no sale on the book.
    ch = Chain(_balances(BOB=500))
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     extra={"per_sale": True})
    tx = transfer_tx(BOB, 50, SK_BOB, sender=BOB, seq=1)
    ch.block([tx], height=21, ts=NOW)
    assert not ch.accepted(tx)
    assert ch.receipt(tx)["reason"] == "invalid_transfer"
    assert ch.book.get_rule(BOB, terms.rule_id).sales == []


def test_a_routed_share_is_no_sale():
    # BOB routes 20% of his credits to CAROL; CAROL holds a
    # per-sale rule. The 20 that lands on CAROL is a payout leg --
    # payout-class -- so CAROL's rule records no sale from it. A
    # direct credit to CAROL records one, proving the guard is the
    # credit's class.
    ch = Chain(_balances())
    _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
             extra={"on_arrival": True})
    carol_terms = _install(ch, CAROL, SK_CAROL, height=20,
                           recipients=[DAVE], extra={"per_sale": True})
    ch.legs_fn = _pct(20)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 100_000 + 20
    assert ch.book.get_rule(CAROL, carol_terms.rule_id).sales == []

    direct = transfer_tx(CAROL, 40, SK_ALICE, sender=ALICE, seq=1)
    ch.block([direct], height=22, ts=NOW)
    sales = ch.book.get_rule(CAROL, carol_terms.rule_id).sales
    assert [s.sale_id for s in sales] == [direct["tx_id"]]
    assert sales[0].amount == 40


def test_every_per_sale_rule_of_the_account_records_the_sale():
    ch = Chain(_balances())
    one = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                   extra={"per_sale": True})
    two = _install(ch, BOB, SK_BOB, height=21, seq=1,
                   recipients=[DAVE], sequence_number=2,
                   extra={"per_sale": True})
    tx = transfer_tx(BOB, 70, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=22, ts=NOW)
    for terms in (one, two):
        sales = ch.book.get_rule(BOB, terms.rule_id).sales
        assert [s.sale_id for s in sales] == [tx["tx_id"]]


def test_apply_level_bound_evicts_the_oldest_sale():
    ch = Chain(_balances())
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     extra={"per_sale": True})
    first = None
    for n in range(MAX_OPEN_SALES + 1):
        tx = transfer_tx(BOB, 10, SK_CAROL, sender=CAROL, seq=n)
        if first is None:
            first = tx["tx_id"]
        ch.block([tx], height=21 + n, ts=NOW)
        assert ch.accepted(tx), ch.receipt(tx)
    state = ch.book.get_rule(BOB, terms.rule_id)
    assert len(state.sales) == MAX_OPEN_SALES
    assert state.sales_missed == 1
    assert state.open_sale(first) is None


# --- apply level: named executions ------------------------------------------------


def test_a_named_execution_pays_from_the_recorded_amount_not_the_claim():
    ch = Chain(_balances())
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     extra={"per_sale": True})
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)

    seen = {}

    def legs_fn(vals):
        seen.update(vals)
        return _pct(5)(vals)

    ch.legs_fn = legs_fn
    # The executor claims a gross of a million; the clause is
    # stepped with the recorded 101, and 5% of 101 is 5.
    ex = execute_tx(settlement_id="royalty-1", gross=1_000_000,
                    rule_id=terms.rule_id, sale_id=tx["tx_id"])
    ch.block([ex], height=22, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[CAROL] == 100_000 + 5
    assert ch.bal[BOB] == 101 - 5
    # The payer of the sale was on i13, beside the owner on i12.
    assert seen[13] == "{ #x" + ALICE + " }:bv[384]"
    assert seen[1] == "101"
    state = ch.book.get_rule(BOB, terms.rule_id)
    assert state.sales == []
    assert state.settlements == [
        "royalty-1", sale_settlement_id(terms.rule_id, tx["tx_id"])]


def test_a_paid_sale_cannot_be_paid_twice():
    ch = Chain(_balances())
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     extra={"per_sale": True})
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    ch.legs_fn = _pct(5)
    ex = execute_tx(settlement_id="royalty-1", rule_id=terms.rule_id,
                    sale_id=tx["tx_id"])
    ch.block([ex], height=22, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)

    again = execute_tx(settlement_id="royalty-2", seq=1,
                       rule_id=terms.rule_id, sale_id=tx["tx_id"])
    ch.block([again], height=23, ts=NOW)
    assert not ch.accepted(again)
    assert "not an open sale" in " ".join(ch.receipt(again)["logs"])
    assert ch.bal[CAROL] == 100_000 + 5
    assert ch.bal[BOB] == 101 - 5


def test_executions_that_misname_their_basis_are_refused():
    ch = Chain(_balances())
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     extra={"per_sale": True})
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    ch.legs_fn = _pct(5)

    unnamed = execute_tx(settlement_id="x1", rule_id=terms.rule_id)
    ch.block([unnamed], height=22, ts=NOW)
    assert not ch.accepted(unnamed)
    assert "must name a sale" in " ".join(ch.receipt(unnamed)["logs"])

    unknown = execute_tx(settlement_id="x2", rule_id=terms.rule_id,
                         sale_id="no-such-credit")
    ch.block([unknown], height=23, ts=NOW)
    assert not ch.accepted(unknown)
    assert "not an open sale" in " ".join(ch.receipt(unknown)["logs"])

    # The sale is still open after both refusals.
    state = ch.book.get_rule(BOB, terms.rule_id)
    assert [s.sale_id for s in state.sales] == [tx["tx_id"]]
    assert state.settlements == []

    # And the mirror image: a sale named against a rule without
    # per_sale is refused, not reinterpreted.
    plain = _install(ch, DAVE, SK_DAVE, height=24,
                     recipients=[CAROL])
    misdirected = execute_tx(owner=DAVE, settlement_id="x3",
                             rule_id=plain.rule_id, sale_id=tx["tx_id"])
    ch.block([misdirected], height=25, ts=NOW)
    assert not ch.accepted(misdirected)
    assert "does not settle per sale" in " ".join(
        ch.receipt(misdirected)["logs"])


def test_a_refused_execution_leaves_the_sale_open():
    ch = Chain(_balances())
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     max_per_execution=100, extra={"per_sale": True})
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    # Legs of 300 break the per-execution cap of 100: refused, and
    # the sale is not consumed by the failed attempt.
    ch.legs = {20: "1", 21: "300", 22: "0"}
    ex = execute_tx(settlement_id="too-big", rule_id=terms.rule_id,
                    sale_id=tx["tx_id"])
    ch.block([ex], height=22, ts=NOW)
    assert not ch.accepted(ex)
    state = ch.book.get_rule(BOB, terms.rule_id)
    assert [s.sale_id for s in state.sales] == [tx["tx_id"]]
    assert state.settlements == []

    ch.legs = {20: "1", 21: "50", 22: "0"}
    ok = execute_tx(settlement_id="fits", rule_id=terms.rule_id,
                    sale_id=tx["tx_id"])
    ch.block([ok], height=23, ts=NOW)
    assert ch.accepted(ok), ch.receipt(ok)
    assert ch.bal[CAROL] == 100_000 + 50
    assert ch.book.get_rule(BOB, terms.rule_id).sales == []


# --- apply level: combined and gated shapes ----------------------------------------


def test_an_arrival_rule_that_is_per_sale_closes_its_sale():
    ch = Chain(_balances())
    terms = _install(ch, BOB, SK_BOB, height=20, recipients=[CAROL],
                     extra={"per_sale": True, "on_arrival": True})
    ch.legs_fn = _pct(20)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 100_000 + 20
    assert ch.bal[BOB] == 101 - 20
    state = ch.book.get_rule(BOB, terms.rule_id)
    # The sale was recorded and closed in the same apply: the book
    # holds the arrival settlement and the sale marker, and no
    # open sale remains for an executor to name.
    assert state.sales == []
    assert state.sales_missed == 0
    from consensus.payouts import arrival_settlement_id
    assert state.settlements == [
        arrival_settlement_id(tx["tx_id"]),
        sale_settlement_id(terms.rule_id, tx["tx_id"]),
    ]
    ex = execute_tx(settlement_id="late", rule_id=terms.rule_id,
                    sale_id=tx["tx_id"])
    ch.block([ex], height=22, ts=NOW)
    assert not ch.accepted(ex)


def test_a_sealed_per_sale_rule_still_settles_its_sales():
    # The seal locks the owner's own transfers to the rule's own
    # settlements; a sale settlement is not the owner's send, and
    # no owner-side gate is consulted about it -- the same stance
    # the arrival trigger takes. The owner's transfer is refused
    # while the executor's named settlement lands.
    ch = Chain(_balances())
    terms = _install(
        ch, BOB, SK_BOB, height=20, recipients=[CAROL],
        extra={"per_sale": True, "sealed": True, "end_period_index": 52})
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)

    own = transfer_tx(CAROL, 10, SK_BOB, sender=BOB, seq=1)
    ch.block([own], height=22, ts=NOW)
    assert not ch.accepted(own)
    assert ch.receipt(own)["reason"] == "payout_rule_sealed"

    ch.legs_fn = _pct(5)
    ex = execute_tx(settlement_id="royalty-1", rule_id=terms.rule_id,
                    sale_id=tx["tx_id"])
    ch.block([ex], height=23, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[CAROL] == 100_000 + 5
    assert ch.bal[BOB] == 101 - 5
