"""Payout stage 2, book level (Bounty 01): the multi-rule book,
in-place updates, sealed terms, the fee cap screen and missed
period accounting -- plus the persistence and admission halves.

The apply-level halves live in tests/test_payout_stage2_apply.py
and the native evidence in tests/test_payout_stage2_native.py.
"""

import json

import pytest
from py_ecc.bls import G2Basic

import db
from consensus import periods
from consensus.admission import (
    validate_payout_execute_payload,
    validate_payout_install_payload,
    validate_payout_remove_payload,
    validate_payout_update_payload,
    validate_rule_change_request_payload,
    validate_user_tx_reserved_domains,
)
from consensus.facade import TipAdmissionView
from consensus.payouts import (
    MAX_RULES_PER_OWNER,
    PayoutBook,
    PayoutShapeError,
    PayoutTerms,
    clock_settlement_id,
    fee_exceeds_cap,
    legs_from_outputs,
    observe_clock,
    rule_ended,
    validate_payout_shape,
)

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
D = "dd" * 48
E = "ee" * 48
F = "ff" * 48
G = "11" * 48

JAN1 = 1767225600  # 2026-01-01 UTC
WEEK = 604800


def _terms(**kw):
    base = dict(
        owner=A, max_per_execution=1000, max_per_period=1500,
        recipients=(B, C), period_kind=periods.PERIOD_WEEK,
        anchor_ts=JAN1, sequence_number=1,
    )
    base.update(kw)
    return PayoutTerms(**base)


# --- F1: the multi-rule book ---------------------------------------------------


def test_two_rules_on_one_account_are_independent():
    book = PayoutBook()
    small = book.install(_terms())
    big = book.install(_terms(
        sequence_number=2, max_per_execution=5000, max_per_period=9000))
    assert book.owner_rule_count(A) == 2
    assert len(book) == 2
    # The same legs are inside the small rule's cap and the big
    # rule's cap is a separate budget: settling one moves only its
    # own period spend and history.
    total = book.check_execution(
        A, "s1", [(B, 700)], ts=JAN1, rule_id=small.terms.rule_id)
    book.settle(A, "s1", total, ts=JAN1, rule_id=small.terms.rule_id)
    assert small.spent_in_period == 700
    assert big.spent_in_period == 0
    assert big.settlements == []
    with pytest.raises(PayoutShapeError):
        book.check_execution(
            A, "s2", [(B, 900)], ts=JAN1, rule_id=small.terms.rule_id)
    assert book.check_execution(
        A, "s2", [(B, 900)], ts=JAN1, rule_id=big.terms.rule_id) == 900
    # An unnamed execution is refused rather than guessed at.
    with pytest.raises(PayoutShapeError):
        book.check_execution(A, "s3", [(B, 1)], ts=JAN1)
    # Removing one rule leaves the other untouched.
    assert book.remove(A, small.terms.rule_id)
    assert book.get(A) is big
    assert book.owner_rule_count(A) == 1


def test_a_full_owner_book_refuses_a_ninth_rule():
    book = PayoutBook()
    for i in range(MAX_RULES_PER_OWNER):
        book.install(_terms(sequence_number=100 + i))
    assert book.owner_rule_count(A) == MAX_RULES_PER_OWNER
    with pytest.raises(PayoutShapeError):
        book.install(_terms(sequence_number=999))
    # Reinstalling terms already held is a replace, not a ninth.
    book.install(_terms(sequence_number=100))
    assert book.owner_rule_count(A) == MAX_RULES_PER_OWNER


def test_legacy_single_rule_rows_restore_identically():
    # A row dict in exactly the stage-1 shape (no stage-2 keys)
    # restores without error, recomputes its id, and keeps its
    # settlements and caps; the restored book is a fixpoint.
    terms = _terms()
    row = {
        "rule_id": terms.rule_id, "owner": A,
        "max_per_execution": 1000, "max_per_period": 1500,
        "recipients": [B, C], "period_kind": periods.PERIOD_WEEK,
        "anchor_ts": JAN1, "sequence_number": 1,
        "period_index": 0, "spent_in_period": 700,
        "settlements": ["s1"],
    }
    book = PayoutBook.restore([row])
    state = book.get(A)
    assert state is not None
    assert state.terms.rule_id == terms.rule_id
    assert state.settlements == ["s1"]
    assert state.spent_in_period == 700
    assert state.version == 1 and state.lineage == []
    again = PayoutBook.restore(book.snapshot_rows())
    assert again.root() == book.root()


def test_triggered_rule_survives_the_db_round_trip():
    # Stage 1 wrote only the v1 columns to the database, dropping
    # the trigger fields, so a clock rule's row no longer
    # recomputed its id on restore. Stage 2's v2 rows carry the
    # complete row; this is the regression test.
    book = PayoutBook()
    book.install(_terms(due=True, max_fires=4))
    book.settle_clock(
        A, clock_settlement_id(book.get(A).terms.rule_id, 0),
        500, ts=JAN1)
    db.init_db()
    with db._db_lock:
        db._write_payout_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()
    restored = PayoutBook.restore(db.load_payout_state())
    assert restored.root() == book.root()
    state = restored.get(A)
    assert state.terms.due is True and state.terms.max_fires == 4
    assert state.fires == 1 and state.total_spent == 500


def test_multi_rule_book_survives_the_db_round_trip():
    book = PayoutBook()
    book.install(_terms())
    book.install(_terms(sequence_number=2, due=True, max_total=4000))
    book.install(_terms(owner=B, recipients=(C,)))
    db.init_db()
    with db._db_lock:
        db._write_payout_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()
    restored = PayoutBook.restore(db.load_payout_state())
    assert restored.root() == book.root()
    assert restored.owner_rule_count(A) == 2
    assert restored.owner_rule_count(B) == 1


def test_payout_book_view_lists_every_rule():
    from commands.getpayouts import execute

    book = PayoutBook()
    book.install(_terms())
    updated = book.install(_terms(sequence_number=2))
    book.settle(A, "s1", 700, ts=JAN1, rule_id=updated.terms.rule_id)
    db.init_db()
    with db._db_lock:
        db._write_payout_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()
    result = execute(f"getpayouts {A}", None)
    if isinstance(result, str):
        result = json.loads(result)
    data = result["data"] if "data" in result else result
    views = data["payout_rules"]
    assert len(views) == 2
    by_id = {v["rule_id"]: v for v in views}
    settled = by_id[updated.terms.rule_id]
    assert settled["paid_total"] == 700
    assert settled["executions"] == 1
    assert settled["settled_count"] == 1
    assert data["semantics"]["max_legs"] == 8
    assert data["semantics"]["max_rules_per_owner"] == 8
    # The stage-1 field still reports the owner's first rule.
    assert data["payout_rule"]["rule_id"] == views[0]["rule_id"]


# --- F2: updates that preserve lineage AND accounting state --------------------


def _settled_book():
    book = PayoutBook()
    terms = _terms(due=True, max_fires=10)
    state = book.install(terms)
    total = book.check_execution(
        A, "draw-1", [(B, 700)], ts=JAN1, rule_id=terms.rule_id)
    book.settle(A, "draw-1", total, ts=JAN1, rule_id=terms.rule_id)
    book.settle_clock(
        A, clock_settlement_id(terms.rule_id, 0), 500, ts=JAN1,
        rule_id=terms.rule_id)
    return book, terms, state


def test_an_update_preserves_settlements_and_period_spend():
    book, terms, _state = _settled_book()
    new_terms = _terms(
        due=True, max_fires=10, sequence_number=2,
        max_per_execution=2000, max_per_period=2500)
    updated = book.update(A, terms.rule_id, new_terms, ts=JAN1)
    assert updated.terms.rule_id == new_terms.rule_id
    # History, period spend and clock accounting all carry over.
    assert updated.settlements == [
        "draw-1", clock_settlement_id(terms.rule_id, 0)]
    assert updated.spent_in_period == 1200
    assert updated.total_spent == 500
    assert updated.fires == 1
    assert updated.paid_total == 1200
    assert updated.executions == 2
    # Lineage: version 2, superseding the install's id.
    assert updated.version == 2
    assert updated.lineage == [terms.rule_id]
    # The superseded id no longer resolves as a live rule.
    assert book.get_rule(A, terms.rule_id) is None
    assert book.get_rule(A, new_terms.rule_id) is updated


def test_an_update_cannot_resurrect_a_settled_settlement_id():
    book, terms, _state = _settled_book()
    new_terms = _terms(
        due=True, max_fires=10, sequence_number=2,
        max_per_execution=2000, max_per_period=2500)
    book.update(A, terms.rule_id, new_terms, ts=JAN1)
    with pytest.raises(PayoutShapeError):
        book.check_execution(
            A, "draw-1", [(B, 10)], ts=JAN1,
            rule_id=new_terms.rule_id)
    with pytest.raises(PayoutShapeError):
        book.check_execution(
            A, clock_settlement_id(terms.rule_id, 0), [(B, 10)],
            ts=JAN1, rule_id=new_terms.rule_id)


def test_an_update_below_spent_period_cap_is_refused():
    book, terms, _state = _settled_book()
    # 1,200 already spent in the current period (700 + 500 clock).
    greedy = _terms(
        due=True, max_fires=10, sequence_number=2,
        max_per_execution=1000, max_per_period=1199)
    problem = book.update_problem(A, terms.rule_id, greedy, ts=JAN1)
    assert problem is not None and "already spent" in problem
    with pytest.raises(PayoutShapeError):
        book.update(A, terms.rule_id, greedy, ts=JAN1)
    # Exactly the spent amount is allowed (the rule is then full
    # for this period, but the update itself is honest).
    exact = _terms(
        due=True, max_fires=10, sequence_number=2,
        max_per_execution=1000, max_per_period=1200)
    assert book.update_problem(A, terms.rule_id, exact, ts=JAN1) is None


def test_an_update_cannot_move_the_schedule():
    book, terms, _state = _settled_book()
    moved = _terms(due=True, max_fires=10, sequence_number=2,
                   anchor_ts=JAN1 + 3600)
    problem = book.update_problem(A, terms.rule_id, moved, ts=JAN1)
    assert problem is not None and "schedule" in problem
    other_kind = _terms(due=True, max_fires=10, sequence_number=2,
                        period_kind=periods.PERIOD_MONTH)
    assert book.update_problem(
        A, terms.rule_id, other_kind, ts=JAN1) is not None


def test_an_update_to_a_sibling_rules_terms_is_refused():
    book, terms, _state = _settled_book()
    sibling = book.install(_terms(sequence_number=7))
    problem = book.update_problem(
        A, terms.rule_id, _terms(sequence_number=7), ts=JAN1)
    assert problem is not None and "already carries" in problem
    assert book.get_rule(A, sibling.terms.rule_id) is sibling


def test_an_update_rolls_period_spend_under_the_same_schedule():
    book, terms, _state = _settled_book()
    # Two weeks later the period has rolled: the new period starts
    # unspent (the old spend is history, not a reset of THIS
    # period's cap -- the cap was never charged in this period).
    new_terms = _terms(
        due=True, max_fires=10, sequence_number=2,
        max_per_execution=2000, max_per_period=2500)
    updated = book.update(
        A, terms.rule_id, new_terms, ts=JAN1 + 2 * WEEK)
    assert updated.period_index == 2
    assert updated.spent_in_period == 0
    assert updated.settlements  # history itself is untouched
    assert updated.total_spent == 500


# --- F3: eight legs --------------------------------------------------------------


def test_eight_legs_are_read_and_a_ninth_is_malformed():
    terms = _terms(
        recipients=(B, C, D, E, F, G),
        max_per_execution=10000, max_per_period=10000)
    outputs = {20: "6"}
    amounts = [5000, 1000, 1000, 1000, 1500, 500]
    for k, amount in enumerate(amounts):
        outputs[21 + 2 * k] = str(amount)
        outputs[22 + 2 * k] = str(k)
    legs = legs_from_outputs(outputs, terms)
    assert legs == [(B, 5000), (C, 1000), (D, 1000),
                    (E, 1000), (F, 1500), (G, 500)]
    assert sum(amount for _r, amount in legs) == 10000
    outputs[20] = "9"
    with pytest.raises(PayoutShapeError):
        legs_from_outputs(outputs, terms)


# --- F4: sealed terms ------------------------------------------------------------


def test_sealed_terms_need_an_end_condition():
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(sealed=True), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(
            _terms(sealed=True, max_fires=3), now_ts=JAN1)
    # A sealed clock rule ends on any of the three end conditions;
    # a sealed non-clock rule only on its final period.
    validate_payout_shape(
        _terms(sealed=True, due=True, max_fires=3), now_ts=JAN1)
    validate_payout_shape(
        _terms(sealed=True, end_period_index=2), now_ts=JAN1)


def test_a_sealed_rule_ends_exactly_at_its_end_condition():
    book = PayoutBook()
    state = book.install(_terms(sealed=True, end_period_index=1))
    assert not rule_ended(state, JAN1)
    assert not rule_ended(state, JAN1 + WEEK)
    assert rule_ended(state, JAN1 + 2 * WEEK)


# --- F5: the fee cap screen -------------------------------------------------------


def test_the_fee_cap_compares_against_the_declared_cap():
    capped = _terms(max_fee_per_execution=7)
    assert not fee_exceeds_cap(capped, 7)
    assert fee_exceeds_cap(capped, 8)
    uncapped = _terms()
    assert not fee_exceeds_cap(uncapped, 10 ** 9)


# --- F6: missed-period accounting ---------------------------------------------------


def test_missed_periods_are_counted_when_periods_close_unsettled():
    book = PayoutBook()
    state = book.install(_terms(due=True, max_fires=10))
    assert observe_clock(state, JAN1) == 0
    book.settle_clock(
        A, clock_settlement_id(state.terms.rule_id, 0), 100, ts=JAN1)
    # Three periods later: periods 1 and 2 closed unsettled.
    assert observe_clock(state, JAN1 + 3 * WEEK) == 2
    assert state.missed_periods == 2
    # Observing again at the same time counts nothing twice.
    assert observe_clock(state, JAN1 + 3 * WEEK) == 0
    assert state.missed_periods == 2


def test_missed_periods_stop_at_the_end_condition():
    book = PayoutBook()
    state = book.install(_terms(due=True, end_period_index=0))
    assert observe_clock(state, JAN1) == 0
    # Period 0 is the rule's last; periods after it are over, not
    # missed, even though period 0 itself never settled.
    assert observe_clock(state, JAN1 + 4 * WEEK) == 1
    assert state.missed_periods == 1
    assert observe_clock(state, JAN1 + 9 * WEEK) == 0


# --- admission halves --------------------------------------------------------------


def _pk(seed):
    return G2Basic.SkToPk(seed).hex()


ALICE = _pk(11111)
BOB = _pk(44444)
CAROL = _pk(55555)


class _View(TipAdmissionView):
    def __init__(self, ts):
        self._ts = ts

    @property
    def next_block_timestamp(self):
        return self._ts

    @property
    def next_block_height(self):
        return 100


def _write_book(book):
    db.init_db()
    with db._db_lock:
        db._write_payout_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()


def _a_terms(**kw):
    base = dict(
        owner=ALICE, max_per_execution=1000, max_per_period=1500,
        recipients=(BOB, CAROL), period_kind=periods.PERIOD_WEEK,
        anchor_ts=JAN1, sequence_number=1,
    )
    base.update(kw)
    return PayoutTerms(**base)


def _update_tx(terms, rule_id, **over):
    tx = {
        "tx_type": "payout_rule_update",
        "sender_pubkey": ALICE,
        "rule_id": rule_id,
        "max_per_execution": terms.max_per_execution,
        "max_per_period": terms.max_per_period,
        "recipients": list(terms.recipients),
        "period_kind": terms.period_kind,
        "anchor_ts": terms.anchor_ts,
        "sequence_number": terms.sequence_number,
        "due": terms.due,
        "on_arrival": terms.on_arrival,
        "end_period_index": terms.end_period_index,
        "max_fires": terms.max_fires,
        "max_total": terms.max_total,
    }
    tx.update(over)
    return tx


def test_update_admission_accepts_and_refuses():
    book = PayoutBook()
    terms = _a_terms()
    book.install(terms)
    book.settle(ALICE, "s1", 700, ts=JAN1, rule_id=terms.rule_id)
    _write_book(book)
    view = _View(JAN1)

    new_terms = _a_terms(sequence_number=2, max_per_period=2500,
                         max_per_execution=2000)
    ok = validate_payout_update_payload(
        _update_tx(new_terms, terms.rule_id), view)
    assert ok.is_valid, ok
    assert ok.data["supersedes"] == terms.rule_id
    assert ok.data["version"] == 2

    below = _a_terms(sequence_number=2, max_per_execution=500,
                     max_per_period=600)
    refused = validate_payout_update_payload(
        _update_tx(below, terms.rule_id), view)
    assert not refused.is_valid
    assert refused.code == "PAYOUT_UPDATE_REFUSED"

    unknown = validate_payout_update_payload(
        _update_tx(new_terms, "ab" * 32), view)
    assert not unknown.is_valid
    assert unknown.code == "NO_PAYOUT_RULE"


def test_execute_admission_names_its_rule():
    book = PayoutBook()
    first = book.install(_a_terms())
    book.install(_a_terms(sequence_number=2))
    _write_book(book)
    view = _View(JAN1)
    tx = {
        "tx_type": "payout_execute", "sender_pubkey": CAROL,
        "owner": ALICE, "settlement_id": "s1", "gross": 10,
    }
    ambiguous = validate_payout_execute_payload(tx, view)
    assert not ambiguous.is_valid
    assert ambiguous.code == "PAYOUT_RULE_AMBIGUOUS"
    named = validate_payout_execute_payload(
        {**tx, "rule_id": first.terms.rule_id}, view)
    # The rule resolves; the refusal now is the missing clause,
    # which is a different screen entirely.
    assert named.code == "NO_PAYOUT_CLAUSE"


def test_sealed_admission_screens():
    book = PayoutBook()
    terms = _a_terms(sealed=True, end_period_index=2)
    book.install(terms)
    _write_book(book)
    view = _View(JAN1)

    remove = validate_payout_remove_payload({
        "tx_type": "payout_rule_remove", "sender_pubkey": ALICE,
        "rule_id": terms.rule_id,
    }, view)
    assert not remove.is_valid
    assert remove.code == "PAYOUT_RULE_SEALED"

    replace = validate_payout_install_payload({
        "tx_type": "payout_rule_install", "sender_pubkey": ALICE,
        "max_per_execution": 1000, "max_per_period": 1500,
        "recipients": [BOB, CAROL], "period_kind": periods.PERIOD_WEEK,
        "anchor_ts": JAN1, "sequence_number": 1,
        "sealed": True, "end_period_index": 2,
    }, view)
    assert not replace.is_valid
    assert replace.code == "PAYOUT_RULE_SEALED"

    transfer = validate_user_tx_reserved_domains({
        "tx_type": "user_tx", "sender_pubkey": ALICE,
        "operations": {"1": [[ALICE, BOB, "10"]]},
    }, view)
    assert not transfer.is_valid
    assert transfer.code == "PAYOUT_RULE_SEALED"

    # After the final period the seal lifts: the same screens pass
    # (the remove screen reaches its own success verdict).
    late = _View(JAN1 + 3 * WEEK)
    remove_late = validate_payout_remove_payload({
        "tx_type": "payout_rule_remove", "sender_pubkey": ALICE,
        "rule_id": terms.rule_id,
    }, late)
    assert remove_late.is_valid, remove_late


def test_guarded_update_admission_parity():
    # Rule-change kind 6 carries the same update to a guarded
    # account; admission applies the same screens as the direct
    # payout_rule_update validator.
    book = PayoutBook()
    terms = _a_terms()
    book.install(terms)
    book.settle(ALICE, "s1", 700, ts=JAN1, rule_id=terms.rule_id)
    _write_book(book)
    view = _View(JAN1)

    new_terms = _a_terms(sequence_number=2, max_per_period=2500,
                         max_per_execution=2000)
    payload = {
        "rule_id": terms.rule_id,
        "max_per_execution": 2000, "max_per_period": 2500,
        "recipients": [BOB, CAROL],
        "period_kind": periods.PERIOD_WEEK, "anchor_ts": JAN1,
        "sequence_number": 2,
    }
    tx = {
        "tx_type": "rule_change_request", "sender_pubkey": ALICE,
        "sequence_number": 0, "kind": 6,
        "rule_text": json.dumps(payload),
        "approvers": {}, "expire_at_height": 5000,
    }
    ok = validate_rule_change_request_payload(tx, view)
    assert ok.is_valid, ok

    # Below the 700 already spent in the period (and shape-valid:
    # the period cap still covers one execution).
    payload["max_per_execution"] = 500
    payload["max_per_period"] = 600
    tx = {**tx, "rule_text": json.dumps(payload)}
    refused = validate_rule_change_request_payload(tx, view)
    assert not refused.is_valid
