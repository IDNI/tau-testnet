"""Payout-rule book semantics (Bounty 01, issue #63).

The book-level half of the design's case -> test mapping for #63:
caps, the declared recipient set, settlement idempotency and the
period cap, all enforced by the node-side book.
"""

import pytest

from consensus import periods
from consensus.payouts import (
    PayoutBook,
    PayoutShapeError,
    PayoutTerms,
    legs_from_outputs,
    validate_payout_shape,
)

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
D = "dd" * 48

JAN1 = 1767225600  # 2026-01-01 UTC
FEB1 = 1769904000  # 2026-02-01 UTC


def _terms(**kw):
    base = dict(
        owner=A, max_per_execution=1000, max_per_period=1500,
        recipients=(B, C), period_kind=periods.PERIOD_MONTH,
        anchor_ts=JAN1, sequence_number=1,
    )
    base.update(kw)
    return PayoutTerms(**base)


def _book(**kw):
    book = PayoutBook()
    book.install(_terms(**kw))
    return book


def test_payout_rule_outputs_checked_against_declared_caps():
    book = _book()
    legs = [(B, 600), (C, 400)]
    assert book.check_execution(A, "s1", legs, ts=JAN1) == 1000
    with pytest.raises(PayoutShapeError):
        book.check_execution(A, "s2", [(B, 1001)], ts=JAN1)


def test_payout_cannot_pay_undeclared_recipient():
    # Legs are read by index into the declared set: an index outside
    # the set is malformed, so an undeclared recipient cannot be paid.
    terms = _terms()
    with pytest.raises(PayoutShapeError):
        legs_from_outputs({20: "1", 21: "10", 22: "2"}, terms)
    with pytest.raises(PayoutShapeError):
        legs_from_outputs({20: "1", 21: "10", 22: "-1"}, terms)
    assert legs_from_outputs({20: "1", 21: "10", 22: "1"}, terms) == [(C, 10)]
    assert legs_from_outputs({}, terms) == []


def test_royalty_5pct_on_101_pays_5_once():
    # The rule outputs a 5-unit leg on a gross of 101 (5% of 101,
    # floored by the rule itself); the settlement id makes the second
    # identical execution settle nothing.
    book = _book()
    legs = legs_from_outputs({20: "1", 21: "5", 22: "0"}, _terms())
    total = book.check_execution(A, "royalty-101", legs, ts=JAN1)
    assert total == 5
    book.settle(A, "royalty-101", total, ts=JAN1)
    with pytest.raises(PayoutShapeError):
        book.check_execution(A, "royalty-101", legs, ts=JAN1)


def test_payout_period_cap_binds_across_executions():
    book = _book()
    book.settle(A, "s1", book.check_execution(A, "s1", [(B, 1000)], ts=JAN1), ts=JAN1)
    with pytest.raises(PayoutShapeError):
        book.check_execution(A, "s2", [(B, 501)], ts=JAN1)
    # A new period frees the cap again.
    assert book.check_execution(A, "s3", [(B, 1000)], ts=FEB1) == 1000


def test_payout_shape_validation():
    validate_payout_shape(_terms(), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(max_per_execution=0), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(
            _terms(max_per_execution=100, max_per_period=50), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(recipients=()), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(recipients=(B, B)), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(recipients=(B, "zz")), now_ts=JAN1)


def test_payout_snapshot_restore_round_trip():
    book = _book()
    book.settle(A, "s1", book.check_execution(A, "s1", [(B, 700)], ts=JAN1), ts=JAN1)
    restored = PayoutBook.restore(book.snapshot_rows())
    assert restored.root() == book.root()
    assert restored.get(A).spent_in_period == 700
    assert restored.get(A).already_settled("s1")


def test_payout_remove_and_reinstall():
    book = _book()
    assert book.remove(A) is True
    assert book.get(A) is None
    assert book.remove(A) is False
    book.install(_terms(sequence_number=2))
    assert book.get(A) is not None
