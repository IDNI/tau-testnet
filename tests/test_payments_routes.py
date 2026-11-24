"""Receive-routing tests for Bounty 01 issue #35 (stage 2).

Written only from the public API in ``consensus/payments.py``:
``RouteBook``, ``RouteTerms``, ``RouteReceipt``, ``DictLedger``,
``FEE_SINK_PUBKEY`` and the ``CREDIT_CLASS_*`` constants.

Routing is a property of the book, not of any wallet process: a routable
credit is split by the recipient's installed route, atomically, with
exactly one fee charged to the sender. A routed leg is final — it never
triggers the destination's own route.
"""
from __future__ import annotations

import inspect

import pytest

from consensus.payments import (
    CREDIT_CLASS_CLAIMED_PAYMENT,
    CREDIT_CLASS_PLAIN_TRANSFER,
    CREDIT_CLASS_STANDING_PAYMENT,
    FEE_SINK_PUBKEY,
    DictLedger,
    PaymentRefused,
    PaymentShapeError,
    PayoutBook,
    PayoutTerms,
    RouteBook,
    RouteTerms,
)


def pk(i: int) -> str:
    return f"{i:096x}"


# 1 -------------------------------------------------------------------------

def test_route_101_at_20pct_gives_20_and_81_one_fee():
    book = RouteBook()
    book.install(RouteTerms(owner=pk(2), destinations=((pk(3), 2000),)))
    ledger = DictLedger({pk(1): 1000})

    receipt = book.apply_credit(
        pk(1), pk(2), 101, CREDIT_CLASS_PLAIN_TRANSFER,
        fee=3, ledger=ledger, ts=100,
    )

    assert ledger.balance(pk(3)) == 20
    assert ledger.balance(pk(2)) == 81
    # Sender debited exactly gross + one fee (104), never one fee per leg.
    assert ledger.balance(pk(1)) == 1000 - 104
    assert ledger.balance(FEE_SINK_PUBKEY) == 3
    assert receipt.gross == 101
    assert receipt.net == 81
    assert receipt.legs == ((pk(3), 20),)
    assert receipt.fee == 3
    assert receipt.routed is True
    assert receipt.owner == pk(2)


# 2 -------------------------------------------------------------------------

def test_routed_share_never_triggers_route():
    book = RouteBook()
    book.install(RouteTerms(owner=pk(2), destinations=((pk(3), 2000),)))
    # The destination has its own route: 50% onward to pk(4).
    book.install(RouteTerms(owner=pk(3), destinations=((pk(4), 5000),)))
    ledger = DictLedger({pk(1): 1000})

    book.apply_credit(
        pk(1), pk(2), 101, CREDIT_CLASS_PLAIN_TRANSFER,
        fee=3, ledger=ledger, ts=100,
    )
    # The routed leg (20 to pk(3)) is final: pk(3)'s route does NOT fire.
    assert ledger.balance(pk(3)) == 20
    assert ledger.balance(pk(4)) == 0

    # A DIRECT plain credit to pk(3) DOES fire pk(3)'s route.
    receipt = book.apply_credit(
        pk(1), pk(3), 100, CREDIT_CLASS_PLAIN_TRANSFER,
        fee=0, ledger=ledger, ts=101,
    )
    assert receipt.routed is True
    assert receipt.legs == ((pk(4), 50),)
    assert receipt.net == 50
    assert ledger.balance(pk(4)) == 50
    assert ledger.balance(pk(3)) == 20 + 50


# 3 -------------------------------------------------------------------------

def test_route_applies_identically_online_or_offline():
    # There is no wallet-online parameter anywhere in the book API; routing
    # cannot depend on recipient presence by construction.
    params = inspect.signature(RouteBook.apply_credit).parameters
    assert not any("online" in name or "wallet" in name for name in params)

    def run_world(with_unrelated_activity: bool):
        book = RouteBook()
        book.install(RouteTerms(owner=pk(2), destinations=((pk(3), 2000),)))
        ledger = DictLedger({pk(1): 1000})
        if with_unrelated_activity:
            # Unrelated payout rule installed AND executed by the recipient
            # (against a scratch ledger, so the compared world is untouched),
            # plus an unrelated route install/remove for another account.
            payouts = PayoutBook()
            rule_id = payouts.install(PayoutTerms(
                owner=pk(2),
                candidates=((pk(8), 500),),
                max_per_execution=500,
                max_per_period=500,
                period_kind="week",
                anchor_ts=0,
                clause="o30 = 1:bv[64]",
            ))
            scratch = DictLedger({pk(2): 500})
            payouts.execute(
                rule_id, "unrelated-event", 50,
                lambda _ctx: [(0, 50)],
                ts=100, ledger=scratch,
            )
            assert scratch.balance(pk(8)) == 50
            book.install(RouteTerms(owner=pk(9), destinations=((pk(10), 1000),)))
            book.remove(pk(9), pk(9), 100)
        receipt = book.apply_credit(
            pk(1), pk(2), 101, CREDIT_CLASS_PLAIN_TRANSFER,
            fee=3, ledger=ledger, ts=100,
        )
        return ledger, receipt

    ledger_a, receipt_a = run_world(False)
    ledger_b, receipt_b = run_world(True)

    assert receipt_a == receipt_b
    assert ledger_a.balances == ledger_b.balances
    assert ledger_b.balance(pk(2)) == 81
    assert ledger_b.balance(pk(3)) == 20


# 4 -------------------------------------------------------------------------

def test_normal_transfer_cannot_bypass_route():
    book = RouteBook()
    book.install(RouteTerms(owner=pk(2), destinations=((pk(3), 2000),)))
    ledger = DictLedger({pk(1): 2000})

    plain = book.apply_credit(
        pk(1), pk(2), 100, CREDIT_CLASS_PLAIN_TRANSFER,
        fee=0, ledger=ledger, ts=100,
    )
    assert plain.routed is True
    assert plain.legs == ((pk(3), 20),)
    assert plain.net == 80

    claimed = book.apply_credit(
        pk(1), pk(2), 100, CREDIT_CLASS_CLAIMED_PAYMENT,
        fee=0, ledger=ledger, ts=101,
    )
    assert claimed.routed is True
    assert claimed.legs == ((pk(3), 20),)
    assert claimed.net == 80

    # Both credits split: there is no non-routing path for either class.
    assert ledger.balance(pk(3)) == 40
    assert ledger.balance(pk(2)) == 160


# 5 -------------------------------------------------------------------------

def test_invalid_and_recursive_route_sets_rejected_safely():
    # Self-route: destination == owner.
    with pytest.raises(PaymentShapeError):
        RouteTerms(owner=pk(2), destinations=((pk(2), 1000),))
    # Shares summing to more than 10000 bps.
    with pytest.raises(PaymentShapeError):
        RouteTerms(owner=pk(2), destinations=((pk(3), 6000), (pk(4), 6000)))
    # Five destinations (bound is 4).
    with pytest.raises(PaymentShapeError):
        RouteTerms(owner=pk(2), destinations=(
            (pk(3), 1000), (pk(4), 1000), (pk(5), 1000),
            (pk(6), 1000), (pk(7), 1000),
        ))
    # Invalid pubkey destination.
    with pytest.raises(PaymentShapeError):
        RouteTerms(owner=pk(2), destinations=(("not-a-pubkey", 1000),))
    # Zero share.
    with pytest.raises(PaymentShapeError):
        RouteTerms(owner=pk(2), destinations=((pk(3), 0),))

    # Cycle: pk(2) -> pk(3) installed; pk(3) -> pk(2) would close a cycle.
    book = RouteBook()
    book.install(RouteTerms(owner=pk(2), destinations=((pk(3), 1000),)))
    with pytest.raises(PaymentShapeError):
        book.install(RouteTerms(owner=pk(3), destinations=((pk(2), 1000),)))
    # The rejected install left the book untouched.
    assert book.get(pk(3)) is None
    assert book.get(pk(2)) is not None


# 6 -------------------------------------------------------------------------

def test_locked_route_remains_binding_until_expiry():
    book = RouteBook()
    book.install(RouteTerms(
        owner=pk(2), destinations=((pk(3), 1000),),
        locked=True, expires_ts=2000,
    ))
    # Locked: the owner cannot remove it before expiry.
    with pytest.raises(PaymentRefused):
        book.remove(pk(2), pk(2), 1000)
    assert book.get(pk(2)) is not None
    # A non-owner cannot remove it even at/after expiry.
    with pytest.raises(PaymentRefused):
        book.remove(pk(2), pk(9), 2000)
    assert book.get(pk(2)) is not None
    # At expiry the owner can remove it.
    book.remove(pk(2), pk(2), 2000)
    assert book.get(pk(2)) is None

    # A locked route without an expiry is refused at construction.
    with pytest.raises(PaymentShapeError):
        RouteTerms(
            owner=pk(2), destinations=((pk(3), 1000),),
            locked=True, expires_ts=None,
        )

    # An unlocked route is removable at any time by its owner.
    book2 = RouteBook()
    book2.install(RouteTerms(owner=pk(2), destinations=((pk(3), 1000),)))
    book2.remove(pk(2), pk(2), 0)
    assert book2.get(pk(2)) is None


# 7 -------------------------------------------------------------------------

def test_route_receipt_and_history_show_gross_net_routed_and_fee():
    book = RouteBook()
    book.install(RouteTerms(owner=pk(2), destinations=(
        (pk(3), 1000), (pk(4), 2000), (pk(5), 3000),
    )))
    ledger = DictLedger({pk(1): 2000})

    receipt = book.apply_credit(
        pk(1), pk(2), 1000, CREDIT_CLASS_PLAIN_TRANSFER,
        fee=4, ledger=ledger, ts=100,
    )

    assert receipt.gross == 1000
    assert receipt.net == 400
    assert receipt.legs == ((pk(3), 100), (pk(4), 200), (pk(5), 300))
    assert receipt.fee == 4
    assert receipt.routed is True

    # Balances match the receipt exactly.
    assert ledger.balance(pk(3)) == 100
    assert ledger.balance(pk(4)) == 200
    assert ledger.balance(pk(5)) == 300
    assert ledger.balance(pk(2)) == receipt.net
    assert ledger.balance(pk(1)) == 2000 - 1000 - 4
    assert ledger.balance(FEE_SINK_PUBKEY) == 4


# 8 -------------------------------------------------------------------------

def test_route_replay_and_snapshot_restore_preserve_balances():
    credits = [
        (101, CREDIT_CLASS_PLAIN_TRANSFER, 3, 100),
        (200, CREDIT_CLASS_CLAIMED_PAYMENT, 2, 101),
        (100, CREDIT_CLASS_STANDING_PAYMENT, 1, 102),
    ]

    book_a = RouteBook()
    book_a.install(RouteTerms(owner=pk(2), destinations=((pk(3), 2000),)))
    ledger_a = DictLedger({pk(1): 1000})
    receipts_a = [
        book_a.apply_credit(pk(1), pk(2), gross, cls, fee=fee,
                            ledger=ledger_a, ts=ts)
        for gross, cls, fee, ts in credits
    ]
    # The standing-payment credit is not routable in v1: no split.
    assert receipts_a[2].routed is False
    assert receipts_a[2].legs == ()
    assert receipts_a[2].net == 100
    assert receipts_a[0].legs == ((pk(3), 20),)
    assert receipts_a[1].legs == ((pk(3), 40),)

    book_b = RouteBook.restore(book_a.snapshot_rows())
    assert book_b.root_blobs() == book_a.root_blobs()

    ledger_b = DictLedger({pk(1): 1000})
    receipts_b = [
        book_b.apply_credit(pk(1), pk(2), gross, cls, fee=fee,
                            ledger=ledger_b, ts=ts)
        for gross, cls, fee, ts in credits
    ]

    assert receipts_b == receipts_a
    assert ledger_b.balances == ledger_a.balances


# 9 -------------------------------------------------------------------------

def test_route_floor_rounding_remainder_to_recipient():
    book = RouteBook()
    book.install(RouteTerms(owner=pk(2), destinations=((pk(3), 3300),)))
    ledger = DictLedger({pk(1): 1000})

    receipt = book.apply_credit(
        pk(1), pk(2), 99, CREDIT_CLASS_PLAIN_TRANSFER,
        fee=0, ledger=ledger, ts=100,
    )

    # floor(99 * 3300 / 10000) == 32; the recipient keeps the remainder.
    assert receipt.legs == ((pk(3), 32),)
    assert receipt.net == 67
    assert ledger.balance(pk(3)) == 32
    assert ledger.balance(pk(2)) == 67


# 10 ------------------------------------------------------------------------

def test_expired_route_does_not_split():
    book = RouteBook()
    book.install(RouteTerms(
        owner=pk(2), destinations=((pk(3), 2000),), expires_ts=1000,
    ))
    ledger = DictLedger({pk(1): 1000})

    receipt = book.apply_credit(
        pk(1), pk(2), 100, CREDIT_CLASS_PLAIN_TRANSFER,
        fee=0, ledger=ledger, ts=1500,
    )

    assert receipt.routed is False
    assert receipt.legs == ()
    assert receipt.net == 100
    assert ledger.balance(pk(2)) == 100
    assert ledger.balance(pk(3)) == 0
