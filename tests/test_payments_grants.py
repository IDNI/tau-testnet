"""Grants, refunds, shared caps, condition combination, capability
reporting, and book/governance integration (Bounty 01, stages 4/5).

Written only from the public APIs in ``consensus/payments.py``,
``consensus/periods.py`` and ``consensus/governance.py``.
Deterministic, no native bindings.
"""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone

import pytest

from consensus.governance import (
    ConsensusLifecycleManager,
    build_mechanism_metadata,
)
from consensus.payments import (
    FEE_SINK_PUBKEY,
    GRANT_ESCROW_PUBKEY,
    MAX_CATCH_UP_LIMIT,
    MAX_PAYOUT_CANDIDATES,
    MAX_ROUTE_DESTINATIONS,
    DictLedger,
    FeeOracle,
    GrantBook,
    GrantTerms,
    PaymentRefused,
    PayoutTerms,
    ProgrammablePayments,
    RouteTerms,
    StandingTerms,
    capability_report,
    check_payment_envelope,
)


def pk(i: int) -> str:
    return f"{i:096x}"


def ts(year: int, month: int, day: int, hour: int = 0) -> int:
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


class FixedFee(FeeOracle):
    """FeeOracle subclass with a fixed fee."""

    def __init__(self, fee: int) -> None:
        self._fee = fee

    def execution_fee(self, payer: str, recipient: str, amount: int) -> int:
        return self._fee


# 1. gmikeyg case 5, with the addendum correction on the refund fee ---------


def test_grant_5000_returns_3800_after_1200_drawn():
    alice, bob = pk(1), pk(2)
    start = ts(2026, 12, 1)
    expires = ts(2027, 1, 1)
    ledger = DictLedger({alice: 10000})
    book = GrantBook()
    grant_id = book.create(
        GrantTerms(
            grantor=alice,
            grantee=bob,
            principal=5000,
            period_cap=500,
            period_kind="week",
            start_ts=start,
            expires_ts=expires,
            max_fee_per_execution=10,
        ),
        ledger=ledger,
    )
    # Principal is escrowed at create.
    assert ledger.balance(alice) == 5000
    assert ledger.balance(GRANT_ESCROW_PUBKEY) == 5000

    # Week 0: 300 + 200 = 500, exactly the period cap.
    assert book.draw(grant_id, 300, ts=ts(2026, 12, 1), ledger=ledger) == 300
    assert book.draw(grant_id, 200, ts=ts(2026, 12, 2), ledger=ledger) == 200
    with pytest.raises(PaymentRefused):
        book.draw(grant_id, 1, ts=ts(2026, 12, 2), ledger=ledger)

    # Week 1 and week 3 draws.
    assert book.draw(grant_id, 500, ts=ts(2026, 12, 8), ledger=ledger) == 500
    assert book.draw(grant_id, 200, ts=ts(2026, 12, 22), ledger=ledger) == 200

    acct = book.accounting(grant_id)
    assert acct["drawn"] == 1200
    assert acct["held"] == 3800
    assert acct["refunded"] == 0
    assert acct["principal"] == acct["drawn"] + acct["held"] + acct["refunded"]
    assert ledger.balance(bob) == 1200

    alice_before = ledger.balance(alice)
    records = book.sweep_refunds(ts=expires, ledger=ledger, fees=FixedFee(7))
    assert len(records) == 1
    record = records[0]
    assert record.grant_id == grant_id
    assert record.to == alice
    assert record.amount == 3800
    assert record.fee == 7

    # The 3800 is credited in full; the fee is NOT netted from it — it is
    # debited separately from Alice to the fee sink.
    assert ledger.balance(alice) == alice_before + 3800 - 7
    assert ledger.balance(FEE_SINK_PUBKEY) == 7
    assert ledger.balance(bob) == 1200
    assert ledger.balance(GRANT_ESCROW_PUBKEY) == 0

    # Exactly once: a second sweep refunds nothing more.
    assert book.sweep_refunds(ts=expires, ledger=ledger, fees=FixedFee(7)) == []

    acct = book.accounting(grant_id)
    assert acct["principal"] == 5000
    assert acct["drawn"] == 1200
    assert acct["held"] == 0
    assert acct["refunded"] == 3800
    assert 5000 == 1200 + 0 + 3800
    assert acct["principal"] == acct["drawn"] + acct["held"] + acct["refunded"]


# 2. Shared cap counted exactly once across 108 histories --------------------


def test_shared_cap_counts_exactly_once_across_108_histories():
    alice, bob, carol = pk(1), pk(2), pk(3)
    start = ts(2026, 12, 1)
    expires = start + 30 * 24 * 60 * 60

    histories = 0
    second_refused = 0
    naive_would_allow_over_500 = 0

    for first_idx in (0, 1):
        for first_amount in (100, 200, 300, 400, 500, 600):
            for second_amount in range(100, 1000, 100):  # 100..900 step 100
                histories += 1
                ledger = DictLedger({alice: 10000})
                book = GrantBook()
                book.set_shared_cap(alice, 500)
                grant_ids = []
                for grantee in (bob, carol):
                    grant_ids.append(
                        book.create(
                            GrantTerms(
                                grantor=alice,
                                grantee=grantee,
                                principal=2000,
                                period_cap=2000,
                                period_kind="week",
                                start_ts=start,
                                expires_ts=expires,
                                max_fee_per_execution=10,
                                per_payment_cap=None,
                                shared_cap=True,
                            ),
                            ledger=ledger,
                        )
                    )
                first_id = grant_ids[first_idx]
                second_id = grant_ids[1 - first_idx]

                try:
                    book.draw(first_id, first_amount, ts=start, ledger=ledger)
                except PaymentRefused:
                    pass
                second_was_refused = False
                try:
                    book.draw(second_id, second_amount, ts=start, ledger=ledger)
                except PaymentRefused:
                    second_was_refused = True
                if second_was_refused:
                    second_refused += 1

                total_drawn = sum(
                    book.accounting(gid)["drawn"] for gid in grant_ids
                )
                assert total_drawn <= 500
                shared = book.shared_cap_state(alice)
                assert shared is not None
                assert shared.spent == total_drawn

                # Naive per-grant-counter model, computed inline: each
                # grant independently capped at 500 would allow both
                # draws whenever each one individually is <= 500, even
                # when their sum exceeds the shared 500.
                if (
                    first_amount <= 500
                    and second_amount <= 500
                    and first_amount + second_amount > 500
                ):
                    naive_would_allow_over_500 += 1

    assert histories == 108
    # The test has teeth: the real shared cap refuses some second draws,
    # and the naive model would have let the total exceed 500 somewhere.
    assert second_refused > 0
    assert naive_would_allow_over_500 > 0


# 3. Grant draw window / caps -------------------------------------------------


def test_grant_draw_window_enforced():
    alice, bob = pk(1), pk(2)
    start = ts(2026, 12, 1)
    expires = start + 30 * 24 * 60 * 60

    ledger = DictLedger({alice: 10000})
    book = GrantBook()
    grant_id = book.create(
        GrantTerms(
            grantor=alice,
            grantee=bob,
            principal=1000,
            period_cap=1000,
            period_kind="week",
            start_ts=start,
            expires_ts=expires,
            max_fee_per_execution=10,
            per_payment_cap=100,
        ),
        ledger=ledger,
    )

    # Before the start.
    with pytest.raises(PaymentRefused):
        book.draw(grant_id, 10, ts=start - 1, ledger=ledger)
    # At and after the expiry.
    with pytest.raises(PaymentRefused):
        book.draw(grant_id, 10, ts=expires, ledger=ledger)
    with pytest.raises(PaymentRefused):
        book.draw(grant_id, 10, ts=expires + 1, ledger=ledger)
    # Per-payment cap, when set.
    with pytest.raises(PaymentRefused):
        book.draw(grant_id, 101, ts=start, ledger=ledger)
    assert book.draw(grant_id, 100, ts=start, ledger=ledger) == 100

    # Exceeding the remaining held principal (separate grant with no
    # per-payment cap and a period cap large enough not to interfere).
    ledger2 = DictLedger({alice: 10000})
    book2 = GrantBook()
    grant2 = book2.create(
        GrantTerms(
            grantor=alice,
            grantee=bob,
            principal=1000,
            period_cap=5000,
            period_kind="week",
            start_ts=start,
            expires_ts=expires,
            max_fee_per_execution=10,
            per_payment_cap=None,
        ),
        ledger=ledger2,
    )
    with pytest.raises(PaymentRefused):
        book2.draw(grant2, 1001, ts=start, ledger=ledger2)
    assert book2.draw(grant2, 1000, ts=start, ledger=ledger2) == 1000
    with pytest.raises(PaymentRefused):
        book2.draw(grant2, 1, ts=start, ledger=ledger2)


# 4. How conditions combine ---------------------------------------------------


def test_combination_conflict_names_pair():
    recipient = pk(3)
    locked_route = RouteTerms(
        owner=recipient,
        destinations=((pk(4), 5000),),
        locked=True,
        expires_ts=ts(2027, 1, 1),
    )
    payout_excluding = PayoutTerms(
        owner=pk(5),
        candidates=((pk(6), 1000), (pk(7), 1000)),
        max_per_execution=1000,
        max_per_period=1000,
    )
    payout_including = PayoutTerms(
        owner=pk(5),
        candidates=((recipient, 1000), (pk(7), 1000)),
        max_per_execution=1000,
        max_per_period=1000,
    )

    # Sender policy refuses.
    result = check_payment_envelope(
        policy_allows=False,
        route=None,
        payout_terms=None,
        recipient=recipient,
    )
    assert result is not None
    assert "sender policy" in result

    # Order: the policy refusal wins even when a route conflict also exists.
    result = check_payment_envelope(
        policy_allows=False,
        route=locked_route,
        payout_terms=None,
        recipient=recipient,
        requires_direct_credit=True,
    )
    assert result is not None
    assert "sender policy" in result
    assert "recipient route" not in result

    # Locked route + direct-credit requirement names BOTH sides of the pair.
    result = check_payment_envelope(
        policy_allows=True,
        route=locked_route,
        payout_terms=None,
        recipient=recipient,
        requires_direct_credit=True,
    )
    assert result is not None
    assert "sender policy" in result
    assert "recipient route" in result

    # Payout candidate set excludes the recipient.
    result = check_payment_envelope(
        policy_allows=True,
        route=None,
        payout_terms=payout_excluding,
        recipient=recipient,
    )
    assert result is not None
    assert "payout" in result

    # All compatible: no refusal.
    assert (
        check_payment_envelope(
            policy_allows=True,
            route=locked_route,
            payout_terms=payout_including,
            recipient=recipient,
            requires_direct_credit=False,
        )
        is None
    )
    assert (
        check_payment_envelope(
            policy_allows=True,
            route=None,
            payout_terms=None,
            recipient=recipient,
        )
        is None
    )


# 5. Capability reporting -------------------------------------------------------


def test_capability_reports_schedule_and_route_semantics():
    report = capability_report()

    schedule = report["standing_payments"]["schedule_semantics"]
    assert schedule["month_end_rule"] == "last_day_of_shorter_month"
    assert schedule["anchor_drift_after_short_month"] is False
    assert schedule["missed_period_default"] == "skip"
    assert schedule["max_catch_up_bound"] == 3
    assert schedule["max_catch_up_bound"] == MAX_CATCH_UP_LIMIT

    routing = report["receive_routing"]
    assert routing["max_destinations"] == 4
    assert routing["max_destinations"] == MAX_ROUTE_DESTINATIONS
    assert set(routing["routable_credit_classes"]) == {
        "plain_transfer",
        "claimed_payment",
    }
    assert "floor" in routing["rounding"]
    assert "one_fee" in routing["fee_semantics"]

    payouts = report["rule_payouts"]
    assert payouts["max_candidates"] == 8
    assert payouts["max_candidates"] == MAX_PAYOUT_CANDIDATES
    assert "candidate" in payouts["recipient_selection"]


# 6. Book root gating, restore, deepcopy isolation ------------------------------


def test_payments_books_root_gating_and_restore():
    # Default mechanism metadata carries no programmable-payments root.
    default_meta = build_mechanism_metadata("supermajority")
    assert "programmable_payments_root" not in default_meta

    # Two fresh managers hash identically.
    manager = ConsensusLifecycleManager()
    other = ConsensusLifecycleManager()
    assert manager.consensus_meta_hash() == other.consensus_meta_hash()
    assert manager.programmable_payments.is_empty()

    # Adding a route to the manager's books changes the meta hash.
    hash_before_route = manager.consensus_meta_hash()
    manager.programmable_payments.routes.install(
        RouteTerms(
            owner=pk(3),
            destinations=((pk(4), 5000),),
        )
    )
    assert manager.consensus_meta_hash() != hash_before_route
    assert not manager.programmable_payments.is_empty()

    # Restore round-trip for a container with one entry in each book.
    # The standing book is network-bound, so build it standalone.
    network_id = "ab" * 32
    start = ts(2026, 12, 1)
    books = ProgrammablePayments(network_id=network_id)
    books.standing.create(
        StandingTerms(
            payer=pk(1),
            payee=pk(2),
            amount=100,
            period_kind="week",
            start_ts=start,
            end_kind="count",
            end_value=3,
            max_fee_per_execution=10,
            genesis_hash=network_id,
        )
    )
    books.routes.install(
        RouteTerms(owner=pk(3), destinations=((pk(4), 5000),))
    )
    books.payouts.install(
        PayoutTerms(
            owner=pk(5),
            candidates=((pk(6), 1000),),
            max_per_execution=500,
            max_per_period=1000,
            clause="o30 = 1:bv[64]",
        )
    )
    grant_ledger = DictLedger({pk(7): 10000})
    books.grants.create(
        GrantTerms(
            grantor=pk(7),
            grantee=pk(8),
            principal=1000,
            period_cap=500,
            period_kind="week",
            start_ts=start,
            expires_ts=start + 30 * 24 * 60 * 60,
            max_fee_per_execution=10,
        ),
        ledger=grant_ledger,
    )
    assert not books.is_empty()
    restored = ProgrammablePayments.restore(books.snapshot_rows())
    assert restored.root() == books.root()

    # Deepcopy isolation: cancelling an authorization in a fork of the
    # manager leaves the original's authorization active.
    auth_id = manager.programmable_payments.standing.create(
        StandingTerms(
            payer=pk(1),
            payee=pk(2),
            amount=100,
            period_kind="week",
            start_ts=start,
            end_kind="count",
            end_value=3,
            max_fee_per_execution=10,
            genesis_hash="cd" * 32,
        )
    )
    fork = deepcopy(manager)
    fork.programmable_payments.standing.cancel(auth_id, signer=pk(1))
    fork_state = fork.programmable_payments.standing.get(auth_id)
    assert fork_state is not None
    assert fork_state.status == "cancelled"
    original_state = manager.programmable_payments.standing.get(auth_id)
    assert original_state is not None
    assert original_state.status == "active"
