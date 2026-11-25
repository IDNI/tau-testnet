"""Arrival settlements are bounded by the gross credit (issue #35).

A receive route divides what arrived: its legs are computed from
the gross credit and may not exceed it, however much balance the
owner already holds, and across all of the owner's on-arrival
rules one credit's shares sum to at most the credit. A route
whose legs exceed what is left of the credit settles nothing on
it -- the credit still lands whole; a trigger never fails the
crediting transaction. The clock trigger is not bounded this
way: a standing payment settles from the balance by design.

Authored 2026-11-25 against PR #179 head 4dd600f54772; NOT run
yet (see fix-arrival-gross-cap-README-2026-11-25.md). The Chain
harness is the one in tests/test_payout_triggers.py.
"""

from tests.test_payout_triggers import (
    ALICE, BOB, CAROL, MALLORY, PROPOSER,
    SK_ALICE, SK_BOB, Chain, _pct, install_tx, transfer_tx,
)
from consensus.payouts import (
    PAYOUT_STREAM_INDEX, arrival_settlement_id, parse_payout_install,
)


def _fixed(amount):
    """Legs for a clause paying a fixed amount to recipient 0,
    whatever the gross (i1) says."""
    def legs(vals):
        return {20: "1", 21: str(amount), 22: "0"}
    return legs


def _install_multi(ch, owner, sk, *, height, seq=0, **kw):
    """Install a further rule on an owner who already holds one.

    The stage-1 harness helper (Chain.install_rule) closes by
    asserting book.get(owner), which reads the owner's ONLY rule
    and is None once two rules are installed; this is the stage-2
    idiom of tests/test_payout_stage2_apply.py::_install.
    """
    ch.lm.rule_offers.accepted_clauses[(owner, PAYOUT_STREAM_INDEX)] = (
        "always (o20[t] = 1)."
    )
    tx = install_tx(owner=owner, sk=sk, seq=seq, **kw)
    ch.block([tx], height=height)
    assert ch.accepted(tx), ch.receipt(tx)
    terms = parse_payout_install(tx)
    assert ch.book.get_rule(owner, terms.rule_id) is not None
    return terms


def test_a_fixed_leg_larger_than_the_credit_settles_nothing():
    # The clause would pay 500 on any arrival; a 101 credit cannot
    # fund it out of the credit, and the route may not draw on the
    # 1,000 the owner already holds. Pre-fix this settled 500.
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, MALLORY: 0,
                PROPOSER: 0})
    ch.install_rule(BOB, SK_BOB, height=20, recipients=[CAROL],
                    extra={"on_arrival": True})
    ch.legs_fn = _fixed(500)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 0
    assert ch.bal[BOB] == 1_000 + 101
    assert ch.book.get(BOB).settlements == []


def test_a_fixed_leg_within_the_credit_still_settles():
    # The bound is the credit, not a ban on fixed legs: a fixed 50
    # on a 101 credit settles as before.
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0,
                PROPOSER: 0})
    ch.install_rule(BOB, SK_BOB, height=20, recipients=[CAROL],
                    extra={"on_arrival": True})
    ch.legs_fn = _fixed(50)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 50
    assert ch.bal[BOB] == 101 - 50
    assert ch.book.get(BOB).settlements == [
        arrival_settlement_id(tx["tx_id"])]


def test_two_routes_on_one_credit_share_the_gross_budget():
    # Stage 2: two on-arrival rules on one owner. Each clause pays
    # 60% of the gross; together they may not pay 120% of it. The
    # first settles 60 of 101 (floored); the second finds only 41
    # left of the credit and settles nothing. The owner starts
    # funded: on an empty account the staged-balance check alone
    # masks the multiplication (the second route's legs exceed the
    # balance the first route left), so the routes must be stopped
    # by the credit itself, not by an empty till. Pre-fix both
    # routes settle, 120 in all.
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, MALLORY: 0,
                PROPOSER: 0})
    ch.install_rule(BOB, SK_BOB, height=20, recipients=[CAROL],
                    extra={"on_arrival": True})
    _install_multi(ch, BOB, SK_BOB, height=20, seq=1, recipients=[CAROL],
                   extra={"on_arrival": True})
    ch.legs_fn = _pct(60)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 60
    assert ch.bal[BOB] == 1_000 + 101 - 60
    settled = [s for state in ch.book.rules_of(BOB)
               for s in state.settlements]
    assert settled == [arrival_settlement_id(tx["tx_id"])]
