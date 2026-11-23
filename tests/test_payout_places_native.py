"""Several payout rules per account, and a due point tried again, on the REAL Tau engine.

    two rents       100 to Bob and 30 to Carol on the 31st, two rules, one account
    two routes      a fifth of every payment, and a fifth of payments of 50 or more
    rent, retried   the rent finds the account short; the node runs it again in
                    later blocks and it is paid in the block that brings the money

Each rule is an ordinary rule text in its own place on the account; the node
code is `consensus/payout.py` and the engine's end-of-block functions, nothing
else. Skipped where the native module is not built.
"""
import types

from consensus.engine import _run_arrival_payouts, _run_due_payouts, _run_retry_payouts
from consensus.payout import PayoutBook, parse_payout_rule_set, payout_key, validate_terms_shape

from tests.test_payout_conditions_native import (  # noqa: F401  (`real` is a fixture)
    ALICE, BOB, DAY, STRANGER, _key, _utc, pytestmark, real,
)
from tests.test_payout_triggers_native import FLOOR, JAN31, RENT, ROUTE, _only_the_node, c

CAROL = _key("carol")
SMALL_RENT = _only_the_node(c(30))


class Account:
    """One account with rules in several places, and the blocks the node walks it through."""

    def __init__(self, *rules, balance=1_000, installed=_utc(2026, 1, 10)):
        self.book = PayoutBook()
        for index, (rule, slots, signed) in enumerate(rules):
            signed = dict(signed)
            signed.setdefault("cap_per_execution", 10_000)
            signed.setdefault("cap_per_period", 1_000_000)
            signed.setdefault("period_seconds", DAY)
            signed.setdefault("expires_at", _utc(2026, 12, 31))
            terms = parse_payout_rule_set({
                "sender_pubkey": ALICE, "sequence_number": index, "rule_text": rule,
                "slots": list(slots), **signed,
                **({"rule_index": index} if index else {})})
            assert validate_terms_shape(terms, 1_000, installed) is None
            self.book.install(terms, installed)
        self.balances = {ALICE: balance}
        self.height = 1_000
        self.sales = 0

    def _run(self, fn, at):
        lm = types.SimpleNamespace(payout_rules=self.book, faucet_amount=0)
        return fn(lm, self.balances, {k: 0 for k in self.balances}, None, self.height, at)

    def block(self, at, brings=0):
        """The end of a block that brought `brings` to the account by a transfer."""
        self.height += 1
        if brings:
            self.sales += 1
            self.book.note_sale(ALICE, bytes([self.sales]) * 32, STRANGER, brings,
                                self.height, at)
            self.balances[ALICE] += brings
        return (self._run(_run_arrival_payouts, at) + self._run(_run_due_payouts, at)
                + self._run(_run_retry_payouts, at))

    def held(self, who=ALICE):
        return self.balances.get(who, 0)


def _paid(events):
    return [(e.get("rule_index"), e["outcome"], e.get("total", 0)) for e in events]


def test_two_rents_in_two_places_are_paid_in_one_block(real):
    rents = Account((RENT, (BOB,), {"due_at": JAN31, "due_months": 1}),
                    (SMALL_RENT, (CAROL,), {"due_at": JAN31, "due_months": 1}))
    assert rents.book.keys_of(ALICE) == [ALICE, payout_key(ALICE, 1)]
    assert rents.block(_utc(2026, 1, 30)) == []
    assert _paid(rents.block(JAN31)) == [(None, "executed", 100), (1, "executed", 30)]
    assert _paid(rents.block(_utc(2026, 2, 28))) == [(None, "executed", 100), (1, "executed", 30)]
    assert (rents.held(), rents.held(BOB), rents.held(CAROL)) == (740, 200, 60)


def test_two_routes_share_each_payment_by_their_own_rule(real):
    routes = Account((ROUTE, (BOB,), {"per_sale": True, "on_arrival": True}),
                     (FLOOR, (CAROL,), {"per_sale": True, "on_arrival": True}))
    assert _paid(routes.block(_utc(2026, 2, 1), brings=100)) == [
        (None, "executed", 20), (1, "executed", 20)]
    assert _paid(routes.block(_utc(2026, 2, 2), brings=40)) == [
        (None, "executed", 8), (1, "arrival_not_paid", 0)]
    assert (routes.held(), routes.held(BOB), routes.held(CAROL)) == (1_092, 28, 20)


def test_a_short_rent_is_paid_in_the_block_that_brings_the_money(real):
    rent = Account((RENT, (BOB,), {"due_at": JAN31, "due_months": 1, "due_retry": 7 * DAY}),
                   balance=40)
    event, = rent.block(JAN31)
    assert event["outcome"] == "due_not_paid" and "holds 40" in event["reason"]
    assert event["retry_at"] == JAN31 + 1
    again, = rent.block(JAN31 + 3_600)
    assert (again["retry"], again["outcome"]) == (True, "due_not_paid")
    assert _paid(rent.block(JAN31 + 2 * DAY, brings=500)) == [(None, "executed", 100)]
    assert rent.block(JAN31 + 3 * DAY) == []                           # paid once
    assert (rent.held(), rent.held(BOB)) == (440, 100)


def test_a_rent_the_account_never_funds_in_time_is_not_paid_later(real):
    rent = Account((RENT, (BOB,), {"due_at": JAN31, "due_months": 1, "due_retry": DAY}),
                   balance=40)
    rent.block(JAN31)
    ended, = rent.block(JAN31 + 2 * DAY, brings=500)
    assert ended["outcome"] == "due_retry_ended"
    assert (rent.held(), rent.held(BOB)) == (540, 0)
    assert _paid(rent.block(_utc(2026, 2, 28))) == [(None, "executed", 100)]
