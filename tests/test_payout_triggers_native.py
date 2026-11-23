"""Three ways a payout rule is started, on the REAL Tau engine.

A recurring payment and a share routed from each incoming payment, each as ONE
Tau rule on the payout path, with the node code of `consensus/payout.py` and
nothing else. The node decides only when it asks the rule: at the signed due
points, and when a payment arrives. What is paid, to whom and under which
condition is the rule's answer.

    rent            100 on the 31st of each month; the last day of a shorter month
    allowance       a part of what the account holds, every 256 blocks
    route           a fifth of every payment that arrives
    route + floor   only payments of 50 or more are shared
    two shares      a fifth to one key and a twentieth to another
    not from Carol  payments from one named payer are not shared
    until a date    the share stops at a date; the rule goes on unchanged

Every one of these is a different rule text on the same two engine functions.
The runs go through the engine's own end-of-block functions.

Skipped where the native module is not built.
"""
import random
import types

import pytest

from consensus.engine import _run_arrival_payouts, _run_due_payouts
from consensus.payout import (
    MIN_DUE_EVERY_BLOCKS,
    PayoutBook,
    parse_payout_rule_set,
    screen_payout_body,
    validate_terms_shape,
)

from tests.test_payout_conditions_native import (  # noqa: F401  (`real` is a fixture)
    ALICE, BOB, DAY, GRANT, GRANT_5000, HOLDS, NOW, SHOP, STRANGER, _is, _key, _utc, c,
    pytestmark, real,
)

CAROL = _key("carol")
JAN31 = _utc(2026, 1, 31)
NOBODY = "(i13[t]:bv[384] = { 0 }:bv[384])"
SALE, PAYER = "i27[t]:bv[24]", "i28[t]:bv[384]"


def _only_the_node(amount):
    """`amount` to slot 0 when the node itself runs the rule, nothing for anyone else."""
    return (f"always ( {NOBODY} ? (o30[t]:bv[24] = {amount}) "
            f": (o30[t]:bv[24] = {c(0)}) ).")


RENT = _only_the_node(c(100))
ALLOWANCE = _only_the_node(f"({HOLDS} / {c(10)})")          # a tenth of what is there
ROUTE = f"always ( o30[t]:bv[24] = {SALE} / {c(5)} )."
FLOOR = (f"always ( ({SALE} >= {c(50)}) ? (o30[t]:bv[24] = {SALE} / {c(5)}) "
         f": (o30[t]:bv[24] = {c(0)}) ).")
TWO_SHARES = (f"always ( (o30[t]:bv[24] = {SALE} / {c(5)}) && "
              f"(o31[t]:bv[24] = {SALE} / {c(20)}) ).")
NOT_FROM_CAROL = (f"always ( ({PAYER} = {{ #x{CAROL} }}:bv[384]) ? (o30[t]:bv[24] = {c(0)}) "
                  f": (o30[t]:bv[24] = {SALE} / {c(5)}) ).")
UNTIL = _utc(2026, 6, 1)
UNTIL_A_DATE = (f"always ( ({NOW} < {c(UNTIL, 64)}) ? (o30[t]:bv[24] = {SALE} / {c(5)}) "
                f": (o30[t]:bv[24] = {c(0)}) ).")


class Account:
    """An account with one payout rule, and the blocks the node walks it through."""

    def __init__(self, rule, *, balance=1_000, slots=(BOB,), installed=None, height=1_000,
                 **signed):
        signed.setdefault("cap_per_execution", 10_000)
        signed.setdefault("cap_per_period", 1_000_000)
        if "period_blocks" not in signed:
            signed.setdefault("period_seconds", DAY)
        self.terms = parse_payout_rule_set({
            "sender_pubkey": ALICE, "sequence_number": 0, "rule_text": rule,
            "slots": list(slots), **signed})
        clock = height if "period_blocks" in signed else installed
        assert validate_terms_shape(self.terms, height, installed or 0) is None
        self.book = PayoutBook()
        self.book.install(self.terms, clock)
        self.balances = {ALICE: balance}
        self.height = height
        self.sales = 0

    def _run(self, fn, at):
        lm = types.SimpleNamespace(payout_rules=self.book, faucet_amount=0)
        sequences = {key: 0 for key in self.balances}
        return fn(lm, self.balances, sequences, None, self.height, at)

    def block(self, at=0, height=None):
        """The end of a block with no transactions: what the node runs by itself."""
        self.height = self.height + 1 if height is None else height
        return self._run(_run_arrival_payouts, at) + self._run(_run_due_payouts, at)

    def pays_in(self, amount, at=0, payer=STRANGER):
        """A block in which `payer` sends `amount`: the chain records the sale,
        credits the account, and the node makes its runs."""
        self.height += 1
        self.sales += 1
        noted = self.book.note_sale(ALICE, bytes([self.sales]) * 32, payer, amount,
                                    self.height, at)
        self.balances[ALICE] += amount
        events = self._run(_run_arrival_payouts, at)
        return noted, events

    def held(self, who=ALICE):
        return self.balances.get(who, 0)


def _paid(events):
    return [(e["outcome"], e.get("total", 0)) for e in events]


def test_the_rules_pass_the_screen_and_build(real):
    for rule, slots, per_sale in ((RENT, 1, False), (ALLOWANCE, 1, False), (ROUTE, 1, True),
                                  (FLOOR, 1, True), (TWO_SHARES, 2, True),
                                  (NOT_FROM_CAROL, 1, True), (UNTIL_A_DATE, 1, True)):
        body = parse_payout_rule_set({
            "sender_pubkey": ALICE, "sequence_number": 0, "rule_text": rule,
            "slots": [BOB, SHOP][:slots], "cap_per_execution": 1, "cap_per_period": 1,
            "period_seconds": DAY, "expires_at": 2, **({"per_sale": True} if per_sale else {}),
        }).body
        assert screen_payout_body(body, slots, per_sale) is None
        assert real.validate(body).ok


# --- the clock starts the rule ----------------------------------------------------------------


def _rent(**over):
    return Account(RENT, installed=_utc(2026, 1, 10), due_at=JAN31, due_months=1,
                   expires_at=_utc(2026, 12, 31), **over)


def test_rent_on_the_31st_is_paid_on_the_last_day_of_each_month(real):
    rent = _rent()
    paid = []
    for month, day in ((1, 30), (1, 31), (2, 1), (2, 27), (2, 28), (3, 30), (3, 31),
                       (4, 29), (4, 30), (5, 30), (5, 31)):
        events = rent.block(_utc(2026, month, day))
        paid.append(((month, day), sum(e.get("total", 0) for e in events)))
    assert [when for when, amount in paid if amount] == [(1, 31), (2, 28), (3, 31),
                                                         (4, 30), (5, 31)]
    assert all(amount in (0, 100) for _, amount in paid)
    assert (rent.held(), rent.held(BOB)) == (500, 500)


def test_a_block_late_in_the_day_still_pays_that_months_rent_once(real):
    rent = _rent()
    assert _paid(rent.block(JAN31 + 17 * 3_600)) == [("executed", 100)]
    assert rent.block(JAN31 + 18 * 3_600) == []
    assert rent.block(_utc(2026, 2, 27, 23)) == []
    assert _paid(rent.block(_utc(2026, 2, 28) + 5)) == [("executed", 100)]


def test_months_the_chain_slept_through_are_not_paid_later(real):
    rent = _rent()
    assert _paid(rent.block(_utc(2026, 4, 2))) == [("executed", 100)]     # January's, late
    assert rent.block(_utc(2026, 4, 3)) == []                             # Feb, Mar: gone
    assert _paid(rent.block(_utc(2026, 4, 30))) == [("executed", 100)]
    assert rent.held(BOB) == 200


def test_an_empty_account_owes_nothing_and_pays_again_when_it_holds_the_rent(real):
    rent = _rent(balance=40)
    event, = rent.block(JAN31)
    assert event["outcome"] == "due_not_paid" and "holds 40" in event["reason"]
    assert (rent.held(), rent.held(BOB)) == (40, 0)
    rent.balances[ALICE] += 500
    assert rent.block(_utc(2026, 2, 10)) == []                            # no making up
    assert _paid(rent.block(_utc(2026, 2, 28))) == [("executed", 100)]
    assert (rent.held(), rent.held(BOB)) == (440, 100)


def test_an_allowance_reads_the_balance_at_every_run(real):
    """Every 256 blocks a tenth of what the account holds: 100, then 90, then 81."""
    start = 1_000
    account = Account(ALLOWANCE, period_blocks=10, due_at=start + 6,
                      due_every=MIN_DUE_EVERY_BLOCKS, expires_at=start + 5_000, height=start)
    seen = []
    for k in range(3):
        assert account.block(height=start + 5 + k * MIN_DUE_EVERY_BLOCKS) == []
        events = account.block(height=start + 6 + k * MIN_DUE_EVERY_BLOCKS)
        seen.append(_paid(events))
    assert seen == [[("executed", 100)], [("executed", 90)], [("executed", 81)]]
    assert (account.held(), account.held(BOB)) == (729, 271)


# --- a payment starts the rule ------------------------------------------------------------------


def _routed(rule=ROUTE, **over):
    over.setdefault("slots", (BOB,))
    return Account(rule, installed=_utc(2026, 1, 10), per_sale=True, on_arrival=True,
                   expires_at=_utc(2026, 12, 31), **over)


def test_101_routed_at_a_fifth_gives_20_and_81(real):
    account = _routed(balance=0)
    noted, events = account.pays_in(101, _utc(2026, 2, 1))
    assert noted == "recorded" and _paid(events) == [("executed", 20)]
    assert events[0]["executor_pubkey"] is None
    assert (account.held(), account.held(BOB)) == (81, 20)
    assert account.book.state_of(ALICE).open_sales == ()
    assert account.block(_utc(2026, 2, 2)) == []                          # once


@pytest.mark.parametrize("seed", range(3))
def test_every_payment_is_split_by_the_floor_of_the_exact_share(real, seed):
    rng = random.Random(seed)
    account = _routed(balance=0)
    kept = shared = 0
    for n in range(12):
        amount = rng.choice([1, 4, 5, 9, 99, 100, 101, rng.randrange(1, 9_000)])
        _, events = account.pays_in(amount, _utc(2026, 2, 1) + n)
        share = amount // 5
        assert _paid(events) == ([("executed", share)] if share else [("arrival_not_paid", 0)])
        kept, shared = kept + amount - share, shared + share
    assert (account.held(), account.held(BOB)) == (kept, shared)
    assert not account.book.has_arrivals()


def test_a_floor_is_one_line_of_the_rule(real):
    account = _routed(FLOOR, balance=0)
    assert _paid(account.pays_in(49, _utc(2026, 2, 1))[1]) == [("arrival_not_paid", 0)]
    assert _paid(account.pays_in(50, _utc(2026, 2, 2))[1]) == [("executed", 10)]
    assert (account.held(), account.held(BOB)) == (89, 10)


def test_two_shares_are_paid_together(real):
    account = _routed(TWO_SHARES, balance=0, slots=(BOB, SHOP))
    _, (event,) = account.pays_in(200, _utc(2026, 2, 1))
    assert event["legs"] == [{"slot": 0, "recipient_pubkey": BOB, "amount": 40},
                             {"slot": 1, "recipient_pubkey": SHOP, "amount": 10}]
    assert (account.held(), account.held(BOB), account.held(SHOP)) == (150, 40, 10)


def test_the_rule_reads_who_paid(real):
    account = _routed(NOT_FROM_CAROL, balance=0)
    assert _paid(account.pays_in(100, _utc(2026, 2, 1), payer=CAROL)[1]) == [
        ("arrival_not_paid", 0)]
    assert _paid(account.pays_in(100, _utc(2026, 2, 2), payer=STRANGER)[1]) == [
        ("executed", 20)]
    assert (account.held(), account.held(BOB)) == (180, 20)


def test_a_share_that_stops_at_a_date(real):
    account = _routed(UNTIL_A_DATE, balance=0)
    assert _paid(account.pays_in(100, UNTIL - 1)[1]) == [("executed", 20)]
    assert _paid(account.pays_in(100, UNTIL)[1]) == [("arrival_not_paid", 0)]
    assert (account.held(), account.held(BOB)) == (180, 20)


def test_the_cap_of_the_rule_holds_for_a_run_on_arrival(real):
    account = _routed(balance=0, cap_per_execution=30, cap_per_period=30)
    _, (event,) = account.pays_in(500, _utc(2026, 2, 1))                  # a fifth is 100
    assert event["outcome"] == "arrival_not_paid" and "cap per execution" in event["reason"]
    assert _paid(account.pays_in(150, _utc(2026, 2, 1) + 1)[1]) == [("executed", 30)]
    _, (event,) = account.pays_in(5, _utc(2026, 2, 1) + 2)
    assert event["outcome"] == "arrival_not_paid" and "cap per period" in event["reason"]
    assert (account.held(), account.held(BOB)) == (625, 30)


# --- the sealed grant ------------------------------------------------------------------------


def test_the_5000_grant_sealed_returns_the_rest_and_the_key_never_mattered(real):
    from tests.test_payout_options_native import Dated, HOUR
    from tests.test_payout_conditions_native import DEADLINE, START, WEEK

    grant = Dated(periods_from=START, due_at=DEADLINE, sealed=True)
    assert grant.book.sealed(GRANT)
    assert grant.book.can_admit_revoke(GRANT)[0] is False
    for week in range(3):
        assert grant.execute(BOB, START + week * WEEK + HOUR, 500) == {SHOP: 500}
    event, = grant.end_of_block(DEADLINE)
    assert event["legs"] == [{"slot": 1, "recipient_pubkey": ALICE, "amount": 3_500}]
    assert grant.balance == 0 and grant.book.sealed(GRANT)
