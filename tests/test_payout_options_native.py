"""The optional terms and the two kept clocks of a payout rule, on the REAL Tau engine.

The grant of test_payout_conditions_native.py again, with what its rule could
not say there:

    periods_from   "500 a week from 1 December" counts its weeks from 1 December,
                   whenever the rule was installed
    due_at         what Bob has not spent goes back to Alice at the deadline with
                   nobody's transaction: the node runs the rule itself
    i48            "locked for six hours after it was set up"
    i49            "goes back if unused for 30 days"

The rule text of the grant is the same; only its signed terms gain two numbers.
The due run goes through the engine's own end-of-block function.

Skipped where the native module is not built.
"""
import types

import pytest

from consensus import sender_policy
from consensus.engine import _run_due_payouts
from consensus.payout import (
    PayoutBook,
    PayoutExecution,
    POOL_APPLY,
    execution_inputs,
    parse_payout_rule_set,
    screen_payout_body,
    settle,
)

from tests.test_payout_conditions_native import (  # noqa: F401  (`real` is a fixture)
    ALICE, AMOUNT, ASKED, BOB, CAP, DAY, DEADLINE, GRANT, GRANT_5000, HOLDS, NOW, PAID, SHOP,
    START, STRANGER, WEEK, Grant, _is, _pays, _utc, c, pytestmark, real,
)

THURSDAY = _utc(2026, 11, 26)                # the install: not the weekday of the start
HOUR = 3_600
INSTALLED_AT, LAST_PAID = "i48[t]:bv[64]", "i49[t]:bv[64]"


class Dated(Grant):
    """The grant account with optional terms, and the block the node is at."""

    def __init__(self, rule=GRANT_5000, amount=AMOUNT, installed=THURSDAY, **optional):
        self.terms = parse_payout_rule_set({
            "sender_pubkey": GRANT, "sequence_number": 0, "rule_text": rule,
            "slots": ["", ALICE], "cap_per_execution": amount, "cap_per_period": 2 * amount,
            "period_seconds": WEEK, "expires_at": DEADLINE + 52 * WEEK, **optional,
        })
        self.book = PayoutBook()
        self.book.install(self.terms, installed)
        self.balance = amount
        self.height = 1_000
        self.others = {}

    def end_of_block(self, at, same_block=False):
        """What the node does by itself at the end of the block at time `at`."""
        self.height += 0 if same_block else 1
        lm = types.SimpleNamespace(payout_rules=self.book, faucet_amount=0)
        balances = dict(self.others, **{GRANT: self.balance})
        sequences = {key: 0 for key in balances}
        events = _run_due_payouts(lm, balances, sequences, None, self.height, at)
        self.balance = balances.pop(GRANT)
        self.others = balances
        return events


# --- periods from a date -----------------------------------------------------------------


def test_the_weeks_count_from_1_december_not_from_the_install(real):
    grant = Dated(periods_from=START)
    assert grant.execute(BOB, START + DAY, 500) == {SHOP: 500}            # Wednesday 2 Dec
    # Thursday 3 December is a week after the install; the cap does not come back.
    assert grant.refused(BOB, _utc(2026, 12, 3), 1)
    assert grant.refused(BOB, START + WEEK - 1, 1)
    assert grant.execute(BOB, START + WEEK, 500) == {SHOP: 500}           # Tuesday 8 Dec
    assert grant.refused(BOB, _utc(2026, 12, 10), 1)                      # a Thursday again
    assert grant.execute(BOB, START + 2 * WEEK, 500) == {SHOP: 500}


def test_without_the_term_the_same_rule_counts_from_the_install(real):
    grant = Dated()
    assert grant.execute(BOB, START + DAY, 500) == {SHOP: 500}
    assert grant.execute(BOB, _utc(2026, 12, 3), 500) == {SHOP: 500}      # install + 1 week


def test_the_install_day_does_not_move_the_weeks(real):
    for installed in (_utc(2026, 11, 20), THURSDAY, START - 1):
        grant = Dated(installed=installed, periods_from=START)
        assert grant.execute(BOB, START, 500) == {SHOP: 500}
        assert grant.refused(BOB, START + WEEK - 1, 1)
        assert grant.execute(BOB, START + WEEK, 500) == {SHOP: 500}


# --- the node runs the rule at the deadline ------------------------------------------------


def test_the_5000_grant_returns_what_is_left_without_anyones_transaction(real):
    grant = Dated(periods_from=START, due_at=DEADLINE)
    for week in range(3):
        assert grant.execute(BOB, START + week * WEEK + HOUR, 500) == {SHOP: 500}
    assert grant.end_of_block(DEADLINE - 1) == []                         # not due yet
    event, = grant.end_of_block(DEADLINE + 7)                             # the first block after
    assert event["outcome"] == "executed" and event["executor_pubkey"] is None
    assert event["legs"] == [{"slot": 1, "recipient_pubkey": ALICE, "amount": 3_500}]
    assert grant.balance == 0 and grant.others == {ALICE: 3_500}
    assert grant.end_of_block(DEADLINE + 20) == []                        # once
    assert grant.refused(BOB, DEADLINE + 30, 1)


def test_untouched_money_returns_in_full_by_itself(real):
    grant = Dated(periods_from=START, due_at=DEADLINE)
    event, = grant.end_of_block(DEADLINE)
    assert event["total"] == AMOUNT and grant.others == {ALICE: AMOUNT}


def test_the_run_returns_exactly_the_rest_after_a_last_spend(real):
    grant = Dated(periods_from=START, due_at=DEADLINE)
    assert grant.execute(BOB, DEADLINE - 1, 500) == {SHOP: 500}           # the block before
    event, = grant.end_of_block(DEADLINE)
    assert event["total"] == AMOUNT - 500 and grant.balance == 0


def test_a_spend_in_the_deadline_block_goes_back_and_the_run_finds_nothing(real):
    """In the block that reaches the deadline the rule already answers Bob's
    execution with the return. The node's own run comes after the block's
    transactions, finds nothing left, pays nothing, and is done."""
    grant = Dated(periods_from=START, due_at=DEADLINE)
    assert grant.execute(BOB, DEADLINE, 100) == {ALICE: AMOUNT}
    event, = grant.end_of_block(DEADLINE, same_block=True)
    assert event["outcome"] == "due_not_paid" and "pays nothing" in event["reason"]
    assert grant.balance == 0 and grant.end_of_block(DEADLINE + 1) == []


def test_a_due_run_cannot_be_turned_into_a_spend(real):
    """The node names no executor and no payee. The rule's own first line asks for
    Bob, so before the deadline a run by the node pays nobody."""
    early = Dated(due_at=START + DAY)             # a due point inside the spending time
    event, = early.end_of_block(START + DAY)
    assert event["outcome"] == "due_not_paid" and "pays nothing" in event["reason"]
    assert early.balance == AMOUNT and early.others == {}
    assert early.execute(BOB, START + DAY + 1, 500) == {SHOP: 500}        # Bob still can


def test_the_return_does_not_wait_for_a_stranger_but_a_stranger_may_still_send_it(real):
    grant = Dated(periods_from=START)             # no due point: as before
    assert grant.end_of_block(DEADLINE + 5) == []
    assert grant.execute(STRANGER, DEADLINE + 6) == {ALICE: AMOUNT}


# --- the two clocks ----------------------------------------------------------------------


def _fits(cap):
    return f"({ASKED} <= {c(cap)}) && ({PAID} <= {c(cap)}) && ({ASKED} <= ({c(cap)} - {PAID}))"


def held(hours, cap=CAP):
    """Bob may spend once the money has been set up for `hours` hours."""
    ready = f"({NOW} >= ({INSTALLED_AT} + {c(hours * HOUR, 64)}))"
    return (f"always ( ({_is(BOB)} && {ready} && {_fits(cap)}) "
            f"? {_pays(ASKED, c(0))} : {_pays(c(0), c(0))} ).")


def idle(days, cap=CAP):
    """Bob spends under the cap; after `days` days without a paid execution what is
    left goes back to Alice, whoever sends the execution."""
    unused = f"({NOW} >= ({LAST_PAID} + {c(days * DAY, 64)}))"
    return (f"always ( {unused} ? {_pays(c(0), HOLDS)} : "
            f"( ({_is(BOB)} && {_fits(cap)}) ? {_pays(ASKED, c(0))} : {_pays(c(0), c(0))} ) ).")


def test_both_rules_pass_the_screen_and_build(real):
    for rule in (held(6), idle(30)):
        terms = Dated(rule).terms
        assert terms.reads_clocks and screen_payout_body(terms.body, 2) is None
        built = real.validate(terms.body)
        assert built.ok, built.error


def test_locked_for_six_hours_after_it_was_set_up(real):
    grant = Dated(held(6))
    assert grant.refused(BOB, THURSDAY + 1, 100)
    assert grant.refused(BOB, THURSDAY + 6 * HOUR - 1, 100)
    assert grant.execute(BOB, THURSDAY + 6 * HOUR, 100) == {SHOP: 100}
    assert grant.refused(STRANGER, THURSDAY + 7 * HOUR, 100)


def test_the_lock_counts_from_each_install(real):
    for installed in (THURSDAY, START, START + 12_345):
        grant = Dated(held(6), installed=installed)
        assert grant.refused(BOB, installed + 6 * HOUR - 1, 100)
        assert grant.execute(BOB, installed + 6 * HOUR, 100) == {SHOP: 100}


def test_unused_for_30_days_goes_back(real):
    grant = Dated(idle(30))
    assert grant.execute(BOB, THURSDAY + 10 * DAY, 300) == {SHOP: 300}
    last = THURSDAY + 10 * DAY
    assert grant.refused(STRANGER, last + 30 * DAY - 1)           # 29 days and a bit: not yet
    assert grant.execute(BOB, last + 20 * DAY, 100) == {SHOP: 100}        # a spend restarts it
    last += 20 * DAY
    assert grant.refused(STRANGER, last + 30 * DAY - 1)
    assert grant.execute(STRANGER, last + 30 * DAY) == {ALICE: AMOUNT - 400}
    assert grant.balance == 0


def test_never_used_goes_back_30_days_after_the_install(real):
    grant = Dated(idle(30))
    assert grant.refused(STRANGER, THURSDAY + 30 * DAY - 1)
    assert grant.execute(BOB, THURSDAY + 30 * DAY, 100) == {ALICE: AMOUNT}    # even Bob's ask


def test_the_rule_is_handed_the_clocks_the_book_keeps(real):
    grant = Dated(idle(30))
    exe = PayoutExecution(BOB, GRANT, grant.terms.rule_id, ((0, SHOP),), ((0, 5),))
    state = grant.book.state_of(GRANT)
    values = execution_inputs(grant.terms, state, exe, parent_balance=1, height=7, ts=THURSDAY + 9)
    assert (values[48], values[49]) == (str(THURSDAY), str(THURSDAY))
    assert grant.execute(BOB, THURSDAY + 50, 5) == {SHOP: 5}
    state = grant.book.state_of(GRANT)
    values = execution_inputs(grant.terms, state, exe, parent_balance=1, height=8, ts=THURSDAY + 99)
    assert (values[48], values[49]) == (str(THURSDAY), str(THURSDAY + 50))
    # and the engine's answer moves with them: `settle` on its outputs
    outputs = sender_policy.payout_outputs(grant.terms.body, values, pool=POOL_APPLY)
    assert settle(grant.terms, state, exe, outputs, height=8, ts=THURSDAY + 99,
                  balance=10) == [(0, SHOP, 5)]
