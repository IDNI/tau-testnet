"""Conditions on money, written as one payout rule, on the REAL Tau engine.

Alice gives Bob money he may spend only under her conditions: so much per week,
not before a date, only on some days and hours, and what he has not spent by a
deadline goes back to her. Here every one of these is a line of ONE Tau rule on
an account that holds nothing but that money (a grant account). The node code is
the payout path of `consensus/payout.py` and nothing else: no condition below
has a line of its own in the node.

    the money        the grant account's balance (the rule reads it as i2)
    who spends       the executor (i13) must be Bob; he names the payee (slot 0)
    how much         what he asks (i40), with what the rule paid this period (i26)
    when             the block's time (i5)
    what is left     goes to Alice (slot 1) once the deadline has passed, whoever
                     sends the execution

A second payment to Bob under the same cap is a second transfer into the same
grant account: one account, one rule, one count, so the cap is shared by
construction.

Skipped where the native module is not built.
"""
import calendar
import hashlib
import itertools
import os
import pathlib
import random

import pytest

import tau_policy
from consensus import sender_policy
from consensus.payout import (
    PayoutBook,
    PayoutExecution,
    PayoutRefused,
    POOL_APPLY,
    execution_inputs,
    parse_payout_rule_set,
    screen_payout_body,
    settle,
)


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = str(pathlib.Path(__file__).resolve().parent.parent)
TIMEOUT = 120.0


def _key(label):
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest() for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


def _utc(year, month, day, hour=0):
    return calendar.timegm((year, month, day, hour, 0, 0))


GRANT, ALICE, BOB, SHOP, STRANGER = (_key(n) for n in ("grant", "alice", "bob", "shop", "x"))
DAY, WEEK = 86_400, 7 * 86_400
INSTALLED = _utc(2026, 11, 24)               # a Tuesday; the weeks of the cap count from here
START, DEADLINE = _utc(2026, 12, 1), _utc(2026, 12, 29)
AMOUNT, CAP = 5_000, 500
PAYEE, BACK = 0, 1                           # the slots: whoever Bob names, and Alice


@pytest.fixture(scope="module")
def real():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=env, timeout=TIMEOUT)
    sender_policy.set_evaluator(POOL_APPLY, ev)
    yield ev
    sender_policy.set_evaluator(POOL_APPLY, None)
    ev.close()


# --- the rule ------------------------------------------------------------------------


def c(n, w=24):
    return "{ %d }:bv[%d]" % (n, w)


EXECUTOR, NOW = "i13[t]:bv[384]", "i5[t]:bv[64]"
HOLDS, PAID, ASKED = (f"i{n}[t]:bv[24]" for n in (2, 26, 40))


def _is(pubkey):
    return f"({EXECUTOR} = {{ #x{pubkey} }}:bv[384])"


def _pays(payee, back):
    return f"((o30[t]:bv[24] = {payee}) && (o31[t]:bv[24] = {back}))"


def conditions(*, cap, start=None, deadline, weekdays=None, hours=None):
    """Alice's conditions as one payout rule.

    weekdays: (first, last) with 0 = Monday; hours: (from, to), UTC, `to` excluded.
    """
    when = [f"({NOW} >= {c(start, 64)})"] if start is not None else []
    when.append(f"({NOW} < {c(deadline, 64)})")
    if weekdays is not None:
        day = f"((({NOW} / {c(DAY, 64)}) + {c(3, 64)}) % {c(7, 64)})"
        when.append(f"({day} >= {c(weekdays[0], 64)}) && ({day} <= {c(weekdays[1], 64)})")
    if hours is not None:
        hour = f"(({NOW} % {c(DAY, 64)}) / {c(3_600, 64)})"
        when.append(f"({hour} >= {c(hours[0], 64)}) && ({hour} < {c(hours[1], 64)})")
    # what the rule paid this period plus what is asked stays inside the cap; the
    # first two comparisons keep the subtraction from wrapping
    fits = f"({ASKED} <= {c(cap)}) && ({PAID} <= {c(cap)}) && ({ASKED} <= ({c(cap)} - {PAID}))"
    spend = f"({_is(BOB)} && {' && '.join(when)} && {fits})"
    over = f"({NOW} >= {c(deadline, 64)})"
    return (f"always ( {spend} ? {_pays(ASKED, c(0))} : "
            f"( {over} ? {_pays(c(0), HOLDS)} : {_pays(c(0), c(0))} ) ).")


GRANT_5000 = conditions(cap=CAP, start=START, deadline=DEADLINE)


class Grant:
    """A grant account holding Alice's money, with her rule installed."""

    def __init__(self, rule=GRANT_5000, amount=AMOUNT, installed=INSTALLED):
        self.terms = parse_payout_rule_set({
            "sender_pubkey": GRANT, "sequence_number": 0, "rule_text": rule,
            "slots": ["", ALICE],
            # the rule itself holds Bob to the cap; these bounds only have to let
            # the whole amount go back in one execution
            "cap_per_execution": amount, "cap_per_period": 2 * amount,
            "period_seconds": WEEK, "expires_at": DEADLINE + 52 * WEEK,
        })
        self.book = PayoutBook()
        self.book.install(self.terms, installed)
        self.balance = amount
        self.height = 1_000

    def execute(self, who, at, ask=0, payee=SHOP):
        """One execution at block time `at`: {recipient: amount}, or PayoutRefused."""
        self.height += 1
        named = ((PAYEE, payee),) if payee else ()
        exe = PayoutExecution(who, GRANT, self.terms.rule_id, named,
                              ((0, ask),) if ask else ())
        rule, state = self.book.check_execution(exe, self.height, at)
        values = execution_inputs(rule, state, exe, parent_balance=self.balance,
                                  height=self.height, ts=at)
        outputs = sender_policy.payout_outputs(rule.body, values, pool=POOL_APPLY)
        legs = settle(rule, state, exe, outputs, height=self.height, ts=at,
                      balance=self.balance)
        total = sum(amount for _, _, amount in legs)
        self.book.record(GRANT, total, self.height, at)
        self.balance -= total
        return {who: amount for _slot, who, amount in legs}

    def refused(self, who, at, ask=0, payee=SHOP, why="pays nothing"):
        before = self.balance
        with pytest.raises(PayoutRefused, match=why):
            self.execute(who, at, ask, payee)
        assert self.balance == before
        return True


def test_the_conditions_pass_the_screen_and_build(real):
    for rule in (GRANT_5000,
                 conditions(cap=CAP, deadline=DEADLINE),
                 conditions(cap=CAP, start=START, deadline=DEADLINE,
                            weekdays=(0, 4), hours=(9, 17))):
        terms = Grant(rule).terms
        assert screen_payout_body(terms.body, 2) is None
        built = real.validate(terms.body)
        assert built.ok, built.error


def test_the_guide_prints_this_rule():
    """The rule in docs/payout_rules.md ("Money with conditions") is the one tested
    here, character for character apart from line breaks."""
    guide = (pathlib.Path(REPO) / "docs" / "payout_rules.md").read_text()
    section = guide.split("## Money with conditions", 1)[1]
    printed = section.split("```", 2)[1].replace("<bob_pubkey>", BOB)
    squeeze = lambda text: "".join(text.split())                       # noqa: E731
    assert squeeze(printed) == squeeze(GRANT_5000)


# --- a cap per period ------------------------------------------------------------------


def test_bob_spends_up_to_the_cap_of_each_week(real):
    grant = Grant()
    week = START                     # 1 December is the start of a week of the cap
    assert grant.execute(BOB, week + 10, 300) == {SHOP: 300}
    assert grant.execute(BOB, week + 20, 200) == {SHOP: 200}
    assert grant.refused(BOB, week + 30, 1)                       # the week's 500 are spent
    assert grant.refused(BOB, week + WEEK - 1, 1)                 # to its last second
    assert grant.execute(BOB, week + WEEK, 500) == {SHOP: 500}    # the next week starts
    assert grant.balance == AMOUNT - 1_000


def test_one_spend_over_the_cap_moves_nothing(real):
    grant = Grant()
    assert grant.refused(BOB, START, CAP + 1)
    assert grant.execute(BOB, START, 499) == {SHOP: 499}
    assert grant.refused(BOB, START + 1, 2)                       # 499 + 2 > 500
    assert grant.execute(BOB, START + 2, 1) == {SHOP: 1}


def test_nothing_carries_over(real):
    grant = Grant()
    assert grant.execute(BOB, START, 100) == {SHOP: 100}          # 400 of week one unused
    assert grant.refused(BOB, START + WEEK, CAP + 1)              # week two is 500, not 900
    assert grant.execute(BOB, START + WEEK, CAP) == {SHOP: CAP}


def test_only_bob_spends_and_he_names_the_payee(real):
    grant = Grant()
    for who in (ALICE, STRANGER, SHOP, GRANT):
        assert grant.refused(who, START, 100)
    assert grant.refused(BOB, START, 100, payee=None, why="no recipient was named")
    assert grant.execute(BOB, START, 100, payee=BOB) == {BOB: 100}     # to himself
    assert grant.execute(BOB, START, 100, payee=STRANGER) == {STRANGER: 100}


def test_bob_never_spends_more_than_the_account_holds(real):
    grant = Grant(amount=700)
    assert grant.execute(BOB, START, 500) == {SHOP: 500}
    assert grant.refused(BOB, START + WEEK, 201, why="the account holds 200")
    assert grant.execute(BOB, START + WEEK, 200) == {SHOP: 200}
    assert grant.balance == 0


def test_each_payment_and_each_recipient_has_its_own_cap(real):
    """A cap is a number in a rule, and every grant account has its own rule: 500 a
    week for Bob from one account, 200 a week from another, each counted alone."""
    wide, narrow = Grant(), Grant(conditions(cap=200, start=START, deadline=DEADLINE))
    assert wide.execute(BOB, START, 500) == {SHOP: 500}
    assert narrow.refused(BOB, START, 201)
    assert narrow.execute(BOB, START, 200) == {SHOP: 200}
    assert narrow.refused(BOB, START + 1, 1) and wide.refused(BOB, START + 1, 1)


# --- a start, a deadline, days and hours -------------------------------------------------


def test_nothing_before_the_start(real):
    grant = Grant()
    assert grant.refused(BOB, INSTALLED + 1, 100)
    assert grant.refused(BOB, START - 1, 100)
    assert grant.execute(BOB, START, 100) == {SHOP: 100}


def test_only_on_working_days_in_office_hours(real):
    """Monday to Friday, 09:00 to 17:00 UTC. 1 December 2026 is a Tuesday."""
    grant = Grant(conditions(cap=CAP, start=START, deadline=DEADLINE,
                             weekdays=(0, 4), hours=(9, 17)))
    tuesday = START
    assert grant.refused(BOB, tuesday + 8 * 3_600 + 3_599, 10)         # 08:59:59
    assert grant.execute(BOB, tuesday + 9 * 3_600, 10) == {SHOP: 10}   # 09:00:00
    assert grant.execute(BOB, tuesday + 16 * 3_600 + 3_599, 10) == {SHOP: 10}
    assert grant.refused(BOB, tuesday + 17 * 3_600, 10)                # 17:00:00
    saturday, sunday, monday = (tuesday + n * DAY + 12 * 3_600 for n in (4, 5, 6))
    assert grant.refused(BOB, saturday, 10)
    assert grant.refused(BOB, sunday, 10)
    assert grant.execute(BOB, monday, 10) == {SHOP: 10}


# --- what is left goes back --------------------------------------------------------------


def test_the_5000_grant_500_a_week_from_1_december_and_the_rest_returns_at_the_deadline(real):
    """The example of the program page as one rule: Alice gives Bob 5,000, at most
    500 a week, from 1 December, and what he has not spent by the deadline returns
    to her. Bob spends 500 in each of three weeks; 3,500 go back."""
    grant = Grant()
    assert grant.refused(BOB, START - 1, 500)
    for n in range(3):
        assert grant.execute(BOB, START + n * WEEK + 3_600, 500) == {SHOP: 500}
        assert grant.refused(BOB, START + n * WEEK + 7_200, 1)
    assert grant.refused(ALICE, DEADLINE - 1)                     # not a second early
    assert grant.balance == 3_500
    assert grant.execute(STRANGER, DEADLINE, payee=None) == {ALICE: 3_500}
    assert grant.balance == 0
    assert grant.refused(STRANGER, DEADLINE + 1, payee=None)      # nothing is left
    assert grant.refused(BOB, DEADLINE + 1, 1)


def test_a_spend_after_the_deadline_sends_the_rest_back_instead(real):
    """Bob is too late: his own execution at the deadline pays Alice, not his payee."""
    grant = Grant()
    assert grant.execute(BOB, START, 500) == {SHOP: 500}
    assert grant.execute(BOB, DEADLINE, 500) == {ALICE: 4_500}
    assert grant.balance == 0


def test_the_executor_cannot_send_the_rest_anywhere_else(real):
    """After the deadline anyone may send the execution, and it pays Alice whatever
    the executor names or asks."""
    grant = Grant()
    assert grant.execute(STRANGER, DEADLINE + 5, ask=4_000, payee=STRANGER) == {ALICE: AMOUNT}


def test_untouched_money_returns_in_full(real):
    grant = Grant()
    assert grant.execute(ALICE, DEADLINE, payee=None) == {ALICE: AMOUNT}


# --- two payments under one cap -----------------------------------------------------------


def test_300_from_one_payment_leaves_200_for_both(real):
    grant = Grant(amount=1_000)
    assert grant.execute(BOB, START, 300) == {SHOP: 300}
    grant.balance += 1_000                           # Alice's second payment arrives
    assert grant.refused(BOB, START + 60, 201)
    assert grant.execute(BOB, START + 60, 200) == {SHOP: 200}
    assert grant.refused(BOB, START + 120, 1)
    assert grant.execute(BOB, START + WEEK, 500) == {SHOP: 500}


DRAWS = (1, 200, 250, 300, 499, 500, 501)


def test_every_history_of_two_spends_under_one_cap(real):
    """Two payments of Alice to Bob under one cap, and every history of two spends:
    each amount of DRAWS twice, the second spend in the same week or the next, the
    second payment arriving before the first spend, between the two, or after.
    A spend is paid exactly when it fits what is left of that week's cap."""
    checked = 0
    for first, second in itertools.product(DRAWS, DRAWS):
        for gap in (60, WEEK):
            for arrives in (0, 1, 2):
                grant = Grant(amount=1_000)
                if arrives == 0:
                    grant.balance += 1_000
                spent = 0
                ok = first <= CAP
                assert (grant.execute(BOB, START, first) == {SHOP: first}) if ok \
                    else grant.refused(BOB, START, first)
                spent += first if ok else 0
                if arrives == 1:
                    grant.balance += 1_000
                left = CAP - (spent if gap < WEEK else 0)
                ok = second <= left
                assert (grant.execute(BOB, START + gap, second) == {SHOP: second}) if ok \
                    else grant.refused(BOB, START + gap, second)
                spent += second if ok else 0
                if arrives == 2:
                    grant.balance += 1_000
                assert grant.balance == 2_000 - spent, (first, second, gap, arrives)
                checked += 1
    assert checked == len(DRAWS) ** 2 * 2 * 3 == 294


# --- against a model, at random -----------------------------------------------------------


def _model(balance, paid_in_week, who, at, ask):
    """What one execution must pay, worked out without the engine."""
    if who == BOB and START <= at < DEADLINE and 1 <= ask <= CAP - paid_in_week:
        return ("spend", ask) if ask <= balance else ("short", 0)
    if at >= DEADLINE and balance:
        return ("back", balance)
    return ("nothing", 0)


@pytest.mark.parametrize("seed", range(6))
def test_the_rule_and_a_model_agree_on_random_histories(real, seed):
    """A walk through the grant's whole life, the clock aimed at the start, the
    deadline and the week boundaries: every execution pays what the model says."""
    rng = random.Random(seed)
    grant = Grant(amount=rng.choice((900, 2_400, AMOUNT)))
    edges = sorted([START, DEADLINE] + [INSTALLED + n * WEEK for n in range(1, 7)])
    at, week, paid = INSTALLED + 1, 0, 0
    kinds = set()
    for _ in range(150):
        ahead = [e for e in edges if e - 1 > at]
        if ahead and rng.random() < 0.15:
            at = ahead[0] + rng.choice((-1, 0, 1))
        else:
            at += rng.choice((1, 600, 3 * 3_600, DAY))
        if (at - INSTALLED) // WEEK != week:
            week, paid = (at - INSTALLED) // WEEK, 0
        who = rng.choice((BOB, BOB, BOB, ALICE, STRANGER))
        ask = max(0, rng.choice((0, 1, 100, 250, CAP - paid, CAP - paid + 1, CAP, CAP + 1)))
        kind, amount = _model(grant.balance, paid, who, at, ask)
        kinds.add(kind)
        if kind == "spend":
            assert grant.execute(who, at, ask) == {SHOP: ask}
            paid += ask
        elif kind == "back":
            assert grant.execute(who, at, ask) == {ALICE: amount}
            paid += amount
        elif kind == "short":
            assert grant.refused(who, at, ask, why="the account holds")
        else:
            assert grant.refused(who, at, ask)
    assert {"spend", "nothing", "back"} <= kinds
    assert grant.balance == 0
