"""Payout rules on the REAL Tau engine (#63): the documented example rules build
and step in their own policy pool, and the amounts they write are what
`settle` pays.

Skipped where the native module is not built.
"""
import hashlib
import os
import pathlib

import pytest

import tau_policy
from consensus import sender_policy
from consensus.payout import (
    PayoutBook,
    PayoutExecution,
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
HEIGHT, TS = 100, 1_767_225_600


def _key(label):
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest() for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


ACCOUNT, BOB, REVIEWER, STRANGER = (_key(n) for n in ("account", "bob", "reviewer", "x"))

PASSTHROUGH = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
REVIEWED = (
    "always ( (i13[t]:bv[384] = { #x" + REVIEWER + " }:bv[384]) ? "
    "(o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { #x000000 }:bv[24]) )."
)
SPLIT = (
    "always ( (o30[t]:bv[24] = i40[t]:bv[24]) && "
    "(o31[t]:bv[24] = i40[t]:bv[24]) )."
)


@pytest.fixture
def real():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    ev = tau_policy.pool_evaluator(POOL_APPLY, cwd=REPO, env=env, timeout=TIMEOUT)
    sender_policy.set_evaluator(POOL_APPLY, ev)
    yield ev
    sender_policy.set_evaluator(POOL_APPLY, None)
    ev.close()


def _terms(text, slots):
    return parse_payout_rule_set({
        "sender_pubkey": ACCOUNT, "sequence_number": 0, "rule_text": text, "slots": slots,
        "cap_per_execution": 1_000, "cap_per_period": 5_000, "period_blocks": 100,
        "expires_at": HEIGHT + 10_000,
    })


def _run(terms, executor, data, recipients=(), balance=10_000):
    book = PayoutBook()
    book.install(terms, HEIGHT - 1)
    exe = PayoutExecution(executor, ACCOUNT, terms.rule_id, tuple(recipients),
                          tuple(sorted(data.items())))
    rule, state = book.check_execution(exe, HEIGHT, TS)
    values = execution_inputs(rule, state, exe, parent_balance=balance, height=HEIGHT, ts=TS)
    outputs = sender_policy.payout_outputs(rule.body, values, pool=POOL_APPLY)
    return settle(rule, state, exe, outputs, height=HEIGHT, ts=TS, balance=balance)


@pytest.mark.parametrize("text, slots", [
    (PASSTHROUGH, [BOB]), (REVIEWED, [""]), (SPLIT, [BOB, ""]),
])
def test_the_documented_rules_pass_the_screen_and_build(real, text, slots):
    terms = _terms(text, slots)
    assert screen_payout_body(terms.body, len(slots)) is None
    built = real.validate(terms.body)
    assert built.ok, built.error


def test_the_rule_writes_the_amount_it_reads(real):
    legs = _run(_terms(PASSTHROUGH, [BOB]), STRANGER, {0: 250})
    assert legs == [(0, BOB, 250)]


def test_only_the_named_executor_moves_money(real):
    terms = _terms(REVIEWED, [""])
    assert _run(terms, REVIEWER, {0: 300}, recipients=[(0, BOB)]) == [(0, BOB, 300)]
    from consensus.payout import PayoutRefused
    with pytest.raises(PayoutRefused, match="pays nothing"):
        _run(terms, STRANGER, {0: 300}, recipients=[(0, BOB)])


def test_two_slots_are_paid_together(real):
    terms = _terms(SPLIT, [BOB, ""])
    assert _run(terms, STRANGER, {0: 40}, recipients=[(1, REVIEWER)]) == \
        [(0, BOB, 40), (1, REVIEWER, 40)]


# --- per sale: a 5% royalty, once per sale ---------------------------------------------

# 5% is a twentieth; dividing only, the amount can never wrap at bv[24]
ROYALTY = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] )."
BUYER = _key("buyer")


def _royalty_terms():
    return parse_payout_rule_set({
        "sender_pubkey": ACCOUNT, "sequence_number": 0, "rule_text": ROYALTY, "slots": [BOB],
        "cap_per_execution": 1_000, "cap_per_period": 5_000, "period_blocks": 100,
        "expires_at": HEIGHT + 10_000, "per_sale": True,
    })


def test_a_5_percent_royalty_on_101_pays_5_once(real):
    """On the real engine: the rule reads the recorded sale (i27 = 101) and pays 5;
    the paid sale is closed, so naming it again is refused."""
    from consensus.payout import PayoutRefused

    terms = _royalty_terms()
    assert screen_payout_body(terms.body, 1, per_sale=True) is None
    built = real.validate(terms.body)
    assert built.ok, built.error
    book = PayoutBook()
    book.install(terms, HEIGHT - 1)
    sale = hashlib.sha256(b"a sale of 101").digest()
    assert book.note_sale(ACCOUNT, sale, BUYER, 101, HEIGHT - 1) == "recorded"
    exe = PayoutExecution(STRANGER, ACCOUNT, terms.rule_id, (), (), sale)
    rule, state = book.check_execution(exe, HEIGHT, TS)
    values = execution_inputs(rule, state, exe, parent_balance=10_000, height=HEIGHT, ts=TS)
    outputs = sender_policy.payout_outputs(rule.body, values, pool=POOL_APPLY)
    legs = settle(rule, state, exe, outputs, height=HEIGHT, ts=TS, balance=10_000)
    assert legs == [(0, BOB, 5)]
    book.record(ACCOUNT, 5, HEIGHT, TS, sale)
    with pytest.raises(PayoutRefused, match="not an open sale"):
        book.check_execution(exe, HEIGHT + 1, TS + 1)


@pytest.mark.parametrize("amount, paid", [(1_000, 50), (20, 1), (19, 0)])
def test_the_royalty_rounds_down(real, amount, paid):
    from consensus.payout import PayoutRefused

    terms = _royalty_terms()
    book = PayoutBook()
    book.install(terms, HEIGHT - 1)
    sale = hashlib.sha256(str(amount).encode()).digest()
    book.note_sale(ACCOUNT, sale, BUYER, amount, HEIGHT - 1)
    exe = PayoutExecution(STRANGER, ACCOUNT, terms.rule_id, (), (), sale)
    rule, state = book.check_execution(exe, HEIGHT, TS)
    values = execution_inputs(rule, state, exe, parent_balance=10_000, height=HEIGHT, ts=TS)
    outputs = sender_policy.payout_outputs(rule.body, values, pool=POOL_APPLY)
    if paid:
        assert settle(rule, state, exe, outputs, height=HEIGHT, ts=TS, balance=10_000) == \
            [(0, BOB, paid)]
    else:
        with pytest.raises(PayoutRefused, match="pays nothing"):
            settle(rule, state, exe, outputs, height=HEIGHT, ts=TS, balance=10_000)


# --- a condition chooses between amounts; it cannot stand alone --------------------------

BARE = ("always ( (i40[t]:bv[24] > { 100 }:bv[24]) && "
        "(o30[t]:bv[24] = i40[t]:bv[24]) ).")
CHOSEN = ("always ( (i40[t]:bv[24] > { 100 }:bv[24]) ? "
          "(o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).")


def test_a_bare_condition_does_not_build_and_the_screen_says_why(real):
    """`(condition) && amount` has no answer where the condition fails, and the
    engine builds only clauses that answer every input. The screen refuses the
    shape with its reason before the engine is asked."""
    body = BARE[len("always "):-1]
    built = real.validate(body)
    assert not built.ok
    assert "a bare condition on inputs" in screen_payout_body(body, 1)


def test_a_choice_pays_or_pays_nothing(real):
    from consensus.payout import PayoutRefused

    terms = _terms(CHOSEN, [BOB])
    assert screen_payout_body(terms.body, 1) is None
    assert _run(terms, STRANGER, {0: 250}) == [(0, BOB, 250)]
    with pytest.raises(PayoutRefused, match="pays nothing"):
        _run(terms, STRANGER, {0: 100})


# --- a work escrow: one locked price, several recipients, exactly the price paid --------
#
# The evidence case of #63: a poster locks a task price in an escrow account. When
# the review is done an arbiter settles it: the worker, two reviewers, whoever found
# a defect, and the remainder back to the poster. A tenth is held back for a
# warranty window and released in a second execution, to the worker, or to a late
# defect's finder and the poster. Whatever path is taken, the account pays exactly
# the locked price and then nothing more.
#
# Data: i40 the verdict (1 accepted, 2 rejected), i41 the defects confirmed in the
# review (0..3), i42 a late defect confirmed in the warranty window (0 or 1).
# i26 (paid by this rule so far) tells the two executions apart.

WORKER, REVIEWER_A, REVIEWER_B, POSTER, ARBITER, FINDER = (
    _key(n) for n in ("worker", "reviewer a", "reviewer b", "poster", "arbiter", "finder"))
SLOT_WORKER, SLOT_A, SLOT_B, SLOT_FINDER, SLOT_POSTER = range(5)
WARRANTY_END = HEIGHT + 500
MAX_DEFECTS = 3


def _split(price):
    """The terms of an escrow of `price`: review fee, held back, the worker's cut
    per defect and the finder's bounty out of it."""
    fee, held, cut, bounty = price // 25, price // 10, price // 12, price // 20
    assert price - held - 2 * fee >= MAX_DEFECTS * cut and cut >= bounty > 0
    return fee, held, cut, bounty


def work_escrow(price):
    fee, held, cut, bounty = _split(price)
    c = lambda n, w=24: "{ %d }:bv[%d]" % (n, w)                     # noqa: E731
    verdict, defects, late, paid = (f"i{n}[t]:bv[24]" for n in (40, 41, 42, 26))
    accepted, rejected = f"({c(2)} - {verdict})", f"({verdict} - {c(1)})"

    def amounts(*per_slot):
        return " && ".join(f"(o{30 + k}[t]:bv[24] = {v})" for k, v in enumerate(per_slot))

    arbiter = f"(i13[t]:bv[384] = {{ #x{ARBITER} }}:bv[384])"
    review = amounts(
        f"{accepted} * ({c(price - held - 2 * fee)} - ({defects} * {c(cut)}))",
        c(fee), c(fee),
        f"{accepted} * ({defects} * {c(bounty)})",
        f"({rejected} * {c(price - 2 * fee)}) + ({accepted} * ({defects} * {c(cut - bounty)}))")
    warranty = amounts(
        f"({c(1)} - {late}) * {c(held)}", c(0), c(0),
        f"{late} * {c(bounty)}", f"{late} * {c(held - bounty)}")
    nothing = amounts(*[c(0)] * 5)
    at_review = (f"({arbiter} && ({paid} = {c(0)}) && ({verdict} >= {c(1)}) && "
                 f"({verdict} <= {c(2)}) && ({defects} <= {c(MAX_DEFECTS)}))")
    in_warranty = (f"({arbiter} && ({paid} = {c(price - held)}) && ({late} <= {c(1)}) && "
                   f"(({late} = {c(1)}) || (i6[t]:bv[64] >= {c(WARRANTY_END, 64)})))")
    return (f"always ( {at_review} ? ({review}) : "
            f"( {in_warranty} ? ({warranty}) : ({nothing}) ) ).")


def _escrow_model(price, verdict, defects, late):
    """What each execution must pay, worked out without the engine:
    [review legs, warranty legs] as {slot: amount} (zero amounts left out)."""
    fee, held, cut, bounty = _split(price)
    if verdict == 2:
        return [{SLOT_A: fee, SLOT_B: fee, SLOT_POSTER: price - 2 * fee}]
    review = {SLOT_WORKER: price - held - 2 * fee - defects * cut, SLOT_A: fee, SLOT_B: fee,
              SLOT_FINDER: defects * bounty, SLOT_POSTER: defects * (cut - bounty)}
    warranty = ({SLOT_FINDER: bounty, SLOT_POSTER: held - bounty} if late
                else {SLOT_WORKER: held})
    return [{k: v for k, v in legs.items() if v} for legs in (review, warranty)]


class _Escrow:
    """An escrow account holding exactly the price, with the rule installed."""

    def __init__(self, price):
        self.terms = parse_payout_rule_set({
            "sender_pubkey": ACCOUNT, "sequence_number": 0, "rule_text": work_escrow(price),
            "slots": [WORKER, REVIEWER_A, REVIEWER_B, "", POSTER],
            "cap_per_execution": price, "cap_per_period": price,
            # one period for the rule's whole life, so i26 never starts again
            "period_blocks": 1_000_000, "expires_at": HEIGHT - 1 + 1_000_000,
        })
        self.book = PayoutBook()
        self.book.install(self.terms, HEIGHT - 1)
        self.balance = price

    def execute(self, data, height, *, executor=ARBITER, finder=FINDER):
        named = ((SLOT_FINDER, finder),) if finder else ()
        exe = PayoutExecution(executor, ACCOUNT, self.terms.rule_id, named,
                              tuple(sorted(data.items())))
        rule, state = self.book.check_execution(exe, height, TS)
        values = execution_inputs(rule, state, exe, parent_balance=self.balance,
                                  height=height, ts=TS)
        outputs = sender_policy.payout_outputs(rule.body, values, pool=POOL_APPLY)
        legs = settle(rule, state, exe, outputs, height=height, ts=TS, balance=self.balance)
        total = sum(amount for _, _, amount in legs)
        self.book.record(ACCOUNT, total, height, TS)
        self.balance -= total
        return {slot: amount for slot, _who, amount in legs}


ESCROW_PRICES = [600, 999, 1_000, 12_345, 1_000_000]


def test_the_work_escrow_passes_the_screen_and_builds(real):
    terms = _Escrow(1_000).terms
    assert screen_payout_body(terms.body, 5) is None
    built = real.validate(terms.body)
    assert built.ok, built.error


@pytest.mark.parametrize("price", ESCROW_PRICES)
def test_a_work_escrow_pays_exactly_the_locked_price_on_every_path(real, price):
    """Every settlement path: accepted with 0..3 defects, then the warranty part
    released clean or after a late defect; and rejected. Each execution pays what
    the model says, the account ends at zero, and nothing more can be paid."""
    from consensus.payout import PayoutRefused

    paths = [(1, d, late) for d in range(MAX_DEFECTS + 1) for late in (0, 1)]
    paths += [(2, d, 0) for d in range(MAX_DEFECTS + 1)]
    for verdict, defects, late in paths:
        escrow = _Escrow(price)
        expected = _escrow_model(price, verdict, defects, late)
        paid = [escrow.execute({0: verdict, 1: defects}, HEIGHT)]
        if verdict == 1:
            # the warranty part: at once for a late defect, else only at its end
            at = HEIGHT + 7 if late else WARRANTY_END
            paid.append(escrow.execute({2: late}, at))
        assert paid == expected, (verdict, defects, late)
        assert sum(sum(legs.values()) for legs in paid) == price
        assert escrow.balance == 0
        with pytest.raises(PayoutRefused, match="pays nothing"):
            escrow.execute({0: 1, 2: 1}, WARRANTY_END + 1)


def test_the_work_escrow_refuses_everything_else(real):
    from consensus.payout import PayoutRefused

    def refused(data, height=HEIGHT, why="pays nothing", **kw):
        escrow = _Escrow(1_000)
        with pytest.raises(PayoutRefused, match=why):
            escrow.execute(data, height, **kw)
        assert escrow.balance == 1_000

    refused({0: 1}, executor=STRANGER)             # only the arbiter settles
    refused({})                                    # no verdict is no settlement
    refused({0: 3})                                # a verdict the rule does not know
    refused({0: 1, 1: MAX_DEFECTS + 1})            # more defects than the rule allows
    refused({2: 1})                                # the warranty part before the review
    refused({0: 1, 1: 2}, finder=None, why="no recipient was named")

    escrow = _Escrow(1_000)
    escrow.execute({0: 1}, HEIGHT)
    for data, height in (({2: 0}, WARRANTY_END - 1),   # a clean release before the end
                         ({2: 2}, WARRANTY_END)):      # neither a yes nor a no
        with pytest.raises(PayoutRefused, match="pays nothing"):
            escrow.execute(data, height)
    # the review is never paid twice: at the end the same data releases only the
    # held part to the worker
    assert escrow.execute({0: 1}, WARRANTY_END) == {SLOT_WORKER: 100}
    assert escrow.balance == 0


# --- one rule at a time in the pool -------------------------------------------------
#
# On the pinned engine (tau-lang c3ea334) an interpreter that is stepped after another
# one was built and probed in the same process sometimes refused the step, about 5
# steps in 100 for the first rule below. The payout pools keep one interpreter at a
# time (`tau_policy.pool_options`), so these never fail.


def _divide(by):
    return "o30[t]:bv[24] = i27[t]:bv[24] / { %d }:bv[24]" % by


def test_a_rule_answers_the_same_after_every_other_rule_that_is_built(real):
    fifth = _divide(5)
    assert real.outputs(fifth, {"i27": "100"})["o30"] == "20"
    for by in range(6, 66):
        assert real.validate(_divide(by)).ok
        assert real.outputs(fifth, {"i27": "100"})["o30"] == "20", by
        assert real.outputs(fifth, {"i27": "101"})["o30"] == "20", by
    assert real.stats()["live"] == 1


def test_rules_in_turn_in_one_pool_all_answer_like_their_model(real):
    import random

    def c(n):
        return "{ %d }:bv[24]" % n

    rules = [
        (_divide(5), lambda v: v // 5),
        (_divide(2), lambda v: v // 2),
        (f"(i27[t]:bv[24] > {c(50)}) ? (o30[t]:bv[24] = {c(7)}) : (o30[t]:bv[24] = {c(0)})",
         lambda v: 7 if v > 50 else 0),
        (f"o30[t]:bv[24] = i27[t]:bv[24] + {c(3)}", lambda v: v + 3),
        (f"(i27[t]:bv[24] < {c(10)}) ? (o30[t]:bv[24] = {c(0)}) : "
         f"(o30[t]:bv[24] = i27[t]:bv[24] / {c(10)})", lambda v: 0 if v < 10 else v // 10),
        (f"(o30[t]:bv[24] = i27[t]:bv[24] / {c(4)}) && (o31[t]:bv[24] = i27[t]:bv[24] / {c(8)})",
         lambda v: v // 4),
    ]
    rng = random.Random(63)
    for n in range(400):
        if rng.random() < 0.3:
            assert real.validate(rng.choice(rules)[0]).ok
        body, model = rng.choice(rules)
        value = rng.choice([0, 1, 4, 9, 10, 25, 50, 51, 100, 101, 999, 65_535, 1_000_000])
        assert real.outputs(body, {"i27": str(value)})["o30"] == str(model(value)), (n, body)
