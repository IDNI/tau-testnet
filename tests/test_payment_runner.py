"""The Amendment 2 payment runner: one rule per account, three triggers.

Book-level tests run the RunnerBook directly against a DictLedger with
scripted clause callables (the book's injected seam — the callable
receives the run's fact context, the book-level names of the i1..i17
streams). Engine-level tests at the end run the real apply path in the
scripted-Tau idiom of test_payments_apply.py, with a clearly marked
evaluator double on the codebase's own override seam
(``sender_policy.set_evaluator("payout", ...)``): the production
adapter, the production A1 decode and the production book enforcement
all run for real; only the Tau step itself is scripted, because the
native bindings are not built in this sandbox.
"""
import contextlib
import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from py_ecc.bls import G2Basic

from consensus import sender_policy
from consensus.admission import TipAdmissionView, validate_mempool_admission
from consensus.payments import (
    FEE_SINK_PUBKEY,
    DictLedger,
    PaymentRefused,
    PaymentShapeError,
    ProgrammablePayments,
)
from consensus.payment_runner import (
    RUNNER_ESCROW_PUBKEY,
    ClockTerms,
    RuleTerms,
    RunnerBook,
)

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
D = "dd" * 48
TS = 1_700_000_000
WEEK = 604_800
FAR = 9_999_999_999


class ZeroFees:
    def execution_fee(self, payer, recipient, amount):
        return 0


class FixedFees:
    def __init__(self, fee):
        self.fee = fee

    def execution_fee(self, payer, recipient, amount):
        return self.fee


def _ts(year, month, day):
    return int(datetime(year, month, day, tzinfo=timezone.utc).timestamp())


def clock_terms(**over):
    fields = dict(anchor_ts=TS, period_kind="week")
    fields.update(over)
    return ClockTerms(**fields)


def rule_terms(**over):
    fields = dict(
        owner=A, clause="clause-body", parties=(B,), party_caps=(0,),
        triggers=("execute",), max_per_run=0, max_fee_per_execution=10,
    )
    fields.update(over)
    return RuleTerms(**fields)


# --- (a) standing via clock: monthly on the 31st, once per period ------------

def test_clock_monthly_anchored_on_31st_fires_on_last_day_of_short_month():
    book = RunnerBook()
    anchor = _ts(2026, 1, 31)
    terms = rule_terms(
        triggers=("clock",),
        clock=clock_terms(anchor_ts=anchor, period_kind="month"),
    )
    rule_id = book.install(terms)
    ledger = DictLedger({A: 10_000, B: 0})
    pay100 = lambda ctx: [(0, 100)]
    factory = lambda t: pay100

    # Period 0 opens on the anchor day itself (Jan 31).
    runs = book.sweep_clock(ts=anchor, height=1, ledger=ledger,
                            fees=ZeroFees(), clause_factory=factory)
    assert [r.period_index for r in runs] == [0]
    assert ledger.balance(B) == 100

    # The same period never fires twice, however often the sweep runs.
    runs = book.sweep_clock(ts=anchor + 3600, height=2, ledger=ledger,
                            fees=ZeroFees(), clause_factory=factory)
    assert runs == [] and ledger.balance(B) == 100

    # February 2026 is shorter: the run fires on its last day, Feb 28 —
    # the clamped start of period 1 — not on a nonexistent Feb 31.
    runs = book.sweep_clock(ts=_ts(2026, 2, 28), height=3, ledger=ledger,
                            fees=ZeroFees(), clause_factory=factory)
    assert [r.period_index for r in runs] == [1]
    assert ledger.balance(B) == 200

    # March 30 is still period 1 (period 2 starts Mar 31 — the anchor
    # day does not drift after the short month): nothing fires.
    runs = book.sweep_clock(ts=_ts(2026, 3, 30), height=4, ledger=ledger,
                            fees=ZeroFees(), clause_factory=factory)
    assert runs == [] and ledger.balance(B) == 200
    runs = book.sweep_clock(ts=_ts(2026, 3, 31), height=5, ledger=ledger,
                            fees=ZeroFees(), clause_factory=factory)
    assert [r.period_index for r in runs] == [2]
    assert ledger.balance(B) == 300
    assert book.get(rule_id).clock_next == 3


def test_clock_run_whose_fee_exceeds_the_bound_does_not_fire():
    book = RunnerBook()
    rule_id = book.install(rule_terms(
        triggers=("clock",), clock=clock_terms(), max_fee_per_execution=5))
    ledger = DictLedger({A: 10_000, B: 0})
    clause = lambda ctx: [(0, 100)]
    # The quoted fee (7) exceeds the signed bound (5): the run does not
    # fire, nothing is recorded, and the period stays open.
    runs = book.sweep_clock(ts=TS, height=1, ledger=ledger,
                            fees=FixedFees(7), clause_factory=lambda t: clause)
    assert runs == []
    assert ledger.balance(B) == 0 and ledger.balance(A) == 10_000
    assert book.get(rule_id).clock_next == 0
    ok, reason = book.can_clock_run(rule_id, clause, ts=TS, height=1,
                                    ledger=ledger, fees=FixedFees(7))
    assert not ok and "fee" in reason
    # Within the bound the same period fires and the fee is charged to
    # the account, separately from the leg.
    runs = book.sweep_clock(ts=TS, height=1, ledger=ledger,
                            fees=FixedFees(5), clause_factory=lambda t: clause)
    assert len(runs) == 1 and runs[0].fee == 5
    assert ledger.balance(B) == 100
    assert ledger.balance(FEE_SINK_PUBKEY) == 5
    assert ledger.balance(A) == 10_000 - 100 - 5


# --- (c) grants over a held balance ------------------------------------------

def _grant_book(draw_amount):
    """A grant in runner shape: the poster's rule, funded 5,000, the
    recipient a party who draws `draw_amount` per week by execute runs;
    the deadline clock run refunds the remainder to the poster."""
    book = RunnerBook()
    terms = rule_terms(
        owner=A, parties=(B, A), party_caps=(0, 0),
        triggers=("clock", "execute"),
        clock=clock_terms(until_ts=TS + 4 * WEEK, deadline_run=True),
    )
    rule_id = book.install(terms)
    ledger = DictLedger({A: 10_000, B: 0})
    book.fund(rule_id, A, 5_000, ledger=ledger)

    def draw_clause(ctx):
        if ctx["executor"] != B:
            return []
        due = draw_amount - ctx["period_settled"]
        return [(0, due)] if due > 0 else []

    def refund_clause(ctx):
        return [(1, ctx["held"])] if ctx["held"] else []

    return book, rule_id, ledger, draw_clause, refund_clause


def test_grant_draws_500_a_week_and_deadline_refunds_3500():
    book, rule_id, ledger, draw_clause, refund_clause = _grant_book(500)
    assert book.get(rule_id).held == 5_000
    assert ledger.balance(RUNNER_ESCROW_PUBKEY) == 5_000
    for w in range(3):
        record = book.execute(rule_id, f"draw-{w}", 500, draw_clause,
                              executor=B, ts=TS + w * WEEK + 10,
                              height=20 + w, ledger=ledger)
        assert record.total == 500
    assert ledger.balance(B) == 1_500
    assert book.get(rule_id).held == 3_500

    runs = book.sweep_clock(ts=TS + 4 * WEEK, height=30, ledger=ledger,
                            fees=ZeroFees(),
                            clause_factory=lambda t: refund_clause)
    assert [(r.key, r.total) for r in runs] == [("clock:deadline", 3_500)]
    assert ledger.balance(A) == 10_000 - 5_000 + 3_500
    assert book.get(rule_id).held == 0
    assert ledger.balance(RUNNER_ESCROW_PUBKEY) == 0
    # The deadline run fires exactly once.
    runs = book.sweep_clock(ts=TS + 4 * WEEK + 10, height=31, ledger=ledger,
                            fees=ZeroFees(),
                            clause_factory=lambda t: refund_clause)
    assert runs == []


def test_grant_canonical_1200_drawn_refunds_exactly_3800_fee_not_netted():
    book, rule_id, ledger, draw_clause, refund_clause = _grant_book(400)
    for w in range(3):
        book.execute(rule_id, f"draw-{w}", 400, draw_clause,
                     executor=B, ts=TS + w * WEEK + 10,
                     height=20 + w, ledger=ledger)
    assert ledger.balance(B) == 1_200

    # The refund's fee (7, within the signed bound of 10) is charged to
    # the poster's account separately: the poster is refunded the full
    # 3,800, not 3,800 minus the fee (the addendum's case-5 correction).
    runs = book.sweep_clock(ts=TS + 4 * WEEK, height=30, ledger=ledger,
                            fees=FixedFees(7),
                            clause_factory=lambda t: refund_clause)
    assert [(r.key, r.total, r.fee) for r in runs] == [
        ("clock:deadline", 3_800, 7)]
    assert ledger.balance(A) == 10_000 - 5_000 - 7 + 3_800
    assert ledger.balance(FEE_SINK_PUBKEY) == 7


def test_grant_draw_by_a_stranger_settles_nothing():
    book, rule_id, ledger, draw_clause, _ = _grant_book(500)
    # The clause is the policy: an executor who is not the recipient
    # gets no legs, the run settles nothing and is refused, and the
    # event stays open for the recipient's own draw.
    with pytest.raises(PaymentRefused, match="settles nothing"):
        book.execute(rule_id, "draw-0", 500, draw_clause,
                     executor=C, ts=TS + 10, height=20, ledger=ledger)
    record = book.execute(rule_id, "draw-0", 500, draw_clause,
                          executor=B, ts=TS + 10, height=20, ledger=ledger)
    assert record.total == 500


# --- (d) catch-up --------------------------------------------------------------

def test_catch_up_settles_at_most_max_missed_and_clause_sees_i15():
    book = RunnerBook()
    terms = rule_terms(
        triggers=("clock",),
        clock=clock_terms(max_catch_up=2),
    )
    rule_id = book.install(terms)
    ledger = DictLedger({A: 10_000, B: 0})
    seen = []

    def clause(ctx):
        seen.append(dict(ctx))
        covered = 1 + min(ctx["missed"], 2)
        return [(0, 10 * covered)]

    # Four periods have fully elapsed with no run: at period 4 the
    # clause sees all 4 missed periods as i15, but the run settles at
    # most the signed catch-up (2) plus the current period.
    runs = book.sweep_clock(ts=TS + 4 * WEEK + 60, height=9, ledger=ledger,
                            fees=ZeroFees(), clause_factory=lambda t: clause)
    assert len(runs) == 1
    assert seen[0]["missed"] == 4 and seen[0]["trigger"] == 2
    assert runs[0].periods_covered == 3
    assert runs[0].period_index == 4
    assert ledger.balance(B) == 30
    state = book.get(rule_id)
    assert state.clock_next == 5
    # The skipped periods are resolved: the same sweep again is quiet.
    runs = book.sweep_clock(ts=TS + 4 * WEEK + 120, height=10, ledger=ledger,
                            fees=ZeroFees(), clause_factory=lambda t: clause)
    assert runs == []


def test_no_catch_up_skips_missed_periods_by_default():
    book = RunnerBook()
    rule_id = book.install(rule_terms(
        triggers=("clock",), clock=clock_terms()))  # max_catch_up = 0
    ledger = DictLedger({A: 10_000, B: 0})
    seen = []
    clause = lambda ctx: (seen.append(dict(ctx)), [(0, 10)])[1]
    runs = book.sweep_clock(ts=TS + 3 * WEEK + 60, height=9, ledger=ledger,
                            fees=ZeroFees(), clause_factory=lambda t: clause)
    assert len(runs) == 1 and runs[0].periods_covered == 1
    assert seen[0]["missed"] == 3
    assert ledger.balance(B) == 10
    assert book.get(rule_id).clock_next == 4


# --- (e) one rule per account: replacement + combination clause ---------------

def test_install_replaces_and_combination_clause_serves_two_triggers():
    book = RunnerBook()
    first = book.install(rule_terms(clause="first"))
    second_terms = rule_terms(
        clause="combo", parties=(B, C), party_caps=(0, 0),
        triggers=("arrival", "execute"))
    second = book.install(second_terms)
    assert second != first
    # One rule per account: the first rule is gone entirely.
    assert book.get(first) is None
    assert book.get_by_owner(A).terms.rule_id == second

    def combo(ctx):
        # One clause, discriminating on the trigger-kind fact (i14):
        # execute runs pay party 0 a fixed leg; arrival runs pay party 1
        # a fifth of the credit.
        if ctx["trigger"] == 1:
            return [(0, 50)]
        if ctx["trigger"] == 3:
            return [(1, ctx["amount"] // 5)]
        return []

    ledger = DictLedger({A: 1_000, B: 0, C: 0, D: 500})
    record = book.execute(second, "evt-1", 50, combo, executor=D,
                          ts=TS, height=1, ledger=ledger)
    assert record.legs == ((B, 50),)
    receipt = book.apply_arrival(A, D, 100, combo, fee=0, ts=TS, height=1,
                                 ledger=ledger, run_key="tx-1")
    assert receipt.legs == ((C, 20),) and receipt.net == 80
    assert ledger.balance(B) == 50 and ledger.balance(C) == 20
    assert ledger.balance(A) == 1_000 - 50 + 80


def test_replacement_and_removal_are_refused_while_funds_are_held():
    book = RunnerBook()
    rule_id = book.install(rule_terms())
    ledger = DictLedger({A: 1_000})
    book.fund(rule_id, A, 400, ledger=ledger)
    ok, reason = book.can_install(rule_terms(clause="other", sequence_number=1))
    assert not ok and "holds funds" in reason
    with pytest.raises(PaymentShapeError, match="holds funds"):
        book.install(rule_terms(clause="other", sequence_number=1))
    ok, reason = book.can_remove(A, A)
    assert not ok and "holds funds" in reason


def test_install_requires_a_clause_and_a_registered_shared_cap():
    book = RunnerBook()
    ok, reason = book.can_install(rule_terms(clause="  "))
    assert not ok and "no clause" in reason
    ok, reason = book.can_install(rule_terms(shared_cap_id="nope"))
    assert not ok and "not registered" in reason
    book.set_shared_cap("nope", 1_000)
    ok, _ = book.can_install(rule_terms(shared_cap_id="nope"))
    assert ok


# --- (f) shared cap across a payer's rules --------------------------------------

def test_shared_cap_counts_each_settled_run_exactly_once_across_rules():
    book = RunnerBook()
    book.set_shared_cap("alice-cap", 1_000)
    rule_one = book.install(rule_terms(
        owner=A, parties=(B,), party_caps=(0,), shared_cap_id="alice-cap"))
    rule_two = book.install(rule_terms(
        owner=D, parties=(B,), party_caps=(0,), shared_cap_id="alice-cap"))
    ledger = DictLedger({A: 5_000, D: 5_000, B: 0})
    pay = lambda ctx: [(0, ctx["amount"])]

    book.execute(rule_one, "e1", 300, pay, executor=C, ts=TS, height=1,
                 ledger=ledger)
    book.execute(rule_two, "e2", 300, pay, executor=C, ts=TS, height=1,
                 ledger=ledger)
    assert book.shared_cap_state("alice-cap").spent == 600

    # A refused run counts nothing: 600 + 500 would exceed the cap.
    with pytest.raises(PaymentRefused, match="shared cap"):
        book.execute(rule_one, "e3", 500, pay, executor=C, ts=TS, height=2,
                     ledger=ledger)
    assert book.shared_cap_state("alice-cap").spent == 600
    # A replay counts nothing either — it is refused before the plan.
    with pytest.raises(PaymentRefused, match="already settled"):
        book.execute(rule_one, "e1", 300, pay, executor=C, ts=TS, height=2,
                     ledger=ledger)
    assert book.shared_cap_state("alice-cap").spent == 600

    book.execute(rule_two, "e4", 400, pay, executor=C, ts=TS, height=3,
                 ledger=ledger)
    assert book.shared_cap_state("alice-cap").spent == 1_000
    assert ledger.balance(B) == 1_000


# --- execute trigger: pays-once, open execution ---------------------------------

def test_execute_pays_once_per_event_and_replay_is_refused():
    book = RunnerBook()
    rule_id = book.install(rule_terms())
    ledger = DictLedger({A: 1_000, B: 0})
    clause = lambda ctx: [(0, 200)]
    record = book.execute(rule_id, "sale-1", 200, clause, executor=C,
                          ts=TS, height=1, ledger=ledger)
    assert record.total == 200 and ledger.balance(B) == 200
    ok, reason = book.can_execute(rule_id, "sale-1", 200, clause,
                                  executor=D, ts=TS, height=2, ledger=ledger)
    assert not ok and "already settled" in reason
    with pytest.raises(PaymentRefused, match="already settled"):
        book.execute(rule_id, "sale-1", 200, clause, executor=D,
                     ts=TS, height=2, ledger=ledger)
    assert ledger.balance(B) == 200


# --- removal is the standing cancellation of this shape --------------------------

def test_remove_prevents_later_clock_runs_and_only_the_owner_removes():
    book = RunnerBook()
    book.install(rule_terms(triggers=("clock",), clock=clock_terms()))
    ledger = DictLedger({A: 1_000, B: 0})
    ok, reason = book.can_remove(A, B)
    assert not ok and "only the owner" in reason
    book.remove(A, A)
    assert book.get_by_owner(A) is None
    runs = book.sweep_clock(ts=TS + WEEK, height=2, ledger=ledger,
                            fees=ZeroFees(),
                            clause_factory=lambda t: (lambda ctx: [(0, 1)]))
    assert runs == [] and ledger.balance(B) == 0


# --- (g) admission/apply agreement on the refusal matrix --------------------------

_REFUSAL_CASES = {
    "out_of_set": lambda ctx: [(7, 100)],
    "over_party_cap": lambda ctx: [(0, 600)],
    "not_a_leg_list": lambda ctx: "junk",
    "leg_not_a_pair": lambda ctx: [(0, 100, 5)],
    "clause_refuses": lambda ctx: (_ for _ in ()).throw(
        PaymentRefused("rule clause cannot be evaluated: scripted")),
}


def test_can_and_apply_agree_on_execute_refusals():
    for name, clause in _REFUSAL_CASES.items():
        book = RunnerBook()
        rule_id = book.install(rule_terms(party_caps=(500,)))
        ledger = DictLedger({A: 10_000, B: 0})
        ok, reason = book.can_execute(rule_id, "evt", 1_000, clause,
                                      executor=C, ts=TS, height=1,
                                      ledger=ledger)
        assert not ok, name
        with pytest.raises(PaymentRefused) as caught:
            book.execute(rule_id, "evt", 1_000, clause, executor=C,
                         ts=TS, height=1, ledger=ledger)
        assert str(caught.value) == reason, name
        # Nothing settled, nothing recorded: the event stays open.
        assert ledger.balance(B) == 0
        assert book.get(rule_id).runs == {}


def test_can_and_apply_agree_on_clock_refusals():
    for name, clause in _REFUSAL_CASES.items():
        book = RunnerBook()
        rule_id = book.install(rule_terms(
            triggers=("clock",), clock=clock_terms(), party_caps=(500,)))
        ledger = DictLedger({A: 10_000, B: 0})
        ok, reason = book.can_clock_run(rule_id, clause, ts=TS, height=1,
                                        ledger=ledger, fees=ZeroFees())
        assert not ok, name
        with pytest.raises(PaymentRefused) as caught:
            book.run_clock(rule_id, clause, ts=TS, height=1,
                           ledger=ledger, fees=ZeroFees())
        assert str(caught.value) == reason, name
        # The sweep reaches the same verdict quietly: no run, no record,
        # the period stays open.
        runs = book.sweep_clock(ts=TS, height=1, ledger=ledger,
                                fees=ZeroFees(),
                                clause_factory=lambda t: clause)
        assert runs == [] and book.get(rule_id).clock_next == 0


# --- admission validators (the tip-view half of (g)) ------------------------------

@pytest.fixture
def tip_books():
    return ProgrammablePayments()


@pytest.fixture
def tip(tip_books):
    balances = {}
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = 50
    view.tip_timestamp = TS
    view.next_block_timestamp = TS
    view.payment_books.return_value = tip_books
    view.balance_of.side_effect = lambda pubkey: balances.get(pubkey, 0)
    view.payment_balances = balances
    return view


def _tx(tx_type, sender, **fields):
    tx = {
        "tx_type": tx_type, "sender_pubkey": sender, "sequence_number": 0,
        "expiration_time": FAR, "expire_at_height": 70, "fee_limit": "100",
    }
    tx.update(fields)
    return tx


SK_ALICE, ALICE = 11111, G2Basic.SkToPk(11111).hex()
SK_BOB, BOB = 44444, G2Basic.SkToPk(44444).hex()
SK_CAROL, CAROL = 55555, G2Basic.SkToPk(55555).hex()


def _install_tx(**over):
    fields = dict(
        owner=ALICE, clause="clause-body", parties=[[BOB, 0]],
        triggers=["execute"], max_per_run=0, max_fee_per_execution=10,
    )
    fields.update(over)
    return _tx("payment_rule_install", ALICE, **fields)


def test_admission_runner_install_fund_execute_remove(tip, tip_books):
    result = validate_mempool_admission(_install_tx(), tip)
    assert result.is_valid is True, result.error
    rule_id = bytes.fromhex(result.data["rule_id"])

    # A second install from a non-signer is refused.
    tx = _install_tx()
    tx["sender_pubkey"] = BOB
    assert validate_mempool_admission(tx, tip).is_valid is False

    tip_books.runner.install(rule_terms(owner=ALICE, parties=(BOB,)))
    assert tip_books.runner.get(rule_id) is not None

    # Funding: only the owner, and only against a real balance.
    tip.payment_balances[ALICE] = 1_000
    fund = _tx("payment_rule_fund", ALICE, rule_id=rule_id.hex(), amount=400)
    assert validate_mempool_admission(fund, tip).is_valid is True
    fund["sender_pubkey"] = BOB
    assert validate_mempool_admission(fund, tip).is_valid is False

    # Execution is open: a third party is admitted; a settled event and
    # an unknown rule are refused.
    execute = _tx("payment_rule_execute", CAROL, rule_id=rule_id.hex(),
                  event_id="evt-1", amount=100)
    assert validate_mempool_admission(execute, tip).is_valid is True
    ledger = DictLedger({ALICE: 1_000})
    tip_books.runner.execute(rule_id, "evt-1", 100, lambda ctx: [(0, 100)],
                             executor=CAROL, ts=TS, height=1, ledger=ledger)
    assert validate_mempool_admission(execute, tip).is_valid is False
    execute["rule_id"] = "ff" * 32
    assert validate_mempool_admission(execute, tip).is_valid is False

    # Removal follows the book: a funded rule cannot be removed.
    tip_books.runner.fund(rule_id, ALICE, 100,
                          ledger=DictLedger({ALICE: 500}))
    remove = _tx("payment_rule_remove", ALICE, owner=ALICE)
    assert validate_mempool_admission(remove, tip).is_valid is False


# --- persistence: the runner section rides the books' snapshot -------------------

def test_runner_snapshot_restore_round_trip():
    books = ProgrammablePayments()
    book = books.runner
    book.set_shared_cap("cap", 1_000)
    rule_id = book.install(rule_terms(
        triggers=("clock", "execute"), clock=clock_terms(),
        shared_cap_id="cap"))
    ledger = DictLedger({A: 10_000, B: 0})
    book.fund(rule_id, A, 2_000, ledger=ledger)
    book.execute(rule_id, "evt", 300, lambda ctx: [(0, 300)], executor=C,
                 ts=TS, height=1, ledger=ledger)
    rows_before = books.snapshot_rows()
    root_before = books.root()

    restored = ProgrammablePayments.restore(rows_before)
    assert restored.snapshot_rows() == rows_before
    assert restored.root() == root_before
    state = restored.runner.get(rule_id)
    assert state.held == 1_700 and state.held_funded
    assert set(state.runs) == {"execute:evt"}
    assert restored.runner.shared_cap_state("cap").spent == 300


def test_restore_without_a_runner_section_is_an_empty_runner():
    books = ProgrammablePayments()
    books.runner.install(rule_terms())
    rows = books.snapshot_rows()
    del rows["runner"]   # rows written before the runner existed
    restored = ProgrammablePayments.restore(rows)
    assert restored.runner.is_empty()
    assert restored.is_empty()


def test_restore_refuses_two_rules_for_one_account():
    books = ProgrammablePayments()
    books.runner.install(rule_terms())
    rows = books.snapshot_rows()
    rows["runner"]["rules"].append(rows["runner"]["rules"][0])
    with pytest.raises(ValueError, match="duplicate payment rule"):
        ProgrammablePayments.restore(rows)


# --- engine level: the real apply path ---------------------------------------
#
# The Chain harness and the evaluator double mirror test_payments_apply.py:
# the double answers clause_outputs on the "payout" pool (the pool both the
# payout and the runner evaluators step in) with Tau-literal output text
# computed from the fed inputs.

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
PROPOSER = "d4" * 48
SK_DAVE, DAVE = 66666, G2Basic.SkToPk(66666).hex()
_SKS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, DAVE: SK_DAVE}
_TX_SEQ = itertools.count()


def _tau_bv(value):
    """One output value in the literal text form a Tau step returns."""
    return f"{{ #x{value:x} }}:bv[64]"


def leg_outputs(legs):
    """The A1 output map for (party_index, amount) legs."""
    outputs = {"o30": _tau_bv(len(legs))}
    for k, (index, amount) in enumerate(legs):
        outputs[f"o{31 + 2 * k}"] = _tau_bv(index)
        outputs[f"o{32 + 2 * k}"] = _tau_bv(amount)
    return outputs


class ScriptedRunnerEvaluator:
    """TEST DOUBLE for tau_policy.PolicyEvaluator.outputs on the "payout"
    pool. Scripts are callables from the clause input map ({"i1": amount
    text, "i14": trigger text, ...}) to an output map of Tau-literal
    text. An unscripted body is a test bug and raises."""

    def __init__(self):
        self._scripts = {}
        self.calls = []

    def script(self, body, fn):
        self._scripts[body] = fn
        return self

    def outputs(self, body, inputs, *, timeout=None):
        self.calls.append((body, dict(inputs or {})))
        fn = self._scripts.get(body)
        if fn is None:
            raise AssertionError(f"no runner script for clause body {body!r}")
        return fn(dict(inputs or {}))


@contextlib.contextmanager
def runner_evaluator(double):
    sender_policy.set_evaluator("payout", double)
    try:
        yield double
    finally:
        sender_policy.set_evaluator("payout", None)


class Chain:
    """One chain advanced block by block through the real apply path."""

    def __init__(self, balances, *, fee=3):
        self.fee = fee
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        from consensus.governance import ConsensusLifecycleManager
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.lm.activate_approval_slots()

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = str(vals.get(1, "0"))
        return {1: amount, 8: "0", 9: str(self.fee), 5: "1"}

    def block(self, txs, height, ts):
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.bal),
                "sequence_numbers": dict(self.seq),
                "last_transfer_ts": dict(self.lts),
                "lifecycle_manager": self.lm,
                "consensus_rules_state":
                    "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ALICE)],
            mechanism_specific_metadata={"poa": True},
        )
        blk = Block.create(
            block_number=height,
            previous_hash="00" * 32,
            transactions=txs,
            proposer_pubkey=PROPOSER,
            timestamp=ts,
        )
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
                patch("tau_manager.communicate_with_tau_multi",
                      side_effect=self._multi), \
                patch("chain_state.get_application_rules_state",
                      return_value=""), \
                patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, blk, parent)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        return result

    def books(self):
        return self.lm.programmable_payments


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _base(tx_type, sender, seq):
    return {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
    }


def runner_install_tx(owner, seq, **fields):
    tx = _base("payment_rule_install", owner, seq)
    tx.update({"owner": owner, "max_per_run": 0, "max_fee_per_execution": 10})
    tx.update(fields)
    return _sign(tx, _SKS[owner])


def runner_execute_tx(rule_id, event_id, amount, sender, seq):
    tx = _base("payment_rule_execute", sender, seq)
    tx.update({"rule_id": rule_id, "event_id": event_id, "amount": amount})
    return _sign(tx, _SKS[sender])


def spend_tx(sender, to, amount, seq):
    tx = _base("user_tx", sender, seq)
    tx["operations"] = {"1": [[sender, to, amount]]}
    return _sign(tx, _SKS[sender])


def _logs(result, i=0):
    return " | ".join(result.outcomes[i].receipt_logs or [])


# --- (b) route via arrival, on live credits -----------------------------------

def test_engine_arrival_splits_101_with_one_fee_and_no_retrigger():
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 1_000, DAVE: 0,
                PROPOSER: 0})
    # Bob's rule routes 20% of every arrival to Carol (party 0).
    result = ch.block([runner_install_tx(
        BOB, 0, clause="route20", parties=[[CAROL, 0]],
        triggers=["arrival"])], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    # Carol's own rule would route 50% onward to Dave — if a leg could
    # re-trigger. It cannot (the runner invariant).
    result = ch.block([runner_install_tx(
        CAROL, 0, clause="route50", parties=[[DAVE, 0]],
        triggers=["arrival"])], HEIGHT + 1, TS + 10)
    assert result.outcomes[0].status == "applied"

    double = ScriptedRunnerEvaluator()
    double.script("route20", lambda inputs: leg_outputs(
        [(0, int(inputs["i1"]) * 20 // 100)]))
    double.script("route50", lambda inputs: leg_outputs(
        [(0, int(inputs["i1"]) * 50 // 100)]))
    with runner_evaluator(double):
        result = ch.block([spend_tx(ALICE, BOB, 101, 0)], HEIGHT + 2, TS + 20)
    assert result.outcomes[0].status == "applied"
    # 101 at 20%: Carol's leg is 20, Bob keeps 81 — and Carol's leg is a
    # FINAL credit: her own 50% rule does not split it, Dave gets 0.
    assert ch.bal[CAROL] == 1_000 - 3 + 20
    assert ch.bal[DAVE] == 0
    assert ch.bal[BOB] == 1_000 - 3 + 81
    # Exactly ONE fee for the whole credit (the transfer's step fee);
    # the split charged nothing — the payments fee sink stays empty.
    assert ch.bal[ALICE] == 10_000 - 101 - 3
    assert ch.bal[PROPOSER] == 3 + 3 + 3
    assert ch.bal.get(FEE_SINK_PUBKEY, 0) == 0
    assert "Transfer split by payment rule" in _logs(result)
    # The clause was stepped ONCE, on the arrival facts (i14 = 3).
    assert len(double.calls) == 1
    assert double.calls[0][1]["i14"] == "3"


# --- execute trigger at apply ---------------------------------------------------

def test_engine_execute_trigger_open_execution_and_pays_once():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 1_000, PROPOSER: 0})
    result = ch.block([runner_install_tx(
        ALICE, 0, clause="pay200", parties=[[BOB, 0]],
        triggers=["execute"])], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    rule_id = ch.books().runner.get_by_owner(ALICE).terms.rule_id.hex()

    double = ScriptedRunnerEvaluator().script(
        "pay200", lambda inputs: leg_outputs([(0, 200)]))
    # Carol — any account — executes Alice's rule. The legs debit the
    # OWNER; the fee-bearing execution charges the EXECUTOR.
    with runner_evaluator(double):
        result = ch.block(
            [runner_execute_tx(rule_id, "sale-1", 200, CAROL, 0)],
            HEIGHT + 1, TS + 10)
    assert result.outcomes[0].status == "applied"
    assert ch.bal[BOB] == 200
    assert ch.bal[ALICE] == 10_000 - 3 - 200
    assert ch.bal[CAROL] == 1_000 - 3
    assert ch.bal[PROPOSER] == 3 + 3

    # A replay of the same event is refused at the shared check and its
    # fee unwinds with the rejection.
    with runner_evaluator(double):
        result = ch.block(
            [runner_execute_tx(rule_id, "sale-1", 200, BOB, 0)],
            HEIGHT + 2, TS + 20)
    assert result.outcomes[0].status == "invalid"
    assert result.outcomes[0].reason == "payment_not_applied"
    assert ch.bal[BOB] == 200 and ch.bal[ALICE] == 10_000 - 3 - 200
    assert ch.bal[PROPOSER] == 3 + 3


# --- clock trigger at apply: the sweep fires the standing rule ------------------

def test_engine_clock_sweep_fires_standing_rule_once_per_period():
    ch = Chain({ALICE: 10_000, BOB: 0, PROPOSER: 0})
    double = ScriptedRunnerEvaluator().script(
        "pay100", lambda inputs: leg_outputs([(0, 100)]))
    # The install block's own sweep fires period 0 (the standing-create
    # behaviour of the books build): Bob is paid, the run's fee — the
    # measured 3, within the signed bound of 10 — goes to the fee sink,
    # charged to the account, not the leg.
    with runner_evaluator(double):
        result = ch.block([runner_install_tx(
            ALICE, 0, clause="pay100", parties=[[BOB, 0]],
            triggers=["clock"], clock_anchor_ts=TS,
            clock_period_kind="week")], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    rule_id = ch.books().runner.get_by_owner(ALICE).terms.rule_id
    runs = result.governance_changes["payment_runner_runs"]
    assert runs == [(rule_id.hex(), "clock:0", 100, 3)]
    assert ch.bal[BOB] == 100
    assert ch.bal[ALICE] == 10_000 - 3 - 100 - 3
    assert ch.bal[FEE_SINK_PUBKEY] == 3

    # One period later the sweep fires exactly one more run.
    with runner_evaluator(double):
        result = ch.block([], HEIGHT + 1, TS + WEEK)
    runs = result.governance_changes["payment_runner_runs"]
    assert runs == [(rule_id.hex(), "clock:1", 100, 3)]
    assert ch.bal[BOB] == 200
    assert ch.bal[ALICE] == 10_000 - 3 - 200 - 6
    assert ch.bal[FEE_SINK_PUBKEY] == 6

    # A second block inside the same period fires nothing more.
    with runner_evaluator(double):
        result = ch.block([], HEIGHT + 2, TS + WEEK + 60)
    assert result.governance_changes["payment_runner_runs"] == []
    assert ch.bal[BOB] == 200
