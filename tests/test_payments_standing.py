"""Standing payments (#34, stage 1): tests built only from the public API
in consensus/payments.py and consensus/periods.py.

Deterministic and native-free: no tau_native, scripted policy gate and
fixed fee oracle doubles only.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone

import pytest

from consensus.payments import (
    DictLedger,
    FeeOracle,
    PaymentRefused,
    PaymentShapeError,
    PolicyGate,
    StandingBook,
    StandingTerms,
)

GENESIS = "ab" * 32
WRONG_GENESIS = "cd" * 32


def pk(i: int) -> str:
    return f"{i:096x}"


def ts(year: int, month: int, day: int, hour: int = 12, minute: int = 0) -> int:
    return int(
        datetime(year, month, day, hour, minute, tzinfo=timezone.utc).timestamp()
    )


START = ts(2027, 1, 31, 12, 0)


class ScriptedPolicyGate(PolicyGate):
    def __init__(self, allow: bool = True) -> None:
        self.allow = allow
        self.deny_payers = set()
        self.calls = []

    def allows_debit(self, payer, recipient, amount) -> bool:
        self.calls.append((payer, recipient, amount))
        return self.allow and payer not in self.deny_payers


class FixedFeeOracle(FeeOracle):
    def __init__(self, fee: int = 1) -> None:
        self.fee = fee

    def execution_fee(self, payer, recipient, amount) -> int:
        return self.fee


def make_terms(**overrides) -> StandingTerms:
    defaults = dict(
        payer=pk(1),
        payee=pk(2),
        amount=100,
        period_kind="month",
        start_ts=START,
        end_kind="count",
        end_value=12,
        max_fee_per_execution=5,
        genesis_hash=GENESIS,
        sequence_number=0,
    )
    defaults.update(overrides)
    return StandingTerms(**defaults)


def make_auth(book, **overrides):
    terms = make_terms(**overrides)
    return book.create(terms)


def make_book():
    return StandingBook(network_id=GENESIS)


def make_ledger(balance: int = 100000) -> DictLedger:
    return DictLedger({pk(1): balance})


def sweep(book, when, ledger, gate, fees):
    return book.sweep(
        ts=when, network_id=GENESIS, ledger=ledger, gate=gate, fees=fees
    )


def execute(book, auth_id, period_index, when, ledger, gate, fees, **kwargs):
    return book.execute_period(
        auth_id,
        period_index,
        ts=when,
        network_id=GENESIS,
        ledger=ledger,
        gate=gate,
        fees=fees,
        **kwargs,
    )


# 1
def test_monthly_authorization_executes_at_most_once_per_period():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book)

    first = sweep(book, START, ledger, gate, fees)
    assert len(first) == 1
    assert first[0].period_index == 0

    second = sweep(book, START, ledger, gate, fees)
    assert second == []

    fact = book.paid_fact(auth_id, 0)
    assert fact is not None
    assert fact["paid"] is True


# 2
def test_execution_outside_window_or_twice_in_period_rejected():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book)

    # Before period start (one hour before START)
    before = ts(2027, 1, 31, 11, 0)
    with pytest.raises(PaymentRefused):
        execute(book, auth_id, 0, before, ledger, gate, fees)

    # Settle period 0 inside its window
    settlement = execute(book, auth_id, 0, START, ledger, gate, fees)
    assert settlement.period_index == 0

    # Twice in same period
    with pytest.raises(PaymentRefused):
        execute(book, auth_id, 0, START, ledger, gate, fees)

    # Period 1 during period 0's window
    with pytest.raises(PaymentRefused):
        execute(book, auth_id, 1, START, ledger, gate, fees)


# 3
def test_any_party_can_trigger_but_cannot_alter_signed_terms():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book)

    settlement = execute(
        book, auth_id, 0, START, ledger, gate, fees, caller=pk(99)
    )
    assert settlement.payee == pk(2)
    assert settlement.amount == 100
    assert settlement.payer == pk(1)
    assert ledger.balance(pk(2)) == 100
    # Payer paid amount + fee (1)
    assert ledger.balance(pk(1)) == 100000 - 101
    # Unrelated caller received nothing
    assert ledger.balance(pk(99)) == 0


# 4
def test_cancel_prevents_all_later_executions():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book, max_catch_up=3)

    with pytest.raises(PaymentRefused):
        book.cancel(auth_id, signer=pk(2))

    book.cancel(auth_id, signer=pk(1))
    assert book.get(auth_id).status == "cancelled"

    # Later sweep, several periods missed, catch-up signed -- still nothing
    later = ts(2027, 4, 30, 12, 0)  # period 3 window
    result = sweep(book, later, ledger, gate, fees)
    assert result == []
    assert ledger.balance(pk(2)) == 0

    with pytest.raises(PaymentRefused):
        execute(book, auth_id, 3, later, ledger, gate, fees)


# 5
def test_insufficient_funds_no_debt_no_partial_no_false_completion():
    book = make_book()
    # amount 100 + fee 1 = 101 needed; give only 50
    ledger = make_ledger(balance=50)
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book)

    result = sweep(book, START, ledger, gate, fees)
    assert result == []
    assert ledger.balance(pk(2)) == 0
    assert ledger.balance(pk(1)) == 50
    assert book.paid_fact(auth_id, 0) is None
    state = book.get(auth_id)
    assert state.cumulative_spent == 0
    assert 0 not in state.settled
    assert 0 not in state.skipped

    # Fund the payer and sweep again in the same window -- settles it
    ledger.credit(pk(1), 1000)
    result2 = sweep(book, START, ledger, gate, fees)
    assert len(result2) == 1
    assert result2[0].period_index == 0
    assert ledger.balance(pk(2)) == 100
    assert book.paid_fact(auth_id, 0) is not None
    assert book.get(auth_id).cumulative_spent == 100


# 6
def test_replay_and_cross_network_execution_rejected():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book)

    execute(book, auth_id, 0, START, ledger, gate, fees)

    # Replay same period
    with pytest.raises(PaymentRefused):
        execute(book, auth_id, 0, START, ledger, gate, fees)

    # Cross-network execution: period 1 in its own window, wrong network
    period1_ts = ts(2027, 2, 28, 12, 0)
    with pytest.raises(PaymentRefused):
        book.execute_period(
            auth_id,
            1,
            ts=period1_ts,
            network_id=WRONG_GENESIS,
            ledger=ledger,
            gate=gate,
            fees=fees,
        )

    # Terms bound to a wrong genesis are refused at creation
    bad_terms = make_terms(genesis_hash=WRONG_GENESIS, sequence_number=99)
    with pytest.raises(PaymentShapeError):
        book.create(bad_terms)


# 7
def test_current_policy_and_book_local_total_apply_exactly_once():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book)

    r0 = sweep(book, START, ledger, gate, fees)
    assert len(r0) == 1
    r1 = sweep(book, ts(2027, 2, 28, 12, 0), ledger, gate, fees)
    assert len(r1) == 1

    assert len(gate.calls) == 2
    state = book.get(auth_id)
    assert state.cumulative_spent == 2 * 100

    # Current policy now denies -- period 2 settles nothing
    gate.allow = False
    r2 = sweep(book, ts(2027, 3, 31, 12, 0), ledger, gate, fees)
    assert r2 == []
    assert book.get(auth_id).cumulative_spent == 2 * 100

    # --- Book-local total end condition ---
    book2 = make_book()
    ledger2 = make_ledger()
    gate2 = ScriptedPolicyGate()
    fees2 = FixedFeeOracle()
    auth2 = make_auth(book2, end_kind="total", end_value=250)

    assert len(sweep(book2, START, ledger2, gate2, fees2)) == 1
    assert len(sweep(book2, ts(2027, 2, 28, 12, 0), ledger2, gate2, fees2)) == 1
    state2 = book2.get(auth2)
    assert state2.cumulative_spent == 200

    # Third would exceed 250 (200 + 100 > 250) -- refused by sweep
    r_third = sweep(book2, ts(2027, 3, 31, 12, 0), ledger2, gate2, fees2)
    assert r_third == []
    assert book2.get(auth2).cumulative_spent == 200
    assert book2.get(auth2).status == "completed"


# 8
def test_admission_and_apply_agree_on_authorization_state():
    # Each scenario builder returns (book, ledger, gate, fees, auth_id)
    def fresh():
        book = make_book()
        ledger = make_ledger()
        gate = ScriptedPolicyGate()
        fees = FixedFeeOracle()
        auth_id = make_auth(book)
        return book, ledger, gate, fees, auth_id

    def already_settled():
        book, ledger, gate, fees, auth_id = fresh()
        execute(book, auth_id, 0, START, ledger, gate, fees)
        return book, ledger, gate, fees, auth_id

    def cancelled():
        book, ledger, gate, fees, auth_id = fresh()
        book.cancel(auth_id, signer=pk(1))
        return book, ledger, gate, fees, auth_id

    def insufficient():
        book = make_book()
        ledger = make_ledger(balance=50)
        gate = ScriptedPolicyGate()
        fees = FixedFeeOracle()
        auth_id = make_auth(book)
        return book, ledger, gate, fees, auth_id

    def policy_deny():
        book, ledger, gate, fees, auth_id = fresh()
        gate.allow = False
        return book, ledger, gate, fees, auth_id

    scenarios = [fresh, already_settled, cancelled, insufficient, policy_deny]

    for build in scenarios:
        book, ledger, gate, fees, auth_id = build()

        can, _reason = book.can_execute(
            auth_id, 0, START, GENESIS, ledger, gate, fees
        )

        # Apply on a deepcopy with fresh doubles replicating the scenario
        book_copy = copy.deepcopy(book)
        ledger_copy = copy.deepcopy(ledger)
        gate_copy = ScriptedPolicyGate(allow=gate.allow)
        gate_copy.deny_payers = set(gate.deny_payers)
        fees_copy = FixedFeeOracle(fee=fees.fee)

        succeeded = False
        try:
            book_copy.execute_period(
                auth_id,
                0,
                ts=START,
                network_id=GENESIS,
                ledger=ledger_copy,
                gate=gate_copy,
                fees=fees_copy,
            )
            succeeded = True
        except PaymentRefused:
            succeeded = False

        assert can == succeeded, (
            f"scenario {build.__name__}: can_execute={can} but apply succeeded={succeeded}"
        )


# 9
def test_monthly_on_31st_runs_last_day_short_month():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book)

    # Anchor Jan 31; period 0 is [Jan 31, Feb 28), period 1 [Feb 28, Mar 31),
    # period 2 [Mar 31, Apr 30).
    # Sweep at Feb 28 settles period 1 (period 0 is missed/skipped by default)
    r_feb = sweep(book, ts(2027, 2, 28, 12, 0), ledger, gate, fees)
    assert [s.period_index for s in r_feb] == [1]
    assert book.paid_fact(auth_id, 1) is not None

    # Mar 30 is still inside period 1 -- nothing for period 2
    r_mar30 = sweep(book, ts(2027, 3, 30, 12, 0), ledger, gate, fees)
    assert r_mar30 == []
    assert book.paid_fact(auth_id, 2) is None

    # Mar 31 settles period 2 -- anchor did not drift to Mar 28/30
    r_mar31 = sweep(book, ts(2027, 3, 31, 12, 0), ledger, gate, fees)
    assert [s.period_index for s in r_mar31] == [2]
    assert book.paid_fact(auth_id, 2) is not None


# 10
def test_missed_period_skipped_by_default():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book, max_catch_up=0)

    # First sweep in period 2's window
    result = sweep(book, ts(2027, 3, 31, 12, 0), ledger, gate, fees)
    assert [s.period_index for s in result] == [2]
    state = book.get(auth_id)
    assert state.skipped == {0, 1}
    assert set(state.settled.keys()) == {2}


# 11
def test_catch_up_bounded_by_signed_max():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book, max_catch_up=2)

    # First sweep in period 3's window: missed 0,1,2; current 3
    result = sweep(book, ts(2027, 4, 30, 12, 0), ledger, gate, fees)
    assert {s.period_index for s in result} == {1, 2, 3}
    state = book.get(auth_id)
    assert set(state.settled.keys()) == {1, 2, 3}
    assert state.skipped == {0}


# 12
def test_catch_up_occurrences_counted_once_each():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle()
    auth_id = make_auth(book, max_catch_up=2)

    result = sweep(book, ts(2027, 4, 30, 12, 0), ledger, gate, fees)
    assert len(result) == 3
    state = book.get(auth_id)
    assert state.cumulative_spent == 3 * 100
    assert state.completed_count == 3
    assert len(gate.calls) == 3


# 13
def test_authorization_without_end_condition_refused():
    with pytest.raises(PaymentShapeError):
        make_terms(end_kind="none")

    with pytest.raises(PaymentShapeError):
        make_terms(end_kind="count", end_value=0)


# 14
def test_paid_fact_readable():
    book = make_book()
    ledger = make_ledger()
    gate = ScriptedPolicyGate()
    fees = FixedFeeOracle(fee=1)
    auth_id = make_auth(book)

    sweep(book, START, ledger, gate, fees)

    fact = book.paid_fact(auth_id, 0)
    assert fact is not None
    assert fact["paid"] is True
    assert fact["amount"] == 100
    assert fact["fee"] == 1
    assert fact["period_index"] == 0

    # Unknown / unsettled period returns None
    assert book.paid_fact(auth_id, 7) is None
    assert book.paid_fact(b"\x00" * 32, 0) is None
