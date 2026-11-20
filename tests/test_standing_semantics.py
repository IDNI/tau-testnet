"""The getstandingpayments capability semantics, pinned (Bounty 01, #34).

The command declares the semantics a wallet needs to predict
settlement -- time source, period kinds, month-end behaviour, one
execution per period, missed periods, the end-condition rule, who may
execute and who pays the fee, the validation bounds, and the network
binding of the signatures. A declaration that drifts from the code is
worse than none, so every field declared in
commands/getstandingpayments.SEMANTICS is pinned here against the
behaviour it declares.
"""

import json

import pytest

import db
import tau_defs
from bls_keys import pubkey_hex
from commands import getstandingpayments
from commands.getstandingpayments import SEMANTICS
from consensus.periods import (
    PERIOD_DAY,
    PERIOD_MONTH,
    PERIOD_WEEK,
    period_start,
    validate_schedule,
)
from consensus.standing import (
    END_FINAL_PERIOD,
    END_MAX_OCCURRENCES,
    END_MAX_TOTAL,
    MAX_HORIZON_SECONDS,
    MAX_OPEN_STANDING_PER_PAYER,
    MAX_OPEN_STANDING_TOTAL,
    StandingBook,
    StandingShapeError,
    StandingTerms,
    parse_standing_create,
    validate_standing_shape,
    validate_terms,
)
from consensus.tx_signing import network_binding, signing_message_bytes

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
ANCHOR = 1769817600  # 2026-01-31T12:00:00Z, a 31st anchor
DAY = 86_400


def _terms(**overrides):
    base = dict(
        payer=A,
        recipient=B,
        amount=1000,
        kind=PERIOD_MONTH,
        anchor_ts=ANCHOR,
        window_start_offset=0,
        window_end_offset=DAY,
        end_kind=END_MAX_OCCURRENCES,
        end_value=12,
        sequence_number=1,
    )
    base.update(overrides)
    return StandingTerms(**base)


def _book(**overrides):
    book = StandingBook()
    book.create(_terms(**overrides), tau_defs.MAX_TRANSFER_VALUE)
    return book


def test_the_command_declares_the_semantics():
    db.init_db()
    resp = getstandingpayments.execute(f"getstandingpayments {A}", None)
    payload = json.loads(resp)
    assert payload["status"] == "ok"
    assert payload["data"]["standing_payments"] == []
    declared = payload["data"]["semantics"]
    assert declared == SEMANTICS
    assert declared["supported"] is True


def test_time_source_is_block_timestamps():
    # due_period is a pure function of the block timestamp handed to
    # it: before the window nothing is due, inside it period 0 is due,
    # and the same question at the same timestamp always answers the
    # same -- no wall clock is consulted anywhere in the book.
    book = _book()
    sid = _terms().standing_id
    assert book.due_period(sid, ANCHOR - 60) is None
    assert book.due_period(sid, ANCHOR + 3600) == 0
    assert book.due_period(sid, ANCHOR + 3600) == 0


def test_period_kinds_are_day_week_month():
    assert SEMANTICS["period_kinds"] == ["day", "week", "month"]
    for kind in (PERIOD_DAY, PERIOD_WEEK, PERIOD_MONTH):
        validate_schedule(ANCHOR, kind)  # accepted
    with pytest.raises(ValueError):
        validate_schedule(ANCHOR, 3)  # no fourth kind exists


def test_month_end_is_clamped_to_the_last_day():
    assert SEMANTICS["month_end"] == "clamped_to_last_day_of_month"
    # Anchored on Jan 31: February's period starts on Feb 28 (2026 is
    # not a leap year), and March returns to the 31st -- the clamp does
    # not drift.
    feb = period_start(ANCHOR, PERIOD_MONTH, 1)
    mar = period_start(ANCHOR, PERIOD_MONTH, 2)
    assert feb == ANCHOR + 28 * DAY  # 2026-02-28T12:00:00Z
    assert mar == ANCHOR + 59 * DAY  # 2026-03-31T12:00:00Z


def test_one_execution_per_period():
    assert SEMANTICS["executions_per_period"] == 1
    book = _book()
    sid = _terms().standing_id
    period, amount = book.settle(sid, ANCHOR + 3600)
    assert (period, amount) == (0, 1000)
    # The same period can never be due or settled again.
    assert book.due_period(sid, ANCHOR + 3600) is None
    with pytest.raises(ValueError):
        book.settle(sid, ANCHOR + 3600)


def test_missed_periods_are_skipped_with_no_catch_up():
    assert SEMANTICS["missed_periods"] == "skipped_no_catch_up"
    book = _book()
    sid = _terms().standing_id
    # Period 0's window passes unsettled. Inside period 1's window the
    # book offers period 1 -- period 0 is lapsed, never due again.
    p1_start = period_start(ANCHOR, PERIOD_MONTH, 1)
    assert book.due_period(sid, p1_start + 60) == 1
    period, _amount = book.settle(sid, p1_start + 60)
    assert period == 1
    assert book.paid_for_period(sid, 1)
    assert not book.paid_for_period(sid, 0)


def test_end_condition_is_exactly_one_of_three():
    assert SEMANTICS["end_condition"] == "exactly_one_of_three_required"
    assert SEMANTICS["end_conditions"] == [
        "final_period",
        "max_occurrences",
        "max_total",
    ]
    base = {
        "tx_type": "standing_payment_create",
        "sender_pubkey": A,
        "recipient_pubkey": B,
        "amount": 1000,
        "sequence_number": 1,
        "period_kind": PERIOD_MONTH,
        "anchor_timestamp": ANCHOR,
        "window_start_offset": 0,
        "window_end_offset": DAY,
    }
    with pytest.raises(StandingShapeError):
        parse_standing_create(dict(base))  # none of the three
    with pytest.raises(StandingShapeError):
        parse_standing_create(
            dict(base, max_occurrences=12, max_total=12_000)
        )  # two of the three
    for field, kind in (
        ("final_period", END_FINAL_PERIOD),
        ("max_occurrences", END_MAX_OCCURRENCES),
        ("max_total", END_MAX_TOTAL),
    ):
        terms = parse_standing_create(dict(base, **{field: 12}))
        assert terms.end_kind == kind


def test_executor_is_anyone_and_pays_the_fee():
    assert SEMANTICS["executor"] == "anyone"
    assert SEMANTICS["fee_payer"] == "executor"
    # Carol is neither payer nor recipient; she executes, and the fee
    # comes out of her balance, not the payer's. (The apply-level
    # original is test_standing_apply.test_executor_pays_the_fee_not_the_payer.)
    from test_standing_apply import (
        ALICE,
        BOB,
        CAROL,
        DUE_JAN,
        Chain,
        _balances,
        _created_chain,
    )

    ch, sid = _created_chain(fee=7)
    assert ch.bal[ALICE] == 10_000 - 7  # creation fee, paid by its signer
    from test_standing_apply import execute_tx

    ex = execute_tx(sid.hex())  # Carol executes by default
    ch.block([ex], height=21, ts=DUE_JAN)
    assert ch.accepted(ex)
    assert ch.bal[ALICE] == 10_000 - 7 - 1_000  # exactly the amount, no fee
    assert ch.bal[BOB] == 1_000
    assert ch.bal[CAROL] == 100 - 7  # the executor paid the execution fee


def test_bounds_match_the_validation_constants():
    bounds = SEMANTICS["bounds"]
    assert bounds["max_open_per_payer"] == MAX_OPEN_STANDING_PER_PAYER
    assert bounds["max_open_total"] == MAX_OPEN_STANDING_TOTAL
    assert bounds["max_horizon_seconds"] == MAX_HORIZON_SECONDS
    assert bounds["amount_min"] == 1
    assert bounds["amount_max"] == tau_defs.MAX_TRANSFER_VALUE
    # The amount bounds are enforced, not just declared.
    with pytest.raises(ValueError):
        validate_terms(_terms(amount=0), tau_defs.MAX_TRANSFER_VALUE)
    with pytest.raises(ValueError):
        validate_terms(
            _terms(amount=tau_defs.MAX_TRANSFER_VALUE + 1),
            tau_defs.MAX_TRANSFER_VALUE,
        )
    validate_terms(
        _terms(amount=tau_defs.MAX_TRANSFER_VALUE), tau_defs.MAX_TRANSFER_VALUE
    )
    # The per-payer open cap is enforced.
    book = StandingBook()
    for seq in range(MAX_OPEN_STANDING_PER_PAYER):
        book.create(
            _terms(sequence_number=seq + 1), tau_defs.MAX_TRANSFER_VALUE
        )
    assert not book.can_admit_create(
        _terms(sequence_number=10_000), tau_defs.MAX_TRANSFER_VALUE
    )
    # The horizon is enforced against the block timestamp.
    far = _terms(anchor_ts=ANCHOR + MAX_HORIZON_SECONDS + DAY)
    assert validate_standing_shape(far, ANCHOR) is not None
    near = _terms(anchor_ts=ANCHOR + MAX_HORIZON_SECONDS - DAY)
    assert validate_standing_shape(near, ANCHOR) is None


def test_chain_binding_is_the_network_id_in_the_preimage():
    assert SEMANTICS["chain_binding"] == "network_id_in_signing_preimage"
    tx = {
        "tx_type": "standing_payment_create",
        "sender_pubkey": A,
        "recipient_pubkey": B,
        "amount": 1000,
        "sequence_number": 1,
        "expiration_time": 9_999_999_999,
        "fee_limit": "100",
        "period_kind": PERIOD_MONTH,
        "anchor_timestamp": ANCHOR,
        "window_start_offset": 0,
        "window_end_offset": DAY,
        "max_occurrences": 12,
    }
    decoded = json.loads(signing_message_bytes(tx))
    assert decoded["network_id"] == network_binding()
