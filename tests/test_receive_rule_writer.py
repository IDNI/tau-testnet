"""`recipient_policy.receive_rule`: the receiver's rule written from numbers.

"Only Alice", "30 days" and "500 a week" are numbers. The writer turns them
into an ordinary o5 clause; these tests hold what it writes to the rules of the
design, to the node's own deploy screens and to the limits of the record.
`test_recipient_policy_native.py` holds the written rules to the real engine.
"""
from unittest.mock import MagicMock

import pytest

import tau_defs
from consensus import recipient_policy
from consensus.admission import TipAdmissionView, validate_o5_clause_routing
from consensus.rule_offers import clause_body_v1, clause_comparison_count

ALICE = "8f" * 48
BOB = "3c" * 48
DAY, WEEK = 86_400, 604_800
NEVER = tau_defs.RECEIVE_NEVER
write = recipient_policy.receive_rule


def _same(written: str, expected: str) -> bool:
    return " ".join(written.split()) == " ".join(expected.split())


# The eight rules of the design, as posted.
ONLY_ALICE = """
always ( ( (i17[t]:bv[64] = { 0 }:bv[64]) || (i3[t]:bv[384] = { #x%s }:bv[384]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
""" % ALICE
FINAL_ONLY = """
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
"""
HOLD_AND_RECALL = """
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
        || ( (i17[t]:bv[64] = { 2 }:bv[64])
          && (i50[t]:bv[64] <= { 2592000 }:bv[64]) && (i51[t]:bv[64] <= { 3600 }:bv[64]) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
"""
MIN_ALLOWANCE = """
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64]) || (i53[t]:bv[64] = { 0 }:bv[64])
        || ( (i17[t]:bv[64] = { 2 }:bv[64])
          && (i52[t]:bv[64] >= ({ 500 }:bv[64]
               * ((i53[t]:bv[64] + { 604799 }:bv[64]) / { 604800 }:bv[64]))) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
"""
NO_LIMITS = """
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64]) || (i53[t]:bv[64] = { 0 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
"""
MIN_REFUND = """
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
        || ( (i17[t]:bv[64] = { 2 }:bv[64]) && (i54[t]:bv[64] >= { 7776000 }:bv[64]) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
"""
NO_REFUNDS = """
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64]) || (i54[t]:bv[64] = { 18446744073709551615 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
"""
EVERYTHING = """
always ( ( (i17[t]:bv[64] = { 0 }:bv[64])
        || ( (i3[t]:bv[384] = { #x%s }:bv[384])
          && ( (i17[t]:bv[64] = { 1 }:bv[64])
            || ( (i17[t]:bv[64] = { 2 }:bv[64])
              && (i50[t]:bv[64] <= { 2592000 }:bv[64]) && (i51[t]:bv[64] <= { 3600 }:bv[64])
              && ( (i53[t]:bv[64] = { 0 }:bv[64])
                || (i52[t]:bv[64] >= ({ 500 }:bv[64]
                     * ((i53[t]:bv[64] + { 604799 }:bv[64]) / { 604800 }:bv[64]))) )
              && (i54[t]:bv[64] >= { 7776000 }:bv[64]) ) ) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
""" % ALICE

EVERY_NUMBER = dict(senders=[ALICE], max_hold_seconds=30 * DAY, max_recall_seconds=3_600,
                    min_allowance=500, per_seconds=WEEK, min_refund_seconds=90 * DAY)
DESIGN = [
    ("only Alice", dict(senders=[ALICE]), ONLY_ALICE),
    ("instant and final only", dict(final_only=True), FINAL_ONLY),
    ("held 30 days, taken back within 1 hour",
     dict(max_hold_seconds=30 * DAY, max_recall_seconds=3_600), HOLD_AND_RECALL),
    ("at least 500 a week, or no limit", dict(min_allowance=500, per_seconds=WEEK),
     MIN_ALLOWANCE),
    ("no limits", dict(no_limits=True), NO_LIMITS),
    ("nothing refunded within 90 days", dict(min_refund_seconds=90 * DAY), MIN_REFUND),
    ("no refunds", dict(no_refunds=True), NO_REFUNDS),
    ("every condition in one rule", EVERY_NUMBER, EVERYTHING),
]


@pytest.mark.parametrize("name, numbers, posted", DESIGN, ids=[d[0] for d in DESIGN])
def test_the_writer_writes_the_rules_of_the_design(name, numbers, posted):
    assert _same(write(**numbers), posted)


def _view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {BOB}
    view.next_block_height = 10
    view.eligibility_mode = ""
    view.approval_slots_active = True
    view.recipient_policy_active = True
    view.clause_for.return_value = None
    return view


MORE = [
    dict(senders=[ALICE, BOB]),
    dict(senders=[ALICE], final_only=True),
    dict(max_hold_seconds=600),
    dict(max_hold_blocks=100),
    dict(max_hold_seconds=600, max_hold_blocks=100),
    dict(max_recall_seconds=0, max_hold_seconds=30 * DAY),
    dict(senders=[ALICE], max_hold_seconds=600, max_recall_blocks=5, max_hold_blocks=50),
    dict(min_allowance=500, per_seconds=30 * DAY, average=True),
    dict(min_allowance=500, per_seconds=WEEK, per_blocks=50_000),
    dict(min_allowance=16_777_215, per_seconds=31_622_400, max_hold_seconds=1),
    dict(senders=[ALICE], no_limits=True, no_refunds=True),
    dict(no_limits=True, max_hold_seconds=600, min_refund_blocks=1_000),
    dict(min_refund_seconds=NEVER),
    dict(EVERY_NUMBER, max_hold_blocks=1_000, max_recall_blocks=10, per_blocks=50_000,
         min_refund_blocks=200_000),
]
ALL_NUMBERS = [numbers for _name, numbers, _posted in DESIGN] + MORE


@pytest.mark.parametrize("numbers", ALL_NUMBERS)
def test_what_it_writes_registers_as_a_receive_rule(numbers):
    rule = write(**numbers)
    tx = {"tx_type": "user_tx", "sender_pubkey": BOB, "operations": {"0": rule}}
    result = validate_o5_clause_routing(tx, _view(), rule)
    assert result is not None and result.is_valid is True, getattr(result, "error", None)
    assert result.data["o5_clause_action"] == "declare"
    body = clause_body_v1(rule)
    assert recipient_policy.reads_receive_stream(body) is True
    assert recipient_policy.screen_receive_stream_width(body) is None
    assert clause_comparison_count(body) <= 32


def test_the_same_numbers_give_the_same_text():
    assert write(**EVERY_NUMBER) == write(**EVERY_NUMBER)
    assert write(senders=[ALICE.upper()]) == write(senders=[ALICE])


@pytest.mark.parametrize("numbers, said", [
    (dict(), "nothing to write"),
    (dict(senders=["zz"]), "96 hex"),
    (dict(senders=[ALICE, ALICE]), "listed twice"),
    (dict(final_only=True, max_hold_seconds=5), "final only"),
    (dict(final_only=True, no_refunds=True), "final only"),
    (dict(min_allowance=500), "together with its period"),
    (dict(per_seconds=WEEK), "together with its period"),
    (dict(min_allowance=0, per_seconds=WEEK), "from 1 to 16777215"),
    (dict(min_allowance=16_777_216, per_seconds=WEEK), "from 1 to 16777215"),
    (dict(min_allowance=5, per_seconds=0), "from 1 to 31622400"),
    (dict(min_allowance=5, per_seconds=31_622_401), "from 1 to 31622400"),
    (dict(min_allowance=5, per_blocks=1_000_001), "from 1 to 1000000"),
    (dict(min_allowance=5, per_seconds=WEEK, no_limits=True), "exclude each other"),
    (dict(min_refund_seconds=5, no_refunds=True), "exclude each other"),
    (dict(average=True, max_hold_seconds=5), "needs a minimum allowance"),
    (dict(max_hold_seconds=-1), "whole number"),
    (dict(max_hold_seconds=NEVER + 1), "whole number"),
    (dict(max_recall_blocks=1.5), "whole number"),
    (dict(max_hold_seconds=True), "whole number"),
])
def test_numbers_that_contradict_or_do_not_fit_are_refused(numbers, said):
    with pytest.raises(ValueError) as refused:
        write(**numbers)
    assert said in str(refused.value)


def test_a_list_too_long_for_one_clause_is_refused_with_the_reason():
    """The clause limits apply to a written rule as to any other."""
    many = ["%096x" % n for n in range(1, 40)]
    with pytest.raises(ValueError) as refused:
        write(senders=many[:30])
    assert "would not register" in str(refused.value) and "32" in str(refused.value)
    # 29 senders, "my own payment" and the two answers are the 32 comparisons
    assert clause_comparison_count(clause_body_v1(write(senders=many[:29]))) == 32


def test_a_period_inside_the_ceiling_cannot_make_the_rounding_wrap():
    """The strict reading adds `per - 1` to the payment's period. Both are at
    most the ceiling of the record, far below 2^64."""
    ceiling = tau_defs.RECEIVE_PERIOD_CEILING_SECONDS
    assert ceiling + (ceiling - 1) < 2 ** 64
    assert 16_777_215 * ((ceiling + ceiling - 1) // 1) < 2 ** 64
    # the average reading multiplies instead: cap x per and allowance x period
    assert 16_777_215 * ceiling < 2 ** 64
