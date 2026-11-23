"""Payout rules outside block apply: admission, signing, the meta hash,
persistence, RPC, gossip, the command line and the book's own invariants.

The admission tests end with a corpus judged by BOTH the admission validator and
the book apply consults: they must accept and reject the same rules, or a
proposer and the mempool disagree about what can land.
"""
import copy
import json
import types
from unittest.mock import MagicMock

import pytest

import chain_state
import db
import tau_defs
from commands import getpayoutrule, gettxstatus
from consensus import sender_policy
from consensus.admission import (
    TipAdmissionView,
    validate_mempool_admission,
    validate_payout_execute_payload,
    validate_payout_rule_revoke_payload,
    validate_payout_rule_set_payload,
    validate_payout_rule_update_payload,
)
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.lanes import LANE_FAST, LANE_SLOW, TAU_EVALUATING_TX_TYPES, classify_lane
from consensus.network_binding import chain_genesis_hash
from consensus.payout import (
    MAX_SLOTS,
    PayoutBook,
    PayoutShapeError,
    abi_width,
    parse_payout_execute,
    parse_payout_rule_set,
    parse_payout_spec,
    payout_rule_body,
    payout_spec_text,
    screen_payout_body,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_checks import apply_tx_error
from consensus.tx_signing import signing_message_bytes
from errors import DatabaseError
from network.service import _SNAPSHOT_TX_TYPES, NetworkService

from bls_keys import pubkey_hex

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
C = pubkey_hex(0x3C)
NEXT_HEIGHT = 50
TIP_TS = 1_767_225_600
FAR = 9_999_999_999
KEY = "payout_rules_root"
RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
BODY = payout_rule_body(RULE)


def rule_set(**over):
    tx = {
        "tx_type": "payout_rule_set", "genesis_hash": chain_genesis_hash(),
        "sender_pubkey": A, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
        "rule_text": RULE, "slots": [B], "cap_per_execution": 100, "cap_per_period": 300,
        "period_blocks": 10, "expires_at": NEXT_HEIGHT + 1000,
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def execute(default_id, **over):
    rule_id = over.pop("rule_id", default_id)
    tx = {
        "tx_type": "payout_execute", "genesis_hash": chain_genesis_hash(),
        "sender_pubkey": C, "sequence_number": 0,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
        "account_pubkey": A, "rule_id": rule_id, "recipients": {}, "data": {"0": 40},
    }
    tx.update(over)
    return tx


def revoke(signer=A, rule_id="00" * 32):
    return {"tx_type": "payout_rule_revoke", "genesis_hash": chain_genesis_hash(),
            "sender_pubkey": signer, "sequence_number": 2,
            "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "0",
            "rule_id": rule_id}


def update(default_id, **over):
    """A payout_rule_update naming `default_id`, with the rule fields of rule_set."""
    rule_id = over.pop("rule_id", default_id)
    tx = {
        "tx_type": "payout_rule_update", "genesis_hash": chain_genesis_hash(),
        "sender_pubkey": A, "sequence_number": 2,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
        "rule_id": rule_id, "rule_text": RULE, "slots": [B], "cap_per_execution": 100,
        "cap_per_period": 300, "period_blocks": 10, "expires_at": NEXT_HEIGHT + 1000,
    }
    tx.update(over)
    return tx


@pytest.fixture
def evaluator():
    mock = MockPolicyEvaluator(pool="payout_admission")
    mock.set_outputs(BODY, lambda inputs: {"o30": inputs.get("i40", "0")})
    sender_policy.set_evaluator("payout_admission", mock)
    yield mock
    sender_policy.set_evaluator("payout_admission", None)


@pytest.fixture
def book():
    return PayoutBook()


@pytest.fixture
def tip_view(book, evaluator, monkeypatch):
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = TIP_TS
    view.next_block_timestamp = TIP_TS
    view.payout_book.return_value = book
    view.clause_for.return_value = None
    monkeypatch.setitem(chain_state._balances, A, 1_000)
    return view


def _installed(book, **over):
    terms = parse_payout_rule_set(rule_set(**over))
    book.install(terms, NEXT_HEIGHT - 1)
    return terms


# --- parsing and the ABI screen ----------------------------------------------------

def test_the_abi_widths():
    assert abi_width("i2") == 24 and abi_width("i13") == 384 and abi_width("i26") == 24
    assert abi_width("i30", 2) == 384 and abi_width("i32", 2) is None
    assert abi_width("o31", 2) == 24 and abi_width("o32", 2) is None
    assert abi_width("i40") == abi_width("i47") == 24
    assert abi_width("i48") == abi_width("i49") == 64   # the kept clocks
    assert abi_width("o5") is None and abi_width("i1") is None and abi_width("i0") is None


@pytest.mark.parametrize("body, problem", [
    (BODY, None),
    ("o30[t]:bv[24] = i40[t]", "must be written"),
    ("o30[t]:bv[24] = i41[t]:bv[24] + i2[t]:bv[24]", None),
    ("o30[t]:bv[24] = i3[t]:bv[24]", "not part of the payout ABI"),
    ("o30[t]:bv[24] = i13[t]:bv[24]", "must be bv[384]"),
    ("o30[t]:bv[24] = { #x000005 }:bv[24]", "read at least one input"),
    ("i40[t]:bv[24] = { #x000005 }:bv[24]", "write at least one slot"),
])
def test_the_screen(body, problem):
    got = screen_payout_body(body, 1)
    assert (got is None) if problem is None else (problem in got), got


_O, _P = "o30[t]:bv[24]", "o31[t]:bv[24]"
_X, _Y = "i40[t]:bv[24]", "i41[t]:bv[24]"
_Z = "{ #x000000 }:bv[24]"
_KEY = "{ #x" + "ab" * 48 + " }:bv[384]"


@pytest.mark.parametrize("body, problem", [
    # every amount fixed: definitions, a choice on inputs
    (f"{_O} = {_X}", None),
    (f"({_O} = {_X}) && ({_P} = {_Y})", None),
    (f"(i13[t]:bv[384] = {_KEY}) ? ({_O} = {_X}) : ({_O} = {_Z})", None),
    (f"(i13[t]:bv[384] = {_KEY}) ? (({_O} = {_X}) && ({_P} = {_Z})) : (({_O} = {_Z}) && ({_P} = {_X}))", None),
    (f"({_X} > {_Z}) ? ({_O} = min({_X}, i2[t]:bv[24])) : ({_O} = {_Z})", None),
    (f"({_X} > {_Z} || {_Y} > {_Z}) ? ({_O} = {_X} - {_Y}) : ({_O} = {_Z})", None),
    (f"{_O} = {{ 5 }}:bv[24] + {_X}'", None),
    # a bare condition beside an amount: no answer where it does not hold
    (f"({_X} > {_Z}) && {_O} = min({_X}, i2[t]:bv[24])", "a bare condition on inputs"),
    (f"({_X} > {_Z} || {_Y} > {_Z}) && {_O} = {_X} - {_Y}", "a bare condition on inputs"),
    (f"({_X} > {_Z}) ? (({_Y} > {_Z}) && {_O} = {_X}) : ({_O} = {_Z})", "a bare condition on inputs"),
    # an amount the rule leaves open: the engine would pick one
    (f"{_O} <= {_X}", "o30 is not fixed"),
    (f"{_O} > {_Z} && {_O} < i2[t]:bv[24]", "o30 is not fixed"),
    (f"({_O} = {_X}) || ({_O} = {_Z})", "o30 is not fixed"),
    (f"!({_O} = {_X})", "o30 is not fixed"),
    (f"({_X} > {_Z}) ? ({_O} = {_X}) : ({_X} = {_X})", "fixed on one side of a condition only"),
    (f"({_O} = {_X}) ? ({_O} = {_X}) : ({_O} = {_Z})", "a condition may read inputs only"),
    (f"{_P} = {_O} && {_O} = {_X}", "not by another amount"),
    (f"{_O} = {_X} && {_P} = {_Y} || {_X} > {_Z}", "put parentheses around"),
    (f"{_X} > {_Z} || {_Y} > {_Z} && {_O} = {_X}", "put parentheses around"),
    (f"!({_X} = {_Z}) && {_O} = {_X}", "put parentheses around"),
    (f"({_X} = {_Z}) ? ({_O} = {_X}) : ({_O} = {_Z}) && {_P} = {_X}", "put parentheses around"),
    # anything that reads earlier steps, in every spelling the engine parses
    (f"{_O} = {_X} && ({_X} = {_Z} since {_Y} = {_Z})", "may not use 'since'"),
    (f"{_O} = {_X} && ({_X} = {_Z} S {_Y} = {_Z})", "may not use 'S'"),
    (f"{_O} = {_X} && ({_X} = {_Z} U {_Y} = {_Z})", "may not use 'U'"),
    (f"{_O} = {_X} && <> ({_X} = {_Z})", "may not use '<>'"),
    (f"{_O} = {_X} && [] ({_X} = {_Z})", "may not use '[]"),
    (f"{_O} = {_X} && G ({_X} = {_Z})", "may not use 'G'"),
    (f"{_O} = {_X} && F", "may not use 'F'"),
    (f"{_O} = {_X} && [t > 3]", "may not use '[t'"),
    (f"{_O} = {_X} && ex x ({_X} = x)", "may not use 'ex'"),
    (f"{_O} = {_X} && <a:b>", "may not use"),
    (f"{_O} = -{_X}", "may not use '-'"),
])
def test_every_amount_is_fixed_and_reads_this_step_only(body, problem):
    got = screen_payout_body(body, 2)
    assert (got is None) if problem is None else (got is not None and problem in got), got


def test_slots_must_be_keys_or_open():
    with pytest.raises(PayoutShapeError):
        parse_payout_rule_set(rule_set(slots=[]))
    with pytest.raises(PayoutShapeError):
        parse_payout_rule_set(rule_set(slots=["xyz"]))
    with pytest.raises(PayoutShapeError):
        parse_payout_rule_set(rule_set(slots=[B] * (MAX_SLOTS + 1)))
    assert parse_payout_rule_set(rule_set(slots=[""])).slots == ("",)


def test_exactly_one_period_clock():
    with pytest.raises(PayoutShapeError, match="exactly one"):
        parse_payout_rule_set(rule_set(period_seconds=60))
    with pytest.raises(PayoutShapeError, match="exactly one"):
        parse_payout_rule_set(rule_set(period_blocks=None))


@pytest.mark.parametrize("over", [
    {"recipients": {"8": B}}, {"recipients": {"00": B}}, {"recipients": {"0": "nope"}},
    {"data": {"8": 1}}, {"data": {"0": -1}}, {"data": {"0": tau_defs.MAX_TRANSFER_VALUE + 1}},
    {"data": {"0": True}}, {"rule_id": "AB" * 32}, {"account_pubkey": "x"},
])
def test_malformed_executions(over):
    with pytest.raises(PayoutShapeError):
        parse_payout_execute(execute("ab" * 32, **dict(over)))


def test_every_term_changes_the_rule_id():
    base = parse_payout_rule_set(rule_set()).rule_id
    for over in ({"sequence_number": 2}, {"rule_text": RULE.replace("i40", "i41")},
                 {"slots": [C]}, {"slots": [""]}, {"cap_per_execution": 99},
                 {"cap_per_period": 299}, {"period_blocks": 11},
                 {"period_blocks": None, "period_seconds": 10}, {"expires_at": NEXT_HEIGHT + 999},
                 {"sender_pubkey": C}):
        assert parse_payout_rule_set(rule_set(**over)).rule_id != base, over
    # Formatting of the rule text does not: the body is normalized.
    spaced = RULE.replace("( ", "(   ")
    assert parse_payout_rule_set(rule_set(rule_text=spaced)).rule_id == base


def test_spec_text_round_trips_and_must_be_canonical():
    tx = rule_set()
    text = payout_spec_text(tx)
    assert parse_payout_spec(text, A, 1).rule_id == parse_payout_rule_set(tx).rule_id
    stored = payout_spec_text(tx, 1)
    assert parse_payout_spec(stored, A).rule_id == parse_payout_rule_set(tx).rule_id
    with pytest.raises(PayoutShapeError, match="exactly one sequence"):
        parse_payout_spec(stored, A, 1)
    with pytest.raises(PayoutShapeError, match="canonical"):
        parse_payout_spec(json.dumps(json.loads(text), indent=1), A, 1)
    with pytest.raises(PayoutShapeError, match="may carry only"):
        parse_payout_spec(payout_spec_text(tx)[:-1] + ',"zz":1}', A, 1)


# --- admission ---------------------------------------------------------------------

def test_a_valid_rule_is_admitted_with_its_id(tip_view, evaluator):
    result = validate_payout_rule_set_payload(rule_set(), tip_view)
    assert result.is_valid, result.error
    assert result.data["rule_id"] == parse_payout_rule_set(rule_set()).rule_id.hex()
    assert evaluator.validate_calls == [BODY]


@pytest.mark.parametrize("over, code", [
    ({"slots": [A]}, "INVALID_PAYOUT_RULE"),
    ({"slots": ["ab" * 48]}, "INVALID_PAYOUT_RULE"),
    ({"cap_per_execution": 0}, "INVALID_PAYOUT_RULE"),
    ({"rule_text": "nope"}, "INVALID_PAYOUT_RULE"),
    ({"expires_at": NEXT_HEIGHT}, "INVALID_PAYOUT_RULE"),
])
def test_rule_refusals_carry_a_code(tip_view, over, code):
    assert validate_payout_rule_set_payload(rule_set(**over), tip_view).code == code


def test_a_rule_that_does_not_build_is_refused(tip_view, evaluator):
    evaluator.fail_build(BODY, "bad")
    assert validate_payout_rule_set_payload(rule_set(), tip_view).code == \
        "PAYOUT_RULE_DOES_NOT_BUILD"


def test_a_guard_refuses_a_direct_install(tip_view):
    guard = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
    tip_view.clause_for.side_effect = lambda who, idx: (
        guard if idx == tau_defs.RULE_CHANGE_GUARD_INDEX else None)
    mock = MockPolicyEvaluator(pool="admission")
    mock.set_verdict(guard, 0)
    sender_policy.set_evaluator("admission", mock)
    try:
        result = validate_payout_rule_set_payload(rule_set(), tip_view)
        assert result.code == "RULE_CHANGE_NEEDS_APPROVAL"
        assert mock.verdict_calls[0][1]["i1"] == str(tau_defs.RULE_CHANGE_KIND_SET_PAYOUT)
    finally:
        sender_policy.set_evaluator("admission", None)


def test_a_guard_refuses_a_direct_update(tip_view, book):
    terms = _installed(book)
    guard = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
    tip_view.clause_for.side_effect = lambda who, idx: (
        guard if idx == tau_defs.RULE_CHANGE_GUARD_INDEX else None)
    mock = MockPolicyEvaluator(pool="admission")
    mock.set_verdict(guard, 0)
    sender_policy.set_evaluator("admission", mock)
    try:
        result = validate_payout_rule_update_payload(
            update(terms.rule_id.hex()), tip_view)
        assert result.code == "RULE_CHANGE_NEEDS_APPROVAL"
        assert mock.verdict_calls[0][1]["i1"] == str(tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT)
    finally:
        sender_policy.set_evaluator("admission", None)


def test_book_full_and_duplicate(tip_view, book, monkeypatch):
    terms = _installed(book)
    tx = rule_set()
    assert validate_payout_rule_set_payload(tx, tip_view).code == "DUPLICATE_PAYOUT_RULE"
    import consensus.payout as payout
    monkeypatch.setattr(payout, "MAX_PAYOUT_RULES_TOTAL", 1)
    other = rule_set(sender_pubkey=C, slots=[B])
    assert validate_payout_rule_set_payload(other, tip_view).code == "PAYOUT_BOOK_FULL"
    # A second rule for your own account needs free room too: installing
    # never replaces, so the full book refuses it as well.
    assert validate_payout_rule_set_payload(
        rule_set(sequence_number=2), tip_view).code == "PAYOUT_BOOK_FULL"
    assert terms.account_pubkey == A


def test_revoke_admission(tip_view, book):
    assert validate_payout_rule_revoke_payload(revoke(), tip_view).code == "NO_PAYOUT_RULE"
    terms = _installed(book)
    assert validate_payout_rule_revoke_payload(
        revoke(rule_id=terms.rule_id.hex()), tip_view).is_valid
    assert not validate_payout_rule_revoke_payload(
        revoke(signer=B, rule_id=terms.rule_id.hex()), tip_view).is_valid


def test_execute_admission_reports_the_legs(tip_view, book, evaluator):
    terms = _installed(book)
    result = validate_payout_execute_payload(execute(terms.rule_id.hex()), tip_view)
    assert result.is_valid, result.error
    assert result.data["total"] == 40
    assert result.data["legs"] == [{"slot": 0, "recipient_pubkey": B, "amount": 40}]
    inputs = evaluator.output_calls[0][1]
    assert inputs["i2"] == "1000" and inputs["i13"] == "#x" + C


@pytest.mark.parametrize("over, why", [
    ({"data": {"0": 101}}, "cap per execution"),
    ({"data": {"0": 0}}, "pays nothing"),
    ({"rule_id": "00" * 32}, "no payout rule with that id"),
    ({"recipients": {"0": C}}, "fixed recipient"),
])
def test_execute_refusals(tip_view, book, over, why):
    terms = _installed(book)
    result = validate_payout_execute_payload(execute(terms.rule_id.hex(), **over), tip_view)
    assert result.code == "PAYOUT_REFUSED" and why in result.error


def test_the_dispatcher_routes_all_four_types(tip_view, book):
    terms = _installed(book)
    assert validate_mempool_admission(rule_set(sequence_number=2), tip_view).is_valid
    assert validate_mempool_admission(execute(terms.rule_id.hex()), tip_view).is_valid
    assert validate_mempool_admission(
        update(terms.rule_id.hex()), tip_view).is_valid
    assert validate_mempool_admission(
        revoke(rule_id=terms.rule_id.hex()), tip_view).is_valid


CORPUS = [
    rule_set(),
    rule_set(slots=[A]),
    rule_set(slots=[B, B], rule_text="always ( (o30[t]:bv[24] = i40[t]:bv[24]) && "
             "(o31[t]:bv[24] = i40[t]:bv[24]) )."),
    rule_set(cap_per_execution=0),
    rule_set(cap_per_execution=301),
    rule_set(cap_per_period=tau_defs.MAX_TRANSFER_VALUE + 1),
    rule_set(period_blocks=0),
    rule_set(period_blocks=1_000_001),
    rule_set(period_blocks=None, period_seconds=31_622_401, expires_at=TIP_TS + 100),
    rule_set(period_blocks=None, period_seconds=60, expires_at=TIP_TS),
    rule_set(period_blocks=None, period_seconds=60, expires_at=TIP_TS + 4 * 31_622_400 + 1),
    rule_set(expires_at=NEXT_HEIGHT + 10_000_001),
    rule_set(rule_text="always ( o30[t]:bv[16] = i40[t]:bv[16] )."),
    rule_set(rule_text="always ( o30[t]:bv[24] = i40[t-1]:bv[24] )."),
]


@pytest.mark.parametrize("tx", CORPUS)
def test_admission_and_apply_agree_on_every_rule(tip_view, tx):
    admitted = validate_payout_rule_set_payload(tx, tip_view)
    terms = parse_payout_rule_set(tx)
    applied, reason = PayoutBook().can_admit_set(terms, NEXT_HEIGHT, TIP_TS)
    assert admitted.is_valid == applied, (admitted.error, reason)


# --- signing and shared checks -------------------------------------------------------

@pytest.mark.parametrize("field, value", [
    ("rule_text", RULE.replace("i40", "i41")), ("slots", [C]), ("cap_per_execution", 99),
    ("cap_per_period", 299), ("period_blocks", 11), ("period_seconds", 10),
    ("expires_at", 7), ("fee_limit", "11"),
])
def test_every_term_of_a_rule_is_signed(field, value):
    assert signing_message_bytes(rule_set(**{field: value})) != signing_message_bytes(rule_set())


@pytest.mark.parametrize("field, value", [
    ("account_pubkey", B), ("rule_id", "11" * 32), ("recipients", {"0": B}),
    ("data", {"0": 41}), ("data", {"1": 40}),
])
def test_every_part_of_an_execution_is_signed(field, value):
    base = execute("00" * 32)
    assert signing_message_bytes(execute("00" * 32, **{field: value})) != \
        signing_message_bytes(base)


def test_apply_refuses_a_slot_or_recipient_that_is_not_a_key():
    assert apply_tx_error(rule_set(slots=["ab" * 48]))[0] == "invalid_recipient_key"
    assert apply_tx_error(rule_set(slots=[""])) is None
    assert apply_tx_error(execute("00" * 32, recipients={"0": "ab" * 48}))[0] == \
        "invalid_recipient_key"
    assert apply_tx_error(execute("00" * 32, account_pubkey="ab" * 48))[0] == \
        "invalid_recipient_key"
    assert apply_tx_error(rule_set()) is None and apply_tx_error(execute("00" * 32)) is None


def test_lanes_and_tau_needs():
    assert classify_lane(rule_set()) == LANE_SLOW
    assert classify_lane(update("00" * 32)) == LANE_SLOW
    assert classify_lane(execute("00" * 32)) == LANE_FAST
    assert classify_lane(revoke()) == LANE_FAST
    assert {"payout_rule_set", "payout_rule_update",
            "payout_execute"} <= TAU_EVALUATING_TX_TYPES
    assert "payout_rule_revoke" not in TAU_EVALUATING_TX_TYPES


def test_engine_and_admission_agree_on_who_pays_a_fee():
    from commands import sendtx
    from consensus import engine

    assert engine.FEE_BEARING_TX_TYPES == sendtx.FEE_BEARING_TX_TYPES
    assert {"payout_rule_set", "payout_rule_update",
            "payout_execute"} <= sendtx.FEE_BEARING_TX_TYPES
    assert "payout_rule_revoke" not in sendtx.FEE_BEARING_TX_TYPES
    assert {"payout_rule_set", "payout_rule_update", "payout_rule_revoke",
            "payout_execute"} <= sendtx.KNOWN_TX_TYPES


# --- the book and the meta hash --------------------------------------------------------

def test_an_unused_book_leaves_the_meta_hash_as_it_was():
    lm = ConsensusLifecycleManager()
    assert KEY not in build_mechanism_metadata("supermajority")
    before = lm.consensus_meta_hash()
    lm.payout_rules = PayoutBook()
    assert lm.consensus_meta_hash() == before


def test_the_book_is_bound_once_used_and_stays_bound():
    lm = ConsensusLifecycleManager()
    empty = lm.consensus_meta_hash()
    terms = _installed(lm.payout_rules)
    opened = lm.consensus_meta_hash()
    lm.payout_rules.record(A, terms.rule_id, 10, NEXT_HEIGHT, TIP_TS)
    spent = lm.consensus_meta_hash()
    lm.payout_rules.revoke(A, terms.rule_id)
    closed = lm.consensus_meta_hash()
    assert len({empty, opened, spent, closed}) == 4


def test_a_copy_does_not_leak_into_its_original(book):
    terms = _installed(book)
    root = book.root()
    clone = copy.deepcopy(book)
    clone.record(A, terms.rule_id, 10, NEXT_HEIGHT, TIP_TS)
    clone.install(parse_payout_rule_set(rule_set(sender_pubkey=C)), NEXT_HEIGHT)
    clone.revoke(A, terms.rule_id)
    assert book.root() == root and book.get(A) is not None and book.get(C) is None


def test_expiry_takes_both_clocks_in_order(book):
    _installed(book, expires_at=NEXT_HEIGHT + 3)
    book.install(parse_payout_rule_set(rule_set(
        sender_pubkey=C, period_blocks=None, period_seconds=60, expires_at=TIP_TS + 5)), TIP_TS)
    assert not book.has_expiring(NEXT_HEIGHT + 2, TIP_TS + 4)
    assert [t.account_pubkey for t in book.expire(NEXT_HEIGHT + 2, TIP_TS + 5)] == [C]
    assert [t.account_pubkey for t in book.expire(NEXT_HEIGHT + 3, TIP_TS + 5)] == [A]
    assert book.count() == 0 and book.resolved_count == 2


def test_a_period_rolls_over_from_the_anchor(book):
    terms = _installed(book, period_blocks=10)
    state = book.record(A, terms.rule_id, 30, NEXT_HEIGHT + 8, TIP_TS)
    assert state.period_at(terms, NEXT_HEIGHT + 8) == 0
    assert state.spent_at(terms, NEXT_HEIGHT + 8) == 30
    assert state.spent_at(terms, NEXT_HEIGHT + 9) == 0        # anchor + 10
    state = book.record(A, terms.rule_id, 5, NEXT_HEIGHT + 9, TIP_TS)
    assert (state.period_index, state.spent_in_period, state.paid_total) == (1, 5, 35)


# --- persistence ---------------------------------------------------------------------

def _seed():
    lm = ConsensusLifecycleManager(active_validators=[A])
    # Run on the loaded genesis, as the restarted node will: other modules may
    # leave a genesis faucet grant or slot flag set, and a restart reads both.
    lm.faucet_amount = chain_state._genesis_faucet_amount
    if chain_state._genesis_approval_slots_active:
        lm.activate_approval_slots()
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 500, B: 7})
    chain_state._sequence_numbers.update({A: 3})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    book = lm.payout_rules
    terms_a = _installed(book, slots=[B, ""], rule_text="always ( (o30[t]:bv[24] = i40[t]:bv[24]) "
               "&& (o31[t]:bv[24] = i41[t]:bv[24]) ).")
    book.record(A, terms_a.rule_id, 25, NEXT_HEIGHT + 3, TIP_TS)
    book.install(parse_payout_rule_set(rule_set(
        sender_pubkey=C, period_blocks=None, period_seconds=60, expires_at=TIP_TS + 600)),
        TIP_TS)
    terms_b = parse_payout_rule_set(rule_set(sender_pubkey=B, slots=[C]))
    book.install(terms_b, NEXT_HEIGHT)
    book.revoke(B, terms_b.rule_id)
    return lm


def _reload():
    chain_state.commit_state_to_db("head-hash", 60)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_book_round_trips(temp_database):
    lm = _seed()
    meta = lm.consensus_meta_hash()
    book = lm.payout_rules
    reloaded = _reload().payout_rules
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded.resolved_state() == book.resolved_state()
    assert reloaded._expiry == book._expiry
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


@pytest.mark.usefixtures("isolated_chain_state")
@pytest.mark.parametrize("column, value", [
    ("cap_per_execution", 101), ("expires_at", 7), ("slots_json", "[\"\"]"),
    ("spent_in_period", 10_000), ("paid_total", 0),
])
def test_a_tampered_row_refuses_to_load(temp_database, column, value):
    _seed()
    chain_state.commit_state_to_db("head-hash", 60)
    with db._db_conn as conn:
        conn.execute(f"UPDATE payout_rules_v2 SET {column} = ? WHERE account_pubkey = ?",
                     (value, A))
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="payout"):
        chain_state.load_state_from_db()


# --- RPC --------------------------------------------------------------------------------

@pytest.fixture
def container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def call(module, line, container):
    return json.loads(module.execute(line, container))


@pytest.mark.usefixtures("isolated_chain_state")
def test_getpayoutrule_shows_the_rule_and_its_history(temp_database, container, monkeypatch):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    terms = _installed(lm.payout_rules)
    lm.payout_rules.record(A, terms.rule_id, 30, NEXT_HEIGHT, TIP_TS)
    monkeypatch.setattr(getpayoutrule, "_tip", lambda: ("head", NEXT_HEIGHT + 1,
                                                        lm.payout_rules))
    data = call(getpayoutrule, f"getpayoutrule {A}", container)["data"]
    assert data["installed"] is True
    rule = data["rule"]
    assert rule["rule_id"] == terms.rule_id.hex() and rule["rule_text"] == RULE
    assert rule["slots"] == [{"slot": 0, "recipient_pubkey": B, "open": False}]
    assert (rule["spent_this_period"], rule["left_this_period"]) == (30, 270)
    assert data["semantics"]["limits"]["executions_per_block"] == 16
    assert data["semantics"]["o5"].startswith("not consulted")

    events = [{"account_pubkey": A, "rule_id": terms.rule_id.hex(), "outcome": "installed",
               "tx_id": "t1"},
              {"account_pubkey": A, "rule_id": terms.rule_id.hex(), "outcome": "executed",
               "tx_id": "t2", "total": 30, "executor_pubkey": C,
               "legs": [{"slot": 0, "recipient_pubkey": B, "amount": 30}]}]
    db.record_payout_events("blk", NEXT_HEIGHT, events)
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (h == "blk", 1))
    lm.payout_rules.revoke(A, terms.rule_id)
    db.record_payout_events("blk2", NEXT_HEIGHT + 1, [
        {"account_pubkey": A, "rule_id": terms.rule_id.hex(), "outcome": "revoked",
         "tx_id": "t3"}])
    gone = call(getpayoutrule, f"getpayoutrule {A}", container)["data"]
    assert gone["installed"] is False
    assert [e["outcome"] for e in gone["history"]] == ["executed", "installed"]   # blk2 not canonical
    assert gone["history"][0]["legs"][0]["amount"] == 30


def test_bad_rpc_arguments(container):
    assert call(getpayoutrule, "getpayoutrule", container)["error"]["code"] == "INVALID_PARAMS"
    assert call(getpayoutrule, "getpayoutrule xyz", container)["error"]["code"] == \
        "INVALID_PARAMS"


@pytest.mark.usefixtures("isolated_chain_state")
def test_gettxstatus_names_what_a_payout_tx_did(temp_database, monkeypatch):
    rid = "ab" * 32
    db.record_payout_events("blk", 9, [
        {"account_pubkey": A, "rule_id": rid, "outcome": "installed", "tx_id": "h1"},
        {"account_pubkey": A, "rule_id": rid, "outcome": "executed", "tx_id": "h2",
         "total": 5, "executor_pubkey": C, "legs": []},
    ])
    db.record_payout_events("blk2", 10, [
        {"account_pubkey": A, "rule_id": "cd" * 32, "outcome": "installed", "tx_id": "h3",
         "replaced": rid},
    ])
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (True, 1))
    installed = gettxstatus._payout_fields(
        {"tx_type": "payout_rule_set", "sender_pubkey": A}, "h1", "blk")
    assert installed["payout"]["status"] == "replaced"
    executed = gettxstatus._payout_fields(
        {"tx_type": "payout_execute", "sender_pubkey": C, "account_pubkey": A}, "h2", "blk")
    assert executed["payout"]["outcome"] == "executed" and executed["payout"]["total"] == 5
    current = gettxstatus._payout_fields(
        {"tx_type": "payout_rule_set", "sender_pubkey": A}, "h3", "blk2")
    assert current["payout"]["status"] == "installed"
    missing = gettxstatus._payout_fields(
        {"tx_type": "payout_rule_set", "sender_pubkey": A}, "zz", "blk2")
    assert missing == {"payout": {"status": "not_recorded"}}


def test_history_names_transactions_by_hash_on_every_path():
    block = types.SimpleNamespace(tx_ids=["h0", "h1"])
    assert chain_state._with_tx_hash(block, {"tx_id": "1"})["tx_id"] == "h1"
    assert chain_state._with_tx_hash(block, {"tx_id": "tx0"})["tx_id"] == "h0"
    assert chain_state._with_tx_hash(block, {"tx_id": "h1"})["tx_id"] == "h1"
    assert chain_state._with_tx_hash(block, {"tx_id": "9"})["tx_id"] is None
    assert "tx_id" not in chain_state._with_tx_hash(block, {"outcome": "expired"})


# --- gossip and the command line ----------------------------------------------------------

def test_gossip_routes_and_snapshots_all_four_types():
    for t in ("payout_rule_set", "payout_rule_update", "payout_rule_revoke",
             "payout_execute"):
        assert NetworkService.topic_for_tx_type(t) == "tau/payout/1.0.0"
        assert t in _SNAPSHOT_TX_TYPES


def test_the_cli_builders_make_what_the_node_parses():
    from tau_testnet_cli import tx as tx_mod

    built = tx_mod.build_payout_rule_set_tx(
        sender_pubkey=A, sequence_number=1, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, rule_text=RULE, slots=[B.upper(), "open"],
        cap_per_execution=100, cap_per_period=300, period_blocks=10,
        expires_at=NEXT_HEIGHT + 1000)
    terms = parse_payout_rule_set(built)
    assert terms.slots == (B, "")
    upd = tx_mod.build_payout_rule_update_tx(
        sender_pubkey=A, sequence_number=2, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, rule_id=terms.rule_id.hex(),
        rule_text=RULE, slots=[B], cap_per_execution=50, cap_per_period=300,
        period_blocks=10, expires_at=NEXT_HEIGHT + 1000, sealed=True,
        max_fee_per_execution=7)
    from consensus.payout import parse_payout_rule_update
    account, old_id, new_terms = parse_payout_rule_update(upd)
    assert (account, old_id) == (A, terms.rule_id)
    assert new_terms.sealed is True and new_terms.max_fee_per_execution == 7
    rev = tx_mod.build_payout_rule_revoke_tx(
        sender_pubkey=A, sequence_number=3, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, rule_id=terms.rule_id.hex())
    assert rev["rule_id"] == terms.rule_id.hex()
    with pytest.raises(ValueError, match="rule_id"):
        tx_mod.build_payout_rule_revoke_tx(
            sender_pubkey=A, sequence_number=3, expiration_time=FAR,
            expire_at_height=NEXT_HEIGHT + 5, rule_id="zz")
    exe = tx_mod.build_payout_execute_tx(
        sender_pubkey=C, sequence_number=0, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, account_pubkey=A, rule_id=terms.rule_id.hex(),
        recipients={1: B}, data={0: 40})
    parsed = parse_payout_execute(exe)
    assert parsed.recipients == ((1, B),) and parsed.data == ((0, 40),)
    with pytest.raises(ValueError):
        tx_mod.build_payout_rule_set_tx(
            sender_pubkey=A, sequence_number=1, expiration_time=FAR,
            expire_at_height=NEXT_HEIGHT + 5, rule_text=RULE, slots=[B],
            cap_per_execution=1, cap_per_period=1, expires_at=1)
    req = tx_mod.build_rule_change_request_tx(
        sender_pubkey=A, sequence_number=4, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, kind=6, rule_text=payout_spec_text(built))
    assert req["rule_text"] == payout_spec_text(built)
    with pytest.raises(ValueError, match="no rule text"):
        tx_mod.build_rule_change_request_tx(
            sender_pubkey=A, sequence_number=4, expiration_time=FAR,
            expire_at_height=NEXT_HEIGHT + 5, kind=7, rule_text="x")


def test_the_cli_parses_the_payout_commands():
    from tau_testnet_cli.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["payout", "set", "--key", "k", "--body", RULE, "--slot", B,
                              "--slot", "open", "--cap-per-execution", "5",
                              "--cap-per-period", "9", "--period-blocks", "10",
                              "--ends-in", "100", "--request", "--approver", f"18={C}"])
    assert args.slot == [B, "open"] and args.request and args.approver == [f"18={C}"]
    args = parser.parse_args(["payout", "execute", "--key", "k", "--account", A,
                              "--recipient", f"1={B}", "--data", "0=40"])
    assert args.recipient == [f"1={B}"] and args.data == ["0=40"]
    assert parser.parse_args(["payout", "show", A]).address == A
    assert parser.parse_args(["payout", "revoke", "--key", "k"]).request is False
    args = parser.parse_args(["payout", "update", "--key", "k", "--rule-id", "ab" * 32,
                              "--body", RULE, "--slot", B, "--cap-per-execution", "5",
                              "--cap-per-period", "9", "--period-blocks", "10",
                              "--ends-in", "100", "--sealed", "--due-at", "60",
                              "--due-every", "256", "--max-fee-per-execution", "7"])
    assert args.rule_id == "ab" * 32 and args.sealed is True
    assert args.due_at == 60 and args.due_every == 256
    assert args.max_fee_per_execution == 7
    args = parser.parse_args(["payout", "set", "--key", "k", "--body", RULE, "--slot", B,
                              "--cap-per-execution", "5", "--cap-per-period", "9",
                              "--period-blocks", "10", "--ends-in", "100",
                              "--on-arrival", "--per-sale"])
    assert args.on_arrival is True and args.per_sale is True


def test_payout_revoke_without_fee_sends_fee_limit_0_and_asks_for_no_estimate(monkeypatch):
    """A fee-exempt type gets no estimate from the node, so the CLI must not ask
    for one (it used to fail with "give the fee limit with --fee")."""
    from tau_testnet_cli import cli
    from tau_testnet_cli import tx as tx_mod

    def no_estimate(*_a, **_k):
        raise RuntimeError("no estimated_fee for a fee-exempt type")

    sent = []
    monkeypatch.setattr(tx_mod, "get_sequence_tip_and_network",
                        lambda *_a, **_k: (3, 100, chain_genesis_hash()))
    monkeypatch.setattr(tx_mod, "estimate_fee", no_estimate)
    monkeypatch.setattr(tx_mod, "submit_tx", lambda payload, **_k: sent.append(payload)
                        or '{"status": "ok", "data": {"tx_hash": "ab"}}')
    args = cli.build_parser().parse_args(
        ["payout", "revoke", "--privkey", "1", "--rule-id", "ab" * 32])
    assert args.func(args) == cli.EXIT_OK
    assert [(t["tx_type"], t["fee_limit"]) for t in sent] == [("payout_rule_revoke", "0")]
    assert sent[0]["rule_id"] == "ab" * 32
    assert sent[0]["genesis_hash"] == chain_genesis_hash()


def test_the_proposer_leaves_executions_over_the_block_cap_in_the_mempool(monkeypatch):
    from commands import createblock
    from consensus.payout import MAX_PAYOUT_EXECUTIONS_PER_BLOCK as CAP

    held = []
    monkeypatch.setattr(db, "unreserve_mempool_txs", lambda ids: held.extend(ids))
    senders = [pubkey_hex(0x100 + n) for n in range(CAP + 2)]
    txs = [execute("00" * 32, sender_pubkey=s) for s in senders]
    # The last over-cap sender also has a later transfer: it must wait as well.
    txs.append({"tx_type": "user_tx", "sender_pubkey": senders[-1], "sequence_number": 1})
    txs.append({"tx_type": "user_tx", "sender_pubkey": A, "sequence_number": 0})
    execution, ids = [dict(t) for t in txs], list(range(len(txs)))
    out = createblock._defer_payout_overflow(txs, execution, ids)
    assert out == held == [CAP, CAP + 1, CAP + 2]
    assert len(txs) == len(execution) == len(ids) == CAP + 1
    assert sum(t["tx_type"] == "payout_execute" for t in txs) == CAP
    assert txs[-1]["sender_pubkey"] == A
