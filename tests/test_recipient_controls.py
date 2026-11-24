"""Recipient-side policy (issues #47, #76): the helper, the receive stream, and
the apply/admission sites that judge a payment with the RECIPIENT's own clause.

These tests exercise the node plumbing with `MockPolicyEvaluator`: they prove
which clause is consulted, with which `i12`/`i17`, at which point, and what the
refusal says. What a real clause computes from those values is covered by the
native-Tau suite, not here.
"""
import json
import time
from unittest.mock import patch

import pytest

import chain_state
import db
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from commands import sendtx
from consensus import approvals, recipient_policy, sender_policy
from consensus import admission as admission_mod
from consensus.approvals import screen_receive_widths
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import KIND_HEIGHT, KIND_TIME

import test_approval_apply as ap

POOLS = ("apply", "admission")

# "Only Alice may pay me" — the shipped inbound allow-list template, plus the
# hold cap in the same unit: refuse anything held longer than 600 seconds.
INBOUND_BODY = (
    "always ( (i3[t]:bv[384] = { #x" + ap.ALICE + " }:bv[384])"
    " && (i17[t]:bv[64] <= { #x0259 }:bv[64])"
    " -> (o5[t]:bv[24] = { #x000001 }:bv[24]) ) ||"
    " (i17[t]:bv[64] > { #x0259 }:bv[64] -> (o5[t]:bv[24] = { #x000000 }:bv[24]))"
)


# Mentions i17 (so the clause opts into inbound judging) but blocks exactly the
# plain, final payment — used to prove the reason is not a hold refusal.
BLOCK_FINAL = (
    "(i17[t]:bv[64] = { #x0001 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24])"
    " : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)


class _Exploding:
    def verdict(self, *a, **k):
        raise AssertionError("the evaluator must not be consulted")


def _judgeable(body=INBOUND_BODY, decide="0", pool="apply"):
    """An evaluator whose verdict for `body` comes from `decide`."""
    ev = MockPolicyEvaluator(pool=pool)
    ev.set_verdict(body, decide)
    return ev


def _registered(recipient_body=None, recipient=ap.BOB):
    lm = ap._lm()
    if recipient_body:
        lm.rule_offers.accepted_clauses[(recipient, tau_defs.USER_POLICY_STREAM_INDEX)] = recipient_body
    return lm


def _transfer_tx(amount, to=ap.BOB, seq=0):
    return ap._sign({
        "tx_id": f"rcpt-{next(ap._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": ap.ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[ap.ALICE, to, str(amount)]]},
    }, ap.SK_ALICE)


def _reason(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.reason


# --- the encoding -----------------------------------------------------------

def test_a_plain_transfer_is_final_and_a_park_carries_its_hold():
    assert recipient_policy.plain_transfer_value() == tau_defs.RECEIVE_FINAL == 1
    assert recipient_policy.hold_seconds_value(600) == 601
    assert recipient_policy.hold_blocks_value(100) == (1 << 63) + 100
    # Ordered families: every seconds value sits below every block value, so one
    # comparison ("held longer than C seconds") also refuses block-based parks.
    assert recipient_policy.hold_seconds_value(2 ** 32) < recipient_policy.hold_blocks_value(1)


def test_the_hold_is_measured_against_the_clock_the_park_uses():
    assert recipient_policy.park_value(KIND_TIME, 1_700_000_600, 10, 1_700_000_000) == 601
    assert recipient_policy.park_value(KIND_HEIGHT, 110, 10, 1_700_000_000) == (1 << 63) + 100
    # A clock that moved backwards cannot produce a negative hold.
    assert recipient_policy.park_value(KIND_TIME, 1_600_000_000, 10, 1_700_000_000) == 2


def test_the_cap_is_read_back_from_the_shipped_template_for_the_message():
    assert recipient_policy.cap_description(INBOUND_BODY) == "at most 600 seconds"
    assert recipient_policy.cap_description("") == ""
    assert recipient_policy.cap_description("always (o5[t]:bv[24] = { #x000001 }:bv[24]).") == ""


# --- judge ------------------------------------------------------------------

@pytest.mark.parametrize("body", [None, ""])
def test_an_account_without_a_clause_never_reaches_the_evaluator(body):
    sender_policy.set_evaluator("apply", _Exploding())
    assert recipient_policy.judge(
        lambda _who, _stream: body, ap.BOB, {1: "5"}, 1, pool="apply"
    ) == (False, "", "")


def test_the_recipient_pass_feeds_its_own_key_and_the_hold():
    ev = _judgeable(decide="1")
    sender_policy.set_evaluator("apply", ev)
    recipient_policy.judge(
        lambda _who, _stream: INBOUND_BODY, ap.BOB,
        {1: "500", 3: "{ #x" + ap.ALICE + " }:bv[384]"},
        recipient_policy.hold_seconds_value(600), pool="apply",
    )
    body, inputs = ev.verdict_calls[-1]
    assert body == INBOUND_BODY
    assert inputs["i12"] == "#x" + ap.BOB          # the RECIPIENT, not the sender
    assert inputs["i17"] == "601"
    assert inputs["i3"] == "#x" + ap.ALICE


def test_a_mixed_case_recipient_cannot_slip_past_its_own_clause():
    seen = {}
    sender_policy.set_evaluator("apply", _judgeable(decide="1"))
    recipient_policy.judge(
        lambda who, _stream: seen.setdefault("who", who) or None,
        ap.BOB.upper(), {}, 1, pool="apply",
    )
    assert seen["who"] == ap.BOB


def test_a_clause_that_never_reads_i17_is_never_judged_inbound():
    """Existing policy must not acquire an inbound meaning on upgrade."""
    legacy = ("always ( !(i3[t]:bv[384] = { #x" + ap.ALICE + " }:bv[384]) -> "
              "(o5[t]:bv[24] = { #x000000 }:bv[24]) ).")
    sender_policy.set_evaluator("apply", _Exploding())
    assert recipient_policy.judge(
        lambda _who, _stream: legacy, ap.BOB, {}, 1, pool="apply"
    ) == (False, "", "")
    assert recipient_policy.mentions_receive_stream(INBOUND_BODY) is True
    assert recipient_policy.mentions_receive_stream(legacy) is False


def test_the_payers_approval_slots_are_zeroed_for_the_recipient():
    """A co-signature the sender collected must not satisfy the recipient."""
    ev = _judgeable(decide="1")
    sender_policy.set_evaluator("apply", ev)
    slot = tau_defs.approval_slot_indices()[0]
    recipient_policy.judge(
        lambda _who, _stream: INBOUND_BODY, ap.BOB,
        {slot: "{ #x" + ap.ALICE + " }:bv[384]", 1: "500"},
        recipient_policy.plain_transfer_value(), pool="apply",
    )
    _body, inputs = ev.verdict_calls[-1]
    assert inputs[f"i{slot}"] == "0"
    assert inputs["i1"] == "500"


def test_a_refusal_names_the_hold_and_the_cap():
    sender_policy.set_evaluator("apply", _judgeable(decide="0"))
    blocked, reason, message = recipient_policy.judge(
        lambda _who, _stream: INBOUND_BODY, ap.BOB, {}, 3601, pool="apply",
    )
    assert blocked is True
    assert reason == recipient_policy.REASON_MAX_HOLD
    assert "held 3600 seconds" in message and "at most 600 seconds" in message


def test_a_plain_payment_refusal_is_not_a_hold_refusal():
    body = BLOCK_FINAL
    sender_policy.set_evaluator("apply", _judgeable(body=body, decide="0"))
    blocked, reason, _message = recipient_policy.judge(
        lambda _who, _stream: body,
        ap.BOB, {}, recipient_policy.plain_transfer_value(), pool="apply",
    )
    assert blocked is True and reason == recipient_policy.REASON_BLOCK


# --- apply ------------------------------------------------------------------

def test_apply_rejects_a_transfer_the_recipients_clause_blocks():
    ev = _judgeable(decide="0")
    sender_policy.set_evaluator("apply", ev)
    tx = _transfer_tx(500)
    result, _lm, _calls = ap._apply([tx], lm=_registered(INBOUND_BODY))
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == recipient_policy.REASON_BLOCK
    assert ap._balances(result)[ap.ALICE] == 100000  # nothing moved
    assert "recipient's own policy clause" in ap._logs(result)
    assert ev.verdict_calls[-1][1]["i12"] == "#x" + ap.BOB


def test_apply_lets_a_transfer_through_when_the_recipient_allows():
    sender_policy.set_evaluator("apply", _judgeable(decide="1"))
    tx = _transfer_tx(500)
    result, _lm, _calls = ap._apply([tx], lm=_registered(INBOUND_BODY))
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ap._balances(result)[ap.BOB] == 500


def test_apply_to_an_account_without_a_clause_costs_no_evaluator_step():
    sender_policy.set_evaluator("apply", _Exploding())
    tx = _transfer_tx(500)
    result, _lm, _calls = ap._apply([tx], lm=_registered(None))
    assert tx["tx_id"] in result.accepted_tx_ids


def test_one_unit_serves_both_directions_at_apply():
    """The recipient's clause judges payments TO it; its own outgoing payment is
    judged with i17 = 0, so the same body can allow both."""
    seen = []

    def decide(inputs):
        seen.append((inputs.get("i12"), inputs.get("i17")))
        # inbound: allow only Alice; outbound (i17 = 0): allow everything
        if inputs.get("i17") == "0":
            return "1"
        return "1" if inputs.get("i3") == "#x" + ap.ALICE else "0"

    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(INBOUND_BODY, decide)
    sender_policy.set_evaluator("apply", ev)
    lm = _registered(INBOUND_BODY)
    lm.rule_offers.accepted_clauses[(ap.ALICE, tau_defs.USER_POLICY_STREAM_INDEX)] = INBOUND_BODY
    tx = _transfer_tx(500)                      # ALICE -> BOB
    result, _lm, _calls = ap._apply([tx], lm=lm)
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ("#x" + ap.ALICE, "0") in seen       # the sender pass
    assert ("#x" + ap.BOB, "1") in seen         # the recipient pass


def test_a_recipient_refusal_invalidates_the_whole_batch():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(BLOCK_FINAL, "0")
    sender_policy.set_evaluator("apply", ev)
    third = pubkey_hex(SK_CAROL)   # a third account, no clause
    tx = ap._sign({
        "tx_id": f"rcpt-{next(ap._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": ap.ALICE,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[ap.ALICE, ap.BOB, "10"], [ap.ALICE, third, "10"]]},
    }, ap.SK_ALICE)
    lm = _registered(BLOCK_FINAL)
    result, _lm, _calls = ap._apply([tx], lm=lm)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert ap._balances(result)[ap.BOB] == 0
    assert ap._balances(result).get(third, 0) == 0


def test_a_retractable_park_is_judged_on_its_hold_at_apply():
    seen = {}

    def decide(inputs):
        seen["i17"] = inputs.get("i17")
        return "0"

    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(INBOUND_BODY, decide)
    sender_policy.set_evaluator("apply", ev)
    tx = ap._sign({
        "tx_id": f"rcpt-{next(ap._TX_SEQ)}",
        "tx_type": "retractable_transfer",
        "sender_pubkey": ap.ALICE,
        "recipient_pubkey": ap.BOB,
        "amount": 100,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "release_at_height": 200,
    }, ap.SK_ALICE)
    result, _lm, _calls = ap._apply([tx], lm=_registered(INBOUND_BODY))
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == recipient_policy.REASON_MAX_HOLD
    assert int(seen["i17"]) >= tau_defs.RECEIVE_BLOCKS_BASE


# --- admission --------------------------------------------------------------

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
ADMISSION_CLAUSE_VIEW = "consensus.facade.TipAdmissionView.clause_for"


@pytest.fixture
def admission(temp_database):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state.load_genesis("data/genesis.json")
    db.clear_mempool()
    chain_state._balances[SENDER] = 100000
    with patch("commands.sendtx.validate_bls_pubkey", return_value=None), \
            patch("tau_manager.is_force_test_enabled", return_value=False), \
            patch("tau_manager.communicate_with_tau_multi", return_value={1: "1", 5: "1"}), \
            patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        yield


def _queue(to=RECIPIENT, amount="1"):
    tx = {
        "sender_pubkey": SENDER,
        "sequence_number": chain_state.get_sequence_number(SENDER),
        "expiration_time": int(time.time()) + 1000,
        "expire_at_height": 5000,
        "operations": {"1": [[SENDER, to, amount]]},
        "fee_limit": "1000",
    }
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, SK_ALICE)))


def _clause_only_for(body, recipient=RECIPIENT):
    """clause_for that answers for the recipient only, so the sender pass stays out."""
    def clause_for(who, stream):
        return body if (who, stream) == (recipient, tau_defs.USER_POLICY_STREAM_INDEX) else None
    return clause_for


def test_admission_rejects_a_transfer_the_recipients_clause_blocks(admission):
    ev = _judgeable(decide="0", pool="admission")
    sender_policy.set_evaluator("admission", ev)
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clause_only_for(INBOUND_BODY)):
        res = _queue()
    assert res["ok"] is False and res["code"] == "TX_REJECTED"
    assert "recipient's own policy clause" in res["message"]
    assert res["details"]["reason"] == recipient_policy.REASON_BLOCK
    assert db.get_mempool_txs() == []
    body, inputs = ev.verdict_calls[-1]
    assert inputs["i12"] == "#x" + RECIPIENT and inputs["i17"] == "1"


def test_admission_accepts_when_the_recipient_allows(admission):
    sender_policy.set_evaluator("admission", _judgeable(decide="1", pool="admission"))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clause_only_for(INBOUND_BODY)):
        assert _queue()["ok"] is True


def test_admission_never_judges_an_account_without_a_clause(admission):
    sender_policy.set_evaluator("admission", _Exploding())
    with patch(ADMISSION_CLAUSE_VIEW, return_value=None):
        assert _queue()["ok"] is True


def test_an_evaluator_failure_at_admission_is_operational_not_a_rejection(admission):
    from tau_speculation import WorkerLost

    class _Lost:
        def verdict(self, *a, **k):
            raise WorkerLost("gone")

    sender_policy.set_evaluator("admission", _Lost())
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clause_only_for(INBOUND_BODY)):
        res = _queue()
    assert res["ok"] is False and res["code"] == "ADMISSION_UNAVAILABLE"


# --- the stream is reserved and typed ---------------------------------------

def test_receive_stream_is_write_forbidden_and_clause_readable():
    assert tau_defs.RECEIVE_STREAM_INDEX in tau_defs.reserved_operation_keys()
    forbidden = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE)
    assert "i17" not in forbidden
    consensus_forbidden = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_CONSENSUS)
    assert "i17" in consensus_forbidden


@pytest.mark.parametrize("text", [
    "i17 > { #x01 }:bv[64]",
    "i17[t] = { #x01 }:bv[16]",
])
def test_a_mistyped_receive_stream_is_refused(text):
    assert screen_receive_widths(text) is not None


def test_a_correctly_typed_receive_stream_passes_the_screen():
    assert screen_receive_widths("i17[t]:bv[64] > { #x01 }:bv[64]") is None
    assert screen_receive_widths("i3[t]:bv[384]") is None


def test_a_two_stream_layout_refuses_a_clause_that_bounds_only_one(monkeypatch):
    """The screen that makes the two-stream layout fail closed at deploy time."""
    body_one = ("(i17[t]:bv[64] > { #x0259 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24])"
                " : (o5[t]:bv[24] = { #x000001 }:bv[24])")
    body_both = ("((i17[t]:bv[64] > { #x0259 }:bv[64]) && (i27[t]:bv[64] > { #x0001 }:bv[64]))"
                 " ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")
    body_none = "(i3[t]:bv[384] = { #x" + ap.ALICE + " }:bv[384]) ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24])"

    # today the group is a single unit-tagged stream: nothing to enforce
    assert approvals.screen_hold_mentions(body_one) is None
    assert tau_defs.HOLD_STREAM_GROUP == (tau_defs.RECEIVE_STREAM_INDEX,)

    # the day a block-denominated stream joins it, a half-bounded clause is refused
    err = approvals.screen_hold_mentions(body_one, group=(17, 27))
    assert err and "i27" in err and "i17" in err
    assert approvals.screen_hold_mentions(body_both, group=(17, 27)) is None
    assert approvals.screen_hold_mentions(body_none, group=(17, 27)) is None

    # and the admission screen carries it, with the shared-rules prefix
    monkeypatch.setattr(tau_defs, "HOLD_STREAM_GROUP", (17, 27))
    rejection = admission_mod._screen_clause_widths_and_structure(body_one)
    assert rejection and rejection.startswith("Shared rules: ") and "i27" in rejection
    assert admission_mod._screen_clause_widths_and_structure(body_none) is None


def test_a_comment_about_a_hold_stream_does_not_count_as_bounding_it():
    body = ("# i27 is the block stream\n"
            "(i17[t]:bv[64] > { #x0259 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24])"
            " : (o5[t]:bv[24] = { #x000001 }:bv[24])")
    assert approvals.screen_hold_mentions(body, group=(17, 27))


MIN_ALLOWANCE = ("(i26[t]:bv[64] < { #x01F4 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24])"
                 " : (o5[t]:bv[24] = { #x000001 }:bv[24])")


def test_the_extra_payment_facts_are_off_and_a_clause_reading_them_is_refused():
    """Parts 3-5 compare bounty 01's conditions; until it lands they are inert."""
    assert tau_defs.RECEIVE_FACTS_ACTIVE is False
    rejection = admission_mod._screen_clause_widths_and_structure(MIN_ALLOWANCE)
    assert rejection and "i26" in rejection and "bounty 01" in rejection
    # and a clause is not silently judged against zeros it cannot interpret
    sender_policy.set_evaluator("apply", _Exploding())
    assert recipient_policy.judge(
        lambda _who, _stream: MIN_ALLOWANCE, ap.BOB, {}, 1, pool="apply"
    ) == (False, "", "")


def test_when_the_facts_are_on_the_node_feeds_them_and_the_clause_decides(monkeypatch):
    monkeypatch.setattr(tau_defs, "RECEIVE_FACTS_ACTIVE", True)
    assert tau_defs.active_receive_fact_streams() == (17, 26, 27, 28)
    # the clause is now an opt-in receive policy, and every fact is fed
    assert recipient_policy.mentions_receive_stream(MIN_ALLOWANCE) is True
    ev = _judgeable(MIN_ALLOWANCE, decide="1")
    sender_policy.set_evaluator("apply", ev)
    blocked, _reason, _message = recipient_policy.judge(
        lambda _who, _stream: MIN_ALLOWANCE, ap.BOB, {1: "500"},
        recipient_policy.plain_transfer_value(), pool="apply",
        facts={26: 600, 27: 0, 28: 0},
    )
    assert blocked is False
    _body, inputs = ev.verdict_calls[-1]
    assert inputs["i26"] == "600" and inputs["i27"] == "0" and inputs["i28"] == "0"
    assert inputs["i17"] == str(recipient_policy.plain_transfer_value())


def test_the_fact_widths_are_screened_when_they_are_live(monkeypatch):
    monkeypatch.setattr(tau_defs, "RECEIVE_FACTS_ACTIVE", True)
    bad = "(i27[t]:bv[32] < { #x01 }:bv[32]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
    err = approvals.screen_receive_widths(bad)
    assert err and "i27" in err and "bv[64]" in err
    assert approvals.screen_receive_widths(MIN_ALLOWANCE) is None
