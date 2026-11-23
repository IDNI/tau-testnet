"""Regression coverage for recipient controls (#47, #76).

The spec tests pin the hold code. These pin the places a wiring change would
disagree with that code: block apply, admission, the restart path, and the
refusal search. The policy verdicts come from the in-process mock. queue_transaction is
covered in test_recipient_controls_sendtx.py.
"""
import ast
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import chain_state
import db
import tau_defs
from block import Block
from consensus import sender_policy
from consensus.admission import (
    _check_host_contract_patch,
    screen_user_rule_text,
    validate_o5_clause_routing,
)
from consensus.approvals import STATUS_FAILED
from consensus.engine import (
    ActiveConsensusView,
    TauConsensusEngine,
    _clause_domain_rejection,
)
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.policy_mock import MockPolicyEvaluator
from consensus.recipient_policy import (
    HEIGHT_CODE_BASE,
    HEIGHT_CODE_MAX,
    MAX_HOLD,
    POLICY_BLOCK,
    SECONDS_LO,
    TIME_CODE_MAX,
    clause_reads_hold_stream,
    park_hold_code,
    recipient_refusal,
    screen_hold_clause,
    sender_clause_inputs,
)
from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    MAX_RELEASE_WINDOW_BLOCKS,
    MAX_RELEASE_WINDOW_SECONDS,
)
from consensus.state import TauStateSnapshot
from tau_speculation import WorkerLost

import test_approval_apply as ap
import test_retractable_apply as parks

# The `+ {0}` keeps this off the literal-threshold path. These tests decide
# the verdict in the mock, and the literal path would read `{1}` out of the
# text instead of asking the mock where the cap actually is.
HOLD = (
    "(i17[t]:bv[64] + {0}:bv[64] > {1}:bv[64]) ? "
    "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
    "(o5[t]:bv[24] = { #x000001 }:bv[24])"
)
CUSTOM = (
    "(i17[t]:bv[24] = { #x000007 }:bv[24]) ? "
    "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
    "(o5[t]:bv[24] = { #x000001 }:bv[24])"
)
ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _mock_evaluator():
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)
    yield
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)


class _Exploding:
    def verdict(self, *args, **kwargs):
        raise AssertionError("the evaluator must not be consulted")

    def validate(self, *args, **kwargs):
        raise AssertionError("the evaluator must not be consulted")


def _install(decide, body=HOLD):
    ev = MockPolicyEvaluator()
    if isinstance(decide, dict):
        for clause, rule in decide.items():
            ev.set_verdict(clause, rule)
    else:
        ev.set_verdict(body, decide)
    sender_policy.set_evaluator("apply", ev)
    return ev


def _over(limit):
    def decide(inputs):
        return 0 if int(inputs["i17"]) > limit else 1
    return decide


def _use(decide, body=HOLD, pool="apply"):
    ev = MockPolicyEvaluator(pool=pool)
    ev.set_verdict(body, decide)
    sender_policy.set_evaluator(pool, ev)
    return ev


def _lm(*, on=False, clauses=None):
    lm = ap._lm()
    if on:
        lm.activate_recipient_controls()
    for who, body in (clauses or {}).items():
        lm.rule_offers.accepted_clauses[(who, 5)] = body
    return lm


def _transfer(amount=500, to=None, seq=0, legs=None, extra=None):
    ops = {"1": legs or [[ap.ALICE, to or ap.BOB, str(amount)]]}
    if extra:
        ops.update(extra)
    return ap._sign({
        "tx_id": f"tr-{next(ap._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": ap.ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": ops,
    }, ap.SK_ALICE)


def _rule(body, seq=0):
    return ap.rule_tx("always ( %s )." % body, seq=seq)


def _apply(txs, lm=None, *, fee=0, replay=False, balances=None, height=ap.HEIGHT):
    lm = lm if lm is not None else ap._lm()
    bal = balances if balances is not None else {
        ap.ALICE: 100000, ap.AUTH: 10, ap.SCAN: 10, ap.BOB: 0,
    }
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": dict(bal),
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(ap.ALICE)],
        mechanism_specific_metadata={"poa": True},
    )
    block = Block.create(
        block_number=height, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=ap.ALICE, timestamp=1234567890,
    )
    calls = []
    persisted = []

    def _fake_multi(**kwargs):
        calls.append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        slot18 = str(vals.get(18, "0"))
        blocked = amount > ap.TIER_1 and ap.AUTH not in slot18
        return {1: str(amount), 8: "0", 9: str(fee), 5: "0" if blocked else "1"}

    def _fake_single(**kwargs):
        text = kwargs.get("rule_text")
        if text and kwargs.get("apply_rules_update"):
            persisted.append(str(text).strip())
        return "T"

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", side_effect=_fake_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply_block(view, block, parent, replay_mode=replay)
    return result, result.next_snapshot.metadata["lifecycle_manager"], calls


def _reason(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.reason


def _logs(result):
    out = []
    for outcome in result.outcomes:
        out.extend(outcome.receipt_logs or [])
    return " | ".join(str(line) for line in out)


def _main_inputs(calls):
    return [c.get("input_stream_values") or {} for c in calls]


# --- the refusal search -----------------------------------------------------

@pytest.mark.parametrize("cap", [0, 1, 2, 599, 600, MAX_RELEASE_WINDOW_SECONDS - 1])
def test_a_seconds_threshold_reports_that_cap_and_not_one_past_it(cap):
    _use(_over(1 + cap))
    assert recipient_refusal(HOLD, {}, 1 + cap, pool="apply") is None
    if cap == MAX_RELEASE_WINDOW_SECONDS - 1:
        refused = TIME_CODE_MAX
    else:
        refused = 1 + cap + 1
    refusal = recipient_refusal(HOLD, {}, refused, pool="apply")
    assert refusal.code == MAX_HOLD
    assert refusal.details == {"max_hold_seconds": cap}


@pytest.mark.parametrize("cap", [0, 1, 2, 10, MAX_RELEASE_WINDOW_BLOCKS - 1])
def test_a_blocks_threshold_reports_that_cap_and_still_allows_a_time_park(cap):
    _use(_over(HEIGHT_CODE_BASE + cap))
    assert recipient_refusal(HOLD, {}, 1 + 3600, pool="apply") is None
    assert recipient_refusal(HOLD, {}, HEIGHT_CODE_BASE + cap, pool="apply") is None
    refusal = recipient_refusal(HOLD, {}, HEIGHT_CODE_BASE + cap + 1, pool="apply")
    assert refusal.code == MAX_HOLD
    assert refusal.details == {"max_hold_blocks": cap}
    if cap == 0:
        assert "straight away" not in refusal.message
        assert "max_hold_seconds" not in refusal.details


def test_the_search_stops_at_the_boundary_instead_of_scanning_the_window():
    ev = _use(_over(601))
    refusal = recipient_refusal(HOLD, {3: "payer"}, 1 + 3600, pool="apply")
    assert refusal.details == {"max_hold_seconds": 600}
    assert len(ev.verdict_calls) < 48
    assert ev.verdict_calls[0][1]["i17"] == str(1 + 3600)
    assert ev.verdict_calls[0][1]["i3"] == "payer"


def test_the_callers_input_map_is_not_modified():
    values = {3: "payer", 17: "forged"}
    _use(_over(1))
    recipient_refusal(HOLD, values, 5, pool="apply")
    assert values == {3: "payer", 17: "forged"}


def test_a_hole_below_the_apparent_cap_is_not_quoted_as_a_maximum():
    """Allow, then block, then allow again up to 600 seconds, then block.

    A plain binary search reports 600. The point halfway back to the short
    end is inside the hole, so there is no single cap.
    """
    def decide(inputs):
        code = int(inputs["i17"])
        if code == SECONDS_LO or 401 <= code <= 601:
            return 1
        return 0
    _use(decide)
    refusal = recipient_refusal(HOLD, {}, 1 + 1000, pool="apply")
    assert refusal.code == POLICY_BLOCK
    assert refusal.details == {}


def test_a_hole_above_the_apparent_cap_is_not_quoted_as_a_maximum():
    """Allow up to 100 seconds, block the rest, except one code on the probe
    between that threshold and the far end of the window.

    Without that probe the search would report a cap of 99 seconds.
    """
    hole = (101 + TIME_CODE_MAX) // 2

    def decide(inputs):
        code = int(inputs["i17"])
        if code <= 100 or code == hole:
            return 1
        return 0
    _use(decide)
    refusal = recipient_refusal(HOLD, {}, 200, pool="apply")
    assert refusal.code == POLICY_BLOCK
    assert refusal.details == {}


def test_blocking_both_ends_while_the_middle_allows_is_not_a_zero_cap():
    def decide(inputs):
        code = int(inputs["i17"])
        if code in (SECONDS_LO, TIME_CODE_MAX, 1 + 60):
            return 0
        return 1
    _use(decide)
    refusal = recipient_refusal(HOLD, {}, 1 + 60, pool="apply")
    assert refusal.code == POLICY_BLOCK
    assert refusal.details == {}


def test_a_single_blocked_code_inside_an_otherwise_open_window_is_not_a_cap():
    def decide(inputs):
        return 0 if int(inputs["i17"]) == 1 + 60 else 1
    _use(decide)
    refusal = recipient_refusal(HOLD, {}, 1 + 60, pool="apply")
    assert refusal.code == POLICY_BLOCK


def test_a_code_past_the_height_window_is_not_given_a_manufactured_cap():
    _use(_over(1))
    refusal = recipient_refusal(HOLD, {}, HEIGHT_CODE_MAX + 1, pool="apply")
    assert refusal.code == POLICY_BLOCK
    assert refusal.details == {}


def test_a_clause_that_fails_to_step_refuses_the_payment():
    ev = MockPolicyEvaluator()
    ev.fail_step(HOLD, "engine says no")
    sender_policy.set_evaluator("apply", ev)
    refusal = recipient_refusal(HOLD, {}, 1, pool="apply")
    assert refusal.code == POLICY_BLOCK
    assert refusal.details == {}


def test_loss_of_the_evaluator_propagates_out_of_the_recipient_pass():
    class _Lost:
        def verdict(self, *args, **kwargs):
            raise WorkerLost("gone")

    sender_policy.set_evaluator("apply", _Lost())
    with pytest.raises(WorkerLost):
        recipient_refusal(HOLD, {}, 1, pool="apply")


def test_the_admission_pool_and_the_apply_pool_do_not_share_a_verdict():
    _use(_over(1), pool="apply")
    _use(lambda inputs: 0, pool="admission")
    assert recipient_refusal(HOLD, {}, 1, pool="apply") is None
    assert recipient_refusal(HOLD, {}, 1, pool="admission").code == POLICY_BLOCK


def test_the_probe_timeout_reaches_the_evaluator():
    seen = {}

    class _Spy:
        def verdict(self, body, inputs, *, timeout):
            seen["timeout"] = timeout
            from tau_policy import PolicyVerdict
            return PolicyVerdict(blocked=False, o5="1", built=True)

    sender_policy.set_evaluator("apply", _Spy())
    assert recipient_refusal(HOLD, {}, 1, pool="apply", timeout=2.5) is None
    assert seen["timeout"] == 2.5


def test_a_comment_is_not_a_mention_and_i170_is_not_i17():
    commented = "# i17[t]:bv[64]\n(o5[t]:bv[24] = { #x000000 }:bv[24])"
    assert clause_reads_hold_stream(commented) is False
    assert clause_reads_hold_stream("i170[t]:bv[64] = {0}:bv[64]") is False
    _use(lambda inputs: 0, commented)
    assert recipient_refusal(commented, {}, 1, pool="apply") is None


def test_the_sender_pass_overwrites_a_forged_i17_without_touching_the_original():
    values = {1: "5", 17: "9", "17": "9", "i17": "9"}
    fed = sender_clause_inputs(values, True)
    assert fed[17] == "0"
    assert fed["17"] == "0"
    assert fed["i17"] == "0"
    assert values["i17"] == "9"
    assert sender_clause_inputs(None, True) == {17: "0", "17": "0", "i17": "0"}


def test_a_non_positive_hold_stays_inside_its_unit_and_an_unknown_kind_does_not():
    assert park_hold_code(KIND_TIME, 0, 0, 50) == 2
    assert park_hold_code(KIND_HEIGHT, 0, 50, 0) == HEIGHT_CODE_BASE + 1
    assert park_hold_code(KIND_TIME, 10**12, 0, 0) == 1 + MAX_RELEASE_WINDOW_SECONDS
    assert park_hold_code(
        KIND_HEIGHT, 10**12, 0, 0,
    ) == HEIGHT_CODE_BASE + MAX_RELEASE_WINDOW_BLOCKS
    with pytest.raises(ValueError):
        park_hold_code(9, 10, 0, 0)


def test_spacing_is_legal_and_a_padded_width_or_a_shifted_step_is_not():
    spaced = "i17 [ t ] : bv [ 64 ]"
    assert screen_hold_clause(spaced, active=True) is None
    assert screen_hold_clause(spaced, active=False) is not None
    assert screen_hold_clause("i17[t]:bv[064]", active=True) is not None
    assert screen_hold_clause("i17[t-1]:bv[64]", active=True) is not None
    assert screen_hold_clause("i17[t]:bv[64] && i17", active=True) is not None
    assert screen_hold_clause("i170[t]:bv[24]", active=True) is None
    assert screen_hold_clause("i17[t]:bv[24]", active=False) is None


# --- block apply ------------------------------------------------------------

def test_while_the_flag_is_off_an_inbound_clause_is_not_consulted():
    sender_policy.set_evaluator("apply", _Exploding())
    tx = _transfer()
    result, post, calls = _apply([tx], lm=_lm(clauses={ap.BOB: HOLD}))
    assert tx["tx_id"] in result.accepted_tx_ids
    assert result.next_snapshot.metadata["balances"][ap.BOB] == 500
    assert post.recipient_controls_active is False
    assert all(17 not in values for values in _main_inputs(calls))


def test_an_outbound_clause_is_not_consulted_on_money_arriving():
    """Bob's clause blocks every payment, and it never mentions i17."""
    sender_policy.set_evaluator("apply", _Exploding())
    blocking = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
    tx = _transfer()
    result, _post, _calls = _apply(
        [tx], lm=_lm(on=True, clauses={ap.BOB: blocking}),
    )
    assert tx["tx_id"] in result.accepted_tx_ids
    assert result.next_snapshot.metadata["balances"][ap.BOB] == 500


def test_a_commented_mention_does_not_turn_a_blocking_clause_into_a_gate():
    sender_policy.set_evaluator("apply", _Exploding())
    commented = "# i17\n(o5[t]:bv[24] = { #x000000 }:bv[24])"
    tx = _transfer()
    result, _post, _calls = _apply(
        [tx], lm=_lm(on=True, clauses={ap.BOB: commented}),
    )
    assert tx["tx_id"] in result.accepted_tx_ids


def test_the_sender_pass_sees_zero_and_the_recipient_pass_sees_the_payment():
    sender = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
    # Distinct text so each pass is visible. The mock, not the text, decides.
    sender_body = sender + " "
    recipient_body = HOLD

    def allow_own_send(inputs):
        return 1 if inputs.get("i17") == "0" else 0

    def allow_plain_arrival(inputs):
        return 1 if inputs.get("i17") == "1" else 0

    ev = _install({sender_body: allow_own_send, recipient_body: allow_plain_arrival})
    tx = _transfer()
    result, _post, calls = _apply([tx], lm=_lm(on=True, clauses={
        ap.ALICE: sender_body, ap.BOB: recipient_body,
    }))
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ev.verdict_calls[0][1]["i17"] == "0"
    recipient = ev.verdict_calls[-1][1]
    assert recipient["i17"] == "1"
    assert recipient["i3"] == "#x" + ap.ALICE
    assert recipient["i12"] == "#x" + ap.ALICE
    assert recipient["i4"] == "#x" + ap.BOB
    assert all(17 not in values for values in _main_inputs(calls))


def test_a_recipient_block_rejects_the_transfer_and_charges_no_fee():
    _install(lambda inputs: 0)
    tx = _transfer()
    result, _post, _calls = _apply(
        [tx], lm=_lm(on=True, clauses={ap.BOB: HOLD}), fee=7,
    )
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == POLICY_BLOCK
    balances = result.next_snapshot.metadata["balances"]
    assert balances[ap.BOB] == 0
    assert balances[ap.ALICE] == 100000
    assert "Fee charged" not in _logs(result)
    assert "rejected by recipient policy" in _logs(result)


def test_one_refused_leg_puts_the_earlier_leg_back():
    _install(lambda inputs: 0)
    tx = _transfer(legs=[
        [ap.ALICE, ap.BOB, "40"],
        [ap.ALICE, ap.AUTH, "40"],
    ])
    result, _post, _calls = _apply(
        [tx], lm=_lm(on=True, clauses={ap.AUTH: HOLD}), fee=7,
    )
    assert tx["tx_id"] in result.invalid_tx_ids
    balances = result.next_snapshot.metadata["balances"]
    assert balances[ap.BOB] == 0
    assert balances[ap.AUTH] == 10
    assert balances[ap.ALICE] == 100000
    assert "Fee charged" not in _logs(result)


def test_replay_keeps_the_transaction_and_does_not_pay_the_recipient():
    _install(lambda inputs: 0)
    live = _transfer()
    live_result, _post, _calls = _apply(
        [live], lm=_lm(on=True, clauses={ap.BOB: HOLD}), fee=7,
    )
    assert live["tx_id"] in live_result.invalid_tx_ids
    assert "Fee charged" not in _logs(live_result)

    replayed = _transfer()
    result, _post, _calls = _apply(
        [replayed], lm=_lm(on=True, clauses={ap.BOB: HOLD}), fee=7, replay=True,
    )
    assert replayed["tx_id"] in result.accepted_tx_ids
    assert result.next_snapshot.metadata["balances"][ap.BOB] == 0
    assert result.next_snapshot.metadata["sequence_numbers"][ap.ALICE] == 1
    assert "Fee charged: 7" in _logs(result)
    assert "rejected by recipient policy" in _logs(result)


def test_a_lost_evaluator_is_not_turned_into_a_recipient_verdict():
    class _Lost:
        def verdict(self, *args, **kwargs):
            raise WorkerLost("gone")

    sender_policy.set_evaluator("apply", _Lost())
    with pytest.raises(WorkerLost):
        _apply([_transfer()], lm=_lm(on=True, clauses={ap.BOB: HOLD}))


def test_a_clause_the_engine_will_not_step_fails_closed_at_apply():
    ev = MockPolicyEvaluator()
    ev.fail_step(HOLD)
    sender_policy.set_evaluator("apply", ev)
    tx = _transfer()
    result, _post, _calls = _apply([tx], lm=_lm(on=True, clauses={ap.BOB: HOLD}))
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == POLICY_BLOCK
    assert result.next_snapshot.metadata["balances"][ap.BOB] == 0


def test_a_bv64_hold_clause_is_refused_until_the_flag_is_on_and_registers_after():
    sender_policy.set_evaluator("apply", MockPolicyEvaluator())
    early = _rule(HOLD)
    refused, post, _calls = _apply([early], lm=_lm())
    assert early["tx_id"] in refused.invalid_tx_ids
    assert _reason(refused, early) == "RECIPIENT_CONTROLS_INACTIVE"
    assert post.rule_offers.clause_for(ap.ALICE, 5) is None

    late = _rule(HOLD)
    accepted, post, _calls = _apply([late], lm=_lm(on=True))
    assert late["tx_id"] in accepted.accepted_tx_ids
    assert post.rule_offers.clause_for(ap.ALICE, 5) == HOLD


def test_a_custom_bv24_i17_clause_registers_only_while_the_feature_is_off():
    sender_policy.set_evaluator("apply", MockPolicyEvaluator())
    early = _rule(CUSTOM)
    accepted, post, _calls = _apply([early], lm=_lm())
    assert early["tx_id"] in accepted.accepted_tx_ids
    assert post.rule_offers.clause_for(ap.ALICE, 5) == CUSTOM

    late = _rule(CUSTOM)
    refused, post, _calls = _apply([late], lm=_lm(on=True))
    assert late["tx_id"] in refused.invalid_tx_ids
    assert "must be written i17[t]:bv[64]" in _logs(refused)
    assert post.rule_offers.clause_for(ap.ALICE, 5) is None


def test_a_user_rule_may_mention_i17_only_while_the_feature_is_off():
    rule = "always ( i17[t]:bv[64] = {0}:bv[64] )."
    off = _transfer(extra={"0": rule})
    accepted, _post, _calls = _apply([off], lm=_lm())
    assert off["tx_id"] in accepted.accepted_tx_ids

    on = _transfer(extra={"0": rule})
    refused, _post, _calls = _apply([on], lm=_lm(on=True))
    assert on["tx_id"] in refused.invalid_tx_ids
    assert _reason(refused, on) == "reserved_input_stream"


def test_a_sender_can_write_i17_only_while_the_feature_is_off():
    off = _transfer(amount=50, extra={"17": "7"})
    accepted, _post, calls = _apply([off], lm=_lm())
    assert off["tx_id"] in accepted.accepted_tx_ids
    fed = [values for values in _main_inputs(calls) if values.get(1) == "50"]
    assert fed and fed[-1][17] == ["7"]

    on = _transfer(amount=50, extra={"17": "7"})
    refused, _post, calls = _apply([on], lm=_lm(on=True))
    assert on["tx_id"] in refused.invalid_tx_ids
    assert _reason(refused, on) == "reserved_operation_key"
    assert all(17 not in values for values in _main_inputs(calls))


def test_creating_an_approval_request_does_not_ask_the_recipient():
    """The request parks on the sender's policy. The recipient is asked when
    a vote later pays, and a refusal fails that payment without dropping the vote.
    """
    ev = _install(lambda inputs: 0)
    req = ap._request()
    request = ap.request_tx(req)
    vote = ap.vote_tx(req)
    result, post, _calls = _apply(
        [request, vote], lm=_lm(on=True, clauses={ap.BOB: HOLD}),
    )
    assert "Approval request parked" in _logs(result)
    assert post.approval_requests.terminal_status[req.request_id] == STATUS_FAILED
    assert "Parked transfer could not be executed" in _logs(result)
    assert result.next_snapshot.metadata["balances"][ap.BOB] == 0
    assert result.next_snapshot.metadata["balances"][ap.ALICE] == 100000
    assert [call[1]["i17"] for call in ev.verdict_calls] == ["1"]
    assert result.accepted_tx_ids == [request["tx_id"], vote["tx_id"]]


def test_a_rule_change_guard_cannot_read_i17_either_way():
    guard = (
        "(i17[t]:bv[64] = {0}:bv[64]) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24])"
    )
    for active in (False, True):
        error, reason = _clause_domain_rejection(
            guard, guard=True, recipient_controls_active=active,
        )
        assert "i17" in error
        assert reason == "rule_not_applied"


# --- parks, retracts, releases ----------------------------------------------

def _arm(ch, body=HOLD):
    ch.lm.activate_recipient_controls()
    ch.lm.rule_offers.accepted_clauses[(parks.BOB, 5)] = body
    return ch


def _hold_seen(release_at, ts):
    seen = []

    def decide(inputs):
        seen.append(int(inputs["i17"]))
        return 1

    _install(decide)
    ch = _arm(parks.Chain(parks._balances()))
    tx = parks.park_tx(at_time=release_at)
    ch.block([tx], ts=ts)
    assert tx["tx_id"] in ch.last.accepted_tx_ids
    return seen[0]


def test_a_time_park_is_measured_on_the_block_clock():
    """The same release point is a shorter hold when the block is later."""
    assert _hold_seen(parks.TS + 700, parks.TS + 100) == 601
    assert _hold_seen(parks.TS + 700, parks.TS) == 701


def test_a_seconds_cap_refuses_a_long_time_park_and_a_height_park_at_apply():
    _install(_over(601))
    ch = _arm(parks.Chain(parks._balances(), fee=7))
    late = parks.park_tx(amount=500, at_time=parks.TS + 3600)
    result = ch.block([late])
    assert late["tx_id"] in result.invalid_tx_ids
    assert _reason(result, late) == MAX_HOLD
    assert "max_hold_seconds=600" in _logs(result)
    assert ch.bal[parks.ALICE] == 10_000
    assert ch.bal[parks.PROPOSER] == 0
    assert ch.book.open == {}

    ch = _arm(parks.Chain(parks._balances(), fee=7))
    height = parks.park_tx(amount=500, at_height=parks.HEIGHT + 10)
    result = ch.block([height])
    assert _reason(result, height) == MAX_HOLD
    assert "max_hold_blocks=0" in _logs(result)
    assert "max_hold_seconds=600" in _logs(result)
    assert "straight away" not in _logs(result)
    assert ch.book.open == {}
    assert ch.bal[parks.PROPOSER] == 0


def test_a_hold_inside_the_cap_is_escrowed_and_the_flag_stays_on():
    _install(_over(601))
    ch = _arm(parks.Chain(parks._balances(), fee=7))
    oracle = parks.Oracle(parks._balances())
    tx = parks.park_tx(amount=500, at_time=parks.TS + 600)
    result = ch.block([tx])
    oracle.park(tx, fee=7, ts=parks.TS)
    oracle.check(ch)
    assert result.accepted_tx_ids == [tx["tx_id"]]
    assert ch.lm.recipient_controls_active is True


def test_a_retract_is_not_judged_again_after_the_feature_turns_on():
    ch = parks.Chain(parks._balances())
    tx = parks.park_tx(amount=400, at_height=parks.HEIGHT + 20)
    ch.block([tx])
    _arm(ch)
    sender_policy.set_evaluator("apply", _Exploding())
    result = ch.block(
        [parks.retract_tx(parks.rid_of(tx), seq=1)], height=parks.HEIGHT + 1,
    )
    assert "Retractable transfer retracted" in parks._logs(result)
    assert ch.bal[parks.ALICE] == 10_000
    assert ch.book.open == {}


def test_a_release_is_not_judged_again_after_the_feature_turns_on():
    ch = parks.Chain(parks._balances())
    tx = parks.park_tx(amount=400, at_height=parks.HEIGHT + 5)
    ch.block([tx])
    _arm(ch)
    sender_policy.set_evaluator("apply", _Exploding())
    ch.block([], height=parks.HEIGHT + 5)
    assert ch.bal[parks.BOB] == 400
    assert ch.bal[parks.ALICE] == 10_000 - 400
    assert ch.book.open == {}


# --- admission, governance, restart -----------------------------------------

def test_admission_refuses_a_hold_clause_until_the_flag_is_on():
    tip = MagicMock()
    tip.clause_for.return_value = None
    tip.next_block_timestamp = 0
    tip.recipient_controls_active = False
    rule = "always ( %s )." % HOLD
    tx = {"sender_pubkey": "ab" * 48, "operations": {"0": rule}}
    refused = validate_o5_clause_routing(tx, tip, rule)
    assert refused.is_valid is False
    assert refused.code == "RECIPIENT_CONTROLS_INACTIVE"

    tip.recipient_controls_active = True
    accepted = validate_o5_clause_routing(tx, tip, rule)
    assert accepted.is_valid is True
    assert accepted.data["o5_clause_body"] == HOLD

    custom = "always ( %s )." % CUSTOM
    custom_tx = {"sender_pubkey": "ab" * 48, "operations": {"0": custom}}
    rejected = validate_o5_clause_routing(custom_tx, tip, custom)
    assert rejected.is_valid is False
    assert "must be written i17[t]:bv[64]" in rejected.error


def test_a_user_rule_screen_ignores_i17_in_a_comment():
    mentioned = "always ( i17[t]:bv[64] = {0}:bv[64] )."
    commented = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] ). # i17"
    assert screen_user_rule_text(mentioned, "", False, False) is None
    on = screen_user_rule_text(mentioned, "", False, True)
    assert on.reason == "reserved_input_stream"
    commented_on = screen_user_rule_text(commented, "", False, True)
    assert commented_on is None or commented_on.reason != "reserved_input_stream"


def test_the_proposal_is_refused_when_a_deployed_rule_mentions_i17():
    with patch(
        "consensus.admission._tip_effective_spec_texts",
        return_value=[("clause:alice", "i17[t]:bv[24] = {7}:bv[24]")],
    ):
        refused = _check_host_contract_patch({"recipient_controls_active": True})
    assert "cannot be activated" in refused
    assert "clause:alice" in refused

    with patch("consensus.admission._tip_effective_spec_texts", return_value=[]):
        assert _check_host_contract_patch({"recipient_controls_active": True}) is None
    turned_off = _check_host_contract_patch({"recipient_controls_active": False})
    assert "must be true" in turned_off


def test_activation_is_one_way_and_a_comment_or_i170_does_not_block_it():
    validators = ["ab" * 48]
    for value in (False, 1, "true", None):
        lm = ConsensusLifecycleManager(active_validators=validators)
        with pytest.raises(ValueError):
            lm.apply_host_contract_patch({"recipient_controls_active": value})

    lm = ConsensusLifecycleManager(active_validators=validators)
    before = lm.consensus_meta_hash()
    lm.apply_host_contract_patch(
        {"recipient_controls_active": True},
        effective_spec_texts=[
            ("comment", "# i17 stays a custom stream here"),
            ("neighbour", "i170[t]:bv[24] = {1}:bv[24]"),
            ("blank", "   "),
            ("missing", None),
        ],
    )
    assert lm.recipient_controls_active is True
    assert lm.approval_slots_active is False
    first = lm.consensus_meta_hash()
    assert first != before
    lm.apply_host_contract_patch(
        {"recipient_controls_active": True}, effective_spec_texts=[],
    )
    assert lm.consensus_meta_hash() == first

    collided = ConsensusLifecycleManager(active_validators=validators)
    untouched = collided.consensus_meta_hash()

    def texts():
        return [("consensus_rules", "i17[t]:bv[64] = {0}:bv[64]")]

    collided.apply_host_contract_patch(
        {"recipient_controls_active": True}, effective_spec_texts=texts,
    )
    assert collided.recipient_controls_active is False
    assert collided.consensus_meta_hash() == untouched


def test_the_flag_is_omitted_from_the_hash_until_it_is_on():
    off = build_mechanism_metadata("majority")
    explicit = build_mechanism_metadata("majority", recipient_controls_active=False)
    assert off == explicit
    assert "recipient_controls_active" not in off
    on = build_mechanism_metadata("majority", recipient_controls_active=True)
    assert on["recipient_controls_active"] is True
    keys = list(on)
    assert keys[keys.index("recipient_controls_active") + 1] == "retractable_transfers_root"


def test_the_active_view_and_getgovernance_report_the_same_flag():
    engine = TauConsensusEngine()
    lm = ConsensusLifecycleManager(active_validators=["aa" * 48])
    snap = TauStateSnapshot(
        state_hash="0" * 64, tau_bytes=b"",
        metadata={"lifecycle_manager": lm, "consensus_rules_state": ""},
    )
    assert engine.derive_active_consensus(
        snap, 3,
    ).mechanism_specific_metadata["recipient_controls_active"] is False
    mocked = TauStateSnapshot(
        state_hash="0" * 64, tau_bytes=b"",
        metadata={"lifecycle_manager": MagicMock(), "consensus_rules_state": ""},
    )
    assert engine.derive_active_consensus(
        mocked, 3,
    ).mechanism_specific_metadata["recipient_controls_active"] is False

    lm.activate_recipient_controls()
    assert engine.derive_active_consensus(
        snap, 4,
    ).mechanism_specific_metadata["recipient_controls_active"] is True

    import json
    from commands.getgovernance import execute as getgov

    class _Lock:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class _Chain:
        _balance_lock = _Lock()
        _sequence_lock = _Lock()
        _rules_lock = _Lock()
        _active_consensus_id = None
        _consensus_rules_state = ""
        _application_rules_state = ""
        _lifecycle_manager = lm

    class _DB:
        def get_canonical_head_block(self):
            return {"block_hash": "abc", "header": {"block_number": 1}}

    class _Container:
        chain_state = _Chain()
        db = _DB()

    payload = json.loads(getgov("getgovernance", _Container()))["data"]
    assert payload["recipient_controls_active"] is True
    lm.recipient_controls_active = False
    payload = json.loads(getgov("getgovernance", _Container()))["data"]
    assert payload["recipient_controls_active"] is False


def test_the_facade_reads_the_canonical_manager(monkeypatch):
    lm = ConsensusLifecycleManager(active_validators=["ab" * 48])
    monkeypatch.setattr(chain_state, "_lifecycle_manager", lm)
    view = TipAdmissionView()
    assert view.recipient_controls_active is False
    lm.activate_recipient_controls()
    assert view.recipient_controls_active is True
    monkeypatch.setattr(chain_state, "_lifecycle_manager", MagicMock())
    assert TipAdmissionView().recipient_controls_active is False


def test_a_later_save_that_omits_the_flag_does_not_clear_it(temp_database):
    db.save_canonical_state_atomically(
        "aa" * 32, 1, {}, {}, "", "", "", [], [], [], [],
        recipient_controls_active=True,
    )
    assert db.get_chain_state_value("recipient_controls_active", None) == "1"
    db.save_canonical_state_atomically(
        "aa" * 32, 2, {}, {}, "", "", "", [], [], [], [],
    )
    assert db.get_chain_state_value("recipient_controls_active", None) == "1"
    db.save_canonical_state_atomically(
        "aa" * 32, 3, {}, {}, "", "", "", [], [], [], [],
        recipient_controls_active=False,
    )
    assert db.get_chain_state_value("recipient_controls_active", None) == "0"


def _seed(lm):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances["acct"] = 1
    chain_state._sequence_numbers["acct"] = 0
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    return lm


def _reload():
    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(
        active_validators=["d" * 96],
    )
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_flag_survives_a_restart_and_stays_off_when_it_was_never_set(temp_database):
    off = _seed(ConsensusLifecycleManager(active_validators=["d" * 96]))
    off_hash = off.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.recipient_controls_active is False
    assert reloaded.consensus_meta_hash() == off_hash

    on = _seed(ConsensusLifecycleManager(active_validators=["d" * 96]))
    on.activate_recipient_controls()
    on_hash = on.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.recipient_controls_active is True
    assert reloaded.consensus_meta_hash() == on_hash
    assert on_hash != off_hash


@pytest.mark.usefixtures("isolated_chain_state")
def test_only_a_stored_one_or_a_genesis_pin_turns_the_flag_on(temp_database, monkeypatch):
    _seed(ConsensusLifecycleManager(active_validators=["d" * 96]))
    chain_state.commit_state_to_db("head-hash", 20)
    for stored in ("0", "yes", ""):
        db.set_chain_state_value("recipient_controls_active", stored)
        chain_state._lifecycle_manager = ConsensusLifecycleManager(
            active_validators=["d" * 96],
        )
        assert chain_state.load_state_from_db() is True
        assert chain_state._lifecycle_manager.recipient_controls_active is False

    db.set_chain_state_value("recipient_controls_active", "1")
    chain_state._lifecycle_manager = ConsensusLifecycleManager(
        active_validators=["d" * 96],
    )
    assert chain_state.load_state_from_db() is True
    assert chain_state._lifecycle_manager.recipient_controls_active is True

    monkeypatch.setattr(chain_state, "_genesis_recipient_controls_active", True)
    db.set_chain_state_value("recipient_controls_active", "0")
    chain_state._lifecycle_manager = ConsensusLifecycleManager(
        active_validators=["d" * 96],
    )
    assert chain_state.load_state_from_db() is True
    assert chain_state._lifecycle_manager.recipient_controls_active is True
    assert db.get_chain_state_value("recipient_controls_active") == "1"


# --- the two call sites stay on the helper, not the main interpreter --------

def _calls(path):
    tree = ast.parse((ROOT / path).read_text())
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            else:
                name = None
            found.append((name, node))
    return found


def test_the_main_interpreter_is_not_fed_the_hold_stream():
    """i17 is added on the copy the clause evaluator sees. The fee step keeps
    the transfer map it had before this feature, or a custom i17 would pin the
    process-global width.
    """
    engine_calls = _calls("consensus/engine.py")
    sendtx_calls = _calls("commands/sendtx.py")
    for label, calls, pool in (
        ("apply", engine_calls, "apply"),
        ("admission", sendtx_calls, "admission"),
    ):
        refusals = [node for name, node in calls if name == "recipient_refusal"]
        assert len(refusals) == 1, label
        pools = [
            kw.value.value for kw in refusals[0].keywords if kw.arg == "pool"
        ]
        assert pools == [pool]
        for name, node in calls:
            if name in ("evaluate", "step_multi") and node.args:
                arg = node.args[0]
                fed = isinstance(arg, ast.Call) and (
                    (isinstance(arg.func, ast.Name) and arg.func.id == "sender_clause_inputs")
                    or (isinstance(arg.func, ast.Attribute)
                        and arg.func.attr == "sender_clause_inputs")
                )
                assert not fed, label
