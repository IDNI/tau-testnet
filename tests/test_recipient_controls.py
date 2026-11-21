"""Recipient controls (#47, #76): the hold code, the clause screen, and the refusal.

The evaluator is the in-process mock. These tests do not need the native engine:
the admission and apply paths call the same `recipient_refusal`.
"""
import pytest
from unittest.mock import MagicMock

import db
import tau_defs
from consensus.admission import (
    _admission_from_domain_error,
    _screen_clause_domains,
    validate_user_tx_reserved_domains,
)
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.policy_mock import MockPolicyEvaluator
from consensus.recipient_policy import (
    BLOCKS_LO,
    CODE_PLAIN,
    HEIGHT_CODE_BASE,
    MAX_HOLD,
    POLICY_BLOCK,
    TIME_CODE_MAX,
    audit_hold_stream,
    clause_reads_hold_stream,
    controls_active,
    park_hold_code,
    recipient_refusal,
    screen_hold_clause,
    sender_clause_inputs,
)
from consensus.retractable import KIND_HEIGHT, KIND_TIME
from consensus import sender_policy

HOLD = "i17[t]:bv[64]"
CAP_600 = 601  # i17 > 601, a hold of 600 seconds
PAYER = "aa" * 48
OTHER = "bb" * 48


@pytest.fixture(autouse=True)
def _mock_evaluator():
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)
    yield
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)


def _use(decide, body=HOLD):
    mock = MockPolicyEvaluator()
    mock.set_verdict(body, decide)
    sender_policy.set_evaluator("apply", mock)
    return mock


def _over(limit):
    def decide(inputs):
        return 0 if int(inputs["i17"]) > limit else 1
    return decide


def _allow_payer(payer, body=HOLD):
    def decide(inputs):
        if int(inputs["i17"]) == 0:
            return 1
        return 1 if inputs.get("i3") == payer else 0
    _use(decide, body)
    return body


def test_a_time_park_and_a_height_park_use_different_ranges():
    assert park_hold_code(KIND_TIME, 1_000 + 600, 0, 1_000) == 601
    assert park_hold_code(KIND_HEIGHT, 10 + 3, 10, 0) == HEIGHT_CODE_BASE + 3
    assert park_hold_code(KIND_TIME, 5, 0, 5) == 2
    assert HEIGHT_CODE_BASE == TIME_CODE_MAX
    assert BLOCKS_LO == TIME_CODE_MAX + 1


def test_the_sender_pass_feeds_zero_only_when_the_feature_is_on():
    values = {1: "5", 3: PAYER}
    assert sender_clause_inputs(values, False) is values
    fed = sender_clause_inputs(values, True)
    assert fed[17] == "0"
    assert 17 not in values


def test_an_outbound_clause_is_not_asked_about_an_incoming_payment():
    body = "i4[t]:bv[384]"
    assert clause_reads_hold_stream(body) is False

    def explode(_inputs):
        raise AssertionError("recipient pass ran")

    _use(explode, body)
    assert recipient_refusal(body, {3: OTHER}, CODE_PLAIN, pool="apply") is None


def test_cap_zero_admits_a_plain_payment_and_refuses_every_park():
    _use(_over(CODE_PLAIN))
    assert recipient_refusal(HOLD, {}, CODE_PLAIN, pool="apply") is None
    for code in (2, 601):
        refusal = recipient_refusal(HOLD, {}, code, pool="apply")
        assert refusal.code == MAX_HOLD
        assert refusal.details == {"max_hold_seconds": 0}
        assert "straight away" in refusal.message
    height = recipient_refusal(
        HOLD, {}, park_hold_code(KIND_HEIGHT, 20, 10, 0), pool="apply",
    )
    assert height.code == MAX_HOLD
    assert height.details == {"max_hold_blocks": 0, "max_hold_seconds": 0}
    assert "straight away" in height.message


def test_a_600_second_cap_allows_600_and_refuses_an_hour():
    _use(_over(CAP_600))
    assert recipient_refusal(HOLD, {}, 601, pool="apply") is None
    refusal = recipient_refusal(HOLD, {}, 1 + 3600, pool="apply")
    assert refusal.code == MAX_HOLD
    assert refusal.details == {"max_hold_seconds": 600}
    assert "600 seconds" in refusal.message
    height = recipient_refusal(HOLD, {}, HEIGHT_CODE_BASE + 10, pool="apply")
    assert height.code == MAX_HOLD
    assert height.details == {"max_hold_blocks": 0, "max_hold_seconds": 600}
    assert "600 seconds" in height.message
    assert "straight away" not in height.message
    assert "max_hold_blocks=0" in height.message


def test_the_recipient_pass_sees_co_signers_as_zero_and_leaves_absent_slots_out():
    cosigner = "{ #x" + PAYER + " }:bv[384]"
    values = {3: OTHER, 18: cosigner, "i25": cosigner}
    mock = _use(lambda inputs: 0 if inputs.get("i18") not in (None, "0") else 1)
    assert recipient_refusal(HOLD, values, CODE_PLAIN, pool="apply") is None
    assert values[18] == cosigner
    seen = mock.verdict_calls[0][1]
    assert seen["i18"] == "0"
    assert seen["i25"] == "0"
    bare = {3: OTHER}
    mock = _use(lambda inputs: 1)
    assert recipient_refusal(HOLD, bare, CODE_PLAIN, pool="apply") is None
    assert "i18" not in mock.verdict_calls[0][1]
    assert "i25" not in mock.verdict_calls[0][1]


def test_an_allow_list_names_the_payer_and_does_not_invent_a_hold_cap():
    body = _allow_payer(PAYER)
    assert recipient_refusal(body, {3: PAYER}, CODE_PLAIN, pool="apply") is None
    assert recipient_refusal(body, {3: PAYER}, 1 + 3600, pool="apply") is None
    blocked = recipient_refusal(body, {3: OTHER}, CODE_PLAIN, pool="apply")
    assert blocked.code == POLICY_BLOCK
    assert blocked.details == {}
    parked = recipient_refusal(body, {3: OTHER}, 1 + 60, pool="apply")
    assert parked.code == POLICY_BLOCK
    assert "max_hold" not in parked.message


def test_a_non_monotonic_hold_rule_does_not_report_a_maximum():
    def decide(inputs):
        code = int(inputs["i17"])
        if code == CODE_PLAIN or code == TIME_CODE_MAX:
            return 1
        return 0
    _use(decide)
    refusal = recipient_refusal(HOLD, {}, 1 + 60, pool="apply")
    assert refusal.code == POLICY_BLOCK
    assert refusal.details == {}


def test_inactive_screen_refuses_a_bv64_hold_clause_and_keeps_a_custom_i17():
    hold = (
        "(i17[t]:bv[64] > {1}:bv[64]) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24])"
    )
    custom = (
        "(i17[t]:bv[24] = { #x000007 }:bv[24]) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24])"
    )
    inactive = _screen_clause_domains(hold)
    assert inactive.startswith("recipient controls are not active")
    assert _admission_from_domain_error(inactive).code == "RECIPIENT_CONTROLS_INACTIVE"
    assert _screen_clause_domains(custom) is None
    assert screen_hold_clause(hold, active=True) is None
    assert screen_hold_clause(custom, active=True) is not None


def test_a_deployed_i17_mention_blocks_activation_and_a_clean_spec_does_not():
    validators = ["ab" * 48]
    blocked = ConsensusLifecycleManager(active_validators=validators)
    blocked.apply_host_contract_patch(
        {"recipient_controls_active": True},
        effective_spec_texts=[("application_rules", "i17[t]:bv[24] = 1")],
    )
    assert blocked.recipient_controls_active is False

    clean = ConsensusLifecycleManager(active_validators=validators)
    before = clean.consensus_meta_hash()
    clean.apply_host_contract_patch(
        {"recipient_controls_active": True}, effective_spec_texts=[],
    )
    assert clean.recipient_controls_active is True
    assert clean.consensus_meta_hash() != before
    assert "recipient_controls_active" not in build_mechanism_metadata("majority")
    assert build_mechanism_metadata(
        "majority", recipient_controls_active=True,
    )["recipient_controls_active"] is True


def test_the_flag_cannot_be_turned_off():
    lm = ConsensusLifecycleManager(active_validators=["ab" * 48])
    with pytest.raises(ValueError):
        lm.apply_host_contract_patch({"recipient_controls_active": False})


def test_i17_is_reserved_only_while_the_feature_is_on():
    assert tau_defs.RECIPIENT_HOLD_STREAM_INDEX == 17
    assert tau_defs.RECIPIENT_HOLD_BV_WIDTH == 64
    assert 17 not in tau_defs.reserved_operation_keys("")
    assert 17 in tau_defs.reserved_operation_keys("", recipient_controls_active=True)
    user = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_USER, recipient_controls_active=True,
    )
    clause = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE, recipient_controls_active=True,
    )
    assert "i17" in user
    assert "i17" not in clause


def test_a_sender_cannot_write_i17_once_the_feature_is_on():
    tip = MagicMock()
    tip.eligibility_mode = ""
    tip.approval_slots_active = False
    tip.recipient_controls_active = True
    result = validate_user_tx_reserved_domains(
        {"operations": {"17": "1"}, "sender_pubkey": PAYER}, tip,
    )
    assert result.is_valid is False
    assert "17" in result.error


def test_a_missing_flag_reads_as_off_even_on_a_mock():
    assert controls_active(object()) is False
    assert controls_active(MagicMock()) is False

    class On:
        recipient_controls_active = True

    assert controls_active(On()) is True


def test_audit_reports_every_deployed_mention():
    assert audit_hold_stream([("consensus_rules", "o6[t]:bv[8] = 1")]) == []
    found = audit_hold_stream([
        ("clause:alice", "i17[t]:bv[24] = {7}:bv[24]"),
        ("comment_only", "# i17 is discussed here"),
    ])
    assert len(found) == 1
    assert "clause:alice" in found[0]


def test_the_flag_round_trips_through_canonical_state(temp_database):
    db.save_canonical_state_atomically(
        "aa" * 32, 1, {}, {}, "", "", "", [], [], [], [],
        recipient_controls_active=True,
    )
    assert db.get_chain_state_value("recipient_controls_active", None) == "1"
