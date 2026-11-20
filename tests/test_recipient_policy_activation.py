"""The receive stream (i17) activates as consensus state, one way, and a chain
that never activates it is byte-identical to one without the feature."""
import copy

import pytest

import chain_state
import tau_defs
from consensus import recipient_policy
from consensus.governance import (
    HOST_CONTRACT_PATCH_KEYS,
    ConsensusLifecycleManager,
    build_mechanism_metadata,
    validate_recipient_policy_active,
)
from consensus.retractable import RetractableBook

import recipient_rules as rules
from test_approval_activation import _legacy_meta_hash
from test_approval_persistence import _reload, _seed_state
from test_getgovernance_scheduled_patch import governance_with_a_scheduled_patch

# Several tests here rebind chain_state globals (rules, manager, genesis flags).
pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = "1a" * 48
B = "2b" * 48

_CLEAN = [
    ("consensus_rules", "always ( o6[t]:bv[16] = i10[t]:bv[16] )."),
    ("application_rules", "always ( o12[t]:bv[24] = i1[t]:bv[24] )."),
    ("clause_aaaaaaaaaa_o5", rules.SPEND_LIMIT),
]


# --- hash compatibility -------------------------------------------------------

@pytest.mark.parametrize("mode", ["", "validator_set", "stake", "tau_validator_set"])
def test_an_untouched_chain_keeps_the_legacy_meta_hash(mode):
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.eligibility_mode = mode
    assert lm.recipient_policy_active is False
    assert lm.consensus_meta_hash() == _legacy_meta_hash(lm)


def test_the_genesis_shaped_call_is_unaffected():
    assert build_mechanism_metadata("supermajority") == {
        "vote_quorum": "supermajority",
        "retractable_transfers_root": RetractableBook().root().hex(),
    }
    mech = build_mechanism_metadata("supermajority", recipient_policy_active=True)
    assert mech["recipient_policy_active"] is True


def test_activation_changes_the_hash_and_is_idempotent():
    lm = ConsensusLifecycleManager(active_validators=[A])
    base = lm.consensus_meta_hash()
    lm.activate_recipient_policy()
    active = lm.consensus_meta_hash()
    assert active != base
    lm.activate_recipient_policy()
    assert lm.consensus_meta_hash() == active


def test_the_two_feature_flags_are_bound_apart():
    slots, receive, both = (ConsensusLifecycleManager(active_validators=[A]) for _ in range(3))
    slots.activate_approval_slots()
    receive.activate_recipient_policy()
    both.activate_approval_slots()
    both.activate_recipient_policy()
    assert len({m.consensus_meta_hash() for m in (slots, receive, both)}) == 3


def test_a_candidate_block_does_not_leak_the_flag():
    parent = ConsensusLifecycleManager(active_validators=[A])
    candidate = copy.deepcopy(parent)
    candidate.activate_recipient_policy()
    assert parent.recipient_policy_active is False


# --- the one-way switch -------------------------------------------------------

@pytest.mark.parametrize("value", [False, None, 0, 1, "true", "", []])
def test_only_true_is_a_legal_patch_value(value):
    assert validate_recipient_policy_active(value) is not None


def test_the_patch_activates_and_refuses_to_deactivate():
    assert "recipient_policy_active" in HOST_CONTRACT_PATCH_KEYS
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.apply_host_contract_patch({"recipient_policy_active": True},
                                 effective_spec_texts=_CLEAN)
    assert lm.recipient_policy_active is True
    with pytest.raises(ValueError, match="cannot be deactivated"):
        lm.apply_host_contract_patch({"recipient_policy_active": False})
    assert lm.recipient_policy_active is True


def test_one_patch_can_turn_on_both_features():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.apply_host_contract_patch(
        {"approval_slots_active": True, "recipient_policy_active": True},
        effective_spec_texts=_CLEAN)
    assert lm.approval_slots_active is True and lm.recipient_policy_active is True


# --- the activation audit -----------------------------------------------------

@pytest.mark.parametrize("label", ["consensus_rules", "application_rules",
                                   "builtin_rule_3", "clause_bbbbbbbbbb_o5"])
def test_a_rule_that_already_reads_i17_blocks_activation(label):
    texts = _CLEAN + [(label, "always ( (i17[t]:bv[24] = { #x01 }:bv[24]) -> "
                              "(o13[t]:bv[24] = { #x01 }:bv[24]) ).")]
    findings = recipient_policy.audit_receive_stream_collisions(texts)
    assert len(findings) == 1 and label in findings[0] and "i17" in findings[0]


def test_neighbours_and_comments_are_not_collisions():
    for stream in ("i1", "i7", "i16", "i18", "i170", "i117"):
        texts = [("application_rules", "always ( (%s[t]:bv[24] = { #x01 }:bv[24]) -> "
                                       "(o13[t]:bv[24] = { #x01 }:bv[24]) )." % stream)]
        assert recipient_policy.audit_receive_stream_collisions(texts) == [], stream
    commented = [("application_rules", "# i17 will be the receive stream\n"
                                       "always ( o12[t]:bv[24] = i1[t]:bv[24] ).")]
    assert recipient_policy.audit_receive_stream_collisions(commented) == []


def test_a_collision_leaves_the_flag_false_on_every_node_alike():
    """Raising at the activation height would freeze the chain, so the second
    phase declines, and every node declines the same way."""
    colliding = _CLEAN + [("clause_cccccccccc_o5", rules.allow_list(A))]
    one, two = (ConsensusLifecycleManager(active_validators=[A]) for _ in range(2))
    for lm in (one, two):
        lm.apply_host_contract_patch({"recipient_policy_active": True},
                                     effective_spec_texts=colliding)
    assert one.recipient_policy_active is two.recipient_policy_active is False
    assert one.consensus_meta_hash() == two.consensus_meta_hash()


def test_the_proposal_is_refused_loudly_when_the_tip_collides(temp_database):
    from consensus.admission import _check_host_contract_patch

    chain_state._consensus_rules_state = "always ( o6[t]:bv[16] = i10[t]:bv[16] )."
    chain_state._application_rules_state = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
    assert _check_host_contract_patch({"recipient_policy_active": True}) is None

    chain_state._application_rules_state = (
        "always ( (i17[t]:bv[24] = { #x01 }:bv[24]) -> (o13[t]:bv[24] = { #x01 }:bv[24]) )."
    )
    err = _check_host_contract_patch({"recipient_policy_active": True})
    assert err is not None and "cannot be activated on this chain" in err
    assert "application_rules" in err

    err = _check_host_contract_patch({"recipient_policy_active": False})
    assert err is not None and "cannot be deactivated" in err


# --- what is reserved, and when -----------------------------------------------

def test_i17_is_write_reserved_only_when_active():
    for mode in ("", "validator_set", "stake", "tau_validator_set"):
        assert tau_defs.reserved_operation_keys(mode) == \
            tau_defs.reserved_operation_keys(mode, recipient_policy_active=False)
        assert 17 not in tau_defs.reserved_operation_keys(mode, approval_slots_active=True)
        assert 17 in tau_defs.reserved_operation_keys(mode, recipient_policy_active=True)


def test_a_clause_may_read_i17_and_no_other_rule_may():
    kinds = {
        kind: tau_defs.rule_text_forbidden_input_streams(
            kind, "", approval_slots_active=True, recipient_policy_active=True)
        for kind in (tau_defs.RULE_TEXT_CONTEXT_USER, tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE,
                     tau_defs.RULE_TEXT_CONTEXT_CONSENSUS)
    }
    assert "i17" in kinds[tau_defs.RULE_TEXT_CONTEXT_USER]
    assert "i17" in kinds[tau_defs.RULE_TEXT_CONTEXT_CONSENSUS]
    assert "i17" not in kinds[tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE]
    inactive = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_USER, "", approval_slots_active=True)
    assert "i17" not in inactive


# --- the values of the stream -------------------------------------------------

def test_the_receive_stream_values():
    assert tau_defs.RECEIVE_SIDE_SENDER == 0
    assert tau_defs.receive_stream_value() == tau_defs.RECEIVE_FINAL_NOW == 1
    assert tau_defs.receive_stream_value(0) == 1
    assert tau_defs.receive_stream_value(600) == 601
    assert tau_defs.receive_stream_value(-5) == 1, "a hold is never negative"
    blocks = tau_defs.RECEIVE_HOLD_BLOCKS
    assert blocks == 10 ** 18
    assert tau_defs.receive_stream_value(hold_blocks=1) == blocks + 1
    assert tau_defs.receive_stream_value(hold_blocks=100_000) == blocks + 100_000
    assert tau_defs.receive_stream_value(hold_blocks=-3) == blocks, "never negative"


def test_the_two_ranges_never_run_into_each_other():
    """A length that does not fit its range reads as the longest of that range."""
    blocks = tau_defs.RECEIVE_HOLD_BLOCKS
    top = (1 << tau_defs.RECEIVE_STREAM_BV_WIDTH) - 1
    assert tau_defs.receive_stream_value(1 << 70) == blocks - 1
    assert tau_defs.receive_stream_value(blocks) == blocks - 1
    assert tau_defs.receive_stream_value(hold_blocks=1 << 70) == top
    # The longest park the chain admits is far inside each range.
    assert 1 + 7_776_000 < blocks and blocks + 100_000 < top


def test_hold_seconds_of_inverts_the_value():
    assert recipient_policy.hold_seconds_of(0) is None
    assert recipient_policy.hold_seconds_of(1) == 0
    assert recipient_policy.hold_seconds_of(601) == 600
    assert recipient_policy.hold_seconds_of(tau_defs.RECEIVE_HOLD_BLOCKS - 1) \
        == tau_defs.RECEIVE_HOLD_BLOCKS - 2
    assert recipient_policy.hold_seconds_of(tau_defs.RECEIVE_HOLD_BLOCKS) is None
    assert recipient_policy.hold_seconds_of(tau_defs.RECEIVE_HOLD_BLOCKS + 30) is None


def test_hold_blocks_of_inverts_the_value():
    assert recipient_policy.hold_blocks_of(0) is None
    assert recipient_policy.hold_blocks_of(1) is None
    assert recipient_policy.hold_blocks_of(7_776_001) is None
    assert recipient_policy.hold_blocks_of(tau_defs.RECEIVE_HOLD_BLOCKS + 30) == 30


def test_a_hold_of_no_length_is_a_payment_that_is_final_at_once():
    for unit in (recipient_policy.SECONDS, recipient_policy.BLOCKS):
        assert recipient_policy.hold_value(unit, 0) == tau_defs.RECEIVE_FINAL_NOW
    assert recipient_policy.hold_value(recipient_policy.SECONDS, 600) == 601
    assert recipient_policy.hold_value(recipient_policy.BLOCKS, 30) \
        == tau_defs.RECEIVE_HOLD_BLOCKS + 30


def test_the_recipient_view_empties_the_slots_and_sets_the_stream():
    values = {1: "5", 18: "{ #x" + A + " }:bv[384]", 26: "7"}
    view = recipient_policy.receive_inputs(values, 601)
    assert view == {1: "5", 18: "0", 26: "7", 17: "601"}
    assert values == {1: "5", 18: "{ #x" + A + " }:bv[384]", 26: "7"}, "the input is not mutated"
    assert 19 not in view, "a slot the sender pass did not feed is not invented"


# --- reading and typing the stream --------------------------------------------

def test_reading_i17_is_decided_from_the_text_outside_comments():
    assert recipient_policy.reads_receive_stream(rules.allow_list(A)) is True
    assert recipient_policy.reads_receive_stream(rules.SPEND_LIMIT) is False
    assert recipient_policy.reads_receive_stream("# i17 later\n" + rules.SPEND_LIMIT) is False
    assert recipient_policy.reads_receive_stream(
        rules.SPEND_LIMIT.replace("i1[", "i170[")) is False
    assert recipient_policy.reads_receive_stream("") is False


@pytest.mark.parametrize("mention", [
    "i17[t]:bv[24]", "i17[t]:bv[384]", "i17[t]", "i17[t-1]:bv[64]", "i17",
])
def test_every_mention_must_be_typed_at_the_frozen_width(mention):
    body = "( (%s = { 1 }:bv[64]) ? %s : %s )" % (mention, rules.ALLOW, rules.BLOCK)
    assert "i17[t]:bv[64]" in recipient_policy.screen_receive_stream_width(body)


def test_the_documented_rules_pass_the_width_screen():
    for body in (rules.allow_list(A), rules.max_hold(600), rules.one_unit(A, B, 60),
                 "( (i17[t] : bv[ 64 ] > { 1 }:bv[64]) ? %s : %s )" % (rules.BLOCK, rules.ALLOW)):
        assert recipient_policy.screen_receive_stream_width(body) is None


# --- the longest hold a clause accepts ----------------------------------------

LONGEST = 7_776_000


FARTHEST = 100_000
SECONDS, BLOCKS = recipient_policy.SECONDS, recipient_policy.BLOCKS
BASE = tau_defs.RECEIVE_HOLD_BLOCKS


def _holds(allows, receive_value):
    return recipient_policy.accepted_holds(
        allows, receive_value, seconds_window=LONGEST, blocks_window=FARTHEST)


@pytest.mark.parametrize("cap", [0, 1, 599, 600, 601, 86_400, LONGEST - 1])
def test_the_cap_in_seconds_is_found_by_bisection(cap):
    calls = []

    def allows(value):
        calls.append(value)
        return value <= cap + 1

    assert recipient_policy.max_accepted_hold(allows, SECONDS, cap + 5_000, LONGEST) == cap
    assert recipient_policy.max_accepted_hold(allows, SECONDS, None, LONGEST) == cap
    assert len(calls) <= 2 * 26, "bisection, not a scan"
    assert _holds(allows, cap + 5_000) == {"max_hold_seconds": cap}


@pytest.mark.parametrize("cap", [1, 2, 99, 100, 101, 5_000, FARTHEST - 1])
def test_the_cap_in_blocks_is_found_by_bisection(cap):
    calls = []

    def allows(value):
        calls.append(value)
        return value <= 601 or BASE <= value <= BASE + cap

    assert recipient_policy.max_accepted_hold(allows, BLOCKS, None, FARTHEST) == cap
    calls.clear()
    assert _holds(allows, BASE + cap + 1) == {"max_hold_blocks": cap}
    assert _holds(allows, BASE + FARTHEST) == {"max_hold_blocks": cap}
    assert len(calls) <= 2 * 20, "bisection, not a scan"


def test_both_ends_of_a_reported_cap_are_answers_of_the_clause():
    """The cap was accepted and the next longer hold was refused, by the clause."""
    for unit, cap, base in ((SECONDS, 600, 1), (BLOCKS, 100, BASE)):
        asked = {}

        def allows(value):
            asked[value] = value <= 601 or BASE <= value <= BASE + 100
            return asked[value]

        assert recipient_policy.max_accepted_hold(allows, unit, None, FARTHEST) == cap
        assert asked[base + cap] is True and asked[base + cap + 1] is False


def test_a_clause_with_a_cap_in_seconds_alone_takes_no_height_release():
    """So a refused height release is told both: no blocks, and the seconds."""
    calls = []

    def allows(value):
        calls.append(value)
        return value <= 601

    assert _holds(allows, BASE + 30) == {"max_hold_blocks": 0, "max_hold_seconds": 600}
    assert len(calls) <= 28
    assert _holds(lambda value: value <= 1, BASE + 30) == {
        "max_hold_blocks": 0, "max_hold_seconds": 0}


def test_a_height_release_of_one_block_that_is_refused_reports_no_blocks():
    allows = lambda value: value <= 601
    assert _holds(allows, BASE + 1) == {"max_hold_blocks": 0, "max_hold_seconds": 600}


def test_no_cap_is_reported_when_the_refusal_is_not_about_the_hold():
    assert recipient_policy.max_accepted_hold(lambda value: False, SECONDS, 600, LONGEST) is None
    assert _holds(lambda value: False, 601) is None
    assert _holds(lambda value: False, BASE + 30) is None


def test_a_clause_that_only_refuses_height_releases_reports_the_longest_window():
    allows = lambda value: value <= LONGEST + 1
    assert recipient_policy.max_accepted_hold(allows, SECONDS, None, LONGEST) == LONGEST
    assert recipient_policy.max_accepted_hold(allows, BLOCKS, None, FARTHEST) == 0


# --- persistence --------------------------------------------------------------

@pytest.fixture
def neutral_genesis(monkeypatch):
    """A reload takes what the database does not hold from the loaded genesis
    (the faucet amount on every load). Keep whatever genesis an earlier test
    loaded out of the comparison with a freshly seeded manager."""
    for name, value in (
        ("_genesis_faucet_amount", 0), ("_genesis_vote_quorum", ""),
        ("_genesis_eligibility_mode", ""), ("_genesis_fee_beneficiary", ""),
        ("_genesis_approval_slots_active", False),
        ("_genesis_recipient_policy_active", False),
    ):
        monkeypatch.setattr(chain_state, name, value)


def test_the_flag_survives_a_restart(temp_database, neutral_genesis):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_recipient_policy()
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.recipient_policy_active is True
    assert reloaded.approval_slots_active is False
    assert reloaded.consensus_meta_hash() == before


def test_an_inactive_chain_restarts_inactive(temp_database, neutral_genesis):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.recipient_policy_active is False
    assert reloaded.consensus_meta_hash() == before


def test_a_genesis_can_ship_with_it_on(temp_database, neutral_genesis, monkeypatch):
    import db

    _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    monkeypatch.setattr(chain_state, "_genesis_recipient_policy_active", True)
    reloaded = _reload()
    assert reloaded.recipient_policy_active is True
    assert db.get_chain_state_value("recipient_policy_active", None) == "1"


# --- reading governance while the patch is scheduled ---------------------------

def test_getgovernance_answers_while_the_patch_is_scheduled(temp_database, monkeypatch):
    """The advisory check of this patch audits the rules in force, like the one
    for the approval slots (tests/test_getgovernance_scheduled_patch.py)."""
    entry = governance_with_a_scheduled_patch(monkeypatch, {"recipient_policy_active": True})
    assert entry["host_contract_patch"] == {"recipient_policy_active": True}
    assert entry["precheck"] == "ok", entry


def test_the_scheduled_patch_is_flagged_when_a_rule_started_reading_i17(
        temp_database, monkeypatch):
    """The warning window the advisory check exists for: a rule that reads i17
    arrived after the proposal was admitted, so the activation will leave the
    flag off. The operator sees it before the height, not after."""
    import consensus.admission as admission

    monkeypatch.setattr(admission, "_tip_effective_spec_texts", lambda: [
        ("clause_aaaaaaaaaa_o5", rules.allow_list(A)),
    ])
    entry = governance_with_a_scheduled_patch(
        monkeypatch, {"recipient_policy_active": True})
    assert entry["precheck"] == "fail"
    assert "cannot be activated on this chain" in entry["precheck_error"]
