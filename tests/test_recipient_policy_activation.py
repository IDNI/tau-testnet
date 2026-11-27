"""The receive record (i17, i50 to i54) activates as consensus state, one way, and a chain
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
    meta = build_mechanism_metadata("supermajority")
    assert "recipient_policy_active" not in meta
    assert meta["vote_quorum"] == "supermajority"
    assert meta["retractable_transfers_root"] == RetractableBook().root().hex()
    assert meta == build_mechanism_metadata("supermajority", recipient_policy_active=False)
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

RECORD = ["i%d" % index for index in tau_defs.RECEIVE_RECORD_INDICES]


def test_the_record_is_six_inputs():
    assert RECORD == ["i17", "i50", "i51", "i52", "i53", "i54"]
    assert tau_defs.RECEIVE_STREAM_BV_WIDTH == 64
    assert tau_defs.RECEIVE_NEVER == 2 ** 64 - 1


@pytest.mark.parametrize("stream", RECORD)
@pytest.mark.parametrize("label", ["consensus_rules", "application_rules",
                                   "builtin_rule_3", "clause_bbbbbbbbbb_o5"])
def test_a_rule_that_already_reads_the_record_blocks_activation(label, stream):
    """Before activation every input of the record is an ordinary custom
    stream, so the audit covers all six."""
    texts = _CLEAN + [(label, "always ( (%s[t]:bv[24] = { #x01 }:bv[24]) -> "
                              "(o13[t]:bv[24] = { #x01 }:bv[24]) )." % stream)]
    findings = recipient_policy.audit_receive_stream_collisions(texts)
    assert len(findings) == 1 and label in findings[0] and stream in findings[0]


def test_neighbours_and_comments_are_not_collisions():
    for stream in ("i1", "i7", "i16", "i18", "i170", "i117", "i5", "i49", "i55",
                   "i500", "i150", "i26"):
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

@pytest.mark.parametrize("index", tau_defs.RECEIVE_RECORD_INDICES)
def test_the_record_is_write_reserved_only_when_active(index):
    for mode in ("", "validator_set", "stake", "tau_validator_set"):
        assert tau_defs.reserved_operation_keys(mode) == \
            tau_defs.reserved_operation_keys(mode, recipient_policy_active=False)
        assert index not in tau_defs.reserved_operation_keys(mode, approval_slots_active=True)
        assert index in tau_defs.reserved_operation_keys(mode, recipient_policy_active=True)


def test_a_clause_may_read_the_record_and_no_other_rule_may():
    kinds = {
        kind: tau_defs.rule_text_forbidden_input_streams(
            kind, "", approval_slots_active=True, recipient_policy_active=True)
        for kind in (tau_defs.RULE_TEXT_CONTEXT_USER, tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE,
                     tau_defs.RULE_TEXT_CONTEXT_CONSENSUS)
    }
    inactive = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_USER, "", approval_slots_active=True)
    for stream in RECORD:
        assert stream in kinds[tau_defs.RULE_TEXT_CONTEXT_USER]
        assert stream in kinds[tau_defs.RULE_TEXT_CONTEXT_CONSENSUS]
        assert stream not in kinds[tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE]
        assert stream not in inactive


# --- the record -----------------------------------------------------------------

SECONDS, BLOCKS = recipient_policy.SECONDS, recipient_policy.BLOCKS
Record = recipient_policy.ReceiveRecord
NEVER = tau_defs.RECEIVE_NEVER


def test_the_kinds_of_a_payment():
    assert (tau_defs.RECEIVE_KIND_OWN, tau_defs.RECEIVE_KIND_FINAL,
            tau_defs.RECEIVE_KIND_SECONDS, tau_defs.RECEIVE_KIND_BLOCKS) == (0, 1, 2, 3)


def test_a_final_payment_carries_the_most_permissive_value_of_every_condition():
    final = recipient_policy.FINAL
    assert final == Record(kind=1, hold=0, recall=0, limit=0, period=0, refund=NEVER)
    assert final.unit is None
    assert final.streams() == {17: "1", 50: "0", 51: "0", 52: "0", 53: "0", 54: str(NEVER)}


@pytest.mark.parametrize("unit, kind", [(SECONDS, 2), (BLOCKS, 3)])
def test_a_park_is_held_and_open_to_a_recall_until_its_release(unit, kind):
    park = recipient_policy.park_record(unit, 600)
    assert park == Record(kind=kind, hold=600, recall=600, limit=0, period=0, refund=NEVER)
    assert park.unit == unit
    assert park.streams() == {17: str(kind), 50: "600", 51: "600", 52: "0", 53: "0",
                              54: str(NEVER)}
    assert recipient_policy.park_record(unit, -5).hold == 0, "a hold is never negative"


def test_a_number_that_does_not_fit_reads_as_the_largest():
    record = Record(kind=2, hold=1 << 70, recall=-3, refund=1 << 90)
    streams = record.streams()
    assert streams[50] == str(NEVER) and streams[51] == "0" and streams[54] == str(NEVER)


def test_seconds_and_blocks_are_never_one_number():
    """One clock a payment, named by the kind: the same length in seconds and
    in blocks differs in i17 alone, so a rule written for one never matches the
    other by accident."""
    timed = recipient_policy.park_record(SECONDS, 100).streams()
    by_height = recipient_policy.park_record(BLOCKS, 100).streams()
    assert {key for key in timed if timed[key] != by_height[key]} == {17}


@pytest.mark.parametrize("record, said", [
    (Record(kind=2, limit=16_777_216, period=60), "spending limit above 16777215"),
    (Record(kind=2, limit=5, period=31_622_401), "period above 31622400 seconds"),
    (Record(kind=3, limit=5, period=1_000_001), "period above 1000000 blocks"),
    (Record(kind=2, limit=5, period=NEVER - 126), "period above"),
])
def test_terms_above_the_ceilings_of_the_limit_are_not_put_to_the_receiver(record, said):
    """The ceilings are part of the record. Above them the sum a limit rule
    rounds with would wrap (for a period of 2^64 - 126 the rule accepts any
    cap), so such a payment is refused before the receiver is asked."""
    assert said in recipient_policy.record_ceiling_error(record)

    asked = []
    blocked, detail = recipient_policy.recipient_blocks(
        lambda account, stream: rules.max_hold(600), "bb", {}, record, pool="apply")
    assert blocked is True and said in detail and asked == []


@pytest.mark.parametrize("record", [
    recipient_policy.FINAL,
    Record(kind=2, limit=16_777_215, period=31_622_400),
    Record(kind=3, limit=16_777_215, period=1_000_000),
    Record(kind=2, hold=NEVER, recall=NEVER, refund=0),
])
def test_terms_inside_the_ceilings_are_put_to_the_receiver(record):
    assert recipient_policy.record_ceiling_error(record) is None


def test_the_recipient_view_empties_the_slots_and_sets_the_record():
    values = {1: "5", 18: "{ #x" + A + " }:bv[384]", 26: "7"}
    view = recipient_policy.receive_inputs(values, recipient_policy.park_record(SECONDS, 600))
    assert view == {1: "5", 18: "0", 26: "7", 17: "2", 50: "600", 51: "600",
                    52: "0", 53: "0", 54: str(NEVER)}
    assert values == {1: "5", 18: "{ #x" + A + " }:bv[384]", 26: "7"}, "the input is not mutated"
    assert 19 not in view, "a slot the sender pass did not feed is not invented"


def test_a_sender_cannot_set_the_record_through_a_custom_input():
    """Whatever the sender pass carried on a stream of the record is replaced."""
    values = {1: "5", 50: "0", 54: "0", 17: "1"}
    view = recipient_policy.receive_inputs(values, recipient_policy.park_record(BLOCKS, 9))
    assert (view[17], view[50], view[51], view[54]) == ("3", "9", "9", str(NEVER))


# --- reading and typing the stream --------------------------------------------

def test_reading_the_record_is_decided_from_the_text_outside_comments():
    assert recipient_policy.reads_receive_stream(rules.allow_list(A)) is True
    for stream in RECORD:
        body = "( (%s[t]:bv[64] <= { 5 }:bv[64]) ? %s : %s )" % (
            stream, rules.ALLOW, rules.BLOCK)
        assert recipient_policy.reads_receive_stream(body) is True, stream
        assert recipient_policy.reads_receive_stream(
            "# %s later\n%s" % (stream, rules.SPEND_LIMIT)) is False
    assert recipient_policy.reads_receive_stream(rules.SPEND_LIMIT) is False
    assert recipient_policy.reads_receive_stream("# i17 later\n" + rules.SPEND_LIMIT) is False
    assert recipient_policy.reads_receive_stream(
        rules.SPEND_LIMIT.replace("i1[", "i170[")) is False
    assert recipient_policy.reads_receive_stream("") is False


@pytest.mark.parametrize("stream", RECORD)
@pytest.mark.parametrize("tail", ["[t]:bv[24]", "[t]:bv[384]", "[t]", "[t-1]:bv[64]", ""])
def test_every_mention_must_be_typed_at_the_frozen_width(stream, tail):
    body = "( (%s%s = { 1 }:bv[64]) ? %s : %s )" % (stream, tail, rules.ALLOW, rules.BLOCK)
    assert "%s[t]:bv[64]" % stream in recipient_policy.screen_receive_stream_width(body)


def test_one_wrongly_typed_mention_among_good_ones_is_found():
    body = rules.max_hold(600).replace("i50[t]:bv[64]", "i50[t]:bv[32]")
    assert "i50[t]:bv[64]" in recipient_policy.screen_receive_stream_width(body)


def test_the_documented_rules_pass_the_width_screen():
    for body in (rules.allow_list(A), rules.final_only(), rules.max_hold(600),
                 rules.max_hold_either(600, 100), rules.hold_and_recall(2_592_000, 3_600),
                 rules.hold_plus_recall(3_600), rules.one_unit(A, B, 60),
                 "( (i17[t] : bv[ 64 ] > { 1 }:bv[64]) ? %s : %s )" % (rules.BLOCK, rules.ALLOW)):
        assert recipient_policy.screen_receive_stream_width(body) is None


# --- the shape of a clause that reads the record --------------------------------

def _reading_the_record(condition):
    return "( (%s%s) ? %s : %s )" % (condition, rules.FINAL, rules.ALLOW, rules.BLOCK)


@pytest.mark.parametrize("condition, named", [
    ("[t > 3] && ", "[t > 3]"),
    ("[t = 0] || ", "[t = 0]"),
    ("[ t>=2 ] && ", "[ t>=2 ]"),
    ("<> ", "<>"),
    ("[] ", "[]"),
    ("sometimes ", "sometimes"),
    ("always ", "always"),
    ("ex x (x = { 1 }:bv[64]) && ", "ex"),
    ("all x (x = x) && ", "all"),
    ("(i17[t]:bv[64] = 1) && ", "1"),
    ("(i50[t]:bv[64] = #x01) && ", "#x01"),
    ("f(i50[t]:bv[64]) && ", "f"),
])
def test_a_receive_clause_whose_answer_can_depend_on_earlier_steps_is_refused(condition, named):
    """The receiver is asked again for every incoming payment, on whatever
    engine instance the node has at hand. A step constraint, a temporal operator,
    a variable or a piece the scanner does not know could make that answer
    depend on how many steps the instance has taken."""
    error = recipient_policy.screen_receive_clause_shape(_reading_the_record(condition))
    assert error is not None and "found '%s'" % named in error, error


def test_a_step_constraint_named_only_in_a_comment_is_not_read():
    body = "# [t > 3] would split the nodes\n" + _reading_the_record("")
    assert recipient_policy.screen_receive_clause_shape(body) is None


def test_a_clause_that_does_not_read_the_record_is_not_screened_for_its_shape():
    """Its answer is asked only about its owner's own sends, as on main."""
    body = "( ([t > 3] && %s) ? %s : %s )" % (
        "(i1[t]:bv[24] > { 5 }:bv[24])", rules.BLOCK, rules.ALLOW)
    assert recipient_policy.reads_receive_stream(body) is False
    assert recipient_policy.screen_receive_clause_shape(body) is None


def test_every_documented_and_helper_rule_has_the_shape():
    bodies = [rules.allow_list(A), rules.allow_list(A, B), rules.final_only(),
              rules.max_hold(600), rules.max_hold_either(600, 100),
              rules.hold_and_recall(2_592_000, 3_600), rules.hold_plus_recall(3_600),
              rules.one_unit(A, B, 60), rules.min_allowance(500, 604_800),
              rules.average_allowance(500, 604_800), rules.no_limits(),
              rules.min_refund(3_600), rules.no_refunds(),
              rules.combined(A, 600, 60, 500, 604_800, 3_600),
              rules.needs_reference(30),
              "( (T && %s) ? %s : %s )" % (rules.FINAL, rules.ALLOW, rules.BLOCK)]
    for body in bodies:
        assert recipient_policy.reads_receive_stream(body) is True
        assert recipient_policy.screen_receive_clause_shape(body) is None, body


def test_the_rule_syntax_refuses_a_step_constraint_with_or_without_the_feature():
    """The node's rule syntax refuses a step constraint in every clause, at
    admission and at apply, so no block carries one. The record's own screen
    stays behind it as a second line."""
    from consensus.admission import _screen_clause
    from consensus.engine import _clause_domain_rejection

    body = _reading_the_record("[t > 3] && ")
    for active in (False, True):
        refused = _screen_clause(body, receive_active=active)
        assert refused is not None and "outside the admitted syntax" in refused
        error, reason = _clause_domain_rejection(body, receive_active=active)
        assert error == refused and reason == "rule_fragment"


# --- which condition refused, and what the receiver would take ------------------

LONGEST = 7_776_000
FARTHEST = 100_000
SENDER_, HOLD, RECALL = recipient_policy.SENDER, recipient_policy.HOLD, recipient_policy.RECALL
LIMIT, REFUND, COMBINED = (recipient_policy.LIMIT, recipient_policy.REFUND,
                           recipient_policy.COMBINED)


def _clause(hold=None, recall=None, blocks_hold=None, min_limit_per_week=None,
            min_refund=None, calls=None):
    """A receiver's rule as a function of the record: bounds on block time, and
    optionally a hold bound on block height."""
    def allows(record):
        if calls is not None:
            calls.append(record)
        if record.kind <= 1:
            return True
        if record.kind == 3:
            return blocks_hold is not None and record.hold <= blocks_hold
        if hold is not None and record.hold > hold:
            return False
        if recall is not None and record.recall > recall:
            return False
        if min_limit_per_week is not None and record.period != 0:
            weeks = (record.period + 604_799) // 604_800
            if record.limit < min_limit_per_week * weeks:
                return False
        if min_refund is not None and record.refund < min_refund:
            return False
        return True
    return allows


def _bounds(allows, record, condition):
    return recipient_policy.accepted_instead(
        allows, record, condition, seconds_window=LONGEST, blocks_window=FARTHEST)


def test_each_condition_is_asked_alone_with_the_others_at_their_most_permissive():
    record = Record(kind=2, hold=10, recall=20, limit=30, period=40, refund=50)
    alone = Record(kind=2)
    assert alone == Record(kind=2, hold=0, recall=0, limit=0, period=0, refund=NEVER)
    assert recipient_policy.isolated(record, HOLD) == alone._replace(hold=10)
    assert recipient_policy.isolated(record, RECALL) == alone._replace(recall=20)
    assert recipient_policy.isolated(record, LIMIT) == alone._replace(limit=30, period=40)
    assert recipient_policy.isolated(record, REFUND) == alone._replace(refund=50)


def test_a_payment_refused_even_when_final_is_refused_for_its_sender():
    calls = []

    def allows(record):
        calls.append(record)
        return False

    park = recipient_policy.park_record(SECONDS, 600)
    assert recipient_policy.refused_condition(allows, park) == SENDER_
    assert calls == [recipient_policy.FINAL], "nothing more is asked about the other terms"


def test_a_refused_final_payment_is_not_asked_again():
    def allows(record):
        raise AssertionError("a final payment carries no condition to isolate")

    assert recipient_policy.refused_condition(allows, recipient_policy.FINAL) == SENDER_


@pytest.mark.parametrize("record, clause, condition", [
    (Record(kind=2, hold=700, recall=10), dict(hold=600, recall=60), HOLD),
    (Record(kind=2, hold=600, recall=61), dict(hold=600, recall=60), RECALL),
    (Record(kind=2, hold=700, recall=700), dict(hold=600, recall=60), HOLD),
    (Record(kind=2, limit=1_999, period=2_592_000), dict(min_limit_per_week=500), LIMIT),
    (Record(kind=2, hold=5, limit=150, period=604_800, refund=10 ** 7),
     dict(hold=600, min_limit_per_week=500), LIMIT),
    (Record(kind=2, refund=7_775_999), dict(min_refund=7_776_000), REFUND),
    (Record(kind=2, recall=61, limit=1, period=1, refund=5),
     dict(recall=60, min_limit_per_week=500, min_refund=10), RECALL),
    (Record(kind=3, hold=30, recall=30), dict(hold=600), HOLD),
])
def test_the_first_condition_refused_on_its_own_is_named(record, clause, condition):
    allows = _clause(**clause)
    assert not allows(record)
    assert recipient_policy.refused_condition(allows, record) == condition


def test_the_order_is_sender_hold_recall_limit_refund():
    calls = []
    record = Record(kind=2, hold=1, recall=2, limit=3, period=4, refund=5)
    recipient_policy.refused_condition(_clause(calls=calls), record)
    alone = Record(kind=2)
    assert calls == [recipient_policy.FINAL, alone._replace(hold=1), alone._replace(recall=2),
                     alone._replace(limit=3, period=4), alone._replace(refund=5)]


def test_a_condition_the_payment_does_not_carry_is_not_asked():
    calls = []
    park = recipient_policy.park_record(SECONDS, 600)
    recipient_policy.refused_condition(_clause(calls=calls), park)
    assert calls == [recipient_policy.FINAL, Record(kind=2, hold=600),
                     Record(kind=2, recall=600)]


def test_a_rule_that_ties_two_conditions_together_is_the_combination():
    tied = lambda record: record.kind <= 1 or record.hold + record.recall <= 3_600
    park = recipient_policy.park_record(SECONDS, 2_400)
    assert not tied(park)
    assert recipient_policy.refused_condition(tied, park) == COMBINED


def test_every_condition_has_its_code():
    assert recipient_policy.REFUSAL_CODES == {
        SENDER_: "RECIPIENT_SENDER", HOLD: "RECIPIENT_HOLD", RECALL: "RECIPIENT_RECALL",
        LIMIT: "RECIPIENT_LIMIT", REFUND: "RECIPIENT_REFUND",
        COMBINED: "RECIPIENT_COMBINED",
    }


@pytest.mark.parametrize("cap", [0, 1, 599, 600, 601, 86_400, LONGEST - 1])
@pytest.mark.parametrize("condition", [HOLD, RECALL])
def test_the_bound_in_seconds_is_found_by_bisection(cap, condition):
    calls = []
    allows = _clause(calls=calls, **{condition: cap})
    find = recipient_policy.longest_accepted
    assert find(allows, SECONDS, condition, cap + 5_000, LONGEST) == cap
    assert find(allows, SECONDS, condition, None, LONGEST) == cap
    assert len(calls) <= 2 * 26, "bisection, not a scan"
    asked = Record(kind=2, **{condition: cap + 5_000})
    assert _bounds(allows, asked, condition) == {"max_%s_seconds" % condition: cap}
    other = RECALL if condition == HOLD else HOLD
    assert all(getattr(record, other) == 0 for record in calls), \
        "the other condition stays at its most permissive value"


@pytest.mark.parametrize("cap", [1, 2, 99, 100, 101, 5_000, FARTHEST - 1])
def test_the_bound_in_blocks_is_found_by_bisection(cap):
    calls = []
    allows = _clause(hold=600, blocks_hold=cap, calls=calls)
    assert recipient_policy.longest_accepted(allows, BLOCKS, HOLD, None, FARTHEST) == cap
    calls.clear()
    assert _bounds(allows, Record(kind=3, hold=cap + 1), HOLD) == {"max_hold_blocks": cap}
    assert _bounds(allows, Record(kind=3, hold=FARTHEST), HOLD) == {"max_hold_blocks": cap}
    assert len(calls) <= 2 * 20, "bisection, not a scan"


def test_both_ends_of_a_reported_bound_are_answers_of_the_clause():
    """The bound was accepted and the next longer one was refused, by the clause."""
    for unit, kind, cap in ((SECONDS, 2, 600), (BLOCKS, 3, 100)):
        asked = {}
        rule = _clause(hold=600, blocks_hold=100)

        def allows(record):
            asked[record] = rule(record)
            return asked[record]

        assert recipient_policy.longest_accepted(allows, unit, HOLD, None, FARTHEST) == cap
        assert asked[Record(kind=kind, hold=cap)] is True
        assert asked[Record(kind=kind, hold=cap + 1)] is False


def test_a_rule_with_a_bound_in_seconds_alone_takes_no_height_release():
    """So a refused height release is told both: no blocks, and the seconds."""
    calls = []
    allows = _clause(hold=600, calls=calls)
    park = recipient_policy.park_record(BLOCKS, 30)
    assert _bounds(allows, park, HOLD) == {"max_hold_blocks": 0, "max_hold_seconds": 600}
    assert len(calls) <= 28
    final_only = lambda record: record.kind <= 1
    assert _bounds(final_only, park, HOLD) == {"max_hold_blocks": 0, "max_hold_seconds": 0}
    assert _bounds(final_only, recipient_policy.park_record(SECONDS, 30), HOLD) == {
        "max_hold_seconds": 0}


def test_a_height_release_of_one_block_that_is_refused_reports_no_blocks():
    allows = _clause(hold=600)
    assert _bounds(allows, recipient_policy.park_record(BLOCKS, 1), HOLD) == {
        "max_hold_blocks": 0, "max_hold_seconds": 600}


def test_nothing_on_a_clock_is_no_bound_on_it():
    refuses_all = lambda record: False
    assert recipient_policy.longest_accepted(refuses_all, SECONDS, HOLD, 600, LONGEST) is None
    assert recipient_policy.longest_accepted(refuses_all, BLOCKS, RECALL, None, FARTHEST) is None


def test_a_rule_without_a_bound_reports_the_longest_window():
    allows = _clause()
    assert recipient_policy.longest_accepted(allows, SECONDS, HOLD, None, LONGEST) == LONGEST
    assert recipient_policy.longest_accepted(allows, SECONDS, RECALL, None, LONGEST) == LONGEST
    assert recipient_policy.longest_accepted(allows, BLOCKS, HOLD, None, FARTHEST) is None


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


def test_the_scheduled_patch_is_flagged_when_a_rule_started_reading_the_record(
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
