"""Approval slots activate as CONSENSUS STATE, and only forwards.

Two things are being defended here.

1. HASH COMPATIBILITY. While the feature is untouched, the meta hash must be
   byte-identical to the pre-feature preimage, so an existing chain needs no
   regenesis and `gen_genesis` is unaffected. `_legacy_meta_hash` reconstructs
   that preimage by hand rather than calling the current builder, so a change to
   the builder cannot quietly redefine what "unchanged" means.

2. THE FLAG IS NOT A MODULE GLOBAL. `engine.apply` does
   `lm = copy.deepcopy(parent_lm)` (engine.py:511) so every candidate block
   simulates against an isolated manager. A `tau_defs.APPROVAL_SLOTS_ACTIVE`
   would sit outside that copy and leak across candidate simulation, rollback,
   reorg and competing branches -- and governance cannot safely mutate a Python
   global at all. `COOLDOWN_STREAM_ACTIVE` is not a precedent: it is a
   compile-time constant that ships flipped or not.
"""
import copy

import pytest

import tau_defs
from consensus.approvals import STATUS_FAILED, ApprovalRequest
from consensus.governance import (
    DEFAULT_ELIGIBILITY_MODE,
    DEFAULT_FEE_BENEFICIARY,
    DEFAULT_MAX_RULE_TXS_PER_BLOCK,
    ConsensusLifecycleManager,
    build_mechanism_metadata,
    validate_approval_slots_active,
)
from consensus.state import compute_consensus_meta_hash

A = "1a" * 48
B = "2b" * 48
AUTH = "aa" * 48


def _legacy_meta_hash(lm):
    """The pre-feature preimage, hand-rolled."""
    mech = {"vote_quorum": lm.effective_quorum_policy()}
    if lm.effective_eligibility_mode() != DEFAULT_ELIGIBILITY_MODE:
        mech["eligibility_mode"] = lm.effective_eligibility_mode()
    if lm.effective_fee_beneficiary() != DEFAULT_FEE_BENEFICIARY:
        mech["fee_beneficiary"] = lm.effective_fee_beneficiary()
    if lm.max_rule_txs_per_block != DEFAULT_MAX_RULE_TXS_PER_BLOCK:
        mech["max_rule_txs_per_block"] = lm.max_rule_txs_per_block
    vote_records = [(u, v) for u, voters in lm.votes.items() for v in voters]
    return compute_consensus_meta_hash(
        host_contract={},
        active_validators=list(lm.active_validators),
        pending_updates=list(lm.pending_updates),
        vote_records=vote_records,
        activation_schedule=lm.scheduled_updates,
        checkpoint_references=[],
        mechanism_specific_metadata=mech,
    )


def _request(seq=1, amount=5000):
    return ApprovalRequest(sender_pubkey=A, recipient_pubkey=B, amount=amount,
                           sequence_number=seq, expire_at_height=900,
                           approvers={18: AUTH}, custom_inputs={})


@pytest.mark.parametrize("mode", ["", "validator_set", "stake", "tau_validator_set"])
@pytest.mark.parametrize("validators", [[], [A]])
def test_untouched_feature_preserves_the_legacy_meta_hash(mode, validators):
    lm = ConsensusLifecycleManager(active_validators=validators or None)
    lm.eligibility_mode = mode
    assert lm.approval_slots_active is False
    assert lm.approval_requests.is_empty()
    assert lm.consensus_meta_hash() == _legacy_meta_hash(lm)


def test_gen_genesis_shaped_call_is_unaffected():
    """gen_genesis calls the builder without the new arguments, so block 0 stays
    byte-identical."""
    assert build_mechanism_metadata("supermajority") == {"vote_quorum": "supermajority"}


def test_activation_changes_the_hash_and_is_idempotent():
    lm = ConsensusLifecycleManager(active_validators=[A])
    base = lm.consensus_meta_hash()
    lm.activate_approval_slots()
    activated = lm.consensus_meta_hash()
    assert activated != base
    assert activated != _legacy_meta_hash(lm)
    lm.activate_approval_slots()
    assert lm.consensus_meta_hash() == activated


def test_first_request_changes_the_hash_again():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.activate_approval_slots()
    activated = lm.consensus_meta_hash()
    lm.approval_requests.submit_request(_request())
    assert lm.consensus_meta_hash() != activated


def test_recording_a_vote_changes_the_hash():
    """Votes decide whether the parked transfer executes, so they must be bound."""
    from consensus.approvals import TransferVote

    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.activate_approval_slots()
    req = _request()
    lm.approval_requests.submit_request(req)
    before = lm.consensus_meta_hash()
    lm.approval_requests.commit_vote(
        TransferVote(request_id=req.request_id, voter_pubkey=AUTH, approve=True))
    assert lm.consensus_meta_hash() != before


def test_resolving_never_reverts_to_the_activated_hash():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.activate_approval_slots()
    activated = lm.consensus_meta_hash()
    req = _request()
    lm.approval_requests.submit_request(req)
    lm.approval_requests.resolve(req.request_id, STATUS_FAILED)
    assert lm.approval_requests.open_requests == {}
    assert lm.consensus_meta_hash() != activated


# --- the one-way property ----------------------------------------------------

@pytest.mark.parametrize("value", [False, None, 0, 1, "true", "", []])
def test_only_true_is_a_legal_patch_value(value):
    assert validate_approval_slots_active(value) is not None


def test_true_is_accepted():
    assert validate_approval_slots_active(True) is None


def test_patch_activates_and_refuses_to_deactivate():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.apply_host_contract_patch({"approval_slots_active": True})
    assert lm.approval_slots_active is True
    with pytest.raises(ValueError, match="cannot be deactivated"):
        lm.apply_host_contract_patch({"approval_slots_active": False})
    assert lm.approval_slots_active is True, "a refused downgrade must change nothing"


def test_the_key_is_governance_patchable():
    """Miss this and the knob is unreachable forever: unknown keys are rejected
    at admission."""
    from consensus.governance import HOST_CONTRACT_PATCH_KEYS

    assert "approval_slots_active" in HOST_CONTRACT_PATCH_KEYS


# --- isolation across candidate blocks ---------------------------------------

def test_deepcopy_isolates_activation_and_the_book():
    """The reason this is a manager field and not a module global."""
    parent = ConsensusLifecycleManager(active_validators=[A])
    parent_hash = parent.consensus_meta_hash()

    candidate = copy.deepcopy(parent)
    candidate.activate_approval_slots()
    candidate.approval_requests.submit_request(_request())

    assert parent.approval_slots_active is False
    assert parent.approval_requests.is_empty()
    assert parent.consensus_meta_hash() == parent_hash
    assert candidate.consensus_meta_hash() != parent_hash


def test_two_candidates_do_not_see_each_other():
    parent = ConsensusLifecycleManager(active_validators=[A])
    one = copy.deepcopy(parent)
    two = copy.deepcopy(parent)
    one.approval_requests.submit_request(_request(seq=1))
    two.approval_requests.submit_request(_request(seq=2))
    assert set(one.approval_requests.open_requests) != set(two.approval_requests.open_requests)
    assert len(one.approval_requests.open_requests) == 1
    assert len(two.approval_requests.open_requests) == 1


# --- the reserved-stream split ----------------------------------------------

def test_slots_are_write_reserved_only_when_active():
    assert 18 not in tau_defs.reserved_operation_keys("")
    active = tau_defs.reserved_operation_keys("", approval_slots_active=True)
    for slot in tau_defs.approval_slot_indices():
        assert slot in active


def test_inactive_reserved_set_is_unchanged():
    """Behaviour-identical before activation, including the legacy positional
    call every existing ingest site uses."""
    for mode in ("", "validator_set", "stake", "tau_validator_set"):
        assert (tau_defs.reserved_operation_keys(mode)
                == tau_defs.reserved_operation_keys(mode, approval_slots_active=False))


def test_a_clause_may_read_slots_but_a_user_rule_may_not():
    """Reserving the slots must not reject the very rule the feature exists for.
    Writing them as an operation stays forbidden everywhere."""
    user = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_USER, "tau_validator_set", approval_slots_active=True)
    clause = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE, "tau_validator_set", approval_slots_active=True)
    consensus_rev = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_CONSENSUS, "tau_validator_set", approval_slots_active=True)

    assert "i18" in user and "i25" in user
    assert "i18" not in clause and "i25" not in clause
    assert "i18" in consensus_rev, "consensus revisions may never type a slot"
    # i12 stays readable everywhere: that is how a policy rule scopes itself.
    assert "i12" not in user and "i12" not in clause


def test_request_custom_inputs_start_above_the_slot_block():
    assert tau_defs.REQUEST_CUSTOM_INPUT_MIN == max(tau_defs.approval_slot_indices()) + 1


# --- the activation audit ----------------------------------------------------
#
# Reserving i18..i25 and routing o5 rules are consensus-visible changes, and a
# source grep proves nothing about a LIVE chain: before activation the slots were
# ordinary custom streams any rule could type at any width, and o5 rules were
# appended raw. Both collisions are fatal, so the audit reports rather than
# tolerates.

from consensus.approvals import audit_stream_collisions

_CLEAN = [
    ("consensus_rules", "always ( o6[t]:bv[16] = i10[t]:bv[16] )."),
    ("builtin_rule_0", "always ( o1[t]:bv[24] = i1[t]:bv[24] )."),
    ("application_rules", "always ( o12[t]:bv[24] = i1[t]:bv[24] )."),
]


def test_a_clean_spec_passes_the_audit():
    assert audit_stream_collisions(_CLEAN) == []


@pytest.mark.parametrize("label", ["consensus_rules", "application_rules", "builtin_rule_7",
                                   "clause_aaaaaaaaaa_o5"])
def test_a_slot_already_typed_anywhere_blocks_activation(label):
    """Auditing the application rules alone would miss a collision hiding in a
    consensus revision, a builtin, or a stored clause body."""
    texts = _CLEAN + [(label, "always ( (i18[t]:bv[24] = { #x01 }:bv[24]) -> "
                              "(o13[t]:bv[24] = { #x01 }:bv[24]) ).")]
    findings = audit_stream_collisions(texts)
    assert len(findings) == 1
    assert label in findings[0] and "i18" in findings[0]


@pytest.mark.parametrize("slot", [18, 25])
def test_every_slot_in_the_block_is_audited(slot):
    texts = [("application_rules", "always ( (i%d[t]:bv[64] = { 1 }:bv[64]) -> "
                                   "(o13[t]:bv[24] = { #x01 }:bv[24]) )." % slot)]
    assert audit_stream_collisions(texts) != []


def test_a_neighbouring_stream_is_not_a_false_positive():
    """Word-boundary matched, so i1/i17/i180 are not mistaken for a slot."""
    for stream in ("i1", "i17", "i26", "i180"):
        texts = [("application_rules", "always ( (%s[t]:bv[24] = { #x01 }:bv[24]) -> "
                                       "(o13[t]:bv[24] = { #x01 }:bv[24]) )." % stream)]
        assert audit_stream_collisions(texts) == [], stream


def test_a_slot_named_only_in_a_comment_is_not_a_collision():
    texts = [("application_rules", "# i18 is the auth slot\n"
                                   "always ( o12[t]:bv[24] = i1[t]:bv[24] ).")]
    assert audit_stream_collisions(texts) == []


def test_a_legacy_raw_o5_writer_blocks_activation():
    """The first derived composite would be a second total-form unit on o5
    beside it, and two of those either fail to conjoin or supersede each other."""
    texts = [("application_rules",
              "always ( (i12[t]:bv[384] = { #x" + A + " }:bv[384]) -> "
              "(o5[t]:bv[24] = { #x000000 }:bv[24]) ).")]
    findings = audit_stream_collisions(texts)
    assert len(findings) == 1 and "raw o5 policy rule" in findings[0]


def test_a_clause_body_writing_o5_is_not_a_legacy_writer():
    """Only the raw accumulation can hold one: a registered clause is fed with
    apply_rules_update=False and never enters it."""
    texts = [("clause_aaaaaaaaaa_o5", "(o5[t]:bv[24] = { #x000000 }:bv[24])")]
    assert audit_stream_collisions(texts) == []


# --- phase 2: a refused activation must not halt the chain -------------------

def test_a_collision_leaves_the_flag_false_without_raising():
    """Raising at the activation height would invalidate every block from there
    on and freeze the chain permanently, so the second phase can only decline."""
    lm = ConsensusLifecycleManager(active_validators=[A])
    colliding = [("application_rules",
                  "always ( (i18[t]:bv[24] = { #x01 }:bv[24]) -> "
                  "(o13[t]:bv[24] = { #x01 }:bv[24]) ).")]
    lm.apply_host_contract_patch({"approval_slots_active": True},
                                 effective_spec_texts=colliding)
    assert lm.approval_slots_active is False


def test_a_clean_spec_activates_at_the_height():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.apply_host_contract_patch({"approval_slots_active": True},
                                 effective_spec_texts=_CLEAN)
    assert lm.approval_slots_active is True


def test_the_audit_verdict_is_deterministic_across_nodes():
    """No extra hash key is needed to make a refused activation agree: the audit
    reads only hash-bound state, so every node computes the same findings and the
    flag -- which IS hash-bound -- stays False on all of them."""
    colliding = [("consensus_rules",
                  "always ( (i19[t]:bv[64] = { 1 }:bv[64]) -> (o6[t]:bv[16] = { 1 }:bv[16]) ).")]
    node_a = ConsensusLifecycleManager(active_validators=[A])
    node_b = ConsensusLifecycleManager(active_validators=[A])
    for lm in (node_a, node_b):
        lm.apply_host_contract_patch({"approval_slots_active": True},
                                     effective_spec_texts=colliding)
    assert node_a.approval_slots_active is node_b.approval_slots_active is False
    assert node_a.consensus_meta_hash() == node_b.consensus_meta_hash()


# --- a fresh chain can ship with it on ---------------------------------------

def test_genesis_metadata_omits_the_flag_by_default():
    """A genesis generated without --approval-slots stays byte-identical."""
    assert "approval_slots_active" not in build_mechanism_metadata("supermajority")


def test_genesis_metadata_carries_the_flag_when_asked():
    mech = build_mechanism_metadata("supermajority", approval_slots_active=True)
    assert mech["approval_slots_active"] is True


# --- phase 1: the proposal is refused at admission --------------------------
#
# This is the ONLY place a collision can be reported loudly. At the activation
# height the second phase can merely decline, so an operator who never sees this
# error would just watch the flag silently fail to flip.

def test_the_proposal_is_refused_when_the_tip_spec_collides(temp_database):
    import chain_state
    from consensus.admission import _check_host_contract_patch

    chain_state._consensus_rules_state = "always ( o6[t]:bv[16] = i10[t]:bv[16] )."
    chain_state._application_rules_state = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
    assert _check_host_contract_patch({"approval_slots_active": True}) is None

    chain_state._application_rules_state = (
        "always ( (i18[t]:bv[24] = { #x01 }:bv[24]) -> "
        "(o13[t]:bv[24] = { #x01 }:bv[24]) )."
    )
    err = _check_host_contract_patch({"approval_slots_active": True})
    assert err is not None and "cannot be activated on this chain" in err
    assert "application_rules" in err


def test_the_proposal_audit_reads_consensus_rules_not_the_accumulation(temp_database):
    """chain_state.get_rules_state() returns the APPLICATION accumulation (it
    prefers `app` because `u` state retention makes that a whole restoreable
    spec). Using it here audited the application rules twice and never looked at
    a consensus revision at all."""
    import chain_state
    from consensus.admission import _tip_effective_spec_texts, _check_host_contract_patch

    chain_state._application_rules_state = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
    chain_state._consensus_rules_state = (
        "always ( (i19[t]:bv[64] = { 1 }:bv[64]) -> (o6[t]:bv[16] = { 1 }:bv[16]) )."
    )
    labels = [label for label, _ in _tip_effective_spec_texts()]
    assert labels[:2] == ["consensus_rules", "application_rules"]
    corpus = dict(_tip_effective_spec_texts())
    assert corpus["consensus_rules"] != corpus["application_rules"]

    err = _check_host_contract_patch({"approval_slots_active": True})
    assert err is not None and "consensus_rules" in err


def test_deactivation_is_refused_at_admission(temp_database):
    from consensus.admission import _check_host_contract_patch

    err = _check_host_contract_patch({"approval_slots_active": False})
    assert err is not None and "cannot be deactivated" in err
