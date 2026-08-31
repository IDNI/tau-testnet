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
