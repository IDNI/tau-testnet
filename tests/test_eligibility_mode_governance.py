"""Phase 1: eligibility_mode field wiring (grammar, patch, hash-compat, admission).

The field's EFFECT on block verification is Phase 3; this only exercises the
field plumbing, mirroring the vote_quorum precedent.
"""
import pytest

from consensus.governance import (
    ConsensusLifecycleManager,
    validate_eligibility_mode,
    is_tau_authoritative_eligibility_mode,
    DEFAULT_ELIGIBILITY_MODE,
)


def test_validate_eligibility_mode_grammar():
    assert validate_eligibility_mode("validator_set") is None
    assert validate_eligibility_mode("stake") is None
    assert validate_eligibility_mode("tau_validator_set") is None
    # Empty string is only the internal "genesis did not pin" sentinel.
    assert validate_eligibility_mode("") is not None
    assert validate_eligibility_mode("pos") is not None
    assert validate_eligibility_mode(7) is not None


def test_tau_authoritative_modes():
    """Modes where Tau's o7 binds proposer eligibility and the host membership
    gate is bypassed. validator_set (PoA) must stay host-gated: grouping it here
    would let any proposer past the gate, since its rule pins o7=1 for everyone."""
    assert is_tau_authoritative_eligibility_mode("stake") is True
    assert is_tau_authoritative_eligibility_mode("tau_validator_set") is True
    assert is_tau_authoritative_eligibility_mode("validator_set") is False
    assert is_tau_authoritative_eligibility_mode("") is False
    assert is_tau_authoritative_eligibility_mode(None) is False


def test_apply_host_contract_patch_sets_mode():
    lm = ConsensusLifecycleManager(active_validators=["a" * 96])
    lm.apply_host_contract_patch({"eligibility_mode": "stake"})
    assert lm.eligibility_mode == "stake"


def test_apply_host_contract_patch_rejects_bogus_mode():
    lm = ConsensusLifecycleManager(active_validators=["a" * 96])
    with pytest.raises(ValueError):
        lm.apply_host_contract_patch({"eligibility_mode": "bogus"})


def test_effective_eligibility_mode_defaults_when_unset():
    lm = ConsensusLifecycleManager(active_validators=["a" * 96])
    assert lm.eligibility_mode == ""
    assert lm.effective_eligibility_mode() == DEFAULT_ELIGIBILITY_MODE == "validator_set"


def test_meta_hash_compat_default_unchanged_stake_differs():
    validators = ["a" * 96, "b" * 96, "c" * 96]

    # A manager with the unset sentinel and one explicitly pinned to the default
    # both resolve to the default, so eligibility_mode is OMITTED from the hashed
    # metadata -> byte-identical hash to a pre-eligibility_mode chain state.
    lm_unset = ConsensusLifecycleManager(active_validators=validators)
    lm_default = ConsensusLifecycleManager(active_validators=validators)
    lm_default.eligibility_mode = "validator_set"
    assert lm_unset.consensus_meta_hash() == lm_default.consensus_meta_hash()

    # Switching to stake includes the key -> the meta hash MUST change.
    lm_stake = ConsensusLifecycleManager(active_validators=validators)
    lm_stake.eligibility_mode = "stake"
    assert lm_stake.consensus_meta_hash() != lm_unset.consensus_meta_hash()


def test_check_host_contract_patch_admission():
    from consensus.admission import _check_host_contract_patch
    validators = ["a" * 96, "b" * 96, "c" * 96]
    assert _check_host_contract_patch({"eligibility_mode": "stake"}, validators) is None
    err = _check_host_contract_patch({"eligibility_mode": "pos"}, validators)
    assert err is not None and "eligibility_mode" in err


def test_pending_update_with_mode_patch_survives_reload(temp_database):
    """A PENDING update whose host_contract_patch carries eligibility_mode is
    persisted and reloaded with the patch dict intact (db already stores
    arbitrary patch dicts as JSON — this only asserts it)."""
    import chain_state
    from consensus.governance import ConsensusRuleUpdate, ConsensusRuleVote

    validators = ["a" * 96, "b" * 96, "c" * 96]  # threshold 2 -> 1 vote stays pending
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm = ConsensusLifecycleManager(active_validators=validators)
    chain_state._lifecycle_manager = lm

    update = ConsensusRuleUpdate(
        ["always ( o6[t]:bv[16] = i10[t]:bv[16] )."], 50,
        host_contract_patch={"eligibility_mode": "stake"},
    )
    assert lm.submit_update(update)
    assert lm.submit_vote(ConsensusRuleVote(update.update_id, True), validators[0])
    assert update.update_id in lm.pending_updates  # 1 of 2: still pending

    chain_state.commit_state_to_db("head-hash", 9)
    chain_state._lifecycle_manager = ConsensusLifecycleManager()

    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager
    assert update.update_id in reloaded.pending_updates
    payload = reloaded.update_payloads[update.update_id]
    assert payload.host_contract_patch == {"eligibility_mode": "stake"}


class TestFeeBeneficiary:
    """Issue #25: the o9 levy can be routed to a named account by governance.

    The credit site was hard-wired to block.header.proposer_pubkey, so a proposal
    of the shape "N AGRS of every transfer goes to <address>" could not be
    authored at all -- the percentage half is #19, this is the routing half.
    """

    def _mgr(self):
        from consensus.governance import ConsensusLifecycleManager
        return ConsensusLifecycleManager(active_validators=["a" * 96, "b" * 96, "c" * 96])

    # --- grammar ---------------------------------------------------------
    def test_proposer_literal_is_valid_and_normalizes_to_empty(self):
        from consensus.governance import validate_fee_beneficiary, normalize_fee_beneficiary
        assert validate_fee_beneficiary("proposer") is None
        assert normalize_fee_beneficiary("proposer") == ""

    def test_pubkey_is_valid_and_kept_verbatim(self):
        from consensus.governance import validate_fee_beneficiary, normalize_fee_beneficiary
        pk = "ab" * 48
        assert validate_fee_beneficiary(pk) is None
        assert normalize_fee_beneficiary(pk) == pk

    def test_malformed_values_rejected(self):
        from consensus.governance import validate_fee_beneficiary
        for bad in ("", "0x" + "ab" * 47, "AB" * 48, "ab" * 47, "zz" * 48, 123, None):
            assert validate_fee_beneficiary(bad) is not None, f"{bad!r} wrongly accepted"

    def test_empty_string_rejected_as_an_authored_value(self):
        """"" is the internal 'not set' marker; authors say 'proposer'. Allowing
        both spellings would give one semantics two stored forms, and the value
        is bound into update_id and the meta hash."""
        from consensus.governance import validate_fee_beneficiary
        assert "proposer" in validate_fee_beneficiary("")

    # --- activation ------------------------------------------------------
    def test_patch_sets_and_normalizes(self):
        mgr = self._mgr()
        mgr.apply_host_contract_patch({"fee_beneficiary": "cd" * 48})
        assert mgr.effective_fee_beneficiary() == "cd" * 48
        mgr.apply_host_contract_patch({"fee_beneficiary": "proposer"})
        assert mgr.effective_fee_beneficiary() == ""

    def test_activation_validates_completely(self):
        """This raise is the only consensus-binding validation: admission runs on
        one path, block apply reaches activation without it."""
        import pytest
        mgr = self._mgr()
        with pytest.raises(ValueError, match="fee_beneficiary"):
            mgr.apply_host_contract_patch({"fee_beneficiary": "not-a-pubkey"})

    # --- hash compat -----------------------------------------------------
    def test_default_leaves_the_meta_hash_byte_identical(self):
        """The whole point of the non-default gate: a network that never sets a
        beneficiary must hash exactly as it did before this field existed."""
        mgr = self._mgr()
        before = mgr.consensus_meta_hash()
        mgr.apply_host_contract_patch({"fee_beneficiary": "proposer"})
        assert mgr.consensus_meta_hash() == before

    def test_non_default_changes_the_meta_hash(self):
        mgr = self._mgr()
        before = mgr.consensus_meta_hash()
        mgr.apply_host_contract_patch({"fee_beneficiary": "ef" * 48})
        assert mgr.consensus_meta_hash() != before

    def test_genesis_generator_and_runtime_build_identical_metadata(self):
        """gen_genesis and the runtime hash used to carry two copies of this
        conditional with a 'MUST match' comment; they now share one function, so
        block 0 cannot fail its own state-hash invariant on replay."""
        from consensus.governance import build_mechanism_metadata
        mgr = self._mgr()
        mgr.apply_host_contract_patch({"fee_beneficiary": "ab" * 48})
        assert build_mechanism_metadata(
            mgr.effective_quorum_policy(),
            mgr.effective_eligibility_mode(),
            mgr.effective_fee_beneficiary(),
        ) == {"vote_quorum": mgr.effective_quorum_policy(), "fee_beneficiary": "ab" * 48}

    def test_default_metadata_omits_the_field_entirely(self):
        from consensus.governance import build_mechanism_metadata
        assert build_mechanism_metadata("supermajority") == {"vote_quorum": "supermajority"}
