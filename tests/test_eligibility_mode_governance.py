"""Phase 1: eligibility_mode field wiring (grammar, patch, hash-compat, admission).

The field's EFFECT on block verification is Phase 3; this only exercises the
field plumbing, mirroring the vote_quorum precedent.
"""
import pytest

from consensus.governance import (
    ConsensusLifecycleManager,
    validate_eligibility_mode,
    DEFAULT_ELIGIBILITY_MODE,
)


def test_validate_eligibility_mode_grammar():
    assert validate_eligibility_mode("validator_set") is None
    assert validate_eligibility_mode("stake") is None
    # Empty string is only the internal "genesis did not pin" sentinel.
    assert validate_eligibility_mode("") is not None
    assert validate_eligibility_mode("pos") is not None
    assert validate_eligibility_mode(7) is not None


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
