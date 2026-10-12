"""Header verification when the in-process interpreter is not up.

Worker-backed authority starts before the interpreter does, so a journal
migration verifies headers while `tau_ready` is still unset. Verification must
then answer from the advisory evaluator, and must refuse at once -- not wait on
an interpreter that is not coming -- when that evaluator gives no answer.
"""
import time
from unittest.mock import MagicMock, patch

import pytest

import tau_authority
import tau_manager
from block import Block
from consensus import engine as ce
from consensus.engine import ActiveConsensusView, TauConsensusEngine

A = "aa" * 48


def _view(mode):
    return ActiveConsensusView(
        target_height=10,
        consensus_rules="always ( o6[t]:bv[16] = i10[t]:bv[16] ).",
        active_validators=[bytes.fromhex(A)],
        mechanism_specific_metadata={"poa": True, "eligibility_mode": mode},
    )


def _block():
    blk = Block.create(block_number=10, previous_hash="00" * 32, transactions=[],
                       proposer_pubkey=A, timestamp=1234567890)
    blk.consensus_proof = {"scheme": "bls_header_sig", "signature": "ab" * 48}
    return blk


def _not_ready():
    ready = MagicMock()
    ready.is_set.return_value = False
    return ready


def _verify(mode, advisory_answer, *, enabled=True):
    owner = MagicMock()
    owner.enabled = enabled
    evaluator = MagicMock()
    evaluator.evaluate_consensus.return_value = advisory_answer
    forbidden = MagicMock(side_effect=AssertionError("fell back to the interpreter"))
    with patch.object(tau_manager, "tau_ready", _not_ready()), \
         patch.object(tau_manager, "tau_test_mode", False), \
         patch.object(tau_manager, "communicate_with_tau_multi", forbidden), \
         patch.object(tau_manager, "communicate_with_tau", forbidden), \
         patch.object(tau_authority, "owner", return_value=owner), \
         patch.object(ce.tau_advisory, "evaluator", return_value=evaluator), \
         patch.object(TauConsensusEngine, "_view_eligibility_mode",
                      staticmethod(lambda v: mode)), \
         patch("consensus.engine.normalize_validator_set", return_value={A}):
        started = time.monotonic()
        verdict = TauConsensusEngine().verify_block_header(
            _view(mode), _block(), {"proof_ok": True})
        return verdict, time.monotonic() - started


@pytest.mark.parametrize("mode", ["validator_set", "tau_validator_set"])
def test_no_advisory_answer_and_no_interpreter_refuses_at_once(mode):
    verdict, elapsed = _verify(mode, None)
    assert verdict is False
    assert elapsed < 5


@pytest.mark.parametrize("mode,answer", [
    ("validator_set", {6: "1"}),
    ("tau_validator_set", {6: "1", 7: "1"}),
])
def test_the_advisory_answer_decides_while_the_interpreter_is_down(mode, answer):
    assert _verify(mode, answer)[0] is True


def test_an_advisory_rejection_is_final():
    assert _verify("validator_set", {6: "0"})[0] is False


def test_without_authority_or_native_interface_the_interpreter_is_still_required():
    with patch.object(tau_manager, "tau_ready", _not_ready()), \
         patch.object(tau_manager, "tau_test_mode", False), \
         patch.object(tau_manager, "tau_direct_interface", None), \
         patch.object(tau_authority, "owner", return_value=MagicMock(enabled=False)), \
         patch.object(TauConsensusEngine, "_view_eligibility_mode",
                      staticmethod(lambda v: "validator_set")), \
         patch("consensus.engine.normalize_validator_set", return_value={A}):
        assert TauConsensusEngine().verify_block_header(
            _view("validator_set"), _block(), {"proof_ok": True}) is False


def test_worker_backed_authority_makes_the_advisory_evaluator_available():
    owner = MagicMock(enabled=True)
    with patch.object(tau_authority, "owner", return_value=owner), \
         patch.object(tau_manager, "tau_direct_interface", None), \
         patch.object(tau_manager, "tau_test_mode", False):
        assert ce._advisory_is_available() is True
    with patch.object(tau_authority, "owner", return_value=owner), \
         patch.object(tau_manager, "tau_test_mode", True):
        assert ce._advisory_is_available() is False
