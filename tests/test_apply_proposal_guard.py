"""The isolation guard is proposal mode's, not the caller's.

Whether a speculative block can reach committed state must not depend on the
call site remembering to wrap it. `apply(proposal=...)` installs a strict guard
itself, and a violation aborts the proposal as an integration failure -- never as
a verdict about whichever transaction happened to be executing.
"""
from unittest.mock import MagicMock, patch

import pytest

import tau_allocator as alloc
import tau_guard
import tau_journal as tj
import tau_proposal
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot

SENDER = "aa" * 48
PROPOSER = "bb" * 48
RULE = "always ( o5[t]:bv[24] = { #x000002 }:bv[24] )."


def _proposal(session):
    plan = tr.plan_representation(candidate_rules=[RULE])
    snapshot = alloc.DbMappingSnapshot()
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan,
        lifecycle=MagicMock(approval_slots_active=False),
    )


def _tx():
    return {"tx_id": "r1", "tx_type": "user_tx", "sender_pubkey": SENDER,
            "sequence_number": 0, "fee_limit": "100",
            "operations": {"0": RULE}}


def _apply(session, proposal):
    engine = TauConsensusEngine(state_store=MagicMock())
    return engine.apply(
        TauStateSnapshot(b"hash", b"rules", {}),
        [_tx()], 1700000000,
        target_balances={SENDER: 1000},
        target_sequences={},
        target_lifecycle=proposal.lifecycle,
        proposer_pubkey=PROPOSER,
        block_height=1,
        proposal=proposal,
        session=session,
    )


def test_a_proposal_driving_the_authoritative_evaluator_is_refused(temp_database):
    """The mistake this catches is a plausible one: handing proposal mode the
    live in-process session, which steps the node's own interpreter for a block
    that may never commit. No caller-side guard is involved."""
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", return_value="ok") as live, \
         patch("tau_manager.get_last_revision_receipt", return_value=None):
        ready.is_set.return_value = True
        session = ts.InProcessSession()
        proposal = _proposal(session)
        with pytest.raises(tau_guard.GlobalStateLeak) as excinfo:
            _apply(session, proposal)
    assert "tau_manager.communicate_with_tau" in str(excinfo.value)
    assert live.call_count == 0, "the authoritative evaluator was stepped anyway"
    # Aborted, not rejected: the proposal is unusable, and the transaction was
    # never given a verdict of its own.
    assert proposal.poisoned, "the breach left the proposal usable"
    assert "isolation breach" in proposal.poisoned


def test_a_leak_is_not_reported_as_an_invalid_transaction(temp_database):
    """The failure mode this pins was real: routed through `Exception`, the
    breach was swallowed by the rule handler's broad catch and came back as
    `rule_not_applied` -- blaming a transaction that was perfectly valid for a
    defect in the node."""
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", return_value="ok"), \
         patch("tau_manager.get_last_revision_receipt", return_value=None):
        ready.is_set.return_value = True
        session = ts.InProcessSession()
        proposal = _proposal(session)
        with pytest.raises(tau_guard.GlobalStateLeak):
            _apply(session, proposal)


def test_the_leak_survives_a_broad_except_clause():
    """Directly: an `except Exception` must not be able to absorb it."""
    import chain_state
    with tau_guard.ProposalIsolationGuard(strict=True):
        with pytest.raises(tau_guard.GlobalStateLeak):
            try:
                chain_state.save_application_rules_state("x")
            except Exception:  # noqa: BLE001 - the point of the test
                pytest.fail("a broad catch absorbed the isolation breach")


def test_the_guard_is_gone_once_apply_returns(temp_database):
    """A guard that leaked out of apply would trap the node's own committed
    writes for the rest of the process."""
    import chain_state
    original = chain_state.save_application_rules_state
    session = MagicMock()
    session.ready.return_value = False
    session.is_speculative = True
    proposal = _proposal(session)
    _apply(session, proposal)
    assert chain_state.save_application_rules_state is original


def test_non_proposal_apply_installs_no_guard(temp_database):
    """The authoritative path legitimately writes committed state; guarding it
    would break the node, so the guard must be proposal-scoped."""
    import chain_state
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    seen = []
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", side_effect=lambda **k: seen.append(k) or "ok"), \
         patch("tau_manager.communicate_with_tau_multi", return_value={9: "0"}), \
         patch("tau_manager.get_last_revision_receipt", return_value=None), \
         patch("chain_state.get_application_rules_state", return_value=RULE):
        ready.is_set.return_value = True
        engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [_tx()], 1700000000,
            target_balances={SENDER: 1000},
            target_sequences={},
            target_lifecycle=MagicMock(approval_slots_active=False),
            proposer_pubkey=PROPOSER,
            block_height=1,
        )
    assert seen, "the authoritative path was not allowed to reach the evaluator"


# --- the terminal boundary ----------------------------------------------------

def test_the_boundary_converts_a_leak_into_a_typed_operational_failure():
    """GlobalStateLeak bypasses `except Exception` on purpose, which means
    nothing between the breach and the proposal's owner will stop it. Left
    unbounded it unwinds the node over a node-local integration failure, the way
    KeyboardInterrupt would."""
    import chain_state
    from errors import ProposalIsolationFailure

    proposal = MagicMock()
    proposal.poisoned = None
    with pytest.raises(ProposalIsolationFailure) as excinfo:
        with tau_proposal.boundary(proposal, label="test"):
            with tau_guard.ProposalIsolationGuard(strict=True):
                chain_state.save_application_rules_state("x")

    assert "chain_state.save_application_rules_state" in str(excinfo.value)
    proposal.poison.assert_called_once()
    assert "isolation breach" in proposal.poison.call_args[0][0]


def test_the_typed_failure_is_an_ordinary_exception():
    """So a caller's existing error handling can report it, which is the whole
    point of converting it here rather than letting the BaseException run."""
    from errors import ProposalIsolationFailure, TauTestnetError

    assert issubclass(ProposalIsolationFailure, Exception)
    assert issubclass(ProposalIsolationFailure, TauTestnetError)
    assert not issubclass(tau_guard.GlobalStateLeak, Exception)


def test_cleanup_runs_before_the_failure_leaves_the_owner():
    """A `finally` inside the wrapped block completes first, so the worker is
    disposed whether or not the block leaked."""
    import chain_state
    from errors import ProposalIsolationFailure

    disposed = []
    proposal = MagicMock()
    proposal.poisoned = None
    proposal.dispose.side_effect = lambda: disposed.append(True)

    with pytest.raises(ProposalIsolationFailure):
        with tau_proposal.boundary(proposal, label="test"):
            try:
                with tau_guard.ProposalIsolationGuard(strict=True):
                    chain_state.save_application_rules_state("x")
            finally:
                proposal.dispose()
    assert disposed == [True], "the proposal was not disposed before the failure surfaced"


def test_an_already_poisoned_proposal_keeps_its_first_reason():
    """The first breach is the one that explains what happened."""
    import chain_state
    from errors import ProposalIsolationFailure

    proposal = MagicMock()
    proposal.poisoned = "the original reason"
    with pytest.raises(ProposalIsolationFailure):
        with tau_proposal.boundary(proposal, label="test"):
            with tau_guard.ProposalIsolationGuard(strict=True):
                chain_state.save_application_rules_state("x")
    proposal.poison.assert_not_called()
