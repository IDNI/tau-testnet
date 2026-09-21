"""The guard exists because "try not to call those paths" is not a boundary.

A convenience fallback is by definition what happens when nobody was thinking
about it, so proposal execution is made INCAPABLE of reaching committed state
rather than merely discouraged from it.
"""
import pytest

import tau_guard


def test_a_committed_write_is_refused():
    import chain_state
    with tau_guard.ProposalIsolationGuard() as guard:
        with pytest.raises(tau_guard.GlobalStateLeak):
            chain_state.save_effective_tau_spec("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).")
    assert "chain_state.save_effective_tau_spec" in guard.calls()


def test_a_mutable_canonical_read_is_refused():
    """A proposal built from parent H that reads canonical state directly stops
    representing H the moment anything else changes it."""
    import chain_state
    with tau_guard.ProposalIsolationGuard() as guard:
        with pytest.raises(tau_guard.GlobalStateLeak):
            chain_state.get_application_rules_state()
    assert guard.violations[0]["kind"] == "read"


def test_the_authoritative_evaluator_is_refused():
    import tau_manager
    with tau_guard.ProposalIsolationGuard():
        with pytest.raises(tau_guard.GlobalStateLeak):
            tau_manager.communicate_with_tau(rule_text="R")


def test_the_committed_allocator_is_refused():
    import db
    with tau_guard.ProposalIsolationGuard():
        with pytest.raises(tau_guard.GlobalStateLeak):
            db.get_shrink_id("bv384:whatever")


def test_originals_are_restored_on_exit():
    import chain_state
    before = chain_state.save_effective_tau_spec
    with tau_guard.ProposalIsolationGuard():
        assert chain_state.save_effective_tau_spec is not before
    assert chain_state.save_effective_tau_spec is before


def test_a_recording_guard_reports_instead_of_raising():
    import chain_state
    with tau_guard.ProposalIsolationGuard(strict=False) as guard:
        try:
            chain_state.get_application_rules_state()
        except Exception:
            pass
    with pytest.raises(AssertionError):
        guard.assert_clean()


def test_an_explicit_allowance_is_respected():
    """Migration happens family by family; a section not yet moved can be named
    rather than silently tolerated."""
    import chain_state
    with tau_guard.ProposalIsolationGuard(
            allow={"chain_state.get_application_rules_state"}) as guard:
        chain_state.get_application_rules_state()
    guard.assert_clean()
