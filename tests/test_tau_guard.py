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


# --- nesting ------------------------------------------------------------------

def test_a_lax_outer_guard_cannot_relax_a_strict_inner_one():
    """Proposal mode installs its own strict guard.

    A caller that wraps it in a recording guard -- to collect violations rather
    than raise -- must not thereby turn the proposal's integration failure into
    a logged warning. The strictest ACTIVE guard decides.
    """
    import chain_state
    outer = tau_guard.ProposalIsolationGuard(strict=False)
    with outer:
        with tau_guard.ProposalIsolationGuard(strict=True):
            with pytest.raises(tau_guard.GlobalStateLeak):
                chain_state.save_application_rules_state("x")


def test_a_strict_outer_guard_still_sees_calls_under_a_lax_inner_one():
    import chain_state
    with pytest.raises(tau_guard.GlobalStateLeak):
        with tau_guard.ProposalIsolationGuard(strict=True):
            with tau_guard.ProposalIsolationGuard(strict=False):
                chain_state.save_application_rules_state("x")


def test_an_inner_guard_exit_does_not_untrap_the_outer_one():
    """The failure this prevents is silent: the inner __exit__ restores the
    module attribute, and everything after it inside the outer guard runs
    unwatched."""
    import chain_state
    outer = tau_guard.ProposalIsolationGuard(strict=False)
    with outer:
        with tau_guard.ProposalIsolationGuard(strict=False):
            pass
        chain_state.save_application_rules_state("x")
    assert "chain_state.save_application_rules_state" in outer.calls()


def test_every_active_guard_records_the_same_call():
    import chain_state
    outer = tau_guard.ProposalIsolationGuard(strict=False)
    inner = tau_guard.ProposalIsolationGuard(strict=False)
    with outer, inner:
        chain_state.save_application_rules_state("x")
    assert outer.calls() == inner.calls() == ["chain_state.save_application_rules_state"]


def test_originals_are_restored_after_the_outermost_exit():
    import chain_state
    original = chain_state.save_application_rules_state
    with tau_guard.ProposalIsolationGuard(strict=False):
        with tau_guard.ProposalIsolationGuard(strict=False):
            pass
        assert chain_state.save_application_rules_state is not original
    assert chain_state.save_application_rules_state is original


def test_another_thread_reading_committed_state_is_not_a_leak():
    """While a block executes, the node keeps serving RPC and gossip on other
    threads. A `sendtx` admission reading a live balance there is not the
    proposal reaching past its snapshot, and must not be refused."""
    import threading
    import chain_state
    outcome = {}

    def admission():
        try:
            chain_state.get_balance("00" * 48)
            outcome["ok"] = True
        except BaseException as exc:  # GlobalStateLeak is a BaseException
            outcome["exc"] = exc

    with tau_guard.ProposalIsolationGuard() as guard:
        worker = threading.Thread(target=admission)
        worker.start()
        worker.join()
        assert outcome == {"ok": True}
        assert guard.violations == []
        with pytest.raises(tau_guard.GlobalStateLeak):
            chain_state.get_balance("00" * 48)
