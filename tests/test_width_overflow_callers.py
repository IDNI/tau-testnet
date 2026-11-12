"""Each caller of the planner sends a ShrinkWidthOverflow to the re-exec.

A fallback or a plain stream at the wrong width is never a correct answer:
only a fresh process at a wider width is.
"""
import threading
from types import SimpleNamespace

import pytest

import tau_authority as auth
import tau_journal as tj
import tau_manager
import tau_reconstruction as tr
import tau_shrink as ts

RULE = "always ( i4[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384] )."


class _ReExec(BaseException):
    """Stands for os.execv, which never returns to the caller."""


@pytest.fixture
def overflow(monkeypatch):
    seen = []

    def _plan(**_kwargs):
        raise ts.ShrinkWidthOverflow("id 300 exceeds bv[8]")

    def _reexec(exc):
        seen.append(exc)
        raise _ReExec()

    monkeypatch.setattr(tr, "plan_representation", _plan)
    monkeypatch.setattr(tau_manager, "_handle_width_overflow", _reexec)
    return seen


def _assert_reexec(seen, call):
    with pytest.raises(_ReExec):
        call()
    assert len(seen) == 1 and isinstance(seen[0], ts.ShrinkWidthOverflow)


def test_the_context_manager_passes_other_errors(monkeypatch):
    monkeypatch.setattr(tau_manager, "_handle_width_overflow",
                        lambda exc: pytest.fail("not an overflow"))
    with pytest.raises(ValueError):
        with tau_manager.reexec_on_width_overflow():
            raise ValueError("other")


def test_createblock_does_not_fall_back_in_process(temp_database, overflow, monkeypatch):
    import chain_state
    import commands.createblock as createblock

    monkeypatch.setattr(auth, "owner", lambda: SimpleNamespace(enabled=False))
    monkeypatch.setattr(tau_manager, "tau_test_mode", False)
    monkeypatch.setattr(tau_manager, "tau_direct_interface", object())
    monkeypatch.setattr(chain_state, "get_tau_restore_plan", lambda *a, **k: [{"text": RULE}])
    monkeypatch.setattr(createblock, "_program_baseline", lambda: "always ( o0[t] = 0 ).")
    _assert_reexec(overflow, lambda: createblock._speculative_proposal([RULE]))


def test_admission_conflict_check(temp_database, overflow):
    import tau_admission

    plan = SimpleNamespace(interned=frozenset({4}))
    _assert_reexec(overflow, lambda: tau_admission._conflicts(plan, [RULE]))


def test_admission_plan(temp_database, overflow):
    import tau_admission

    _assert_reexec(overflow, lambda: tau_admission._plan_for({}, [], [RULE]))


def _owner(store=None, baseline="always ( o0[t] = 0 )."):
    return auth.AuthoritativeTauOwner(ready=threading.Event(), program_baseline=baseline,
                                      store=store)


def test_authority_committed_plan(temp_database, overflow):
    store = SimpleNamespace(latest_block_commit=lambda: None)
    owner = _owner(store)
    _assert_reexec(overflow, lambda: owner._committed_plan(store, tj.Journal()))


def test_authority_proposal(temp_database, overflow):
    store = SimpleNamespace(committed_journal_entries=lambda: [])
    owner = _owner(store)
    _assert_reexec(overflow, lambda: owner.build_proposal(candidate_rules=[RULE], lend=False))


def test_authority_lend_check(temp_database, overflow):
    owner = _owner()
    session = SimpleNamespace(plan=SimpleNamespace(interned=frozenset({4})),
                              dispose=lambda: None)
    owner._serve(session, descriptor=tr.ReconstructionDescriptor(journal_head_hash=None))
    _assert_reexec(overflow, lambda: owner._try_lend(tj.Journal(), [RULE], "miner"))


def test_authority_genesis(temp_database, overflow, monkeypatch):
    import chain_state

    monkeypatch.setattr(chain_state, "get_tau_restore_plan", lambda *a, **k: [{"text": RULE}])
    owner = _owner()
    _assert_reexec(overflow, lambda: owner._commit_genesis("00" * 32))
