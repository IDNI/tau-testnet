"""The sender's own o5 clause as a second, independent block condition.

Every call site (apply, admission, approval preview) goes through here so the
inputs, the failure mapping and the evaluator choice cannot drift apart.
"""
from __future__ import annotations

import atexit
import threading

import tau_manager
import tau_policy
from consensus.policy_mock import MockPolicyEvaluator
from tau_policy import PolicyBuildError
from tau_session import WorkerSession
from tau_speculation import _SESSION_DEFAULT

_lock = threading.Lock()
_overrides: dict = {}
_mocks: dict = {}
_atexit_registered = False


def set_evaluator(pool: str, evaluator) -> None:
    """Install `evaluator` for `pool`; None restores the default."""
    with _lock:
        if evaluator is None:
            _overrides.pop(pool, None)
        else:
            _overrides[pool] = evaluator


def evaluator(pool: str):
    global _atexit_registered
    with _lock:
        override = _overrides.get(pool)
        if override is not None:
            return override
        if tau_manager.is_force_test_enabled():
            if pool not in _mocks:
                _mocks[pool] = MockPolicyEvaluator(pool=pool)
            return _mocks[pool]
        if not _atexit_registered:
            atexit.register(tau_policy.close_policy_evaluators)
            _atexit_registered = True
    return tau_policy.get_policy_evaluator(pool)


def clause_inputs(values: dict) -> dict:
    """Per-transfer input map -> the bare, one-value-per-stream map the policy
    worker takes, keyed `iN`."""
    out = {}
    for key, value in (values or {}).items():
        name = key if isinstance(key, str) and key.startswith("i") else f"i{key}"
        out[name] = WorkerSession._bare(WorkerSession._single(value))
    return out


def clause_blocks(body, values: dict, *, pool: str,
                  timeout=_SESSION_DEFAULT) -> tuple[bool, str]:
    """(blocked, detail) for `body` against one transfer's inputs.

    A clause that does not build blocks: every node reaches the same result.
    Loss of the evaluator propagates, because it says nothing about the transfer.
    """
    if not body:
        return False, ""
    try:
        verdict = evaluator(pool).verdict(
            body, clause_inputs(values), timeout=timeout
        )
    except PolicyBuildError as exc:
        return True, str(exc)
    return verdict.blocked, str(verdict.o5)
