"""The sender's own o5 clause as a second, independent block condition.

Every call site (apply, admission, approval preview) goes through here so the
inputs, the failure mapping and the evaluator choice cannot drift apart.
"""
from __future__ import annotations

import atexit
import threading

import tau_defs
import tau_manager
import tau_policy
from consensus.policy_mock import MockPolicyEvaluator
from tau_policy import PolicyBuildError, PolicyStepError
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


def change_inputs(kind: int, timestamp: int, slot_values: dict = None) -> dict:
    """Input map for a rule-change guard: i1 = change kind, i5 = block timestamp
    (as the transfer path feeds it), i18..i25 = approval slots, 0 when empty."""
    values = {1: str(kind)}
    values.update({idx: "0" for idx in tau_defs.approval_slot_indices()})
    for slot, value in (slot_values or {}).items():
        values[slot] = value
    values[5] = str(timestamp)
    return clause_inputs(values)


def slot_literals(voted: dict) -> dict:
    """slot -> approver pubkey, as the `{ #x.. }:bv[384]` literal the transfer path feeds."""
    return {
        int(slot): "{ #x" + str(pubkey) + " }:bv[%d]" % tau_defs.APPROVAL_SLOT_BV_WIDTH
        for slot, pubkey in (voted or {}).items()
    }


def rule_change_blocked(clause_for, sender: str, kind: int, timestamp: int, *,
                        pool: str, timeout=_SESSION_DEFAULT,
                        voted: dict = None) -> tuple[bool, str]:
    """(blocked, detail) from the sender's rule-change guard; (False, "") when
    none is registered. `voted` is slot -> approver pubkey for filled slots."""
    guard = clause_for(sender, tau_defs.RULE_CHANGE_GUARD_INDEX)
    if not isinstance(guard, str) or not guard:
        return False, ""
    return clause_blocks(
        guard, change_inputs(kind, timestamp, slot_literals(voted)),
        pool=pool, timeout=timeout,
    )


def clause_blocks(body, values: dict, *, pool: str,
                  timeout=_SESSION_DEFAULT) -> tuple[bool, str]:
    """(blocked, detail) for `body` against one transfer's inputs.

    A clause that does not build, or that the engine refuses to step, blocks:
    every node reaches the same result.
    Loss of the evaluator propagates, because it says nothing about the transfer.
    """
    if not body:
        return False, ""
    try:
        verdict = evaluator(pool).verdict(
            body, clause_inputs(values), timeout=timeout
        )
    except (PolicyBuildError, PolicyStepError) as exc:
        return True, str(exc)
    return verdict.blocked, str(verdict.o5)


def clause_builds(body, *, pool: str, timeout=_SESSION_DEFAULT) -> tuple[bool, str]:
    """(ok, engine_error) for building `always ( body ).` in the pool's evaluator.

    Loss or timeout of the evaluator propagates: it says nothing about the clause.
    """
    result = evaluator(pool).validate(body, timeout=timeout)
    return result.ok, result.error


# --- Recipient-side policy (issues #47, #76) ---------------------------------
#
# The same per-account o5 clause, evaluated a second time for the account a
# payment is going TO. i17 tells the clause which side it is on (see tau_defs):
# 0 for the owner's own outgoing transfer, 1 + hold seconds for an incoming one.
# Every other input is the transfer's own, so "allow only from A" is a plain
# comparison on i3. Only a clause that reads i17 takes part: an existing
# outbound-only clause was never written to judge incoming money.

def reads_recipient_input(body) -> bool:
    """Whether a clause body reads i17, i.e. opted in to judging incoming payments."""
    if not isinstance(body, str) or not body:
        return False
    import re

    from consensus.rule_offers import strip_clause_comments

    return re.search(
        r"\bi%d\b" % tau_defs.RECIPIENT_POLICY_STREAM_INDEX,
        strip_clause_comments(body),
    ) is not None


def outbound_values(values: dict, recipient_policy_active: bool) -> dict:
    """The sender pass's inputs: i17 = 0 once recipient policy is on, so a clause
    with inbound rules reads a defined value on its owner's own transfers."""
    if not recipient_policy_active:
        return values
    out = dict(values)
    out[tau_defs.RECIPIENT_POLICY_STREAM_INDEX] = str(tau_defs.RECIPIENT_POLICY_OUTBOUND)
    return out


def inbound_values(values: dict, hold_seconds: int) -> dict:
    """The recipient pass's inputs: the transfer's own, with i17 = 1 + hold."""
    out = dict(values)
    out[tau_defs.RECIPIENT_POLICY_STREAM_INDEX] = str(
        tau_defs.recipient_policy_inbound_value(hold_seconds)
    )
    return out


def recipient_clause_blocks(clause_for, recipient: str, values: dict,
                            hold_seconds: int = 0, *, pool: str,
                            timeout=_SESSION_DEFAULT) -> tuple[bool, str]:
    """(blocked, detail) from the RECIPIENT's o5 clause for one incoming payment.

    (False, "") when the recipient has no clause or its clause does not read i17.
    A clause that does not build or step blocks, as on the sender side.
    """
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    if not reads_recipient_input(body):
        return False, ""
    return clause_blocks(body, inbound_values(values, hold_seconds),
                         pool=pool, timeout=timeout)


def hold_refusal_cap(clause_for, recipient: str, values: dict, hold_seconds: int, *,
                     pool: str, timeout=_SESSION_DEFAULT) -> tuple[bool, int | None]:
    """For a park the recipient refused: (is_hold_refusal, cap_seconds).

    A refusal is about the HOLD when the same payment with no hold passes. The
    cap is then the longest hold the clause still accepts, found by bisection
    over 0..hold_seconds-1 (a cap rule is monotonic in the hold). Used only to
    word the refusal, never to decide it.
    """
    blocked_now, _ = recipient_clause_blocks(
        clause_for, recipient, values, 0, pool=pool, timeout=timeout)
    if blocked_now:
        return False, None
    lo, hi = 0, max(0, int(hold_seconds) - 1)  # lo always passes
    while lo < hi:
        mid = (lo + hi + 1) // 2
        blocked, _ = recipient_clause_blocks(
            clause_for, recipient, values, mid, pool=pool, timeout=timeout)
        if blocked:
            hi = mid - 1
        else:
            lo = mid
    return True, lo
