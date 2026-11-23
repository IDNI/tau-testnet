"""The sender's own o5 clause as a second, independent block condition, and
the recipient's o5 clause as a third (issues #47/#76).

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


# --- Recipient policy (issues #47/#76) ---------------------------------------
#
# A transfer is judged by the RECIPIENT's o5 clause as well as the sender's,
# once per transfer output, at admission and at apply. The clause is fetched
# by the same (pubkey, stream) key as the sender's; the evaluation, the
# failure mapping and the cap probe below are shared by both paths so they
# cannot drift apart.
#
# The guarded (accumulated) o5 output stays sender-scoped: the shared spec
# has no per-account separation, so a second guarded pass with i12 re-fed to
# the recipient would re-judge the sender's own rules as if the recipient
# were the sender, and would break the fee model's one-evaluation-per-transfer
# contract. The recipient gate is clause-only, by design.

# Probes are bounded: a binary search over the hold range plus verification
# and monotonicity spot-checks. A time hold is at most
# MAX_RELEASE_WINDOW_SECONDS (7,776,000, ~23 probes); a blocks hold at most
# MAX_RELEASE_WINDOW_BLOCKS (100,000, ~17 probes) -- see
# consensus/retractable.py. 32 covers both with room for the spot-checks.
MAX_HOLD_PROBES = 32


def probe_hold_cap(body, values: dict, *, pool: str, timeout=_SESSION_DEFAULT,
                   hold_stream: int, hold_value: int):
    """The max hold `body` allows, or None when there is no clean cap to report.

    Called ONLY on the refusal path: `body` already blocked at `hold_value`.
    Re-evaluates the clause with only the hold stream varied and
    binary-searches the flip point (allow -> block). Deterministic: the probe
    sequence is a pure function of (body, hold_value), so admission and apply
    report the same cap for the same hold.

    Returns None when:
    - the clause also blocks at hold 0 (the equivalent plain transfer): the
      refusal is not about the hold at all, so there is no cap to report;
    - the threshold cannot be verified (threshold allows, threshold+1 blocks);
    - monotonicity spot-checks fail: a genuine cap allows everything below
      it and blocks everything above it, so a clause that blocks below the
      threshold or allows above it has no single cap. The checks are spot
      checks, not a proof: a clause crafted to be non-monotone only between
      the sampled points can still pass, but the reported cap is always a
      genuine flip point (it allows, and one more blocks);
    - the probe budget runs out (unreachable for a validated park).
    """
    if not body or hold_value <= 0:
        return None
    probed: dict = {}

    def blocks_at(hold: int):
        """Whether the clause blocks at this hold, or None when the probe
        budget is spent (the caller then reports no cap)."""
        if hold in probed:
            return probed[hold]
        if len(probed) >= MAX_HOLD_PROBES:
            return None
        trial = dict(values)
        trial.pop(f"i{hold_stream}", None)
        trial[hold_stream] = str(hold)
        blocked, _ = clause_blocks(body, trial, pool=pool, timeout=timeout)
        probed[hold] = blocked
        return blocked

    # Hold 0 is the equivalent plain transfer: if the clause blocks that too,
    # the refusal is not about the hold.
    if blocks_at(0) is not False:
        return None
    if blocks_at(hold_value) is not True:
        return None
    lo, hi = 0, hold_value  # allows(lo), blocks(hi)
    while hi - lo > 1:
        mid = (lo + hi) // 2
        verdict = blocks_at(mid)
        if verdict is None:
            return None
        if verdict:
            hi = mid
        else:
            lo = mid
    # lo allows and lo + 1 blocks by construction (the invariant). Spot-check
    # monotonicity: a genuine cap allows everything below it and blocks
    # everything above it.
    if lo > 1 and blocks_at(lo // 2) is not False:
        return None
    if hi < hold_value and blocks_at((hi + hold_value) // 2) is not True:
        return None
    return lo


def recipient_blocks(clause_for, recipient: str, values: dict, *, pool: str,
                     timeout=_SESSION_DEFAULT, hold_stream=None, hold_value=0):
    """(blocked, detail, cap) for the RECIPIENT's o5 clause on one transfer.

    The recipient-side gate, shared by admission and apply. `clause_for` is
    the path's clause lookup (TipAdmissionView.clause_for at admission, the
    block lifecycle manager's rule_offers.clause_for at apply); the
    evaluation, the failure mapping and the cap probe are identical on both.

    The gate is inert while tau_defs.RECIPIENT_POLICY_ACTIVE is off: no
    clause is evaluated and every transfer passes. A recipient with no clause
    passes (clause_blocks returns (False, "") for no body).

    `hold_stream`/`hold_value` name the park's hold (17/seconds or 27/blocks)
    when this transfer is a retractable park; 0/absent for a plain transfer.
    When the clause blocks a park, the cap is probed (probe_hold_cap) and
    returned; otherwise `cap` is None. Probing runs only on the refusal path,
    never on the happy path.
    """
    if not tau_defs.RECIPIENT_POLICY_ACTIVE:
        return False, "", None
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    blocked, detail = clause_blocks(body, values, pool=pool, timeout=timeout)
    if not blocked or hold_value <= 0 or hold_stream is None:
        return blocked, detail, None
    cap = probe_hold_cap(body, values, pool=pool, timeout=timeout,
                         hold_stream=hold_stream, hold_value=hold_value)
    return True, detail, cap
