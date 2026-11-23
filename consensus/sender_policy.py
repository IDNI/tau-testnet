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


# --- Recipient side (issues #47, #76) -----------------------------------------
#
# Until now one account's clause judged a transfer: the sender's. Once the
# network has activated recipient policy, the RECIPIENT's clause judges it too,
# through the helpers below. Every call site (admission, apply, parks) goes
# through here, so the inputs fed to the recipient's clause cannot drift
# between mempool admission and block apply.

_RECEIVE_STREAM_RE = None


def reads_receive_stream(body) -> bool:
    """Whether a clause body reads the receive stream i17 (comments ignored).

    This is the opt-in: a clause that never reads i17 was written as an outbound
    rule, and judging incoming payments with it would turn every existing
    outbound whitelist into an inbound block. Decided from the text alone, so
    every node decides it the same way.
    """
    global _RECEIVE_STREAM_RE
    if not body:
        return False
    if _RECEIVE_STREAM_RE is None:
        import re
        _RECEIVE_STREAM_RE = re.compile(r"\bi%d\b" % tau_defs.RECIPIENT_HOLD_STREAM_INDEX)
    from consensus.rule_offers import strip_clause_comments
    return bool(_RECEIVE_STREAM_RE.search(strip_clause_comments(body)))


def sending_inputs(values: dict) -> dict:
    """The sender-pass input map once recipient policy is active: the same map,
    with i17 = 0 ("the owner is sending") written last, so a clause that carries
    an inbound rule next to its outbound rules knows which side it is judging."""
    out = dict(values or {})
    out[tau_defs.RECIPIENT_HOLD_STREAM_INDEX] = str(tau_defs.RECIPIENT_HOLD_SENDING)
    return out


def receiving_inputs(values: dict, recipient_pubkey: str, hold,
                     owner_balance=None) -> dict:
    """The recipient-pass input map, built from the transfer's own map.

    Everything the sender pass saw stays (i1 amount, i3 sender, i4 recipient,
    i5 time, custom inputs, empty approval slots), so the clause reads the
    counterparty on i3 exactly as an outbound rule reads it on i4. Up to three
    streams change, all to keep "i-streams describe the clause owner" true in
    both passes: i12 becomes the recipient (the owner, as the sender is in the
    sender pass), i2 becomes the recipient's own balance when the caller knows
    it (the same parent-block snapshot the sender's i2 comes from), and i17
    carries the receive context and the hold.
    """
    out = dict(values or {})
    out[12] = "{ #x" + str(recipient_pubkey) + " }:bv[384]"
    if owner_balance is not None:
        out[2] = str(owner_balance)
    out[tau_defs.RECIPIENT_HOLD_STREAM_INDEX] = str(
        tau_defs.recipient_hold_value(hold)
    )
    return out


def recipient_clause_blocks(body, values: dict, recipient_pubkey: str,
                            hold, *, pool: str, owner_balance=None,
                            timeout=_SESSION_DEFAULT) -> tuple[bool, str]:
    """(blocked, detail) for the recipient's clause on one incoming payment.

    A recipient with no clause, or with a clause that never reads i17, allows
    everything (the neutral default) without touching an evaluator. Otherwise
    the verdict, build and step failures map exactly as for the sender's clause.
    """
    if not body or not reads_receive_stream(body):
        return False, ""
    return clause_blocks(
        body, receiving_inputs(values, recipient_pubkey, hold, owner_balance),
        pool=pool, timeout=timeout,
    )


_BV64_LITERAL_RE = None
_ARITHMETIC_RE = None


def _literal_value(text: str):
    t = text.strip().lower()
    try:
        if t.startswith("#x"):
            return int(t[2:], 16)
        if t.startswith("#b"):
            return int(t[2:], 2)
        return int(t)
    except ValueError:
        return None


# Evaluations the admission path may spend naming a cap for a refused park.
# Covers a cap in either unit or both (at most 8 points); a clause with more
# constants is still enforced, its refusal just carries no number at sendtx.
ADMISSION_CAP_MAX_POINTS = 12


def recipient_hold_cap(body, values: dict, recipient_pubkey: str, *,
                       blocks: bool = False, pool: str, owner_balance=None,
                       held=None, timeout=_SESSION_DEFAULT, max_points=None):
    """The largest hold the recipient's clause admits for this payment, in
    seconds (or in blocks when `blocks`), or None when no exact cap exists.

    Used only to word a RECIPIENT_MAX_HOLD refusal (admission, checktx, the
    advisory RPC; never at apply). Exact, not estimated: for this payment every
    input but i17 is fixed, and a clause compares i17 only with the bv[64]
    constants written in it, so its verdict can change only at a constant c
    (between c - 1, c and c + 1). The node evaluates the clause at those points
    alone. The verdict is a cap exactly when it is "admit" up to some point and
    "refuse" from the next one to the end of the release window; that point is
    returned. A clause that is not a cap (admits 0-100 s and 300-400 s, say),
    or that does arithmetic, gets no number: its refusal still enforces.
    """
    import re
    from consensus.retractable import (
        MAX_RELEASE_WINDOW_BLOCKS,
        MAX_RELEASE_WINDOW_SECONDS,
    )
    from consensus.rule_offers import strip_clause_comments

    global _BV64_LITERAL_RE, _ARITHMETIC_RE
    if _BV64_LITERAL_RE is None:
        _BV64_LITERAL_RE = re.compile(
            r"\{\s*(#[xX][0-9a-fA-F]+|#[bB][01]+|\d+)\s*\}\s*:\s*bv\s*\[\s*%d\s*\]"
            % tau_defs.RECIPIENT_HOLD_BV_WIDTH)
        # Any arithmetic or bitwise operator: then i17 might be shifted or
        # masked before a comparison, and the change points are not the
        # constants. Logical &&, ||, ! and the -> implication are fine.
        _ARITHMETIC_RE = re.compile(r"[+*/%^~]|<<|>>|(?<![&])&(?![&])|(?<![|])\|(?![|])|-(?!>)")
    if not body:
        return None
    text = strip_clause_comments(body)
    scrubbed = re.sub(r"\{[^}]*\}", "{}", text)       # literals cannot hold operators
    if _ARITHMETIC_RE.search(scrubbed):
        return None
    # Every mention of i17 must sit in a direct comparison with a bv[64]
    # literal: `i17 OP { c }` or `{ c } OP i17`. A comparison with another
    # stream (i17 < i26), or i17 inside any other expression, moves the change
    # points away from the written constants, so no number is reported.
    i17 = r"i%d\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*%d\s*\]" % (
        tau_defs.RECIPIENT_HOLD_STREAM_INDEX, tau_defs.RECIPIENT_HOLD_BV_WIDTH)
    lit = r"\{\s*(?:#[xX][0-9a-fA-F]+|#[bB][01]+|\d+)\s*\}\s*:\s*bv\s*\[\s*%d\s*\]" % (
        tau_defs.RECIPIENT_HOLD_BV_WIDTH)
    op = r"\s*(?:!=|<=|>=|=|<|>)\s*"
    mentions = len(re.findall(r"\bi%d\b" % tau_defs.RECIPIENT_HOLD_STREAM_INDEX, text))
    direct = len(re.findall(i17 + op + lit, text)) + len(re.findall(lit + op + i17, text))
    if mentions == 0 or direct != mentions:
        return None

    window = MAX_RELEASE_WINDOW_BLOCKS if blocks else MAX_RELEASE_WINDOW_SECONDS
    base = tau_defs.RECIPIENT_HOLD_BLOCKS_BASE if blocks else tau_defs.RECIPIENT_HOLD_INSTANT
    make = tau_defs.HeldBlocks if blocks else int
    points = {0, window}
    for m in _BV64_LITERAL_RE.finditer(text):
        c = _literal_value(m.group(1))
        if c is None:
            continue
        for v in (c - 1, c, c + 1):
            n = v - base                       # the hold this i17 value stands for
            if 0 <= n <= window:
                points.add(n)
    points = sorted(points)
    # A refused payment pays no fee, so the work spent naming a number for it
    # is bounded: past `max_points` the refusal stands without one.
    if max_points is not None and len(points) > max_points:
        return None

    # A cap: admit, ..., admit, refuse, ..., refuse (at least one of each).
    # Stop at the first verdict that rules that shape out.
    first_refused = None
    for i, n in enumerate(points):
        blocked, _ = recipient_clause_blocks(
            body, values, recipient_pubkey, make(n), pool=pool,
            owner_balance=owner_balance, timeout=timeout)
        if not blocked:
            if first_refused is not None:
                return None                     # refuse, then admit again
        elif i == 0:
            return None                         # not even a zero hold
        elif first_refused is None:
            first_refused = i
    if first_refused is None:
        return None
    cap = points[first_refused - 1]
    # Between two neighbouring points the verdict is constant, so the last
    # admitted hold is the point just below the first refused one.
    cap = points[first_refused] - 1 if points[first_refused] - 1 >= cap else cap
    if held is not None and int(held) <= cap:
        return None
    return cap
