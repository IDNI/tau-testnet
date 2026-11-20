"""The sender's own o5 clause as a second, independent block condition.

Every call site (apply, admission, approval preview) goes through here so the
inputs, the failure mapping and the evaluator choice cannot drift apart.
"""
from __future__ import annotations

import atexit
import re
import threading

import tau_defs
import tau_manager
import tau_policy
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import strip_clause_comments
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


# --- Recipient gate (issues #47 + #76) ---------------------------------------
#
# The recipient's own o5 clause as a second, independent block condition,
# evaluated through the SAME machinery as the sender's clause above — same
# input-map builder upstream, same evaluator pools, same failure mapping — so
# the two directions cannot drift apart. The only differences are the ones the
# feature is made of: the clause is the RECIPIENT's, and the input map carries
# the hold/context overlay (i17/i16) the gate forces in.
#
# One clause per account serves both directions. The clause opts into inbound
# judging by reading i17 or i16: a body that never mentions either keeps
# exactly its outbound meaning and is never invoked inbound (the neutral
# default). A body that wants to tell the directions apart branches on i16 —
# 0 is "judging my outgoing payment", 1/2/3 is "judging a payment to me" —
# so one unit can carry an outbound whitelist and an inbound whitelist side
# by side, as #47 acceptance case 4 requires.


def _streams_read(body) -> set:
    """Input stream indices a clause body reads (comments stripped)."""
    if not body:
        return set()
    scrubbed = strip_clause_comments(body)
    return {int(m.group(1)) for m in re.finditer(r"\bi(\d+)\b", scrubbed)}


def clause_is_inbound_capable(body) -> bool:
    """True when a clause opts into inbound judging by reading i17 or i16.

    The opt-in is what makes the set of inbound-capable clauses statically
    decidable at deploy: a clause reading neither stream is never invoked
    inbound (the neutral default), and a clause reading only i3 keeps exactly
    its outbound meaning. It is also what makes the deploy refusal complete —
    a node without the gate refuses exactly the clauses that could only run
    as inbound rules (consensus/admission.py).
    """
    read = _streams_read(body)
    return (
        tau_defs.HOLD_STREAM_INDEX in read
        or tau_defs.CONTEXT_STREAM_INDEX in read
    )


def clause_reads_hold_without_context(body) -> bool:
    """True for a unit-blind hold rule: reads i17 but never i16.

    Such a rule would have to judge seconds and blocks with one number — a
    height park would reach it denominated in blocks while its cap was
    written for seconds (or the reverse). Refused at deploy
    (consensus/admission.py), so no deployed hold rule can silently admit
    the other unit.
    """
    read = _streams_read(body)
    return (
        tau_defs.HOLD_STREAM_INDEX in read
        and tau_defs.CONTEXT_STREAM_INDEX not in read
    )


def inactive_refusal_reason(body, active: bool):
    """Reason an inbound-capable clause body cannot deploy, else None.

    Acceptance #47.5 / #76.6: a node without the gate must refuse an inbound
    rule at deploy with a clear reason rather than silently admit a rule that
    never runs. Because every inbound-capable clause must read i17 or i16
    (the opt-in), the screen is complete — for allow-lists and hold caps
    alike. Admission and block apply share this predicate, so the two paths
    refuse the same bodies.
    """
    if active:
        return None
    if not clause_is_inbound_capable(body):
        return None
    return (
        "Recipient-side policy is not active on this chain. This rule reads "
        "i17/i16 (the recipient hold/context streams), so it could only run "
        "as an inbound recipient rule; the feature activates by governance "
        "patch (recipient_policy_active), which reserves i17 and i16."
    )


def recipient_hold_inputs(values: dict, *, hold: int, context: int) -> dict:
    """A copy of a transfer input map with the gate's overlay forced in.

    i17 = the hold in its native unit, i16 = the judgment context. Forced —
    never merged — so a sender-supplied value on either stream (possible in
    a parked request's custom inputs before activation) never reaches the
    recipient's clause.
    """
    out = dict(values or {})
    out[tau_defs.HOLD_STREAM_INDEX] = str(int(hold))
    out[tau_defs.CONTEXT_STREAM_INDEX] = str(int(context))
    return out


def sender_pass_inputs(values: dict) -> dict:
    """The overlay the SENDER pass always carries while the gate is active:
    i17 = 0, i16 = 0 ("judging an outgoing payment"), so an owner's inbound
    rules can never fire on their own outgoing payments."""
    return recipient_hold_inputs(
        values, hold=0, context=tau_defs.CONTEXT_OUTGOING
    )


def park_hold(kind: int, release_at: int, block_height: int,
              block_timestamp: int) -> tuple[int, int]:
    """(hold, context) for a park, measured against the given block clock.

    The hold is denominated in the park's own unit — seconds against the
    block timestamp for a time park, blocks against the block height for a
    height park — and saturates at 0 rather than going negative (a park
    whose release is not in the future is refused by the park shape screen
    before the gate ever sees it; this is the belt on those braces).
    """
    from consensus.retractable import KIND_HEIGHT

    if kind == KIND_HEIGHT:
        return max(0, int(release_at) - int(block_height)), \
            tau_defs.CONTEXT_INCOMING_HEIGHT_PARK
    return max(0, int(release_at) - int(block_timestamp)), \
        tau_defs.CONTEXT_INCOMING_TIME_PARK


# Canonical i17 comparisons, for the cap HINT only (never a verdict): the
# caller verifies any candidate against the clause's actual evaluation
# before printing it (see `recipient_clause_blocks`).
_HOLD_CMP_RE = re.compile(
    r"\bi17\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]\s*(<=|>=|<|>)\s*"
    r"\{\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}\s*:\s*bv\s*\[\s*64\s*\]"
)
_HOLD_CMP_FLIPPED_RE = re.compile(
    r"\{\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}\s*:\s*bv\s*\[\s*64\s*\]"
    r"\s*(<=|>=|<|>)\s*\bi17\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]"
)
_CONTEXT_GUARD_RE = re.compile(
    r"\bi" + str(tau_defs.CONTEXT_STREAM_INDEX) +
    r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]\s*=\s*"
    r"\{\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}\s*:\s*bv\s*\[\s*64\s*\]"
)
_SENDER_GUARD_RE = re.compile(
    r"\bi3\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*384\s*\]\s*=\s*"
    r"\{\s*#x([0-9a-fA-F]{96})\s*\}\s*:\s*bv\s*\[\s*384\s*\]"
)


def _bare_sender(values: dict) -> str:
    """The transfer's sender as bare lowercase hex, for payer attribution."""
    raw = (values or {}).get(3, (values or {}).get("i3", ""))
    text = str(raw or "").strip()
    if text.startswith("{") and "}" in text:
        text = text[1:text.index("}")].strip()
    if text.lower().startswith("#x"):
        text = text[2:]
    return text.lower()


def _literal_value(match, base: int) -> int:
    hex_part, bin_part, dec_part = match.group(base), match.group(base + 1), \
        match.group(base + 2)
    if hex_part is not None:
        return int(hex_part, 16)
    if bin_part is not None:
        return int(bin_part, 2)
    return int(dec_part)


def extract_candidate_cap(body, context: int, sender: str = None):
    """A candidate hold cap for `context` (and `sender`) from canonical
    i17 comparisons.

    A HINT, never a verdict: the caller verifies the candidate against the
    clause's actual evaluation before printing it (see
    `recipient_clause_blocks`). Extraction is branch-aware — a comparison is
    attributed to the i16 branch whose guard most recently precedes it in
    the ternary chain — and per-payer: a comparison governed by an `i3 =`
    sender guard most recently preceding it counts only for that sender, so
    a per-counterparty cap (600 for A, 60 for B) is never reported to the
    wrong payer. Within one (branch, payer) the minimum bound wins — the
    most restrictive cap in that branch, never a global "most restrictive
    wins" over the whole clause.
    """
    if not body:
        return None
    scrubbed = strip_clause_comments(body)
    guards = [
        (m.start(), _literal_value(m, 1)) for m in _CONTEXT_GUARD_RE.finditer(scrubbed)
    ]
    payer_guards = [
        (m.start(), m.group(1).lower()) for m in _SENDER_GUARD_RE.finditer(scrubbed)
    ]

    def branch_of(pos: int):
        branch = None
        for gpos, gval in guards:
            if gpos < pos:
                branch = gval
            else:
                break
        return branch

    def payer_of(pos: int):
        payer = None
        for gpos, gval in payer_guards:
            if gpos < pos:
                payer = gval
            else:
                break
        return payer

    # The operator-to-cap mapping assumes the comparison bounds the hold
    # from above in whichever polarity the rule writes it (allow form
    # `i17 <= cap`, refusal form `i17 > cap`). It only ever produces a
    # candidate; `_cap_verified` decides.
    caps = []
    for m in _HOLD_CMP_RE.finditer(scrubbed):
        if guards and branch_of(m.start()) != context:
            continue
        payer = payer_of(m.start())
        if payer is not None and sender is not None and payer != str(sender).lower():
            continue
        bound = _literal_value(m, 2)
        caps.append(bound - 1 if m.group(1) in ("<", ">=") else bound)
    for m in _HOLD_CMP_FLIPPED_RE.finditer(scrubbed):
        if guards and branch_of(m.start()) != context:
            continue
        payer = payer_of(m.start())
        if payer is not None and sender is not None and payer != str(sender).lower():
            continue
        bound = _literal_value(m, 1)
        caps.append(bound - 1 if m.group(4) in (">", "<") else bound)
    caps = [c for c in caps if c >= 0]
    if not caps:
        return None
    return min(caps)


def _cap_verified(body, values: dict, *, cap: int, context: int,
                  pool: str, timeout) -> bool:
    """True when the clause admits hold == cap and refuses hold == cap + 1
    for THIS counterparty (the actual sender, amount and context in
    `values`). A non-monotonic rule (admits 0 and 2, refuses 1) fails here
    and is honestly reported without a number.

    Two evaluations, bounded and constant — not a probe sweep, and not an
    assumption of monotonicity over the whole range: only the boundary the
    text itself names is checked, and only for this payer.
    """
    blocked_at_cap, _ = clause_blocks(
        body, recipient_hold_inputs(values, hold=cap, context=context),
        pool=pool, timeout=timeout,
    )
    if blocked_at_cap:
        return False
    blocked_above_cap, _ = clause_blocks(
        body, recipient_hold_inputs(values, hold=cap + 1, context=context),
        pool=pool, timeout=timeout,
    )
    return blocked_above_cap


def recipient_clause_blocks(clause_for, recipient: str, values: dict, *,
                            hold: int, context: int, pool: str,
                            timeout=_SESSION_DEFAULT):
    """(blocked, info) for the recipient's clause on one inbound transfer.

    `values` is the transfer input map BEFORE the gate overlay; the overlay
    is forced in here. `info` is None when the recipient has no
    inbound-capable clause (the neutral default — nothing was evaluated).
    On a block, `info` carries the receipt fields:

    - reason "recipient_policy_block" (allow-list refusal), or
      "recipient_max_hold" when re-judging the same transfer at hold 0
      admits it — the block was caused by the hold alone;
    - for a hold refusal: the measured `hold` and its `unit`, plus the cap
      ONLY when verified against this payer's actual evaluation
      (`cap_kind` "threshold" with `max_hold_seconds`/`max_hold_blocks`),
      else `cap_kind` "rule" and no number.
    """
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    if not body or not clause_is_inbound_capable(body):
        return False, None

    judged = recipient_hold_inputs(values, hold=hold, context=context)
    blocked, o5 = clause_blocks(body, judged, pool=pool, timeout=timeout)
    if not blocked:
        return False, {"o5": o5}

    info = {
        "o5": o5,
        "recipient": recipient,
        "reason": "recipient_policy_block",
    }
    if context == tau_defs.CONTEXT_OUTGOING or int(hold) <= 0:
        return True, info

    # Was it the hold that refused, or the allow-list? Re-judge at hold 0 in
    # the same context: an allow-list block refuses at every hold.
    at_zero, _ = clause_blocks(
        body, recipient_hold_inputs(values, hold=0, context=context),
        pool=pool, timeout=timeout,
    )
    if at_zero:
        return True, info

    unit = "seconds" if context == tau_defs.CONTEXT_INCOMING_TIME_PARK \
        else "blocks"
    info.update({
        "reason": "recipient_max_hold",
        # The code the issues name for this refusal, carried alongside the
        # measured hold and its unit so a wallet can always print the
        # sentence ("accepts payments held for up to ...") — with the cap
        # itself present only when verified below.
        "code": "RECIPIENT_MAX_HOLD",
        "hold": int(hold),
        "unit": unit,
    })
    candidate = extract_candidate_cap(body, context, sender=_bare_sender(values))
    if candidate is not None and candidate >= 0 and _cap_verified(
        body, values, cap=candidate, context=context,
        pool=pool, timeout=timeout,
    ):
        info["cap_kind"] = "threshold"
        info["max_hold_seconds" if unit == "seconds"
             else "max_hold_blocks"] = candidate
    else:
        info["cap_kind"] = "rule"
    return True, info


def spec_mentions_account(spec_text, pubkey: str) -> bool:
    """Pre-screen for the guarded-mode recipient pass: the account's key as
    a literal in the spec text. A guarded unit scopes on its owner's key, so
    absence proves there is no unit of theirs to enforce."""
    if not spec_text or not pubkey:
        return False
    return str(pubkey).lower() in spec_text.lower()


def guarded_pass_inputs(values: dict, recipient: str, *, hold: int,
                        context: int) -> dict:
    """Input map for the guarded-mode recipient pass: the transfer map with
    i12 set to the RECIPIENT (the 'acting-as / policy owner' reading of
    #47), plus the gate overlay. i3 stays the sender — the counterparty the
    recipient's guard matches on."""
    out = recipient_hold_inputs(values, hold=hold, context=context)
    out[12] = "{ #x" + str(recipient) + " }:bv[384]"
    return out
