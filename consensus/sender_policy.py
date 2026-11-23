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


def _streams_read(body) -> set:
    """Input stream indices a clause body reads (comments stripped)."""
    if not body:
        return set()
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(body)
    return {int(m.group(1)) for m in re.finditer(r"\bi(\d+)\b", scrubbed)}


def clause_is_inbound_capable(body) -> bool:
    """True when a clause opts into inbound judging by reading i17 or i16.

    The opt-in is what makes the set of inbound-capable clauses statically
    decidable at deploy: a clause reading neither stream is never invoked
    inbound (the neutral default), and a clause reading only i3 keeps exactly
    its outbound meaning.
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


def recipient_hold_inputs(values: dict, *, hold: int, context: int) -> dict:
    """A copy of a transfer input map with the gate's overlay forced in.

    i17 = the hold in its native unit, i16 = the judgment context. Forced —
    never merged — so a sender-supplied value on either stream (possible in
    a parked request's custom inputs before activation) never reaches the
    recipient's clause.

    Forced under EVERY key shape: the same stream can be spelled `17`,
    `"17"` or `"i17"` in a hand-built map, and the clause path collapses
    those spellings last-one-wins (`clause_inputs`), so forcing only the
    integer key would let a forged `"i17"` entry sitting after it win.
    The alias spellings are removed and the canonical integer key carries
    the gate's value — one shape per gated stream, which is also the only
    shape the raw evaluator path accepts (it rejects duplicate aliases).
    """
    out = dict(values or {})
    for idx in (tau_defs.HOLD_STREAM_INDEX, tau_defs.CONTEXT_STREAM_INDEX):
        out.pop(str(idx), None)
        out.pop(f"i{idx}", None)
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
_HOLD_STREAM_CMP_RE = re.compile(
    r"\bi17\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]\s*(<=|>=|<|>)\s*"
    r"i(\d+)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]"
)
_HOLD_STREAM_CMP_FLIPPED_RE = re.compile(
    r"\bi(\d+)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]\s*(<=|>=|<|>)\s*"
    r"i17\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]"
)
_HOLD_MENTION_RE = re.compile(
    r"\bi17\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]"
)

# Past this many change points in one branch the cap is reported without a
# number rather than verified point by point (each point costs an engine
# evaluation on the refusal path).
_MAX_CAP_CHANGE_POINTS = 24


def _literal_value(match, base: int) -> int:
    hex_part, bin_part, dec_part = match.group(base), match.group(base + 1), \
        match.group(base + 2)
    if hex_part is not None:
        return int(hex_part, 16)
    if bin_part is not None:
        return int(bin_part, 2)
    return int(dec_part)


def _branch_change_points(body, context: int, fed: dict = None):
    """The hold values at which the verdict for `context` can change, or
    None when this branch's cap cannot be named soundly.

    A cap is named ONLY from change points this payment fixes:

    - every i17 mention attributed to this branch must be a DIRECT
      comparison — against a bv[64] literal, or against another bv[64]
      stream whose value this payment fixes (resolved from `fed`, the
      input map the clause is judged with). A mention doing anything
      else (arithmetic, a comparison with i16/i17 itself, a stream this
      payment does not fix) means the branch's threshold is not a fixed
      set of points, and no cap is named;
    - comparisons in other branches are that branch's business: they are
      attributed by the same positional i16-guard rule the extractor has
      always used and checked when that branch's cap is named.

    Returns the sorted, de-duplicated polarity-adjusted bounds (the same
    operator-to-cap mapping the literal extractor has always used); the
    caller verifies them against actual evaluation before printing.
    """
    if not body:
        return None
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(body)
    guards = [
        (m.start(), _literal_value(m, 1)) for m in _CONTEXT_GUARD_RE.finditer(scrubbed)
    ]

    def branch_of(pos: int):
        branch = None
        for gpos, gval in guards:
            if gpos < pos:
                branch = gval
            else:
                break
        return branch

    def in_branch(pos: int) -> bool:
        return not guards or branch_of(pos) == context

    mentions = [
        m.start() for m in _HOLD_MENTION_RE.finditer(scrubbed)
        if in_branch(m.start())
    ]
    if not mentions:
        return None

    points = []
    covered = []

    def note_literal(match, bound: int, op: str, flipped: bool) -> None:
        if not in_branch(match.start()):
            return
        adjust = ("<", ">=") if not flipped else (">", "<")
        points.append(bound - 1 if op in adjust else bound)
        covered.append((match.start(), match.end()))

    for m in _HOLD_CMP_RE.finditer(scrubbed):
        note_literal(m, _literal_value(m, 2), m.group(1), flipped=False)
    for m in _HOLD_CMP_FLIPPED_RE.finditer(scrubbed):
        note_literal(m, _literal_value(m, 1), m.group(4), flipped=True)

    for match in _HOLD_STREAM_CMP_RE.finditer(scrubbed):
        if not in_branch(match.start()):
            continue
        op, idx = match.group(1), int(match.group(2))
        if idx in (tau_defs.HOLD_STREAM_INDEX, tau_defs.CONTEXT_STREAM_INDEX):
            return None
        raw = (fed or {}).get(f"i{idx}")
        if raw is None or not re.fullmatch(r"\d+", str(raw).strip()):
            return None
        points.append(int(raw) - 1 if op in ("<", ">=") else int(raw))
        covered.append((match.start(), match.end()))
    for match in _HOLD_STREAM_CMP_FLIPPED_RE.finditer(scrubbed):
        if not in_branch(match.start()):
            continue
        idx, op = int(match.group(1)), match.group(2)
        if idx in (tau_defs.HOLD_STREAM_INDEX, tau_defs.CONTEXT_STREAM_INDEX):
            return None
        raw = (fed or {}).get(f"i{idx}")
        if raw is None or not re.fullmatch(r"\d+", str(raw).strip()):
            return None
        points.append(int(raw) - 1 if op in (">", "<") else int(raw))
        covered.append((match.start(), match.end()))

    for pos in mentions:
        if not any(start <= pos < end for start, end in covered):
            return None
    points = sorted({p for p in points if p >= 0})
    if not points or len(points) > _MAX_CAP_CHANGE_POINTS:
        return None
    return points


def _fed_values(values: dict, context: int) -> dict:
    """The bare input map the recipient's clause is judged with for this
    payment (gate overlay forced, hold irrelevant to every other stream)."""
    return clause_inputs(recipient_hold_inputs(values, hold=0, context=context))


def extract_candidate_cap(body, context: int, values: dict = None):
    """A candidate hold cap for `context`, from the branch's change points.

    A HINT, never a verdict: the caller verifies the candidate against the
    clause's actual evaluation before printing it (see
    `recipient_clause_blocks`). Change points are branch-aware — a
    comparison is attributed to the i16 branch whose guard most recently
    precedes it in the ternary chain — and per-branch restrictive (the
    minimum bound in the branch), never a global "most restrictive wins"
    over the whole clause, which would print one counterparty's cap to
    another. A comparison against another stream counts only when
    `values` (this payment's input map) fixes that stream's value; with
    `values=None` such a clause names no cap here.
    """
    fed = _fed_values(values, context) if values is not None else None
    points = _branch_change_points(body, context, fed)
    if not points:
        return None
    return min(points)


def _cap_verified(body, values: dict, *, cap: int, context: int,
                  points, pool: str, timeout) -> bool:
    """True when the clause's verdict for THIS counterparty (the actual
    sender, amount and context in `values`) is a single threshold at
    `cap` across the branch's whole change-point set: admitted exactly
    at holds <= cap. Evaluates hold 0, the unit maximum, and every
    change point and its successor — a holed rule (admits 0..101 and
    5000..6000, refuses between) fails at the hole's edge and is
    honestly reported without a number, as is any rule whose verdict
    moves anywhere the points did not predict."""
    from consensus.retractable import (
        MAX_RELEASE_WINDOW_BLOCKS,
        MAX_RELEASE_WINDOW_SECONDS,
    )

    unit_max = MAX_RELEASE_WINDOW_SECONDS \
        if context == tau_defs.CONTEXT_INCOMING_TIME_PARK \
        else MAX_RELEASE_WINDOW_BLOCKS
    probes = {0, unit_max}
    for point in points:
        probes.add(min(point, unit_max))
        probes.add(min(point + 1, unit_max))
    for hold in sorted(probes):
        blocked, _ = clause_blocks(
            body, recipient_hold_inputs(values, hold=hold, context=context),
            pool=pool, timeout=timeout,
        )
        if blocked == (hold <= cap):
            return False
    return True


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
    points = _branch_change_points(body, context, _fed_values(values, context))
    candidate = min(points) if points else None
    if candidate is not None and _cap_verified(
        body, values, cap=candidate, context=context, points=points,
        pool=pool, timeout=timeout,
    ):
        info["cap_kind"] = "threshold"
        info["max_hold_seconds" if unit == "seconds"
             else "max_hold_blocks"] = candidate
    else:
        info["cap_kind"] = "rule"
    return True, info


# A guarded unit scopes on its owner by comparing i12 against the owner's
# key as a full-width literal: `i12[t] = { #xKEY }:bv[384]` (the stream
# reference may itself carry a `:bv[N]` annotation). Matching that literal
# inside a unit's GUARD — never a raw substring of the spec — is what makes
# the recipient pass judge only recipients who actually have a unit.
_UNIT_SCOPE_RE = re.compile(
    r"\bi12\s*\[\s*t\s*\]\s*(?::\s*bv\s*\[\s*\d+\s*\])?\s*=\s*"
    r"\{\s*#x([0-9a-fA-F]+)\s*\}\s*:\s*bv\s*\[\s*384\s*\]"
)
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)


def _padded_key_literal(literal: str) -> str:
    """A spec key literal normalised to the bare, lower-case, 96-hex-digit
    public key the rest of the node compares against. Spec text may carry
    a key in any zero-padded width and either case; a direct string
    compare would then miss its own unit."""
    return (literal or "").strip().lower().rjust(96, "0")[-96:]


def spec_mentions_account(spec_text, pubkey: str) -> bool:
    """Pre-screen for the guarded-mode recipient pass: True only when the
    spec carries a unit whose guard binds i12 to this account's key
    literal — i.e. the account actually has a guarded unit to enforce.

    Units are the top-level `always` statements, comments scrubbed first;
    the binding must sit in the unit's guard (the text before the unit's
    first `?`). A key that appears only in a comment, or only inside
    another unit's body, is not a scope and must not make the pass step
    for a recipient with no unit of her own: whatever the accumulated spec
    resolves to under i12 = recipient would otherwise become her verdict,
    delivered by somebody else's unit. (This is the fix pattern PR #133
    published against PR #126's identical substring prescreen, ported to
    this module; the shapes are pinned in
    tests/test_recipient_guarded_prescreen.py.)"""
    if not spec_text or not pubkey:
        return False
    from consensus.rule_offers import strip_clause_comments

    target = _padded_key_literal(str(pubkey))
    scrubbed = _BLOCK_COMMENT_RE.sub(
        " ", strip_clause_comments(str(spec_text)))
    for chunk in scrubbed.split("always"):
        guard = chunk.partition("?")[0]
        for match in _UNIT_SCOPE_RE.finditer(guard):
            if _padded_key_literal(match.group(1)) == target:
                return True
    return False


def guarded_pass_inputs(values: dict, recipient: str, *, hold: int,
                        context: int) -> dict:
    """Input map for the guarded-mode recipient pass: the transfer map with
    i12 set to the RECIPIENT (the 'acting-as / policy owner' reading), plus
    the gate overlay. i3 stays the sender — the counterparty the recipient's
    guard matches on."""
    out = recipient_hold_inputs(values, hold=hold, context=context)
    out[12] = "{ #x" + str(recipient) + " }:bv[384]"
    return out
