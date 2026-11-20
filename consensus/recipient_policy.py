"""Recipient-side o5 policy: the shared half of issues #47 and #76.

A transfer to R is admitted (and applied) only if BOTH the sender's o5
policy and R's o5 policy allow it. The two call sites -- mempool admission
(commands/sendtx.py) and block apply (consensus/engine.py) -- each own their
Tau session, so they run the guarded-mode steps themselves; everything that
must agree between them lives here so it cannot drift:

  * the hold length of a park against a block clock (`hold_length_for_park`),
  * whether the recipient may have a guarded unit in the evaluated spec
    (`recipient_may_have_guarded_policy`),
  * the recipient clause verdict, including the hold-0 discriminator that
    tells a cap block from an allow-list block (`evaluate_recipient_clause`),
  * the max-hold constant a policy states, for the refusal message
    (`extract_hold_cap`),
  * the refusal codes, receipt reasons and message text.

Neutral default throughout: a recipient with no policy, or a policy that
never mentions o5, allows everything. A clause that does not build, or that
the engine refuses to step, blocks -- the same fail-closed rule as the
sender's clause (consensus/sender_policy.py).
"""
from __future__ import annotations

import re
from typing import Optional, Tuple

import tau_defs
from consensus import sender_policy
from consensus.retractable import KIND_HEIGHT, KIND_TIME

# Admission / checktx error codes (sendtx collapses nothing here: a wallet
# must be able to tell which side said no).
RECIPIENT_POLICY_CODE = "RECIPIENT_POLICY_BLOCK"
RECIPIENT_MAX_HOLD_CODE = "RECIPIENT_MAX_HOLD"

# Block-apply receipt reasons (engine.py).
RECIPIENT_POLICY_REASON = "recipient_policy_block"
RECIPIENT_MAX_HOLD_REASON = "recipient_max_hold"

HOLD_UNIT_SECONDS = "seconds"
HOLD_UNIT_BLOCKS = "blocks"


def hold_length_for_park(kind: int, release_at: int, *,
                         height: int, timestamp: int) -> Tuple[int, str]:
    """(hold, unit) of a park against the given block clock.

    Time parks measure in seconds (`release_at_time` minus the block time);
    height parks in blocks (`release_at_height` minus the height). There is
    no deterministic blocks<->seconds conversion -- future block times are
    unknown -- so the unit follows the park's release kind. Clamped at 0:
    the admission clock and the apply clock can differ by a second at the
    boundary, and a negative hold is meaningless.
    """
    if kind == KIND_TIME:
        return max(0, int(release_at) - int(timestamp)), HOLD_UNIT_SECONDS
    if kind == KIND_HEIGHT:
        return max(0, int(release_at) - int(height)), HOLD_UNIT_BLOCKS
    return 0, HOLD_UNIT_SECONDS


def cap_detail_field(hold_unit: str) -> str:
    """The refusal-detail key carrying the cap for this hold unit."""
    return "max_hold_seconds" if hold_unit == HOLD_UNIT_SECONDS else "max_hold_blocks"


def recipient_may_have_guarded_policy(spec_text: str, recipient_pubkey: str) -> bool:
    """True when the recipient's key appears in the evaluated spec text.

    The guarded recipient pass (a second Tau step with i12 = recipient) runs
    only on a True here, so the common case -- a recipient with no guarded
    unit -- costs no extra step. A False positive (the key named in a comment
    or in another account's whitelist) costs one extra step and cannot change
    a verdict: a unit that does not guard on the recipient yields allow in
    the recipient pass, exactly as in the sender pass. A False negative needs
    a rule that gates on i12 without naming the recipient's key literally
    (e.g. `i12[t] = i4[t]`); such rules are not recipient-evaluated, which
    docs/recipient-policy.md says outright.
    """
    if not spec_text or not recipient_pubkey:
        return False
    return re.search(re.escape(recipient_pubkey), spec_text, re.IGNORECASE) is not None


def recipient_pass_inputs(values: dict, recipient_pubkey: str) -> dict:
    """The guarded recipient pass: the transfer's inputs with i12 = recipient.

    Everything else is identical -- i3 still carries the sender key (the
    counterparty), i4 the recipient, i1 the amount, i17 the hold -- so a
    rule reads the same transfer from the recipient's side.
    """
    inputs = dict(values)
    inputs[tau_defs.SENDER_PUBKEY_STREAM_INDEX] = (
        "{ #x" + str(recipient_pubkey).lower() + " }:bv[384]"
    )
    return inputs


def instant_inputs(values: dict) -> dict:
    """The same inputs with the hold forced to 0: "this transfer, instant"."""
    inputs = dict(values)
    inputs[tau_defs.HOLD_STREAM_INDEX] = "0"
    return inputs


# --- The recipient clause verdict ------------------------------------------

def evaluate_recipient_clause(body, values: dict, *, pool: str, timeout,
                              hold: int) -> Tuple[str, Optional[int], str]:
    """(verdict, cap, detail) for the recipient's o5 clause on one transfer.

    `values` is the per-transfer input map (i17 = hold). Verdicts:
      * "allow" -- no clause, or the clause allows;
      * "policy_block" -- the clause blocks for a reason other than the hold;
      * "cap_block" -- the clause blocks this park but allows the identical
        transfer at hold 0, so the hold caused the block (the discriminator).
    `cap` is the max-hold constant the body states in a documented form when
    the verdict is "cap_block", else None. Evaluator loss propagates, as on
    the sender side: it says nothing about the transfer.
    """
    if not body:
        return "allow", None, ""
    blocked, detail = sender_policy.clause_blocks(
        body, values, pool=pool, timeout=timeout
    )
    if not blocked:
        return "allow", None, detail
    if hold and hold > 0:
        instant_blocked, _ = sender_policy.clause_blocks(
            body, instant_inputs(values), pool=pool, timeout=timeout
        )
        if not instant_blocked:
            return "cap_block", extract_hold_cap(body), detail
    return "policy_block", None, detail


# --- The max-hold constant, for the refusal message -------------------------
#
# Best-effort text analysis of the DOCUMENTED cap forms only. A rule that
# states its cap another way still gets the RECIPIENT_MAX_HOLD reason (the
# discriminator proves the hold caused the block); it just does not get the
# cap value in the message.

def _literal(suffix: str) -> str:
    # A bv literal: `{ #x... }` or `{ N }`, hex or decimal. Group names carry
    # the suffix because `re` forbids defining one name twice in a pattern.
    return (
        r"\{\s*(?:#x(?P<hex" + suffix + r">[0-9a-fA-F]+)"
        r"|(?P<dec" + suffix + r">\d+))\s*\}"
    )


_I17 = r"\bi17\s*\[\s*t\s*\]\s*(?::\s*bv\s*\[\s*\d+\s*\])?"

# `i17 > N` / `i17 >= N` (cap N / N-1) and the flipped `N < i17` / `N <= i17`.
_EXCEEDS_RE = re.compile(
    _I17 + r"\s*(?P<op>>=|>)\s*" + _literal("1")
    + r"|"
    + _literal("2") + r"\s*(?::\s*bv\s*\[\s*\d+\s*\])?\s*(?P<op2><=|<)\s*" + _I17,
    re.IGNORECASE,
)

_O5_ALLOW = (
    r"o5\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*24\s*\]\s*=\s*"
    r"\{\s*(?:#x0*1|1)\s*\}\s*(?::\s*bv\s*\[\s*24\s*\])?"
)
_O5_BLOCK = (
    r"o5\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*24\s*\]\s*=\s*"
    r"\{\s*(?:#x0*0|0)\s*\}\s*(?::\s*bv\s*\[\s*24\s*\])?"
)

# `(i17 <= N) ? allow : block` (cap N) and `(i17 < N) ? allow : block`
# (cap N-1), plus the flipped `N >= i17` / `N > i17` spellings.
_TERNARY_RE = re.compile(
    r"(?:" + _I17 + r"\s*(?P<op><=|<)\s*" + _literal("1")
    + r"\s*(?::\s*bv\s*\[\s*\d+\s*\])?"
    + r"|" + _literal("2")
    + r"\s*(?::\s*bv\s*\[\s*\d+\s*\])?\s*(?P<op2>>=|>)\s*" + _I17 + r")"
    + r"\s*\)?\s*\?\s*\(?\s*" + _O5_ALLOW
    + r"\s*\)?\s*:\s*\(?\s*" + _O5_BLOCK,
    re.IGNORECASE,
)

# The recipient's guarded unit: its key compared against i12, either way
# round. Scoping the search to this unit is what stops another account's cap
# being reported as this recipient's.
_GUARD_WINDOW_CHARS = 8192


def _owner_unit_window(text: str, owner_pubkey: str) -> Optional[str]:
    key = re.escape(owner_pubkey)
    guard = re.compile(
        r"\bi12\s*\[\s*t\s*\]\s*(?::\s*bv\s*\[\s*\d+\s*\])?\s*=\s*"
        r"\{\s*#x" + key + r"\s*\}"
        r"|"
        r"\{\s*#x" + key + r"\s*\}\s*(?::\s*bv\s*\[\s*\d+\s*\])?\s*=\s*"
        r"\bi12\s*\[\s*t\s*\]",
        re.IGNORECASE,
    )
    match = guard.search(text)
    if match is None:
        return None
    return text[match.start():match.start() + _GUARD_WINDOW_CHARS]


def _literal_value(match) -> Optional[int]:
    for suffix in ("1", "2"):
        hex_part = match.group("hex" + suffix)
        if hex_part:
            return int(hex_part, 16)
        dec_part = match.group("dec" + suffix)
        if dec_part:
            return int(dec_part)
    return None


def extract_hold_cap(text: str, owner_pubkey: Optional[str] = None) -> Optional[int]:
    """The max-hold constant a policy states, or None when it states none
    in a documented form.

    With `owner_pubkey` (guarded mode: `text` is the whole spec) the search
    is scoped to the owner's own guarded unit; without it (clause mode:
    `text` is the one clause body) the whole text is searched. A negative
    result is never reported: `i17 >= 0` blocks plain transfers too, so the
    discriminator never calls this a cap block in the first place.
    """
    if not text:
        return None
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(text)
    if owner_pubkey:
        scrubbed = _owner_unit_window(scrubbed, owner_pubkey)
        if scrubbed is None:
            return None

    match = _EXCEEDS_RE.search(scrubbed)
    if match is not None:
        value = _literal_value(match)
        if value is not None:
            op = match.group("op") or match.group("op2")
            cap = value if op in (">", "<") else value - 1
            return cap if cap >= 0 else None

    match = _TERNARY_RE.search(scrubbed)
    if match is not None:
        value = _literal_value(match)
        if value is not None:
            op = match.group("op") or match.group("op2")
            cap = value if op in ("<=", ">=") else value - 1
            return cap if cap >= 0 else None
    return None


# --- Refusal text (shared, so admission and apply say the same thing) ------

def policy_refusal_text(recipient_pubkey: str) -> str:
    """The generic recipient-policy refusal (allow-list, amount, ...)."""
    return (
        f"rejected by recipient policy (o5): recipient "
        f"{str(recipient_pubkey)[:16]}... does not accept this transfer"
    )


def cap_refusal_text(recipient_pubkey: str, hold: int, hold_unit: str,
                     cap: Optional[int]) -> str:
    """The RECIPIENT_MAX_HOLD refusal, carrying R's cap when known."""
    unit_word = "seconds" if hold_unit == HOLD_UNIT_SECONDS else "blocks"
    who = str(recipient_pubkey)[:16] + "..."
    if cap is None:
        return (
            f"RECIPIENT_MAX_HOLD: recipient {who} caps how long a payment to "
            f"it may be held; this park would be held {hold} {unit_word}"
        )
    field = cap_detail_field(hold_unit)
    return (
        f"RECIPIENT_MAX_HOLD: recipient {who} accepts payments held for up "
        f"to {cap} {unit_word} ({field}={cap}); this park would be held "
        f"{hold} {unit_word}"
    )
