"""Recipient-side policy: an account's o5 clause judging payments made TO it.

A clause that reads the receive stream (`tau_defs.RECEIVE_STREAM_INDEX`, i17) is
evaluated a second time for every payment whose recipient is its owner, after
the sender's own checks, on the same transfer inputs with the approval slots
emptied and i17 set (see tau_defs for the values). A clause that does not read
i17 is never asked, so a clause written before the feature keeps its meaning.

Every call site (apply, admission) goes through here so the inputs and the
failure mapping cannot drift apart, the way `sender_policy` does it for the
sender's side.
"""
from __future__ import annotations

import re
from functools import lru_cache
from typing import Callable, List, Optional, Tuple

import tau_defs

RECIPIENT_POLICY_BLOCK_REASON = "recipient_policy_block"

_RECEIVE = tau_defs.RECEIVE_STREAM_INDEX
_WIDTH = tau_defs.RECEIVE_STREAM_BV_WIDTH
_MENTION_RE = re.compile(r"\bi%d\b" % _RECEIVE)
_TYPED_TAIL_RE = re.compile(r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*%d\s*\]" % _WIDTH)


def recipient_policy_active(tip_view) -> bool:
    """Whether the receive stream is reserved and fed at the tip.

    Requires a genuine `True`, for the reason `approval_slots_active` does: a
    partial or mocked view answers something truthy for an attribute it was
    never given, and running as if a consensus feature were on is the kind of
    thing that passes every test and then diverges on a live chain.
    """
    return getattr(tip_view, "recipient_policy_active", False) is True


@lru_cache(maxsize=1024)
def reads_receive_stream(body: str) -> bool:
    """Whether a clause body reads i17 outside a comment.

    This alone decides whether the clause is asked about incoming payments: a
    pure function of the registered text, so every node agrees.
    """
    from consensus.rule_offers import strip_clause_comments

    return bool(_MENTION_RE.search(strip_clause_comments(body or "")))


def screen_receive_stream_width(body: str) -> Optional[str]:
    """None when every mention of i17 is typed bv[64], else the reason.

    Reject-unless-annotated, like the approval slots: stream typing is
    process-global and sticky, so one clause typing i17 at another width (or not
    at all, which lets the engine infer one) would fail the build of every other
    clause that reads it.
    """
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(body or "")
    for match in _MENTION_RE.finditer(scrubbed):
        if not _TYPED_TAIL_RE.match(scrubbed, match.end()):
            return (
                f"every mention of the receive stream i{_RECEIVE} must be written "
                f"i{_RECEIVE}[t]:bv[{_WIDTH}]"
            )
    return None


def audit_receive_stream_collisions(spec_texts) -> List[str]:
    """Reasons the receive stream cannot safely be activated. Empty means clear.

    Before activation i17 is an ordinary custom input stream, so a deployed
    rule or clause may already read it. Activating over one would turn that
    clause into a receive policy its owner never wrote, or type the stream at a
    second width. `spec_texts` is the same (label, text) corpus the approval
    slot audit takes: consensus rules, builtin rules, the application-rules
    accumulation and every stored clause body.
    """
    from consensus.rule_offers import strip_clause_comments

    findings: List[str] = []
    for label, text in spec_texts or ():
        if not isinstance(text, str) or not text.strip():
            continue
        if _MENTION_RE.search(strip_clause_comments(text)):
            findings.append(
                f"{label} already references i{_RECEIVE}; activating would turn it "
                f"into a receive policy or type the stream at a second width. "
                f"Replace or revoke it first"
            )
    return findings


def receive_inputs(values: dict, receive_value: int) -> dict:
    """The recipient's view of one transfer.

    The sender-pass input map, with the approval slots emptied (the sender's
    co-signers did not vote on behalf of the recipient) and i17 set.
    """
    out = dict(values or {})
    for slot in tau_defs.approval_slot_indices():
        if slot in out:
            out[slot] = "0"
    out[_RECEIVE] = str(int(receive_value))
    return out


def recipient_clause(clause_for, recipient: str) -> Optional[str]:
    """The recipient's clause body when it reads the receive stream, else None."""
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    if not isinstance(body, str) or not body or not reads_receive_stream(body):
        return None
    return body


_UNSET = object()


def recipient_blocks(clause_for, recipient: str, values: dict, receive_value: int,
                     *, pool: str, timeout=_UNSET) -> Tuple[bool, str]:
    """(blocked, detail) from the recipient's own clause for one incoming payment.

    (False, "") when the recipient has no clause or its clause does not read
    i17. A clause that cannot be built or stepped blocks, as on the sender's
    side, so every node reaches the same result.
    """
    body = recipient_clause(clause_for, recipient)
    if body is None:
        return False, ""
    from consensus import sender_policy

    # An omitted timeout means the evaluator's own default, as on the sender's side.
    kwargs = {} if timeout is _UNSET else {"timeout": timeout}
    return sender_policy.clause_blocks(
        body, receive_inputs(values, receive_value), pool=pool, **kwargs
    )


SECONDS = "seconds"
BLOCKS = "blocks"


def hold_seconds_of(receive_value: int) -> Optional[int]:
    """The hold in seconds an i17 value stands for; None when it has none
    (the owner's own payment, or a height-based park)."""
    value = int(receive_value)
    if value < tau_defs.RECEIVE_FINAL_NOW or value >= tau_defs.RECEIVE_HOLD_BLOCKS:
        return None
    return value - tau_defs.RECEIVE_FINAL_NOW


def hold_blocks_of(receive_value: int) -> Optional[int]:
    """The hold in blocks an i17 value stands for; None unless it is a
    height-based park."""
    value = int(receive_value)
    if value < tau_defs.RECEIVE_HOLD_BLOCKS:
        return None
    return value - tau_defs.RECEIVE_HOLD_BLOCKS


def hold_value(unit: str, length: int) -> int:
    """The i17 value of a hold of `length` in `unit`. A hold of no length is a
    payment that is final at once, in either unit."""
    if int(length) <= 0:
        return tau_defs.RECEIVE_FINAL_NOW
    if unit == BLOCKS:
        return tau_defs.receive_stream_value(hold_blocks=length)
    return tau_defs.receive_stream_value(length)


def _bisect(allows: Callable[[int], bool], unit: str, low: int, high: int) -> int:
    """The largest N in low..high-1 whose hold the clause accepts, given that it
    accepts `low` and refuses `high`."""
    while high - low > 1:
        mid = (low + high) // 2
        if allows(hold_value(unit, mid)):
            low = mid
        else:
            high = mid
    return low


def longest_hold(allows: Callable[[int], bool], unit: str,
                 refused: Optional[int], longest_window: int) -> int:
    """The longest hold in `unit` a clause accepts for one payment that it
    accepts when final at once.

    `allows(v)` answers whether the clause lets the payment through with
    i17 = v. `refused` is a length the clause is known to refuse, or None.
    The largest N in 0..`longest_window` whose hold it accepts, found by
    bisection (at most 24 evaluations for the 90 days in seconds, 18 for the
    window in blocks), where 0 means only a payment that is final at once.

    Both ends are answers of the clause itself: N was accepted and N + 1 was
    refused. For the message a wallet prints, never for a verdict: a clause need
    not be monotone in the hold, and then this is one boundary of several.
    """
    if refused is None or refused > longest_window:
        if allows(hold_value(unit, longest_window)):
            return longest_window
        refused = longest_window
    return _bisect(allows, unit, 0, int(refused))


def max_accepted_hold(allows: Callable[[int], bool], unit: str,
                      refused: Optional[int], longest_window: int) -> Optional[int]:
    """`longest_hold`, or None when the clause refuses the payment even with no
    hold: a refusal is then not about the hold."""
    if not allows(tau_defs.RECEIVE_FINAL_NOW):
        return None
    return longest_hold(allows, unit, refused, longest_window)


def accepted_holds(allows: Callable[[int], bool], receive_value: int, *,
                   seconds_window: int, blocks_window: int) -> Optional[dict]:
    """What a clause that refused an incoming park would take instead.

    None when it refuses the payment even final at once. For a time-based park
    `{"max_hold_seconds": N}`. For a height-based one `{"max_hold_blocks": N}`
    when the clause takes a height release at all; when it takes none, also its
    cap in seconds, so the payer learns which kind of release to use. At most
    about 27 evaluations either way.
    """
    if not allows(tau_defs.RECEIVE_FINAL_NOW):
        return None
    blocks = hold_blocks_of(receive_value)
    if blocks is None:
        return {"max_hold_seconds": longest_hold(
            allows, SECONDS, hold_seconds_of(receive_value), seconds_window)}
    if blocks > 1 and allows(hold_value(BLOCKS, 1)):
        return {"max_hold_blocks": _bisect(
            allows, BLOCKS, 1, min(blocks, blocks_window + 1))}
    return {
        "max_hold_blocks": 0,
        "max_hold_seconds": longest_hold(allows, SECONDS, None, seconds_window),
    }
