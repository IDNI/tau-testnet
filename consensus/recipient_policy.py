"""The recipient's own o5 clause judging the payments made TO it.

Every call site (apply, mempool admission) goes through here, for the same
reason `consensus/sender_policy.py` exists: the inputs, the encoding of the
receive stream and the failure mapping cannot drift apart between the two
paths, or admission and the block disagree about the same transaction.

The one thing that changes between the two passes is `i12`:

* the sender pass feeds `i12 = the sender`, so the sender's clause judges the
  payment it starts;
* the recipient pass feeds `i12 = the recipient`, so the recipient's clause --
  the same, single o5 unit per account -- judges the payment it receives.

`i17` (node-fed, bv[64]) tells a clause WHICH of the two payments it is judging
and how long the money would be held; see `tau_defs.RECEIVE_*`. A clause cannot
read `i12` (clause bodies are screened against it), so `i17` is the only way an
inbound rule can tell itself apart from an outbound one.
"""
from __future__ import annotations

import re

import tau_defs
from consensus import sender_policy
from consensus.retractable import KIND_HEIGHT

# Apply-side receipt reason. Admission carries the same strings in its message.
REASON_BLOCK = "recipient_policy_block"
REASON_MAX_HOLD = "RECIPIENT_MAX_HOLD"

# `i17[t]:bv[64] > { #x025a }:bv[64]` -- the shipped cap template. Extracted
# only to make a refusal printable ("at most 600 seconds"); enforcement never
# depends on it. A clause that computes its cap some other way is still
# enforced, the message then names the hold alone.
_CAP_RE = re.compile(
    r"i17\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*64\s*\]\s*(>=|>)\s*"
    r"(?:\{\s*(?:#x([0-9a-fA-F]+)|(\d+))\s*\}|(\d+))"
)


def _mention_re(streams) -> re.Pattern:
    return re.compile(r"\bi(?:%s)\b" % "|".join(str(i) for i in streams))


def mentions_receive_stream(body: str) -> bool:
    """True when the clause reads `i17` and therefore opts into inbound judging.

    A clause written before this feature exists says nothing about how its owner
    wants to be PAID, and must not acquire that meaning silently: a policy that
    merely reads `i3` (or `i1`) for outbound rules would otherwise start refusing
    inbound payments the moment the node upgrades. Reading `i17` is the opt-in,
    and it is the only thing a clause can read to tell the two passes apart.
    """
    from consensus.rule_offers import strip_clause_comments

    streams = tau_defs.active_receive_fact_streams()
    return bool(_mention_re(streams).search(strip_clause_comments(body or "")))


def hold_seconds_value(hold_seconds: int) -> int:
    """`i17` for an incoming payment released `hold_seconds` after the block."""
    return tau_defs.RECEIVE_FINAL + int(hold_seconds)


def hold_blocks_value(hold_blocks: int) -> int:
    """`i17` for an incoming payment released `hold_blocks` blocks ahead."""
    return tau_defs.RECEIVE_BLOCKS_BASE + int(hold_blocks)


def plain_transfer_value() -> int:
    """`i17` for an incoming payment that is final in this block."""
    return tau_defs.RECEIVE_FINAL


def park_value(release_kind: str, release_at: int, height: int, timestamp: int) -> int:
    """`i17` for a park: the hold in the park's own unit, never below 1.

    A park whose release point is not in the future cannot exist (`validate_park_shape`
    refuses it), and the saturation keeps a clock that moved backwards from
    wrapping into an enormous hold.
    """
    if release_kind == KIND_HEIGHT:
        return hold_blocks_value(max(1, int(release_at) - int(height)))
    return hold_seconds_value(max(1, int(release_at) - int(timestamp)))


def describe(value: int) -> str:
    """Human sentence for an `i17` value, used in logs and refusal messages."""
    value = int(value)
    if value == tau_defs.RECEIVE_OUTBOUND:
        return "the owner sends this payment"
    if value == tau_defs.RECEIVE_FINAL:
        return "the payment is final in this block"
    if value > tau_defs.RECEIVE_BLOCKS_BASE:
        blocks = value - tau_defs.RECEIVE_BLOCKS_BASE
        return f"held {blocks} block{'s' if blocks != 1 else ''}"
    seconds = value - tau_defs.RECEIVE_FINAL
    return f"held {seconds} second{'s' if seconds != 1 else ''}"


def cap_description(body: str) -> str:
    """Best-effort reading of the cap a clause enforces: '' when unrecognised."""
    from consensus.rule_offers import strip_clause_comments

    match = _CAP_RE.search(strip_clause_comments(body or ""))
    if not match:
        return ""
    op = match.group(1)
    literal = match.group(2) or match.group(3) or match.group(4)
    if literal is None:
        return ""
    try:
        bound = int(literal, 16) if match.group(2) else int(literal)
    except ValueError:
        return ""
    # `i17 > X` allows i17 <= X, and i17 == 1 + hold, so the cap is X - 1
    # (`>=` is off by one the other way and is reported as-is).
    cap = bound if op == ">=" else bound - 1
    if cap >= tau_defs.RECEIVE_BLOCKS_BASE:
        return f"at most {cap - tau_defs.RECEIVE_BLOCKS_BASE} blocks"
    return f"at most {cap} second{'s' if cap != 1 else ''}"


def judge(clause_for, recipient: str, inputs: dict, value: int, *,
          pool: str, timeout=None, facts=None) -> tuple[bool, str, str]:
    """(blocked, reason, message) for one payment judged by the RECIPIENT.

    Two things keep this from changing what already-deployed policy means:

    * an account with no clause on o5 never reaches the evaluator, and
    * a clause that does not read `i17` never does either (`mentions_receive_stream`),
      so only a policy written for the receiving side is judged on it.
    """
    # The registry is keyed by the lowercase hex form, and the literal below must
    # be the same bytes, so normalise once here rather than at every call site: a
    # mixed-case recipient must not be able to slip past its own clause.
    recipient = str(recipient).strip().lower()
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    if not isinstance(body, str) or not body:
        return False, "", ""
    if not mentions_receive_stream(body):
        return False, "", ""
    values = dict(inputs or {})
    values[tau_defs.RECEIVE_STREAM_INDEX] = str(int(value))
    # The remaining payment facts (bounty 03 parts 3-5). They are fed as 0 while
    # `RECEIVE_FACTS_ACTIVE` is False, which is the honest value: no payment
    # carries a condition record yet, and a clause that reads them is refused at
    # deploy in that state, so nothing can be judged against a fake zero.
    provided = dict(facts or {})
    for idx in tau_defs.active_receive_fact_streams():
        if idx == tau_defs.RECEIVE_STREAM_INDEX:
            continue
        values[idx] = str(int(provided.get(idx, 0)))
    # The payer's approval slots belong to the payer's axis: a co-signature the
    # SENDER collected must never satisfy the recipient's rule. Zeroed rather
    # than removed so every clause sees the same shape of input map.
    for slot in tau_defs.approval_slot_indices():
        values[slot] = "0"
    # The recipient's own key, in the same literal shape every other pubkey
    # stream is fed, so one guarded unit per account serves both directions.
    values[tau_defs.SENDER_KEY_STREAM_INDEX] = (
        "{ #x" + recipient + " }:bv[384]"
    )
    blocked, o5 = sender_policy.clause_blocks(body, values, pool=pool, timeout=timeout)
    if not blocked:
        return False, "", ""
    hold = describe(value)
    cap = cap_description(body)
    reason = REASON_MAX_HOLD if int(value) > tau_defs.RECEIVE_FINAL else REASON_BLOCK
    message = f"the recipient's own policy clause refused this payment ({hold})"
    if cap:
        message += f"; the recipient accepts payments {cap}"
    if reason == REASON_MAX_HOLD:
        message = f"{REASON_MAX_HOLD}: " + message
    return True, reason, message + f". Policy output: {o5}"
