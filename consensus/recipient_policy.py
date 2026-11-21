"""The recipient's o5 clause as a second, independent block condition.

Every payment path (apply, admission) goes through here so the inputs, the
failure mapping and the reason discrimination cannot drift apart -- the same
discipline consensus/sender_policy.py imposes on the sender's clause.

Model (issues #47/#76): an account has ONE o5 clause. It is evaluated once
in the sender role (consensus.sender_policy, the owner is the sender) and
once here in the recipient role (the owner is i4, the counterparty sender
is i3 -- clause bodies may not reference i12). A transfer lands only when
both evaluations allow it. A recipient with no clause, or a clause whose
conditions do not fire, allows everything: the neutral default.

Fail-closed, throughout:
  * a recipient clause that does not build, or that the engine refuses to
    step, blocks (sender_policy.clause_blocks already maps those to a
    block; loss of the evaluator itself propagates, as on the sender path);
  * the hold streams (tau_defs i17/i27) are host-fed into every clause
    evaluation AFTER the sender's custom inputs merge, so a sender cannot
    smuggle a fake hold into either verdict;
  * a hold cap is measured, never parsed out of rule text: when a block is
    hold-related, the cap is found by re-evaluating the clause over hold
    values (binary search), so the reported cap is the largest hold this
    recipient's policy actually accepts for this transfer.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional

import tau_defs
from consensus import sender_policy

_SECONDS = tau_defs.RECIPIENT_HOLD_SECONDS_STREAM_INDEX
_BLOCKS = tau_defs.RECIPIENT_HOLD_BLOCKS_STREAM_INDEX


@dataclass(frozen=True)
class RecipientVerdict:
    blocked: bool
    reason: Optional[str] = None        # tau_defs.REASON_* when blocked
    detail: str = ""                    # the clause's o5 text, when blocked
    cap: Optional[int] = None           # measured cap, for the MAX_HOLD reason
    cap_unit: Optional[str] = None      # "seconds" | "blocks"

    @property
    def max_hold(self) -> dict:
        """The cap as a wallet-facing dict, e.g. {"max_hold_seconds": 600}."""
        if self.cap is None or self.cap_unit is None:
            return {}
        return {f"max_hold_{self.cap_unit}": self.cap}


ALLOWED = RecipientVerdict(blocked=False)


def with_hold(values: dict, hold_seconds: int = 0, hold_blocks: int = 0) -> dict:
    """A copy of a per-transfer input map carrying the hold streams.

    Fed into clause evaluations only -- never into the shared session map --
    and set here, after every merge, so no sender-supplied custom input can
    shadow the host's values.
    """
    out = dict(values or {})
    out[_SECONDS] = str(max(0, int(hold_seconds)))
    out[_BLOCKS] = str(max(0, int(hold_blocks)))
    return out


def park_hold(park, height: int, timestamp: int) -> tuple:
    """(hold_seconds, hold_blocks) a retractable park carries right now.

    Exactly one component is positive: a park is time-based or height-based
    (consensus.retractable), and the other unit's stream stays 0, so a cap
    written against one unit sees the other unit's parks as a positive hold
    on the other stream rather than as 0.
    """
    from consensus.retractable import KIND_TIME

    if int(park.kind) == KIND_TIME:
        return max(0, int(park.release_at) - int(timestamp)), 0
    return 0, max(0, int(park.release_at) - int(height))


def _evaluate(body, values, hold_seconds, hold_blocks, *, pool, timeout):
    return sender_policy.clause_blocks(
        body, with_hold(values, hold_seconds, hold_blocks),
        pool=pool, timeout=timeout,
    )


def recipient_verdict(
    clause_for: Callable, recipient: str, values: dict, *,
    pool: str, timeout, hold_seconds: int = 0, hold_blocks: int = 0,
    sender: str = "",
) -> RecipientVerdict:
    """The recipient-role verdict for one transfer.

    `clause_for(pubkey, stream_index)` resolves the recipient's registered
    clause, exactly as the sender path resolves the sender's. `values` is
    the per-transfer input map the sender clause was judged on. A
    self-transfer is never gated here: the owner's clause already judged
    it in the sender role.
    """
    if not tau_defs.RECIPIENT_POLICY_ACTIVE or not recipient:
        return ALLOWED
    if sender and str(recipient).lower() == str(sender).lower():
        return ALLOWED
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    if not body:
        return ALLOWED

    blocked, detail = _evaluate(
        body, values, hold_seconds, hold_blocks, pool=pool, timeout=timeout
    )
    if not blocked:
        return ALLOWED

    hold_seconds = max(0, int(hold_seconds))
    hold_blocks = max(0, int(hold_blocks))
    if hold_seconds == 0 and hold_blocks == 0:
        # No hold to blame: an allow-list or other policy refusal.
        return RecipientVerdict(
            blocked=True, reason=tau_defs.REASON_RECIPIENT_POLICY_BLOCK,
            detail=detail,
        )

    # Hold-related? Zeroing the hold must turn the verdict into an allow.
    # (An evaluation failure here still reads as blocked -- fail closed --
    # and is then reported as a plain policy refusal, never as a cap.)
    still_blocked, _ = _evaluate(body, values, 0, 0, pool=pool, timeout=timeout)
    if still_blocked:
        return RecipientVerdict(
            blocked=True, reason=tau_defs.REASON_RECIPIENT_POLICY_BLOCK,
            detail=detail,
        )

    # Measure the cap in the park's native unit: the largest hold that this
    # clause still allows for this transfer. Deterministic across nodes --
    # same body, same inputs, same evaluator.
    if hold_seconds > 0:
        unit, total = "seconds", hold_seconds
    else:
        unit, total = "blocks", hold_blocks
    lo, hi = 0, total  # lo allows (0 was just measured), hi blocks
    while hi - lo > 1:
        mid = (lo + hi) // 2
        mid_blocked, _ = _evaluate(
            body, values,
            mid if unit == "seconds" else 0,
            mid if unit == "blocks" else 0,
            pool=pool, timeout=timeout,
        )
        if mid_blocked:
            hi = mid
        else:
            lo = mid
    return RecipientVerdict(
        blocked=True, reason=tau_defs.REASON_RECIPIENT_MAX_HOLD,
        detail=detail, cap=lo, cap_unit=unit,
    )


# --- Plain-language clause templates -----------------------------------------
# The bodies below are what the wallet/CLI installs when a user says "only
# accept from senders I approve" or "only accept instant payments". Each
# condition is guarded by (i4 = ME): the clause is also evaluated in the
# sender role, where i4 is the counterparty, and the guard keeps the
# recipient conditions from firing on the owner's own sends.

def _key(pubkey: str) -> str:
    return "{ #x" + str(pubkey).strip().lower() + " }:bv[384]"


def _o5(value: int) -> str:
    return "(o5[t]:bv[24] = { #x%06x }:bv[24])" % value


def _hold_violation(max_hold_seconds, max_hold_blocks) -> Optional[str]:
    """The condition under which a hold breaks the cap, or None for no cap.

    An unset unit caps at 0: a seconds-only cap refuses height parks
    outright (fail closed) instead of reading them as a 0-second hold.
    """
    if max_hold_seconds is None and max_hold_blocks is None:
        return None
    seconds_cap = 0 if max_hold_seconds is None else int(max_hold_seconds)
    blocks_cap = 0 if max_hold_blocks is None else int(max_hold_blocks)
    return (
        "(i17[t]:bv[64] > { #x%x }:bv[64] || i27[t]:bv[64] > { #x%x }:bv[64])"
        % (seconds_cap, blocks_cap)
    )


def recipient_clause_body(
    owner_pubkey: str,
    allowed_senders=(),
    max_hold_seconds=None,
    max_hold_blocks=None,
) -> str:
    """A clause body enforcing the given recipient controls, and nothing else.

    `allowed_senders`: the only sender pubkeys whose payments may land.
    `max_hold_seconds` / `max_hold_blocks`: the longest park that may land;
    leave both None for no hold cap, set one to cap that unit (the other
    unit is then refused outright), set a cap of 0 on both for
    instant-only ("paid means final").
    """
    violations = []
    senders = [str(s).strip().lower() for s in (allowed_senders or ())]
    if senders:
        listed = " || ".join(
            "i3[t]:bv[384] = %s" % _key(s) for s in senders
        )
        violations.append("!(%s)" % listed)
    hold = _hold_violation(max_hold_seconds, max_hold_blocks)
    if hold is not None:
        violations.append(hold)
    if not violations:
        # No controls requested: the frozen neutral body ("no opinion").
        return "(o5[t]:bv[24] = { #x000001 }:bv[24])"
    condition = "(i4[t]:bv[384] = %s && (%s))" % (
        _key(owner_pubkey), " || ".join(violations),
    )
    return "( %s ? %s : %s )" % (condition, _o5(0), _o5(1))


def allowlist_clause_body(owner_pubkey: str, allowed_senders) -> str:
    """"Only accept payments from senders I approve." """
    return recipient_clause_body(owner_pubkey, allowed_senders=allowed_senders)


def instant_only_clause_body(owner_pubkey: str) -> str:
    """"Only accept instant, final payments" -- every park is refused."""
    return recipient_clause_body(
        owner_pubkey, max_hold_seconds=0, max_hold_blocks=0
    )


def max_hold_clause_body(owner_pubkey: str, *, seconds=None, blocks=None) -> str:
    """"Accept parks held up to a cap" (one unit; the other is refused)."""
    return recipient_clause_body(
        owner_pubkey, max_hold_seconds=seconds, max_hold_blocks=blocks
    )
