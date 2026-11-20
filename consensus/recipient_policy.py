"""The recipient's own o5 policy as a second, independent block condition.

Issues #47 (recipient-side o5) and #76 (recipient-side max-hold cap).

A transfer to account R is admitted (and applied) only if BOTH the sender's
o5 policy and R's o5 policy allow it. The two modes share this module:

* Clause mode: R's registered o5 clause, evaluated on the same transfer
  inputs as the sender's clause. The counterparty is readable on i3 (sender
  id) and the amount on i1; the hold length on i17. A clause never sees i12
  (`clause_body_v1` rejects it: a clause is evaluated only for its owner).
* Guarded mode: a second evaluation pass with i12 set to the recipient, so
  R's unit -- guarded on its own key exactly like the sender's -- can say no.
  The step itself lives at the call sites (admission, block apply); the
  hold computation, the cap extraction and the gating scan live here.

Every helper is pure and deterministic: admission and apply must agree for
the same state and transaction, exactly as the sender-side o5 does.
"""
from __future__ import annotations

import re
from typing import Optional

import tau_defs
from consensus import sender_policy
from consensus.retractable import KIND_HEIGHT, KIND_TIME
from tau_speculation import _SESSION_DEFAULT

# Canonical hold-cap shapes, in the order they are tried. The literal must be
# a bv[64] value: the hold length is fed at that width, and a cap written at
# another width would pin process-global stream typing. The literal group is
# non-capturing on the outside so the `|` inside it cannot leak into the
# shape alternation (a bare literal must never match on its own).
_CAP_LIT_RE = r"(?:\{\s*#x([0-9a-fA-F]+)\s*\}:\s*bv\[\s*64\s*\]|\{\s*([0-9]+)\s*\}:\s*bv\[\s*64\s*\])"
_CAP_RE = re.compile(
    r"i17\s*\[\s*t\s*\]\s*:\s*bv\[\s*64\s*\]\s*"
    r"(<=|<|>=|>)\s*" + _CAP_LIT_RE
    + r"|"
    + _CAP_LIT_RE +
    r"\s*(<=|<|>=|>)\s*i17\s*\[\s*t\s*\]\s*:\s*bv\[\s*64\s*\]"
)


def _cap_literal(match: re.Match) -> Optional[int]:
    """The integer a cap-comparison literal stands for, or None.

    Groups 2/3 are the literal in the ``i17 <op> {N}`` shape, groups 4/5
    in the ``{N} <op> i17`` shape.
    """
    hex_digits = match.group(2) or match.group(4)
    dec_digits = match.group(3) or match.group(5)
    try:
        if hex_digits is not None:
            return int(hex_digits, 16)
        if dec_digits is not None:
            return int(dec_digits, 10)
    except ValueError:
        return None
    return None


def hold_length_for_transfer(*, kind: Optional[int] = None,
                             release_at: Optional[int] = None,
                             height: int, timestamp: int) -> int:
    """Hold length of the transfer being judged, in the park's native unit.

    0 for a plain transfer. A time-kind park holds ``release_at_time`` minus
    the block time (seconds); a height-kind park holds ``release_at_height``
    minus the block height (blocks). The floor at 0 keeps a park whose
    release point has passed (refused elsewhere by shape) from feeding a
    negative hold into an unsigned comparison.
    """
    if kind is None or release_at is None:
        return 0
    if kind == KIND_TIME:
        return max(0, int(release_at) - int(timestamp))
    if kind == KIND_HEIGHT:
        return max(0, int(release_at) - int(height))
    return 0


def extract_hold_cap(rule_text: Optional[str]) -> Optional[int]:
    """Largest hold a canonical cap comparison allows, or None.

    Reads the cap out of the rule text so a refusal can carry it ("Third only
    accepts payments held for up to 10 minutes"). Only the canonical shapes
    count: ``i17[t]:bv[64] <= {N}:bv[64]`` (and the ``<`` / ``>`` / ``>=``
    mirrors, literal on either side). Several different caps, or a cap below
    zero, is ambiguous and returns None -- the refusal then carries the
    refused hold length instead of a cap number.

    Best-effort by design: the comparison alone cannot say which branch it
    guards, so the extractor reads the canonical wallet-template orientation
    (allow when the hold is small, block when it is large). A rule written
    the other way round still refuses correctly -- only the reported cap
    could be wrong, never the verdict.
    """
    if not rule_text:
        return None
    from consensus.rule_offers import strip_clause_comments

    scrubbed = strip_clause_comments(rule_text)
    caps = set()
    for match in _CAP_RE.finditer(scrubbed):
        op = match.group(1) or match.group(6)
        # A literal on the left mirrors the operator: `{N} >= i17` is
        # `i17 <= {N}`. The mapping below is for the i17-on-the-left shape.
        if match.group(6) is not None:
            op = {"<=": ">=", "<": ">", ">": "<", ">=": "<="}[op]
        value = _cap_literal(match)
        if value is None:
            continue
        if op == "<=":
            caps.add(value)
        elif op == "<":
            caps.add(value - 1)
        elif op == ">":
            caps.add(value)
        elif op == ">=":
            caps.add(value - 1)
    # A cap of -1 means a refuse-everything branch (`i17 < {0}`): the rule
    # has no meaningful cap to report.
    if -1 in caps or len(caps) != 1:
        return None
    cap = caps.pop()
    return cap if cap >= 0 else None


def recipient_may_have_guarded_unit(rules_text: Optional[str],
                                    recipient_pubkey: str) -> bool:
    """True when the application-rules text may hold a guarded unit for R.

    Substring on the bare 96-hex key: a guarded unit must name its owner's
    key, so a miss is exact. A hit elsewhere in the text (someone's whitelist
    naming R as a recipient) only costs an extra evaluation step, never a
    wrong verdict.
    """
    if not rules_text or not recipient_pubkey:
        return False
    key = str(recipient_pubkey).strip().lower()
    if len(key) != 96 or any(c not in "0123456789abcdef" for c in key):
        return False
    return key in str(rules_text).lower()


def recipient_clause_blocks(clause_for, recipient: str, values: dict, *,
                            pool: str,
                            timeout=_SESSION_DEFAULT) -> tuple[bool, str]:
    """(blocked, detail) for the recipient's own o5 clause on one transfer's
    inputs. Mirrors the sender side: an absent clause allows everything."""
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    return sender_policy.clause_blocks(
        body, values, pool=pool, timeout=timeout,
    )


def recipient_unit_hold_cap(rules_text: str, recipient: str) -> Optional[int]:
    """The hold cap in the recipient's guarded unit(s), when exactly one can be read.

    Best-effort message detail only: the refusal itself never depends on it.
    Units are the application-rules lines; a unit names its guarded account by
    its pubkey, so only units containing the recipient's key are read.
    """
    if not rules_text:
        return None
    key = str(recipient).strip().lower()
    caps = set()
    for unit in str(rules_text).split("\n"):
        if key in unit.lower():
            cap = extract_hold_cap(unit)
            if cap is not None:
                caps.add(cap)
    return caps.pop() if len(caps) == 1 else None


def recipient_clause_body(clause_for, recipient: str) -> Optional[str]:
    """The recipient's registered o5 clause body, or None."""
    body = clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    return body if isinstance(body, str) and body else None


def clause_block_is_hold_only(clause_for, recipient: str, values: dict, *,
                              pool: str,
                              timeout=_SESSION_DEFAULT) -> bool:
    """True when the recipient's clause blocks these inputs but allows the
    same transfer with a zero hold: the block is due to the hold length, not
    to the sender or the amount. Only meaningful when the clause already
    blocked; re-evaluates once with i17 forced to 0."""
    probe = dict(values or {})
    probe[tau_defs.HOLD_LENGTH_STREAM_INDEX] = "0"
    blocked, _ = recipient_clause_blocks(
        clause_for, recipient, probe, pool=pool, timeout=timeout,
    )
    return not blocked
