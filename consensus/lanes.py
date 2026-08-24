"""Transaction lane classification.

Rule-bearing transactions and coin transfers have wildly different costs. A
coin transfer needs one cheap Tau step (single-digit milliseconds); applying a
rule rebuilds the interpreter, whose cost grows steeply with the complexity of
the accumulated specification -- seconds at a handful of rules, and past the
COMM_TIMEOUT watchdog threshold beyond that. Both kinds share one mempool
ordering key (`estimated_fee DESC`) and one process-global Tau lock, so a burst
of rule work delays every queued transfer behind it.

Lanes separate the two so transfers keep flowing: the mempool selects them
under independent quotas, evicts within a lane rather than across lanes, and
the block builder caps how much rule work one block may carry.

Fee cannot drive this split. A rule emits its own `o8` user fee, so
`estimated_fee` is self-declared and a rule transaction can price itself to the
front of the queue. Quotas are the only sound mechanism.

`classify_lane` is a PURE function of the transaction. The `mempool.lane`
column is a materialised cache of it for indexing, never an authority.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

LANE_FAST = 0
LANE_SLOW = 1

LANE_NAMES = {LANE_FAST: "fast", LANE_SLOW: "slow"}

# Types whose apply path routes text through i0 and rebuilds the interpreter.
# `rule_offer` is slow because admission compiles the offered clause;
# `rule_offer_reject` is fast because it only resolves a set membership.
SLOW_TX_TYPES = frozenset({
    "rule_offer",
    "rule_offer_accept",
    "consensus_rule_update",
})


def classify_lane(tx: Optional[Dict[str, Any]]) -> int:
    """Lane for a parsed transaction dict.

    A `user_tx` carrying BOTH a rule (`operations["0"]`) and transfers
    (`operations["1"]`) is SLOW: the BLS signature covers the whole payload, so
    it cannot be split, and the rule half dominates the cost.

    A whitespace-only `operations["0"]` is fast, matching the `if rule_text:`
    check on the admission path -- otherwise an empty rule key would silently
    demote a pure transfer into the slow lane.
    """
    if not isinstance(tx, dict):
        return LANE_FAST

    tx_type = tx.get("tx_type") or "user_tx"
    if tx_type in SLOW_TX_TYPES:
        return LANE_SLOW
    if tx_type != "user_tx":
        return LANE_FAST

    operations = tx.get("operations")
    if not isinstance(operations, dict):
        return LANE_FAST
    rule_text = operations.get("0")
    if isinstance(rule_text, str) and rule_text.strip():
        return LANE_SLOW
    return LANE_FAST


def classify_lane_payload(payload: Optional[str]) -> int:
    """Lane for a raw mempool payload blob. Tolerant of junk: an unparseable
    row is treated as fast so a malformed payload can never claim slow-lane
    quota (it is dropped by the block builder anyway)."""
    import json

    if not isinstance(payload, str):
        return LANE_FAST
    text = payload.strip()
    # Historical mempool rows were stored with a "json:" prefix.
    if text.startswith("json:"):
        text = text[len("json:"):]
    try:
        parsed = json.loads(text)
    except Exception:
        return LANE_FAST
    return classify_lane(parsed)


def is_rule_bearing(tx: Optional[Dict[str, Any]]) -> bool:
    """True when the transaction carries Tau rule text needing compilation."""
    return classify_lane(tx) == LANE_SLOW
