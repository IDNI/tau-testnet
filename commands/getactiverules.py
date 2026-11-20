"""The rules in force, read from the spec the engine runs (issue #42).

Usage: getactiverules [account] [height]

Answers from the canonical-spec snapshots recorded at block commit whenever
spec_revision advanced (consensus/active_rules.py) -- never from the
append-only accumulation gettaustate returns, whose text pointwise revision
can leave claiming rules that are no longer in force.

Without arguments: the latest snapshot (full effective spec text, its
sha256, spec_revision, height). With a height: the newest snapshot at or
before it; if every snapshot is later than the requested height, the
earliest snapshot is returned and BOTH heights are in the answer, so the
substitution is explicit. With an account: additionally the statements of
the effective spec guarded by that account (`account_rules`) and the
statements no single account can be attributed to (`unattributed`).
Statements guarded by exactly one other account are omitted.

When no snapshot exists yet (no rule-bearing block committed since this
view was introduced), the answer carries `available: false` rather than
substituting the accumulation text -- a truthful "not available" over a
plausible-looking answer derived from submitted text.
"""
import logging

import api_response
from consensus import active_rules

logger = logging.getLogger(__name__)


def _parse_args(parts):
    """Split the argument tail into (account, height); either may be None.

    A bare integer is a height; anything else is an account. Both orders
    are accepted.
    """
    account = None
    height = None
    for arg in parts:
        if arg.isdigit() and len(arg) < 20 and height is None:
            height = int(arg)
        elif account is None:
            account = arg
        else:
            return None, None, False
    return account, height, True


def execute(raw_command: str, container):
    parts = raw_command.split()
    account, height, ok = _parse_args(parts[1:])
    if not ok or len(parts) > 3:
        return api_response.error_response(
            "getactiverules",
            "Usage: getactiverules [account] [height]",
            "INVALID_PARAMS",
        )

    try:
        snapshot = active_rules.resolve_snapshot(height)
    except Exception as exc:
        logger.exception("Failed to resolve spec snapshot")
        return api_response.error_response(
            "getactiverules", f"Failed to resolve active rules: {exc}",
            "INTERNAL_ERROR",
        )

    data = {
        "account": active_rules.normalize_account(account) if account else None,
        "requested_height": height,
        "available": snapshot is not None,
    }
    if snapshot is None:
        return api_response.success_response("getactiverules", data)

    data.update({
        "height": snapshot["height"],
        "spec_revision": snapshot["spec_revision"],
        "spec_hash": snapshot["spec_hash"],
        "effective_spec": snapshot["spec_text"],
    })
    if account:
        mine, unattributed = active_rules.attribute_rules(
            snapshot["spec_text"], account
        )
        data["account_rules"] = mine
        data["unattributed"] = unattributed
    return api_response.success_response("getactiverules", data)
