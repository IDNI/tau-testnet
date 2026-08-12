"""Read-only admission dry-run (issue #26).

`checktx <json_payload>` answers "would sendtx accept this?" without touching the
mempool, broadcasting, or charging anything. The verdict comes from
`sendtx.queue_transaction(dry_run=True)` — the same code path, so the `code` and
`details` on a rejection are byte-identical to what `sendtx` would have returned,
which is the whole value of the command. Anything else would be a second
implementation of admission that drifts.

Tau EVALUATION is deliberately not performed (`tau_evaluated: false`). Steps
2/3/3b of admission are not side-effect-free: they intern addresses into SQLite,
advance the live interpreter's logical time, can rebuild it from stdout, and on
intern-width overflow re-exec the node — none of which an unauthenticated,
fee-free, infinitely-repeatable RPC may do. Running them safely needs a bounded
evaluation subprocess and a read-only intern lookup; until those exist the honest
answer is "structurally admissible, policy verdict not computed", not a guess.

What IS checked: JSON shape, all field validation, BLS signature, sequence,
admission (including the consensus-revision staging compile, which already runs
in a SIGKILL-able subprocess), transfer structure, custom-input screening, and
the fee-limit/funds check against a zero fee estimate.

Deliberately absent from the response: `estimated_fee`. Emitting "0" while the
fee streams were never evaluated would hand a wallet a number it would use as a
fee_limit and then have rejected at submit.

`MEMPOOL_FULL` is never reported: that is a fact about the node's capacity right
now, not a verdict about this transaction.
"""
import logging

import api_response
from commands import sendtx

logger = logging.getLogger(__name__)


def execute(raw_command: str, container):
    parts = raw_command.split(None, 1)
    if len(parts) < 2 or not parts[1].strip():
        return api_response.error_response(
            "checktx", "Usage: checktx <json_payload>", "INVALID_PARAMS"
        )

    try:
        result = sendtx.queue_transaction(
            parts[1], propagate=False, dry_run=True, skip_tau_eval=True
        )
    except Exception as exc:  # mirrors sendtx.execute's outer guard
        logger.exception("checktx dry run failed")
        return api_response.error_response("checktx", str(exc), "INTERNAL_ERROR")

    if result.get("ok"):
        data = {
            "admissible": True,
            "tx_hash": result["tx_hash"],
            "tx_type": result.get("tx_type"),
            "tau_evaluated": result.get("tau_evaluated", False),
            "checks_skipped": ["tau_eval"],
        }
        if result.get("update_id"):
            data["update_id"] = result["update_id"]
        return api_response.success_response("checktx", data)

    # Rejection: forward sendtx's own code and details unchanged, and say which
    # checks did not run so "admissible: false" is never over-read.
    details = dict(result.get("details") or {})
    details["tau_evaluated"] = False
    details["checks_skipped"] = ["tau_eval"]
    return api_response.error_response(
        "checktx",
        result.get("message", "Transaction would be rejected."),
        result.get("code", "TX_REJECTED"),
        details=details,
    )
