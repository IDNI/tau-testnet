"""Read-only admission dry-run. The forms and fields are in docs/developer_cli.md.

The verdict comes from `sendtx.queue_transaction(dry_run=True)`, so a refusal has
the same `code` and `details` as `sendtx`. A second admission implementation drifts.
"""
import logging

import api_response
from commands import sendtx

logger = logging.getLogger(__name__)


USAGE = "Usage: checktx [estimate] <json_payload>"


def _split(raw_command: str):
    """(estimate, payload) of `checktx [estimate] <json_payload>`."""
    parts = raw_command.split(None, 1)
    rest = parts[1].strip() if len(parts) > 1 else ""
    head = rest.split(None, 1)
    if head and head[0] == "estimate":
        return True, head[1].strip() if len(head) > 1 else ""
    return False, rest


def execute(raw_command: str, container):
    estimate, payload = _split(raw_command)
    if not payload:
        return api_response.error_response("checktx", USAGE, "INVALID_PARAMS")

    try:
        result = sendtx.queue_transaction(
            payload, propagate=False, dry_run=True,
            skip_tau_eval=not estimate, estimate=estimate,
        )
    except Exception as exc:  # mirrors sendtx.execute's outer guard
        logger.exception("checktx dry run failed")
        return api_response.error_response("checktx", str(exc), "INTERNAL_ERROR")

    # The flags say what really ran, not what the mode allowed.
    tau_evaluated = bool(result.get("tau_evaluated", False))
    fee_checked = bool(result.get("fee_checked", False))
    checks_skipped = ([] if tau_evaluated else ["tau_eval"]) + (
        [] if fee_checked else ["fee_limit"])
    if result.get("ok"):
        fee_bearing = result.get("tx_type") in sendtx.FEE_BEARING_TX_TYPES
        data = {
            "admissible": True if estimate and not fee_bearing else None,
            "fee_checked": fee_checked,
            "tx_hash": result["tx_hash"],
            "tx_type": result.get("tx_type"),
            "tau_evaluated": tau_evaluated,
            "checks_skipped": checks_skipped,
        }
        if estimate and "estimated_fee" in result:
            data["estimated_fee"] = result["estimated_fee"]
            data["fee_limit"] = result["fee_limit"]
            data["admissible"] = int(result["fee_limit"]) >= int(result["estimated_fee"])
        if not estimate:
            data["note"] = (
                "The fee check was skipped: no fee was evaluated. "
                "Use 'checktx estimate' for the fee and a full verdict."
            )
        elif not fee_bearing:
            data["note"] = "fee_exempt: this transaction type pays no fee."
        elif not fee_checked:
            data["note"] = "The fee check was skipped: no fee was evaluated."
        if result.get("update_id"):
            data["update_id"] = result["update_id"]
        return api_response.success_response("checktx", data)

    # Rejection: forward sendtx's own code and details unchanged, and say which
    # checks did not run so "admissible: false" is never over-read.
    details = dict(result.get("details") or {})
    details["tau_evaluated"] = tau_evaluated
    details["checks_skipped"] = checks_skipped
    details["fee_checked"] = fee_checked
    return api_response.error_response(
        "checktx",
        result.get("message", "Transaction would be rejected."),
        result.get("code", "TX_REJECTED"),
        details=details,
    )
