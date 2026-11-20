"""Read-only admission dry-run. The forms and fields are in docs/developer_cli.md.

The verdict comes from `sendtx.queue_transaction(dry_run=True)`, so a refusal has
the same `code` and `details` as `sendtx`. A second admission implementation drifts.
"""
import json
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


def _recipient_policy_active() -> bool:
    try:
        from consensus.facade import TipAdmissionView

        return TipAdmissionView().recipient_policy_active
    except Exception:
        return False


def _inbound_rule_refusal(payload: str):
    """A rejection for a rule that reads i17 while recipient policy is off.

    Advisory only (checktx never decides consensus): before activation i17 is an
    ordinary custom stream, so admission still accepts such a rule, but it would
    never judge an incoming payment. Saying so here keeps a wallet from deploying
    an inbound allow-list or hold cap that silently does nothing (issue #47,
    acceptance case 5; issue #76, case 6).
    """
    try:
        tx = json.loads(payload)
    except (TypeError, ValueError):
        return None
    if not isinstance(tx, dict):
        return None
    texts = [tx.get("rule_text")]
    operations = tx.get("operations")
    if isinstance(operations, dict):
        texts.append(operations.get("0"))
    from consensus.sender_policy import reads_recipient_input

    if not any(reads_recipient_input(t) for t in texts if isinstance(t, str)):
        return None
    if _recipient_policy_active():
        return None
    return api_response.error_response(
        "checktx",
        "This rule reads i17, the recipient-policy input, but recipient-side policy "
        "is not active on this network, so it would never judge an incoming "
        "payment. It becomes available with the governance patch "
        "recipient_policy_active.",
        "RECIPIENT_POLICY_INACTIVE",
        details={"recipient_policy_active": False},
    )


def execute(raw_command: str, container):
    estimate, payload = _split(raw_command)
    if not payload:
        return api_response.error_response("checktx", USAGE, "INVALID_PARAMS")

    refusal = _inbound_rule_refusal(payload)
    if refusal is not None:
        return refusal

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
        if result.get("receive_routing"):
            data["receive_routing"] = result["receive_routing"]
        data["recipient_policy_active"] = _recipient_policy_active()
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
