"""Read-only admission dry-run (issue #26).

`checktx <json_payload>` answers "would sendtx accept this?" without touching the
mempool, broadcasting, or charging anything. The verdict comes from
`sendtx.queue_transaction(dry_run=True)` — the same code path, so the `code` and
`details` on a rejection are byte-identical to what `sendtx` would have returned,
which is the whole value of the command. Anything else would be a second
implementation of admission that drifts.

Two forms:

`checktx <json_payload>` performs no Tau evaluation (`tau_evaluated: false`).
Steps 2/3/3b of admission are not side-effect-free on the in-process path: they
intern addresses into SQLite, advance the live interpreter's logical time, can
rebuild it from stdout, and on intern-width overflow re-exec the node. So this
form checks JSON shape, all field validation, BLS signature, sequence,
admission (including the consensus-revision staging compile, which already runs
in a SIGKILL-able subprocess), transfer structure and custom-input screening.
A success answer has `admissible: null` and `fee_checked: false`: the fee
limit is checked against a fee that was never evaluated, so the answer cannot
say "admissible". It reports `tau_eval` and `fee_limit` in `checks_skipped`,
and it gives no `estimated_fee`: a "0" there would be used as a fee_limit and
then refused at submit.

`checktx estimate <json_payload>` also runs steps 2/3/3b, only in an isolated
admission context on its own single slot (`tau_admission.open_context`). It
returns `ESTIMATE_BUSY` at once when another estimate runs, and
`ADMISSION_UNAVAILABLE` when the node has no isolated context; it never falls
back to the in-process path. It returns `estimated_fee` for every fee-bearing
type. The fee limit of the payload does not change the estimate, so a wallet can
sign a draft with any fee_limit, ask, and sign again with the estimate.
`admissible` is then true only when the payload's fee_limit covers the estimate.

The flags say what really ran. `tau_evaluated` is true only when the admission
context ran a Tau step. `fee_checked` is true only when the fee of a type in
`FEE_BEARING_TX_TYPES` was estimated. A fee-exempt type (an approval vote, a
retract, a governance vote) runs no fee step: `fee_checked` is false,
`checks_skipped` names `fee_limit` (and `tau_eval` when no step ran), and
`note` starts with `fee_exempt`.

A rejection carries the `code` and `details` of `sendtx`, plus `tau_evaluated`,
`checks_skipped` and `fee_checked` in `details`, with the same meaning.

`MEMPOOL_FULL` is never reported: that is a fact about the node's capacity right
now, not a verdict about this transaction.
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
    if estimate:
        checks_skipped = ([] if tau_evaluated else ["tau_eval"]) + (
            [] if fee_checked else ["fee_limit"])
    else:
        checks_skipped = ["tau_eval", "fee_limit"]
    if result.get("ok"):
        data = {
            "admissible": True if estimate else None,
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
        elif result.get("tx_type") not in sendtx.FEE_BEARING_TX_TYPES:
            data["note"] = "fee_exempt: this transaction type pays no fee."
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
