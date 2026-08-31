"""One approval request in full, including who has signed and who has not."""
import api_response
from consensus.approvals import STATUS_NAMES

_CMD = "getapprovalrequest"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <request_id>", "INVALID_PARAMS"
        )
    request_id = parts[1].strip().lower()

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    if not tip.approval_slots_active:
        return api_response.error_response(
            _CMD, "Co-signature approvals are not active on this chain.",
            "FEATURE_INACTIVE",
        )

    row = tip.get_approval_request(request_id)
    if row is None:
        return api_response.error_response(
            _CMD, f"Unknown approval request: {request_id}", "REQUEST_UNKNOWN"
        )

    approvers = row.get("approvers") or {}
    voted = {int(k) for k in (row.get("voted") or {})}
    declined = {int(d) for d in (row.get("declined") or [])}
    awaiting = sorted(int(s) for s in approvers if int(s) not in voted | declined)

    from commands.getapprovalrequests import _row_view

    data = _row_view(row)
    # The actionable summary: which slots are still holding the transfer up.
    data["awaiting_slots"] = awaiting
    data["awaiting_approvers"] = [approvers[s] if s in approvers else approvers.get(str(s))
                                  for s in awaiting]
    data["all_answered"] = not awaiting
    data["status_code"] = int(row.get("status", 0))
    data["status"] = STATUS_NAMES.get(int(row.get("status", 0)), "unknown")
    return api_response.success_response(_CMD, data)
