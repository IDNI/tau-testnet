"""One standing payment: open with its progress and history, or how it ended."""
import re

import api_response
from commands.getstandingpayments import _tip

_CMD = "getstandingpayment"
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL = ("ended", "cancelled", "replaced")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <standing_id>", "INVALID_PARAMS"
        )
    sid = parts[1].strip().lower()
    if not _ID_RE.match(sid):
        return api_response.error_response(
            _CMD, "standing_id must be 64 hex characters.", "INVALID_PARAMS"
        )

    import db

    try:
        history = db.get_canonical_standing_events(sid)
    except Exception:
        history = []
    _head, book = _tip()
    key = bytes.fromhex(sid)
    terms = book.get(key)
    if terms is not None:
        data = book.describe(key)
        data["history"] = history
        return api_response.success_response(_CMD, data)

    for event in history:  # newest first
        if event.get("outcome") in _TERMINAL:
            data = {
                "standing_id": sid,
                "status": event["outcome"],
                "resolved_at_height": event["block_number"],
                "history": history,
            }
            if event.get("replaced_by"):
                data["replaced_by"] = event["replaced_by"]
            return api_response.success_response(_CMD, data)
    return api_response.error_response(
        _CMD, f"Unknown standing payment: {sid}", "STANDING_PAYMENT_UNKNOWN"
    )
