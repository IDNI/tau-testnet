"""One retractable transfer: open, or how it ended."""
import re

import api_response
from consensus.retractable import (
    KIND_HEIGHT,
    RETRACTABLE_STATUS_OPEN,
    RETRACTABLE_STATUS_RELEASED,
    RETRACTABLE_STATUS_RETRACTED,
)

_CMD = "getretractable"
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL = {
    "released": RETRACTABLE_STATUS_RELEASED,
    "retracted": RETRACTABLE_STATUS_RETRACTED,
}


def entry_view(row: dict) -> dict:
    """An open entry as clients see it; exactly one release field is present."""
    view = {
        "retractable_id": row["retractable_id"],
        "sender_pubkey": row["sender_pubkey"],
        "recipient_pubkey": row["recipient_pubkey"],
        "amount": row["amount"],
        "sequence_number": row["sequence_number"],
        "status": RETRACTABLE_STATUS_OPEN,
    }
    if int(row["release_kind"]) == KIND_HEIGHT:
        view["release_at_height"] = row["release_at"]
    else:
        view["release_at_time"] = row["release_at"]
    return view


def resolution(retractable_id: str):
    """(status, height) from canonical events when resolved, else None."""
    import db

    for event in reversed(db.get_canonical_retractable_events(retractable_id)):
        status = _TERMINAL.get(event.get("outcome"))
        if status:
            return status, int(event["block_number"])
    return None


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <retractable_id>", "INVALID_PARAMS"
        )
    rid = parts[1].strip().lower()
    if not _ID_RE.match(rid):
        return api_response.error_response(
            _CMD, "retractable_id must be 64 hex characters.", "INVALID_PARAMS"
        )

    from consensus.facade import TipAdmissionView

    row = TipAdmissionView().get_retractable(bytes.fromhex(rid))
    if row is not None:
        return api_response.success_response(_CMD, entry_view(row))

    resolved = resolution(rid)
    if resolved is None:
        return api_response.error_response(
            _CMD, f"Unknown retractable transfer: {rid}", "RETRACTABLE_UNKNOWN"
        )
    status, height = resolved
    return api_response.success_response(
        _CMD, {"retractable_id": rid, "status": status, "resolved_at_height": height}
    )
