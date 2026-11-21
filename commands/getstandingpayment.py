"""A standing-payment authorization (#34) by its id: the signed terms plus
the book's computed state at the tip — status (active/cancelled/ended),
next due, totals executed, and the paid-for-period facts (the readable
"paid for this period" record issue #34 asks for)."""
import re

import api_response

_CMD = "getstandingpayment"
_AUTH_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <auth_id_hex64>", "INVALID_PARAMS"
        )
    auth_id_hex = parts[1].strip().lower()
    if not _AUTH_ID_RE.match(auth_id_hex):
        return api_response.error_response(
            _CMD, "auth_id must be 64 lowercase hex characters.", "INVALID_PARAMS"
        )

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView().get_standing_payment(bytes.fromhex(auth_id_hex))
    if view is None:
        return api_response.error_response(
            _CMD, f"No standing payment with id: {auth_id_hex}",
            "STANDING_PAYMENT_UNKNOWN",
        )
    return api_response.success_response(_CMD, view)
