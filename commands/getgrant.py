"""A grant (stages 2-5) by its id: the signed terms — funder, beneficiary,
total, release schedule, deadline and time conditions — plus the book's
computed state at the tip: how much has been released, drawn, held and
refunded, the effective deadline, and the funder's shared cap (the
readable proof that a release settled at most once per period and that
the refund, when it comes, returns exactly the unspent remainder)."""
import re

import api_response

_CMD = "getgrant"
_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <grant_id_hex64>", "INVALID_PARAMS"
        )
    grant_id = parts[1].strip().lower()
    if not _ID_RE.match(grant_id):
        return api_response.error_response(
            _CMD, "grant_id must be 64 lowercase hex characters.", "INVALID_PARAMS"
        )

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView().get_grant(bytes.fromhex(grant_id))
    if view is None:
        return api_response.error_response(
            _CMD, f"No grant with id: {grant_id}",
            "GRANT_UNKNOWN",
        )
    return api_response.success_response(_CMD, view)
