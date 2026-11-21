"""One account's installed receive route (#35), or that it has none."""
import re

import api_response

_CMD = "getreceiveroute"
_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <owner_pubkey>", "INVALID_PARAMS"
        )
    owner = parts[1].strip().lower()
    if not _PUBKEY_RE.match(owner):
        return api_response.error_response(
            _CMD, "owner_pubkey must be 96 lowercase hex characters.", "INVALID_PARAMS"
        )

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView().get_receive_route(owner)
    if view is None:
        return api_response.error_response(
            _CMD, f"No receive route installed for: {owner}", "RECEIVE_ROUTE_UNKNOWN"
        )
    return api_response.success_response(_CMD, view)
