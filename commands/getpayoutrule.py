"""A payout rule (#63) by its owner's pubkey: the signed terms — declared
recipient set, leg program, caps and period shape — plus the book's
computed state at the tip: the current period and its paid total, and the
settlement records (the readable proof that a settled execution paid
exactly once)."""
import re

import api_response

_CMD = "getpayoutrule"
_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <owner_pubkey_hex96>", "INVALID_PARAMS"
        )
    owner = parts[1].strip().lower()
    if not _PUBKEY_RE.match(owner):
        return api_response.error_response(
            _CMD, "owner_pubkey must be 96 lowercase hex characters.", "INVALID_PARAMS"
        )

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView().get_payout_rule_for_owner(owner)
    if view is None:
        return api_response.error_response(
            _CMD, f"No payout rule installed for: {owner}",
            "PAYOUT_RULE_UNKNOWN",
        )
    return api_response.success_response(_CMD, view)
