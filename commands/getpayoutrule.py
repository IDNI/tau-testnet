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
    if len(parts) not in (2, 3):
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <owner_pubkey_hex96> [rule_index]",
            "INVALID_PARAMS",
        )
    owner = parts[1].strip().lower()
    if not _PUBKEY_RE.match(owner):
        return api_response.error_response(
            _CMD, "owner_pubkey must be 96 lowercase hex characters.", "INVALID_PARAMS"
        )
    # FIX 7: an owner may hold up to 8 rules; the optional slot selects
    # one (slot 0 when omitted — the owner's first rule).
    rule_index = 0
    if len(parts) == 3:
        try:
            rule_index = int(parts[2])
        except ValueError:
            return api_response.error_response(
                _CMD, "rule_index must be an integer.", "INVALID_PARAMS"
            )
        if not 0 <= rule_index <= 7:
            return api_response.error_response(
                _CMD, "rule_index must be in 0..7.", "INVALID_PARAMS"
            )

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView().get_payout_rule_for_owner_index(owner, rule_index)
    if view is None:
        return api_response.error_response(
            _CMD, f"No payout rule installed for: {owner}",
            "PAYOUT_RULE_UNKNOWN",
        )
    return api_response.success_response(_CMD, view)
