"""Open conditional grants for an address, with what can be drawn right now.

Usage: ``getgrants <address> [in|out|all]`` -- ``out`` lists grants the address
made, ``in`` grants it can draw from, ``all`` both. Each entry carries its
signed terms, its spending state and ``drawable_now``: the largest single draw
the terms allow at the node's advisory next-block timestamp.
"""
import api_response
import db
from consensus.facade import TipAdmissionView
from consensus.grants import load_grant_book

_CMD = "getgrants"
_ROLES = ("in", "out", "all")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2 or len(parts) > 3:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [in|out|all]", "INVALID_PARAMS"
        )
    address = parts[1].strip().lower()
    if len(address) != 96 or any(c not in "0123456789abcdef" for c in address):
        return api_response.error_response(
            _CMD, "address must be 96 hex characters.", "INVALID_PARAMS"
        )
    role = parts[2].lower() if len(parts) > 2 else "all"
    if role not in _ROLES:
        return api_response.error_response(
            _CMD, f"role must be one of {', '.join(_ROLES)}", "INVALID_PARAMS"
        )

    state = db.load_grants_state()
    try:
        book = load_grant_book(state)
    except Exception:
        return api_response.error_response(_CMD, "stored grant state is corrupt", "INTERNAL")
    now = TipAdmissionView().next_block_timestamp
    out = []
    for row in db.get_open_grants(address, role):
        view = dict(row)
        grant = book.get(bytes.fromhex(row["grant_id"]))
        if grant is not None:
            view["spent_this_period"] = grant.spent_this_period(now)
            view["drawable_now"] = grant.drawable_now(now)
        out.append(view)
    return api_response.success_response(_CMD, {
        "address": address,
        "role": role,
        "as_of": now,
        "grants": out,
    })
