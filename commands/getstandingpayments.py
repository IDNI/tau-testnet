"""Open standing payments for an address, with what is due now (#34).

Usage: ``getstandingpayments <address> [in|out|all]`` -- ``out`` lists payments
the address pays, ``in`` payments it receives. Each entry carries the signed
schedule, ``executions``, ``total_executed``, ``due_period`` (the period anyone
may execute right now, or null), ``paid_this_period`` and ``next_due_at``,
judged at the node's advisory next-block timestamp.
"""
import api_response
import db
from consensus.facade import TipAdmissionView
from consensus.standing import load_standing_book

_CMD = "getstandingpayments"
_ROLES = ("in", "out", "all")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2 or len(parts) > 3:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [in|out|all]", "INVALID_PARAMS"
        )
    address = parts[1].strip().lower()
    if len(address) != 96 or any(c not in "0123456789abcdef" for c in address):
        return api_response.error_response(_CMD, "address must be 96 hex characters.", "INVALID_PARAMS")
    role = parts[2].lower() if len(parts) > 2 else "all"
    if role not in _ROLES:
        return api_response.error_response(
            _CMD, f"role must be one of {', '.join(_ROLES)}", "INVALID_PARAMS"
        )
    try:
        book = load_standing_book(db.load_standing_state())
    except Exception:
        return api_response.error_response(_CMD, "stored standing payment state is corrupt", "INTERNAL")
    now = TipAdmissionView().next_block_timestamp
    out = []
    for row in book.snapshot_rows():
        mine = {
            "out": row["payer_pubkey"] == address,
            "in": row["recipient_pubkey"] == address,
        }
        if not (mine["out"] or mine["in"]) or (role != "all" and not mine[role]):
            continue
        state = book.get(bytes.fromhex(row["standing_id"]))
        view = dict(row)
        view["due_period"] = state.due_period(now)
        current = state.terms.period_of(now) if now >= state.terms.start_at else None
        view["paid_this_period"] = current is not None and state.next_period > current
        view["next_due_at"] = state.next_due_at(now)
        out.append(view)
    return api_response.success_response(_CMD, {
        "address": address, "role": role, "as_of": now, "standing_payments": out,
    })
