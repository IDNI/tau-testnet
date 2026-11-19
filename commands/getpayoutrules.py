"""Payout rules (#63) owned by, or paying, an address.

Usage: ``getpayoutrules <address> [in|out|all]`` -- ``out``: rules the address
owns; ``in``: rules that list it as a recipient. Each entry carries the rule
text, recipients (slot k is paid from output o<k>), caps, what was paid this
period and the input conventions the rule is stepped with.
"""
import api_response
import db
from consensus.facade import TipAdmissionView
from consensus.payouts import EXECUTOR_INPUT_MAX, EXECUTOR_INPUT_MIN, load_payout_book

_CMD = "getpayoutrules"
_ROLES = ("in", "out", "all")

INPUT_CONVENTIONS = {
    "i1": "owner's spendable balance before the execution (bv[24])",
    "i2": "executions so far in the current period (bv[24])",
    "i3": "period index (bv[64])",
    f"i{EXECUTOR_INPUT_MIN}..i{EXECUTOR_INPUT_MAX}": "values supplied by the executor",
    "o<k>": "amount for recipient slot k (bv[24]); unwritten = 0",
}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2 or len(parts) > 3:
        return api_response.error_response(_CMD, f"Usage: {_CMD} <address> [in|out|all]", "INVALID_PARAMS")
    address = parts[1].strip().lower()
    if len(address) != 96 or any(c not in "0123456789abcdef" for c in address):
        return api_response.error_response(_CMD, "address must be 96 hex characters.", "INVALID_PARAMS")
    role = parts[2].lower() if len(parts) > 2 else "all"
    if role not in _ROLES:
        return api_response.error_response(_CMD, f"role must be one of {', '.join(_ROLES)}", "INVALID_PARAMS")
    try:
        book = load_payout_book(db.load_payouts_state())
    except Exception:
        return api_response.error_response(_CMD, "stored payout state is corrupt", "INTERNAL")
    now = TipAdmissionView().next_block_timestamp
    out = []
    for row in book.snapshot()["rules"]:
        mine = {"out": row["owner_pubkey"] == address, "in": address in row["recipients"]}
        if not (mine["out"] or mine["in"]) or (role != "all" and not mine[role]):
            continue
        state = book.get(bytes.fromhex(row["rule_id"]))
        paid, count = state.paid_this_period(now)
        view = dict(row)
        view.update(active=state.terms.active_at(now), paid_this_period=paid,
                    executions_this_period=count,
                    left_this_period=state.terms.max_per_period - paid)
        out.append(view)
    return api_response.success_response(_CMD, {
        "address": address, "role": role, "as_of": now, "payout_rules": out,
        "conventions": INPUT_CONVENTIONS,
    })
