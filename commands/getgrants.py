"""A conditional grant by id (Bounty 01, issue #63).

Reports the grant's held remainder, its per-period draw cap and
window, and whether it is open, drawable or refunded at the tip.
Read from the persisted tip tables, like getroutes.
"""
import api_response

_CMD = "getgrants"

SEMANTICS = {
    "supported": True,
    "held": "escrow_in_book_not_recipient_balance",
    "draw_window": "opens_at_to_deadline",
    "period": "week_604800s_from_opens_at",
    "refund": "sweep_at_deadline_fee_free_full_remainder",
}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <grant_id>", "INVALID_PARAMS"
        )
    grant_id = parts[1].strip().lower()

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView()
    row = view.get_grant(grant_id)
    data = {"grant": None, "semantics": SEMANTICS}
    if row is not None:
        tip_ts = view.next_block_timestamp
        if row["refunded"]:
            state = "refunded"
        elif tip_ts < row["opens_at"]:
            state = "not_open"
        elif tip_ts >= row["deadline"]:
            state = "expired_refund_due"
        else:
            state = "drawable"
        data["grant"] = {
            "grant_id": row["grant_id"],
            "sender_pubkey": row["sender_pubkey"],
            "recipient_pubkey": row["recipient_pubkey"],
            "total": row["total"],
            "remaining": row["remaining"],
            "cap_per_period": row["cap_per_period"],
            "opens_at": row["opens_at"],
            "deadline": row["deadline"],
            "drawn_in_period": row["drawn_in_period"],
            "last_draw_ts": row["last_draw_ts"],
            "refunded": row["refunded"],
            "state_at_tip": state,
        }
    return api_response.success_response(_CMD, data)
