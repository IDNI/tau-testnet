"""The receive route installed by an address (Bounty 01, issue #35).

Reports the installed route's signed terms, whether it is active at
the tip, and the semantics a wallet needs to predict a split: the
credit classes that trigger routing, the rounding, and the fee rule
(acceptance case 8 of #35). Read from the persisted tip tables, like
getretractables.
"""
import api_response

_CMD = "getroutes"

SEMANTICS = {
    "supported": True,
    "credit_classes": "ordinary_transfers_only",
    "rounding": "floor_on_gross",
    "fee": "single_fee_on_gross_charged_to_sender",
    "max_share_bps": 9999,
    "locked_routes": "destination_signature_or_expiry",
}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <pubkey>", "INVALID_PARAMS"
        )
    address = parts[1].strip().lower()

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView()
    row = view.get_route(address)
    data = {"route": None, "semantics": SEMANTICS}
    if row is not None:
        tip_ts = view.next_block_timestamp
        active = True
        if row["activation_timestamp"] and tip_ts < row["activation_timestamp"]:
            active = False
        if row["expiry_timestamp"] and tip_ts >= row["expiry_timestamp"]:
            active = False
        data["route"] = {
            "route_id": row["route_id"],
            "owner_pubkey": row["owner_pubkey"],
            "destination_pubkey": row["destination_pubkey"],
            "bps": row["bps"],
            "min_incoming": row["min_incoming"],
            "activation_timestamp": row["activation_timestamp"],
            "expiry_timestamp": row["expiry_timestamp"],
            "locked": row["locked"],
            "removal_locked": bool(
                row["locked"]
                and row["expiry_timestamp"]
                and tip_ts < row["expiry_timestamp"]
            ),
            "active_at_tip": active,
        }
    return api_response.success_response(_CMD, data)
