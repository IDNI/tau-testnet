"""The payout rule installed by an address (Bounty 01, issue #63).

Reports the rule's declared caps and recipient set, its current
period spend and settled settlement ids, and the semantics a wallet
needs to predict an execution: legs are chosen by the owner's rule
by index into the declared set, both caps bind, a settlement id
settles at most once. Read from the persisted tip tables, like
getroutes.
"""
import api_response

_CMD = "getpayouts"

SEMANTICS = {
    "supported": True,
    "legs": "rule_outputs_recipient_index_and_amount",
    "caps": "per_execution_and_per_period_both_bind",
    "settlement": "settlement_id_settles_at_most_once",
    "fee": "executor_pays_the_standard_fee",
    "max_recipients": 8,
    "max_legs": 4,
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
    row = view.get_payout_rule(address)
    data = {"payout_rule": None, "semantics": SEMANTICS}
    if row is not None:
        data["payout_rule"] = {
            "rule_id": row["rule_id"],
            "owner_pubkey": row["owner_pubkey"],
            "max_per_execution": row["max_per_execution"],
            "max_per_period": row["max_per_period"],
            "recipients": row["recipients"],
            "period_kind": row["period_kind"],
            "anchor_ts": row["anchor_ts"],
            "period_index": row["period_index"],
            "spent_in_period": row["spent_in_period"],
            "settled_count": len(row["settlements"]),
        }
    return api_response.success_response(_CMD, data)
