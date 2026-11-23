"""The payout rules installed by an address (Bounty 01, issue #63).

Reports every rule in the owner's book (stage 2: up to eight
concurrent rules per account): declared caps and recipient set,
trigger and end condition, seal and fee cap, and the live
accounting -- current period spend, clock totals, paid total,
execution count, missed periods, version and lineage. The
semantics tell a wallet what it needs to predict an execution:
legs are chosen by the owner's rule by index into the declared
set, both caps bind, a settlement id settles at most once.
Read from the persisted tip tables, like getroutes.
"""
import api_response

_CMD = "getpayouts"

SEMANTICS = {
    "supported": True,
    "legs": "rule_outputs_recipient_index_and_amount",
    "caps": "per_execution_and_per_period_both_bind",
    "settlement": "settlement_id_settles_at_most_once",
    "fee": "executor_pays_the_standard_fee_within_the_rules_cap",
    "max_recipients": 8,
    "max_legs": 8,
    "max_rules_per_owner": 8,
    "update": "in_place_preserving_lineage_and_accounting",
}


def _rule_view(row):
    return {
        "rule_id": row["rule_id"],
        "owner_pubkey": row.get("owner_pubkey") or row.get("owner"),
        "max_per_execution": row["max_per_execution"],
        "max_per_period": row["max_per_period"],
        "recipients": row["recipients"],
        "period_kind": row["period_kind"],
        "anchor_ts": row["anchor_ts"],
        "due": bool(row.get("due", False)),
        "on_arrival": bool(row.get("on_arrival", False)),
        "end_period_index": row.get("end_period_index"),
        "max_fires": row.get("max_fires"),
        "max_total": row.get("max_total"),
        "sealed": bool(row.get("sealed", False)),
        "max_fee_per_execution": row.get("max_fee_per_execution"),
        "period_index": row["period_index"],
        "spent_in_period": row["spent_in_period"],
        "total_spent": int(row.get("total_spent", 0)),
        "fires": int(row.get("fires", 0)),
        "paid_total": int(row.get("paid_total", 0)),
        "executions": int(row.get(
            "executions", len(row.get("settlements") or []))),
        "missed_periods": int(row.get("missed_periods", 0)),
        "version": int(row.get("version", 1)),
        "lineage": list(row.get("lineage") or []),
        "settled_count": len(row.get("settlements") or []),
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
    rows = view.get_payout_rules(address)
    data = {"payout_rule": None, "payout_rules": [], "semantics": SEMANTICS}
    if rows:
        views = [_rule_view(row) for row in rows]
        data["payout_rules"] = views
        # The stage-1 field: the owner's first rule, unchanged in
        # shape for readers that predate the multi-rule book.
        first = views[0]
        data["payout_rule"] = {
            "rule_id": first["rule_id"],
            "owner_pubkey": first["owner_pubkey"],
            "max_per_execution": first["max_per_execution"],
            "max_per_period": first["max_per_period"],
            "recipients": first["recipients"],
            "period_kind": first["period_kind"],
            "anchor_ts": first["anchor_ts"],
            "period_index": first["period_index"],
            "spent_in_period": first["spent_in_period"],
            "settled_count": first["settled_count"],
        }
    return api_response.success_response(_CMD, data)
