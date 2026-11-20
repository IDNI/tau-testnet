"""Open standing payments for an address (Bounty 01, issue #34).

For each authorization where the address is payer or recipient: the
signed terms, the settlement progress, and the next due occurrence --
the fields acceptance case 9 of #34 requires a wallet to be able to
read. Read from the persisted tip tables, like getretractables.
"""
import api_response
from consensus.periods import PERIOD_DAY, PERIOD_MONTH, PERIOD_WEEK
from consensus.standing import (
    END_FINAL_PERIOD,
    END_MAX_OCCURRENCES,
    END_MAX_TOTAL,
    StandingBook,
    StandingRecord,
    StandingTerms,
)

_CMD = "getstandingpayments"
_KIND_NAMES = {PERIOD_DAY: "day", PERIOD_WEEK: "week", PERIOD_MONTH: "month"}
_END_NAMES = {
    END_FINAL_PERIOD: "final_period",
    END_MAX_OCCURRENCES: "max_occurrences",
    END_MAX_TOTAL: "max_total",
}


def _record_from_row(row: dict) -> StandingRecord:
    terms = StandingTerms(
        payer=row["payer_pubkey"],
        recipient=row["recipient_pubkey"],
        amount=row["amount"],
        kind=row["period_kind"],
        anchor_ts=row["anchor_timestamp"],
        window_start_offset=row["window_start_offset"],
        window_end_offset=row["window_end_offset"],
        end_kind=row["end_kind"],
        end_value=row["end_value"],
        sequence_number=row["sequence_number"],
        supersedes=(
            bytes.fromhex(row["supersedes_id"]) if row.get("supersedes_id") else None
        ),
    )
    return StandingRecord(
        terms=terms,
        executed_count=row["executed_count"],
        total_executed=row["total_executed"],
        settled_periods=set(row["settled_periods"]),
        last_executed_period=row["last_executed_period"],
    )


def entry_view(row: dict, tip_ts: int) -> dict:
    record = _record_from_row(row)
    book = StandingBook()
    book.open[record.standing_id] = record
    nxt = book.next_due(record.standing_id, tip_ts)
    view = {
        "standing_id": row["standing_id"],
        "payer_pubkey": row["payer_pubkey"],
        "recipient_pubkey": row["recipient_pubkey"],
        "amount": row["amount"],
        "period": _KIND_NAMES.get(row["period_kind"], row["period_kind"]),
        "anchor_timestamp": row["anchor_timestamp"],
        "window_start_offset": row["window_start_offset"],
        "window_end_offset": row["window_end_offset"],
        "end_condition": {
            _END_NAMES.get(row["end_kind"], row["end_kind"]): row["end_value"]
        },
        "status": "active",
        "executed_count": row["executed_count"],
        "total_executed": row["total_executed"],
        "last_executed_period": (
            row["last_executed_period"] if row["last_executed_period"] >= 0 else None
        ),
        "next_due_period": nxt[0] if nxt else None,
        "next_due_at": nxt[1] if nxt else None,
    }
    return view


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <pubkey>", "INVALID_PARAMS"
        )
    address = parts[1].strip().lower()

    from consensus.facade import TipAdmissionView

    view = TipAdmissionView()
    tip_ts = view.next_block_timestamp
    entries = [entry_view(row, tip_ts) for row in view.standings_for(address)]
    return api_response.success_response(_CMD, {"standing_payments": entries})
