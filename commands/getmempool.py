import json
import logging
from datetime import datetime, timezone

import api_response
from db import get_mempool_entries

logger = logging.getLogger(__name__)


def _iso_from_ms(ms: int) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _iso_from_seconds(secs) -> str:
    try:
        return datetime.fromtimestamp(int(secs), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _summarize_entry(entry: dict) -> dict:
    payload_str = entry.get("payload") or ""
    try:
        tx = json.loads(payload_str) if payload_str else {}
    except Exception:
        tx = {}
    operations = tx.get("operations") if isinstance(tx, dict) else None
    op_count = len(operations) if isinstance(operations, dict) else 0
    return {
        "tx_hash": entry.get("tx_hash") or "",
        "sender": tx.get("sender_pubkey", "") if isinstance(tx, dict) else "",
        "sequence_number": tx.get("sequence_number") if isinstance(tx, dict) else None,
        "received_at": _iso_from_ms(entry.get("received_at", 0)),
        "expires_at": _iso_from_seconds(tx.get("expiration_time")) if isinstance(tx, dict) else "",
        "operation_count": op_count,
        "status": entry.get("status") or "pending",
        "fee_limit": entry.get("fee_limit", 0),
        "estimated_fee": entry.get("estimated_fee", 0),
    }


def execute(raw_command: str, container):
    try:
        entries = get_mempool_entries()
    except Exception as exc:
        logger.exception("Failed to retrieve mempool entries")
        return api_response.error_response(
            "getmempool", f"Failed to retrieve mempool: {exc}", "INTERNAL_ERROR"
        )

    summaries = [_summarize_entry(e) for e in entries]
    return api_response.success_response(
        "getmempool", {"count": len(summaries), "transactions": summaries}
    )
