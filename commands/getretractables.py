"""Open retractable transfers for an address, plus queued parks and retracts."""
import json

import api_response
import db
from commands.getretractable import entry_view
from consensus.retractable import (
    RETRACTABLE_TX_TYPES,
    RetractableShapeError,
    parse_retractable_transfer,
)

_CMD = "getretractables"
_ROLES = ("in", "out", "all")


def _mempool_view(address: str) -> list:
    pending = []
    try:
        payloads = db.get_mempool_txs()
    except Exception:
        return pending
    for blob in payloads or []:
        text = blob if isinstance(blob, str) else ""
        if text.startswith("json:"):
            text = text[len("json:"):]
        try:
            tx = json.loads(text)
        except Exception:
            continue
        if not isinstance(tx, dict) or tx.get("tx_type") not in RETRACTABLE_TX_TYPES:
            continue
        sender = str(tx.get("sender_pubkey", "")).lower()
        recipient = str(tx.get("recipient_pubkey", "")).lower()
        if address not in (sender, recipient):
            continue
        item = {"tx_type": tx.get("tx_type"), "sender_pubkey": sender}
        if tx.get("tx_type") == "retractable_transfer":
            item.update(
                recipient_pubkey=recipient,
                amount=tx.get("amount"),
                release_at_height=tx.get("release_at_height"),
                release_at_time=tx.get("release_at_time"),
            )
            try:
                item["retractable_id"] = parse_retractable_transfer(tx).retractable_id.hex()
            except RetractableShapeError:
                item["retractable_id"] = None
        else:
            item["retractable_id"] = tx.get("retractable_id")
        pending.append(item)
    return pending


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

    rows = db.get_open_retractables(address, role)
    return api_response.success_response(_CMD, {
        "address": address,
        "role": role,
        "retractables": [entry_view(r) for r in rows],
        "mempool": _mempool_view(address),
    })
