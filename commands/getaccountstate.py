"""Pending-aware account state for wallet clients (issue #11).

`getbalance` returns only the confirmed chain balance, so a queued send is
invisible to a wallet until it is mined. `getaccountstate` adds the mempool
view — outgoing/incoming amounts and the pending tx list — without changing
`getbalance` (an opt-in surface, as requested on the issue).

Amount fields are decimal STRINGS: transfer amounts can exceed a JS Number's
safe integer range, and `getbalance` already returns `str(balance)`.
`pending_outgoing` includes the node's own admission fee estimate, mirroring
the balance check `sendtx` enforces (balance >= transfers + estimated_fee), so
`available_balance` never invites a wallet to queue a doomed transfer.
Unconfirmed `pending_incoming` is reported but never treated as spendable.
"""
import logging
from datetime import datetime, timezone

import api_response

logger = logging.getLogger(__name__)


def _iso_from_ms(ms) -> str:
    try:
        return datetime.fromtimestamp(int(ms) / 1000.0, tz=timezone.utc).isoformat()
    except Exception:
        return ""


def _iso_from_seconds(secs) -> str:
    try:
        return datetime.fromtimestamp(int(secs), tz=timezone.utc).isoformat()
    except Exception:
        return ""


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            "getaccountstate", "Usage: getaccountstate <address>", "INVALID_PARAMS"
        )
    address = parts[1]

    try:
        chain_balance = int(container.chain_state.get_balance(address))
        pending = container.db.get_mempool_txs_for_address(address)
    except Exception as exc:
        logger.exception("Failed to build account state for %s", address)
        return api_response.error_response(
            "getaccountstate", f"Failed to build account state: {exc}", "INTERNAL_ERROR"
        )

    pending_outgoing = 0
    pending_incoming = 0
    pending_fees = 0
    pending_txs = []
    for tx in pending:
        amount_out = int(tx.get("amount_out") or 0)
        amount_in = int(tx.get("amount_in") or 0)
        # Only the sender pays the fee; recipient-only txs contribute 0.
        fee = int(tx.get("estimated_fee") or 0) if tx.get("sender_pubkey") == address else 0
        pending_outgoing += amount_out
        pending_incoming += amount_in
        pending_fees += fee

        if amount_out and amount_in:
            direction = "self"
        elif amount_out:
            direction = "outgoing"
        else:
            direction = "incoming"
        amount = amount_out if direction in ("outgoing", "self") else amount_in

        pending_txs.append({
            "hash": tx.get("tx_hash", ""),
            "direction": direction,
            "amount": str(amount),
            "fee": str(fee),
            # Both 'pending' and the transient miner-held 'reserved' render as
            # 'queued' so wallet UIs do not flicker during block assembly.
            "status": "queued",
            "sequence_number": tx.get("sequence_number"),
            "tx_type": tx.get("tx_type", "user_tx"),
            "received_at": _iso_from_ms(tx.get("received_at", 0)),
            "expires_at": _iso_from_seconds(tx.get("expiration_time")),
        })

    total_out = pending_outgoing + pending_fees
    available_balance = chain_balance - total_out
    if available_balance < 0:
        available_balance = 0

    return api_response.success_response("getaccountstate", {
        "address": address,
        "chain_balance": str(chain_balance),
        "pending_outgoing": str(pending_outgoing),
        "pending_incoming": str(pending_incoming),
        "pending_fees": str(pending_fees),
        "available_balance": str(available_balance),
        "pending_txs": pending_txs,
    })
