"""Pending-aware account state for wallet clients (issue #11).

`getbalance` returns only the confirmed chain balance, so a queued send is
invisible to a wallet until it is mined. `getaccountstate` adds the mempool
view — outgoing/incoming amounts and the pending tx list — without changing
`getbalance` (an opt-in surface, as requested on the issue).

Amount fields are decimal STRINGS: transfer amounts can exceed a JS Number's
safe integer range, and `getbalance` already returns `str(balance)`.

`pending_outgoing` is the transfer total ONLY; the sender's admission fee
estimate is reported separately in `pending_fees`. The two are summed internally
into `total_out`, which mirrors the balance check `sendtx` enforces
(balance >= transfers + estimated_fee), so `available_balance` never invites a
wallet to queue a doomed transfer. `total_out` is not serialized: clients read
the split fields, or `chain_balance - available_balance` for the authoritative
"not currently spendable" amount.

Unconfirmed `pending_incoming` is reported but never treated as spendable.
"""
import logging
from datetime import datetime, timezone

import api_response
import tau_defs

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
        chain_balance, faucet_pending = container.chain_state.get_balance_view(address)
        chain_balance = int(chain_balance)
        pending = container.db.get_mempool_txs_for_address(address)
    except Exception as exc:
        logger.exception("Failed to build account state for %s", address)
        return api_response.error_response(
            "getaccountstate", f"Failed to build account state: {exc}", "INTERNAL_ERROR"
        )

    try:
        from consensus.facade import TipAdmissionView

        tip = TipAdmissionView()
        escrowed_out = tip.escrowed_out(address)
        escrowed_in = tip.escrowed_in(address)
    except Exception:
        escrowed_out = escrowed_in = 0

    # The account's receive route (issue #35). `pending_incoming` stays gross:
    # the split is made at apply, by the route in force in that block.
    try:
        route = tip.receive_route_book().get(address)
        receive_route = route.to_dict(tip.next_block_timestamp) if route is not None else None
    except Exception:
        receive_route = None

    # Recipient-side policy (issues #47, #76): whether this node evaluates the
    # recipient's clause at all, and whether this account's clause opted in by
    # reading i17. Wallets read `active` before offering an inbound rule.
    try:
        from consensus import sender_policy

        recipient_policy = {
            "active": tip.recipient_policy_active,
            "inbound_rule": sender_policy.reads_recipient_input(
                tip.clause_for(address, tau_defs.USER_POLICY_STREAM_INDEX)),
        }
    except Exception:
        recipient_policy = {"active": False, "inbound_rule": False}

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
        "faucet_pending": bool(faucet_pending),
        "pending_outgoing": str(pending_outgoing),
        "pending_incoming": str(pending_incoming),
        "pending_fees": str(pending_fees),
        "available_balance": str(available_balance),
        "escrowed_out": str(escrowed_out),
        "escrowed_in": str(escrowed_in),
        "receive_route": receive_route,
        "recipient_policy": recipient_policy,
        "pending_txs": pending_txs,
    })
