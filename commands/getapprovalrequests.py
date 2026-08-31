"""List approval requests involving an address — the approver's inbox.

Answers "what needs my signature, and what am I waiting on?". THIS IS WHERE THE
TIER SCOPING SHOWS UP: a request declares only the approvers its amount actually
requires, so an approver whose vote a given amount does not need never sees it.
An account with nothing to sign gets an empty `incoming`, and that emptiness is
the feature working, not a failure.

Reads the persisted tables (the same view every node has at this tip) and
additionally surfaces requests still sitting in the local mempool, so a wallet
can show a just-submitted request before it is mined.
"""
import json

import api_response
import db
from consensus.approvals import (
    APPROVAL_TX_TYPES,
    STATUS_NAMES,
    STATUS_OPEN,
    ApprovalShapeError,
    _normalize_pubkey,
)

_CMD = "getapprovalrequests"
_ROLES = ("in", "out", "all")


def _inactive_response():
    return api_response.error_response(
        _CMD,
        "Co-signature approvals are not active on this chain.",
        "FEATURE_INACTIVE",
    )


def _row_view(row: dict) -> dict:
    """One request, as a client wants to see it."""
    approvers = row.get("approvers") or {}
    voted = row.get("voted") or {}
    declined = set(row.get("declined") or [])
    return {
        "request_id": row["request_id"],
        "sender_pubkey": row["sender_pubkey"],
        "recipient_pubkey": row["recipient_pubkey"],
        "amount": row["amount"],
        "expire_at_height": row["expire_at_height"],
        "status": STATUS_NAMES.get(int(row.get("status", 0)), "unknown"),
        # slot -> {approver, state}. `state` is what a bot polls on: "awaiting"
        # means this slot is the one still holding the transfer up.
        "approvers": {
            str(slot): {
                "pubkey": pubkey,
                "state": ("approved" if int(slot) in {int(k) for k in voted}
                          else "declined" if int(slot) in declined
                          else "awaiting"),
            }
            for slot, pubkey in sorted(approvers.items())
        },
        # Sender-supplied data: a 2FA code, a comment to a partner. PUBLIC --
        # anything here is readable by everyone, which is why the CLI warns
        # before putting a one-time code in it.
        "custom_inputs": {str(k): v for k, v in sorted((row.get("custom_inputs") or {}).items())},
    }


def _mempool_requests(address: str) -> list:
    """Requests and votes from or about this address, queued but not yet mined."""
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
        if not isinstance(tx, dict) or tx.get("tx_type") not in APPROVAL_TX_TYPES:
            continue
        parties = {str(tx.get("sender_pubkey", "")).lower()}
        parties.update(str(v).lower() for v in (tx.get("approvers") or {}).values())
        if address in parties:
            pending.append({
                "tx_type": tx.get("tx_type"),
                "sender_pubkey": tx.get("sender_pubkey"),
                "request_id": tx.get("request_id"),
                "amount": tx.get("amount"),
                "approve": tx.get("approve"),
            })
    return pending


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [in|out|all]", "INVALID_PARAMS"
        )

    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    role = parts[2].lower() if len(parts) > 2 else "all"
    if role not in _ROLES:
        return api_response.error_response(
            _CMD, f"role must be one of {', '.join(_ROLES)}", "INVALID_PARAMS"
        )

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    if not tip.approval_slots_active:
        return _inactive_response()

    incoming = [_row_view(r) for r in tip.open_requests_naming(address)]

    outgoing = []
    try:
        for row in db.load_approval_requests() or []:
            if str(row.get("sender_pubkey", "")).lower() != address:
                continue
            full = tip.get_approval_request(row["request_id"])
            if full:
                outgoing.append(_row_view(full))
    except Exception:
        pass

    data = {
        "address": address,
        "mempool": _mempool_requests(address),
    }
    if role in ("in", "all"):
        # Requests awaiting THIS account's signature. Empty means nothing needs
        # you, which for an amount below the sender's first tier is correct.
        data["incoming"] = incoming
    if role in ("out", "all"):
        data["outgoing"] = outgoing
    return api_response.success_response(_CMD, data)
