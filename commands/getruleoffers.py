"""List rule offers involving an address, plus that address's accepted clauses.

Answers "what rules has someone sent me, and what have I accepted?" -- the read
side of rule sharing. Reads the persisted tables (the same view every node has
at this tip) and additionally surfaces offers still sitting in the local
mempool, so a wallet can show a just-submitted offer before it is mined.
"""
import json

import api_response
import db
from consensus.rule_offers import (
    ALLOWED_TARGET_STREAMS,
    STATUS_OFFERED,
    RuleOfferShapeError,
    normalize_acceptor_pubkey,
)

_CMD = "getruleoffers"

# Full rule text can be 8 KiB; a listing returns a preview plus its digest so a
# client can spot-check without paying for the whole body. `getruleoffer`
# returns the complete text.
_PREVIEW_CHARS = 200


def _preview(text: str) -> dict:
    import hashlib

    body = text or ""
    return {
        "rule_text_preview": body[:_PREVIEW_CHARS],
        "rule_text_truncated": len(body) > _PREVIEW_CHARS,
        "rule_text_sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        "rule_text_bytes": len(body.encode("utf-8")),
    }


def _mempool_offers(address: str) -> list:
    """Offers and decisions from this address that are queued but not yet mined."""
    pending = []
    try:
        payloads = db.get_mempool_txs()
    except Exception:
        return pending

    for raw in payloads:
        text = raw[5:] if isinstance(raw, str) and raw.startswith("json:") else raw
        try:
            tx = json.loads(text)
        except Exception:
            continue
        tx_type = tx.get("tx_type")
        if tx_type not in ("rule_offer", "rule_offer_accept", "rule_offer_reject"):
            continue
        sender = (tx.get("sender_pubkey") or "").lower()
        recipient = (tx.get("recipient_pubkey") or "").lower()
        if address not in (sender, recipient):
            continue

        entry = {
            "lifecycle": "mempool",
            "tx_type": tx_type,
            "offerer_pubkey": sender if tx_type == "rule_offer" else None,
            "recipient_pubkey": recipient or None,
            "offer_id": tx.get("offer_id"),
            "expire_at_height": tx.get("expire_at_height"),
        }
        if isinstance(tx.get("rule_text"), str):
            entry.update(_preview(tx["rule_text"]))
        pending.append(entry)
    return pending


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [in|out|all]", "INVALID_PARAMS"
        )

    try:
        address = normalize_acceptor_pubkey(parts[1])
    except RuleOfferShapeError as exc:
        return api_response.error_response(
            _CMD, f"Invalid address: {exc}", "INVALID_PARAMS"
        )

    role = parts[2].lower() if len(parts) > 2 else "all"
    if role not in ("in", "out", "all"):
        return api_response.error_response(
            _CMD, "Role filter must be one of: in, out, all.", "INVALID_PARAMS"
        )

    database = getattr(container, "db", db) or db
    try:
        rows = database.load_rule_offers()
        clauses = database.load_rule_clauses()
    except Exception as exc:
        return api_response.error_response(
            _CMD, f"Failed to read rule offers: {exc}", "INTERNAL_ERROR"
        )

    incoming, outgoing = [], []
    for row in rows:
        entry = {
            "lifecycle": "chain",
            "offer_id": row["offer_id"],
            "offerer_pubkey": row["offerer_pubkey"],
            "recipient_pubkey": row["recipient_pubkey"],
            "expire_at_height": row["expire_at_height"],
            "status": row["status"],
        }
        entry.update(_preview(row.get("rule_text", "")))
        # Resolved rows keep only the consensus-bound id, so offerer/recipient
        # can be blank; those are reported under neither direction.
        if (row.get("recipient_pubkey") or "").lower() == address:
            incoming.append(entry)
        elif (row.get("offerer_pubkey") or "").lower() == address:
            outgoing.append(entry)

    accepted = [
        {
            "target_stream": clause["target_stream"],
            "clause_body": clause["clause_body"],
        }
        for clause in clauses
        if (clause.get("acceptor_pubkey") or "").lower() == address
    ]

    data = {
        "address": address,
        "pending_incoming": sum(1 for e in incoming if e["status"] == STATUS_OFFERED),
        "accepted_clauses": accepted,
        "supported_target_streams": sorted(ALLOWED_TARGET_STREAMS),
        "mempool": _mempool_offers(address),
    }
    if role in ("in", "all"):
        data["incoming"] = incoming
    if role in ("out", "all"):
        data["outgoing"] = outgoing

    return api_response.success_response(_CMD, data)
