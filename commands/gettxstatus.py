"""Transaction status lookup by hash (issue #11).

Resolution order:
  1. mempool  -> "queued"  (both 'pending' and 'reserved'), or "expired" if the
                 row is past its expiration_time but not yet pruned.
  2. tx_index -> "confirmed" for the first location on the canonical chain
                 (with block_hash/number and confirmation depth). Fork-only
                 locations fall through (a reorged-out tx is re-queued into the
                 mempool, so step 1 usually catches it).
  3. mempool_dropped -> "expired" / "evicted" / "rejected". A "rejected" row
                 may carry the apply receipt's `reason` code and a `detail`
                 log trail. Only the node that built the block records these;
                 other nodes see the tx stay queued until it expires.
  4. "unknown".

"unknown" is a valid answer, not an error; the envelope stays ok. Only a
malformed hash / usage yields INVALID_PARAMS.
"""
import json
import logging
import time
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


def _retractable_fields(db, tx_hash: str, block_hash: str) -> dict:
    """`retractable` for a confirmed park, `retracts` for a confirmed retract."""
    try:
        block = db.get_block_by_hash(block_hash) or {}
        txs = block.get("transactions") or []
        ids = block.get("tx_ids") or []
        if tx_hash not in ids or len(ids) != len(txs):
            return {}
        tx = txs[ids.index(tx_hash)]
        tx_type = tx.get("tx_type") if isinstance(tx, dict) else None
        if tx_type in ("standing_payment_create", "standing_payment_cancel"):
            return _standing_fields(tx)
        if tx_type in ("payout_rule_set", "payout_rule_revoke", "payout_execute"):
            return _payout_fields(tx, tx_hash, block_hash)
        if tx_type == "retract_transfer":
            return {"retracts": tx.get("retractable_id")}
        if tx_type != "retractable_transfer":
            return {}
        from commands.getretractable import resolution
        from consensus.facade import TipAdmissionView
        from consensus.retractable import parse_retractable_transfer

        rid = parse_retractable_transfer(tx).retractable_id
        if TipAdmissionView().get_retractable(rid) is not None:
            status = "open"
        else:
            resolved = resolution(rid.hex())
            status = resolved[0] if resolved else "not_recorded"
        return {"retractable": {"id": rid.hex(), "status": status}}
    except Exception:
        logger.exception("Failed to resolve retractable detail for %s", tx_hash)
        return {}


def _standing_fields(tx: dict) -> dict:
    """`standing` for a confirmed create, `cancels` for a confirmed cancel.

    `status` is the authorization's state now: waiting, due or retrying while it
    is open, ended or cancelled once resolved, not_recorded when this node has
    no record of how it ended.
    """
    if tx.get("tx_type") == "standing_payment_cancel":
        return {"cancels": tx.get("standing_id")}
    from commands.getstandingpayments import _tip
    from consensus.standing import describe, parse_standing_payment_create
    import db

    sid = parse_standing_payment_create(tx).standing_id
    _head, book = _tip()
    if book.knows(sid):
        status = describe(book.get(sid), book.progress[sid], sid)["status"]
    else:
        status = "not_recorded"
        for event in db.get_canonical_standing_events(sid.hex()):
            if event.get("outcome") in ("ended", "cancelled"):
                status = event["outcome"]
                break
    return {"standing": {"id": sid.hex(), "status": status}}


def _payout_fields(tx: dict, tx_hash: str, block_hash: str) -> dict:
    """`payout` for a confirmed payout transaction: what it did in its block.

    For an install, `status` says whether the rule is still the account's rule
    (installed), or how it ended (replaced, revoked, expired, not_recorded).
    """
    import db

    account = tx.get("account_pubkey") if tx.get("tx_type") == "payout_execute" \
        else tx.get("sender_pubkey")
    if not isinstance(account, str):
        return {}
    history = db.get_canonical_payout_events(account.lower(), limit=500)
    mine = next((e for e in history
                 if e.get("tx_id") == tx_hash and e.get("block_hash") == block_hash), None)
    if mine is None:
        return {"payout": {"status": "not_recorded"}}
    out = {k: v for k, v in mine.items() if k not in ("block_hash", "block_number", "tx_id")}
    if mine.get("outcome") == "installed":
        rule_id = mine.get("rule_id")
        status = "installed"
        for event in history:   # newest first: the latest thing that happened to it
            if event.get("block_number", 0) < mine.get("block_number", 0):
                break
            if event.get("rule_id") == rule_id and event.get("outcome") in ("revoked", "expired"):
                status = event["outcome"]
                break
            if event.get("replaced") == rule_id:
                status = "replaced"
                break
        out["status"] = status
    return {"payout": out}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            "gettxstatus", "Usage: gettxstatus <tx_hash>", "INVALID_PARAMS"
        )
    tx_hash = parts[1].lower()
    if len(tx_hash) != 64 or any(c not in "0123456789abcdef" for c in tx_hash):
        return api_response.error_response(
            "gettxstatus", "tx_hash must be 64 hex characters.", "INVALID_PARAMS"
        )

    db = container.db
    try:
        # 1. In the mempool?
        entry = db.get_mempool_entry(tx_hash)
        if entry is not None:
            payload = {}
            try:
                payload = json.loads(entry.get("payload") or "{}")
            except Exception:
                payload = {}
            exp = payload.get("expiration_time")
            now_s = int(time.time())
            data = {
                "tx_hash": tx_hash,
                "sender": payload.get("sender_pubkey"),
                "sequence_number": payload.get("sequence_number"),
                "received_at": _iso_from_ms(entry.get("received_at", 0)),
                "fee_limit": entry.get("fee_limit", 0),
                "estimated_fee": entry.get("estimated_fee", 0),
            }
            if isinstance(exp, int) and exp < now_s:
                data["status"] = "expired"
                data["expires_at"] = _iso_from_seconds(exp)
            else:
                data["status"] = "queued"
                data["expires_at"] = _iso_from_seconds(exp)
            return api_response.success_response("gettxstatus", data)

        # 2. Confirmed on the canonical chain?
        for loc in db.get_tx_block_locations(tx_hash):
            is_canonical, head_number = db.get_canonical_confirmation(
                loc["block_hash"], loc["block_number"]
            )
            if is_canonical:
                confirmations = head_number - loc["block_number"] + 1
                data = {
                    "tx_hash": tx_hash,
                    "status": "confirmed",
                    "block_hash": loc["block_hash"],
                    "block_number": loc["block_number"],
                    "confirmations": max(1, confirmations),
                }
                data.update(_retractable_fields(db, tx_hash, loc["block_hash"]))
                return api_response.success_response("gettxstatus", data)

        # 3. Dropped without being mined?
        dropped = db.get_dropped_tx(tx_hash)
        if dropped is not None:
            data = {
                "tx_hash": tx_hash,
                "status": dropped["reason"],  # expired | evicted | rejected
                "dropped_at": _iso_from_ms(dropped.get("dropped_at", 0)),
            }
            # Apply-time rejection cause, when the node that mined the block
            # recorded one (e.g. rule_not_applied, width_mismatch).
            if dropped.get("reject_code"):
                data["reason"] = dropped["reject_code"]
            if dropped.get("reject_detail"):
                data["detail"] = dropped["reject_detail"]
            return api_response.success_response("gettxstatus", data)

        # 4. Never seen.
        return api_response.success_response("gettxstatus", {
            "tx_hash": tx_hash,
            "status": "unknown",
        })
    except Exception as exc:
        logger.exception("Failed to resolve status for %s", tx_hash)
        return api_response.error_response(
            "gettxstatus", f"Failed to resolve tx status: {exc}", "INTERNAL_ERROR"
        )
