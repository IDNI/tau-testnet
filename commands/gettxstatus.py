"""Transaction status lookup by hash (issue #11).

Resolution order:
  1. mempool  -> "queued"  (both 'pending' and 'reserved'), or "expired" if the
                 row is past its expiration_time but not yet pruned.
  2. tx_index -> "confirmed" for the first location on the canonical chain
                 (with block_hash/number and confirmation depth). Fork-only
                 locations fall through (a reorged-out tx is re-queued into the
                 mempool, so step 1 usually catches it).
                 "confirmed" means included. What the transaction DID is in
                 `outcome` (issue #42): `status` "applied" or "skipped" (a
                 valid no-op), the receipt `reason`, `fee_charged`, the
                 receipt `logs`, and for rule transactions `rule_effects`
                 (registered / replaced / revoked / accumulated, with the
                 sha256 of the stored text). Every node records it for each
                 block it applies or replays; `{"status": "not_recorded"}` for
                 blocks applied before the node began recording.
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


def _rule_text(tx) -> str:
    """The rule a user transaction carries on operation 0, as the engine gets it."""
    if not isinstance(tx, dict) or (tx.get("tx_type") or "user_tx") != "user_tx":
        return ""
    ops = tx.get("operations")
    rule = ops.get("0") if isinstance(ops, dict) else None
    return rule.strip() if isinstance(rule, str) else ""


def journal_rule_outcome(db, tx_hash: str, block_hash: str):
    """What the engine did with the rule this transaction carried, read from the
    committed journal (issue #42), or None when the journal holds no revision
    for it (no rule, a clause kept in the registry, a node without the journal).

    Every revision the engine was asked for in a block is a row of the committed
    journal with that block as its tip, in block order, with the rule text and
    the engine's outcome. The k-th transaction of the block that carries a
    given text is the k-th row with that text. The journal is committed with
    the block, so this needs no record of this node's own and answers for a
    block the node applied before it kept outcomes. A count that does not match
    is reported, never guessed.
    """
    from block import compute_tx_hash

    block = db.get_block_by_hash(block_hash)
    transactions = (block or {}).get("transactions") or []
    position = next((i for i, tx in enumerate(transactions)
                     if isinstance(tx, dict) and compute_tx_hash(tx) == tx_hash), None)
    text = _rule_text(transactions[position]) if position is not None else ""
    if not text:
        return None
    journal = db.journal_revisions_of_block(block_hash)
    rows = [row for row in journal["revisions"] if row["rule_text"] == text]
    if not rows:
        return None
    same = [i for i, tx in enumerate(transactions) if _rule_text(tx) == text]
    out = {"source": "committed_journal"}
    if len(same) != len(rows):
        out["unavailable"] = (f"the block carries this rule {len(same)} time(s) and its "
                              f"journal {len(rows)}")
        return out
    row = rows[same.index(position)]
    outcome = row.get("outcome")
    out.update({
        "engine_outcome": outcome,
        "accepted": outcome in ("ACCEPTED_CHANGED", "ACCEPTED_NOOP"),
        "taken": outcome == "ACCEPTED_CHANGED",
    })
    if journal.get("spec_revision") is not None:
        # The commit record holds the counter after the block; every revision
        # the engine took later in the block lies between this one and it.
        later = sum(1 for r in journal["revisions"]
                    if r["seq"] > row["seq"] and r.get("outcome") == "ACCEPTED_CHANGED")
        out["spec_revision"] = journal["spec_revision"] - later
    return out


def _outcome(db, tx_hash: str, block_hash: str) -> dict:
    """What the confirmed transaction did in its block (issue #42)."""
    try:
        recorded = db.get_tx_outcome(tx_hash, block_hash)
    except Exception:
        logger.exception("Failed to read outcome for %s", tx_hash)
        recorded = None
    outcome = recorded if recorded is not None else {"status": "not_recorded"}
    try:
        from_journal = journal_rule_outcome(db, tx_hash, block_hash)
    except Exception:
        logger.exception("Failed to read the journal outcome for %s", tx_hash)
        from_journal = None
    if from_journal is not None:
        outcome["rule_outcome"] = from_journal
    return outcome


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
                data["outcome"] = _outcome(db, tx_hash, loc["block_hash"])
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
