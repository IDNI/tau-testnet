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


# Transactions expected to write a rule effect at apply time: a user
# transaction carrying a rule unit (operations "0"), and an offer accept (which
# writes the accepted clause). A rule offer, a rule-change request or a cancel
# writes nothing at apply -- the change lands at release or at accept -- so
# they are NOT rule-bearing here: no effect for them is normal, not unmatched.
_RULE_BEARING_TYPES = ("rule_offer_accept",)


def _is_rule_bearing(tx) -> bool:
    """Whether this transaction carries a rule payload apply is expected to act on."""
    if not isinstance(tx, dict):
        return False
    tx_type = tx.get("tx_type") or "user_tx"
    if tx_type in _RULE_BEARING_TYPES:
        return True
    if tx_type == "user_tx":
        ops = tx.get("operations") if isinstance(tx.get("operations"), dict) else {}
        return bool(str(ops.get("0") or "").strip())
    return False


def _annotate_effect(db, effect: dict) -> dict:
    """A clause effect annotated with a POSITIVE registry check (issue #42).

    `registry_confirmed` is true only when the clause is actually found in
    `rule_clauses_v1` now, with the stored body matching the effect (or, for a
    revoke, with the registry no longer holding it). A false says only "not
    in the registry now" -- a clause revoked since reads false too -- and is
    never evidence the effect did not happen. Clause-ness is never inferred
    from absence: an effect is called a clause only because it was recorded
    as one, and the check confirms it against the registry.
    """
    if (effect.get("kind") != "clause" or effect.get("stream") is None
            or not effect.get("account")):
        return effect
    out = dict(effect)
    try:
        body = db.rule_clause_body(effect["account"], int(effect["stream"]))
    except Exception:
        logger.exception("Failed to check the registry for %s", effect.get("account"))
        return out
    import hashlib

    if effect.get("action") == "revoked":
        out["registry_confirmed"] = body is None
    elif effect.get("sha256"):
        out["registry_confirmed"] = (
            body is not None
            and hashlib.sha256(body.encode("utf-8")).hexdigest() == effect["sha256"])
    else:
        out["registry_confirmed"] = body is not None
    return out


def _rule_outcome_from_effects(effects) -> dict:
    """What the engine did with the transaction's rule, read off its effects.

    An application-rule effect carries the engine's revision receipt:
    `engine_outcome` (`ACCEPTED_CHANGED` / `ACCEPTED_NOOP`), whether the
    revision was `taken`, and the revision counter before/after the unit when
    recorded. A clause-only transaction names its registry confirmation
    instead. There is no third case here: a rule-bearing transaction with no
    effect at all is reported as `unmatched` by `_outcome`, never as a clause.
    """
    for effect in effects:
        if effect.get("kind") == "application_rule":
            rev = effect.get("revision") or {}
            if rev.get("engine_outcome"):
                out = {"engine_outcome": rev["engine_outcome"],
                       "taken": bool(rev.get("taken"))}
                for key in ("spec_revision_before", "spec_revision_after",
                            "spec_revision"):
                    if rev.get(key) is not None:
                        out[key] = rev[key]
                return out
    confirmed = [e.get("registry_confirmed") for e in effects
                 if e.get("kind") == "clause" and "registry_confirmed" in e]
    out = {"status": "clause"}
    if confirmed:
        out["registry_confirmed"] = all(confirmed)
    return out


def _block_tx(db, tx_hash: str, block_hash: str):
    """The transaction dict for one confirmed hash, or None when unreadable."""
    try:
        block = db.get_block_by_hash(block_hash) or {}
        txs = block.get("transactions") or []
        ids = block.get("tx_ids") or []
        if tx_hash in ids and len(ids) == len(txs):
            return txs[ids.index(tx_hash)]
    except Exception:
        logger.exception("Failed to read block %s for %s", block_hash, tx_hash)
    return None


def _outcome(db, tx_hash: str, block_hash: str, tx=None) -> dict:
    """What the confirmed transaction did in its block (issue #42)."""
    try:
        recorded = db.get_tx_outcome(tx_hash, block_hash)
    except Exception:
        logger.exception("Failed to read outcome for %s", tx_hash)
        recorded = None
    if recorded is None:
        return {"status": "not_recorded"}
    effects = recorded.get("rule_effects") or []
    if effects:
        recorded["rule_effects"] = [_annotate_effect(db, e) for e in effects]
        recorded["rule_outcome"] = _rule_outcome_from_effects(recorded["rule_effects"])
    elif _is_rule_bearing(tx):
        # A rule payload with no recorded effect: reported as unmatched, in
        # its own words -- never labelled a clause-registry rule, which is
        # what an absence-inferred label would do.
        recorded["rule_outcome"] = {
            "status": "unmatched",
            "detail": ("this transaction carries a rule payload but no rule "
                       "effect was recorded for it in this block"),
        }
    return recorded


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
                data["outcome"] = _outcome(
                    db, tx_hash, loc["block_hash"],
                    _block_tx(db, tx_hash, loc["block_hash"]))
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
