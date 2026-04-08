from __future__ import annotations

import json
from typing import Callable, Dict, Iterable, List, Optional, Tuple

import db
from block import compute_tx_hash


DecodedEntry = Tuple[str, Dict]


def _decode_payload(raw: str) -> Optional[DecodedEntry]:
    blob = raw[5:] if raw.startswith("json:") else raw
    try:
        payload = json.loads(blob)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    return blob, payload


def load_transactions() -> List[Dict]:
    """Return all mempool transactions as parsed dicts (invalid rows skipped)."""
    entries = []
    for raw in db.get_mempool_txs():
        decoded = _decode_payload(raw)
        if decoded:
            _, payload = decoded
            entries.append(payload)
    return entries


def reconcile_with_block(
    block_payload: Dict,
    *,
    validator: Optional[Callable[[Dict], bool]] = None,
) -> Dict[str, int]:
    """
    Remove transactions that were mined or fail the optional validator from the mempool.
    Returns statistics about the pruning step.
    """
    transactions = block_payload.get("transactions")
    if not isinstance(transactions, list):
        transactions = []
    target_hashes = {
        tx_hash
        for tx_hash in block_payload.get("tx_ids", [])  # fast path when tx_ids shipped
        if isinstance(tx_hash, str)
    }
    if not target_hashes:
        target_hashes = {compute_tx_hash(tx) for tx in transactions}

    original_rows = db.get_mempool_txs()
    survivors: List[str] = []
    removed = 0
    revalidations = 0

    for raw in original_rows:
        decoded = _decode_payload(raw)
        if not decoded:
            removed += 1
            continue
        blob, payload = decoded
        tx_hash = compute_tx_hash(payload)
        if tx_hash in target_hashes:
            removed += 1
            continue
        if validator and not validator(payload):
            removed += 1
            revalidations += 1
            continue
        survivors.append(blob)

    if removed > 0:
        db.clear_mempool()
        for blob in survivors:
            db.add_mempool_tx(blob)

    return {
        "original": len(original_rows),
        "kept": len(survivors),
        "removed": removed,
        "invalidated": revalidations,
    }

