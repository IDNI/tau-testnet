from __future__ import annotations

import json
from typing import Dict, List, Optional, Tuple

import db


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
