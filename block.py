"""
block.py

Enhanced block data structures with PoA signature support.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import config

logger = logging.getLogger(__name__)

try:
    from py_ecc.bls import G2Basic

    _BLS_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - optional dependency
    G2Basic = None
    _BLS_AVAILABLE = False
except Exception:  # pragma: no cover - optional dependency
    G2Basic = None
    _BLS_AVAILABLE = False

EMPTY_STATE_HASH = "0" * 64


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_tx_hash(tx: Dict) -> str:
    """
    Compute the SHA256 hash of a transaction dictionary.
    Uses a canonical JSON representation with sorted keys.
    """
    tx_bytes = json.dumps(tx, sort_keys=True, separators=(",", ":")).encode()
    return sha256_hex(tx_bytes)


def compute_merkle_root(tx_hashes: List[str]) -> str:
    """
    Compute the Merkle root from a list of hex-encoded transaction hashes.
    If the list is empty, return SHA256 hash of empty bytes.
    If the list has odd length, duplicate the last hash to compute the tree.
    """
    if not tx_hashes:
        return sha256_hex(b"")
    level = [bytes.fromhex(h) for h in tx_hashes]
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        next_level = []
        for i in range(0, len(level), 2):
            combined = level[i] + level[i + 1]
            next_level.append(hashlib.sha256(combined).digest())
        level = next_level
    return level[0].hex()


def _hex_bytes(value: str, name: str) -> bytes:
    try:
        return bytes.fromhex(value)
    except ValueError as exc:  # pragma: no cover - defensive guard
        raise ValueError(f"Invalid hex string for {name}") from exc


@dataclass
class BlockHeader:
    block_number: int
    previous_hash: str
    timestamp: int
    merkle_root: str
    proposer_pubkey: str
    state_hash: str = EMPTY_STATE_HASH
    state_locator: str = ""

    def canonical_bytes(self) -> bytes:
        return (
            self.block_number.to_bytes(8, byteorder="big", signed=False)
            + _hex_bytes(self.previous_hash, "previous_hash")
            + self.timestamp.to_bytes(8, byteorder="big", signed=False)
            + _hex_bytes(self.merkle_root, "merkle_root")
            + (_hex_bytes(self.proposer_pubkey, "proposer_pubkey") if self.proposer_pubkey else b"")
            + _hex_bytes(self.state_hash, "state_hash")
        )

    def to_dict(self) -> Dict[str, str | int]:
        return {
            "block_number": self.block_number,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "proposer_pubkey": self.proposer_pubkey,
            "state_hash": self.state_hash,
            "state_locator": self.state_locator,
        }


@dataclass
class Block:
    header: BlockHeader
    transactions: List[Dict]
    block_hash: str
    consensus_proof: Optional[str] = None
    tx_ids: List[str] = field(default_factory=list)

    @classmethod
    def create(
        cls,
        block_number: int,
        previous_hash: str,
        transactions: List[Dict],
        proposer_pubkey: str,
        *,
        state_hash: Optional[str] = None,
        state_locator: Optional[str] = None,
        consensus_proof: Optional[str] = None,
        timestamp: Optional[int] = None,
    ) -> "Block":
        timestamp = timestamp or int(time.time())
        tx_hashes = [compute_tx_hash(tx) for tx in transactions]
        merkle_root = compute_merkle_root(tx_hashes)
        header = BlockHeader(
            block_number=block_number,
            previous_hash=previous_hash,
            timestamp=timestamp,
            merkle_root=merkle_root,
            proposer_pubkey=proposer_pubkey,
            state_hash=(state_hash or EMPTY_STATE_HASH),
            state_locator=state_locator or "",
        )
        header_bytes = header.canonical_bytes()
        block_hash = sha256_hex(header_bytes)

        return cls(
            header=header,
            transactions=transactions,
            block_hash=block_hash,
            consensus_proof=consensus_proof,
            tx_ids=tx_hashes,
        )

    @classmethod
    def from_dict(cls, payload: Dict) -> "Block":
        header_payload = payload.get("header", {}) if isinstance(payload, dict) else {}
        header = BlockHeader(
            block_number=int(header_payload.get("block_number") or 0),
            previous_hash=str(header_payload.get("previous_hash") or "0" * 64),
            timestamp=int(header_payload.get("timestamp") or 0),
            merkle_root=str(header_payload.get("merkle_root") or "0" * 64),
            proposer_pubkey=str(header_payload.get("proposer_pubkey") or ""),
            state_hash=str(header_payload.get("state_hash") or EMPTY_STATE_HASH),
            state_locator=str(header_payload.get("state_locator") or ""),
        )
        transactions = payload.get("transactions") if isinstance(payload, dict) else None
        if not isinstance(transactions, list):
            transactions = []
        block_hash = str(payload.get("block_hash") or "")
        tx_ids = payload.get("tx_ids")
        if not isinstance(tx_ids, list) or not all(isinstance(x, str) for x in tx_ids):
            tx_ids = [compute_tx_hash(tx) for tx in transactions]
        block = cls(
            header=header,
            transactions=transactions,
            block_hash=block_hash or sha256_hex(header.canonical_bytes()),
            consensus_proof=payload.get("consensus_proof"),
            tx_ids=tx_ids,
        )
        canonical_hash = sha256_hex(header.canonical_bytes())
        if block.block_hash and block.block_hash != canonical_hash:
            raise ValueError("Block hash mismatch for block_number %s" % header.block_number)
        if not block.block_hash:
            block.block_hash = canonical_hash
        return block

    def to_dict(self) -> Dict:
        return {
            "header": self.header.to_dict(),
            "transactions": self.transactions,
            "block_hash": self.block_hash,
            "consensus_proof": self.consensus_proof,
            "tx_ids": self.tx_ids,
        }


def bls_signing_available() -> bool:
    return _BLS_AVAILABLE