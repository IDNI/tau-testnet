"""
block.py

Module providing Block and BlockHeader data structures, and utility functions for
computing transaction hashes, Merkle roots, and block hashes.
"""

import time
import hashlib
import json
from dataclasses import dataclass
from typing import List, Dict


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compute_tx_hash(tx: Dict) -> str:
    """
    Compute the SHA256 hash of a transaction dictionary.
    Uses a canonical JSON representation with sorted keys.
    """
    tx_bytes = json.dumps(tx, sort_keys=True).encode()
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
            combined = level[i] + level[i+1]
            next_level.append(hashlib.sha256(combined).digest())
        level = next_level
    return level[0].hex()


@dataclass
class BlockHeader:
    block_number: int
    previous_hash: str
    timestamp: int
    merkle_root: str


@dataclass
class Block:
    header: BlockHeader
    transactions: List[Dict]
    block_hash: str

    @classmethod
    def create(cls, block_number: int, previous_hash: str, transactions: List[Dict]):
        timestamp = int(time.time())
        tx_hashes = [compute_tx_hash(tx) for tx in transactions]
        merkle_root = compute_merkle_root(tx_hashes)
        header = BlockHeader(
            block_number=block_number,
            previous_hash=previous_hash,
            timestamp=timestamp,
            merkle_root=merkle_root,
        )
        header_bytes = (
            block_number.to_bytes(8, byteorder='big') +
            bytes.fromhex(previous_hash) +
            timestamp.to_bytes(8, byteorder='big') +
            bytes.fromhex(merkle_root)
        )
        block_hash = sha256_hex(header_bytes)
        return cls(header=header, transactions=transactions, block_hash=block_hash)

    def to_dict(self) -> Dict:
        """
        Serialize the block to a dictionary.
        """
        return {
            "header": {
                "block_number": self.header.block_number,
                "previous_hash": self.header.previous_hash,
                "timestamp": self.header.timestamp,
                "merkle_root": self.header.merkle_root,
            },
            "transactions": self.transactions,
            "block_hash": self.block_hash,
        }