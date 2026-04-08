from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from blake3 import blake3


def compute_state_hash(payload: bytes) -> str:
    """Return the canonical BLAKE3 hex digest for a Tau state payload."""
    return blake3(payload).hexdigest()


def compute_consensus_state_hash(rules_bytes: bytes, accounts_hash: bytes) -> str:
    """
    Computes the final consensus state hash committing to both Rules and Accounts.
    state_hash = BLAKE3(rules_bytes + accounts_hash).hexdigest()
    """
    hasher = blake3()
    hasher.update(rules_bytes)
    hasher.update(accounts_hash)
    return hasher.hexdigest()


@dataclass
class TauStateSnapshot:
    state_hash: str
    tau_bytes: bytes
    metadata: Dict[str, Any] = field(default_factory=dict)

    def clone(self) -> "TauStateSnapshot":
        return TauStateSnapshot(
            state_hash=self.state_hash,
            tau_bytes=self.tau_bytes,
            metadata=dict(self.metadata),
        )


class StateStore:
    """Thread-safe in-memory cache for Tau state snapshots."""

    def __init__(self, initial_snapshot: Optional[TauStateSnapshot] = None) -> None:
        self._lock = threading.Lock()
        self._snapshot = initial_snapshot or TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"",
            metadata={"source": "uninitialized"},
        )

    def current_snapshot(self) -> TauStateSnapshot:
        with self._lock:
            return self._snapshot.clone()

    def commit(self, snapshot: TauStateSnapshot) -> TauStateSnapshot:
        with self._lock:
            self._snapshot = snapshot.clone()
            return self._snapshot.clone()

    def snapshot_from_bytes(self, tau_bytes: bytes, metadata: Optional[Dict[str, Any]] = None) -> TauStateSnapshot:
        return TauStateSnapshot(
            state_hash=compute_state_hash(tau_bytes),
            tau_bytes=tau_bytes,
            metadata=metadata or {},
        )

    def bootstrap_from_chain_state(self) -> TauStateSnapshot:
        """
        Seed the store using the serialized rules currently cached in chain_state.
        """
        # Local import to avoid circular dependency at module import time.
        import chain_state  # pylint: disable=import-outside-toplevel

        rules_text = chain_state.get_rules_state() or ""
        snapshot = self.snapshot_from_bytes(
            rules_text.encode("utf-8"),
            metadata={"source": "chain_state"},
        )
        return self.commit(snapshot)

