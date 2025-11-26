from __future__ import annotations

import json
from typing import Any, Dict, List, NamedTuple, Protocol, Sequence

from .state import StateStore, TauStateSnapshot, compute_state_hash


class TauExecutionResult(NamedTuple):
    snapshot: TauStateSnapshot
    accepted_transactions: List[Dict[str, Any]]
    rejected_transactions: List[Dict[str, Any]]
    receipts: Dict[str, Any]


class TauEngine(Protocol):
    """Interface that real Tau integrations should implement."""

    def apply(
        self,
        snapshot: TauStateSnapshot,
        transactions: Sequence[Dict[str, Any]],
    ) -> TauExecutionResult: ...


class MockTauEngine(TauEngine):
    """
    Deterministic stub used for integration tests before the Docker-based Tau binary is wired in.
    """

    def __init__(self, state_store: Optional[StateStore] = None) -> None:
        self._state_store = state_store or StateStore()

    def apply(
        self,
        snapshot: TauStateSnapshot,
        transactions: Sequence[Dict[str, Any]],
    ) -> TauExecutionResult:
        canonical_batch = json.dumps(list(transactions), sort_keys=True).encode("utf-8")
        combined = snapshot.tau_bytes + canonical_batch
        new_snapshot = TauStateSnapshot(
            state_hash=compute_state_hash(combined),
            tau_bytes=combined,
            metadata={**snapshot.metadata, "mock": True},
        )
        return TauExecutionResult(
            snapshot=self._state_store.commit(new_snapshot),
            accepted_transactions=list(transactions),
            rejected_transactions=[],
            receipts={"engine": "mock"},
        )

