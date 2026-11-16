"""The per-account clause registry: a shared base plus a small private delta.

Copies share the base and carry only their own changes, so copying, hashing and
persisting a registry cost the same however many clauses it holds.
"""
from __future__ import annotations

import secrets
from collections.abc import MutableMapping
from typing import Any, Dict, Iterator, List, Optional, Tuple

from consensus.serialization import (
    clause_entry_vector,
    clause_root_from_state,
    clause_state_add,
    clause_state_remove,
)

ClauseKey = Tuple[str, int]

_REMOVED = object()
_MISSING = object()


class ClausePlan:
    """What a block commit must write for the registry, and how to confirm it.

    Holds a frozen view of the registry, so the rows written are the rows that
    were hashed even if the live registry moves before the write.
    """

    __slots__ = ("token", "new_token", "changes", "_view", "_origin", "_version")

    def __init__(self, registry: "ClauseRegistry") -> None:
        self.token: Optional[str] = registry._token
        self.new_token: str = secrets.token_hex(8)
        self.changes: List[Tuple[ClauseKey, Optional[str]]] = [
            (key, registry.get(key)) for key in sorted(registry._changed)
        ]
        self._view = registry.__copy__()
        self._origin = registry
        self._version = registry._version

    def full_rows(self) -> List[Dict[str, Any]]:
        return [
            {"acceptor_pubkey": acceptor, "target_stream": stream, "clause_body": body}
            for (acceptor, stream), body in sorted(self._view.items())
        ]

    def confirm(self) -> None:
        """Call once the transaction carrying this plan has committed."""
        self._origin._confirm(self)


class ClauseRegistry(MutableMapping):
    """(account pubkey, target stream) -> clause body, with an incremental root."""

    FOLD_AT = 1024
    CHANGED_CAP = 4096

    __slots__ = ("_base", "_delta", "_count", "_state", "_changed", "_token", "_version")

    def __init__(self, items: Any = None) -> None:
        self._base: Dict[ClauseKey, str] = {}
        self._delta: Dict[ClauseKey, Any] = {}
        self._count = 0
        self._state = 0
        self._changed: set = set()
        self._token: Optional[str] = None
        self._version = 0
        if items:
            state = 0
            base = dict(items)
            for (acceptor, stream), body in base.items():
                state = clause_state_add(state, clause_entry_vector(acceptor, stream, body))
            self._base = base
            self._count = len(base)
            self._state = state

    # -- mapping ------------------------------------------------------------

    def __getitem__(self, key: ClauseKey) -> str:
        found = self._delta.get(key, _MISSING)
        if found is _MISSING:
            return self._base[key]
        if found is _REMOVED:
            raise KeyError(key)
        return found

    def get(self, key: ClauseKey, default: Any = None) -> Any:
        found = self._delta.get(key, _MISSING)
        if found is _MISSING:
            return self._base.get(key, default)
        return default if found is _REMOVED else found

    def __contains__(self, key: object) -> bool:
        found = self._delta.get(key, _MISSING)
        if found is _MISSING:
            return key in self._base
        return found is not _REMOVED

    def __len__(self) -> int:
        return self._count

    def __iter__(self) -> Iterator[ClauseKey]:
        delta = self._delta
        for key, body in delta.items():
            if body is not _REMOVED:
                yield key
        for key in self._base:
            if key not in delta:
                yield key

    def __setitem__(self, key: ClauseKey, body: str) -> None:
        previous = self.get(key)
        if previous == body:
            return
        acceptor, stream = key
        state = self._state
        if previous is not None:
            state = clause_state_remove(
                state, clause_entry_vector(acceptor, stream, previous)
            )
        else:
            self._count += 1
        self._state = clause_state_add(state, clause_entry_vector(acceptor, stream, body))
        self._delta[key] = body
        self._touch(key)

    def __delitem__(self, key: ClauseKey) -> None:
        previous = self.get(key)
        if previous is None:
            raise KeyError(key)
        acceptor, stream = key
        self._state = clause_state_remove(
            self._state, clause_entry_vector(acceptor, stream, previous)
        )
        self._count -= 1
        if key in self._base:
            self._delta[key] = _REMOVED
        else:
            del self._delta[key]
        self._touch(key)

    def _touch(self, key: ClauseKey) -> None:
        self._version += 1
        if self._token is not None:
            self._changed.add(key)
            if len(self._changed) > self.CHANGED_CAP:
                self._token = None
                self._changed.clear()
        if len(self._delta) >= self.FOLD_AT:
            self._fold()

    def _fold(self) -> None:
        merged = dict(self._base)
        for key, body in self._delta.items():
            if body is _REMOVED:
                del merged[key]
            else:
                merged[key] = body
        self._base = merged
        self._delta = {}

    # -- copying ------------------------------------------------------------

    def __copy__(self) -> "ClauseRegistry":
        clone = self.__class__.__new__(self.__class__)
        clone._base = self._base
        clone._delta = dict(self._delta)
        clone._count = self._count
        clone._state = self._state
        clone._changed = set(self._changed)
        clone._token = self._token
        clone._version = self._version
        return clone

    def __deepcopy__(self, memo: Dict[int, Any]) -> "ClauseRegistry":
        clone = self.__copy__()
        memo[id(self)] = clone
        return clone

    # -- commitment ---------------------------------------------------------

    def root(self) -> bytes:
        return clause_root_from_state(self._count, self._state)

    # -- persistence --------------------------------------------------------

    def storage_plan(self) -> ClausePlan:
        return ClausePlan(self)

    def adopt_stored_token(self, token: Optional[str]) -> None:
        """Pair a registry rebuilt from the stored rows with the table's token."""
        self._token = token
        self._changed.clear()

    def _confirm(self, plan: ClausePlan) -> None:
        if self._version != plan._version or self._token != plan.token:
            return
        self._token = plan.new_token
        self._changed.clear()
