"""Thin facade around the upstream libp2p KadDHT implementation."""
from __future__ import annotations

from typing import Any, Iterable, Optional

from libp2p.kad_dht.kad_dht import KadDHT
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo


class DHTFacade:
    """Simple delegating wrapper exposing minimal KadDHT functionality."""

    def __init__(self, dht: KadDHT) -> None:
        self._dht = dht

    async def find_peer(self, peer_id: ID) -> Optional[PeerInfo]:
        return await self._dht.find_peer(peer_id)

    async def find_peers_closest_to_key(self, key: bytes, count: int = 20) -> Iterable[ID]:
        return await self._dht.peer_routing.find_closest_peers_network(key, count)

    async def get_value(self, key: bytes) -> Optional[bytes]:
        return await self._dht.get_value(key)

    async def put_value(self, key: bytes, value: bytes) -> bool:
        return await self._dht.put_value(key, value)

    async def provide(self, key: bytes) -> bool:
        return await self._dht.provider_store.provide(key)

    async def find_providers(self, key: bytes) -> Iterable[PeerInfo]:
        return await self._dht.provider_store.find_providers(key)


__all__ = ["DHTFacade"]
