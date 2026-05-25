from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

import multiaddr
import trio
from libp2p.peer.peerinfo import PeerInfo
from libp2p.peer.peerstore import PERMANENT_ADDR_TTL

from .config import NetworkConfig
from .host import HostManager
from .dht_manager import DHTManager
from .libp2p_compat import ensure_peer_id, seed_peerstore

logger = logging.getLogger(__name__)


class DiscoveryManager:
    def __init__(self, config: NetworkConfig, host_manager: HostManager, dht_manager: DHTManager, nursery: Optional[trio.Nursery] = None) -> None:
        self._config = config
        self._host_manager = host_manager
        self._dht_manager = dht_manager
        self._nursery = nursery
        self._opportunistic_peers: Dict[str, float] = {}

    def set_nursery(self, nursery: trio.Nursery):
        self._nursery = nursery

    def _ensure_peer_id(self, peer_id: Any):
        # Kept for backwards compatibility with external callers; delegates to compat.
        return ensure_peer_id(peer_id)

    async def seed_dht_bootstrap_peers(self, bootstrap_peers: List[Any], dht_bootstrap_peers: List[Any]) -> None:
        host = self._host_manager.host
        dht = self._dht_manager.dht
        if host is None or dht is None:
            return

        combined = {}
        for entry in bootstrap_peers:
            combined[str(entry.peer_id)] = entry
        for entry in dht_bootstrap_peers:
            combined[str(entry.peer_id)] = entry

        for entry in combined.values():
            parsed = seed_peerstore(host, entry.peer_id, entry.addrs)
            if not parsed:
                continue
            try:
                peer_id = ensure_peer_id(entry.peer_id)
            except Exception:
                continue
            try:
                await dht.routing_table.add_peer(PeerInfo(peer_id, parsed))
            except Exception:
                pass

    def ingest_peer_entries(self, entries: Iterable[Dict[str, Any]], source: str) -> List[str]:
        ingested = []
        host = self._host_manager.host
        if host is None:
            return ingested

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            peer_id = entry.get("peer_id")
            addrs_raw = entry.get("addrs", [])
            if not peer_id or not isinstance(addrs_raw, list):
                continue

            parsed = seed_peerstore(host, peer_id, addrs_raw)
            if not parsed:
                continue
            self.schedule_opportunistic_seed(peer_id, parsed)
            ingested.append(peer_id)
        return ingested

    def schedule_opportunistic_seed(self, peer_id: str, addrs: Optional[Iterable[Any]] = None) -> None:
        if not peer_id:
            return

        async def _seed() -> None:
            import time
            self._opportunistic_peers[peer_id] = time.time()
            # This would call back into service logic or we implement opportunistic seeding here
            # For now, let's just log or stub it, as the full logic involves connecting/identifying
            pass

        if self._nursery:
            self._nursery.start_soon(_seed)
        else:
            try:
                trio.lowlevel.spawn_system_task(_seed)
            except RuntimeError:
                pass
