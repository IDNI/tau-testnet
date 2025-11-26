from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import trio
from libp2p import new_host
from libp2p.abc import IHost, INotifee
from libp2p.peer.peerstore import PERMANENT_ADDR_TTL

import db
from .config import NetworkConfig
from .identity import keypair_from_seed

logger = logging.getLogger(__name__)


class _NetworkNotifee(INotifee):
    """Bridges swarm connection events back into the HostManager/Service."""

    def __init__(self, callback) -> None:
        self._callback = callback

    async def opened_stream(self, network, stream) -> None:
        return

    async def closed_stream(self, network, stream) -> None:
        return

    async def connected(self, network, conn) -> None:
        if self._callback:
            await self._callback("connected", conn)

    async def disconnected(self, network, conn) -> None:
        if self._callback:
            await self._callback("disconnected", conn)

    async def listen(self, network, multiaddr) -> None:
        return

    async def listen_close(self, network, multiaddr) -> None:
        return


class PeerstorePersistence:
    """DB-backed peerstore persistence."""

    def __init__(self, path: Optional[str]) -> None:
        self._path = path

    def load(self) -> Dict[str, List[str]]:
        try:
            return db.load_peers_basic()
        except Exception:
            return {}

    def save(self, peer_id_to_addrs: Dict[str, List[str]]) -> None:
        try:
            for pid, addrs in peer_id_to_addrs.items():
                db.upsert_peer_basic(
                    pid,
                    [str(addr) for addr in addrs],
                    agent=None,
                    network_id=None,
                    genesis_hash=None,
                )
        except Exception:
            logger.debug("Peerstore persistence failed", exc_info=True)


class HostManager:
    def __init__(self, config: NetworkConfig, event_callback=None) -> None:
        self._config = config
        self._host: Optional[IHost] = None
        self._host_context: Optional[Any] = None
        self._peerstore_persist = PeerstorePersistence(config.peerstore_path)
        self._notifee = _NetworkNotifee(event_callback)

    async def set_host(self, host: IHost, context: Any) -> None:
        """Sets the host instance (created externally or by a factory)."""
        self._host = host
        self._host_context = context
        self._host.get_network().register_notifee(self._notifee)

    async def start(self) -> None:
        if self._host is not None:
            return

        key_pair = None
        if self._config.identity_key:
            try:
                key_pair = keypair_from_seed(self._config.identity_key)
            except Exception:
                logger.warning("Failed to load identity key from config", exc_info=True)
        
        if not key_pair:
             # Generate ephemeral key if no persistent key provided
             import os
             key_pair = keypair_from_seed(os.urandom(32))

        self._host = new_host(
            key_pair=key_pair,
            listen_addrs=self._config.listen_addrs,
        )
        self._host.get_network().register_notifee(self._notifee)
        
        # Load peerstore
        peers = self._peerstore_persist.load()
        for pid, addrs in peers.items():
            try:
                self._host.get_peerstore().add_addrs(ID.from_base58(pid), [multiaddr.Multiaddr(a) for a in addrs], PERMANENT_ADDR_TTL)
            except Exception:
                pass

    async def run_loop(self) -> None:
        if self._host is None:
            return
        # BasicHost.run is an async context manager that handles listening
        async with self._host.run(self._config.listen_addrs):
            await trio.sleep_forever()

    @property
    def host(self) -> Optional[IHost]:
        return self._host

    def get_id(self) -> Any:
        if self._host:
            return self._host.get_id()
        return None

    def get_connected_peers(self) -> List[Any]:
        if self._host:
            return self._host.get_connected_peers()
        return []

    def get_peerstore(self):
        if self._host:
            return self._host.get_peerstore()
        return None
    
    def load_peerstore(self):
        return self._peerstore_persist.load()

    def save_peerstore(self, peer_map):
        self._peerstore_persist.save(peer_map)
