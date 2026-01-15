from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import trio
import multiaddr
from libp2p import new_host
from libp2p.abc import IHost, INotifee
from libp2p.peer.id import ID
from libp2p.peer.peerstore import PERMANENT_ADDR_TTL
from libp2p.rcmgr.manager import ResourceManager, ResourceLimits
from libp2p.rcmgr.connection_limits import ConnectionLimits

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
        # `peerstore_path` is treated as an enable/disable flag for persistence.
        # When disabled (None), do not load any previously persisted peer addresses.
        # This avoids leaking stale addrs between test runs and keeps bootstrapping deterministic.
        if not self._path:
            return {}
        try:
            return db.load_peers_basic()
        except Exception:
            return {}

    def save(self, peer_id_to_addrs: Dict[str, List[str]]) -> None:
        if not self._path:
            return
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
        # Set once the libp2p host has actually entered its listening context.
        # `NetworkService.start()` should not return "ready" until this is set,
        # otherwise callers may see `/tcp/0` or empty addrs and fail to connect.
        self._listening = trio.Event()

    async def set_host(self, host: IHost, context: Any) -> None:
        """Sets the host instance (created externally or by a factory)."""
        self._host = host
        self._host_context = context
        self._host.get_network().register_notifee(self._notifee)

    async def start(self) -> None:
        if self._host is not None:
            return

        key_pair = None
        identity_source = "ephemeral"
        if self._config.identity_key:
            try:
                key_pair = keypair_from_seed(self._config.identity_key)
                identity_source = "persistent"
            except Exception:
                logger.warning("Failed to load identity key from config", exc_info=True)
        
        if not key_pair:
            # Generate ephemeral key if no persistent key provided
            import os
            key_pair = keypair_from_seed(os.urandom(32))
        
        try:
            expected_peer_id = str(ID.from_pubkey(key_pair.public_key))
            logger.info(
                "Network identity ready peer_id=%s source=%s",
                expected_peer_id,
                identity_source,
            )
        except Exception:
            logger.debug("Failed to compute peer_id from identity key", exc_info=True)

        # Configure Resource Manager
        # Map config values to ResourceLimits and ConnectionLimits
        # max_connections: Global hard cap (conn_max_connections)
        # conn_high_water: Used here as max established inbound limit for safety
        
        res_limits = ResourceLimits(
            max_connections=self._config.max_connections,
            max_streams=10000, # Default
        )
        
        conn_limits = ConnectionLimits(
            max_established_total=self._config.max_connections,
            max_established_inbound=self._config.conn_high_water,
            max_established_per_peer=self._config.conn_high_water, # Allow robust peer connections but capped
            max_pending_inbound=self._config.conn_low_water, # Use low water as pending limit?
        )
        
        resource_manager = ResourceManager(
            limits=res_limits,
            connection_limits=conn_limits,
            enable_metrics=True,
            enable_rate_limiting=True,
            connections_per_peer_per_sec=self._config.rate_limit_per_peer,
            burst_connections_per_peer=self._config.burst_per_peer,
        )

        self._host = new_host(
            key_pair=key_pair,
            listen_addrs=self._config.listen_addrs,
            resource_manager=resource_manager,
        )
        
        # Explicitly ensure RM is attached
        if hasattr(self._host.get_network(), "set_resource_manager"):
            self._host.get_network().set_resource_manager(resource_manager)

        self._host.get_network().register_notifee(self._notifee)
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
            try:
                listen_addrs = getattr(self._host.get_network(), "listen_addrs", None)
                # Some libp2p shims expose `listen_addrs` but keep it empty even when the
                # host is actually listening. Fall back to configured listen addrs for logs.
                if not listen_addrs:
                    listen_addrs = self._config.listen_addrs
                listen_strs = [str(a) for a in (listen_addrs or [])]
            except Exception:
                listen_strs = [str(a) for a in self._config.listen_addrs]
            try:
                peer_id_str = str(self.get_id())
            except Exception:
                peer_id_str = "<unknown>"
            connect_hints = [f"{addr}/p2p/{peer_id_str}" for addr in listen_strs]
            self._listening.set()
            logger.info(
                "NetworkService listening peer_id=%s addrs=%s connect=%s",
                peer_id_str,
                listen_strs,
                connect_hints,
            )
            await trio.sleep_forever()

    async def wait_listening(self, timeout: float = 5.0) -> None:
        """Wait until the host has actually started listening (i.e. entered host.run())."""
        with trio.fail_after(timeout):
            await self._listening.wait()

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
