from __future__ import annotations

import logging
from typing import Any, List, Optional

import trio
from libp2p import new_host
from libp2p.abc import IHost
from libp2p.peer.id import ID

from .config import NetworkConfig
from .libp2p_compat import (
    NetworkNotifee,
    PeerstorePersistence,
    attach_resource_manager,
    build_tau_resource_manager,
    keypair_from_seed,
    seed_peerstore_persisted,
)

logger = logging.getLogger(__name__)


# Backwards-compatible alias — some tests / external code still import the
# original private name. Removed once external callers migrate.
_NetworkNotifee = NetworkNotifee


class HostManager:
    def __init__(self, config: NetworkConfig, event_callback=None) -> None:
        self._config = config
        self._host: Optional[IHost] = None
        self._host_context: Optional[Any] = None
        self._peerstore_persist = PeerstorePersistence(config.peerstore_path)
        self._notifee = NetworkNotifee(event_callback)
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

        resource_manager = build_tau_resource_manager(self._config)
        self._host = new_host(
            key_pair=key_pair,
            listen_addrs=self._config.listen_addrs,
            resource_manager=resource_manager,
        )
        attach_resource_manager(self._host, resource_manager)
        self._host.get_network().register_notifee(self._notifee)
        seed_peerstore_persisted(self._host, self._peerstore_persist)

    async def run_loop(self) -> None:
        if self._host is None:
            return
        async with self._host.run(self._config.listen_addrs):
            try:
                listen_addrs = getattr(self._host.get_network(), "listen_addrs", None)
                # Logging-only fallback: some libp2p shims expose `listen_addrs`
                # but keep it empty even when the host is actually listening. Fall
                # back to the configured addrs so the log line is useful. Callers
                # that need observed addrs should use libp2p_compat.collect_listen_addrs.
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
