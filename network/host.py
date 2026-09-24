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
    describe_bind_failure,
    keypair_from_seed,
    seed_peerstore_persisted,
    split_listen_outcome,
)

logger = logging.getLogger(__name__)


# Backwards-compatible alias — some tests / external code still import the
# original private name. Removed once external callers migrate.
_NetworkNotifee = NetworkNotifee


class NetworkListenError(RuntimeError):
    """libp2p holds a socket for none of the configured listen addresses."""


class HostManager:
    def __init__(self, config: NetworkConfig, event_callback=None) -> None:
        self._config = config
        self._host: Optional[IHost] = None
        self._host_context: Optional[Any] = None
        self._peerstore_persist = PeerstorePersistence(config.peerstore_path)
        self._notifee = NetworkNotifee(event_callback)
        # Set once host.run() has attempted every listen addr, bound or not.
        # `NetworkService.start()` should not return "ready" until this is set,
        # otherwise callers may see `/tcp/0` or empty addrs and fail to connect.
        self._listen_settled = trio.Event()
        self._listen_error: Optional[NetworkListenError] = None
        self._bound_addrs: List[Any] = []

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
        configured = list(self._config.listen_addrs)
        async with self._host.run(configured):
            # host.run() does not fail when a bind does: libp2p drops the error
            # (see split_listen_outcome). Judge by what is actually bound; the
            # configured addrs prove nothing. Logging them is how a node whose
            # own WebSocket server held its p2p port looked healthy while every
            # peer's dial reached that server.
            bound, unbound = split_listen_outcome(self._host, configured)
            failures = [f"{addr} ({describe_bind_failure(addr)})" for addr in unbound]
            for failure in failures:
                logger.error("libp2p could not listen on %s", failure)
            self._bound_addrs = bound
            if configured and not bound:
                self._listen_error = NetworkListenError(
                    "libp2p could not listen on any configured address: "
                    + ", ".join(failures)
                )
                self._listen_settled.set()
                return
            try:
                peer_id_str = str(self.get_id())
            except Exception:
                peer_id_str = "<unknown>"
            listen_strs = [str(a) for a in bound]
            announce = getattr(self._config, "announce_addrs", None)
            hint_addrs = [str(a) for a in announce] if isinstance(announce, (list, tuple)) and announce else listen_strs
            connect_hints = [f"{addr}/p2p/{peer_id_str}" for addr in hint_addrs]
            self._listen_settled.set()
            logger.info(
                "NetworkService listening peer_id=%s addrs=%s connect=%s",
                peer_id_str,
                listen_strs,
                connect_hints,
            )
            await trio.sleep_forever()

    async def wait_listening(self, timeout: float = 5.0) -> None:
        """Wait until host.run() has tried every listen addr.

        Raises NetworkListenError if none of them bound, trio.TooSlowError if
        the host has not got that far within `timeout`.
        """
        with trio.fail_after(timeout):
            await self._listen_settled.wait()
        if self._listen_error is not None:
            raise self._listen_error

    @property
    def listen_addrs(self) -> List[Any]:
        """Addresses libp2p actually holds a socket for (ports resolved)."""
        return list(self._bound_addrs)

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
