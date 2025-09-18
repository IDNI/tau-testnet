"""Dependency wiring helpers for the Tau Testnet server."""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import multiaddr

import chain_state
import config
import db
import tau_manager
from commands import createblock, getmempool, gettimestamp, sendtx
from errors import DependencyError
from network import BootstrapPeer, NetworkConfig


@dataclass
class ServiceContainer:
    """Simple dependency container to ease testing and wiring."""

    settings: config.Settings
    logger: logging.Logger
    command_handlers: Dict[str, Any]
    mempool_state: Dict[str, Any]
    db: Any
    chain_state: Any
    tau_manager: Any
    overrides: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def build(
        cls,
        *,
        settings: Optional[config.Settings] = None,
        overrides: Optional[Dict[str, Any]] = None,
    ) -> "ServiceContainer":
        resolved_settings = settings or config.settings
        override_map = overrides or {}

        logger: logging.Logger = override_map.get("logger") or logging.getLogger("tau.server")
        command_handlers = override_map.get("command_handlers") or {
            "sendtx": sendtx,
            "getmempool": getmempool,
            "getcurrenttimestamp": gettimestamp,
            "createblock": createblock,
        }

        mempool = override_map.get("mempool") or []
        mempool_lock = override_map.get("mempool_lock") or threading.Lock()
        mempool_state = override_map.get("mempool_state") or {
            "mempool": mempool,
            "lock": mempool_lock,
        }

        return cls(
            settings=resolved_settings,
            logger=logger,
            command_handlers=command_handlers,
            mempool_state=mempool_state,
            db=override_map.get("db", db),
            chain_state=override_map.get("chain_state", chain_state),
            tau_manager=override_map.get("tau_manager", tau_manager),
            overrides=override_map,
        )

    def build_network_config(self) -> NetworkConfig:
        listen_addrs = []
        for addr in self.settings.network.listen:
            try:
                listen_addrs.append(multiaddr.Multiaddr(addr))
            except Exception as exc:
                self.logger.warning("Skipping invalid listen address %s: %s", addr, exc)

        bootstrap_peers: list[BootstrapPeer] = []
        for entry in self.settings.network.bootstrap_peers:
            try:
                peer_id = entry.get("peer_id")
                addr_list = entry.get("addrs", [])
                if not peer_id:
                    raise DependencyError("Bootstrap peer missing 'peer_id'")
                addrs = [multiaddr.Multiaddr(a) for a in addr_list]
                bootstrap_peers.append(BootstrapPeer(peer_id=peer_id, addrs=addrs))
            except Exception as exc:
                self.logger.warning("Skipping invalid bootstrap peer %s: %s", entry, exc)

        return NetworkConfig(
            network_id=self.settings.network.network_id,
            genesis_hash=self.settings.network.genesis_hash,
            listen_addrs=listen_addrs,
            bootstrap_peers=bootstrap_peers,
            peerstore_path=self.settings.network.peerstore_path,
        )

    def get_command_handler(self, name: str) -> Any:
        handler = self.command_handlers.get(name)
        if handler is None:
            raise DependencyError(f"Unknown command handler requested: {name}")
        return handler
