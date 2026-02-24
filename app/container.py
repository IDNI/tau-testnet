"""Dependency wiring helpers for the Tau Testnet server."""
from __future__ import annotations

import os
import secrets
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import multiaddr

import chain_state
import config
import db
import tau_manager
from commands import createblock, getmempool, gettimestamp, sendtx, getbalance, getsequence, history, getblocks, getallaccounts, gettaustate
from errors import DependencyError
from network import BootstrapPeer, NetworkConfig
from network.identity import IDENTITY_SEED_SIZE


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
    miner: Any = None
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
            "gettimestamp": gettimestamp,
            "createblock": createblock,
            "getbalance": getbalance,
            "getsequence": getsequence,
            "history": history,
            "getblocks": getblocks,
            "getallaccounts": getallaccounts,
            "gettaustate": gettaustate,
        }

        mempool = override_map.get("mempool") or []
        mempool_lock = override_map.get("mempool_lock") or threading.Lock()
        mempool_state = override_map.get("mempool_state") or {
            "mempool": mempool,
            "lock": mempool_lock,
        }


        db_module = override_map.get("db", db)
        chain_state_module = override_map.get("chain_state", chain_state)
        tau_manager_module = override_map.get("tau_manager", tau_manager)

        # Wire up circular dependencies via callbacks
        if hasattr(tau_manager_module, "set_rules_handler") and hasattr(chain_state_module, "save_rules_state"):
            tau_manager_module.set_rules_handler(chain_state_module.save_rules_state)

        # Instantiate Miner if configured
        miner_instance = None
        if resolved_settings.authority.miner_privkey and resolved_settings.authority.mining_enabled:
            from miner.service import SoleMiner
            # We might need to pass custom engine/state store if mocked, but for now use defaults
            miner_instance = SoleMiner(max_block_interval=30.0) 
        else:
            miner_instance = None

        return cls(
            settings=resolved_settings,
            logger=logger,
            command_handlers=command_handlers,
            mempool_state=mempool_state,
            db=db_module,
            chain_state=chain_state_module,
            tau_manager=tau_manager_module,
            miner=miner_instance,
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

        dht_bootstrap_peers: list[BootstrapPeer] = []
        for entry in self.settings.dht.bootstrap_peers:
            try:
                peer_id = entry.get("peer_id")
                addr_list = entry.get("addrs", [])
                if not peer_id:
                    raise DependencyError("DHT bootstrap peer missing 'peer_id'")
                addrs = [multiaddr.Multiaddr(a) for a in addr_list]
                dht_bootstrap_peers.append(BootstrapPeer(peer_id=peer_id, addrs=addrs))
            except Exception as exc:
                self.logger.warning("Skipping invalid DHT bootstrap peer %s: %s", entry, exc)

        identity_key_bytes = None
        if not self.overrides.get("ephemeral_identity"):
            key_path = self.settings.network.identity_key_path or os.path.join(config.DATA_DIR, "identity.key")
            try:
                if not os.path.exists(key_path):
                    try:
                        os.makedirs(os.path.dirname(key_path) or ".", exist_ok=True)
                    except Exception:
                        pass
                    try:
                        generated_key = secrets.token_bytes(IDENTITY_SEED_SIZE)
                    except Exception as exc:
                        self.logger.warning("Failed to generate identity key: %s", exc)
                        generated_key = None
                    if generated_key is not None:
                        try:
                            with open(key_path, "wb") as f:
                                f.write(generated_key)
                            try:
                                os.chmod(key_path, 0o600)
                            except Exception:
                                pass
                        except Exception as exc:
                            self.logger.warning("Failed to write identity key to %s: %s", key_path, exc)
                # Load key if present
                if os.path.exists(key_path):
                    try:
                        with open(key_path, "rb") as f:
                            identity_key_bytes = f.read()
                        if identity_key_bytes:
                            self.logger.info("Loaded libp2p identity key from %s", key_path)
                        if identity_key_bytes and len(identity_key_bytes) != IDENTITY_SEED_SIZE:
                            self.logger.warning(
                                "Ignoring identity key at %s with unexpected length %s (expected %s)",
                                key_path,
                                len(identity_key_bytes),
                                IDENTITY_SEED_SIZE,
                            )
                            identity_key_bytes = None
                            try:
                                regenerated = secrets.token_bytes(IDENTITY_SEED_SIZE)
                                with open(key_path, "wb") as f:
                                    f.write(regenerated)
                                try:
                                    os.chmod(key_path, 0o600)
                                except Exception:
                                    pass
                                identity_key_bytes = regenerated
                            except Exception as regen_exc:
                                self.logger.warning(
                                    "Failed to refresh identity key at %s: %s",
                                    key_path,
                                    regen_exc,
                                )
                    except Exception as exc:
                        self.logger.warning("Failed to read identity key from %s: %s", key_path, exc)
            except Exception as exc:
                self.logger.warning("Identity key setup error: %s", exc)

        return NetworkConfig(
            network_id=self.settings.network.network_id,
            genesis_hash=self.settings.network.genesis_hash,
            listen_addrs=listen_addrs,
            bootstrap_peers=bootstrap_peers,
            peerstore_path=self.settings.network.peerstore_path,
            identity_key=identity_key_bytes,
            dht_record_ttl=self.settings.dht.record_ttl,
            dht_validator_namespaces=list(self.settings.dht.validator_namespaces),
            dht_bootstrap_peers=dht_bootstrap_peers,
            conn_low_water=self.settings.network.conn_low_water,
            conn_high_water=self.settings.network.conn_high_water,
            conn_grace_period=self.settings.network.conn_grace_period,
            max_connections=self.settings.network.max_connections,
            rate_limit_per_peer=self.settings.network.rate_limit_per_peer,
            burst_per_peer=self.settings.network.burst_per_peer,
        )

    def get_command_handler(self, name: str) -> Any:
        handler = self.command_handlers.get(name)
        if handler is None:
            raise DependencyError(f"Unknown command handler requested: {name}")
        return handler
