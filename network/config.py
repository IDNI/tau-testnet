from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import multiaddr


@dataclass
class BootstrapPeer:
    peer_id: str
    addrs: List[multiaddr.Multiaddr]


@dataclass
class NetworkConfig:
    network_id: str
    genesis_hash: str
    listen_addrs: List[multiaddr.Multiaddr]
    bootstrap_peers: List[BootstrapPeer] = field(default_factory=list)
    agent: str = "tau-testnet/0.1"
    peerstore_path: Optional[str] = None
    # Optional raw private key bytes for persistent identity (implementation-specific)
    identity_key: Optional[bytes] = None
    dht_record_ttl: int = 24 * 60 * 60
    dht_validator_namespaces: List[str] = field(default_factory=lambda: ["block", "tx", "state"])
    dht_bootstrap_peers: List[BootstrapPeer] = field(default_factory=list)
    dht_refresh_interval: float = 60.0
    dht_bucket_refresh_interval: float = 0.0
    dht_bucket_refresh_limit: int = 8
    dht_stale_peer_threshold: float = 3600.0
    gossip_health_window: float = 120.0
    dht_opportunistic_cooldown: float = 120.0
