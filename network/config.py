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


