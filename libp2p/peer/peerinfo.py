from __future__ import annotations

from dataclasses import dataclass
from typing import List

import multiaddr


@dataclass
class PeerInfo:
    peer_id: str
    addrs: List[multiaddr.Multiaddr]


