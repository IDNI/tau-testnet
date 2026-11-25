from __future__ import annotations

import ipaddress
import logging
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

import multiaddr
from libp2p.peer.peerstore import PeerStore

logger = logging.getLogger(__name__)


def _ip_of(addr: multiaddr.Multiaddr) -> Optional[ipaddress._BaseAddress]:
    for proto in ("ip4", "ip6"):
        try:
            value = addr.value_for_protocol(proto)
        except multiaddr.exceptions.ProtocolLookupError:
            continue
        if value:
            return ipaddress.ip_address(value)
    return None


def is_public_addr(addr: Any) -> bool:
    """False for an unspecified, loopback, private or link-local IP address.

    An address without an IP part (for example `/dns4/...`) counts as public.
    """
    ma = addr if isinstance(addr, multiaddr.Multiaddr) else multiaddr.Multiaddr(str(addr))
    ip = _ip_of(ma)
    if ip is None:
        return True
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return not (ip.is_unspecified or ip.is_loopback or ip.is_private or ip.is_link_local)


def _without_p2p(addr: Any) -> str:
    return str(addr).split("/p2p/", 1)[0]


def _list_or_empty(value: Any) -> list:
    return list(value) if isinstance(value, (list, tuple)) else []


def _bound_to_non_public_ip(addr: Any) -> bool:
    try:
        ma = addr if isinstance(addr, multiaddr.Multiaddr) else multiaddr.Multiaddr(str(addr))
        ip = _ip_of(ma)
    except Exception:
        return False
    return ip is not None and not ip.is_unspecified and not is_public_addr(ma)


class PeerAddrPolicy:
    """Decides which learned peer addresses a node stores and dials.

    A node on a public network refuses non-public addresses of other peers:
    a peer bound to `0.0.0.0` advertises that address, and a dial to it
    reaches the local listener. A configured bootstrap address is always
    usable for its own peer id.
    """

    def __init__(self, allow_private: bool, bootstrap_addrs: Optional[Dict[str, List[multiaddr.Multiaddr]]] = None) -> None:
        self.allow_private = allow_private
        self._bootstrap_addrs: Dict[str, List[multiaddr.Multiaddr]] = bootstrap_addrs or {}
        self._bootstrap_strs: Dict[str, Set[str]] = {
            pid: {_without_p2p(a) for a in addrs} for pid, addrs in self._bootstrap_addrs.items()
        }

    @classmethod
    def from_config(cls, config: Any) -> "PeerAddrPolicy":
        bootstrap_addrs: Dict[str, List[multiaddr.Multiaddr]] = {}
        for entry in _list_or_empty(getattr(config, "bootstrap_peers", None)) + _list_or_empty(
            getattr(config, "dht_bootstrap_peers", None)
        ):
            pid = entry.get("peer_id") if isinstance(entry, dict) else getattr(entry, "peer_id", None)
            addrs = entry.get("addrs") if isinstance(entry, dict) else getattr(entry, "addrs", None)
            if not pid:
                continue
            known = bootstrap_addrs.setdefault(str(pid), [])
            for a in _list_or_empty(addrs):
                try:
                    ma = a if isinstance(a, multiaddr.Multiaddr) else multiaddr.Multiaddr(str(a))
                except Exception:
                    continue
                if ma not in known:
                    known.append(ma)

        explicit = getattr(config, "allow_private_peer_addrs", None)
        if isinstance(explicit, bool):
            allow_private = explicit
        else:
            # A node that listens on a loopback or private IP, or that has a
            # bootstrap peer at such an IP, runs on a local network.
            allow_private = any(
                _bound_to_non_public_ip(a) for a in _list_or_empty(getattr(config, "listen_addrs", None))
            ) or any(
                _bound_to_non_public_ip(a) for addrs in bootstrap_addrs.values() for a in addrs
            )
        return cls(allow_private, bootstrap_addrs)

    def is_usable(self, peer_id: Any, addr: Any) -> bool:
        if self.allow_private:
            return True
        if _without_p2p(addr) in self._bootstrap_strs.get(str(peer_id), ()):
            return True
        try:
            return is_public_addr(addr)
        except Exception:
            return False

    def filter(self, peer_id: Any, addrs: Iterable[Any]) -> List[multiaddr.Multiaddr]:
        """Parse `addrs` and keep the usable ones. Unparsable items are dropped."""
        kept: List[multiaddr.Multiaddr] = []
        for a in addrs or []:
            try:
                ma = a if isinstance(a, multiaddr.Multiaddr) else multiaddr.Multiaddr(str(a))
            except Exception:
                continue
            if self.is_usable(peer_id, ma):
                kept.append(ma)
            else:
                logger.debug("Refused non-public address %s of peer %s", ma, peer_id)
        return kept

    def bootstrap_addrs(self, peer_id: Any) -> List[multiaddr.Multiaddr]:
        return list(self._bootstrap_addrs.get(str(peer_id), ()))


def advertised_addrs(config: Any, policy: PeerAddrPolicy, own_id: Any, candidates: Iterable[Any]) -> List[multiaddr.Multiaddr]:
    """Addrs that a node tells its peers to dial.

    Configured announce addrs win. Else only the `candidates` that `policy`
    accepts, so a node on `0.0.0.0` with no announce addr sends none.
    """
    announce = getattr(config, "announce_addrs", None)
    if isinstance(announce, (list, tuple)) and announce:
        parsed: List[multiaddr.Multiaddr] = []
        for a in announce:
            try:
                parsed.append(a if isinstance(a, multiaddr.Multiaddr) else multiaddr.Multiaddr(str(a)))
            except Exception:
                logger.warning("Skipped announce address %r: not a multiaddr", a)
        if parsed:
            return parsed
    return policy.filter(own_id, candidates)


def self_advertised_addrs(config: Any, policy: PeerAddrPolicy, host: Any) -> List[multiaddr.Multiaddr]:
    try:
        bound = list(host.get_addrs() or [])
        own_id = host.get_id()
    except Exception:
        bound, own_id = [], None
    return advertised_addrs(config, policy, own_id, bound)


class FilteringPeerStore(PeerStore):
    """Peerstore that stores only the addrs that `PeerAddrPolicy` accepts.

    libp2p identify and the KadDHT write to the peerstore directly, so the
    filter must be here. The configured addrs of a bootstrap peer stay first,
    because libp2p dials the first known addr of each transport.
    """

    def __init__(self, policy: PeerAddrPolicy, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.addr_policy = policy

    def add_addrs(self, peer_id: Any, addrs: Sequence[Any], ttl: int = 0) -> None:
        kept = self.addr_policy.filter(peer_id, addrs)
        if kept:
            super().add_addrs(peer_id, kept, ttl)
        self._put_bootstrap_addrs_first(peer_id)

    def clear_addrs(self, peer_id: Any) -> None:
        configured = self.addr_policy.bootstrap_addrs(peer_id)
        peer_data = self.peer_data_map.get(peer_id)
        if configured and peer_data is not None:
            # Identify clears the addrs of a peer before it adds its own list.
            peer_data.addrs = configured
            return
        super().clear_addrs(peer_id)

    def _put_bootstrap_addrs_first(self, peer_id: Any) -> None:
        configured = self.addr_policy.bootstrap_addrs(peer_id)
        peer_data = self.peer_data_map.get(peer_id) if configured else None
        if peer_data is None:
            return
        peer_data.addrs = configured + [a for a in peer_data.addrs if a not in configured]
