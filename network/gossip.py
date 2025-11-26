from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Union

import trio
from libp2p.peer.id import ID

from .protocols import TAU_PROTOCOL_GOSSIP
from .host import HostManager
from .dht_manager import DHTManager

logger = logging.getLogger(__name__)


class GossipManager:
    def __init__(self, host_manager: HostManager, dht_manager: DHTManager) -> None:
        self._host_manager = host_manager
        self._dht_manager = dht_manager
        self._handlers: Dict[str, List[Callable[[Dict[str, Any]], Any]]] = {}
        self._seen: Dict[str, float] = {}
        self._local_topics: Set[str] = set()
        self._peer_topics: Dict[str, Set[str]] = {}
        self._nursery: Optional[trio.Nursery] = None
        self._route_observer: Optional[Callable[[Dict[str, Any], str], None]] = None
        
        # Metrics
        self._metrics_published_total = 0
        self._metrics_received_total = 0
        self._metrics_last_published = None
        self._metrics_last_received = None

    def set_nursery(self, nursery: trio.Nursery):
        self._nursery = nursery
    
    def set_route_observer(self, observer: Callable[[Dict[str, Any], str], None]) -> None:
        self._route_observer = observer

    def subscribe(self, topic: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        if not topic or not callable(handler):
            raise ValueError("Invalid topic or handler")
        self._handlers.setdefault(topic, []).append(handler)

    async def join_topic(self, topic: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        self.subscribe(topic, handler)
        if topic in self._local_topics:
            return
        self._local_topics.add(topic)
        await self.broadcast_subscriptions([{"topic": topic, "subscribe": True}])

    async def publish(
        self,
        topic: str,
        payload: Any,
        message_id: Optional[str] = None,
        target_peers: Optional[Iterable[Union[str, ID]]] = None,
        content_keys: Optional[Iterable[Union[str, bytes]]] = None,
    ) -> str:
        host = self._host_manager.host
        if host is None:
            raise RuntimeError("Host not started")

        self._metrics_published_total += 1
        self._metrics_last_published = time.time()

        message_id = message_id or uuid.uuid4().hex
        now = time.time()
        envelope = {
            "origin": str(host.get_id()),
            "topic": topic,
            "payload": payload,
            "message_id": message_id,
            "timestamp": now,
            "via": str(host.get_id()),
        }
        
        self._seen[message_id] = now
        
        if self._route_observer:
            try:
                self._route_observer(envelope, "outgoing")
            except Exception:
                pass
        
        # Deliver locally
        # (Logic to call handlers would go here)

        # Rebroadcast or direct send
        if target_peers:
            # Direct send to specific peers
            payload_bytes = json.dumps({
                "peer_id": str(host.get_id()),
                "rpc": {"messages": [envelope]}
            }).encode()
            
            for peer_id in target_peers:
                if self._nursery:
                    self._nursery.start_soon(self._send_gossip, peer_id, payload_bytes)
        else:
            await self._rebroadcast(envelope, exclude={str(host.get_id())})
        return message_id

    async def _rebroadcast(self, message: Dict[str, Any], exclude: Set[str]) -> None:
        host = self._host_manager.host
        if not host:
            return

        peers = host.get_connected_peers()
        if not peers:
            try:
                # Fallback to known peers in peerstore if currently disconnected
                peers = list(getattr(host.get_peerstore(), "peer_data_map", {}).keys())
            except Exception:
                peers = []
        message = dict(message)
        message["via"] = str(host.get_id())
        payload = json.dumps({"peer_id": str(host.get_id()), "rpc": {"messages": [message]}}).encode()

        for peer_id in peers:
            pid_str = str(peer_id)
            if pid_str in exclude:
                continue
            
            # Simple fire-and-forget send
            if self._nursery:
                self._nursery.start_soon(self._send_gossip, peer_id, payload)
            else:
                # If no nursery, we can't easily spawn. 
                # But we should have one if started via Service.
                pass

    async def _send_gossip(self, peer_id: Any, payload: bytes) -> None:
        try:
            if isinstance(peer_id, str):
                peer_id = ID.from_base58(peer_id)
            host = self._host_manager.host
            if not host:
                return
            stream = await host.new_stream(peer_id, [TAU_PROTOCOL_GOSSIP])
            await stream.write(payload)
            await stream.close()
        except Exception:
            # logger.debug("Failed to send gossip to %s", peer_id)
            pass

    async def receive(self, envelope: Dict[str, Any]) -> None:
        import time
        self._metrics_received_total += 1
        self._metrics_last_received = time.time()
        msg_id = envelope.get("message_id")
        
        if self._route_observer:
            try:
                self._route_observer(envelope, "incoming")
            except Exception:
                pass
        
        if not msg_id or msg_id in self._seen:
            return
        
        self._seen[msg_id] = time.time()
        topic = envelope.get("topic")
        
        # Notify handlers
        if topic in self._handlers:
            for handler in self._handlers[topic]:
                try:
                    if self._nursery:
                        self._nursery.start_soon(handler, envelope)
                    else:
                        # Fallback?
                        pass
                except Exception:
                    pass
        
        # Notify wildcard handlers
        if "*" in self._handlers:
            for handler in self._handlers["*"]:
                try:
                    if self._nursery:
                        self._nursery.start_soon(handler, envelope)
                except Exception:
                    pass

        # Rebroadcast (floodsub style)
        # In a real implementation we check hops/TTL
        await self._rebroadcast(envelope, exclude=set())

    async def broadcast_subscriptions(self, subs: List[Dict[str, Any]]) -> None:
        # Send subscriptions to connected peers
        pass
