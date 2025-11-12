from __future__ import annotations

import inspect
import json
import logging
import time
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Union

import multiaddr
import trio
from google.protobuf.message import DecodeError
from libp2p import new_host
from libp2p.abc import IHost, INotifee
from libp2p.identity.identify import ID as IDENTIFY_PROTOCOL_ID
from libp2p.identity.identify.pb.identify_pb2 import Identify as IdentifyMessage
from libp2p.kad_dht import common as dht_common
from libp2p.kad_dht.kad_dht import KadDHT, DHTMode
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo
from libp2p.peer.peerstore import (
    PERMANENT_ADDR_TTL,
    PeerStoreError,
)
from libp2p.tools.async_service import background_trio_service

from . import bus
from .config import BootstrapPeer, NetworkConfig
from .protocols import (
    TAU_GOSSIP_TOPIC_BLOCKS,
    TAU_GOSSIP_TOPIC_TRANSACTIONS,
    TAU_GOSSIP_TOPIC_PEERS,
    TAU_PROTOCOL_BLOCKS,
    TAU_PROTOCOL_GOSSIP,
    TAU_PROTOCOL_HANDSHAKE,
    TAU_PROTOCOL_PING,
    TAU_PROTOCOL_STATE,
    TAU_PROTOCOL_SYNC,
    TAU_PROTOCOL_TX,
)
import chain_state
import db
from commands import sendtx
from .identity import keypair_from_seed


logger = logging.getLogger(__name__)


class _NetworkNotifee(INotifee):
    """Bridges swarm connection events back into the NetworkService."""

    def __init__(self, service: "NetworkService") -> None:
        self._service = service

    async def opened_stream(self, network, stream) -> None:  # pragma: no cover - no-op
        return

    async def closed_stream(self, network, stream) -> None:  # pragma: no cover - no-op
        return

    async def connected(self, network, conn) -> None:
        await self._service._on_peer_connected(conn)

    async def disconnected(self, network, conn) -> None:
        await self._service._on_peer_disconnected(conn)

    async def listen(self, network, multiaddr) -> None:  # pragma: no cover - no-op
        return

    async def listen_close(self, network, multiaddr) -> None:  # pragma: no cover - no-op
        return


class PeerstorePersistence:
    """DB-backed peerstore persistence. The `path` is kept for compatibility."""

    def __init__(self, path: Optional[str]) -> None:
        self._path = path

    def load(self) -> Dict[str, List[str]]:
        try:
            return db.load_peers_basic()
        except Exception:  # pragma: no cover - defensive
            return {}

    def save(self, peer_id_to_addrs: Dict[str, List[str]]) -> None:
        try:
            for pid, addrs in peer_id_to_addrs.items():
                db.upsert_peer_basic(
                    pid,
                    [str(addr) for addr in addrs],
                    agent=None,
                    network_id=None,
                    genesis_hash=None,
                )
        except Exception:  # pragma: no cover - defensive
            logger.debug("Peerstore persistence failed", exc_info=True)


class NetworkService:
    def __init__(
        self,
        config: NetworkConfig,
        *,
        tx_submitter: Optional[Callable[[str], str]] = None,
        state_provider: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        gossip_handler: Optional[Callable[[Dict[str, Any]], Any]] = None,
    ) -> None:
        self._config = config
        self._submit_tx = tx_submitter or sendtx.queue_transaction
        self._state_provider = state_provider or self._default_state_provider

        self._host: Optional[IHost] = None
        self._host_context: Optional[Any] = None

        self._peerstore_persist = PeerstorePersistence(config.peerstore_path)
        self._last_announced_tip: Optional[str] = None

        self._notifee = _NetworkNotifee(self)
        self._mempool_synced_peers: Set[str] = set()

        self._gossip_handlers: Dict[str, List[Callable[[Dict[str, Any]], Any]]] = {}
        if gossip_handler:
            self.subscribe_gossip("*", gossip_handler)

        self._gossip_seen: Dict[str, float] = {}
        self._gossip_seen_ttl = 300.0
        self._gossip_peer_topics: Dict[str, Set[str]] = {}
        self._gossip_local_topics: Set[str] = set()

        self._pending_tx: Dict[str, Dict[str, Any]] = {}

        self._runner_started: Optional[trio.Event] = None
        self._runner_finished: Optional[trio.Event] = None
        self._runner_stop: Optional[trio.Event] = None
        self._nursery: Optional[trio.Nursery] = None
        self._trio_token: Optional[trio.lowlevel.TrioToken] = None
        self._dht: Optional[KadDHT] = None
        self._dht_manager: Optional[Any] = None
        self._dht_validators: Dict[str, Callable[[bytes, bytes], bool]] = {}
        self._dht_allowed_namespaces: Set[str] = set()
        self._dht_value_store_put: Optional[Callable[..., Any]] = None
        self._dht_provider_add: Optional[Callable[..., Any]] = None
        self._dht_refresh_interval = float(getattr(config, "dht_refresh_interval", 60.0) or 60.0)
        bucket_interval_default = self._dht_refresh_interval
        self._dht_bucket_refresh_interval = float(
            getattr(config, "dht_bucket_refresh_interval", bucket_interval_default)
            or bucket_interval_default
        )
        self._dht_bucket_refresh_limit = max(1, int(getattr(config, "dht_bucket_refresh_limit", 8) or 1))
        self._dht_stale_peer_threshold = max(
            0.0, float(getattr(config, "dht_stale_peer_threshold", 3600.0) or 3600.0)
        )
        self._gossip_health_window = max(
            0.0, float(getattr(config, "gossip_health_window", 120.0) or 120.0)
        )
        self._metrics: Dict[str, float] = {
            "gossip_published": 0,
            "gossip_received": 0,
            "dht_refresh_success": 0,
            "dht_refresh_failure": 0,
            "dht_bucket_checks": 0,
            "dht_bucket_replacements": 0,
            "dht_bucket_errors": 0,
        }
        self._metric_timestamps: Dict[str, float] = {
            "gossip_last_publish": 0.0,
            "gossip_last_receive": 0.0,
            "dht_last_refresh": 0.0,
            "dht_last_bucket_refresh": 0.0,
        }
        self._opportunistic_peers: Dict[str, float] = {}
        self._identifying_peers: Set[str] = set()
        self._opportunistic_peer_cooldown = max(
            5.0,
            float(getattr(config, "dht_opportunistic_cooldown", 120.0) or 120.0),
        )
        self._handshake_peer_limit = max(
            0, int(getattr(config, "dht_handshake_max_peers", 16) or 0)
        )
        self._handshake_provider_limit = max(
            0, int(getattr(config, "dht_handshake_max_providers", 16) or 0)
        )
        self._peer_advertisement_interval = max(
            0.0, float(getattr(config, "peer_advertisement_interval", 180.0) or 180.0)
        )
        self._peer_advertisement_max_peers = max(
            0, int(getattr(config, "peer_advertisement_max_peers", 16) or 0)
        )
        recent_window_default = float(
            getattr(config, "peer_advertisement_recent_window", 600.0) or 600.0
        )
        self._peer_advertisement_recent_window = max(
            1.0,
            recent_window_default,
            self._peer_advertisement_interval if self._peer_advertisement_interval > 0 else 0.0,
        )

    # ------------------------------------------------------------------ Gossip API
    def subscribe_gossip(self, topic: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        if not isinstance(topic, str) or not topic:
            raise ValueError("topic must be a non-empty string")
        if not callable(handler):
            raise ValueError("handler must be callable")
        self._gossip_handlers.setdefault(topic, []).append(handler)

    async def join_gossip_topic(self, topic: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        self.subscribe_gossip(topic, handler)
        if topic in self._gossip_local_topics:
            return
        self._gossip_local_topics.add(topic)
        await self._broadcast_gossip_subscriptions(
            [{"topic": topic, "subscribe": True}]
        )

    async def publish_gossip(
        self,
        topic: str,
        payload: Any,
        *,
        message_id: Optional[str] = None,
        target_peers: Optional[Iterable[Union[str, ID]]] = None,
        content_keys: Optional[Iterable[Union[str, bytes]]] = None,
    ) -> str:
        if self._host is None:
            raise RuntimeError("network service is not started")
        if not isinstance(topic, str) or not topic:
            raise ValueError("topic must be a non-empty string")

        message_id = message_id or uuid.uuid4().hex
        now = time.time()
        envelope = {
            "from": str(self._host.get_id()),
            "topic": topic,
            "data": payload,
            "message_id": message_id,
            "timestamp": now,
        }
        try:
            json.dumps(envelope)
        except TypeError as exc:
            raise ValueError("gossip payload must be JSON serializable") from exc

        logger.debug(
            "[network][gossip] Local publish topic=%s message_id=%s payload=%s",
            topic,
            message_id,
            payload,
        )
        self._gossip_seen[message_id] = now
        self._metrics["gossip_published"] += 1
        self._metric_timestamps["gossip_last_publish"] = now
        target_peer_ids: List[str] = []
        if target_peers:
            for peer in target_peers:
                peer_id_str = None
                if isinstance(peer, ID):
                    peer_id_str = str(peer)
                elif isinstance(peer, str):
                    peer_id_str = peer
                else:
                    try:
                        peer_id_str = str(peer)
                    except Exception:
                        peer_id_str = None
                if peer_id_str:
                    target_peer_ids.append(peer_id_str)

        await self._deliver_gossip(envelope, via_peer=None)
        await self._rebroadcast_gossip_message(
            envelope,
            exclude={str(self._host.get_id())},
            target_peers=target_peer_ids or None,
            content_keys=content_keys,
        )
        return message_id

    def broadcast_transaction(self, payload: str, message_id: str) -> None:
        token = self._trio_token
        if token is None:
            logger.debug("broadcast_transaction called before network started")
            return

        async def _publish() -> None:
            await self.publish_gossip(
                TAU_GOSSIP_TOPIC_TRANSACTIONS,
                payload,
                message_id=message_id,
            )

        try:
            trio.from_thread.run(_publish, trio_token=token)
        except RuntimeError:
            # Already inside the Trio loop
            if self._nursery is not None:
                self._nursery.start_soon(_publish)
            else:
                logger.debug("Unable to schedule gossip publish; nursery not available")

    async def _rebroadcast_gossip_message(
        self,
        message: Dict[str, Any],
        *,
        exclude: Optional[Set[str]] = None,
        target_peers: Optional[Iterable[str]] = None,
        content_keys: Optional[Iterable[Union[str, bytes]]] = None,
    ) -> None:
        if self._host is None:
            return

        self_id = str(self._host.get_id())
        exclude_ids = set(exclude or set())
        exclude_ids.add(self_id)
        seen: Set[str] = set()
        candidate_peers: List[str] = []
        topic = message.get("topic")
        content_key_list: Optional[List[Union[str, bytes]]] = (
            list(content_keys) if content_keys is not None else None
        )

        def add_candidate(peer_id: Optional[str]) -> None:
            if not isinstance(peer_id, str) or not peer_id:
                return
            if peer_id == self_id or peer_id in exclude_ids or peer_id in seen:
                return
            seen.add(peer_id)
            candidate_peers.append(peer_id)

        try:
            connected_ids = [str(pid) for pid in self._host.get_connected_peers()]
        except Exception:  # pragma: no cover - defensive
            connected_ids = []
        for peer in connected_ids:
            add_candidate(peer)

        if target_peers:
            for peer in target_peers:
                add_candidate(peer)

        if isinstance(topic, str) and topic:
            for peer_id, topics in self._gossip_peer_topics.items():
                if topic in topics:
                    add_candidate(peer_id)

        if (content_key_list is not None and content_key_list) or not candidate_peers:
            dht_targets = await self._find_gossip_targets_via_dht(
                message,
                extra_keys=content_key_list,
                include_closest=False,
            )
            for peer_id in dht_targets:
                add_candidate(str(peer_id))

        payload = json.dumps(
            {
                "peer_id": str(self._host.get_id()),
                "rpc": {"messages": [message]},
            }
        ).encode()

        sent = False
        sent_peers: List[str] = []
        for peer in candidate_peers:
            if peer in exclude_ids:
                continue
            reachable = await self._ensure_route_to_peer(peer)
            if not reachable:
                continue
            await self._send_gossip_rpc(peer, payload)
            sent = True
            sent_peers.append(peer)

        if sent:
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    "Gossip message %s propagated via connected peers %s",
                    message.get("message_id"),
                    sent_peers,
                )
            return

        if await self._attempt_dht_gossip(message):
            return

    async def _broadcast_gossip_subscriptions(self, subs: List[Dict[str, Any]]) -> None:
        if self._host is None or not subs:
            return

        self_id = str(self._host.get_id())
        payload = json.dumps(
            {
                "peer_id": str(self._host.get_id()),
                "rpc": {"subscriptions": subs},
            }
        ).encode()

        try:
            peer_ids = [
                str(pid)
                for pid in self._host.get_connected_peers()
                if str(pid) != self_id
            ]
        except Exception:  # pragma: no cover - defensive
            return

        for peer in peer_ids:
            await self._send_gossip_rpc(peer, payload)

    async def _send_local_subscriptions_to_peer(self, peer_id: str) -> None:
        if self._host is None or not self._gossip_local_topics:
            return
        if not await self._ensure_route_to_peer(peer_id):
            logger.debug("Skipping subscription push; no route to %s", peer_id)
            return
        payload = json.dumps(
            {
                "peer_id": str(self._host.get_id()),
                "rpc": {
                    "subscriptions": [
                        {"topic": topic, "subscribe": True}
                        for topic in sorted(self._gossip_local_topics)
                    ]
                },
            }
        ).encode()
        logger.debug("Sending local gossip subscriptions to %s: %s", peer_id, sorted(self._gossip_local_topics))
        await self._send_gossip_rpc(peer_id, payload)

    async def _send_gossip_rpc(self, peer_id: str, payload: bytes) -> None:
        if self._host is None:
            return
        if peer_id == str(self._host.get_id()):
            return
        try:
            remote = self._ensure_peer_id(peer_id)
            stream = await self._host.new_stream(remote, [TAU_PROTOCOL_GOSSIP])
        except Exception:
            logger.debug("Failed to open gossip stream to %s", peer_id, exc_info=True)
            return

        try:
            await stream.write(payload)
            ack = await self._read_stream(stream, timeout=1.0)
            if ack:
                try:
                    ack_json = json.loads(ack.decode())
                    logger.debug("Gossip RPC ack from %s: %s", peer_id, ack_json)
                except Exception:
                    logger.debug("Gossip RPC non-JSON ack from %s: %r", peer_id, ack[:64], exc_info=True)
        finally:
            with trio.CancelScope(shield=True):
                try:
                    await stream.close()
                except Exception:
                    pass
        self._schedule_opportunistic_seed(str(peer_id))

    def _schedule_opportunistic_seed(
        self,
        peer_id: Optional[str],
        addrs: Optional[Iterable[multiaddr.Multiaddr]] = None,
    ) -> None:
        if not peer_id:
            return

        async def _seed() -> None:
            await self._opportunistic_seed_peer(peer_id, addrs)

        if self._nursery is not None:
            self._nursery.start_soon(_seed)
        else:
            trio.lowlevel.spawn_system_task(_seed)

    def _ingest_peer_entries(
        self,
        entries: Iterable[Dict[str, Any]],
        source: str,
    ) -> List[str]:
        ingested: List[str] = []
        if self._host is None:
            return ingested
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            peer_id = entry.get("peer_id")
            addrs_raw = entry.get("addrs", [])
            if not isinstance(peer_id, str) or not peer_id:
                continue
            addrs: List[multiaddr.Multiaddr] = []
            if isinstance(addrs_raw, list):
                for addr_str in addrs_raw:
                    if not isinstance(addr_str, str):
                        continue
                    try:
                        addrs.append(multiaddr.Multiaddr(addr_str))
                    except Exception:
                        logger.debug("Invalid peer address from %s: %s", source, addr_str, exc_info=True)
            if not addrs:
                continue
            try:
                pid_obj = self._ensure_peer_id(peer_id)
            except ValueError:
                continue
            try:
                self._host.get_peerstore().add_addrs(pid_obj, addrs, PERMANENT_ADDR_TTL)
            except Exception:
                logger.debug("Failed to persist peer %s from %s", peer_id, source, exc_info=True)
            self._schedule_opportunistic_seed(peer_id, addrs)
            ingested.append(peer_id)
        return ingested

    def _ingest_provider_entries(
        self,
        entries: Iterable[Dict[str, Any]],
        source: str,
    ) -> None:
        if self._dht is None:
            return
        provider_store = getattr(self._dht, "provider_store", None)
        if provider_store is None:
            return
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            key = entry.get("key")
            peer_id = entry.get("peer_id")
            addrs_raw = entry.get("addrs", [])
            if not isinstance(key, str) or not isinstance(peer_id, str):
                continue
            try:
                key_bytes = key.encode("utf-8")
            except Exception:
                continue
            try:
                pid_obj = self._ensure_peer_id(peer_id)
            except ValueError:
                continue
            addrs: List[multiaddr.Multiaddr] = []
            if isinstance(addrs_raw, list):
                for addr_str in addrs_raw:
                    if not isinstance(addr_str, str):
                        continue
                    try:
                        addrs.append(multiaddr.Multiaddr(addr_str))
                    except Exception:
                        logger.debug("Invalid provider addr from %s: %s", source, addr_str, exc_info=True)
            peer_info = PeerInfo(pid_obj, addrs)
            try:
                provider_store.add_provider(key_bytes, peer_info)
            except Exception:
                logger.debug("Failed to ingest provider record %s from %s", key, source, exc_info=True)
            self._schedule_opportunistic_seed(peer_id, addrs)

    def _schedule_iterative_lookups(self, peer_ids: Iterable[str]) -> None:
        if self._dht is None:
            return
        targets: List[ID] = []
        for peer_id in peer_ids:
            if not isinstance(peer_id, str) or not peer_id:
                continue
            try:
                targets.append(self._ensure_peer_id(peer_id))
            except ValueError:
                continue
            if len(targets) >= 16:
                break
        if not targets:
            return

        async def _run() -> None:
            for target in targets:
                try:
                    await self._dht.peer_routing.find_peer(target)
                except Exception:
                    logger.debug("Iterative lookup for %s failed", target, exc_info=True)

        if self._nursery is not None:
            self._nursery.start_soon(_run)
        else:
            trio.lowlevel.spawn_system_task(_run)

    async def _attempt_dht_gossip(self, message: Dict[str, Any]) -> bool:
        if self._host is None or self._dht is None:
            return False

        provider_ids = await self._find_gossip_targets_via_dht(message)
        if not provider_ids:
            return False

        payload_bytes = json.dumps(
            {
                "peer_id": str(self._host.get_id()),
                "rpc": {"messages": [message]},
            }
        ).encode()

        sent = False
        sent_peers: List[str] = []
        for peer_id in provider_ids:
            peer_str = str(peer_id)
            if peer_str == str(self._host.get_id()):
                continue
            if not await self._ensure_route_to_peer(peer_str):
                continue
            await self._send_gossip_rpc(peer_str, payload_bytes)
            sent = True
            sent_peers.append(peer_str)

        if sent:
            logger.debug(
                "Gossip message %s delivered via DHT fallback peers %s",
                message.get("message_id"),
                sent_peers,
            )
        else:
            logger.debug("Unable to deliver gossip message %s via DHT fallback", message.get("message_id"))
        return sent

    def _can_reach_peer(self, peer_id: str) -> bool:
        if self._host is None:
            return False
        if peer_id == str(self._host.get_id()):
            return False
        try:
            if peer_id in {str(pid) for pid in self._host.get_connected_peers()}:
                return True
        except Exception:
            pass
        try:
            pid = ID.from_base58(peer_id)
            addrs = self._host.get_peerstore().addrs(pid)
            return bool(addrs)
        except Exception:
            return False

    async def _ensure_route_to_peer(self, peer_id: str) -> bool:
        if self._can_reach_peer(peer_id):
            self._schedule_opportunistic_seed(peer_id)
            return True
        if self._host is None or self._dht is None:
            return False
        try:
            pid = self._ensure_peer_id(peer_id)
        except ValueError:
            return False
        peer_info: Optional[PeerInfo]
        try:
            peer_info = await self._dht.peer_routing.find_peer(pid)
        except Exception:
            logger.debug("DHT find_peer failed for %s", peer_id, exc_info=True)
            return False
        if peer_info is None or not getattr(peer_info, "addrs", None):
            return False
        try:
            self._host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, PERMANENT_ADDR_TTL)
        except Exception:
            logger.debug("Failed to persist DHT-discovered addresses for %s", peer_id, exc_info=True)
        try:
            await self._host.connect(peer_info)
        except Exception:
            logger.debug("Failed to open connection to DHT-discovered peer %s", peer_id, exc_info=True)
        else:
            if getattr(peer_info, "addrs", None):
                self._store_peer_addresses(peer_info.peer_id, peer_info.addrs)
            self._schedule_identify(peer_id)
        if self._can_reach_peer(peer_id):
            self._schedule_opportunistic_seed(peer_id, peer_info.addrs if peer_info else None)
            return True
        return False

    @staticmethod
    def _queue_transaction_sync(payload: str, propagate: bool = False) -> str:
        try:
            return sendtx.queue_transaction(payload, propagate)
        except TypeError:
            # Backwards compatibility with older signature lacking propagate flag
            if propagate:
                raise
            return sendtx.queue_transaction(payload)

    def _should_retry_gossip(self, result: str) -> bool:
        lowered = result.lower()
        retry_tokens = (
            "invalid sequence number",
            "insufficient funds",
            "could not apply transfer",
        )
        return any(token in lowered for token in retry_tokens)

    def _enqueue_pending_transaction(self, message_id: str, payload: str) -> None:
        if not message_id:
            return
        entry = self._pending_tx.get(message_id)
        if entry:
            entry["payload"] = payload
            return
        self._pending_tx[message_id] = {"payload": payload, "attempts": 0}
        if self._nursery is not None:
            self._nursery.start_soon(self._retry_pending_transaction, message_id)

    def _setup_dht_validators(self) -> None:
        if self._dht is None:
            return
        ttl = getattr(self._config, "dht_record_ttl", None)
        if isinstance(ttl, int) and ttl > 0:
            dht_common.DEFAULT_TTL = ttl
            dht_common.TTL = ttl
        self._register_default_dht_validators()

        value_store = getattr(self._dht, "value_store", None)
        if value_store is not None and self._dht_value_store_put is None:
            original_put = value_store.put

            def validating_put(key: bytes, value: bytes, validity: float = 0.0):
                if not self._validate_dht_record(key, value):
                    raise ValueError("DHT record failed validation")
                return original_put(key, value, validity)

            value_store.put = validating_put  # type: ignore[assignment]
            self._dht_value_store_put = original_put

        provider_store = getattr(self._dht, "provider_store", None)
        if provider_store is not None and self._dht_provider_add is None:
            original_add = provider_store.add_provider

            def validating_add(key: bytes, provider_info: Any):
                if not self._validate_dht_key(key):
                    raise ValueError("Invalid DHT provider key")
                return original_add(key, provider_info)

            provider_store.add_provider = validating_add  # type: ignore[assignment]
            self._dht_provider_add = original_add

    async def _seed_dht_bootstrap_peers(self) -> None:
        if self._host is None or self._dht is None:
            return
        combined: Dict[str, BootstrapPeer] = {}
        for entry in getattr(self._config, "bootstrap_peers", []):
            combined[str(entry.peer_id)] = entry
        for entry in getattr(self._config, "dht_bootstrap_peers", []):
            combined[str(entry.peer_id)] = entry

        for entry in combined.values():
            try:
                peer_id = self._ensure_peer_id(entry.peer_id)
            except ValueError:
                logger.debug("Skipping invalid DHT bootstrap peer id: %s", entry.peer_id)
                continue
            addrs = self._normalize_peer_addrs(entry.addrs)
            addrs_for_store = addrs or list(entry.addrs)
            try:
                self._host.get_peerstore().add_addrs(peer_id, addrs_for_store, PERMANENT_ADDR_TTL)
            except Exception:
                logger.debug("Failed to persist DHT bootstrap peer %s to peerstore", peer_id, exc_info=True)
            try:
                await self._dht.routing_table.add_peer(PeerInfo(peer_id, addrs_for_store))
                if logger.isEnabledFor(logging.DEBUG):
                    try:
                        peers_snapshot = [str(pid) for pid in self._dht.routing_table.get_peer_ids()]
                        logger.debug("DHT routing table updated; peers=%s", peers_snapshot)
                    except Exception:
                        logger.debug("Failed to inspect DHT routing table after insert", exc_info=True)
            except Exception:
                logger.debug("Failed to add DHT bootstrap peer %s to routing table", peer_id, exc_info=True)

    def _register_default_dht_validators(self) -> None:
        self._dht_validators.clear()
        available = {
            "block": self._validate_block_record,
            "tx": self._validate_transaction_record,
            "state": self._validate_state_record,
        }
        namespaces = list(getattr(self._config, "dht_validator_namespaces", []) or available.keys())
        self._dht_allowed_namespaces = set(namespaces)
        for name in namespaces:
            validator = available.get(name)
            if validator is not None:
                self._dht_validators[name] = validator
            else:
                logger.warning("No built-in validator for DHT namespace '%s'; records will be accepted without extra checks", name)

    def _extract_dht_namespace(self, key: bytes) -> Optional[str]:
        try:
            key_str = key.decode("ascii")
        except UnicodeDecodeError:
            return None
        if ":" not in key_str:
            return None
        namespace, _ = key_str.split(":", 1)
        return namespace

    def _validate_dht_key(self, key: bytes) -> bool:
        namespace = self._extract_dht_namespace(key)
        if namespace is None:
            return False
        if self._dht_allowed_namespaces and namespace not in self._dht_allowed_namespaces:
            return False
        try:
            suffix = key.decode("ascii").split(":", 1)[1]
        except (UnicodeDecodeError, IndexError):
            return False
        return bool(suffix)

    def _validate_dht_record(self, key: bytes, value: bytes) -> bool:
        if not self._validate_dht_key(key):
            logger.debug("Rejected DHT record with invalid key: %s", key)
            return False
        namespace = self._extract_dht_namespace(key)
        if not namespace:
            return True
        validator = self._dht_validators.get(namespace)
        if validator is None:
            return True
        try:
            return bool(validator(key, value))
        except Exception:
            logger.debug("DHT validator for %s raised", namespace, exc_info=True)
            return False

    def _validate_block_record(self, key: bytes, value: bytes) -> bool:
        key_str = key.decode("ascii")
        _, suffix = key_str.split(":", 1)
        try:
            payload = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.debug("Block DHT record payload not valid JSON")
            return False
        if not isinstance(payload, dict):
            return False
        block_hash = payload.get("block_hash")
        return isinstance(block_hash, str) and block_hash == suffix

    def _validate_transaction_record(self, key: bytes, value: bytes) -> bool:
        key_str = key.decode("ascii")
        _, suffix = key_str.split(":", 1)
        try:
            json_str = value.decode("utf-8")
            payload = json.loads(json_str)
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.debug("Transaction DHT record payload not valid JSON")
            return False
        if not isinstance(payload, dict):
            return False
        try:
            message_id, canonical = sendtx._compute_transaction_message_id(payload)
        except Exception:
            logger.debug("Failed to compute transaction message id", exc_info=True)
            return False
        if message_id != suffix:
            return False
        expected = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return canonical == expected

    def _validate_state_record(self, key: bytes, value: bytes) -> bool:
        key_str = key.decode("ascii")
        _, suffix = key_str.split(":", 1)
        try:
            payload = json.loads(value.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            logger.debug("State DHT record payload not valid JSON")
            return False
        if not isinstance(payload, dict):
            return False
        block_hash = payload.get("block_hash")
        accounts = payload.get("accounts")
        return (
            isinstance(block_hash, str)
            and block_hash == suffix
            and isinstance(accounts, dict)
        )

    def _collect_gossip_provider_keys(
        self,
        message: Dict[str, Any],
        extra_keys: Optional[Iterable[Union[str, bytes]]] = None,
    ) -> List[bytes]:
        keys: List[bytes] = []
        seen: Set[bytes] = set()

        def add_key(raw: Optional[Union[str, bytes]]) -> None:
            if raw is None:
                return
            if isinstance(raw, bytes):
                key_bytes = raw
            elif isinstance(raw, str):
                try:
                    key_bytes = raw.encode("utf-8")
                except Exception:
                    return
            else:
                try:
                    key_bytes = str(raw).encode("utf-8")
                except Exception:
                    return
            if key_bytes in seen:
                return
            seen.add(key_bytes)
            keys.append(key_bytes)

        if extra_keys:
            for key in extra_keys:
                add_key(key)

        topic = message.get("topic")
        if topic == TAU_GOSSIP_TOPIC_TRANSACTIONS:
            payload = message.get("data")
            tx_payload: Optional[Dict[str, Any]]
            if isinstance(payload, str):
                try:
                    tx_payload = json.loads(payload)
                except json.JSONDecodeError:
                    tx_payload = None
            else:
                tx_payload = None
            if isinstance(tx_payload, dict):
                try:
                    message_id, _ = sendtx._compute_transaction_message_id(tx_payload)
                except Exception:
                    message_id = None
                if message_id:
                    add_key(f"tx:{message_id}".encode("utf-8"))
        elif topic == TAU_GOSSIP_TOPIC_BLOCKS:
            data = message.get("data")
            block_hash: Optional[str] = None
            if isinstance(data, dict):
                headers = data.get("headers") or []
                if headers:
                    header0 = headers[0]
                    block_hash = header0.get("block_hash")
                else:
                    block_hash = data.get("tip_hash")
            if isinstance(block_hash, str):
                add_key(f"block:{block_hash}")
        return keys

    async def _find_gossip_targets_via_dht(
        self,
        message: Dict[str, Any],
        *,
        extra_keys: Optional[Iterable[Union[str, bytes]]] = None,
        include_closest: bool = True,
    ) -> List[ID]:
        if self._dht is None:
            return []
        keys = self._collect_gossip_provider_keys(message, extra_keys)
        provider_ids: List[ID] = []
        seen: Set[ID] = set()

        for key in keys:
            try:
                providers = await self._dht.find_providers(key, count=20)
            except Exception:
                logger.debug("DHT find_providers failed for key %s", key.decode("utf-8", "ignore"), exc_info=True)
                continue
            for provider in providers:
                peer_id = provider.peer_id
                if peer_id not in seen:
                    provider_ids.append(peer_id)
                    seen.add(peer_id)

        if provider_ids or not include_closest:
            return provider_ids

        fallback_key: Optional[bytes] = keys[0] if keys else None
        if fallback_key is None:
            msg_id = message.get("message_id")
            if isinstance(msg_id, str):
                fallback_key = msg_id.encode("utf-8", "ignore")
        if fallback_key is None:
            fallback_key = uuid.uuid4().hex.encode("utf-8")

        try:
            closest_peers = await self._dht.peer_routing.find_closest_peers_network(fallback_key)
        except Exception:
            logger.debug("DHT find_closest_peers_network failed", exc_info=True)
            return provider_ids

        for peer_id in closest_peers:
            if peer_id not in seen:
                provider_ids.append(peer_id)
                seen.add(peer_id)
        return provider_ids

    async def _refresh_dht_routing_table_once(self) -> None:
        if self._dht is None:
            return
        await self._dht.refresh_routing_table()
        self._metric_timestamps["dht_last_refresh"] = time.time()

    async def _refresh_dht_buckets_once(self) -> Dict[str, int]:
        results: Dict[str, int] = {
            "checked": 0,
            "refreshed": 0,
            "removed": 0,
            "errors": 0,
        }
        if self._dht is None:
            return results

        routing_table = getattr(self._dht, "routing_table", None)
        peer_routing = getattr(self._dht, "peer_routing", None)
        if routing_table is None or peer_routing is None:
            return results

        try:
            stale_peers = list(
                routing_table.get_stale_peers(int(self._dht_stale_peer_threshold))
            )
        except Exception:
            logger.debug(
                "Failed to gather stale peers for DHT bucket refresh", exc_info=True
            )
            results["errors"] += 1
            return results

        if not stale_peers:
            self._metric_timestamps["dht_last_bucket_refresh"] = time.time()
            return results

        limit = min(self._dht_bucket_refresh_limit, len(stale_peers))
        selected = stale_peers[:limit]
        results["checked"] = len(selected)

        for peer_id in selected:
            peer_info = None
            try:
                peer_info = await peer_routing.find_peer(peer_id)
            except Exception:
                results["errors"] += 1
                logger.debug("Failed to refresh peer %s via find_peer", peer_id, exc_info=True)

            if peer_info and getattr(peer_info, "addrs", None):
                try:
                    await routing_table.add_peer(peer_info)
                    results["refreshed"] += 1
                    continue
                except Exception:
                    results["errors"] += 1
                    logger.debug("Failed to reinsert peer %s into routing table", peer_id, exc_info=True)

            try:
                if routing_table.remove_peer(peer_id):
                    results["removed"] += 1
            except Exception:
                results["errors"] += 1
                logger.debug("Failed to evict stale peer %s", peer_id, exc_info=True)

        self._metric_timestamps["dht_last_bucket_refresh"] = time.time()
        return results

    async def _dht_refresh_loop(self) -> None:
        try:
            last_bucket_refresh = 0.0
            while True:
                if self._dht is None:
                    return
                try:
                    await self._refresh_dht_routing_table_once()
                    self._metrics["dht_refresh_success"] += 1
                except Exception:
                    self._metrics["dht_refresh_failure"] += 1
                    logger.debug("DHT routing table refresh failed", exc_info=True)
                now = time.time()
                if now - last_bucket_refresh >= self._dht_bucket_refresh_interval:
                    try:
                        bucket_results = await self._refresh_dht_buckets_once()
                    except Exception:
                        self._metrics["dht_bucket_errors"] += 1
                        logger.debug("DHT bucket refresh failed", exc_info=True)
                    else:
                        self._metrics["dht_bucket_checks"] += bucket_results.get("checked", 0)
                        self._metrics["dht_bucket_replacements"] += bucket_results.get("removed", 0)
                        self._metrics["dht_bucket_errors"] += bucket_results.get("errors", 0)
                    last_bucket_refresh = now
                await trio.sleep(max(0.01, self._dht_refresh_interval))
        except trio.Cancelled:
            return

    async def _metrics_log_loop(self) -> None:
        try:
            while True:
                snapshot = self.get_metrics_snapshot()
                logger.info("[metrics] gossip=%s dht=%s", snapshot.get("gossip"), snapshot.get("dht"))
                await trio.sleep(60.0)
        except trio.Cancelled:
            return

    def get_metrics_snapshot(self) -> Dict[str, Any]:
        now = time.time()
        last_publish = self._metric_timestamps.get("gossip_last_publish") or 0.0
        last_receive = self._metric_timestamps.get("gossip_last_receive") or 0.0
        last_activity = max(last_publish, last_receive)

        if last_activity == 0:
            health_status = {"status": "idle", "stale_for": None}
        else:
            stale_for = max(0.0, now - last_activity)
            status = "healthy" if stale_for <= self._gossip_health_window else "stale"
            health_status = {"status": status, "stale_for": stale_for}

        gossip_snapshot: Dict[str, Any] = {
            "published_total": self._metrics["gossip_published"],
            "received_total": self._metrics["gossip_received"],
            "local_topics": sorted(self._gossip_local_topics),
            "peer_topics": {
                peer_id: sorted(list(topics))
                for peer_id, topics in self._gossip_peer_topics.items()
            },
            "last_published": last_publish or None,
            "last_received": last_receive or None,
            "health": health_status,
        }

        dht_snapshot: Dict[str, Any] = {
            "refresh_success": self._metrics["dht_refresh_success"],
            "refresh_failure": self._metrics["dht_refresh_failure"],
            "bucket_checks": self._metrics["dht_bucket_checks"],
            "bucket_replacements": self._metrics["dht_bucket_replacements"],
            "bucket_errors": self._metrics["dht_bucket_errors"],
            "last_refresh": self._metric_timestamps.get("dht_last_refresh") or None,
            "last_bucket_refresh": self._metric_timestamps.get("dht_last_bucket_refresh") or None,
        }

        dht = self._dht
        if dht is not None:
            routing_table = getattr(dht, "routing_table", None)
            if routing_table is not None:
                try:
                    dht_snapshot["routing_table_size"] = routing_table.size()
                except Exception:
                    logger.debug("Failed to read DHT routing table size", exc_info=True)
                try:
                    buckets = getattr(routing_table, "buckets", [])
                    dht_snapshot["bucket_count"] = len(buckets)
                except Exception:
                    logger.debug("Failed to inspect DHT bucket count", exc_info=True)
                try:
                    dht_snapshot["stale_peers"] = len(
                        routing_table.get_stale_peers(int(self._dht_stale_peer_threshold))
                    )
                except Exception:
                    logger.debug("Failed to compute DHT stale peers", exc_info=True)
            value_store = getattr(dht, "value_store", None)
            if value_store is not None:
                try:
                    value_store_records = getattr(value_store, "store", {})
                    dht_snapshot["value_records"] = len(value_store_records)
                except Exception:
                    logger.debug("Failed to gather DHT value store metrics", exc_info=True)
            provider_store = getattr(dht, "provider_store", None)
            if provider_store is not None:
                try:
                    providers = getattr(provider_store, "providers", {})
                    dht_snapshot["provider_records"] = sum(len(v) for v in providers.values())
                except Exception:
                    logger.debug("Failed to gather DHT provider metrics", exc_info=True)

        return {"gossip": gossip_snapshot, "dht": dht_snapshot}

    async def _retry_pending_transaction(self, message_id: str) -> None:
        backoff = (1.0, 2.0, 4.0, 8.0, 16.0)
        for delay in backoff:
            await trio.sleep(delay)
            entry = self._pending_tx.get(message_id)
            if not entry:
                return
            payload = entry["payload"]
            entry["attempts"] += 1
            try:
                result = await trio.to_thread.run_sync(self._queue_transaction_sync, payload, False)
            except Exception:
                logger.debug("Pending gossip transaction %s raised during retry", message_id, exc_info=True)
                continue
            result_str = str(result) if result is not None else ""
            if result_str.startswith("SUCCESS"):
                self._pending_tx.pop(message_id, None)
                return
            if not self._should_retry_gossip(result_str):
                break
        self._pending_tx.pop(message_id, None)
        logger.debug("Dropping pending gossip transaction %s after retries", message_id)

    async def _on_peer_connected(self, conn: Any) -> None:
        if self._host is None:
            return
        peer_id_obj = None
        peer_id = None
        try:
            muxed_conn = getattr(conn, "muxed_conn", None)
            peer_id_obj = getattr(muxed_conn, "peer_id", None)
            peer_id = str(peer_id_obj) if peer_id_obj is not None else None
        except Exception:
            peer_id = None
        if not peer_id or peer_id == str(self._host.get_id()):
            return
        logger.info("Peer connected: %s", peer_id)

        # Extract remote address from connection
        remote_addrs = []
        try:
            # Try to get remote address from connection
            if hasattr(conn, "remote_addr"):
                remote_addr = getattr(conn, "remote_addr")
                if remote_addr:
                    remote_addrs.append(remote_addr)
            elif hasattr(conn, "remote_addrs"):
                remote_addrs.extend(getattr(conn, "remote_addrs", []))
        except Exception:
            logger.debug("Failed to extract remote address from connection", exc_info=True)

        stored_addrs: List[multiaddr.Multiaddr] = []
        if peer_id_obj is not None:
            inline_candidates: List[multiaddr.Multiaddr] = []
            for entry in remote_addrs:
                if isinstance(entry, multiaddr.Multiaddr):
                    inline_candidates.append(entry)
                elif isinstance(entry, str):
                    try:
                        inline_candidates.append(multiaddr.Multiaddr(entry))
                    except Exception:
                        logger.debug("Invalid remote address string from connection: %s", entry, exc_info=True)
                else:
                    try:
                        inline_candidates.append(multiaddr.Multiaddr(str(entry)))
                    except Exception:
                        logger.debug("Unsupported remote address type from connection: %r", entry, exc_info=True)

            if inline_candidates:
                stored_addrs = self._store_peer_addresses(peer_id_obj, inline_candidates)
                if stored_addrs:
                    self._schedule_identify(peer_id)

            if not stored_addrs:
                stored_addrs = await self._identify_peer(peer_id_obj)

        self._insert_peer_into_dht(peer_id, stored_addrs if stored_addrs else None)
        self._schedule_mempool_sync(peer_id)

    async def _try_block_sync(self, peer_id: str, locator: List[str]) -> bool:
        worked = False
        try:
            await self._send_local_subscriptions_to_peer(peer_id)
            worked = True
        except Exception:
            logger.debug("Failed to push subscriptions to %s", peer_id, exc_info=True)
        try:
            added = await self._sync_and_ingest_from_peer(peer_id, locator)
            return worked or added > 0
        except Exception:
            logger.debug("Failed to sync blocks from %s", peer_id, exc_info=True)
            return worked

    async def _on_peer_disconnected(self, conn: Any) -> None:
        try:
            muxed_conn = getattr(conn, "muxed_conn", None)
            peer_id_obj = getattr(muxed_conn, "peer_id", None)
            peer_id = str(peer_id_obj) if peer_id_obj is not None else None
        except Exception:
            peer_id = None
        if not peer_id:
            return
        self._mempool_synced_peers.discard(peer_id)

    def _schedule_mempool_sync(self, peer_id: str) -> None:
        if not peer_id or self._nursery is None or self._host is None:
            return
        if peer_id in self._mempool_synced_peers:
            return

        async def _sync_task() -> None:
            try:
                await self._sync_mempool_with_peer(peer_id)
            except Exception:
                logger.debug("Failed to sync mempool with %s", peer_id, exc_info=True)
                self._mempool_synced_peers.discard(peer_id)

        self._mempool_synced_peers.add(peer_id)
        self._nursery.start_soon(_sync_task)

    async def _sync_mempool_with_peer(self, peer_id: str) -> None:
        if self._host is None:
            return
        try:
            tx_entries = db.get_mempool_txs()
        except Exception:
            logger.debug("Mempool sync: failed to load transactions", exc_info=True)
            return
        if not tx_entries:
            return

        self_id = str(self._host.get_id())
        for entry in tx_entries:
            raw = entry[5:] if entry.startswith("json:") else entry
            payload_str = raw.strip()
            if not payload_str:
                continue
            try:
                payload_dict = json.loads(payload_str)
                message_id, canonical = sendtx._compute_transaction_message_id(payload_dict)
            except Exception:
                logger.debug("Mempool sync: failed to prepare transaction for %s", peer_id, exc_info=True)
                continue
            envelope = {
                "peer_id": self_id,
                "rpc": {
                    "messages": [
                        {
                            "from": self_id,
                            "topic": TAU_GOSSIP_TOPIC_TRANSACTIONS,
                            "data": canonical,
                            "message_id": message_id,
                            "timestamp": trio.current_time(),
                        }
                    ]
                },
            }
            await self._send_gossip_rpc(peer_id, json.dumps(envelope).encode())
            await trio.sleep(0)

    def _insert_peer_into_dht(self, peer_id_str: str, addrs: Optional[List[multiaddr.Multiaddr]] = None) -> None:
        if self._dht is None:
            logger.warning("DHT not initialized, cannot insert peer %s", peer_id_str)
            return
        try:
            peer_id = self._ensure_peer_id(peer_id_str)
        except ValueError:
            logger.warning("Invalid peer ID %s", peer_id_str)
            return
        if addrs is None:
            try:
                addrs = self._host.get_peerstore().addrs(peer_id)
            except Exception:
                addrs = []
        logger.info("Inserting peer %s into DHT with addrs %s", peer_id_str, addrs)
        if not addrs:
            logger.warning("No addresses for peer %s, skipping DHT insertion", peer_id_str)
            return
        async def _add() -> None:
            try:
                await self._dht.routing_table.add_peer(PeerInfo(peer_id, addrs))
                if logger.isEnabledFor(logging.DEBUG):
                    peers_snapshot = [str(pid) for pid in self._dht.routing_table.get_peer_ids()]
                    logger.debug("DHT routing table updated; peers=%s", peers_snapshot)
            except Exception:
                logger.warning("Failed to insert peer %s into DHT routing table", peer_id, exc_info=True)
        if self._nursery is not None:
            self._nursery.start_soon(_add)
        else:
            trio.lowlevel.spawn_system_task(_add)

    def _store_peer_addresses(
        self,
        peer_id: ID,
        addresses: Iterable[multiaddr.Multiaddr],
    ) -> List[multiaddr.Multiaddr]:
        if self._host is None:
            return []
        normalized = self._normalize_peer_addrs(addresses)
        if not normalized:
            return []
        try:
            self._host.get_peerstore().add_addrs(peer_id, normalized, PERMANENT_ADDR_TTL)
        except Exception:
            logger.debug("Failed to persist addresses for %s", peer_id, exc_info=True)
        self._save_peer_basic(PeerInfo(peer_id, normalized))
        peer_id_str = str(peer_id)
        self._opportunistic_peers[peer_id_str] = time.time()
        self._schedule_opportunistic_seed(peer_id_str, normalized)
        return normalized

    async def _identify_peer(self, peer_id: ID) -> List[multiaddr.Multiaddr]:
        if self._host is None:
            return []
        try:
            stream = await self._host.new_stream(peer_id, [IDENTIFY_PROTOCOL_ID])
        except Exception:
            logger.debug("Identify: failed to open stream to %s", peer_id, exc_info=True)
            return []

        try:
            payload = await self._read_stream(stream, timeout=2.0, max_bytes=262144)
        finally:
            with trio.CancelScope(shield=True):
                try:
                    await stream.close()
                except Exception:
                    pass

        if not payload:
            return []

        identify_msg = IdentifyMessage()
        try:
            identify_msg.ParseFromString(payload)
        except DecodeError:
            logger.debug("Identify: failed to parse response from %s", peer_id, exc_info=True)
            return []

        discovered: List[multiaddr.Multiaddr] = []
        for raw_addr in identify_msg.listen_addrs:
            try:
                discovered.append(multiaddr.Multiaddr(raw_addr))
            except Exception:
                logger.debug("Identify: invalid listen address from %s", peer_id, exc_info=True)
        if identify_msg.observed_addr:
            try:
                discovered.append(multiaddr.Multiaddr(identify_msg.observed_addr))
            except Exception:
                logger.debug("Identify: invalid observed address from %s", peer_id, exc_info=True)

        if not discovered:
            return []

        addresses = self._store_peer_addresses(peer_id, discovered)
        if addresses and logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Identify: learned addresses for %s: %s",
                peer_id,
                [str(addr) for addr in addresses],
            )
        return addresses

    def _schedule_identify(self, peer_id: str) -> None:
        if self._host is None or self._nursery is None:
            return
        if not isinstance(peer_id, str) or not peer_id:
            return
        if peer_id in self._identifying_peers:
            return
        try:
            peer_id_obj = self._ensure_peer_id(peer_id)
        except ValueError:
            return

        async def _task() -> None:
            try:
                addrs = await self._identify_peer(peer_id_obj)
                if addrs:
                    self._insert_peer_into_dht(peer_id, addrs)
            finally:
                self._identifying_peers.discard(peer_id)

        self._identifying_peers.add(peer_id)
        self._nursery.start_soon(_task)

    async def _opportunistic_seed_peer(
        self,
        peer_id_str: str,
        addrs: Optional[Iterable[multiaddr.Multiaddr]] = None,
    ) -> None:
        if self._host is None:
            return
        if not peer_id_str or peer_id_str == str(self._host.get_id()):
            return
        now = time.time()
        seen_at = self._opportunistic_peers.get(peer_id_str)
        if seen_at is not None and now - seen_at < self._opportunistic_peer_cooldown:
            return
        self._opportunistic_peers[peer_id_str] = now

        try:
            peer_id = self._ensure_peer_id(peer_id_str)
        except ValueError:
            return

        addr_list: List[multiaddr.Multiaddr] = []
        if addrs:
            try:
                addr_list.extend(self._normalize_peer_addrs(addrs))
            except Exception:
                logger.debug("Failed to normalize opportunistic addresses for %s", peer_id_str, exc_info=True)
        if not addr_list:
            try:
                addr_list = list(self._host.get_peerstore().addrs(peer_id) or [])
            except Exception:
                addr_list = []

        if not addr_list and self._dht is not None:
            try:
                peer_info = await self._dht.peer_routing.find_peer(peer_id)
            except Exception:
                logger.debug("DHT find_peer failed during opportunistic seed for %s", peer_id_str, exc_info=True)
                peer_info = None
            if peer_info and getattr(peer_info, "addrs", None):
                addr_list = self._normalize_peer_addrs(peer_info.addrs)

        if not addr_list:
            return

        try:
            self._host.get_peerstore().add_addrs(peer_id, addr_list, PERMANENT_ADDR_TTL)
        except Exception:
            logger.debug("Failed to persist opportunistic peer %s into peerstore", peer_id_str, exc_info=True)

        peer_info = PeerInfo(peer_id, addr_list)
        self._save_peer_basic(peer_info)
        self._insert_peer_into_dht(peer_id_str, addr_list)

    async def _deliver_gossip(self, message: Dict[str, Any], via_peer: Optional[str]) -> None:
        topic = message.get("topic")
        if not isinstance(topic, str) or not topic:
            return

        envelope = {
            "topic": topic,
            "payload": message.get("data"),
            "origin": message.get("from"),
            "message_id": message.get("message_id"),
            "timestamp": message.get("timestamp"),
            "via": via_peer,
        }

        origin = envelope.get("origin")
        if isinstance(origin, str):
            self._schedule_opportunistic_seed(origin)
        if isinstance(via_peer, str):
            self._schedule_opportunistic_seed(via_peer)

        handlers: List[Callable[[Dict[str, Any]], Any]] = []
        handlers.extend(self._gossip_handlers.get(topic, []))
        handlers.extend(self._gossip_handlers.get("*", []))

        for handler in handlers:
            try:
                result = handler(envelope)
                if inspect.isawaitable(result):
                    await result  # type: ignore[func-returns-value]
            except Exception:
                logger.debug("Gossip handler %s failed", handler, exc_info=True)
        if self._host and envelope.get("origin") != str(self._host.get_id()):
            self._metrics["gossip_received"] += 1
            self._metric_timestamps["gossip_last_receive"] = time.time()

    async def _handle_transaction_gossip(self, envelope: Dict[str, Any]) -> None:
        if self._host and envelope.get("origin") == str(self._host.get_id()):
            return
        message_id = envelope.get("message_id")
        message_id_str = str(message_id) if isinstance(message_id, (str, int)) else ""
        payload = envelope.get("payload")
        if not isinstance(payload, str):
            logger.debug("Ignoring TX gossip with non-string payload")
            return
        try:
            result = await trio.to_thread.run_sync(self._queue_transaction_sync, payload, False)
        except Exception:
            logger.debug("Failed to ingest transaction from gossip", exc_info=True)
            return

        result_str = str(result) if result is not None else ""
        if result_str.startswith("SUCCESS"):
            if message_id_str:
                self._pending_tx.pop(message_id_str, None)
            return

        logger.debug("Gossip transaction rejected: %s", result_str)
        if message_id_str and self._should_retry_gossip(result_str):
            self._enqueue_pending_transaction(message_id_str, payload)

    async def _handle_block_gossip(self, envelope: Dict[str, Any]) -> None:
        if self._host and envelope.get("origin") == str(self._host.get_id()):
            return
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return
        origin = envelope.get("origin")
        via = envelope.get("via")
        candidates: List[str] = []
        if isinstance(origin, str) and origin:
            candidates.append(origin)
        if isinstance(via, str) and via and via not in candidates:
            candidates.append(via)
        if not candidates:
            return

        locator: List[str] = []
        try:
            tip_hash = self._get_tip_hash()
            if tip_hash:
                locator = [tip_hash]
        except Exception:
            locator = []

        for peer_id in candidates:
            if not self._can_reach_peer(peer_id):
                continue
            success = await self._try_block_sync(peer_id, locator)
            if success:
                return
        logger.debug("Block gossip: no reachable peers for candidates %s", candidates)

    async def _handle_peer_advertisement(self, envelope: Dict[str, Any]) -> None:
        if self._host and envelope.get("origin") == str(self._host.get_id()):
            return
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            return
        peer_entries = payload.get("peers")
        ingested: List[str] = []
        if isinstance(peer_entries, list):
            ingested = self._ingest_peer_entries(peer_entries, "peer-advertisement")
        provider_entries = payload.get("providers")
        if isinstance(provider_entries, list):
            self._ingest_provider_entries(provider_entries, "peer-advertisement")
        if ingested:
            self._schedule_iterative_lookups(ingested)

    # ---------------------------------------------------------------- Database helpers
    def _get_tip(self) -> Optional[Dict[str, Any]]:
        try:
            return db.get_latest_block()
        except Exception:
            return None

    def _get_tip_number(self) -> int:
        tip = self._get_tip()
        try:
            return int(tip["header"]["block_number"]) if tip else 0
        except Exception:
            return 0

    def _get_tip_hash(self) -> str:
        tip = self._get_tip()
        try:
            return str(tip["block_hash"]) if tip else self._config.genesis_hash
        except Exception:
            return self._config.genesis_hash

    def _collect_peer_snapshot(self, limit: int, *, recent_only: bool = False) -> List[Dict[str, Any]]:
        if limit <= 0 or self._host is None:
            return []

        candidates: List[str] = []
        seen: Set[str] = set()
        if recent_only:
            cutoff = time.time() - self._peer_advertisement_recent_window
            for peer_id, seen_at in self._opportunistic_peers.items():
                if peer_id and seen_at >= cutoff:
                    candidates.append(peer_id)
        else:
            if self._dht is not None:
                try:
                    candidates.extend(str(pid) for pid in self._dht.routing_table.get_peer_ids())
                except Exception:
                    logger.debug("Failed to read DHT routing table for snapshot", exc_info=True)
        # Always include opportunistic peers as fallback
        if not recent_only:
            for peer_id in self._opportunistic_peers.keys():
                candidates.append(peer_id)

        snapshot: List[Dict[str, Any]] = []
        for peer_id in candidates:
            if not isinstance(peer_id, str) or not peer_id:
                continue
            if peer_id in seen or (self._host and peer_id == str(self._host.get_id())):
                continue
            try:
                pid = self._ensure_peer_id(peer_id)
            except ValueError:
                continue
            try:
                addrs = self._host.get_peerstore().addrs(pid)
            except Exception:
                addrs = []
            if not addrs:
                continue
            try:
                addr_strings = [str(addr) for addr in addrs]
            except Exception:
                continue
            snapshot.append({"peer_id": peer_id, "addrs": addr_strings})
            seen.add(peer_id)
            if len(snapshot) >= limit:
                break
        return snapshot

    def _collect_provider_snapshot(self, limit: int) -> List[Dict[str, Any]]:
        if limit <= 0 or self._dht is None:
            return []
        provider_store = getattr(self._dht, "provider_store", None)
        if provider_store is None:
            return []
        entries: List[Dict[str, Any]] = []
        try:
            providers_map = getattr(provider_store, "providers", {})
            items = list(providers_map.items())
        except Exception:
            logger.debug("Failed to gather provider snapshot", exc_info=True)
            return []

        for key_bytes, provider_dict in items:
            try:
                key_str = key_bytes.decode("utf-8")
            except Exception:
                continue
            for record in provider_dict.values():
                info = getattr(record, "provider_info", None)
                if info is None:
                    continue
                try:
                    addr_strings = [str(addr) for addr in info.addrs]
                except Exception:
                    addr_strings = []
                entries.append(
                    {
                        "key": key_str,
                        "peer_id": str(info.peer_id),
                        "addrs": addr_strings,
                    }
                )
                if len(entries) >= limit:
                    return entries
        return entries[:limit]

    def _build_handshake_payload(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "network_id": self._config.network_id,
            "node_id": str(self._host.get_id()) if self._host else "",
            "agent": self._config.agent,
            "genesis_hash": self._config.genesis_hash,
            "head_number": self._get_tip_number(),
            "head_hash": self._get_tip_hash(),
            "time": trio.current_time(),
        }
        if self._handshake_peer_limit:
            payload["dht_peers"] = self._collect_peer_snapshot(self._handshake_peer_limit)
        if self._handshake_provider_limit:
            payload["dht_providers"] = self._collect_provider_snapshot(self._handshake_provider_limit)
        return payload

    def _build_handshake(self) -> bytes:
        return json.dumps(self._build_handshake_payload()).encode()

    def _ingest_handshake_snapshot(self, payload: Dict[str, Any], source: str) -> None:
        if not isinstance(payload, dict):
            return
        peer_entries = payload.get("dht_peers")
        ingested: List[str] = []
        if isinstance(peer_entries, list):
            ingested = self._ingest_peer_entries(peer_entries, source)
        provider_entries = payload.get("dht_providers")
        if isinstance(provider_entries, list):
            self._ingest_provider_entries(provider_entries, source)
        if ingested:
            self._schedule_iterative_lookups(ingested)

    # ---------------------------------------------------------------- Stream handlers
    async def _handle_handshake(self, stream) -> None:
        peer_id_str: Optional[str] = None
        muxed_conn = getattr(stream, "muxed_conn", None)
        peer_obj = getattr(muxed_conn, "peer_id", None) if muxed_conn is not None else None
        if peer_obj is not None:
            try:
                peer_id_str = str(peer_obj)
            except Exception:
                peer_id_str = None

        raw_req = await self._read_stream(stream, timeout=1.0)
        if raw_req:
            try:
                request_payload = json.loads(raw_req.decode())
            except Exception:
                request_payload = None
            if isinstance(request_payload, dict):
                self._ingest_handshake_snapshot(request_payload, "handshake-request")

        resp = self._build_handshake()
        try:
            await stream.write(resp)
        finally:
            with trio.CancelScope(shield=True):
                try:
                    await stream.close()
                except Exception:
                    pass
        try:
            response_payload = json.loads(resp.decode())
        except Exception:
            response_payload = None
        if isinstance(response_payload, dict):
            self._ingest_handshake_snapshot(response_payload, "handshake-response")
        if peer_id_str:
            self._schedule_opportunistic_seed(peer_id_str)

    async def _handle_ping(self, stream) -> None:
        raw = await self._read_stream(stream, timeout=1.0)
        try:
            data = json.loads(raw.decode()) if raw else {}
            pong = {"nonce": data.get("nonce"), "time": trio.current_time()}
        except Exception:
            pong = {"nonce": None, "time": trio.current_time()}
        await stream.write(json.dumps(pong).encode())
        await stream.close()

    async def _handle_sync(self, stream) -> None:
        raw = await self._read_stream(stream, timeout=1.0)

        request: Dict[str, Any] = {}
        try:
            if raw:
                maybe = json.loads(raw.decode())
                if isinstance(maybe, dict):
                    request = maybe
        except Exception:
            request = {}

        locator = request.get("locator") or []
        stop_hash = request.get("stop")
        limit = request.get("limit", 2000)

        headers = self._load_headers_from_db(
            locator if isinstance(locator, list) else [],
            stop_hash if isinstance(stop_hash, str) else None,
            int(limit) if isinstance(limit, int) else 2000,
        )
        tip = self._get_tip()
        response = {
            "headers": headers,
            "tip_number": self._get_tip_number(),
            "tip_hash": tip["block_hash"] if tip else self._config.genesis_hash,
        }
        await stream.write(json.dumps(response).encode())
        await stream.close()

    def _load_headers_from_db(
        self,
        locator: List[str],
        stop: Optional[str],
        limit: int,
    ) -> List[Dict[str, Any]]:
        limit = max(1, min(int(limit), 2000))
        try:
            with db._db_lock:
                cur = db._db_conn.cursor() if db._db_conn else None
            if cur is None:
                db.init_db()
                with db._db_lock:
                    cur = db._db_conn.cursor()
            cur.execute("SELECT block_data FROM blocks ORDER BY block_number ASC")
            chain: List[Dict[str, Any]] = [json.loads(row[0]) for row in cur.fetchall()]
        except Exception:
            return []

        if not chain:
            return []

        start_index = 0
        locator_set = {h for h in locator if isinstance(h, str)}
        if locator_set:
            for idx, entry in enumerate(chain):
                try:
                    if entry.get("block_hash") in locator_set:
                        start_index = idx + 1
                        break
                except Exception:
                    continue

        headers: List[Dict[str, Any]] = []
        for block in chain[start_index:]:
            header = block.get("header", {})
            hdr = {
                "block_number": header.get("block_number"),
                "previous_hash": header.get("previous_hash"),
                "timestamp": header.get("timestamp"),
                "merkle_root": header.get("merkle_root"),
                "block_hash": block.get("block_hash"),
            }
            headers.append(hdr)
            if len(headers) >= limit:
                break
            if stop and block.get("block_hash") == stop:
                break
        return headers

    async def _handle_blocks(self, stream) -> None:
        raw = await self._read_stream(stream, timeout=1.0)
        request: Dict[str, Any] = {}
        try:
            if raw:
                maybe = json.loads(raw.decode())
                if isinstance(maybe, dict):
                    request = maybe
        except Exception:
            request = {}

        response = {"blocks": []}
        hashes = request.get("hashes")
        if isinstance(hashes, list):
            blocks = []
            for h in hashes:
                if not isinstance(h, str):
                    continue
                try:
                    block = db.get_block_by_hash(h)
                    if block:
                        blocks.append(block)
                except Exception:
                    continue
            response["blocks"] = blocks
        await stream.write(json.dumps(response).encode())
        await stream.close()

    async def _handle_gossip(self, stream) -> None:
        raw = await self._read_stream(stream, timeout=1.5)

        try:
            packet = json.loads(raw.decode()) if raw else {}
        except Exception:
            packet = {}

        if not isinstance(packet, dict):
            await stream.write(json.dumps({"ok": False, "error": "invalid gossipsub frame"}).encode())
            await stream.close()
            return

        rpc = packet.get("rpc")
        if not isinstance(rpc, dict):
            await stream.write(json.dumps({"ok": False, "error": "missing gossipsub rpc"}).encode())
            await stream.close()
            return

        peer_id = packet.get("peer_id")
        peer_id_str = str(peer_id) if isinstance(peer_id, (str, ID)) else None

        if peer_id_str:
            self._schedule_opportunistic_seed(peer_id_str)

        subs_updated = 0
        subs = rpc.get("subscriptions")
        if isinstance(subs, list) and peer_id_str:
            topics = self._gossip_peer_topics.setdefault(peer_id_str, set())
            for entry in subs:
                if not isinstance(entry, dict):
                    continue
                topic = entry.get("topic")
                if not isinstance(topic, str) or not topic:
                    continue
                subscribe = bool(entry.get("subscribe", True))
                if subscribe:
                    if topic not in topics:
                        topics.add(topic)
                        subs_updated += 1
                else:
                    if topic in topics:
                        topics.discard(topic)
                        subs_updated += 1

        duplicates: List[Dict[str, Any]] = []
        messages = rpc.get("messages")
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                topic = msg.get("topic")
                message_id = msg.get("message_id")
                if not isinstance(topic, str) or not isinstance(message_id, str):
                    continue
                duplicate = message_id in self._gossip_seen
                if not duplicate:
                    now = trio.current_time()
                    self._gossip_seen[message_id] = now
                    msg.setdefault("timestamp", now)
                    origin = msg.get("from")
                    if not isinstance(origin, str) and peer_id_str:
                        msg["from"] = peer_id_str
                    exclude = {peer_id_str} if peer_id_str else None
                    await self._deliver_gossip(msg, via_peer=peer_id_str)
                    await self._rebroadcast_gossip_message(msg, exclude=exclude)
                duplicates.append(
                    {
                        "message_id": message_id,
                        "duplicate": duplicate,
                        "topic": topic,
                    }
                )

        response = {
            "ok": True,
            "subscriptions_updated": subs_updated,
            "messages": duplicates,
        }
        await stream.write(json.dumps(response).encode())
        await stream.close()

    async def _handle_tx(self, stream) -> None:
        raw = await self._read_stream(stream, timeout=1.0)

        decoded = raw.decode(errors="ignore") if raw else ""
        payload: Optional[str] = None
        try:
            req = json.loads(decoded) if decoded else {}
        except Exception:
            req = decoded

        if isinstance(req, dict):
            if "tx" in req:
                val = req["tx"]
                payload = val if isinstance(val, str) else json.dumps(val)
            elif "transaction" in req:
                val = req["transaction"]
                payload = val if isinstance(val, str) else json.dumps(val)
            elif "payload" in req:
                val = req["payload"]
                payload = val if isinstance(val, str) else json.dumps(val)
        elif isinstance(req, str):
            payload = req
        elif decoded:
            payload = decoded

        if not payload:
            response = {"ok": False, "error": "missing transaction payload"}
        else:
            try:
                result = self._submit_tx(payload)
                response = {"ok": True, "result": result}
            except Exception as exc:
                response = {"ok": False, "error": str(exc)}

        await stream.write(json.dumps(response).encode())
        await stream.close()

    async def _handle_state(self, stream) -> None:
        raw = await self._read_stream(stream, timeout=1.0)
        request: Dict[str, Any] = {}
        try:
            if raw:
                maybe = json.loads(raw.decode())
                if isinstance(maybe, dict):
                    request = maybe
        except Exception:
            request = {}

        try:
            data = self._state_provider(request)
            if not isinstance(data, dict):
                data = {"data": data}
            response = {"ok": True, **data}
        except Exception as exc:
            response = {"ok": False, "error": str(exc)}

        await stream.write(json.dumps(response).encode())
        await stream.close()

    # ---------------------------------------------------------------- Background loops
    async def _watch_head_and_announce(self) -> None:
        try:
            while True:
                try:
                    tip_hash = self._get_tip_hash()
                    if tip_hash and tip_hash != self._last_announced_tip:
                        latest = db.get_latest_block()
                        header = (latest or {}).get("header", {})
                        tip_num = int(header.get("block_number") or 0)
                        payload = {
                            "headers": [
                                {
                                    "block_number": tip_num,
                                    "previous_hash": header.get("previous_hash"),
                                    "timestamp": header.get("timestamp"),
                                    "merkle_root": header.get("merkle_root"),
                                    "block_hash": tip_hash,
                                }
                            ],
                            "tip_number": tip_num,
                            "tip_hash": tip_hash,
                        }
                        message_id = payload["headers"][0]["block_hash"] or uuid.uuid4().hex
                        await self.publish_gossip(
                            TAU_GOSSIP_TOPIC_BLOCKS,
                            payload,
                            message_id=message_id,
                        )
                        self._last_announced_tip = tip_hash
                except Exception:
                    logger.debug("watch_head iteration failed", exc_info=True)
                await trio.sleep(1.0)
        except trio.Cancelled:
            return

    async def _gossip_cleanup_loop(self) -> None:
        try:
            while True:
                now = trio.current_time()
                cutoff = now - max(self._gossip_seen_ttl, 1.0)
                for message_id, timestamp in list(self._gossip_seen.items()):
                    if timestamp < cutoff:
                        self._gossip_seen.pop(message_id, None)
                await trio.sleep(max(1.0, self._gossip_seen_ttl / 2))
        except trio.Cancelled:
            return

    async def _peer_advertisement_loop(self) -> None:
        if self._peer_advertisement_interval <= 0:
            return
        try:
            while True:
                await trio.sleep(self._peer_advertisement_interval)
                peers = self._collect_peer_snapshot(
                    self._peer_advertisement_max_peers,
                    recent_only=True,
                )
                if not peers:
                    peers = self._collect_peer_snapshot(self._peer_advertisement_max_peers)
                providers: List[Dict[str, Any]] = []
                if self._handshake_provider_limit:
                    providers = self._collect_provider_snapshot(
                        min(self._handshake_provider_limit, self._peer_advertisement_max_peers)
                    )
                if not peers and not providers:
                    continue
                payload: Dict[str, Any] = {}
                if peers:
                    payload["peers"] = peers
                if providers:
                    payload["providers"] = providers
                try:
                    await self.publish_gossip(TAU_GOSSIP_TOPIC_PEERS, payload)
                except Exception:
                    logger.debug("Failed to publish peer advertisement gossip", exc_info=True)
        except trio.Cancelled:
            return

    # ---------------------------------------------------------------- Persistence helpers
    def _restore_peerstore(self) -> None:
        if self._host is None:
            return
        mapping = self._peerstore_persist.load()
        if not mapping:
            return
        store = self._host.get_peerstore()
        for pid_str, addrs in mapping.items():
            try:
                pid = ID.from_base58(pid_str)
                ma_list = [multiaddr.Multiaddr(addr) for addr in addrs]
                store.add_addrs(pid, ma_list, PERMANENT_ADDR_TTL)
            except Exception:
                logger.debug("Failed to restore peer %s", pid_str, exc_info=True)

    def _persist_peerstore(self) -> None:
        if self._host is None:
            return
        store = self._host.get_peerstore()
        data: Dict[str, List[str]] = {}
        for pid in store.peer_ids():
            try:
                addrs = store.addrs(pid)
            except PeerStoreError:
                continue
            data[str(pid)] = [str(addr) for addr in addrs]
        self._peerstore_persist.save(data)

    def _save_peer_basic(self, peer_info: PeerInfo) -> None:
        try:
            db.upsert_peer_basic(
                str(peer_info.peer_id),
                [str(addr) for addr in peer_info.addrs],
                agent=self._config.agent,
                network_id=self._config.network_id,
                genesis_hash=self._config.genesis_hash,
            )
        except Exception:
            logger.debug("Failed to persist peer %s", peer_info.peer_id, exc_info=True)

    # ---------------------------------------------------------------- Bootstrap / sync
    async def _bootstrap(self) -> None:
        if self._host is None or not self._config.bootstrap_peers:
            return
        self_id_str = str(self._host.get_id())
        for peer in self._config.bootstrap_peers:
            try:
                peer_id = self._ensure_peer_id(peer.peer_id)
            except ValueError:
                logger.debug("Invalid bootstrap peer id: %s", peer.peer_id)
                continue
            if str(peer_id) == self_id_str:
                logger.debug("Skipping bootstrap entry for self peer_id=%s", peer.peer_id)
                continue
            cleaned_addrs = self._normalize_peer_addrs(peer.addrs)
            peer_info = PeerInfo(peer_id, cleaned_addrs or list(peer.addrs))
            try:
                addrs_for_store = cleaned_addrs or list(peer.addrs)
                self._host.get_peerstore().add_addrs(peer_id, addrs_for_store, PERMANENT_ADDR_TTL)
                logger.info(
                    "Bootstrapping: connecting to peer_id=%s addrs=%s",
                    peer_id,
                    [str(addr) for addr in addrs_for_store],
                )
                try:
                    await self._host.connect(peer_info)
                except Exception as e:
                    logger.debug("Bootstrap: failed to connect to %s: %s", peer_id, e, exc_info=True)
                    continue
                self._save_peer_basic(peer_info)
                try:
                    rtt = await self._ping(peer_id)
                    if rtt is not None:
                        logger.info("Ping %s: %.1f ms", peer_id, rtt * 1000.0)
                    else:
                        logger.warning("Ping %s failed (no RTT)", peer_id)
                except Exception:
                    logger.warning("Ping %s raised", peer_id, exc_info=True)
                await self._send_local_subscriptions_to_peer(str(peer_id))
                await self._perform_handshake(peer_id)
                logger.debug("Bootstrap: calling sync with peer %s", peer_id)
                await self._sync_and_ingest_from_peer(str(peer_id), [])
                self._schedule_mempool_sync(str(peer_id))
            except Exception:
                logger.warning("Bootstrap with %s failed", peer_id, exc_info=True)

    async def _perform_handshake(self, peer_id: ID) -> None:
        if self._host is None:
            return
        try:
            stream = await self._host.new_stream(peer_id, [TAU_PROTOCOL_HANDSHAKE])
        except Exception:
            logger.debug("Handshake: failed to open stream to %s", peer_id, exc_info=True)
            return
        try:
            request_payload = self._build_handshake_payload()
            await stream.write(json.dumps(request_payload).encode())
            raw = await self._read_stream(stream, timeout=1.0)
            if raw:
                try:
                    data = json.loads(raw.decode())
                    logger.info(
                        "Handshake OK with %s head_number=%s head_hash=%s",
                        peer_id,
                        data.get("head_number"),
                        str(data.get("head_hash"))[:12],
                    )
                    self._ingest_handshake_snapshot(data, "handshake-response")
                except Exception:
                    logger.debug("Handshake: non-JSON payload from %s: %r", peer_id, raw[:64], exc_info=True)
            else:
                logger.debug("Handshake: empty response from %s", peer_id)
            self._ingest_handshake_snapshot(request_payload, "handshake-request")
        finally:
            with trio.CancelScope(shield=True):
                try:
                    await stream.close()
                except Exception:
                    pass

    async def _ping(self, peer_id: ID) -> Optional[float]:
        if self._host is None:
            return None
        start = trio.current_time()
        try:
            stream = await self._host.new_stream(peer_id, [TAU_PROTOCOL_PING])
        except Exception:
            logger.debug("Ping: failed to open stream to %s", peer_id, exc_info=True)
            return None
        try:
            nonce = uuid.uuid4().hex
            payload = json.dumps({"nonce": nonce}).encode()
            await stream.write(payload)
            raw = await self._read_stream(stream, timeout=1.0)
            if not raw:
                logger.debug("Ping: no response from %s", peer_id)
                return None
            try:
                resp = json.loads(raw.decode())
            except Exception:
                logger.debug("Ping: invalid JSON from %s: %r", peer_id, raw[:64], exc_info=True)
                return None
            if resp.get("nonce") != nonce:
                logger.debug("Ping: nonce mismatch from %s (%s != %s)", peer_id, resp.get("nonce"), nonce)
                return None
            rtt = trio.current_time() - start
            return rtt
        finally:
            with trio.CancelScope(shield=True):
                try:
                    await stream.close()
                except Exception:
                    pass

    async def _sync_and_ingest_from_peer(
        self,
        peer_id: str,
        locator: List[str],
        stop: Optional[str] = None,
        limit: int = 2000,
    ) -> int:
        if self._host is None:
            logger.debug("Sync: host is None")
            return 0

        try:
            remote = self._ensure_peer_id(peer_id)
        except ValueError:
            logger.debug("Sync: invalid peer_id %s", peer_id)
            return 0

        logger.debug("Sync: starting sync with peer %s, locator=%s", peer_id, locator)
        try:
            sync_stream = await self._host.new_stream(remote, [TAU_PROTOCOL_SYNC])
            await sync_stream.write(
                json.dumps(
                    {
                        "type": "get_headers",
                        "locator": locator,
                        "stop": stop,
                        "limit": max(1, min(int(limit), 2000)),
                    }
                ).encode()
            )
            raw = await sync_stream.read()
        except Exception as e:
            logger.debug("Sync: failed to open stream or read from %s: %s", peer_id, e)
            return 0
        finally:
            with trio.CancelScope(shield=True):
                try:
                    await sync_stream.close()
                except Exception:
                    pass

        try:
            sync_resp = json.loads(raw.decode()) if raw else {}
        except Exception as e:
            logger.debug("Sync: failed to parse sync response from %s: %s", peer_id, e)
            sync_resp = {}

        headers = sync_resp.get("headers") if isinstance(sync_resp, dict) else []
        if not isinstance(headers, list):
            headers = []

        logger.debug("Sync: received %d headers from %s", len(headers), peer_id)

        known_hashes = await trio.to_thread.run_sync(self._load_known_block_hashes)
        logger.debug("Sync: known hashes: %s", known_hashes)

        wanted_hashes = [
            str(entry.get("block_hash"))
            for entry in headers
            if isinstance(entry, dict)
            and isinstance(entry.get("block_hash"), str)
            and entry["block_hash"] not in known_hashes
        ]

        logger.debug("Sync: wanted hashes: %s", wanted_hashes)

        if not wanted_hashes:
            logger.debug("Sync: no new blocks needed from %s", peer_id)
            return 0

        logger.debug("Sync: requesting %d blocks from %s", len(wanted_hashes), peer_id)
        try:
            block_stream = await self._host.new_stream(remote, [TAU_PROTOCOL_BLOCKS])
            await block_stream.write(
                json.dumps({"type": "get_blocks", "hashes": wanted_hashes}).encode()
            )
            blocks_raw = await block_stream.read()
        except Exception as e:
            logger.debug("Sync: failed to request blocks from %s: %s", peer_id, e)
            return 0
        finally:
            with trio.CancelScope(shield=True):
                try:
                    await block_stream.close()
                except Exception:
                    pass

        try:
            blocks_resp = json.loads(blocks_raw.decode()) if blocks_raw else {}
        except Exception as e:
            logger.debug("Sync: failed to parse blocks response from %s: %s", peer_id, e)
            blocks_resp = {}

        blocks = blocks_resp.get("blocks")
        if not isinstance(blocks, list):
            logger.debug("Sync: invalid blocks response from %s", peer_id)
            return 0

        logger.debug("Sync: received %d blocks from %s", len(blocks), peer_id)
        added = await trio.to_thread.run_sync(self._insert_blocks, blocks)
        logger.debug("Sync: inserted %d blocks from %s", added, peer_id)
        if added > 0:
            await trio.to_thread.run_sync(chain_state.rebuild_state_from_blockchain, 0)
        return added

    def _load_known_block_hashes(self) -> Set[str]:
        with db._db_lock:
            cur = db._db_conn.cursor() if db._db_conn else None
        if cur is None:
            db.init_db()
            with db._db_lock:
                cur = db._db_conn.cursor()
        cur.execute("SELECT block_hash FROM blocks")
        return {row[0] for row in cur.fetchall() if isinstance(row[0], str)}

    def _insert_blocks(self, blocks: List[Dict[str, Any]]) -> int:
        added = 0
        with db._db_lock:
            cur = db._db_conn.cursor() if db._db_conn else None
            if cur is None:
                db.init_db()
                cur = db._db_conn.cursor()
            for block in blocks:
                if not isinstance(block, dict):
                    continue
                block_hash = block.get("block_hash")
                if not isinstance(block_hash, str):
                    continue
                cur.execute("SELECT 1 FROM blocks WHERE block_hash = ?", (block_hash,))
                if cur.fetchone():
                    continue
                header = block.get("header", {})
                try:
                    cur.execute(
                        """
                        INSERT INTO blocks (block_number, block_hash, previous_hash, timestamp, block_data)
                        VALUES (?, ?, ?, ?, ?)
                        """,
                        (
                            int(header.get("block_number") or 0),
                            block_hash,
                            header.get("previous_hash"),
                            int(header.get("timestamp") or 0),
                            json.dumps(block),
                        ),
                    )
                    added += 1
                except Exception:
                    logger.debug("Failed to insert block %s", block_hash, exc_info=True)
            db._db_conn.commit()
        return added

    # ---------------------------------------------------------------- State provider
    def _default_state_provider(self, request: Dict[str, Any]) -> Dict[str, Any]:
        block_hash = request.get("block_hash")
        block_number = request.get("block_number")
        block: Optional[Dict[str, Any]] = None

        def _cursor():
            with db._db_lock:
                cur = db._db_conn.cursor() if db._db_conn else None
            if cur is None:
                db.init_db()
                with db._db_lock:
                    cur = db._db_conn.cursor()
            return cur

        try:
            if isinstance(block_hash, str):
                cur = _cursor()
                cur.execute(
                    "SELECT block_data FROM blocks WHERE block_hash = ? LIMIT 1",
                    (block_hash,),
                )
                row = cur.fetchone()
                if row:
                    block = json.loads(row[0])
            elif isinstance(block_number, int):
                cur = _cursor()
                cur.execute(
                    "SELECT block_data FROM blocks WHERE block_number = ? LIMIT 1",
                    (block_number,),
                )
                row = cur.fetchone()
                if row:
                    block = json.loads(row[0])
        except Exception:
            block = None

        if block is None:
            block = self._get_tip()

        header = block.get("header", {}) if isinstance(block, dict) else {}
        result: Dict[str, Any] = {
            "block_hash": block.get("block_hash") if isinstance(block, dict) else None,
            "block_number": header.get("block_number"),
            "state_root": header.get("merkle_root")
            if header
            else request.get("state_root"),
        }

        accounts_resp: Dict[str, Any] = {}
        accounts_req = request.get("accounts")
        if isinstance(accounts_req, list):
            for addr in accounts_req:
                if isinstance(addr, str):
                    accounts_resp[addr] = {
                        "balance": chain_state.get_balance(addr),
                        "sequence": chain_state.get_sequence_number(addr),
                    }
        result["accounts"] = accounts_resp

        receipts_resp: Dict[str, Any] = {}
        receipts_req = request.get("receipts")
        if isinstance(receipts_req, list):
            for entry in receipts_req:
                receipts_resp[str(entry)] = None
        result["receipts"] = receipts_resp
        return result

    # ---------------------------------------------------------------- Lifecycle
    async def start(self) -> None:
        if self._runner_stop is not None:
            return

        self._runner_started = trio.Event()
        self._runner_finished = trio.Event()
        self._runner_stop = trio.Event()

        async def _runner() -> None:
            try:
                # Try to pass a persistent identity if provided by config by constructing
                # an Ed25519 KeyPair and supplying it via key_pair=...
                host = None
                if getattr(self._config, "identity_key", None):
                    try:
                        key_bytes = self._config.identity_key or b""
                        kp = keypair_from_seed(key_bytes)
                        host = new_host(key_pair=kp, listen_addrs=self._config.listen_addrs)
                    except Exception as exc:
                        logger.warning("Persistent identity key load failed; using ephemeral identity: %s", exc)
                        host = None
                if host is None:
                    host = new_host(listen_addrs=self._config.listen_addrs)
                self._host = host
                # Hard block on shim usage: require native libp2p implementation
                try:
                    host_module = type(self._host).__module__
                except Exception:
                    host_module = ""
                if any(x in host_module for x in ("libp2p_stub", "libp2p_shim", "libp2p_old")):
                    raise RuntimeError(
                        "Native libp2p required: shim host detected (module=%s)" % host_module
                    )
                if not hasattr(self._host, "run"):
                    raise RuntimeError(
                        "Native libp2p required: host missing 'run' context manager"
                    )
                logger.debug("libp2p host module: %s", host_module)
                self._register_handlers()
                self._restore_peerstore()

                try:
                    self._host.get_network().register_notifee(self._notifee)
                except Exception:  # pragma: no cover - defensive
                    logger.debug("Failed to register network notifee", exc_info=True)

                self._dht = KadDHT(self._host, DHTMode.SERVER)
                self._setup_dht_validators()
                await self._seed_dht_bootstrap_peers()

                async with self._host.run(self._config.listen_addrs):
                    self._trio_token = trio.lowlevel.current_trio_token()
                    logger.info(
                        "Network service started peer_id=%s addrs=%s priv=%s",
                        self._host.get_id(),
                        [str(addr) for addr in self._host.get_addrs()],
                        self._host.get_private_key()
                    )
                    bus.register(self)

                    async with background_trio_service(self._dht) as dht_manager:
                        self._dht_manager = dht_manager
                        async with trio.open_nursery() as nursery:
                            self._nursery = nursery
                            await self.join_gossip_topic(TAU_GOSSIP_TOPIC_TRANSACTIONS, self._handle_transaction_gossip)
                            await self.join_gossip_topic(TAU_GOSSIP_TOPIC_BLOCKS, self._handle_block_gossip)
                            await self.join_gossip_topic(TAU_GOSSIP_TOPIC_PEERS, self._handle_peer_advertisement)
                            nursery.start_soon(self._bootstrap)
                            nursery.start_soon(self._watch_head_and_announce)
                            nursery.start_soon(self._gossip_cleanup_loop)
                            if self._dht is not None:
                                nursery.start_soon(self._dht_refresh_loop)
                                nursery.start_soon(self._metrics_log_loop)
                            if self._peer_advertisement_interval > 0:
                                nursery.start_soon(self._peer_advertisement_loop)
                            self._runner_started.set()
                            await self._runner_stop.wait()
                            nursery.cancel_scope.cancel()
            except Exception:
                logger.exception("Network service runner crashed")
                self._runner_started.set()
                raise
            finally:
                try:
                    self._persist_peerstore()
                except Exception:
                    logger.debug("Failed to persist peerstore on shutdown", exc_info=True)

                bus.unregister(self)

                # Best-effort explicit shutdown of network/host to avoid socket leaks
                try:
                    if self._host is not None:
                        try:
                            network = self._host.get_network()
                            close_network = getattr(network, "close", None)
                            if callable(close_network):
                                await close_network()
                        except Exception:
                            logger.debug("Failed to close libp2p network", exc_info=True)
                        try:
                            host_close = getattr(self._host, "close", None)
                            if callable(host_close):
                                await host_close()
                        except Exception:
                            logger.debug("Failed to close libp2p host", exc_info=True)
                except Exception:
                    logger.debug("Unexpected error during host shutdown", exc_info=True)

                self._host = None
                self._nursery = None
                self._trio_token = None
                self._dht_manager = None
                self._dht = None
                self._dht_validators.clear()
                self._dht_value_store_put = None
                self._dht_provider_add = None
                self._gossip_peer_topics.clear()
                self._mempool_synced_peers.clear()
                self._pending_tx.clear()
                self._runner_finished.set()

        trio.lowlevel.spawn_system_task(_runner)
        await self._runner_started.wait()

    async def stop(self) -> None:
        if self._runner_stop is None:
            return
        self._runner_stop.set()
        if self._runner_finished is not None:
            await self._runner_finished.wait()
        self._runner_stop = None
        self._runner_finished = None
        self._runner_started = None

    # ---------------------------------------------------------------- Utils
    @staticmethod
    def _ensure_peer_id(peer_id: Any) -> ID:
        if isinstance(peer_id, ID):
            return peer_id
        if isinstance(peer_id, str):
            return ID.from_base58(peer_id)
        raise ValueError("invalid peer id")

    @staticmethod
    def _normalize_peer_addrs(addrs: Iterable[multiaddr.Multiaddr]) -> List[multiaddr.Multiaddr]:
        # For native libp2p, keep the full multiaddr with /p2p/<peerid>.
        # Also include a stripped TCP form for stacks that accept raw TCP addrs.
        seen: set[str] = set()
        result: List[multiaddr.Multiaddr] = []
        for addr in addrs:
            try:
                full = str(addr)
            except Exception:
                continue
            if full not in seen:
                try:
                    result.append(multiaddr.Multiaddr(full))
                    seen.add(full)
                except Exception:
                    pass
            if "/p2p/" in full:
                base = full.split("/p2p/")[0]
                if base and base not in seen:
                    try:
                        result.append(multiaddr.Multiaddr(base))
                        seen.add(base)
                    except Exception:
                        pass
        return result

    def _register_handlers(self) -> None:
        if self._host is None:
            return
        self._host.set_stream_handler(TAU_PROTOCOL_HANDSHAKE, self._handle_handshake)
        self._host.set_stream_handler(TAU_PROTOCOL_PING, self._handle_ping)
        self._host.set_stream_handler(TAU_PROTOCOL_SYNC, self._handle_sync)
        self._host.set_stream_handler(TAU_PROTOCOL_BLOCKS, self._handle_blocks)
        self._host.set_stream_handler(TAU_PROTOCOL_GOSSIP, self._handle_gossip)
        self._host.set_stream_handler(TAU_PROTOCOL_TX, self._handle_tx)
        self._host.set_stream_handler(TAU_PROTOCOL_STATE, self._handle_state)
        logger.debug("Registered stream handlers for handshake, ping, sync, blocks, gossip, tx, state")

    @property
    def host(self) -> Optional[IHost]:
        return self._host
    async def _read_stream(self, stream, timeout: float = 1.0, max_bytes: int = 65536) -> bytes:
        data = b""
        with trio.move_on_after(timeout) as cancel_scope:
            try:
                data = await stream.read(max_bytes)
            except trio.Cancelled:
                raise
            except Exception:
                data = b""
        if cancel_scope.cancelled_caught:
            # Timed out waiting for EOF; any partial data already returned by read.
            return data or b""
        return data or b""
