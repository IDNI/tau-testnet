from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import uuid
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

import multiaddr

from libp2p import new_host
from libp2p.peer.peerinfo import PeerInfo

from .config import NetworkConfig, BootstrapPeer
import db
import chain_state
from commands import sendtx
from .protocols import (
    TAU_PROTOCOL_HANDSHAKE,
    TAU_PROTOCOL_PING,
    TAU_PROTOCOL_SYNC,
    TAU_PROTOCOL_BLOCKS,
    TAU_PROTOCOL_TX,
    TAU_PROTOCOL_STATE,
    TAU_PROTOCOL_GOSSIP,
    TAU_GOSSIP_TOPIC_BLOCKS,
    TAU_GOSSIP_TOPIC_TRANSACTIONS,
)
from . import bus


logger = logging.getLogger(__name__)


class PeerstorePersistence:
    """
    DB-backed peerstore persistence. Uses db.load_peers_basic / db.upsert_peer_basic.
    The `path` is ignored (kept for signature compatibility).
    """
    def __init__(self, path: Optional[str]) -> None:
        self._path = path

    def load(self) -> Dict[str, List[str]]:
        try:
            return db.load_peers_basic()
        except Exception:
            return {}

    def save(self, peer_id_to_addrs: Dict[str, List[str]]) -> None:
        # Write any provided peers to DB
        try:
            for pid, addrs in peer_id_to_addrs.items():
                db.upsert_peer_basic(pid, [str(a) for a in addrs])
        except Exception:
            return


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
        self._host = None
        self._tasks: List[asyncio.Task] = []
        self._peerstore_persist = PeerstorePersistence(config.peerstore_path)
        self._last_announced_tip: Optional[str] = None
        self._submit_tx = tx_submitter or sendtx.queue_transaction
        self._state_provider = state_provider or self._default_state_provider
        self._gossip_handlers: Dict[str, List[Callable[[Dict[str, Any]], Any]]] = {}
        if gossip_handler:
            self.subscribe_gossip("*", gossip_handler)
        self._gossip_seen: Dict[str, float] = {}
        self._gossip_seen_ttl = 300.0
        self._gossip_peer_topics: Dict[str, Set[str]] = {}
        self._gossip_local_topics: Set[str] = set()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def subscribe_gossip(self, topic: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        """Register a handler for gossip envelopes on a topic. Use '*' for catch-all."""
        if not isinstance(topic, str) or not topic:
            raise ValueError("topic must be a non-empty string")
        if not callable(handler):
            raise ValueError("handler must be callable")
        self._gossip_handlers.setdefault(topic, []).append(handler)

    async def join_gossip_topic(self, topic: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        """Subscribe locally to a topic and announce the subscription to peers."""
        self.subscribe_gossip(topic, handler)
        if topic in self._gossip_local_topics:
            return
        self._gossip_local_topics.add(topic)
        await self._broadcast_gossip_subscriptions([
            {"topic": topic, "subscribe": True}
        ])

    async def publish_gossip(self, topic: str, payload: Any, *, message_id: Optional[str] = None) -> str:
        """Broadcast a gossip payload under a topic using gossipsub semantics."""
        if self._host is None:
            raise RuntimeError("network service is not started")
        if not isinstance(topic, str) or not topic:
            raise ValueError("topic must be a non-empty string")
        message_id = message_id or uuid.uuid4().hex
        message = {
            "from": self._host.get_id(),
            "topic": topic,
            "data": payload,
            "message_id": message_id,
            "timestamp": asyncio.get_event_loop().time(),
        }
        try:
            json.dumps(message)
        except TypeError as exc:
            raise ValueError("gossip payload must be JSON serializable") from exc
        logger.debug("[network][gossip] Local publish topic=%s message_id=%s payload=%s", topic, message_id, message.get("data"))
        self._gossip_seen[message_id] = message["timestamp"]
        # Deliver locally before attempting any rebroadcasts. This ensures handlers
        # can synchronously subscribe to additional topics in response to the
        # message before we forward it to peers.
        await self._deliver_gossip(message, via_peer=None)
        await self._rebroadcast_gossip_message(message, exclude={self._host.get_id()})
        return message_id

    def broadcast_transaction(self, payload: str, message_id: str) -> None:
        if self._loop is None:
            return

        async def _publish() -> None:
            logger.debug("[network][gossip] Scheduling transaction publish message_id=%s payload=%s", message_id, payload)
            await self.publish_gossip(TAU_GOSSIP_TOPIC_TRANSACTIONS, payload, message_id=message_id)

        future = asyncio.run_coroutine_threadsafe(_publish(), self._loop)

        def _log_result(fut: concurrent.futures.Future[Any]) -> None:
            if fut.cancelled():
                return
            exc = fut.exception()
            if exc:
                logger.debug("Transaction gossip publish failed: %s", exc)

        future.add_done_callback(_log_result)

    async def _rebroadcast_gossip_message(self, message: Dict[str, Any], exclude: Optional[Set[str]] = None) -> None:
        if self._host is None:
            return
        topic = message.get("topic")
        if not isinstance(topic, str):
            return
        if exclude is None:
            exclude_ids: Set[str] = set()
        else:
            exclude_ids = set(exclude)
        exclude_ids.add(self._host.get_id())
        peers = list(self._host.get_peerstore().peers())
        if not peers:
            return
        envelope = json.dumps({
            "peer_id": self._host.get_id(),
            "rpc": {"messages": [message]},
        }).encode()
        for peer_id in peers:
            if peer_id in exclude_ids:
                continue
            if not self._should_send_topic_to_peer(peer_id, topic):
                continue
            logger.debug("[network][gossip] Rebroadcasting topic=%s id=%s to peer=%s", topic, message.get("message_id"), peer_id)
            await self._send_gossip_rpc(peer_id, envelope)

    def _should_send_topic_to_peer(self, peer_id: str, topic: str) -> bool:
        topics = self._gossip_peer_topics.get(peer_id)
        return topics is None or topic in topics

    async def _send_gossip_rpc(self, peer_id: str, payload: bytes) -> None:
        if self._host is None:
            return
        try:
            stream = await self._host.new_stream(peer_id, [TAU_PROTOCOL_GOSSIP])
            logger.debug("[network][gossip] Opened gossip stream to %s", peer_id)
            await stream.write(payload)
            try:
                await stream.read()
            except Exception:
                pass
            await stream.close()
            logger.debug("[network][gossip] Closed gossip stream to %s", peer_id)
        except Exception:
            logger.debug("[network][gossip] Failed to send gossip RPC to %s", peer_id, exc_info=True)
            return

    async def _broadcast_gossip_subscriptions(self, subscriptions: Iterable[Dict[str, Any]]) -> None:
        if self._host is None:
            return
        subs = [sub for sub in subscriptions if isinstance(sub.get("topic"), str)]
        if not subs:
            return
        peers = list(self._host.get_peerstore().peers())
        if not peers:
            return
        payload = json.dumps({
            "peer_id": self._host.get_id(),
            "rpc": {"subscriptions": subs},
        }).encode()
        for peer_id in peers:
            logger.debug("[network][gossip] Broadcasting subscriptions to %s topics=%s", peer_id, subs)
            await self._send_gossip_rpc(peer_id, payload)

    async def _send_local_subscriptions_to_peer(self, peer_id: str) -> None:
        if self._host is None or not self._gossip_local_topics:
            return
        payload = json.dumps({
            "peer_id": self._host.get_id(),
            "rpc": {
                "subscriptions": [
                    {"topic": topic, "subscribe": True}
                    for topic in sorted(self._gossip_local_topics)
                ]
            },
        }).encode()
        logger.debug("[network][gossip] Sending local subscriptions to peer %s topics=%s", peer_id, list(self._gossip_local_topics))
        await self._send_gossip_rpc(peer_id, payload)

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
        targets = list(self._gossip_handlers.get(topic, []))
        targets.extend(self._gossip_handlers.get("*", []))
        logger.debug("[network][gossip] Delivering topic=%s id=%s to %d handlers via=%s", topic, envelope.get("message_id"), len(targets), via_peer)
        for handler in targets:
            try:
                maybe = handler(envelope)
                if asyncio.iscoroutine(maybe):
                    await maybe
            except Exception:
                logger.debug("[network][gossip] Handler %s raised exception", handler, exc_info=True)
                continue

    async def _handle_transaction_gossip(self, envelope: Dict[str, Any]) -> None:
        if self._host and envelope.get("origin") == self._host.get_id():
            return
        payload = envelope.get("payload")
        if not isinstance(payload, str):
            logger.debug("[network][gossip] Ignoring TX gossip with non-string payload: %s", type(payload))
            return
        logger.debug("[network][gossip] Processing TX gossip message_id=%s origin=%s", envelope.get("message_id"), envelope.get("origin"))
        try:
            await asyncio.to_thread(sendtx.queue_transaction, payload, False)
        except TypeError:
            # Fallback for legacy signature without propagate flag (during upgrades)
            await asyncio.to_thread(sendtx.queue_transaction, payload)
        except Exception as exc:
            logger.debug("Failed to ingest transaction from gossip: %s", exc)

    async def _handle_block_gossip(self, envelope: Dict[str, Any]) -> None:
        if self._host and envelope.get("origin") == self._host.get_id():
            return
        payload = envelope.get("payload")
        if not isinstance(payload, dict):
            logger.debug("[network][gossip] Ignoring block gossip with invalid payload type=%s", type(payload))
            return
        peer_id = envelope.get("origin") or envelope.get("via")
        if not isinstance(peer_id, str) or not peer_id:
            return
        logger.debug("[network][gossip] Processing block gossip message_id=%s from=%s", envelope.get("message_id"), peer_id)
        locator: List[str] = []
        try:
            tip_hash = self._get_tip_hash()
            if tip_hash:
                locator = [tip_hash]
        except Exception:
            locator = []
        try:
            logger.debug("[network][gossip] Attempting subscription sync to peer %s before block sync", peer_id)
            await self._send_local_subscriptions_to_peer(peer_id)
        except Exception as exc:
            logger.debug("[network][gossip] Failed sending subscriptions to %s: %s", peer_id, exc)
        try:
            await self._sync_and_ingest_from_peer(peer_id, locator)
        except Exception as exc:
            logger.debug("Block gossip sync from %s failed: %s", peer_id, exc)

    async def _sync_and_ingest_from_peer(self, peer_id: str, locator: List[str], stop: Optional[str] = None, limit: int = 2000) -> int:
        """Send SYNC to peer, request bodies for unknown headers, ingest, and rebuild state.
        Returns number of blocks added.
        """
        try:
            sync_req = {"type": "get_headers", "locator": locator, "limit": max(1, min(int(limit), 2000))}
            s = await self._host.new_stream(peer_id, [TAU_PROTOCOL_SYNC])
            await s.write(json.dumps(sync_req).encode())
            resp_raw = await s.read()
            await s.close()
            try:
                sync = json.loads(resp_raw.decode()) if resp_raw else {}
            except Exception:
                sync = {}
            headers = sync.get("headers", []) if isinstance(sync, dict) else []
        except Exception:
            headers = []

        # Build set of known hashes
        try:
            with db._db_lock:
                cur = db._db_conn.cursor() if db._db_conn else None
            if cur is None:
                db.init_db()
                with db._db_lock:
                    cur = db._db_conn.cursor()
            cur.execute('SELECT block_hash FROM blocks')
            known = {h for (h,) in cur.fetchall()}
        except Exception:
            known = set()

        wanted_hashes: List[str] = []
        for h in headers:
            try:
                bh = str(h.get('block_hash'))
                if bh and bh not in known:
                    wanted_hashes.append(bh)
            except Exception:
                continue

        added = 0
        if wanted_hashes:
            try:
                req = {"type": "get_blocks", "hashes": wanted_hashes}
                bs = await self._host.new_stream(peer_id, [TAU_PROTOCOL_BLOCKS])
                await bs.write(json.dumps(req).encode())
                blocks_raw = await bs.read()
                await bs.close()
                try:
                    blocks_resp = json.loads(blocks_raw.decode()) if blocks_raw else {}
                except Exception:
                    blocks_resp = {}
                blocks = blocks_resp.get("blocks", []) if isinstance(blocks_resp, dict) else []
                if blocks:
                    with db._db_lock:
                        cur = db._db_conn.cursor()
                        for b in blocks:
                            try:
                                hdr = b.get("header", {})
                                bn = int(hdr.get("block_number"))
                                prev = str(hdr.get("previous_hash"))
                                ts = int(hdr.get("timestamp"))
                                bh = str(b.get("block_hash"))
                                cur.execute('SELECT 1 FROM blocks WHERE block_hash=?', (bh,))
                                if cur.fetchone():
                                    continue
                                cur.execute(
                                    'INSERT INTO blocks (block_number, block_hash, previous_hash, timestamp, block_data) VALUES (?, ?, ?, ?, ?)',
                                    (bn, bh, prev, ts, json.dumps(b))
                                )
                                added += 1
                            except Exception:
                                continue
                        db._db_conn.commit()
            except Exception:
                added = 0

        if added > 0:
            try:
                import chain_state
                await asyncio.to_thread(chain_state.rebuild_state_from_blockchain, 0)
            except Exception:
                pass
        return added

    def _default_state_provider(self, request: Dict[str, Any]) -> Dict[str, Any]:
        block_hash = request.get("block_hash")
        block_number = request.get("block_number")
        block: Optional[Dict[str, Any]] = None

        def _ensure_cursor():
            with db._db_lock:
                cur = db._db_conn.cursor() if db._db_conn else None
            if cur is None:
                db.init_db()
                with db._db_lock:
                    cur = db._db_conn.cursor()
            return cur

        try:
            if isinstance(block_hash, str):
                cur = _ensure_cursor()
                cur.execute('SELECT block_data FROM blocks WHERE block_hash = ? LIMIT 1', (block_hash,))
                row = cur.fetchone()
                if row:
                    block = json.loads(row[0])
            elif isinstance(block_number, int):
                cur = _ensure_cursor()
                cur.execute('SELECT block_data FROM blocks WHERE block_number = ? LIMIT 1', (block_number,))
                row = cur.fetchone()
                if row:
                    block = json.loads(row[0])
        except Exception:
            block = None

        if block is None:
            try:
                block = db.get_latest_block()
            except Exception:
                block = None

        header = block.get("header", {}) if isinstance(block, dict) else {}
        result: Dict[str, Any] = {
            "block_hash": block.get("block_hash") if isinstance(block, dict) else None,
            "block_number": header.get("block_number"),
            "state_root": header.get("merkle_root") if header else request.get("state_root"),
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

    def _build_handshake(self) -> bytes:
        print(f"[DEBUG][network] Building handshake payload")
        payload = {
            "network_id": self._config.network_id,
            "node_id": self._host.get_id() if self._host else "",
            "agent": self._config.agent,
            "genesis_hash": self._config.genesis_hash,
            "head_number": self._get_tip_number(),
            "head_hash": self._get_tip_hash(),
            "time": asyncio.get_event_loop().time(),
        }
        try:
            print(f"[DEBUG][network] Handshake payload: {json.dumps(payload)}")
        except Exception:
            pass
        return json.dumps(payload).encode()

    def _get_tip(self) -> Optional[Dict]:
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
            return tip["block_hash"] if tip else self._config.genesis_hash
        except Exception:
            return self._config.genesis_hash

    async def _handle_handshake(self, stream) -> None:
        raw = await stream.read()
        print(f"[DEBUG][network] <- HANDSHAKE request bytes={len(raw) if raw else 0}")
        # Respond with our handshake
        resp = self._build_handshake()
        await stream.write(resp)
        print(f"[DEBUG][network] -> HANDSHAKE response bytes={len(resp)}")
        await stream.close()

    async def _handle_ping(self, stream) -> None:
        raw = await stream.read()
        print(f"[DEBUG][network] <- PING raw='{raw.decode(errors='ignore') if raw else ''}'")
        try:
            data = json.loads(raw.decode())
            pong = {"nonce": data.get("nonce"), "time": asyncio.get_event_loop().time()}
        except Exception:
            pong = {"nonce": None, "time": asyncio.get_event_loop().time()}
        out = json.dumps(pong).encode()
        await stream.write(out)
        print(f"[DEBUG][network] -> PONG '{json.dumps(pong)}'")
        await stream.close()

    def _load_headers_from_db(self, locator: List[str], stop: Optional[str], limit: int) -> List[Dict]:
        """
        Load a page of headers from the DB based on a locator-style request.
        - If there are no blocks, return [].
        - If locator contains hashes present in the chain, start after the first match.
        - Otherwise start from the chain head and walk back (but here we'll paginate forward from genesis for simplicity).
        - Respect the limit; if stop is provided, stop when encountered.
        Returns a list of header dicts (without transactions).
        """
        print(f"[DEBUG][network] Loading headers: locator={locator}, stop={stop}, limit={limit}")
        with db._db_lock:
            cur = db._db_conn.cursor() if db._db_conn else None
        if cur is None:
            db.init_db()
            with db._db_lock:
                cur = db._db_conn.cursor()
        cur.execute('SELECT block_data FROM blocks ORDER BY block_number ASC')
        rows = cur.fetchall()
        chain: List[Dict] = [json.loads(r[0]) for r in rows]
        print(f"[DEBUG][network] Headers DB: total_blocks={len(chain)}")
        if not chain:
            return []

        # Map hash -> index for quick lookup
        hash_to_idx: Dict[str, int] = {b["block_hash"]: idx for idx, b in enumerate(chain)}

        start_idx = 0
        matched_hash = None
        for h in locator or []:
            if h in hash_to_idx:
                start_idx = hash_to_idx[h] + 1
                matched_hash = h
                break
        if matched_hash is not None:
            print(f"[DEBUG][network] Locator matched at hash={matched_hash}, start_idx={start_idx}")
        else:
            print(f"[DEBUG][network] Locator had no matches; starting at genesis (idx=0)")

        headers: List[Dict] = []
        count = 0
        for i in range(start_idx, len(chain)):
            blk = chain[i]
            head = blk["header"]
            headers.append({
                "block_number": head["block_number"],
                "previous_hash": head["previous_hash"],
                "timestamp": head["timestamp"],
                "merkle_root": head["merkle_root"],
                "block_hash": blk["block_hash"],
            })
            count += 1
            if stop and blk["block_hash"] == stop:
                print(f"[DEBUG][network] Stop hash encountered at idx={i} hash={blk['block_hash']}")
                break
            if count >= max(1, min(limit, 2000)):
                break
        print(f"[DEBUG][network] Returning {len(headers)} headers (count={count}) from idx={start_idx}")
        return headers

    async def _handle_sync(self, stream) -> None:
        # Accept GetHeaders and respond with headers+tip
        raw = await stream.read()
        print(f"[DEBUG][network] <- SYNC raw='{raw.decode(errors='ignore') if raw else ''}'")
        locator: List[str] = []
        stop: Optional[str] = None
        limit: int = 2000
        try:
            if raw:
                req = json.loads(raw.decode())
                if isinstance(req, dict):
                    if isinstance(req.get("locator"), list):
                        locator = [str(h) for h in req.get("locator")]
                    if isinstance(req.get("stop"), str):
                        stop = req.get("stop")
                    if isinstance(req.get("limit"), int):
                        limit = req.get("limit")
        except Exception:
            # ignore malformed request and use defaults
            pass

        try:
            headers = self._load_headers_from_db(locator, stop, limit)
        except Exception:
            headers = []

        response = {
            "headers": headers,
            "tip_number": self._get_tip_number(),
            "tip_hash": self._get_tip_hash(),
        }
        out = json.dumps(response).encode()
        await stream.write(out)
        try:
            print(f"[DEBUG][network] -> SYNC response: {json.dumps(response)[:512]}")
        except Exception:
            pass
        await stream.close()

    async def _handle_blocks(self, stream) -> None:
        # Accept GetBlocks and respond with blocks.
        raw = await stream.read()
        print(f"[DEBUG][network] <- BLOCKS raw='{raw.decode(errors='ignore') if raw else ''}'")
        req = {}
        try:
            if raw:
                req = json.loads(raw.decode())
        except Exception:
            req = {}

        blocks_out = []
        try:
            # Strategy 1: explicit list of hashes
            hashes = req.get("hashes") if isinstance(req, dict) else None
            if isinstance(hashes, list) and hashes:
                wanted = [str(h) for h in hashes]
                # Load all blocks once and filter/order by wanted
                with db._db_lock:
                    cur = db._db_conn.cursor() if db._db_conn else None
                if cur is None:
                    db.init_db()
                    with db._db_lock:
                        cur = db._db_conn.cursor()
                # Fetch by hash in one query
                qmarks = ",".join(["?"] * len(wanted))
                cur.execute(f"SELECT block_hash, block_data FROM blocks WHERE block_hash IN ({qmarks})", wanted)
                rows = cur.fetchall()
                by_hash = {h: json.loads(j) for (h, j) in rows}
                for h in wanted:
                    if h in by_hash:
                        blocks_out.append(by_hash[h])
            else:
                # Strategy 2: from hash + limit (or from_number)
                from_hash = req.get("from") if isinstance(req, dict) else None
                from_number = req.get("from_number") if isinstance(req, dict) else None
                limit = req.get("limit", 2000) if isinstance(req, dict) else 2000
                with db._db_lock:
                    cur = db._db_conn.cursor() if db._db_conn else None
                if cur is None:
                    db.init_db()
                    with db._db_lock:
                        cur = db._db_conn.cursor()
                start_num = 0
                if isinstance(from_number, int) and from_number >= 0:
                    start_num = from_number
                elif isinstance(from_hash, str) and from_hash:
                    cur.execute('SELECT block_number FROM blocks WHERE block_hash = ? LIMIT 1', (from_hash,))
                    row = cur.fetchone()
                    start_num = (row[0] + 1) if row else 0
                cur.execute('SELECT block_data FROM blocks WHERE block_number >= ? ORDER BY block_number ASC LIMIT ?', (start_num, max(1, min(int(limit), 2000))))
                rows = cur.fetchall()
                blocks_out = [json.loads(j) for (j,) in rows]
        except Exception:
            blocks_out = []

        response = {"blocks": blocks_out}
        out = json.dumps(response).encode()
        await stream.write(out)
        try:
            print(f"[DEBUG][network] -> BLOCKS response: blocks={len(blocks_out)}")
        except Exception:
            pass
        await stream.close()

    async def _handle_gossip(self, stream) -> None:
        raw = await stream.read()
        decoded = raw.decode(errors='ignore') if raw else ''
        print(f"[DEBUG][network] <- GOSSIP raw='{decoded}'")
        try:
            packet = json.loads(decoded) if decoded else {}
        except Exception:
            packet = {}
        response: Dict[str, Any]
        if not isinstance(packet, dict):
            response = {"ok": False, "error": "invalid gossipsub frame"}
            await stream.write(json.dumps(response).encode())
            await stream.close()
            return

        rpc = packet.get("rpc")
        if not isinstance(rpc, dict):
            response = {"ok": False, "error": "missing gossipsub rpc"}
            await stream.write(json.dumps(response).encode())
            await stream.close()
            return

        peer_id = packet.get("peer_id") if isinstance(packet.get("peer_id"), str) else None

        subs_updated = 0
        subs = rpc.get("subscriptions")
        if isinstance(subs, list) and peer_id:
            topics = self._gossip_peer_topics.setdefault(peer_id, set())
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
        loop = asyncio.get_event_loop()
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict):
                    continue
                topic = msg.get("topic")
                message_id = msg.get("message_id")
                if not isinstance(topic, str) or not isinstance(message_id, str):
                    continue
                duplicate = message_id in self._gossip_seen
                logger.debug("[network][gossip] Handling incoming message topic=%s id=%s duplicate=%s via=%s", topic, message_id, duplicate, peer_id)
                if not duplicate:
                    now = loop.time()
                    self._gossip_seen[message_id] = now
                    msg.setdefault("timestamp", now)
                    if not isinstance(msg.get("from"), str) and peer_id:
                        msg["from"] = peer_id
                    exclude: Optional[Set[str]] = {peer_id} if peer_id else None
                    await self._deliver_gossip(msg, via_peer=peer_id)
                    await self._rebroadcast_gossip_message(msg, exclude=exclude)
                duplicates.append({
                    "message_id": message_id,
                    "duplicate": duplicate,
                    "topic": topic,
                })

        response = {
            "ok": True,
            "subscriptions_updated": subs_updated,
            "messages": duplicates,
        }
        await stream.write(json.dumps(response).encode())
        await stream.close()

    async def _handle_tx(self, stream) -> None:
        raw = await stream.read()
        decoded = raw.decode(errors='ignore') if raw else ''
        print(f"[DEBUG][network] <- TX raw='{decoded}'")
        payload: Optional[str] = None
        try:
            req = json.loads(decoded) if decoded else {}
        except Exception:
            req = decoded

        if isinstance(req, dict):
            if 'tx' in req:
                val = req['tx']
                payload = val if isinstance(val, str) else json.dumps(val)
            elif 'transaction' in req:
                val = req['transaction']
                payload = val if isinstance(val, str) else json.dumps(val)
            elif 'payload' in req:
                val = req['payload']
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

        out = json.dumps(response).encode()
        await stream.write(out)
        print(f"[DEBUG][network] -> TX response: {json.dumps(response)}")
        await stream.close()

    async def _handle_state(self, stream) -> None:
        raw = await stream.read()
        decoded = raw.decode(errors='ignore') if raw else ''
        print(f"[DEBUG][network] <- STATE raw='{decoded}'")
        request: Dict[str, Any] = {}
        try:
            if decoded:
                maybe = json.loads(decoded)
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

        out = json.dumps(response).encode()
        await stream.write(out)
        print(f"[DEBUG][network] -> STATE response: {json.dumps(response)[:512]}")
        await stream.close()

    def _register_handlers(self) -> None:
        self._host.set_stream_handler(TAU_PROTOCOL_HANDSHAKE, self._handle_handshake)
        self._host.set_stream_handler(TAU_PROTOCOL_PING, self._handle_ping)
        self._host.set_stream_handler(TAU_PROTOCOL_SYNC, self._handle_sync)
        self._host.set_stream_handler(TAU_PROTOCOL_BLOCKS, self._handle_blocks)
        self._host.set_stream_handler(TAU_PROTOCOL_GOSSIP, self._handle_gossip)
        self._host.set_stream_handler(TAU_PROTOCOL_TX, self._handle_tx)
        self._host.set_stream_handler(TAU_PROTOCOL_STATE, self._handle_state)

    async def _watch_head_and_announce(self) -> None:
        # Periodically check head and announce new headers to known peers
        while True:
            try:
                tip_hash = self._get_tip_hash()
                if tip_hash and tip_hash != self._last_announced_tip:
                    latest = db.get_latest_block()
                    tip_num = int(latest["header"]["block_number"]) if latest else 0
                    hdr = {
                        "block_number": tip_num,
                        "previous_hash": latest["header"].get("previous_hash") if latest else "",
                        "timestamp": latest["header"].get("timestamp") if latest else 0,
                        "merkle_root": latest["header"].get("merkle_root") if latest else "",
                        "block_hash": tip_hash,
                    }
                    addrs = [str(a) for a in (self._host.get_addrs() or [])]
                    try:
                        await self.publish_gossip(
                            TAU_GOSSIP_TOPIC_BLOCKS,
                            {
                                "headers": [hdr],
                                "tip_number": tip_num,
                                "tip_hash": tip_hash,
                            },
                            message_id=hdr.get("block_hash") or uuid.uuid4().hex,
                        )
                    except Exception as exc:
                        logger.debug("Failed to gossip new block header: %s", exc)
                    self._last_announced_tip = tip_hash
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(1.0)

    async def _gossip_cleanup_loop(self) -> None:
        while True:
            try:
                now = asyncio.get_event_loop().time()
                cutoff = now - max(self._gossip_seen_ttl, 1.0)
                for message_id, timestamp in list(self._gossip_seen.items()):
                    if timestamp < cutoff:
                        self._gossip_seen.pop(message_id, None)
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(max(1.0, self._gossip_seen_ttl / 2))

    def _restore_peerstore(self) -> None:
        mapping = self._peerstore_persist.load()
        if not mapping:
            return
        store = self._host.get_peerstore()
        for pid, addrs_str in mapping.items():
            try:
                addrs = [multiaddr.Multiaddr(a) for a in addrs_str]
                store.add_addrs(pid, addrs, 600)
            except Exception:
                continue

    def _persist_peerstore(self) -> None:
        store = self._host.get_peerstore()
        data: Dict[str, List[str]] = {}
        for pid in store.peers():
            # We do not have readback API on shim; skip detailed save in shim.
            data[pid] = []
        self._peerstore_persist.save(data)

    def _save_peer_basic(self, peer_info: PeerInfo) -> None:
        try:
            addrs_str = [str(a) for a in getattr(peer_info, "addrs", [])]
            db.upsert_peer_basic(peer_info.peer_id, addrs_str, agent=self._config.agent,
                                 network_id=self._config.network_id, genesis_hash=self._config.genesis_hash)
        except Exception:
            pass

    async def _bootstrap(self) -> None:
        if not self._config.bootstrap_peers:
            return
        for peer in self._config.bootstrap_peers:
            try:
                peer_info = PeerInfo(peer.peer_id, peer.addrs)
                addrs_str = [str(a) for a in peer_info.addrs]
                print(f"[INFO][network] Bootstrapping: connecting to peer_id={peer_info.peer_id} addrs={addrs_str}")
                self._host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 600)
                await self._host.connect(peer_info)
                print(f"[INFO][network] Connected to bootstrap peer {peer_info.peer_id}")
                self._save_peer_basic(peer_info)
                await self._send_local_subscriptions_to_peer(peer_info.peer_id)

                # Perform a best-effort handshake
                try:
                    hs_stream = await self._host.new_stream(peer_info.peer_id, [TAU_PROTOCOL_HANDSHAKE])
                    await hs_stream.write(b"hi")
                    hs_raw = await hs_stream.read()
                    await hs_stream.close()
                    try:
                        hs = json.loads(hs_raw.decode()) if hs_raw else {}
                    except Exception:
                        hs = {}
                    print(f"[INFO][network] Handshake from {peer_info.peer_id}: {json.dumps(hs) if hs else '{}'}")
                except Exception as e:
                    print(f"[WARN][network] Handshake to {peer_info.peer_id} failed: {e}")

                # Issue an initial SYNC request then ingest missing blocks
                try:
                    locator: List[str] = []
                    try:
                        if self._get_tip_number() > 0:
                            locator = [self._get_tip_hash()]
                    except Exception:
                        locator = []
                    added = await self._sync_and_ingest_from_peer(peer_info.peer_id, locator)
                    print(f"[INFO][network] SYNC from {peer_info.peer_id} added={added}")
                except Exception as e:
                    print(f"[WARN][network] SYNC to {peer_info.peer_id} failed: {e}")
            except Exception as e:
                print(f"[WARN][network] Bootstrap connect to {getattr(peer, 'peer_id', '<unknown>')} failed: {e}")
                continue

    async def start(self) -> None:
        if self._host is not None:
            return
        self._loop = asyncio.get_event_loop()
        self._host = new_host(listen_addrs=self._config.listen_addrs)
        self._register_handlers()
        self._restore_peerstore()
        try:
            addrs = [str(a) for a in (self._host.get_addrs() or [])]
        except Exception:
            addrs = []
        print(f"[INFO][network] Service started. NodeID={self._host.get_id()} listen_addrs={addrs}")
        bus.register(self)
        await self.join_gossip_topic(TAU_GOSSIP_TOPIC_TRANSACTIONS, self._handle_transaction_gossip)
        await self.join_gossip_topic(TAU_GOSSIP_TOPIC_BLOCKS, self._handle_block_gossip)
        # attempt bootstrap and head watcher in background
        self._tasks.append(asyncio.create_task(self._bootstrap()))
        self._tasks.append(asyncio.create_task(self._watch_head_and_announce()))
        self._tasks.append(asyncio.create_task(self._gossip_cleanup_loop()))

    async def stop(self) -> None:
        if self._host is None:
            return
        self._persist_peerstore()
        print(f"[INFO][network] Service stopping. NodeID={self._host.get_id()}")
        await self._host.close()
        self._host = None
        bus.unregister(self)
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
        self._loop = None
        self._gossip_peer_topics.clear()

    @property
    def host(self):
        return self._host
