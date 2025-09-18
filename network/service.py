from __future__ import annotations

import asyncio
import json
import os
from typing import Dict, List, Optional

import multiaddr

from libp2p import new_host
from libp2p.peer.peerinfo import PeerInfo

from .config import NetworkConfig, BootstrapPeer
import db
from .protocols import (
	TAU_PROTOCOL_HANDSHAKE,
	TAU_PROTOCOL_PING,
	TAU_PROTOCOL_SYNC,
	TAU_PROTOCOL_ANNOUNCE,
	TAU_PROTOCOL_BLOCKS,
	TAU_PROTOCOL_TX,
)


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
    def __init__(self, config: NetworkConfig) -> None:
        self._config = config
        self._host = None
        self._tasks: List[asyncio.Task] = []
        self._peerstore_persist = PeerstorePersistence(config.peerstore_path)
        self._last_announced_tip: Optional[str] = None

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

    async def _handle_tx(self, stream) -> None:
        # Accept SubmitTx and respond ok for now
        raw = await stream.read()
        print(f"[DEBUG][network] <- TX raw='{raw.decode(errors='ignore') if raw else ''}'")
        response = {"ok": True}
        out = json.dumps(response).encode()
        await stream.write(out)
        print(f"[DEBUG][network] -> TX response: {json.dumps(response)}")
        await stream.close()

    async def _handle_announce(self, stream) -> None:
        # Accept block/header announcements and trigger sync from announcer
        raw = await stream.read()
        print(f"[DEBUG][network] <- ANNOUNCE raw='{raw.decode(errors='ignore') if raw else ''}'")
        announcer_id = None
        addrs = []
        try:
            data = json.loads(raw.decode()) if raw else {}
        except Exception:
            data = {}
        if isinstance(data, dict):
            announcer_id = data.get("from_id")
            addrs = data.get("from_addrs") or []
        # Record announcer addrs if provided
        if announcer_id and addrs:
            try:
                self._host.get_peerstore().add_addrs(announcer_id, [multiaddr.Multiaddr(a) for a in addrs], 600)
            except Exception:
                pass
        # Respond ack
        try:
            await stream.write(json.dumps({"ok": True}).encode())
        except Exception:
            pass
        await stream.close()

        # Kick off a targeted sync from announcer
        if announcer_id:
            try:
                # Ensure connection
                pi = PeerInfo(announcer_id, [multiaddr.Multiaddr(a) for a in addrs] if addrs else [])
                self._host.get_peerstore().add_addrs(pi.peer_id, pi.addrs, 600)
                try:
                    await self._host.connect(pi)
                except Exception:
                    pass
                locator = []
                try:
                    if self._get_tip_hash():
                        locator = [self._get_tip_hash()]
                except Exception:
                    locator = []
                added = await self._sync_and_ingest_from_peer(announcer_id, locator)
                print(f"[INFO][network] ANNOUNCE-driven sync from {announcer_id}: added={added}")
            except Exception:
                pass

    def _register_handlers(self) -> None:
        self._host.set_stream_handler(TAU_PROTOCOL_HANDSHAKE, self._handle_handshake)
        self._host.set_stream_handler(TAU_PROTOCOL_PING, self._handle_ping)
        self._host.set_stream_handler(TAU_PROTOCOL_SYNC, self._handle_sync)
        self._host.set_stream_handler(TAU_PROTOCOL_ANNOUNCE, self._handle_announce)
        self._host.set_stream_handler(TAU_PROTOCOL_BLOCKS, self._handle_blocks)
        self._host.set_stream_handler(TAU_PROTOCOL_TX, self._handle_tx)

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
                    payload = {
                        "type": "new_headers",
                        "from_id": self._host.get_id(),
                        "from_addrs": addrs,
                        "headers": [hdr],
                        "tip_number": tip_num,
                        "tip_hash": tip_hash,
                    }
                    # Broadcast to configured bootstrap peers for now
                    for p in self._config.bootstrap_peers:
                        try:
                            pi = PeerInfo(p.peer_id, p.addrs)
                            self._host.get_peerstore().add_addrs(pi.peer_id, pi.addrs, 600)
                            try:
                                await self._host.connect(pi)
                            except Exception:
                                pass
                            st = await self._host.new_stream(pi.peer_id, [TAU_PROTOCOL_ANNOUNCE])
                            await st.write(json.dumps(payload).encode())
                            await st.read()
                            await st.close()
                        except Exception:
                            continue
                    self._last_announced_tip = tip_hash
            except asyncio.CancelledError:
                break
            except Exception:
                pass
            await asyncio.sleep(1.0)

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
        self._host = new_host(listen_addrs=self._config.listen_addrs)
        self._register_handlers()
        self._restore_peerstore()
        try:
            addrs = [str(a) for a in (self._host.get_addrs() or [])]
        except Exception:
            addrs = []
        print(f"[INFO][network] Service started. NodeID={self._host.get_id()} listen_addrs={addrs}")
        # attempt bootstrap and head watcher in background
        self._tasks.append(asyncio.create_task(self._bootstrap()))
        self._tasks.append(asyncio.create_task(self._watch_head_and_announce()))

    async def stop(self) -> None:
        if self._host is None:
            return
        self._persist_peerstore()
        print(f"[INFO][network] Service stopping. NodeID={self._host.get_id()}")
        await self._host.close()
        self._host = None
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()

    @property
    def host(self):
        return self._host
