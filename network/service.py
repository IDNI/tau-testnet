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

    def _build_handshake(self) -> bytes:
        payload = {
            "network_id": self._config.network_id,
            "node_id": self._host.get_id() if self._host else "",
            "agent": self._config.agent,
            "genesis_hash": self._config.genesis_hash,
            "head_number": 0,
            "head_hash": self._config.genesis_hash,
            "time": asyncio.get_event_loop().time(),
        }
        return json.dumps(payload).encode()

    async def _handle_handshake(self, stream) -> None:
        _ = await stream.read()
        # Respond with our handshake
        await stream.write(self._build_handshake())
        await stream.close()

    async def _handle_ping(self, stream) -> None:
        raw = await stream.read()
        try:
            data = json.loads(raw.decode())
            pong = {"nonce": data.get("nonce"), "time": asyncio.get_event_loop().time()}
        except Exception:
            pong = {"nonce": None, "time": asyncio.get_event_loop().time()}
        await stream.write(json.dumps(pong).encode())
        await stream.close()

    async def _handle_sync(self, stream) -> None:
        # Accept GetHeaders and respond with empty headers for now
        _ = await stream.read()
        response = {"headers": [], "tip_number": 0, "tip_hash": self._config.genesis_hash}
        await stream.write(json.dumps(response).encode())
        await stream.close()

    async def _handle_blocks(self, stream) -> None:
        # Accept GetBlocks and respond with empty blocks for now
        _ = await stream.read()
        response = {"blocks": []}
        await stream.write(json.dumps(response).encode())
        await stream.close()

    async def _handle_tx(self, stream) -> None:
        # Accept SubmitTx and respond ok for now
        _ = await stream.read()
        response = {"ok": True}
        await stream.write(json.dumps(response).encode())
        await stream.close()

    def _register_handlers(self) -> None:
        self._host.set_stream_handler(TAU_PROTOCOL_HANDSHAKE, self._handle_handshake)
        self._host.set_stream_handler(TAU_PROTOCOL_PING, self._handle_ping)
        self._host.set_stream_handler(TAU_PROTOCOL_SYNC, self._handle_sync)
        self._host.set_stream_handler(TAU_PROTOCOL_BLOCKS, self._handle_blocks)
        self._host.set_stream_handler(TAU_PROTOCOL_TX, self._handle_tx)

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
                self._host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 600)
                await self._host.connect(peer_info)
                self._save_peer_basic(peer_info)
            except Exception:
                continue

    async def start(self) -> None:
        if self._host is not None:
            return
        self._host = new_host(listen_addrs=self._config.listen_addrs)
        self._register_handlers()
        self._restore_peerstore()
        # attempt bootstrap in background
        self._tasks.append(asyncio.create_task(self._bootstrap()))

    async def stop(self) -> None:
        if self._host is None:
            return
        self._persist_peerstore()
        await self._host.close()
        self._host = None
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()

    @property
    def host(self):
        return self._host


