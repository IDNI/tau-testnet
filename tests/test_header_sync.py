"""Header-sync transport and policy: read-to-EOF, paging, in-flight guard, genesis denylist."""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import trio

from network import service as service_mod
from network.config import NetworkConfig
from network.libp2p_compat import (
    StreamReadTimeout,
    StreamTooLarge,
    read_until_eof,
    reset_stream_on_error,
)
from network.service import NetworkService

pytestmark = pytest.mark.trio

FRAME = 64 * 1024


class ChunkedStream:
    """Delivers `payload` one frame at a time, then signals EOF the given way."""

    def __init__(self, payload: bytes, eof: str = "empty", frame: int = FRAME):
        self._buf = payload
        self._eof = eof
        self._frame = frame
        self.read_sizes: List[int] = []

    async def read(self, n: Optional[int] = None):
        self.read_sizes.append(-1 if n is None else n)
        if not self._buf:
            if self._eof == "raise":
                raise EOFError()
            if self._eof == "none":
                return None
            return b""
        take = min(self._frame, n if n is not None else self._frame)
        out, self._buf = self._buf[:take], self._buf[take:]
        return out


# --------------------------------------------------------------------------
# read_until_eof
# --------------------------------------------------------------------------


@pytest.mark.parametrize("eof", ["empty", "raise", "none"])
async def test_read_until_eof_collects_every_frame(eof):
    payload = bytes(range(256)) * 800  # ~200 KB, several frames
    stream = ChunkedStream(payload, eof=eof)
    assert await read_until_eof(stream, 2 * 1024 * 1024) == payload
    assert len(stream.read_sizes) > 3


async def test_read_until_eof_empty_stream():
    assert await read_until_eof(ChunkedStream(b""), 1024) == b""


async def test_read_until_eof_accepts_exactly_the_cap():
    payload = b"x" * 1000
    assert await read_until_eof(ChunkedStream(payload, frame=300), 1000) == payload


async def test_read_until_eof_raises_over_cap():
    with pytest.raises(StreamTooLarge):
        await read_until_eof(ChunkedStream(b"x" * 1001, frame=300), 1000)


async def test_read_until_eof_propagates_other_errors():
    class Resetting:
        async def read(self, n=None):
            raise ConnectionResetError("reset")

    with pytest.raises(ConnectionResetError):
        await read_until_eof(Resetting(), 1024)


async def test_read_until_eof_raises_when_mplex_reports_reset_as_eof():
    from libp2p.network.stream.exceptions import StreamReset

    stream = ChunkedStream(b"x" * 1000, eof="raise", frame=300)
    stream.muxed_stream = MagicMock(spec=["event_reset"])
    stream.muxed_stream.event_reset = trio.Event()
    stream.muxed_stream.event_reset.set()
    with pytest.raises(StreamReset):
        await read_until_eof(stream, 4096)


async def test_read_until_eof_ignores_reset_attributes_of_a_mock():
    stream = ChunkedStream(b"x" * 1000, eof="raise", frame=300)
    stream.muxed_stream = MagicMock()
    assert await read_until_eof(stream, 4096) == b"x" * 1000


async def test_read_until_eof_times_out_when_peer_never_closes():
    class Hanging:
        async def read(self, n=None):
            await trio.sleep_forever()

    with pytest.raises(StreamReadTimeout):
        await read_until_eof(Hanging(), 1024, read_timeout=0.05)


# --------------------------------------------------------------------------
# reset_stream_on_error
# --------------------------------------------------------------------------


class RecordingStream:
    def __init__(self):
        self.resets = 0

    async def reset(self):
        await trio.sleep(0)
        self.resets += 1


async def test_reset_stream_on_error_resets_and_reraises():
    stream = RecordingStream()
    with pytest.raises(StreamTooLarge):
        async with reset_stream_on_error(stream):
            raise StreamTooLarge("too big")
    assert stream.resets == 1


async def test_reset_stream_on_error_resets_when_cancelled():
    stream = RecordingStream()
    with trio.move_on_after(0.01):
        async with reset_stream_on_error(stream):
            await trio.sleep_forever()
    assert stream.resets == 1


async def test_reset_stream_on_error_keeps_stream_on_success():
    stream = RecordingStream()
    async with reset_stream_on_error(stream):
        pass
    assert stream.resets == 0


# --------------------------------------------------------------------------
# Service fixture
# --------------------------------------------------------------------------


@pytest.fixture
def service():
    cfg = MagicMock(spec=NetworkConfig)
    cfg.network_id = "test-net"
    cfg.agent = "test-agent"
    cfg.genesis_hash = "genesis_local"
    cfg.bootstrap_peers = []
    cfg.dht_bootstrap_peers = []
    cfg.peer_advertisement_interval = 0
    cfg.MINER_PUBKEY = ""
    with patch("network.service.HostManager") as MockHostManager, \
         patch("network.service.DHTManager"), \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager"):
        host = MagicMock()
        host.get_id.return_value = "local_peer"
        host.disconnect = AsyncMock()
        MockHostManager.return_value.host = host
        svc = NetworkService(cfg)
        svc.get_id = MagicMock(return_value="local_peer")
        svc._ensure_peer_route = AsyncMock()
        svc._ensure_peer_id = lambda p: p
        return svc


# --------------------------------------------------------------------------
# Paging
# --------------------------------------------------------------------------


class FakeChain:
    """Remote chain of `total` blocks h0..h{total-1} plus the local view of it."""

    def __init__(self, total: int, *, advance: bool = True):
        self.total = total
        self.advance = advance
        self.local: Dict[str, int] = {}
        self.head = -1
        self.header_requests: List[Dict[str, Any]] = []
        self.block_requests = 0
        self.gate: Optional[trio.Event] = None
        self.entered = trio.Event()

    def locator(self) -> List[str]:
        return [f"h{self.head}" if self.head >= 0 else "genesis_local"]

    def get_block_by_hash(self, h: str):
        return {"block_hash": h} if h in self.local else None

    def ingest(self, blocks, peer_id) -> int:
        for b in blocks:
            self.local[b["block_hash"]] = b["header"]["block_number"]
        if self.advance and blocks:
            self.head = max(self.head, max(b["header"]["block_number"] for b in blocks))
        return len(blocks)

    def _respond(self, req: Dict[str, Any]) -> bytes:
        if req["type"] == "get_headers":
            self.header_requests.append(req)
            first = req["locator"][0]
            start = int(first[1:]) + 1 if first.startswith("h") else 0
            out = []
            for i in range(start, self.total):
                out.append({"block_number": i, "block_hash": f"h{i}"})
                if req.get("stop") == f"h{i}" or len(out) >= req["limit"]:
                    break
            return json.dumps({"headers": out}).encode()
        self.block_requests += 1
        blocks = [
            {"block_hash": h, "header": {"block_number": int(h[1:])}} for h in req["hashes"]
        ]
        return json.dumps({"blocks": blocks}).encode()

    async def new_stream(self, peer_id, protocols):
        if self.gate is not None:
            self.entered.set()
            await self.gate.wait()
        chain = self

        class _S:
            payload = b""

            async def write(self, data):
                self.payload = chain._respond(json.loads(data.decode()))

            async def read(self, n=None):
                take = min(FRAME, n or FRAME)
                out, self.payload = self.payload[:take], self.payload[take:]
                if not out:
                    raise EOFError()
                return out

            async def close(self):
                pass

        return _S()


def _wire(service, chain: FakeChain, monkeypatch):
    import db

    service.host.new_stream = chain.new_stream
    service._build_block_locator = chain.locator
    service._ingest_blocks = chain.ingest
    monkeypatch.setattr(db, "get_block_by_hash", chain.get_block_by_hash)


async def test_sync_pages_until_caught_up(service, monkeypatch):
    chain = FakeChain(5000)
    _wire(service, chain, monkeypatch)
    total = await service._sync_and_ingest_from_peer("peerA", chain.locator())
    assert total == 5000
    assert len(chain.header_requests) == 3
    assert [r["locator"][0] for r in chain.header_requests] == ["genesis_local", "h1999", "h3999"]
    assert chain.head == 4999
    assert not service._syncing_peers


async def test_sync_stops_when_head_does_not_advance(service, monkeypatch):
    chain = FakeChain(5000, advance=False)
    _wire(service, chain, monkeypatch)
    total = await service._sync_and_ingest_from_peer("peerA", chain.locator())
    assert total == 2000
    assert len(chain.header_requests) == 1


async def test_sync_stops_when_stop_hash_in_page(service, monkeypatch):
    chain = FakeChain(5000)
    _wire(service, chain, monkeypatch)
    total = await service._sync_and_ingest_from_peer("peerA", chain.locator(), stop="h1999")
    assert total == 2000
    assert len(chain.header_requests) == 1


async def test_sync_respects_page_cap(service, monkeypatch):
    chain = FakeChain(service_mod.MAX_SYNC_PAGES + 10)
    _wire(service, chain, monkeypatch)
    total = await service._sync_and_ingest_from_peer("peerA", chain.locator(), limit=1)
    assert len(chain.header_requests) == service_mod.MAX_SYNC_PAGES
    assert total == service_mod.MAX_SYNC_PAGES


async def test_sync_for_same_peer_is_not_reentrant(service, monkeypatch):
    chain = FakeChain(10)
    chain.gate = trio.Event()
    _wire(service, chain, monkeypatch)
    results: Dict[str, int] = {}

    async def first():
        results["first"] = await service._sync_and_ingest_from_peer("peerA", chain.locator())

    async with trio.open_nursery() as nursery:
        nursery.start_soon(first)
        await chain.entered.wait()
        results["second"] = await service._sync_and_ingest_from_peer("peerA", chain.locator())
        assert chain.header_requests == []
        chain.gate.set()

    assert results["second"] == 0
    assert results["first"] == 10
    assert not service._syncing_peers


async def test_sync_guard_released_after_failure(service, monkeypatch):
    chain = FakeChain(10)
    _wire(service, chain, monkeypatch)

    async def boom(*a, **k):
        raise RuntimeError("dial failed")

    service.host.new_stream = boom
    assert await service._sync_and_ingest_from_peer("peerA", chain.locator()) == 0
    assert not service._syncing_peers


MiB = 1024 * 1024


class LargeBlockChain(FakeChain):
    """FakeChain whose block `i` carries `sizes[i]` bytes of transaction data."""

    def __init__(self, sizes: List[int]):
        super().__init__(len(sizes))
        self.sizes = sizes
        self.block_request_sizes: List[int] = []

    def _respond(self, req: Dict[str, Any]) -> bytes:
        if req["type"] == "get_headers":
            return super()._respond(req)
        self.block_requests += 1
        self.block_request_sizes.append(len(req["hashes"]))
        blocks = [
            {
                "block_hash": h,
                "header": {"block_number": int(h[1:])},
                "transactions": ["x" * self.sizes[int(h[1:])]],
            }
            for h in req["hashes"]
        ]
        return json.dumps({"blocks": blocks}).encode()

    async def new_stream(self, peer_id, protocols):
        chain = self

        class _S:
            payload = b""
            offset = 0

            async def write(self, data):
                self.payload = chain._respond(json.loads(data.decode()))

            async def read(self, n=None):
                take = min(FRAME, n or FRAME)
                out = self.payload[self.offset : self.offset + take]
                self.offset += len(out)
                if not out:
                    raise EOFError()
                return out

            async def close(self):
                pass

            async def reset(self):
                pass

        return _S()


async def test_fetch_block_chunk_refetches_after_a_short_reply(service, monkeypatch):
    from network.protocols import TAU_PROTOCOL_BLOCKS

    opens: List[int] = []

    class ShortReplyStream:
        def __init__(self):
            self.payload = b""
            self.offset = 0

        async def write(self, data):
            req = json.loads(data.decode())
            hashes = req["hashes"]
            blocks = [
                {"block_hash": h, "header": {"block_number": i}}
                for i, h in enumerate(hashes)
            ]
            short = blocks[:2] if len(blocks) > 2 else blocks
            self.payload = json.dumps({"blocks": short}).encode()
            self.offset = 0

        async def read(self, n=None):
            take = min(FRAME, n or FRAME)
            out = self.payload[self.offset : self.offset + take]
            self.offset += len(out)
            if not out:
                raise EOFError()
            return out

        async def close(self):
            pass

        async def reset(self):
            pass

    async def new_stream(peer_id, protocols):
        assert TAU_PROTOCOL_BLOCKS in protocols
        opens.append(1)
        return ShortReplyStream()

    service.host.new_stream = new_stream
    hashes = [f"h{i}" for i in range(6)]
    got = await service._fetch_block_chunk("peerA", hashes)
    assert len(got) == 6
    assert len(opens) == 3


async def test_sync_splits_a_block_chunk_over_the_reply_cap(service, monkeypatch):
    chain = LargeBlockChain([MiB] * 30)
    _wire(service, chain, monkeypatch)
    total = await service._sync_and_ingest_from_peer("peerA", chain.locator())
    assert total == 30
    assert chain.head == 29
    assert chain.block_request_sizes == [30, 15, 15]


async def test_sync_ingests_up_to_a_single_block_over_the_reply_cap(service, monkeypatch, caplog):
    chain = LargeBlockChain([1024, 1024, 1024, 21 * MiB, 1024, 1024])
    _wire(service, chain, monkeypatch)
    with caplog.at_level("ERROR"):
        total = await service._sync_and_ingest_from_peer("peerA", chain.locator())
    assert total == 3
    assert chain.head == 2
    assert chain.block_request_sizes == [6, 3, 3, 1]
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 1
    assert "h3" in errors[0] and "reply cap" in errors[0]


class SyncStream:
    """One sync stream that replies with `reply` and records how it ends."""

    def __init__(self, reply: bytes, *, hang: bool = False, close_error: bool = False):
        self.reply = reply
        self.hang = hang
        self.close_error = close_error
        self.closed = 0
        self.resets = 0

    async def write(self, data):
        pass

    async def read(self, n=None):
        if self.hang:
            await trio.sleep_forever()
        take = min(FRAME, n or FRAME)
        out, self.reply = self.reply[:take], self.reply[take:]
        if not out:
            raise EOFError()
        return out

    async def close(self):
        self.closed += 1
        if self.close_error:
            raise RuntimeError("close failed")

    async def reset(self):
        self.resets += 1


def _wire_sync_streams(service, streams: List[SyncStream], monkeypatch):
    import db

    pending = list(streams)

    async def new_stream(peer_id, protocols):
        return pending.pop(0)

    service.host.new_stream = new_stream
    service._ingest_blocks = lambda blocks, peer_id: len(blocks)
    monkeypatch.setattr(db, "get_block_by_hash", lambda h: None)


def _headers_reply(count: int) -> bytes:
    headers = [{"block_number": i, "block_hash": f"h{i}"} for i in range(count)]
    return json.dumps({"headers": headers}).encode()


def _blocks_reply(count: int) -> bytes:
    blocks = [{"block_hash": f"h{i}", "header": {"block_number": i}} for i in range(count)]
    return json.dumps({"blocks": blocks}).encode()


async def test_sync_resets_header_stream_over_cap(service, monkeypatch):
    stream = SyncStream(b"x" * (2 * 1024 * 1024 + 1))
    _wire_sync_streams(service, [stream], monkeypatch)
    assert await service._sync_and_ingest_from_peer("peerA", ["genesis_local"]) == 0
    assert stream.resets == 1
    assert stream.closed == 0


async def test_sync_resets_block_stream_when_peer_never_closes(service, monkeypatch):
    monkeypatch.setattr(service_mod, "SYNC_READ_TIMEOUT", 0.05)
    headers = SyncStream(_headers_reply(3))
    blocks = SyncStream(b"", hang=True)
    _wire_sync_streams(service, [headers, blocks], monkeypatch)
    assert await service._sync_and_ingest_from_peer("peerA", ["genesis_local"], limit=10) == 0
    assert headers.closed == 1 and headers.resets == 0
    assert blocks.resets == 1 and blocks.closed == 0


async def test_sync_keeps_reply_when_close_fails(service, monkeypatch):
    headers = SyncStream(_headers_reply(3), close_error=True)
    blocks = SyncStream(_blocks_reply(3), close_error=True)
    _wire_sync_streams(service, [headers, blocks], monkeypatch)
    assert await service._sync_and_ingest_from_peer("peerA", ["genesis_local"], limit=10) == 3
    assert headers.resets == 0 and blocks.resets == 0


# --------------------------------------------------------------------------
# Genesis denylist
# --------------------------------------------------------------------------


_HS_MODULES = {
    "db": MagicMock(),
    "multiaddr": MagicMock(),
    "libp2p.peer.id": MagicMock(),
    "libp2p.peer.peerinfo": MagicMock(),
}


def _wire_outbound(service, resp: Dict[str, Any]):
    stream = ChunkedStream(json.dumps(resp).encode(), eof="raise")
    stream.write = AsyncMock()
    stream.close = AsyncMock()
    service.host.new_stream = AsyncMock(return_value=stream)
    service._build_handshake_payload = lambda: {"network_id": "test-net"}


def _inbound_stream(payload: Dict[str, Any], peer: str):
    stream = MagicMock()
    stream.read = AsyncMock(return_value=json.dumps(payload).encode())
    stream.write = AsyncMock()
    stream.close = AsyncMock()
    stream.muxed_conn.peer_id = peer
    return stream


async def test_outbound_genesis_mismatch_denylists_peer(service):
    _wire_outbound(service, {"network_id": "test-net", "genesis_hash": "other"})
    await service._handshake_once("peerA")
    assert "peerA" in service._genesis_rejected_peers
    service.host.disconnect.assert_awaited_once()


async def test_inbound_genesis_mismatch_denylists_peer(service):
    stream = _inbound_stream({"network_id": "test-net", "genesis_hash": ""}, "peerB")
    with patch.dict(sys.modules, _HS_MODULES):
        await service._handle_handshake(stream)
    assert "peerB" in service._genesis_rejected_peers
    stream.write.assert_not_called()


async def test_passing_handshake_clears_denylist_both_directions(service):
    service._mark_genesis_rejected("peerA")
    service._mark_genesis_rejected("peerB")

    _wire_outbound(service, {"network_id": "test-net", "genesis_hash": "genesis_local"})
    await service._handshake_once("peerA")
    assert "peerA" not in service._genesis_rejected_peers

    stream = _inbound_stream({"network_id": "test-net", "genesis_hash": "genesis_local"}, "peerB")
    with patch.dict(sys.modules, _HS_MODULES):
        await service._handle_handshake(stream)
    assert "peerB" not in service._genesis_rejected_peers


async def test_denylisted_peer_gossip_opens_no_sync_stream(service, monkeypatch):
    import db

    monkeypatch.setattr(db, "get_block_by_hash", lambda h: None)
    service._build_block_locator = lambda: ["genesis_local"]
    service.host.new_stream = AsyncMock()
    service._mark_genesis_rejected("peerA")

    await service._handle_block_gossip(
        {"via": "peerA", "payload": {"tip_hash": "a" * 64, "headers": []}}
    )
    service.host.new_stream.assert_not_called()


async def test_denylist_survives_disconnect(service):
    service._mark_genesis_rejected("peerA")
    conn = MagicMock()
    conn.muxed_conn.peer_id = "peerA"
    await service._on_peer_disconnected(conn)
    assert "peerA" in service._genesis_rejected_peers


async def test_denylist_is_bounded_and_evicts_oldest(service):
    cap = service_mod.MAX_GENESIS_REJECTED_PEERS
    for i in range(cap + 5):
        service._mark_genesis_rejected(f"p{i}")
    assert len(service._genesis_rejected_peers) == cap
    assert "p0" not in service._genesis_rejected_peers
    assert f"p{cap + 4}" in service._genesis_rejected_peers
