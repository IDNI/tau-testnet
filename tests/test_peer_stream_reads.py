"""Timeouts and multi-frame reads on handshake, ping and blocks handlers."""
from __future__ import annotations

import json

import db
import multiaddr
import pytest
import trio

from conftest import connect_peers, wait_for_addrs
from network.libp2p_compat import StreamReadTimeout
from network.protocols import TAU_PROTOCOL_BLOCKS, TAU_PROTOCOL_HANDSHAKE, TAU_PROTOCOL_PING
from network.service import (
    BLOCKS_REQUEST_MAX_BYTES,
    SYNC_BLOCKS_REPLY_CAP,
    NetworkService,
)

pytestmark = [pytest.mark.trio, pytest.mark.usefixtures("isolate_db")]


@pytest.fixture
async def two_nodes():
    from network.config import NetworkConfig

    services = [
        NetworkService(
            NetworkConfig(
                network_id="testnet",
                listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
            ),
        )
        for _ in range(2)
    ]
    for svc in services:
        await svc.start()
        await wait_for_addrs(svc.host)
    try:
        await connect_peers(services[0].host, services[1].host)
        yield services[0], services[1]
    finally:
        for svc in services:
            await svc.stop()


def _patch_stored_block(monkeypatch, block_hash: str, number: int, *, pad: int = 0):
    blk = {
        "block_hash": block_hash,
        "header": {"block_number": number, "block_hash": block_hash},
        "padding": "x" * pad,
    }

    def lookup(h: str):
        return blk if h == block_hash else None

    monkeypatch.setattr(db, "get_block_by_hash", lookup)
    return blk


async def test_handshake_request_in_two_frames_is_read(two_nodes):
    svc1, svc2 = two_nodes
    payload = {
        "network_id": "testnet",
        "genesis_hash": "wrong-genesis",
        "padding": "p" * 50000,
    }
    body = json.dumps(payload).encode()
    mid = len(body) // 2
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    try:
        await stream.write(body[:mid])
        # The pause keeps the halves in separate reads of the server.
        await trio.sleep(0.2)
        await stream.write(body[mid:])
        await stream.close_write()
        with trio.fail_after(10):
            while str(svc1.host.get_id()) not in svc2._genesis_rejected_peers:
                await trio.sleep(0.05)
    finally:
        await stream.close()


async def test_handshake_client_times_out_on_silent_peer(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    monkeypatch.setattr("network.service.HANDSHAKE_READ_TIMEOUT", 0.3)

    async def hang(_stream) -> None:
        await trio.sleep_forever()

    svc2.host.set_stream_handler(TAU_PROTOCOL_HANDSHAKE, hang)
    with pytest.raises(StreamReadTimeout):
        await svc1._handshake_once(svc2.host.get_id())


async def test_handshake_server_resets_on_silent_peer(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    monkeypatch.setattr("network.service.HANDSHAKE_READ_TIMEOUT", 0.3)
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    try:
        with trio.fail_after(5):
            while not stream.muxed_stream.reset_received:
                await trio.sleep(0.05)
        assert stream.muxed_stream.reset_received
    finally:
        await stream.reset()


async def test_handshake_request_over_cap_is_reset_without_reply(two_nodes):
    svc1, svc2 = two_nodes
    body = json.dumps({"network_id": "testnet", "junk": "j" * 66000}).encode()
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    try:
        await stream.write(body)
        await stream.close_write()
        with trio.fail_after(5):
            while not stream.muxed_stream.reset_received:
                await trio.sleep(0.05)
        assert stream.muxed_stream.reset_received
    finally:
        await stream.reset()


async def test_ping_silent_peer_resets(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    monkeypatch.setattr("network.service.PING_READ_TIMEOUT", 0.3)
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_PING])
    try:
        with trio.fail_after(5):
            while not stream.muxed_stream.reset_received:
                await trio.sleep(0.05)
        assert stream.muxed_stream.reset_received
    finally:
        await stream.reset()


async def test_blocks_request_spans_two_frames(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    bh = "b" * 64
    _patch_stored_block(monkeypatch, bh, 1, pad=5000)
    req = {"type": "get_blocks", "hashes": [bh]}
    body = json.dumps(req).encode()
    mid = len(body) // 2
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    try:
        await stream.write(body[:mid])
        # The pause keeps the halves in separate reads of the server.
        await trio.sleep(0.2)
        await stream.write(body[mid:])
        await stream.close_write()
        with trio.fail_after(10):
            raw = await stream.read(65535)
        assert raw
        resp = json.loads(raw.decode())
        assert resp["blocks"][0]["block_hash"] == bh
    finally:
        await stream.close()


async def test_blocks_server_resets_on_silent_peer(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    monkeypatch.setattr("network.service.REQUEST_READ_TIMEOUT", 0.3)
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    try:
        with trio.fail_after(5):
            while not stream.muxed_stream.reset_received:
                await trio.sleep(0.05)
        assert stream.muxed_stream.reset_received
    finally:
        await stream.reset()


async def test_blocks_request_over_cap_is_reset_without_reply(two_nodes):
    svc1, svc2 = two_nodes
    body = json.dumps(
        {
            "type": "get_blocks",
            "hashes": ["h"],
            "pad": "p" * (BLOCKS_REQUEST_MAX_BYTES + 1000),
        }
    ).encode()
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    try:
        await stream.write(body)
        await stream.close_write()
        with trio.fail_after(5):
            while not stream.muxed_stream.reset_received:
                await trio.sleep(0.05)
            assert stream.muxed_stream.reset_received
    finally:
        await stream.reset()


class _DelayedSyncStream:
    def __init__(self, payload: bytes, delay: float = 0.4):
        self._payload = payload
        self._delay = delay
        self._sent = False
        self.written: list[bytes] = []

    async def read(self, n=None):
        if not self._sent:
            await trio.sleep(self._delay)
            self._sent = True
            return self._payload
        return b""

    async def write(self, data: bytes) -> None:
        self.written.append(data)

    async def close(self) -> None:
        pass


async def test_sync_late_request_still_honours_locator(two_nodes, monkeypatch):
    _, svc2 = two_nodes
    anchor = "d" * 64
    blocks = {
        anchor: {"block_hash": anchor, "header": {"block_number": 10}},
    }
    for n in range(11, 15):
        h = f"{n:064x}"
        blocks[h] = {"block_hash": h, "header": {"block_number": n}}

    def get_block(h: str):
        return blocks.get(h)

    def after_height(start: int):
        out = []
        n = start
        while n < 15:
            h = anchor if n == 10 else f"{n:064x}"
            out.append(blocks[h])
            n += 1
        return out

    monkeypatch.setattr(db, "get_block_by_hash", get_block)
    monkeypatch.setattr(db, "get_canonical_blocks_at_or_after_height", after_height)
    monkeypatch.setattr(db, "get_canonical_head", lambda: blocks[anchor])

    req = json.dumps(
        {"type": "get_headers", "locator": [anchor], "limit": 10}
    ).encode()
    stream = _DelayedSyncStream(req)
    await svc2._handle_sync(stream)
    resp = json.loads(stream.written[0].decode())
    nums = [int(h["block_number"]) for h in resp["headers"]]
    assert nums and nums[0] == 11


def _padded_block(number: int, pad: int) -> dict:
    h = f"{number:064x}"
    return {"block_hash": h, "header": {"block_number": number}, "padding": "x" * pad}


async def _blocks_reply(svc, req: dict) -> bytes:
    stream = _DelayedSyncStream(json.dumps(req).encode(), delay=0)
    await svc._handle_blocks(stream)
    return stream.written[0]


async def test_blocks_repeated_hashes_stay_under_reply_cap(two_nodes, monkeypatch):
    _, svc2 = two_nodes
    bh = "c" * 64
    _patch_stored_block(monkeypatch, bh, 1, pad=16384)
    raw = await _blocks_reply(svc2, {"type": "get_blocks", "hashes": [bh] * 3000})
    assert len(raw) <= SYNC_BLOCKS_REPLY_CAP
    blocks = json.loads(raw.decode())["blocks"]
    assert 0 < len(blocks) < 2000


@pytest.mark.parametrize(
    "request_fields", [{"from_number": 1}, {"from": "a" * 64}], ids=["number", "hash"]
)
async def test_blocks_range_reply_stays_under_reply_cap(
    two_nodes, monkeypatch, request_fields
):
    _, svc2 = two_nodes
    monkeypatch.setattr("network.service.SYNC_BLOCKS_REPLY_CAP", 10_000)
    chain = [_padded_block(n, 1000) for n in range(1, 41)]
    monkeypatch.setattr(db, "get_block_by_hash", lambda h: None)
    monkeypatch.setattr(db, "get_canonical_blocks_at_or_after_height", lambda n: chain)
    raw = await _blocks_reply(
        svc2, {"type": "get_blocks", "limit": 40, **request_fields}
    )
    assert len(raw) <= 10_000
    assert 0 < len(json.loads(raw.decode())["blocks"]) < 40


async def test_blocks_reply_size_count_matches_the_encoded_reply(two_nodes, monkeypatch):
    _, svc2 = two_nodes
    chain = [_padded_block(n, 100) for n in range(1, 5)]
    exact = len(json.dumps({"blocks": chain}).encode())
    monkeypatch.setattr("network.service.SYNC_BLOCKS_REPLY_CAP", exact - 1)
    monkeypatch.setattr(db, "get_block_by_hash", lambda h: None)
    monkeypatch.setattr(db, "get_canonical_blocks_at_or_after_height", lambda n: chain)
    raw = await _blocks_reply(svc2, {"type": "get_blocks", "from_number": 1, "limit": 4})
    assert len(raw) <= exact - 1
    assert len(json.loads(raw.decode())["blocks"]) == 3


async def test_blocks_single_block_over_cap_stays_in_reply(two_nodes, monkeypatch):
    _, svc2 = two_nodes
    bh = "e" * 64
    _patch_stored_block(monkeypatch, bh, 1, pad=5000)
    monkeypatch.setattr("network.service.SYNC_BLOCKS_REPLY_CAP", 1000)
    raw = await _blocks_reply(svc2, {"type": "get_blocks", "hashes": [bh, bh]})
    assert [b["block_hash"] for b in json.loads(raw.decode())["blocks"]] == [bh]
