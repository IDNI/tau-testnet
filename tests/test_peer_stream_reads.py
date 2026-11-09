"""Timeouts and multi-frame reads on handshake, ping and blocks handlers."""
from __future__ import annotations

import json

import db
import multiaddr
import pytest
import trio
from libp2p.network.stream.exceptions import StreamReset
from libp2p.stream_muxer.exceptions import MuxedStreamReset

from conftest import connect_peers, wait_for_addrs
from network.libp2p_compat import StreamReadTimeout, read_until_eof
from network.protocols import TAU_PROTOCOL_BLOCKS, TAU_PROTOCOL_HANDSHAKE, TAU_PROTOCOL_PING
from network.service import (
    BLOCKS_REQUEST_MAX_BYTES,
    HANDSHAKE_READ_TIMEOUT,
    SYNC_BLOCKS_REPLY_CAP,
    SYNC_REQUEST_EMPTY_TIMEOUT,
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


def _patch_chain_tip(monkeypatch, number: int, block_hash: str) -> None:
    tip = {"block_hash": block_hash, "header": {"block_number": number}}
    monkeypatch.setattr(db, "get_canonical_head_block", lambda: tip)


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


async def test_handshake_request_in_two_frames_is_read(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    bh = "h" * 64
    _patch_chain_tip(monkeypatch, 3, bh)
    payload = {
        "network_id": "testnet",
        "genesis_hash": svc2._genesis_hash,
        "padding": "p" * 50000,
    }
    body = json.dumps(payload).encode()
    mid = len(body) // 2
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    try:
        await stream.write(body[:mid])
        await stream.write(body[mid:])
        await stream.close_write()
        with trio.fail_after(HANDSHAKE_READ_TIMEOUT + 5):
            raw = await stream.read(65535)
        assert raw
        resp = json.loads(raw.decode())
        assert resp["head_number"] == 3
        assert resp["head_hash"] == bh
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


async def test_ping_silent_peer_times_out():
    from network.libp2p_compat import read_json_object
    from tests.test_read_json_object import FrameStream

    stream = FrameStream(b'{"nonce": 1', end="hang")
    with pytest.raises(StreamReadTimeout):
        await read_json_object(stream, 65535, read_timeout=0.3)


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


async def test_blocks_repeated_hashes_stay_under_reply_cap(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    bh = "c" * 64
    _patch_stored_block(monkeypatch, bh, 1, pad=16384)
    hashes = [bh] * 2000
    body = json.dumps({"type": "get_blocks", "hashes": hashes}).encode()
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    try:
        await stream.write(body)
        await stream.close_write()
        with trio.fail_after(10):
            raw = await read_until_eof(stream, SYNC_BLOCKS_REPLY_CAP, read_timeout=10)
        assert len(raw) < SYNC_BLOCKS_REPLY_CAP
        resp = json.loads(raw.decode())
        assert len(resp["blocks"]) < len(hashes)
        assert resp["blocks"][0]["block_hash"] == bh
    finally:
        await stream.close()


class _DelayedSyncStream:
    def __init__(self, payload: bytes):
        self._payload = payload
        self._sent = False
        self.written: list[bytes] = []

    async def read(self, n=None):
        if not self._sent:
            await trio.sleep(0.4)
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


async def test_sync_empty_timeout_is_ten_seconds():
    assert SYNC_REQUEST_EMPTY_TIMEOUT == 10.0


async def test_two_frame_handshake_fails_with_single_stream_read(
    monkeypatch, two_nodes
):
    async def one_read(stream, max_bytes, **kwargs):
        return await stream.read(max_bytes)

    monkeypatch.setattr("network.libp2p_compat.read_json_object", one_read)
    svc1, svc2 = two_nodes
    bh = "h" * 64
    _patch_chain_tip(monkeypatch, 3, bh)
    payload = {
        "network_id": "wrong-net",
        "genesis_hash": svc2._genesis_hash,
        "padding": "p" * 50000,
    }
    body = json.dumps(payload).encode()
    mid = len(body) // 2
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    try:
        await stream.write(body[:mid])
        await stream.write(body[mid:])
        await stream.close_write()
        with trio.fail_after(10):
            raw = await stream.read(65535)
        resp = json.loads(raw.decode())
        assert resp["network_id"] == "testnet"
    finally:
        await stream.close()


async def test_two_frame_blocks_fails_with_single_stream_read(
    monkeypatch, two_nodes
):
    async def one_read(stream, max_bytes, **kwargs):
        return await stream.read(max_bytes)

    monkeypatch.setattr("network.libp2p_compat.read_json_object", one_read)
    svc1, svc2 = two_nodes
    bh = "b" * 64
    _patch_stored_block(monkeypatch, bh, 1)
    req = {"type": "get_blocks", "hashes": [bh]}
    body = json.dumps(req).encode()
    mid = len(body) // 2
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    try:
        await stream.write(body[:mid])
        await stream.write(body[mid:])
        await stream.close_write()
        with trio.fail_after(10):
            raw = await stream.read(65535)
        resp = json.loads(raw.decode())
        assert resp.get("blocks") == []
    finally:
        await stream.close()
