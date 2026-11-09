"""Timeouts and multi-frame reads on handshake, ping and blocks handlers."""
from __future__ import annotations

import json

import multiaddr
import pytest
import trio

from conftest import connect_peers, wait_for_addrs
from network.libp2p_compat import StreamReadTimeout
from network.protocols import TAU_PROTOCOL_BLOCKS, TAU_PROTOCOL_HANDSHAKE, TAU_PROTOCOL_PING
from network.service import HANDSHAKE_READ_TIMEOUT, PING_READ_TIMEOUT, NetworkService

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


async def test_handshake_request_in_two_frames_is_read(two_nodes):
    svc1, svc2 = two_nodes
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
        with trio.fail_after(10):
            raw = await stream.read(65535)
        assert raw
        resp = json.loads(raw.decode())
        assert resp["network_id"] == "testnet"
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


async def test_ping_silent_peer_times_out():
    from network.libp2p_compat import read_json_object
    from tests.test_read_json_object import FrameStream

    stream = FrameStream(b'{"nonce": 1', end="hang")
    with pytest.raises(StreamReadTimeout):
        await read_json_object(stream, 65535, read_timeout=0.3)


async def test_blocks_request_spans_two_frames(two_nodes):
    svc1, svc2 = two_nodes
    req = {"block_hashes": ["abc" * 20] * 200}
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
        assert "blocks" in resp
    finally:
        await stream.close()
