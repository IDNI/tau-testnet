"""Requests over one 64 KiB stream frame on the tx and gossip protocols."""
from __future__ import annotations

import json
from typing import Any, Dict, List

import multiaddr
import pytest
import trio

from conftest import connect_peers, wait_for_addrs
from network.libp2p_compat import read_until_eof, reset_stream_safely

pytestmark = [pytest.mark.trio, pytest.mark.usefixtures("isolate_db")]

SIZES = [pytest.param(1024, id="1k"), pytest.param(100 * 1024, id="100k")]


@pytest.fixture
async def two_nodes():
    from network.config import NetworkConfig
    from network.service import NetworkService

    submissions: List[str] = []

    def submit(payload: str) -> str:
        submissions.append(payload)
        return "queued"

    services = [
        NetworkService(
            NetworkConfig(
                network_id="testnet",
                listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
            ),
            tx_submitter=submit,
        )
        for _ in range(2)
    ]
    for svc in services:
        await svc.start()
        await wait_for_addrs(svc.host)
    try:
        await connect_peers(services[0].host, services[1].host)
        yield services[0], services[1], submissions
    finally:
        for svc in services:
            await svc.stop()


@pytest.mark.parametrize("size", SIZES)
async def test_tx_request_is_received(two_nodes, size):
    from network.protocols import TAU_PROTOCOL_TX

    svc1, svc2, submissions = two_nodes
    tx = "x" * size
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    try:
        await stream.write(json.dumps({"tx": tx}).encode())
        await stream.close()
        raw = await read_until_eof(stream, 65535, read_timeout=10)
    finally:
        await stream.reset()
    assert json.loads(raw.decode()) == {"ok": True, "result": "queued"}
    assert submissions == [tx]


@pytest.mark.parametrize("size", SIZES)
async def test_gossip_message_is_received(two_nodes, size):
    svc1, svc2, _ = two_nodes
    topic = "tau/test-large/1.0.0"
    received: List[Dict[str, Any]] = []
    arrived = trio.Event()

    async def on_message(envelope: Dict[str, Any]) -> None:
        received.append(envelope)
        arrived.set()

    await svc2._gossip_manager.join_topic(topic, on_message)
    blob = "g" * size
    await svc1.publish_gossip(topic, {"blob": blob}, message_id="large-1")
    with trio.move_on_after(5):
        await arrived.wait()
    assert [m["payload"]["blob"] for m in received] == [blob]


@pytest.mark.parametrize("size", SIZES)
async def test_old_tx_sender_without_half_close_gets_the_ack(two_nodes, size):
    from network.protocols import TAU_PROTOCOL_TX

    svc1, svc2, submissions = two_nodes
    tx = "o" * size
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    try:
        await stream.write(json.dumps({"tx": tx}).encode())
        with trio.fail_after(10):
            raw = await read_until_eof(stream, 65535)
    finally:
        await reset_stream_safely(stream)
    assert json.loads(raw.decode()) == {"ok": True, "result": "queued"}
    assert submissions == [tx]


@pytest.mark.parametrize("size", SIZES)
async def test_old_gossip_sender_without_half_close_gets_the_ack(two_nodes, size):
    from network.protocols import TAU_PROTOCOL_GOSSIP

    svc1, svc2, _ = two_nodes
    message = {"topic": "tau/test-old/1.0.0", "message_id": f"old-{size}", "payload": "p" * size}
    request = {"peer_id": str(svc1.host.get_id()), "rpc": {"messages": [message]}}
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_GOSSIP])
    try:
        await stream.write(json.dumps(request).encode())
        with trio.fail_after(10):
            raw = await read_until_eof(stream, 65535)
    finally:
        await reset_stream_safely(stream)
    assert json.loads(raw.decode()) == {
        "ok": True,
        "messages": [{"message_id": f"old-{size}", "duplicate": False}],
    }


async def test_tx_request_in_many_small_writes_is_received(two_nodes):
    from network.protocols import TAU_PROTOCOL_TX

    svc1, svc2, submissions = two_nodes
    tx = 'a"b\\c{d}' * 2000
    body = json.dumps({"tx": tx}).encode()
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    try:
        for i in range(0, len(body), 97):
            await stream.write(body[i : i + 97])
        with trio.fail_after(10):
            raw = await read_until_eof(stream, 65535)
    finally:
        await reset_stream_safely(stream)
    assert json.loads(raw.decode())["ok"] is True
    assert submissions == [tx]


async def test_tx_request_over_the_cap_is_refused(two_nodes):
    from network.protocols import TAU_PROTOCOL_TX, TAU_STREAM_REQUEST_MAX_BYTES

    svc1, svc2, submissions = two_nodes
    body = json.dumps({"tx": "c" * TAU_STREAM_REQUEST_MAX_BYTES}).encode()
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    with trio.fail_after(10):
        try:
            await stream.write(body)
            raw = await read_until_eof(stream, 65535)
        except Exception:
            raw = b""
        finally:
            await reset_stream_safely(stream)
    assert raw == b""
    assert submissions == []


async def test_tx_request_that_never_ends_times_out(two_nodes, monkeypatch):
    import network.service as service_mod
    from network.protocols import TAU_PROTOCOL_TX

    monkeypatch.setattr(service_mod, "REQUEST_READ_TIMEOUT", 0.5)
    svc1, svc2, submissions = two_nodes
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    try:
        await stream.write(b'{"tx": "never ends')
        with trio.fail_after(5):
            try:
                raw = await read_until_eof(stream, 65535)
            except Exception:
                raw = b""
    finally:
        await reset_stream_safely(stream)
    assert raw == b""
    assert submissions == []


async def test_tx_request_reset_in_the_middle_is_dropped(two_nodes):
    from network.protocols import TAU_PROTOCOL_TX

    svc1, svc2, submissions = two_nodes
    body = json.dumps({"tx": "r" * (100 * 1024)}).encode()
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    await stream.write(body[: len(body) // 2])
    await trio.sleep(0.3)
    await stream.reset()
    await trio.sleep(0.3)
    assert submissions == []
