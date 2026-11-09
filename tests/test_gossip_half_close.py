"""Gossip sender half-close: the ack stays readable after close_write."""
from __future__ import annotations

import json
from typing import Any, Dict, List

import multiaddr
import pytest
import trio
from libp2p.network.stream.net_stream import NetStream

from conftest import connect_peers, wait_for_addrs
from network.libp2p_compat import close_stream_safely

pytestmark = [pytest.mark.trio, pytest.mark.usefixtures("isolate_db")]


@pytest.fixture
async def two_nodes():
    from network.config import NetworkConfig
    from network.service import NetworkService

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


async def test_send_gossip_half_close_reads_ack_and_closes_stream(two_nodes, monkeypatch):
    svc1, svc2 = two_nodes
    topic = "tau/half-close/1.0.0"
    received: List[Dict[str, Any]] = []
    arrived = trio.Event()
    ack_bytes: List[bytes] = []
    closed_streams: List[object] = []

    async def on_message(envelope: Dict[str, Any]) -> None:
        received.append(envelope)
        arrived.set()

    await svc2._gossip_manager.join_topic(topic, on_message)
    message = {
        "topic": topic,
        "message_id": "hc-1",
        "payload": {"ping": True},
    }
    payload = json.dumps(
        {
            "peer_id": str(svc1.host.get_id()),
            "rpc": {"messages": [message]},
        }
    ).encode()

    real_read = NetStream.read
    recording = False

    async def read_record(self, n: int) -> bytes:
        data = await real_read(self, n)
        if recording and data:
            ack_bytes.append(data)
        return data

    async def close_record(stream) -> None:
        closed_streams.append(stream)
        await close_stream_safely(stream)

    monkeypatch.setattr(NetStream, "read", read_record)
    monkeypatch.setattr(
        "network.gossip.close_stream_safely",
        close_record,
    )

    recording = True
    await svc1._gossip_manager._send_gossip(svc2.host.get_id(), payload)
    recording = False

    assert ack_bytes
    ack = json.loads(ack_bytes[-1].decode())
    assert ack.get("ok") is True
    assert closed_streams
    assert all(getattr(s, "is_closed", False) for s in closed_streams)

    with trio.move_on_after(5):
        await arrived.wait()
    assert received and received[0]["payload"]["ping"] is True
