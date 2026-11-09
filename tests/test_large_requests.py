"""Requests over one 64 KiB stream frame on the tx and gossip protocols."""
from __future__ import annotations

import json
from typing import Any, Dict, List

import multiaddr
import pytest
import trio

from conftest import connect_peers, wait_for_addrs
from network.libp2p_compat import read_until_eof

pytestmark = [pytest.mark.trio, pytest.mark.usefixtures("isolate_db")]

SERVER_READS_ONE_FRAME = (
    "_handle_tx and _handle_gossip_stream read one frame of at most 65535 bytes"
)
SIZES = [
    pytest.param(1024, id="1k"),
    pytest.param(
        100 * 1024,
        id="100k",
        marks=pytest.mark.xfail(strict=True, reason=SERVER_READS_ONE_FRAME),
    ),
]


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
