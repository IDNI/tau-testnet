"""Gossip sender: a peer that never closes its side does not keep stream entries."""
from __future__ import annotations

import json
from typing import List

import multiaddr
import pytest
import trio

from conftest import connect_peers, wait_for_addrs

pytestmark = [pytest.mark.trio, pytest.mark.usefixtures("isolate_db")]

TRANSPORTS = [
    pytest.param("/ip4/127.0.0.1/tcp/0", id="tcp"),
    pytest.param("/ip4/127.0.0.1/udp/0/quic-v1", id="quic"),
]


@pytest.fixture(params=TRANSPORTS)
async def two_nodes(request):
    from network.config import NetworkConfig
    from network.service import NetworkService

    listen = multiaddr.Multiaddr(request.param)
    services = [
        NetworkService(NetworkConfig(network_id="testnet", listen_addrs=[listen]))
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


def _muxer_stream_entries(host, peer_id) -> int:
    total = 0
    for conn in host.get_network().get_connections(peer_id):
        muxed = conn.muxed_conn
        table = getattr(muxed, "streams", None)
        if not isinstance(table, dict):
            table = muxed._streams  # QUIC connection
        total += len(table)
    return total


def _reset_by_peer(stream) -> bool:
    muxed = stream.muxed_stream
    if getattr(muxed, "reset_received", False) is True:  # yamux
        return True
    is_reset = getattr(muxed, "is_reset", None)  # QUIC
    return callable(is_reset) and is_reset() is True


def _payload(sender) -> bytes:
    return json.dumps(
        {"peer_id": str(sender.host.get_id()), "rpc": {"messages": []}}
    ).encode()


async def test_peer_without_fin_does_not_grow_stream_entries(two_nodes, monkeypatch):
    from network.libp2p_compat import read_json_object
    from network.protocols import TAU_PROTOCOL_GOSSIP

    sender, silent = two_nodes
    monkeypatch.setattr("network.gossip.REQUEST_READ_TIMEOUT", 0.5)

    async def ack_without_fin(stream) -> None:
        await read_json_object(stream, 1 << 20, read_timeout=5)
        await stream.write(b'{"ok": true}')
        await trio.sleep_forever()

    silent.host.set_stream_handler(TAU_PROTOCOL_GOSSIP, ack_without_fin)
    peer_id = silent.host.get_id()
    connections = sender.host.get_network().get_connections(peer_id)
    payload = _payload(sender)
    sends = 50
    for _ in range(sends):
        await sender._gossip_manager._send_gossip(peer_id, payload)

    with trio.move_on_after(10):
        while _muxer_stream_entries(sender.host, peer_id) > 2:
            await trio.sleep(0.1)
    # A reconnect drops all entries, so the check needs the first connection.
    assert sender.host.get_network().get_connections(peer_id) == connections
    assert _muxer_stream_entries(sender.host, peer_id) <= 2


async def test_slow_server_still_receives_full_request(two_nodes, monkeypatch):
    from network.libp2p_compat import read_json_object
    from network.protocols import TAU_PROTOCOL_GOSSIP

    sender, slow = two_nodes
    monkeypatch.setattr("network.gossip.REQUEST_READ_TIMEOUT", 5.0)
    received: List[bytes] = []
    reset_before_read: List[bool] = []
    done = trio.Event()

    async def slow_reader(stream) -> None:
        await trio.sleep(1.5)
        # yamux still gives the buffered request after a reset, so the data alone does not show it.
        reset_before_read.append(_reset_by_peer(stream))
        received.append(await read_json_object(stream, 1 << 20, read_timeout=5))
        await stream.close()
        done.set()

    slow.host.set_stream_handler(TAU_PROTOCOL_GOSSIP, slow_reader)
    payload = json.dumps(
        {"peer_id": str(sender.host.get_id()), "rpc": {"messages": []}, "pad": "x" * 200_000}
    ).encode()
    await sender._gossip_manager._send_gossip(slow.host.get_id(), payload)

    with trio.move_on_after(10):
        await done.wait()
    assert reset_before_read == [False]
    assert received == [payload]
