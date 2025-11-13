import json
from typing import List

import multiaddr
import pytest
import trio
from libp2p import new_host
from libp2p.peer.peerinfo import PeerInfo


pytestmark = pytest.mark.trio


def _strip_p2p(addr: multiaddr.Multiaddr) -> multiaddr.Multiaddr:
    addr_str = str(addr)
    if "/p2p/" in addr_str:
        addr_str = addr_str.split("/p2p/")[0]
    return multiaddr.Multiaddr(addr_str)


def _collect_listen_addrs(host) -> List[multiaddr.Multiaddr]:
    addrs = list(host.get_addrs() or [])
    network = host.get_network()
    get_addrs = getattr(network, "get_addrs", None)
    if not addrs and callable(get_addrs):
        try:
            addrs = list(get_addrs() or [])
        except Exception:
            pass
    listeners = getattr(network, "listeners", None)
    if not addrs and listeners:
        temp: List[multiaddr.Multiaddr] = []
        for listener in listeners.values() if isinstance(listeners, dict) else listeners:
            try:
                getter = getattr(listener, "get_addrs", None)
                if callable(getter):
                    temp.extend(getter() or [])
            except Exception:
                continue
        if temp:
            addrs = temp
    return [_strip_p2p(addr) for addr in addrs]


async def _wait_for_addrs(host, timeout: float = 5.0) -> List[multiaddr.Multiaddr]:
    with trio.fail_after(timeout):
        while True:
            addrs = _collect_listen_addrs(host)
            if addrs:
                return addrs
            await trio.sleep(0.05)


@pytest.fixture
async def hosts():
    listen1 = [multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]
    listen2 = [multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]
    host1 = new_host(listen_addrs=listen1)
    host2 = new_host(listen_addrs=listen2)
    async with host1.run(listen1), host2.run(listen2):
        await _wait_for_addrs(host1)
        await _wait_for_addrs(host2)
        yield host1, host2


async def test_node_connection(hosts):
    host1, host2 = hosts
    addrs2 = await _wait_for_addrs(host2)
    peer_info = PeerInfo(host2.get_id(), addrs2)
    host1.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await host1.connect(peer_info)
    assert host2.get_id() in host1.get_peerstore().peer_ids()


async def test_send_and_receive_message(hosts):
    host1, host2 = hosts
    message_received = trio.Event()
    received_data = {"value": None}
    protocol_id = "/test/chat/1.0.0"

    async def stream_handler(stream):
        data = await stream.read()
        received_data["value"] = (data or b"").decode()
        message_received.set()
        await stream.close()

    host2.set_stream_handler(protocol_id, stream_handler)

    addrs2 = await _wait_for_addrs(host2)
    peer_info = PeerInfo(host2.get_id(), addrs2)
    host1.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await host1.connect(peer_info)

    stream = await host1.new_stream(host2.get_id(), [protocol_id])
    message = "hello"
    await stream.write(message.encode())
    await stream.close()

    with trio.fail_after(5):
        await message_received.wait()

    assert received_data["value"] == message


async def test_node_synchronization(hosts):
    host1, host2 = hosts
    block_received = trio.Event()
    received_block = {"value": None}
    protocol_id = "/test/sync/1.0.0"

    async def stream_handler(stream):
        data = await stream.read()
        received_block["value"] = (data or b"").decode()
        block_received.set()
        await stream.close()

    host2.set_stream_handler(protocol_id, stream_handler)

    addrs2 = await _wait_for_addrs(host2)
    peer_info = PeerInfo(host2.get_id(), addrs2)
    host1.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await host1.connect(peer_info)

    block_json = json.dumps({"message": "new block"})
    stream = await host1.new_stream(host2.get_id(), [protocol_id])
    await stream.write(block_json.encode())
    await stream.close()

    with trio.fail_after(5):
        await block_received.wait()

    assert json.loads(received_block["value"])["message"] == "new block"
