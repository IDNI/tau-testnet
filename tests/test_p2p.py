import pytest
import pytest_asyncio
import asyncio
import multiaddr
from libp2p import new_host
from libp2p.peer.peerinfo import PeerInfo



# Helper: Collect listen addresses from host/network (best effort)
def _collect_listen_addrs(host):
    """Return best-effort list of listen multiaddrs from host/network."""
    addrs = list(host.get_addrs() or [])
    nw = host.get_network()
    # Try swarm.get_addrs() if available
    get_addrs = getattr(nw, "get_addrs", None)
    if not addrs and callable(get_addrs):
        try:
            addrs = list(get_addrs() or [])
        except Exception:
            pass
    # Try listeners attribute
    listeners = getattr(nw, "listeners", None)
    if not addrs and listeners:
        tmp = []
        for lst in listeners:
            try:
                la = lst.get_addrs() if callable(getattr(lst, "get_addrs", None)) else []
                tmp.extend(la or [])
            except Exception:
                continue
        if tmp:
            addrs = tmp
    return addrs

# Helper: Wait for host to report at least one listen address, return address list
async def _wait_for_addrs(host, timeout: float = 5.0):
    """Wait until a host reports at least one listen address or raise TimeoutError. Returns address list."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        addrs = _collect_listen_addrs(host)
        if addrs:
            return addrs
        if loop.time() >= deadline:
            raise TimeoutError("host has no listening addresses")
        await asyncio.sleep(0.05)

@pytest_asyncio.fixture
async def hosts():
    """
    Fixture to create and tear down two libp2p hosts.
    """
    host1 = new_host(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")])
    host2 = new_host(listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")])
    # Wait until both hosts report listen addrs
    await _wait_for_addrs(host1)
    await _wait_for_addrs(host2)
    yield host1, host2
    await asyncio.gather(host1.close(), host2.close())

@pytest.mark.asyncio
async def test_node_connection(hosts):
    """
    Test if a host can connect to another host.
    """
    host1, host2 = hosts

    # Wait for host2 to have at least one listen address
    addrs2 = await _wait_for_addrs(host2)
    # Add host2's address to host1's peer store
    peer_info = PeerInfo(host2.get_id(), addrs2)
    host1.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)

    # Connect and verify
    await host1.connect(peer_info)
    assert host2.get_id() in host1.get_peerstore().peers()

@pytest.mark.asyncio
async def test_send_and_receive_message(hosts):
    """
    Test if a host can send and receive a message from another host.
    """
    host1, host2 = hosts
    message_received = asyncio.Event()
    received_data = None
    protocol_id = "/test/chat/1.0.0"

    async def stream_handler(stream):
        nonlocal received_data
        data = await stream.read()
        received_data = data.decode()
        message_received.set()
        await stream.close()

    host2.set_stream_handler(protocol_id, stream_handler)

    # Wait for host2 to have at least one listen address
    addrs2 = await _wait_for_addrs(host2)
    peer_info = PeerInfo(host2.get_id(), addrs2)
    host1.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    
    await host1.connect(peer_info)
    
    stream = await host1.new_stream(host2.get_id(), [protocol_id])
    message = "hello"
    await stream.write(message.encode())
    await stream.close()

    await asyncio.wait_for(message_received.wait(), timeout=5)
    
    assert received_data == message

@pytest.mark.asyncio
async def test_node_synchronization(hosts):
    """
    Test if a host can receive a block from another host.
    """
    import json
    host1, host2 = hosts
    block_received = asyncio.Event()
    received_block_data = None
    protocol_id = "/test/sync/1.0.0"

    async def stream_handler(stream):
        nonlocal received_block_data
        data = await stream.read()
        received_block_data = data.decode()
        block_received.set()
        await stream.close()

    host2.set_stream_handler(protocol_id, stream_handler)

    # Wait for host2 to have at least one listen address
    addrs2 = await _wait_for_addrs(host2)
    peer_info = PeerInfo(host2.get_id(), addrs2)
    host1.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    
    await host1.connect(peer_info)

    class MockBlock:
        def __init__(self, data):
            self.data = data
        def to_json(self):
            return json.dumps(self.data)

    block = MockBlock({"message": "new block"})
    block_json = block.to_json()

    stream = await host1.new_stream(host2.get_id(), [protocol_id])
    await stream.write(block_json.encode())
    await stream.close()

    await asyncio.wait_for(block_received.wait(), timeout=5)

    assert json.loads(received_block_data)["message"] == "new block"
