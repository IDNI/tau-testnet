import asyncio
import json
import os
import importlib

import pytest
import pytest_asyncio
import multiaddr


@pytest.fixture(autouse=True)
def isolate_db(tmp_path):
    """Isolate the SQLite DB per test to avoid cross-test interference."""
    orig_env = os.environ.get('TAU_DB_PATH')
    db_file = tmp_path / 'p2p_test.db'
    os.environ['TAU_DB_PATH'] = str(db_file)
    # Reload config/db so they pick up the new path
    import config as config_module
    import db as db_module
    importlib.reload(config_module)
    importlib.reload(db_module)
    yield
    # Restore
    if orig_env is None:
        os.environ.pop('TAU_DB_PATH', None)
    else:
        os.environ['TAU_DB_PATH'] = orig_env
    importlib.reload(config_module)
    importlib.reload(db_module)


async def _wait_for_addrs(host, timeout: float = 5.0):
    """Wait until a host reports at least one listen address or raise TimeoutError. Returns address list."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        addrs = list(host.get_addrs() or [])
        if addrs:
            return addrs
        if loop.time() >= deadline:
            raise TimeoutError("host has no listening addresses")
        await asyncio.sleep(0.05)


@pytest_asyncio.fixture
async def two_nodes():
    from network.config import NetworkConfig
    from network.service import NetworkService

    cfg1 = NetworkConfig(
        network_id="testnet",
        genesis_hash="genesis_hash_xyz",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )
    cfg2 = NetworkConfig(
        network_id="testnet",
        genesis_hash="genesis_hash_xyz",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )

    svc1 = NetworkService(cfg1)
    svc2 = NetworkService(cfg2)
    await asyncio.gather(svc1.start(), svc2.start())
    # Ensure both have active listeners
    await _wait_for_addrs(svc1.host)
    await _wait_for_addrs(svc2.host)
    try:
        yield svc1, svc2
    finally:
        await asyncio.gather(svc1.stop(), svc2.stop())


@pytest.mark.asyncio
async def test_each_protocol_communication(two_nodes):
    from libp2p.peer.peerinfo import PeerInfo
    from network.protocols import (
        TAU_PROTOCOL_HANDSHAKE,
        TAU_PROTOCOL_PING,
        TAU_PROTOCOL_SYNC,
        TAU_PROTOCOL_BLOCKS,
        TAU_PROTOCOL_TX,
    )

    svc1, svc2 = two_nodes

    # Connect svc1 -> svc2
    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    # 1) Handshake: send any payload and expect JSON handshake back
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    await stream.write(b"hi")
    data = await stream.read()
    await stream.close()
    hs = json.loads(data.decode())
    assert hs["network_id"] == "testnet"
    assert hs["agent"] == svc2._config.agent
    assert hs["genesis_hash"] == svc2._config.genesis_hash
    assert hs["node_id"] == svc2.host.get_id()

    # 2) Ping: send nonce and expect same nonce in pong
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_PING])
    await stream.write(json.dumps({"nonce": 42}).encode())
    data = await stream.read()
    await stream.close()
    pong = json.loads(data.decode())
    assert pong["nonce"] == 42
    assert isinstance(pong.get("time"), (int, float))

    # 3) Sync: send dummy request, expect empty headers and correct tip
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await stream.write(b"get_headers")
    data = await stream.read()
    await stream.close()
    sync = json.loads(data.decode())
    assert sync["headers"] == []
    assert sync["tip_number"] == 0
    assert sync["tip_hash"] == svc2._config.genesis_hash

    # 4) Blocks: send dummy request, expect empty blocks list
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    await stream.write(b"get_blocks")
    data = await stream.read()
    await stream.close()
    blocks = json.loads(data.decode())
    assert blocks["blocks"] == []

    # 5) Tx: send dummy tx payload, expect ok True
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    await stream.write(json.dumps({"tx": "dummy"}).encode())
    data = await stream.read()
    await stream.close()
    tx_resp = json.loads(data.decode())
    assert tx_resp["ok"] is True


@pytest.mark.asyncio
async def test_sync_protocol_typical_flow(two_nodes):
    """Exercise a typical TAU_PROTOCOL_SYNC flow end-to-end.

    Although the current implementation returns an empty header set, this test
    validates the request/response shape, idempotence across multiple calls,
    and that follow-up block fetching can proceed using the reported tip.
    """
    from libp2p.peer.peerinfo import PeerInfo
    from network.protocols import (
        TAU_PROTOCOL_HANDSHAKE,
        TAU_PROTOCOL_SYNC,
        TAU_PROTOCOL_BLOCKS,
    )

    svc1, svc2 = two_nodes

    # Connect svc1 -> svc2
    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    # 0) Optional handshake to read peer's advertised view
    hs_stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    await hs_stream.write(b"hello")
    hs_raw = await hs_stream.read()
    await hs_stream.close()
    hs = json.loads(hs_raw.decode())
    assert hs["network_id"] == "testnet"
    assert hs["agent"] == svc2._config.agent
    assert hs["genesis_hash"] == svc2._config.genesis_hash
    assert hs["node_id"] == svc2.host.get_id()
    # Current implementation returns head_* fields in handshake
    assert hs["head_number"] == 0
    assert hs["head_hash"] == svc2._config.genesis_hash

    # 1) First sync request with a realistic header locator, stop, and limit
    req1 = {
        "type": "get_headers",
        "locator": ["h3", "h2", "h1"],
        "stop": "h_stop",
        "limit": 2000,
    }
    s1 = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await s1.write(json.dumps(req1).encode())
    resp_raw = await s1.read()
    await s1.close()
    resp = json.loads(resp_raw.decode())
    # Validate response shape and values
    assert isinstance(resp.get("headers"), list)
    assert resp.get("tip_number") == 0
    assert resp.get("tip_hash") == svc2._config.genesis_hash

    # 2) Subsequent paged request with a smaller limit; expect consistent tip
    req2 = {"type": "get_headers", "locator": ["h2", "h1"], "limit": 1}
    s2 = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await s2.write(json.dumps(req2).encode())
    resp2_raw = await s2.read()
    await s2.close()
    resp2 = json.loads(resp2_raw.decode())
    assert isinstance(resp2.get("headers"), list)
    assert resp2.get("tip_number") == 0
    assert resp2.get("tip_hash") == svc2._config.genesis_hash

    # 3) Idempotence check: empty payload should still yield a valid response
    s3 = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await s3.write(b"")
    resp3_raw = await s3.read()
    await s3.close()
    resp3 = json.loads(resp3_raw.decode())
    assert isinstance(resp3.get("headers"), list)
    assert resp3.get("tip_hash") == svc2._config.genesis_hash

    # 4) Follow-up: use reported tip to proceed to block fetching
    bs = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    await bs.write(json.dumps({"type": "get_blocks", "from": resp["tip_hash"], "limit": 5}).encode())
    blocks_raw = await bs.read()
    await bs.close()
    blocks = json.loads(blocks_raw.decode())
    assert isinstance(blocks.get("blocks"), list)


