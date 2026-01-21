import importlib
import json
import os
import threading
import types
from typing import Any, Dict, List

import multiaddr
import pytest
import trio
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo
from libp2p.peer.peerstore import PeerStoreError
from commands import sendtx


pytestmark = pytest.mark.trio


@pytest.fixture(autouse=True)
def isolate_db(tmp_path):
    """Isolate the SQLite DB per test to avoid cross-test interference."""
    orig_env = os.environ.get("TAU_DB_PATH")
    db_file = tmp_path / "p2p_test.db"
    os.environ["TAU_DB_PATH"] = str(db_file)
    import config as config_module
    import db as db_module
    
    # Close any existing connection before reloading to avoid leaks
    if getattr(db_module, "_db_conn", None):
        try:
            db_module._db_conn.close()
        except Exception:
            pass

    importlib.reload(config_module)
    importlib.reload(db_module)
    yield
    
    # Close our test connection before restoring
    if getattr(db_module, "_db_conn", None):
        try:
            db_module._db_conn.close()
        except Exception:
            pass

    if orig_env is None:
        os.environ.pop("TAU_DB_PATH", None)
    else:
        os.environ["TAU_DB_PATH"] = orig_env
    importlib.reload(config_module)
    importlib.reload(db_module)


def _strip_p2p(addr: multiaddr.Multiaddr) -> multiaddr.Multiaddr:
    addr_str = str(addr)
    if "/p2p/" in addr_str:
        addr_str = addr_str.split("/p2p/")[0]
    return multiaddr.Multiaddr(addr_str)


async def _wait_for_addrs(host, timeout: float = 5.0) -> List[multiaddr.Multiaddr]:
    """Wait until a host reports at least one listen address or raise TimeoutError."""
    with trio.fail_after(timeout):
        while True:
            addrs = list(host.get_addrs() or [])
            if addrs:
                return [_strip_p2p(addr) for addr in addrs]
            await trio.sleep(0.05)


@pytest.fixture
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

    submissions: List[str] = []

    def submit(payload: str) -> str:
        submissions.append(payload)
        return "queued"

    svc1 = NetworkService(cfg1, tx_submitter=submit)
    svc2 = NetworkService(cfg2, tx_submitter=submit)
    await svc1.start()
    await svc2.start()
    await _wait_for_addrs(svc1.host)
    await _wait_for_addrs(svc2.host)
    try:
        yield svc1, svc2, submissions
    finally:
        await svc1.stop()
        await svc2.stop()


async def test_each_protocol_communication(two_nodes):
    from network.protocols import (
        TAU_GOSSIP_TOPIC_TRANSACTIONS,
        TAU_PROTOCOL_BLOCKS,
        TAU_PROTOCOL_GOSSIP,
        TAU_PROTOCOL_HANDSHAKE,
        TAU_PROTOCOL_PING,
        TAU_PROTOCOL_SYNC,
        TAU_PROTOCOL_TX,
    )

    svc1, svc2, submissions = two_nodes

    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    # Handshake
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    await stream.write(b"hi")
    try:
        data = await stream.read()
    finally:
        await stream.close()
    hs = json.loads((data or b"{}").decode())
    assert hs["network_id"] == "testnet"
    assert hs["agent"] == svc2._config.agent
    assert hs["genesis_hash"] == svc2._config.genesis_hash
    assert hs["node_id"] == str(svc2.host.get_id())

    # Ping
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_PING])
    await stream.write(json.dumps({"nonce": 42}).encode())
    try:
        data = await stream.read()
    finally:
        await stream.close()
    pong = json.loads((data or b"{}").decode())
    assert pong["nonce"] == 42
    assert isinstance(pong.get("time"), (int, float))

    # Sync
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await stream.write(b"get_headers")
    try:
        data = await stream.read()
    finally:
        await stream.close()
    sync = json.loads((data or b"{}").decode())
    assert sync["headers"] == []
    assert sync["tip_number"] == 0
    assert sync["tip_hash"] == svc2._config.genesis_hash

    # Blocks
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    await stream.write(b"get_blocks")
    try:
        data = await stream.read()
    finally:
        await stream.close()
    blocks = json.loads((data or b"{}").decode())
    assert blocks["blocks"] == []

    # Tx
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_TX])
    await stream.write(json.dumps({"tx": "dummy"}).encode())
    try:
        data = await stream.read()
    finally:
        await stream.close()
    tx_resp = json.loads((data or b"{}").decode())
    assert tx_resp["ok"] is True
    assert tx_resp["result"] == "queued"
    assert submissions[-1] == "dummy"

    received: List[Dict[str, Any]] = []
    gossip_event = trio.Event()

    async def gossip_handler(envelope):
        if envelope.get("topic") == "test.topic":
            received.append(envelope)
            gossip_event.set()

    svc2.subscribe_gossip("*", gossip_handler)

    direct_stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_GOSSIP])
    direct_rpc = {
        "peer_id": str(svc1.host.get_id()),
        "rpc": {
            "messages": [
                {
                    "topic": "direct.check",
                    "message_id": "direct-1",
                    "data": {"ok": True},
                }
            ]
        },
    }
    await direct_stream.write(json.dumps(direct_rpc).encode())
    direct_raw = await direct_stream.read()
    await direct_stream.close()
    direct_resp = json.loads((direct_raw or b"{}").decode())
    assert direct_resp["ok"] is True
    assert direct_resp["messages"][0]["duplicate"] is False
    assert direct_resp["messages"][0]["message_id"] == "direct-1"

    message_id = await svc1.publish_gossip("test.topic", {"value": 123})

    with trio.fail_after(5):
        await gossip_event.wait()
    assert len(received) == 1
    envelope = received[0]
    assert envelope["topic"] == "test.topic"
    assert envelope["payload"] == {"value": 123}
    assert envelope["origin"] == str(svc1.host.get_id())
    assert envelope["message_id"] == message_id


async def test_mempool_snapshot_sent_on_connect(two_nodes, monkeypatch):
    import network.service as net_service
    import db as db_module

    svc1, svc2, _ = two_nodes

    # Patch queue_transaction so we can observe gossip ingestion without Tau/BLS.
    received: List[Dict[str, Any]] = []
    call_event = trio.Event()

    def fake_submit(payload: str, propagate: bool = True) -> str:
        received.append({"payload": payload, "propagate": propagate})
        call_event.set()
        return "queued"

    monkeypatch.setattr(svc2, "_submit_tx", fake_submit)

    # Seed the mempool on svc1 before the connection is established.
    tx_payload = {
        "sender_pubkey": "a" * 96,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "operations": {"1": [["a" * 96, "b" * 96, "1"]]},
        "fee_limit": "0",
        "signature": "0" * 192,
    }
    db_module.add_mempool_tx(json.dumps(tx_payload), "protocol_tx_1", 1000)

    addrs2 = await _wait_for_addrs(svc2.host)
    print(f"DEBUG: svc2 addrs: {addrs2}")
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    print(f"DEBUG: Connecting from svc1 ({svc1.host.get_id()}) to svc2")

    for i in range(5):
        try:
            await svc1.host.connect(peer_info)
            break
        except Exception as e:
            print(f"DEBUG: Connect attempt {i+1} failed: {e}")
            await trio.sleep(1)
    else:
        pytest.fail("Failed to connect after 5 attempts")

    with trio.fail_after(5):
        await call_event.wait()

    assert received, "Expected mempool transaction to be replayed to the new peer"
    replay = received[0]
    assert replay["propagate"] is False
    parsed = json.loads(replay["payload"])
    assert parsed["operations"]["1"][0][2] == "1"
    assert parsed["sender_pubkey"] == "a" * 96


async def test_block_gossip_fallback_to_via(monkeypatch):
    from network.config import NetworkConfig
    from network.protocols import TAU_GOSSIP_TOPIC_BLOCKS
    from network.service import NetworkService

    cfg_a = NetworkConfig(
        network_id="testnet",
        genesis_hash="gen",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )
    cfg_b = NetworkConfig(
        network_id="testnet",
        genesis_hash="gen",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )
    cfg_c = NetworkConfig(
        network_id="testnet",
        genesis_hash="gen",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )

    svc_a = NetworkService(cfg_a)
    svc_b = NetworkService(cfg_b)
    svc_c = NetworkService(cfg_c)
    await svc_a.start()
    await svc_b.start()
    await svc_c.start()

    try:
        addrs_a = await _wait_for_addrs(svc_a.host)
        addrs_b = await _wait_for_addrs(svc_b.host)
        addrs_b = await _wait_for_addrs(svc_b.host)
        addrs_c = await _wait_for_addrs(svc_c.host)

        peer_info_a = PeerInfo(svc_a.host.get_id(), addrs_a)
        svc_b.host.get_peerstore().add_addrs(peer_info_a.peer_id, peer_info_a.addrs, 60)
        await svc_b.host.connect(peer_info_a)

        peer_info_b = PeerInfo(svc_b.host.get_id(), addrs_b)
        svc_c.host.get_peerstore().add_addrs(peer_info_b.peer_id, peer_info_b.addrs, 60)
        await svc_c.host.connect(peer_info_b)

        # Ensure svc_c cannot dial svc_a directly
        pid_a = svc_c._ensure_peer_id(str(svc_a.host.get_id()))
        try:
            svc_c.host.get_peerstore().peer_data_map[pid_a].clear_addrs()
        except KeyError:
            pass

        attempts: List[str] = []

        async def fake_try(self, peer_id: str, locator: List[str]) -> bool:
            attempts.append(peer_id)
            return True

        svc_c._try_block_sync = types.MethodType(fake_try, svc_c)

        envelope = {
            "topic": TAU_GOSSIP_TOPIC_BLOCKS,
            "payload": {"headers": []},
            "origin": str(svc_a.host.get_id()),
            "via": str(svc_b.host.get_id()),
            "message_id": "test",
        }

        await svc_c._handle_block_gossip(envelope)

        assert attempts == [str(svc_b.host.get_id())]
    finally:
        await svc_c.stop()
        await svc_b.stop()
        await svc_a.stop()


async def test_dht_value_validators(two_nodes):
    svc1, _, _ = two_nodes

    dht = getattr(svc1, "_dht", None)
    assert dht is not None

    with pytest.raises(ValueError):
        dht.value_store.put(b"block:bad", b"{}")

    block_hash = "abc123"
    block_payload = json.dumps({"block_hash": block_hash}).encode()
    dht.value_store.put(f"block:{block_hash}".encode(), block_payload)
    block_record = dht.value_store.get(f"block:{block_hash}".encode())
    assert block_record is not None
    assert getattr(block_record, "value", block_record) == block_payload

    tx_payload = {
        "sender_pubkey": "b" * 96,
        "sequence_number": 1,
        "expiration_time": 9999999999,
        "operations": {"1": [["b" * 96, "c" * 96, "1"]]},
        "fee_limit": "0",
        "signature": "0" * 192,
    }
    tx_id, canonical = sendtx._compute_transaction_message_id(tx_payload)
    with pytest.raises(ValueError):
        dht.value_store.put(f"tx:{tx_id}".encode(), b"{}")
    canonical_bytes = canonical.encode()
    dht.value_store.put(f"tx:{tx_id}".encode(), canonical_bytes)
    tx_record = dht.value_store.get(f"tx:{tx_id}".encode())
    assert tx_record is not None
    assert getattr(tx_record, "value", tx_record) == canonical_bytes

    state_hash = "statehash"
    state_payload = json.dumps({"block_hash": state_hash, "accounts": {}}).encode()
    dht.value_store.put(f"state:{state_hash}".encode(), state_payload)
    with pytest.raises(ValueError):
        dht.value_store.put(
            f"state:{state_hash}".encode(),
            json.dumps({"block_hash": "other", "accounts": {}}).encode(),
        )

    # New mode: raw Tau/rules snapshot bytes stored under state:<blake3>.
    from poa.state import compute_state_hash

    tau_snapshot = b"always (o5[t] = { #b1 }:bv)."
    tau_hash = compute_state_hash(tau_snapshot)
    dht.value_store.put(f"state:{tau_hash}".encode(), tau_snapshot)
    with pytest.raises(ValueError):
        dht.value_store.put(f"state:{tau_hash}".encode(), b"mismatched-bytes")

    peer_info = PeerInfo(svc1.host.get_id(), svc1.host.get_addrs())
    with pytest.raises(ValueError):
        dht.provider_store.add_provider(b"block:", peer_info)


async def test_state_protocol_accounts(two_nodes):
    from network.protocols import TAU_PROTOCOL_STATE
    import block as block_module
    import chain_state
    import db as db_module

    svc1, svc2, _ = two_nodes

    chain_state._balances["0xabc"] = 42
    chain_state._sequence_numbers["0xabc"] = 7

    test_block = block_module.Block.create(
        block_number=0,
        previous_hash="0" * 64,
        transactions=[],
    )
    db_module.add_block(test_block)

    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    req = {
        "block_hash": test_block.block_hash,
        "state_root": test_block.header.merkle_root,
        "accounts": ["0xabc", chain_state.GENESIS_ADDRESS],
        "receipts": ["tx1"],
    }
    stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_STATE])
    await stream.write(json.dumps(req).encode())
    data = await stream.read()
    await stream.close()
    resp = json.loads((data or b"{}").decode())
    assert resp["ok"] is True
    assert resp.get("state_root") == test_block.header.merkle_root
    assert resp.get("block_hash") == test_block.block_hash
    accounts = resp.get("accounts", {})
    assert accounts["0xabc"]["balance"] == 42
    assert accounts["0xabc"]["sequence"] == 7
    receipts = resp.get("receipts", {})
    assert receipts.get("tx1") is None


async def test_sync_protocol_typical_flow(two_nodes):
    from network.protocols import (
        TAU_PROTOCOL_BLOCKS,
        TAU_PROTOCOL_HANDSHAKE,
        TAU_PROTOCOL_SYNC,
    )

    svc1, svc2, _ = two_nodes

    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    hs_stream = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    await hs_stream.write(b"hello")
    hs_raw = await hs_stream.read()
    await hs_stream.close()
    hs = json.loads((hs_raw or b"{}").decode())
    assert hs["network_id"] == "testnet"
    assert hs["agent"] == svc2._config.agent
    assert hs["genesis_hash"] == svc2._config.genesis_hash
    assert hs["node_id"] == str(svc2.host.get_id())
    assert hs["head_number"] == 0
    assert hs["head_hash"] == svc2._config.genesis_hash

    req1 = {"type": "get_headers", "locator": ["h3", "h2", "h1"], "stop": "h_stop", "limit": 2000}
    s1 = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await s1.write(json.dumps(req1).encode())
    resp_raw = await s1.read()
    await s1.close()
    resp = json.loads((resp_raw or b"{}").decode())
    assert isinstance(resp.get("headers"), list)
    assert resp.get("tip_number") == 0
    assert resp.get("tip_hash") == svc2._config.genesis_hash

    req2 = {"type": "get_headers", "locator": ["h2", "h1"], "limit": 1}
    s2 = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await s2.write(json.dumps(req2).encode())
    resp2_raw = await s2.read()
    await s2.close()
    resp2 = json.loads((resp2_raw or b"{}").decode())
    assert isinstance(resp2.get("headers"), list)
    assert resp2.get("tip_number") == 0
    assert resp2.get("tip_hash") == svc2._config.genesis_hash

    s3 = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_SYNC])
    await s3.write(b"")
    resp3_raw = await s3.read()
    await s3.close()
    resp3 = json.loads((resp3_raw or b"{}").decode())
    assert isinstance(resp3.get("headers"), list)
    assert resp3.get("tip_hash") == svc2._config.genesis_hash

    bs = await svc1.host.new_stream(svc2.host.get_id(), [TAU_PROTOCOL_BLOCKS])
    await bs.write(json.dumps({"type": "get_blocks", "from": resp["tip_hash"], "limit": 5}).encode())
    blocks_raw = await bs.read()
    await bs.close()
    blocks = json.loads((blocks_raw or b"{}").decode())
    assert isinstance(blocks.get("blocks"), list)


async def test_transaction_gossip_triggers_queue(two_nodes, monkeypatch):
    from commands import sendtx as sendtx_module
    from network.protocols import TAU_GOSSIP_TOPIC_TRANSACTIONS

    svc1, svc2, submissions = two_nodes

    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    signal = threading.Event()
    recorded: List[tuple[str, bool]] = []

    def fake_queue(json_blob: str, propagate: bool = True) -> str:
        recorded.append((json_blob, propagate))
        signal.set()
        return "mocked"

    monkeypatch.setattr(svc2, "_submit_tx", fake_queue)

    tx_payload = json.dumps({"sample": "tx"}, sort_keys=True, separators=(",", ":"))
    await svc1.publish_gossip(TAU_GOSSIP_TOPIC_TRANSACTIONS, tx_payload, message_id="tx-test-1")

    success = await trio.to_thread.run_sync(signal.wait, 5)
    assert success is True
    assert recorded
    payload, propagate_flag = recorded[0]
    assert payload == tx_payload
    assert propagate_flag is False


async def test_block_gossip_triggers_sync(two_nodes, monkeypatch):
    from network.protocols import TAU_GOSSIP_TOPIC_BLOCKS
    from network.service import NetworkService

    svc1, svc2, _ = two_nodes

    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    event = trio.Event()
    recorded_args: Dict[str, Any] = {}

    async def fake_sync(self, peer_id, locator, stop=None, limit=2000):
        recorded_args["peer_id"] = peer_id
        recorded_args["locator"] = list(locator)
        event.set()
        return 0

    monkeypatch.setattr(NetworkService, "_sync_and_ingest_from_peer", fake_sync)

    payload = {
        "headers": [
            {
                "block_number": 1,
                "previous_hash": "0" * 64,
                "timestamp": 123,
                "merkle_root": "f" * 64,
                "block_hash": "a" * 64,
            }
        ],
        "tip_number": 1,
        "tip_hash": "a" * 64,
    }
    await svc1.publish_gossip(TAU_GOSSIP_TOPIC_BLOCKS, payload, message_id="block-test-1")

    with trio.fail_after(5):
        await event.wait()
    assert recorded_args["peer_id"] == str(svc1.host.get_id())
    assert recorded_args["locator"]


async def test_gossip_metrics_snapshot(two_nodes):
    svc1, svc2, _ = two_nodes

    initial = svc1.get_metrics_snapshot()
    baseline_publish = initial["gossip"]["published_total"]
    assert initial["gossip"]["health"]["status"] in {"idle", "healthy", "stale"}

    initial_remote = svc2.get_metrics_snapshot()
    baseline_receive = initial_remote["gossip"]["received_total"]

    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await svc1.host.connect(peer_info)

    gossip_event = trio.Event()

    async def _metrics_handler(envelope):
        if envelope.get("topic") == "metrics.topic":
            gossip_event.set()

    await svc2.join_gossip_topic("metrics.topic", _metrics_handler)

    await svc1.publish_gossip("metrics.topic", {"value": 456})

    with trio.fail_after(5):
        await gossip_event.wait()

    snap1 = svc1.get_metrics_snapshot()
    snap2 = svc2.get_metrics_snapshot()

    assert snap1["gossip"]["published_total"] == baseline_publish + 1
    assert snap1["gossip"]["last_published"] is not None
    assert snap1["gossip"]["health"]["status"] == "healthy"

    assert snap2["gossip"]["received_total"] >= baseline_receive + 1
    assert snap2["gossip"]["last_received"] is not None
    assert snap2["gossip"]["health"]["status"] == "healthy"


async def test_gossip_dht_peer_resolution(two_nodes, monkeypatch):
    topic = "dht.peer.route"
    svc1, svc2, _ = two_nodes

    peer_id_str = str(svc2.host.get_id())
    event = trio.Event()

    async def handler(envelope):
        if envelope.get("topic") == topic:
            event.set()

    await svc2.join_gossip_topic(topic, handler)

    svc1._gossip_peer_topics[peer_id_str] = {topic}

    try:
        pid = svc1._ensure_peer_id(peer_id_str)
        svc1.host.get_peerstore().peer_data_map[pid].clear_addrs()
    except Exception:
        pass

    addrs2 = await _wait_for_addrs(svc2.host)
    peer_info = PeerInfo(svc2.host.get_id(), addrs2)

    find_calls: List[ID] = []

    async def fake_find_peer(peer_id):
        find_calls.append(peer_id)
        return peer_info

    monkeypatch.setattr(svc1._dht.peer_routing, "find_peer", fake_find_peer)

    await svc1.publish_gossip(topic, {"ping": True}, target_peers=[peer_id_str])

    with trio.fail_after(5):
        await event.wait()

    assert find_calls, "Expected DHT find_peer to be invoked for route discovery"


async def test_gossip_opportunistic_seeding(two_nodes, monkeypatch):
    from network.protocols import TAU_PROTOCOL_GOSSIP

    svc1, svc2, _ = two_nodes

    addrs2 = await _wait_for_addrs(svc2.host)
    pid2 = svc2.host.get_id()

    try:
        svc1.host.get_peerstore().peer_data_map[pid2].clear_addrs()
    except Exception:
        pass

    async def fake_find_peer(peer_id):
        return PeerInfo(peer_id, addrs2)

    add_calls: List[PeerInfo] = []

    async def fake_add_peer(peer_info):
        add_calls.append(peer_info)
        return True

    monkeypatch.setattr(svc1._dht.peer_routing, "find_peer", fake_find_peer)
    monkeypatch.setattr(svc1._dht.routing_table, "add_peer", fake_add_peer)

    addrs1 = await _wait_for_addrs(svc1.host)
    svc2.host.get_peerstore().add_addrs(svc1.host.get_id(), addrs1, 60)

    stream = await svc2.host.new_stream(svc1.host.get_id(), [TAU_PROTOCOL_GOSSIP])
    message = {
        "topic": "bootstrap.topic",
        "message_id": "bootstrap-msg",
        "data": {"hello": 1},
    }
    payload = {"peer_id": str(pid2), "rpc": {"messages": [message]}}
    await stream.write(json.dumps(payload).encode())
    await stream.read()
    await stream.close()

    with trio.fail_after(5):
        while not add_calls:
            await trio.sleep(0.05)

    assert str(add_calls[0].peer_id) == str(pid2)
    assert str(pid2) in svc1._opportunistic_peers


async def test_handshake_opportunistic_seeding(two_nodes, monkeypatch):
    from network.protocols import TAU_PROTOCOL_HANDSHAKE

    svc1, svc2, _ = two_nodes

    addrs2 = await _wait_for_addrs(svc2.host)
    pid2 = svc2.host.get_id()

    try:
        svc1.host.get_peerstore().peer_data_map[pid2].clear_addrs()
    except Exception:
        pass

    async def fake_find_peer(peer_id):
        return PeerInfo(peer_id, addrs2)

    add_calls: List[PeerInfo] = []

    async def fake_add_peer(peer_info):
        add_calls.append(peer_info)
        return True

    monkeypatch.setattr(svc1._dht.peer_routing, "find_peer", fake_find_peer)
    monkeypatch.setattr(svc1._dht.routing_table, "add_peer", fake_add_peer)

    addrs1 = await _wait_for_addrs(svc1.host)
    svc2.host.get_peerstore().add_addrs(svc1.host.get_id(), addrs1, 60)

    stream = await svc2.host.new_stream(svc1.host.get_id(), [TAU_PROTOCOL_HANDSHAKE])
    await stream.write(b"hello")
    await stream.read()
    await stream.close()

    with trio.fail_after(5):
        while not add_calls:
            await trio.sleep(0.05)

    assert str(add_calls[0].peer_id) == str(pid2)
    assert str(pid2) in svc1._opportunistic_peers


async def test_handshake_exchanges_peer_snapshot(monkeypatch):
    from network.config import NetworkConfig
    from network.service import NetworkService

    cfg = NetworkConfig(
        network_id="snapshotnet",
        genesis_hash="genesis",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
        dht_handshake_max_peers=8,
        dht_handshake_max_providers=8,
        peer_advertisement_interval=0.0,
    )

    svc_a = NetworkService(cfg)
    svc_b = NetworkService(cfg)
    svc_c = NetworkService(cfg)

    await svc_a.start()
    await svc_b.start()
    await svc_c.start()
    try:
        addrs_a = await _wait_for_addrs(svc_a.host)
        addrs_b = await _wait_for_addrs(svc_b.host)
        addrs_c = await _wait_for_addrs(svc_c.host)

        peer_info_c = PeerInfo(svc_c.host.get_id(), addrs_c)
        svc_a.host.get_peerstore().add_addrs(peer_info_c.peer_id, peer_info_c.addrs, 60)
        await svc_a.host.connect(peer_info_c)
        await svc_a._opportunistic_seed_peer(str(peer_info_c.peer_id), peer_info_c.addrs)
        await trio.sleep(0.1)
        await svc_a._dht.routing_table.add_peer(peer_info_c)
        await svc_a._dht.routing_table.add_peer(peer_info_c)
        # Use a critical key (state for genesis) that _build_handshake_payload will actually advertise
        # Note: chain_state keys are now slash-prefixed.
        provider_key = f"/state/{cfg.genesis_hash}"
        # Also ensure we have the value locally so has_local_data returns true
        # Must be valid state record (JSON with block_hash matching suffix)
        state_payload = json.dumps({"block_hash": cfg.genesis_hash}).encode("utf-8")
        svc_a._dht.value_store.put(provider_key.encode(), state_payload)
        svc_a._dht.provider_store.add_provider(provider_key.encode(), peer_info_c)

        original_payload = svc_a._build_handshake_payload
        recorded_payload: Dict[str, Any] = {}

        def instrumented_payload():
            payload = original_payload()
            recorded_payload["last"] = payload
            return payload

        monkeypatch.setattr(svc_a, "_build_handshake_payload", instrumented_payload)

        original_find = svc_b._dht.peer_routing.find_peer
        lookup_ids: List[ID] = []

        async def instrumented_find(peer_id):
            lookup_ids.append(peer_id)
            return await original_find(peer_id)

        monkeypatch.setattr(svc_b._dht.peer_routing, "find_peer", instrumented_find)

        svc_a.host.get_peerstore().add_addrs(svc_b.host.get_id(), addrs_b, 60)
        svc_b.host.get_peerstore().add_addrs(svc_a.host.get_id(), addrs_a, 60)
        await svc_a._perform_handshake(svc_b.host.get_id())

        advertised_payload = recorded_payload.get("last", {})
        advertised_peers = advertised_payload.get("dht_peers", [])
        assert any(entry.get("peer_id") == str(svc_c.host.get_id()) for entry in advertised_peers)
        advertised_providers = advertised_payload.get("dht_providers", [])
        assert any(entry.get("key") == provider_key for entry in advertised_providers)

        with trio.fail_after(3):
            while True:
                try:
                    known = svc_b.host.get_peerstore().addrs(svc_c.host.get_id())
                    if known:
                        break
                except PeerStoreError:
                    pass
                await trio.sleep(0.05)

        provider_snapshot = getattr(svc_b._dht.provider_store, "providers", {})
        assert any(entry_key == provider_key.encode() for entry_key in provider_snapshot.keys())
        assert any(str(peer_id) == str(svc_c.host.get_id()) for peer_id in lookup_ids)
    finally:
        await svc_c.stop()
        await svc_b.stop()
        await svc_a.stop()


async def test_peer_advertisement_gossip(monkeypatch):
    from network.config import NetworkConfig
    from network.protocols import TAU_GOSSIP_TOPIC_PEERS
    from network.service import NetworkService

    cfg = NetworkConfig(
        network_id="adnet",
        genesis_hash="genesis",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
        dht_handshake_max_peers=0,
        dht_handshake_max_providers=8,
        peer_advertisement_interval=0.2,
        peer_advertisement_max_peers=4,
    )

    svc_a = NetworkService(cfg)
    svc_b = NetworkService(cfg)
    svc_c = NetworkService(cfg)

    await svc_a.start()
    await svc_b.start()
    await svc_c.start()
    try:
        addrs_a = await _wait_for_addrs(svc_a.host)
        addrs_b = await _wait_for_addrs(svc_b.host)
        addrs_c = await _wait_for_addrs(svc_c.host)

        peer_info_c = PeerInfo(svc_c.host.get_id(), addrs_c)
        await svc_a._opportunistic_seed_peer(str(peer_info_c.peer_id), peer_info_c.addrs)
        
        # Use critical key that is actually advertised
        # Key: /state/<genesis_hash>
        # ensure has_local_data pass
        provider_key = f"/state/{cfg.genesis_hash}"
        provider_key_bytes = provider_key.encode("utf-8")
        
        # We must put a valid value so has_local_data returns True
        # And strict validation requires valid JSON payload for 'state' namespace
        import json
        state_payload = json.dumps({"block_hash": cfg.genesis_hash}).encode("utf-8")
        svc_a._dht.value_store.put(provider_key_bytes, state_payload)
        
        svc_a._dht.provider_store.add_provider(provider_key_bytes, peer_info_c)

        svc_b.host.get_peerstore().add_addrs(svc_a.host.get_id(), addrs_a, 60)
        await svc_b.host.connect(PeerInfo(svc_a.host.get_id(), addrs_a))

        original_find = svc_b._dht.peer_routing.find_peer
        lookup_ids: List[ID] = []

        async def instrumented_find(peer_id):
            lookup_ids.append(peer_id)
            return await original_find(peer_id)

        monkeypatch.setattr(svc_b._dht.peer_routing, "find_peer", instrumented_find)

        advertisement_seen = trio.Event()

        captured_payload: Dict[str, Any] = {}

        async def peer_handler(envelope):
            if envelope.get("topic") == TAU_GOSSIP_TOPIC_PEERS:
                captured_payload["payload"] = envelope.get("payload")
                advertisement_seen.set()

        svc_b.subscribe_gossip("*", peer_handler)

        with trio.fail_after(5):
            await advertisement_seen.wait()

        with trio.fail_after(2):
            while True:
                try:
                    known = svc_b.host.get_peerstore().addrs(svc_c.host.get_id())
                    if known:
                        break
                except PeerStoreError:
                    pass
                await trio.sleep(0.05)

        provider_snapshot = getattr(svc_b._dht.provider_store, "providers", {})
        # Check for the key we used
        # Note: provider_store keys are bytes
        expected_key = provider_key.encode("utf-8")
        assert any(key == expected_key for key in provider_snapshot.keys())
        assert any(str(peer_id) == str(svc_c.host.get_id()) for peer_id in lookup_ids)
    finally:
        await svc_c.stop()
        await svc_b.stop()
        await svc_a.stop()


async def test_gossip_dht_multi_hop_routing(monkeypatch):
    from network.config import NetworkConfig
    from network.protocols import TAU_PROTOCOL_GOSSIP

    cfg = NetworkConfig(
        network_id="multi-hop-testnet",
        genesis_hash="genesis_hash_xyz",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )

    from network.service import NetworkService

    svc_a = NetworkService(cfg)
    svc_b = NetworkService(cfg)
    svc_c = NetworkService(cfg)
    await svc_a.start()
    await svc_b.start()
    await svc_c.start()

    try:
        addrs_a = await _wait_for_addrs(svc_a.host)
        addrs_b = await _wait_for_addrs(svc_b.host)
        addrs_c = await _wait_for_addrs(svc_c.host)

        peer_info_b = PeerInfo(svc_b.host.get_id(), addrs_b)
        svc_a.host.get_peerstore().add_addrs(peer_info_b.peer_id, peer_info_b.addrs, 60)
        await svc_a.host.connect(peer_info_b)

        peer_info_c = PeerInfo(svc_c.host.get_id(), addrs_c)
        svc_b.host.get_peerstore().add_addrs(peer_info_c.peer_id, peer_info_c.addrs, 60)
        await svc_b.host.connect(peer_info_c)

        await svc_a.host.get_network().close_peer(svc_b.host.get_id())
        await svc_b.host.get_network().close_peer(svc_a.host.get_id())
        assert not list(svc_a.host.get_connected_peers())

        topic = "multi.hop.route"
        received = trio.Event()
        seen_b = trio.Event()
        latency: Dict[str, Any] = {}

        async def handler_b(envelope):
            if envelope.get("topic") == topic:
                latency.setdefault("b_seen_at", trio.current_time())
                seen_b.set()

        svc_b.subscribe_gossip("*", handler_b)

        async def handler_c(envelope):
            if envelope.get("topic") == topic:
                latency["latency"] = trio.current_time() - latency["start"]
                latency["origin"] = envelope.get("origin")
                latency["via"] = envelope.get("via")
                latency["message_id"] = envelope.get("message_id")
                received.set()

        await svc_c.join_gossip_topic(topic, handler_c)

        latency["start"] = trio.current_time()
        message_id = await svc_a.publish_gossip(
            topic,
            {"value": 999},
        )

        with trio.fail_after(10):
            await seen_b.wait()

        with trio.fail_after(10):
            await received.wait()

        b_seen_time = latency.get("b_seen_at")
        assert b_seen_time is not None
        assert b_seen_time >= latency["start"]
        assert latency["message_id"] == message_id
        assert latency["origin"] == str(svc_a.host.get_id())
        assert latency["latency"] < 5.0
        assert latency["via"] in {
            str(svc_b.host.get_id()),
            str(svc_a.host.get_id()),
        }
        assert str(svc_c.host.get_id()) in svc_a._opportunistic_peers
    finally:
        await svc_c.stop()
        await svc_b.stop()
        await svc_a.stop()


async def test_dht_bucket_refresh_cycle():
    from network.config import NetworkConfig
    from network.service import NetworkService

    cfg = NetworkConfig(
        network_id="metricsnet",
        genesis_hash="0000",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
        dht_refresh_interval=0.01,
        dht_bucket_refresh_interval=0.01,
        dht_bucket_refresh_limit=16,
        dht_stale_peer_threshold=0,
    )
    svc = NetworkService(cfg)

    peer_active = ID(os.urandom(32))
    peer_stale = ID(os.urandom(32))

    class DummyRoutingTable:
        def __init__(self):
            self.added: List[ID] = []
            self.removed: List[ID] = []

        def get_stale_peers(self, threshold: int):
            return [peer_active, peer_stale]

        async def add_peer(self, peer_info):
            self.added.append(peer_info.peer_id)

        def remove_peer(self, peer_id):
            self.removed.append(peer_id)
            return True

    class DummyPeerRouting:
        def __init__(self):
            self.calls: List[ID] = []

        async def find_peer(self, peer_id):
            self.calls.append(peer_id)
            if peer_id == peer_active:
                return PeerInfo(peer_id, [multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/6000")])
            return None

    routing_table = DummyRoutingTable()
    peer_routing = DummyPeerRouting()
    svc._dht = types.SimpleNamespace(routing_table=routing_table, peer_routing=peer_routing)

    results = await svc._refresh_dht_buckets_once()

    assert results["checked"] == 2
    assert results["refreshed"] == 1
    assert results["removed"] == 1
    assert results["errors"] == 0
    assert routing_table.added == [peer_active]
    assert routing_table.removed == [peer_stale]
    assert svc._metric_timestamps["dht_last_bucket_refresh"] > 0
