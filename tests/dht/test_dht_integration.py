import json
from typing import List

import multiaddr
import pytest
import trio
from libp2p.peer.peerinfo import PeerInfo

from network.config import NetworkConfig
from network.service import NetworkService


pytestmark = pytest.mark.trio


async def _wait_for_listen_addrs(host, timeout: float = 5.0) -> List[multiaddr.Multiaddr]:
    with trio.fail_after(timeout):
        while True:
            addrs = list(host.get_addrs() or [])
            if addrs:
                return [multiaddr.Multiaddr(str(addr)) for addr in addrs]
            await trio.sleep(0.05)


@pytest.fixture
async def dht_two_nodes():
    cfg_kwargs = {
        "network_id": "dht-testnet",
        "genesis_hash": "genesis",
        "listen_addrs": [multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
        "bootstrap_peers": [],
        "peerstore_path": None,
        "identity_key": None,
        "dht_record_ttl": 60,
        "dht_validator_namespaces": ["block", "tx", "state"],
        "dht_bootstrap_peers": [],
    }

    svc1 = NetworkService(NetworkConfig(**cfg_kwargs))
    svc2 = NetworkService(NetworkConfig(**cfg_kwargs))
    await svc1.start()
    await svc2.start()
    try:
        addrs1 = await _wait_for_listen_addrs(svc1.host)
        addrs2 = await _wait_for_listen_addrs(svc2.host)

        peer_info2 = PeerInfo(svc2.host.get_id(), addrs2)
        svc1.host.get_peerstore().add_addrs(peer_info2.peer_id, peer_info2.addrs, 60)
        await svc1.host.connect(peer_info2)

        peer_info1 = PeerInfo(svc1.host.get_id(), addrs1)
        svc2.host.get_peerstore().add_addrs(peer_info1.peer_id, peer_info1.addrs, 60)
        await svc2.host.connect(peer_info1)

        if svc1._dht is not None:
            await svc1._dht.add_peer(peer_info2.peer_id)  # type: ignore[func-returns-value]
        if svc2._dht is not None:
            await svc2._dht.add_peer(peer_info1.peer_id)  # type: ignore[func-returns-value]
        yield svc1, svc2
    finally:
        await svc1.stop()
        await svc2.stop()


async def test_dht_value_propagation(dht_two_nodes):
    svc1, svc2 = dht_two_nodes
    assert svc1._dht is not None and svc2._dht is not None  # type: ignore[attr-defined]

    block_hash = "abc123"
    key = f"/block/{block_hash}"
    payload = json.dumps({"block_hash": block_hash}).encode()

    await svc1._dht.put_value(key, payload)  # type: ignore[call-arg]
    await trio.sleep(1.0)

    result = await svc2._dht.get_value(key)  # type: ignore[call-arg]
    assert result == payload


async def test_dht_provider_propagation(dht_two_nodes):
    svc1, svc2 = dht_two_nodes
    assert svc1._dht is not None and svc2._dht is not None  # type: ignore[attr-defined]

    block_hash = "abc123"
    key = f"/block/{block_hash}"
    payload = json.dumps({"block_hash": block_hash}).encode()

    await svc1._dht.put_value(key, payload)  # type: ignore[call-arg]
    await svc1._dht.provide(key)  # type: ignore[call-arg]
    await trio.sleep(1.5)

    providers = await svc2._dht.find_providers(key)  # type: ignore[call-arg]
    ids = {provider.peer_id for provider in providers}
    assert svc1.host.get_id() in ids
