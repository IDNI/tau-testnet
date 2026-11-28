"""A node does not store, dial or send non-public addrs of public peers."""

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import multiaddr
import pytest
from libp2p.crypto.ed25519 import create_new_key_pair
from libp2p.identity.identify.pb.identify_pb2 import Identify
from libp2p.identity.update import update_peerstore_from_identify
from libp2p.peer.id import ID
from libp2p.peer.peerinfo import PeerInfo
from libp2p.peer.peerstore import PeerStore

from network.config import BootstrapPeer, NetworkConfig
from network.discovery import DiscoveryManager
from network.host import HostManager
from network.libp2p_compat import seed_peerstore_persisted
from network.peer_addrs import FilteringPeerStore, PeerAddrPolicy, is_public_addr
from network.service import NetworkService

PUBLIC = "/ip4/34.251.82.246/tcp/4001"
OTHER_PUBLIC = "/ip4/34.251.82.247/tcp/4001"
UNSPECIFIED = "/ip4/0.0.0.0/tcp/4001"
LOOPBACK = "/ip4/127.0.0.1/tcp/4001"
PRIVATE = "/ip4/10.0.0.5/tcp/4001"


def _new_pid() -> ID:
    return ID.from_pubkey(create_new_key_pair().public_key)


def _config(listen=("/ip4/0.0.0.0/tcp/4001",), bootstrap=(), allow=None) -> NetworkConfig:
    return NetworkConfig(
        network_id="addr-policy-test",
        listen_addrs=[multiaddr.Multiaddr(a) for a in listen],
        bootstrap_peers=list(bootstrap),
        allow_private_peer_addrs=allow,
        genesis_hash="g",
    )


def _boot_config(boot: ID, addr: str = PUBLIC, allow=None) -> NetworkConfig:
    return _config(bootstrap=[BootstrapPeer(str(boot), [multiaddr.Multiaddr(addr)])], allow=allow)


def _peerstore(config: NetworkConfig) -> FilteringPeerStore:
    return FilteringPeerStore(PeerAddrPolicy.from_config(config))


def _host_with(peerstore: PeerStore) -> MagicMock:
    host = MagicMock()
    host.get_peerstore.return_value = peerstore
    return host


def _stored(peerstore: PeerStore, pid: ID):
    try:
        return [str(a) for a in peerstore.addrs(pid)]
    except Exception:
        return []


@pytest.mark.parametrize(
    "addr,public",
    [
        (PUBLIC, True),
        (UNSPECIFIED, False),
        (LOOPBACK, False),
        (PRIVATE, False),
        ("/ip4/192.168.1.2/tcp/4001", False),
        ("/ip4/169.254.1.1/tcp/4001", False),
        ("/ip6/::/tcp/4001", False),
        ("/ip6/::1/tcp/4001", False),
        ("/ip6/fd00::1/tcp/4001", False),
        ("/ip6/fe80::1/tcp/4001", False),
        ("/ip6/::ffff:127.0.0.1/tcp/4001", False),
        ("/ip6/2a00:1450:4001::1/tcp/4001", True),
        ("/dns4/boot.example.org/tcp/4001", True),
    ],
)
def test_is_public_addr(addr, public):
    assert is_public_addr(addr) is public


def test_public_node_refuses_non_public_learned_addrs():
    policy = PeerAddrPolicy.from_config(_config())
    assert policy.allow_private is False
    pid = _new_pid()
    kept = policy.filter(pid, [UNSPECIFIED, LOOPBACK, PRIVATE, PUBLIC, "not an addr"])
    assert [str(a) for a in kept] == [PUBLIC]


def test_loopback_listener_means_local_network():
    policy = PeerAddrPolicy.from_config(_config(listen=["/ip4/127.0.0.1/tcp/0"]))
    assert policy.allow_private is True
    assert [str(a) for a in policy.filter(_new_pid(), [LOOPBACK, PRIVATE])] == [LOOPBACK, PRIVATE]


def test_unparsable_addrs_are_not_usable():
    cfg = SimpleNamespace(
        listen_addrs=["not an addr"],
        bootstrap_peers=[{"peer_id": str(_new_pid()), "addrs": ["not an addr"]}],
        dht_bootstrap_peers=[{"addrs": [PUBLIC]}],
    )
    policy = PeerAddrPolicy.from_config(cfg)
    assert policy.allow_private is False
    assert policy.is_usable(_new_pid(), "not an addr") is False


def test_explicit_setting_wins_over_auto():
    cfg = _config(listen=["/ip4/127.0.0.1/tcp/0"], allow=False)
    assert PeerAddrPolicy.from_config(cfg).allow_private is False
    assert PeerAddrPolicy.from_config(_config(allow=True)).allow_private is True


def test_configured_bootstrap_private_addr_stays_usable():
    boot = _new_pid()
    policy = PeerAddrPolicy.from_config(_boot_config(boot, PRIVATE, allow=False))
    assert policy.is_usable(boot, PRIVATE)
    assert policy.is_usable(boot, f"{PRIVATE}/p2p/{boot}")
    assert not policy.is_usable(boot, LOOPBACK)
    assert not policy.is_usable(_new_pid(), PRIVATE)


def test_configured_bootstrap_addr_with_p2p_suffix_stays_usable():
    boot = _new_pid()
    policy = PeerAddrPolicy.from_config(_boot_config(boot, f"{PRIVATE}/p2p/{boot}", allow=False))
    assert policy.is_usable(boot, PRIVATE)
    assert policy.is_usable(boot, f"{PRIVATE}/p2p/{boot}")
    assert not policy.is_usable(_new_pid(), PRIVATE)


@pytest.mark.parametrize(
    "raw,expected",
    [("true", True), ("1", True), ("false", False), ("auto", None), ("", None), ("ture", False)],
)
def test_allow_private_peer_addrs_env_parse(monkeypatch, raw, expected):
    import config

    monkeypatch.setenv("TAU_ALLOW_PRIVATE_PEER_ADDRS", raw)
    assert config._overrides_from_env()["network"]["allow_private_peer_addrs"] is expected


def test_peerstore_stores_only_usable_addrs():
    peerstore = _peerstore(_config())
    pid = _new_pid()
    peerstore.add_addr(pid, multiaddr.Multiaddr(UNSPECIFIED), 600)
    assert _stored(peerstore, pid) == []
    peerstore.add_addrs(pid, [multiaddr.Multiaddr(a) for a in (LOOPBACK, PUBLIC)], 600)
    assert _stored(peerstore, pid) == [PUBLIC]


@pytest.mark.trio
async def test_host_manager_uses_filtering_peerstore():
    manager = HostManager(_config(listen=["/ip4/0.0.0.0/tcp/0"]))
    await manager.start()
    assert isinstance(manager.host.get_peerstore(), FilteringPeerStore)


def _identify(*addrs: str) -> Identify:
    return Identify(listen_addrs=[multiaddr.Multiaddr(a).to_bytes() for a in addrs])


@pytest.mark.trio
async def test_identify_with_unspecified_addr_stores_no_such_addr():
    peer = _new_pid()
    peerstore = _peerstore(_config())
    peerstore.add_addrs(peer, [multiaddr.Multiaddr(OTHER_PUBLIC)], 600)
    await update_peerstore_from_identify(peerstore, peer, _identify(UNSPECIFIED, LOOPBACK))
    assert _stored(peerstore, peer) == []


@pytest.mark.trio
async def test_identify_keeps_configured_bootstrap_addr_first():
    boot = _new_pid()
    peerstore = _peerstore(_boot_config(boot))
    peerstore.add_addrs(boot, [multiaddr.Multiaddr(PUBLIC)], 86400)
    await update_peerstore_from_identify(peerstore, boot, _identify(UNSPECIFIED, OTHER_PUBLIC))
    assert _stored(peerstore, boot) == [PUBLIC, OTHER_PUBLIC]


def test_clear_addrs_keeps_only_configured_bootstrap_addrs():
    boot, other = _new_pid(), _new_pid()
    peerstore = _peerstore(_boot_config(boot))
    peerstore.add_addrs(boot, [multiaddr.Multiaddr(OTHER_PUBLIC)], 600)
    peerstore.add_addrs(other, [multiaddr.Multiaddr(OTHER_PUBLIC)], 600)
    peerstore.clear_addrs(boot)
    peerstore.clear_addrs(other)
    assert _stored(peerstore, boot) == [PUBLIC]
    assert _stored(peerstore, other) == []


def test_peer_gossip_ingest_stores_only_public_addrs():
    peerstore = _peerstore(_config())
    host_manager = MagicMock()
    host_manager.host = _host_with(peerstore)
    discovery = DiscoveryManager(_config(), host_manager, MagicMock())
    bad, loop, good = _new_pid(), _new_pid(), _new_pid()

    discovery.ingest_peer_entries(
        [
            {"peer_id": str(bad), "addrs": [UNSPECIFIED]},
            {"peer_id": str(loop), "addrs": [LOOPBACK]},
            {"peer_id": str(good), "addrs": [UNSPECIFIED, PUBLIC]},
        ],
        "peer_gossip",
    )

    assert _stored(peerstore, bad) == []
    assert _stored(peerstore, loop) == []
    assert _stored(peerstore, good) == [PUBLIC]


def test_persisted_unspecified_addr_is_not_loaded():
    peerstore = _peerstore(_config())
    bad, good = _new_pid(), _new_pid()
    persistence = MagicMock()
    persistence.load.return_value = {str(bad): [UNSPECIFIED], str(good): [UNSPECIFIED, PUBLIC]}

    seed_peerstore_persisted(_host_with(peerstore), persistence)

    assert _stored(peerstore, bad) == []
    assert _stored(peerstore, good) == [PUBLIC]


def _service(config: NetworkConfig) -> NetworkService:
    import trio

    svc = object.__new__(NetworkService)
    svc._config = config
    svc._addr_policy = PeerAddrPolicy.from_config(config)
    svc._runner_stop = trio.Event()
    svc._dht_manager = MagicMock()
    svc._dht_manager.dht = None
    return svc


@pytest.mark.trio
async def test_opportunistic_seed_drops_loopback_of_public_peer():
    # A plain PeerStore: the call site filters, because the routing table
    # keeps its own copy of the addrs.
    peerstore = PeerStore()
    host = _host_with(peerstore)
    svc = _service(_config())
    pid = _new_pid()
    with patch.object(NetworkService, "host", new=property(lambda self: host)):
        await NetworkService._opportunistic_seed_peer(svc, pid, [LOOPBACK, PUBLIC])
    assert _stored(peerstore, pid) == [PUBLIC]


async def _dial_bootstrap(config: NetworkConfig, peerstore: FilteringPeerStore, boot: ID, configured):
    host = _host_with(peerstore)
    seen = {}

    async def connect(peer_info):
        seen["dial_order"] = _stored(peerstore, peer_info.peer_id)

    host.connect = connect
    svc = _service(config)
    with patch.object(NetworkService, "host", new=property(lambda self: host)), \
         patch.object(NetworkService, "get_id", lambda self: "self-id"):
        await NetworkService._connect_to_bootstrap_peer(
            svc, {"peer_id": str(boot), "addrs": list(configured)}
        )
    return seen["dial_order"]


@pytest.mark.trio
async def test_bootstrap_dial_uses_configured_addr_first_after_identify():
    boot = _new_pid()
    config = _boot_config(boot)
    peerstore = _peerstore(config)
    await update_peerstore_from_identify(peerstore, boot, _identify(UNSPECIFIED, OTHER_PUBLIC))

    order = await _dial_bootstrap(config, peerstore, boot, [PUBLIC])
    assert order == [PUBLIC, OTHER_PUBLIC]


@pytest.mark.trio
async def test_bootstrap_dial_at_configured_private_addr():
    boot = _new_pid()
    config = _boot_config(boot, PRIVATE, allow=False)
    peerstore = _peerstore(config)
    peerstore.add_addrs(boot, [multiaddr.Multiaddr(LOOPBACK)], 600)
    order = await _dial_bootstrap(config, peerstore, boot, [PRIVATE])
    assert order == [PRIVATE]


def _own_host(*bound: str) -> MagicMock:
    host = MagicMock()
    host.get_id.return_value = _new_pid()
    host.get_addrs.return_value = [multiaddr.Multiaddr(a) for a in bound]
    return host


def _advertised(config: NetworkConfig, host: MagicMock):
    svc = _service(config)
    with patch.object(NetworkService, "host", new=property(lambda self: host)):
        return NetworkService._self_advertised_addrs(svc)


def test_node_on_unspecified_addr_without_announce_sends_no_addr():
    assert _advertised(_config(), _own_host(UNSPECIFIED, LOOPBACK)) == []


def test_node_sends_its_announce_addr():
    config = _config()
    config.announce_addrs = [multiaddr.Multiaddr(PUBLIC)]
    assert _advertised(config, _own_host(UNSPECIFIED)) == [PUBLIC]


def test_node_sends_its_public_bound_addr():
    assert _advertised(_config(), _own_host(UNSPECIFIED, PUBLIC)) == [PUBLIC]


def test_local_network_node_sends_its_private_addr():
    assert _advertised(_config(listen=(PRIVATE,)), _own_host(PRIVATE)) == [PRIVATE]


def test_handshake_dht_peers_hold_only_usable_addrs():
    svc = _service(_config())
    mixed, local_only = _new_pid(), _new_pid()
    bucket = SimpleNamespace(peers=[
        PeerInfo(mixed, [multiaddr.Multiaddr(UNSPECIFIED), multiaddr.Multiaddr(PUBLIC)]),
        PeerInfo(local_only, [multiaddr.Multiaddr(LOOPBACK)]),
    ])
    svc._dht_manager = MagicMock()
    svc._dht_manager.routing_table.buckets = [bucket]
    svc._dht_manager.dht.value_store.get.return_value = None
    host = _own_host(UNSPECIFIED)
    with patch.object(NetworkService, "host", new=property(lambda self: host)), \
         patch.object(NetworkService, "get_id", lambda self: host.get_id()):
        payload = NetworkService._build_handshake_payload(svc)
    assert payload["dht_peers"] == [{"peer_id": str(mixed), "addrs": [PUBLIC]}]


def test_dht_self_provider_entry_holds_only_usable_addrs():
    from network.dht_manager import DHTManager

    dm = DHTManager(_config())
    dm._dht = MagicMock()
    dm._host = _own_host(UNSPECIFIED, PUBLIC)
    assert dm.put_record_sync(b"state:abc", b"v")
    (_, provider), _ = dm._dht.provider_store.add_provider.call_args
    assert [str(a) for a in provider.addrs] == [PUBLIC]
