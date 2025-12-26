
import pytest
import trio
import sys
from unittest.mock import MagicMock, patch, AsyncMock
from network.service import NetworkService, MAX_HANDSHAKE_PROVIDERS
from network.config import NetworkConfig

@pytest.fixture
def mock_config():
    config = MagicMock(spec=NetworkConfig)
    config.network_id = "test-net"
    config.agent = "test-agent"
    config.genesis_hash = "genesis123"
    config.bootstrap_peers = []
    config.dht_bootstrap_peers = []
    config.peer_advertisement_interval = 0
    return config

@pytest.fixture
def service(mock_config):
    with patch("network.service.HostManager") as MockHostManager, \
         patch("network.service.DHTManager"), \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager"):
        
        # Configure HostManager instance to have a 'host' attribute
        mock_host_instance = MockHostManager.return_value
        mock_host = MagicMock()
        mock_host.get_id.return_value = "local_peer_id"
        mock_host_instance.host = mock_host

        svc = NetworkService(mock_config)
        # svc.host is a property delegating to _host_manager.host, which is set above.
        
        # Mock get_id directly on service if it exists/delegates
        svc.get_id = MagicMock(return_value="local_peer_id")
        return svc

def test_outbound_handshake_capping(service):
    """Verify that _build_handshake_payload caps the number of providers."""
    # Setup DHT mock
    dht = MagicMock()
    service._dht_manager.dht = dht
    
    # 1. Setup Provider Store with 100 entries (spam)
    spam_providers = {}
    for i in range(100):
        key_bytes = f"spam_prov_{i}".encode('utf-8')
        pi = MagicMock()
        pi.peer_id = f"peer_{i}"
        pi.addrs = []
        # provider_store needs to return proper objects if attributes are accessed
        spam_providers[key_bytes] = [pi]
        
    dht.provider_store.providers = spam_providers
    
    # 2. Setup Value Store with critical keys + more spam
    critical_keys = {
        b"/state/head123": "val",
        b"/state/genesis123": "val",
        # b"formula:rule1": "val", # Formula keys not prioritized anymore in service.py
    }
    spam_values = {}
    for i in range(100):
        key_bytes = f"/state/spam_{i}".encode('utf-8')
        spam_values[key_bytes] = "val"
        
    all_values = {**critical_keys, **spam_values}
    
    # Mock value_store.get to return if in dict
    dht.value_store.get.side_effect = lambda k: all_values.get(k)
    dht.value_store.store = all_values 
    # dht.value_store.get_keys.return_value = list(all_values.keys()) # Not used anymore
    
    # Mock encoding helper to match expectations
    # The service calls _dht_manager._encode_dht_key(ns, hash)
    # We should let the real DHTManager do it or mock it if we patched DHTManager?
    # We patched DHTManager in the fixture, but in the test we set service._dht_manager.dht
    # service._dht_manager itself is a Mock from the fixture.
    # So we need to ensure _encode_dht_key works.
    service._dht_manager._encode_dht_key.side_effect = lambda ns, sfx: f"/{ns}/{sfx}".encode("utf-8")
    
    service._config.genesis_hash = "genesis123"
    # Mock db.get_latest_block in sys.modules
    mock_db = MagicMock()
    mock_db.get_latest_block.return_value = {
        "header": {"block_number": 10},
        "block_hash": "head123"
    }
    
    with patch.dict(sys.modules, {"db": mock_db}):
        # Build payload
        payload = service._build_handshake_payload()
        
        providers = payload.get("dht_providers", [])
        
        # Assertion 1: Capped size
        print(f"Providers count: {len(providers)}")
        assert len(providers) <= MAX_HANDSHAKE_PROVIDERS
        assert len(providers) > 0
        
        # Assertion 2: Critical keys present
        keys = [p["key"] for p in providers]
        assert "/state/head123" in keys, "Head state key missing"
        assert "/state/genesis123" in keys, "Genesis state key missing"
        # assert "formula:rule1" in keys, "Formula key missing"
        
        # Assertion 3: Rest are filled? 
        # Actually, new logic only advertises specific prioritized keys + local provider.
        # It does NOT scan the whole value store anymore.
        # So we expect ONLY the critical keys we found locally.
        assert len(providers) == 2 # head + genesis (ourselves)
        # Note: Previous test expected 50 (MAX). New logic is deterministic and small.
        assert len(providers) <= MAX_HANDSHAKE_PROVIDERS

@pytest.mark.trio
async def test_inbound_handshake_truncation(service):
    """Verify that _handle_handshake truncates incoming peers and providers."""
    # Mock stream with AsyncMock methods
    stream = MagicMock()
    # async read/write/close
    stream.read = AsyncMock()
    stream.write = AsyncMock()
    stream.close = AsyncMock()
    
    import json
    
    # Create oversized payload
    # 200 peers
    peers = [{"peer_id": f"peer_{i}", "addrs": []} for i in range(200)]
    # 200 providers
    providers = [{"key": f"key_{i}", "providers": [{"peer_id": f"p_{i}", "addrs": []}]} for i in range(200)]
    
    payload = {
        "dht_peers": peers,
        "dht_providers": providers
    }
    
    stream.read.return_value = json.dumps(payload).encode()
    
    # Mock DHT/host to capture calls
    service._dht_manager.dht = MagicMock()
    # Mock routing_table and provider_store
    
    # Run handler
    # We must patch multiaddr and libp2p.peer.id/peerinfo because _handle_handshake imports them
    # locally or assumes they are available.
    with patch.dict(sys.modules, {
        "db": MagicMock(),  # needed for creating response tip
        "multiaddr": MagicMock(),
        "libp2p.peer.id": MagicMock(),
        "libp2p.peer.peerinfo": MagicMock()
    }):
        # Mock ID.from_base58 to return valid ID Mock
        mock_id_cls = sys.modules["libp2p.peer.id"].ID
        mock_id_cls.from_base58.side_effect = lambda x: MagicMock()
        
        await service._handle_handshake(stream)
    
    # The truncation happens BEFORE creating PeerInfo/ID objects in the loop
    # So we can check valid calls.
    
    # Verify Peer Truncation (Max 100)
    # The code calls: self.host.get_peerstore().add_addrs(pid, maddrs, 600)
    # for each valid peer.
    add_addrs = service.host.get_peerstore().add_addrs
    assert add_addrs.call_count <= 100
    
    # Verify Provider Truncation (MAX + 10 = 60)
    # The code calls: self._dht_manager.dht.provider_store.add_provider(key, pi)
    add_provider = service._dht_manager.dht.provider_store.add_provider
    assert add_provider.call_count <= MAX_HANDSHAKE_PROVIDERS + 10
