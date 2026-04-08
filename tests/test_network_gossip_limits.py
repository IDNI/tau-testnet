import pytest
import trio
import json
from unittest.mock import Mock

from network.service import NetworkService
from network.config import NetworkConfig
from network.protocols import (
    TAU_GOSSIP_MAX_RAW_TX_BYTES,
    TAU_MAX_USER_TX_BYTES,
    TAU_MAX_GOVERNANCE_VOTE_BYTES,
    TAU_MAX_GOVERNANCE_UPDATE_BYTES,
    TAU_GOSSIP_TOPIC_TRANSACTIONS,
    TAU_GOSSIP_TOPIC_GOVERNANCE
)

@pytest.fixture
def network_service():
    import multiaddr
    config = NetworkConfig(
        network_id="test", 
        genesis_hash="genesis",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]
    )
    svc = NetworkService(config)
    svc._queue_tx = Mock()
    return svc

@pytest.mark.trio
async def test_raw_payload_size_limit(network_service):
    # Oversized raw payload is dropped before JSON decode
    oversized_payload = "x" * (TAU_GOSSIP_MAX_RAW_TX_BYTES + 1)
    await network_service._process_gossip_payload(
        {"payload": oversized_payload}, 
        {"user_tx"},
        {"user_tx": TAU_MAX_USER_TX_BYTES}
    )
    network_service._queue_tx.assert_not_called()

@pytest.mark.trio
async def test_governance_update_size_limit(network_service):
    # Oversized consensus_rule_update dropped after extraction
    payload_dict = {
        "tx_type": "consensus_rule_update",
        "some_data": "x" * (TAU_MAX_GOVERNANCE_UPDATE_BYTES + 1)
    }
    await network_service._on_governance_gossip({"payload": payload_dict})
    network_service._queue_tx.assert_not_called()

@pytest.mark.trio
async def test_governance_update_within_limits(network_service):
    payload_dict = {
        "tx_type": "consensus_rule_update",
        "rule_revisions": ["123"],
        "activate_at_height": 100,
        "some_data": "x" * 100
    }
    await network_service._on_governance_gossip({"payload": payload_dict})
    network_service._queue_tx.assert_called_once()
    
@pytest.mark.trio
async def test_unknown_tx_type_dropped(network_service):
    payload_dict = {
        "tx_type": "unknown_type",
        "data": "123"
    }
    await network_service._on_transaction_gossip({"payload": payload_dict})
    network_service._queue_tx.assert_not_called()

@pytest.mark.trio
async def test_legacy_consensus_proposal_dropped(network_service):
    payload_dict = {
        "tx_type": "consensus_proposal",
        "bundle": {}
    }
    await network_service._on_transaction_gossip({"payload": payload_dict})
    network_service._queue_tx.assert_not_called()

@pytest.mark.trio
async def test_topic_mismatch_dropped(network_service):
    # user_tx inside tau/governance/2.0.0 is dropped
    payload_dict = {
        "tx_type": "user_tx",
        "data": "123"
    }
    await network_service._on_governance_gossip({"payload": payload_dict})
    network_service._queue_tx.assert_not_called()

@pytest.mark.trio
async def test_mempool_snapshot_bounds(network_service, monkeypatch):
    import db
    
    txs = []
    # Mix payloads
    for i in range(100):
        txs.append(json.dumps({"tx_type": "consensus_rule_update", "id": i}))
    for i in range(100):
        txs.append(json.dumps({"tx_type": "consensus_rule_vote", "id": i}))
    for i in range(300):
        txs.append(json.dumps({"tx_type": "user_tx", "id": i}))
        
    def mock_get_mempool_txs():
        return txs
        
    monkeypatch.setattr(db, "get_mempool_txs", mock_get_mempool_txs)
    
    class AsyncMock:
        def __init__(self):
             self.calls = []
        async def __call__(self, topic, payload, target_peers=None):
             self.calls.append((topic, payload))
             
    amock = AsyncMock()
    network_service.publish_gossip = amock
    
    await network_service._send_mempool_snapshot("peer_1")
    
    # Analyze calls
    calls = amock.calls
    assert len(calls) == 200 # TAU_MEMPOOL_SNAPSHOT_MAX_TOTAL
    
    updates = [c for c in calls if c[0] == TAU_GOSSIP_TOPIC_GOVERNANCE and c[1].get("tx_type") == "consensus_rule_update"]
    assert len(updates) == 32 # TAU_MEMPOOL_SNAPSHOT_MAX_UPDATES
    
    votes = [c for c in calls if c[0] == TAU_GOSSIP_TOPIC_GOVERNANCE and c[1].get("tx_type") == "consensus_rule_vote"]
    assert len(votes) == 64 # TAU_MEMPOOL_SNAPSHOT_MAX_VOTES
    
    user_txs = [c for c in calls if c[0] == TAU_GOSSIP_TOPIC_TRANSACTIONS and c[1].get("tx_type") == "user_tx"]
    assert len(user_txs) == 104 # 200 - 32 - 64

@pytest.mark.trio
async def test_lightweight_structural_rejection(network_service):
    # consensus_rule_update missing rule_revisions
    payload1 = {"tx_type": "consensus_rule_update", "activate_at_height": 100}
    await network_service._on_governance_gossip({"payload": payload1})
    network_service._queue_tx.assert_not_called()

    # consensus_rule_vote missing update_id
    payload2 = {"tx_type": "consensus_rule_vote", "approve": True}
    await network_service._on_governance_gossip({"payload": payload2})
    network_service._queue_tx.assert_not_called()
    
    # consensus_rule_vote approve=false
    payload3 = {"tx_type": "consensus_rule_vote", "update_id": "123", "approve": False}
    await network_service._on_governance_gossip({"payload": payload3})
    network_service._queue_tx.assert_not_called()
    
    # Valid
    payload4 = {"tx_type": "consensus_rule_vote", "update_id": "123", "approve": True}
    await network_service._on_governance_gossip({"payload": payload4})
    assert network_service._queue_tx.call_count == 1

@pytest.mark.trio
async def test_protocol_version_gate(network_service):
    class MockStream:
        def __init__(self):
            self.closed = False
            self.muxed_conn = Mock(peer_id="peer2")
        async def close(self):
            self.closed = True
            
        async def read(self, *args):
            return json.dumps({"network_id": "tau-legacy-1"}).encode()
            
        async def write(self, *args):
            pass
            
    stream = MockStream()
    await network_service._handle_handshake(stream)
    assert stream.closed is True
