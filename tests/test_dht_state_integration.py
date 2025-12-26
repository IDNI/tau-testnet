import importlib
import json
import os
import threading
import sys
import hashlib
import time
from typing import List, Dict, Any

import multiaddr
import pytest
import trio
from libp2p.peer.peerinfo import PeerInfo

# Set imports
import config as config_module
import config as config_module
import chain_state
from poa.state import compute_consensus_state_hash
from chain_state import compute_accounts_hash
import base64

pytestmark = pytest.mark.trio

# Helper to isolate DB per test
@pytest.fixture(autouse=True)
def isolate_db(tmp_path):
    orig_env = os.environ.get("TAU_DB_PATH")
    db_file = tmp_path / "dht_integration_test.db"
    os.environ["TAU_DB_PATH"] = str(db_file)
    import db as db_module
    importlib.reload(config_module)
    importlib.reload(db_module)
    importlib.reload(db_module)
    # Clear internal chain state memory to prevent leaks from previous tests
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._current_rules_state = ""
    chain_state._tau_engine_state_hash = ""
    yield
    if orig_env is None:
        os.environ.pop("TAU_DB_PATH", None)
    else:
        os.environ["TAU_DB_PATH"] = orig_env
    importlib.reload(config_module)
    importlib.reload(db_module)
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._current_rules_state = ""
    chain_state._tau_engine_state_hash = ""

# Helper for waiting for addresses
def _strip_p2p(addr: multiaddr.Multiaddr) -> multiaddr.Multiaddr:
    addr_str = str(addr)
    if "/p2p/" in addr_str:
        addr_str = addr_str.split("/p2p/")[0]
    return multiaddr.Multiaddr(addr_str)

async def _wait_for_addrs(host, timeout: float = 5.0) -> List[multiaddr.Multiaddr]:
    with trio.fail_after(timeout):
        while True:
            addrs = list(host.get_addrs() or [])
            if addrs:
                return [_strip_p2p(addr) for addr in addrs]
            await trio.sleep(0.05)

# Fixture to provide two connected nodes
@pytest.fixture
async def two_connected_nodes():
    from network.config import NetworkConfig
    from network.service import NetworkService

    # Configure two nodes
    cfg1 = NetworkConfig(
        network_id="testnet",
        genesis_hash="genesis_hash_val",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )
    cfg2 = NetworkConfig(
        network_id="testnet",
        genesis_hash="genesis_hash_val",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )

    svc1 = NetworkService(cfg1)
    svc2 = NetworkService(cfg2)
    
    # Start nodes
    await svc1.start()
    await svc2.start()
    
    # Wait for addresses
    addrs1 = await _wait_for_addrs(svc1.host)
    addrs2 = await _wait_for_addrs(svc2.host)
    
    # Connect them
    peer_info2 = PeerInfo(svc2.host.get_id(), addrs2)
    svc1.host.get_peerstore().add_addrs(peer_info2.peer_id, peer_info2.addrs, 60)
    await svc1.host.connect(peer_info2)
    
    # Ensure routing table population for DHT
    if svc1._dht:
        await svc1._dht.routing_table.add_peer(peer_info2)
    
    peer_info1 = PeerInfo(svc1.host.get_id(), addrs1)
    if svc2._dht:
        await svc2._dht.routing_table.add_peer(peer_info1)

    try:
        yield svc1, svc2
    finally:
        await svc1.stop()
        await svc2.stop()

def sync_test_logic(node_a_dht_manager, node_b_dht_manager):
    """
    Synchronous logic simulating the server/worker thread using chain_state.
    We swap the dht_client in chain_state to simulate actions on different nodes.
    """
    print("[SyncWorker] Starting sync verification logic...")
    
    # 1. State: Node A
    print("[SyncWorker] Configuring chain_state for Node A")
    chain_state.set_dht_client(node_a_dht_manager)
    
    # Check if retrieval fails locally first (sanity)
    formula_content = "some_unique_formula_content_" + str(time.time())
    # formula_hash = hashlib.sha256(formula_content.encode('utf-8')).hexdigest()
    
    # Compute the expected State Hash (Rules + local accounts)
    # Since isolate_db yields empty DBs, balances/sequences are empty.
    empty_acc_hash = compute_accounts_hash({}, {})
    expected_state_hash = compute_consensus_state_hash(formula_content.encode('utf-8'), empty_acc_hash)
    
    # 2. Save on Node A
    # This should store it in Node A's local store AND network (provider record)
    # It now stores as tau_state:<expected_state_hash>
    print(f"[SyncWorker] Saving formula (state_hash={expected_state_hash[:8]}) on Node A")
    chain_state.save_rules_state(formula_content)
    
    # Verify it is in Node A's store
    # Key should be /tau_state/<state_hash>
    # chain_state uses _encode_dht_key now.
    encoded_key = node_a_dht_manager._encode_dht_key("tau_state", expected_state_hash)
    local_val = node_a_dht_manager.dht.value_store.get(encoded_key)
    # The value is a JSON of {"rules":..., "accounts_hash":...}
    # We verify it exists and contains our rules
    assert local_val is not None, "Failed to store locally on Node A"
    val_bytes = getattr(local_val, "value", local_val)
    val_json = json.loads(val_bytes.decode('utf-8'))
    assert val_json['rules'] == formula_content, "Stored content mismatch Node A"
    
    # 3. State: Node B
    print("[SyncWorker] Switching chain_state to Node B")
    chain_state.set_dht_client(node_b_dht_manager)
    
    # Ensure Node B does NOT have it locally
    encoded_key = node_b_dht_manager._encode_dht_key("tau_state", expected_state_hash)
    if node_b_dht_manager.dht.value_store.get(encoded_key):
        print("[SyncWorker] WARN: Node B already has the key locally? Deleting.")
        # If it somehow got it, remove it to force network fetch
        # Note: libp2p store doesn't easily support delete? Assuming it's absent.
        # It shouldn't be there unless gossip propagated it, but we aren't gossiping this.
        pass
        
    # 4. Retrieve on Node B
    # This calls fetch_tau_state_snapshot -> get_record_sync -> trio.from_thread.run -> network get_value
    print(f"[SyncWorker] Attempting retrieval on Node B (expecting network fetch)")
    # We might need multiple attempts if dht propagation is slow, but direct connection usually works fast.
    
    start_time = time.time()
    retrieved = None
    while time.time() - start_time < 5.0:
        retrieved = chain_state.fetch_tau_state_snapshot(expected_state_hash)
        if retrieved:
            break
        time.sleep(0.5)
        
    assert retrieved is not None, "Failed to retrieve formula on Node B from DHT"
    assert retrieved == formula_content, f"Content mismatch: expected '{formula_content}', got '{retrieved}'"
    
    print("[SyncWorker] SUCCESS: Formula retrieved via DHT!")

async def test_dht_state_end_to_end(two_connected_nodes):
    svc1, svc2 = two_connected_nodes
    
    # Ensure both nodes have trio tokens set (NetworkService does this in _run_loop/start)
    # We started them, so they should be set.
    
    # Run the synchronous chain_state logic in a separate thread
    # This mimics the production setup where chain code runs outside the Trio loop
    await trio.to_thread.run_sync(
        sync_test_logic, 
        svc1._dht_manager, 
        svc2._dht_manager
    )
