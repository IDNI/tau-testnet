
import pytest
import pytest
import trio
import sys
import os
import multiaddr

# Ensure we can import from project root
sys.path.append(os.getcwd())

from network.host import HostManager
from network.config import NetworkConfig
from libp2p.rcmgr.manager import ResourceManager

# Define check function
async def check_network_limits():
    # Setup Config
    config = NetworkConfig(
        network_id="test-limits",
        genesis_hash="genesis",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")], # Ephemeral port
        conn_low_water=10,
        conn_high_water=20,
        max_connections=50,
        rate_limit_per_peer=5.0,
        burst_per_peer=15.0
    )

    # Initialize HostManager
    hm = HostManager(config)
    
    # Start (wires everything up)
    await hm.start()
    
    # Access the host and network
    host = hm.host
    assert host is not None, "Host should be initialized"
    
    network = host.get_network()
    assert network is not None, "Network should be available"
    
    # Access Resource Manager
    # In py-libp2p Swarm (network implementation), it's usually `resource_manager` attribute 
    # or accessible via `get_resource_manager()` matches set_resource_manager
    
    # Try attribute first
    rm = getattr(network, "resource_manager", None)
    
    # If not found, try private attribute (common in python impls)
    if rm is None:
        rm = getattr(network, "_resource_manager", None)
        
    assert rm is not None, "ResourceManager should be attached to the network"
    assert isinstance(rm, ResourceManager), "Should be a ResourceManager instance"
    
    # Verify Limits
    
    # 1. Global Max Connections (ResourceLimits)
    # Use config value passed: max_connections=50
    assert rm.limits.max_connections == 50, f"Expected max_connections=50, got {rm.limits.max_connections}"
    
    # 2. Connection Limits (low/high/total)
    cl = rm.connection_limits
    assert cl is not None
    
    # Verifying mappings from HostManager.start():
    # max_established_total = max_connections = 50
    assert cl.max_established_total == 50
    
    # max_established_inbound = conn_high_water = 20
    assert cl.max_established_inbound == 20
    
    # max_established_per_peer = conn_high_water = 20
    assert cl.max_established_per_peer == 20
    
    # max_pending_inbound = conn_low_water = 10
    assert cl.max_pending_inbound == 10
    
    # 3. Rate Limits
    rl = rm.connection_rate_limiter
    assert rl is not None, "Per-peer rate limiter should be enabled"
    
    print("Network limits verification passed!")

def test_run_network_limits():
    trio.run(check_network_limits)

if __name__ == "__main__":
    trio.run(check_network_limits)
