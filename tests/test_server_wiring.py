import unittest
from unittest.mock import MagicMock, patch
import sys
import threading
import trio
import time

import server
from network import bus
# Import real class for unit testing
from network.service import NetworkService

class TestServerWiring(unittest.TestCase):
    def setUp(self):
        # Clear bus
        bus.unregister(bus.get())
        
    def tearDown(self):
        bus.unregister(bus.get())

    def test_runner_registers_service_with_bus(self):
        # We want to test the _runner logic inside server._start_network_background
        # But _start_network_background starts a thread.
        # We can extract the inner _runner if possible, but it's local.
        # So we mock threading.Thread to capture the target.
        
        container = MagicMock()
        container.build_network_config.return_value = MagicMock()
        container.chain_state = MagicMock()
        
        # Mock NetworkService constructor to return a dummy
        mock_service = MagicMock()
        mock_service._dht_manager = MagicMock()
        
        with patch("server.NetworkService", return_value=mock_service) as mock_cls:
            with patch("threading.Thread") as mock_thread_cls:
                server._start_network_background(container)
                
                # Get the target function passed to Thread
                args, kwargs = mock_thread_cls.call_args
                target = kwargs.get("target")
                
                # Execute the runner (simulating the thread start)
                # It spawns trio.run. We mock trio.run too to avoid actual async execution
                with patch("trio.run") as mock_trio_run:
                    target()
                    
                    # Verify NetworkService was instantiated
                    mock_cls.assert_called_once()
                    
                    # Verify bus has the service
                    registered_service = bus.get()
                    self.assertIsNotNone(registered_service, "Service should be registered with bus")
                    self.assertEqual(registered_service, mock_service, "Registered service should match the created instance")

    def test_broadcast_transaction_thread_safety(self):
        # We want to verify that broadcast_transaction can be called from a thread
        # and it schedules work on the trio loop via logic similar to what we implemented.
        
        # 1. Setup mock service with a mock token
        # We instantiate the REAL NetworkService but mock its init to avoid side effects
        with patch.object(NetworkService, "__init__", return_value=None):
            service = NetworkService()
            
            mock_nursery = MagicMock()
            mock_token = MagicMock()
            mock_gossip = MagicMock()
            
            service._nursery = mock_nursery
            service._trio_token = mock_token
            service._gossip_manager = mock_gossip
            
            # 2. Call broadcast_transaction (simulating call from any thread)
            payload = "test_payload"
            msg_id = "test_id"
            service.broadcast_transaction(payload, msg_id)
            
            # 3. Verify it called run_sync_soon on the token
            mock_token.run_sync_soon.assert_called_once()
            args, _ = mock_token.run_sync_soon.call_args
            # args[0] should be nursery.start_soon
            self.assertEqual(args[0], mock_nursery.start_soon)
            # args[1] should be gossip.publish
            self.assertEqual(args[1], mock_gossip.publish)
            # args[2] should be the topic constant
            from network.protocols import TAU_GOSSIP_TOPIC_TRANSACTIONS
            self.assertEqual(args[2], TAU_GOSSIP_TOPIC_TRANSACTIONS)


if __name__ == "__main__":
    unittest.main()
