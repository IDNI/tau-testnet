import unittest
from unittest.mock import MagicMock, AsyncMock, patch
import trio
import json
import sys
sys.path.append(".")
from network.gossip import GossipManager

class TestGossipSubscriptions(unittest.TestCase):
    def setUp(self):
        self.host_manager = MagicMock()
        self.host_manager.host.get_id.return_value = "local_peer"
        self.dht_manager = MagicMock()
        self.gossip_manager = GossipManager(self.host_manager, self.dht_manager)
        self.gossip_manager.set_nursery(MagicMock())
        self.gossip_manager._send_gossip = AsyncMock()

    def test_join_topic_broadcasts_subscription(self):
        async def run_test():
            # Mock broadcast_subscriptions since we want to verify it called _send_gossip internally
            # or just let it run. Let's let it run.
            self.host_manager.host.get_connected_peers.return_value = ["peer1", "peer2"]
            
            await self.gossip_manager.join_topic("test_topic", lambda x: None)
            
            await self.gossip_manager.join_topic("test_topic", lambda x: None)
            
            # Should have scheduled send_gossip for 2 peers
            nursery = self.gossip_manager._nursery
            self.assertEqual(nursery.start_soon.call_count, 2)
            
            # Verify payload from the first call
            # call_args[0] -> (func, peer_id, payload)
            args = nursery.start_soon.call_args_list[0][0]
            func = args[0]
            peer_id = args[1]
            payload = args[2]
            
            self.assertEqual(func, self.gossip_manager._send_gossip)
            data = json.loads(payload.decode())
            self.assertEqual(data["rpc"]["subscriptions"][0]["topic"], "test_topic")
            self.assertTrue(data["rpc"]["subscriptions"][0]["subscribe"])

        trio.run(run_test)

    def test_handle_rpc_updates_peer_topics(self):
        async def run_test():
            rpc_data = {
                "subscriptions": [
                    {"topic": "topic_A", "subscribe": True},
                    {"topic": "topic_B", "subscribe": False}
                ]
            }
            sender = "peer_sender"
            
            # Pre-populate map to test unsubscribe
            self.gossip_manager._peer_topics[sender] = {"topic_B"}
            
            await self.gossip_manager.handle_rpc(rpc_data, sender)
            
            # Check topic_A added
            self.assertIn("topic_A", self.gossip_manager._peer_topics[sender])
            # Check topic_B removed
            self.assertNotIn("topic_B", self.gossip_manager._peer_topics[sender])

        trio.run(run_test)

    def test_publish_filters_peers_by_subscription(self):
        async def run_test():
            self.host_manager.host.get_connected_peers.return_value = ["peer1", "peer2", "peer3"]
            
            # Setup subscriptions: peer1=topic1, peer2=None, peer3=topic1
            self.gossip_manager._peer_topics["peer1"] = {"topic1"}
            # peer2 has no subs
            self.gossip_manager._peer_topics["peer3"] = {"topic1"}
            
            await self.gossip_manager.publish("topic1", "payload")
            
            # Should only schedule for peer1 and peer3
            nursery = self.gossip_manager._nursery
            self.assertEqual(nursery.start_soon.call_count, 2)
            
            scheduled_peers = set()
            for call in nursery.start_soon.call_args_list:
                args = call[0]
                # args: (func, peer_id, payload)
                if args[0] == self.gossip_manager._send_gossip:
                    scheduled_peers.add(args[1])
            
            self.assertIn("peer1", scheduled_peers)
            self.assertIn("peer3", scheduled_peers)
            self.assertNotIn("peer2", scheduled_peers)

        trio.run(run_test)

if __name__ == "__main__":
    # Mock sys.modules for missing deps
    import sys
    sys.modules["network.protocols"] = MagicMock()
    unittest.main()
