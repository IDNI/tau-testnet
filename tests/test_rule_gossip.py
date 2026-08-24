"""Gossip routing and bounds for rule-sharing transactions.

Rule offers ride their own topic so a flood of large offers cannot crowd out
coin-transfer gossip. Each topic's handler enforces its own allow-list, so
publishing to the wrong topic silently drops a transaction at every peer --
which is exactly what used to happen to consensus_rule_vote.
"""
import json
from unittest.mock import MagicMock, patch

import pytest
import trio

from network.config import NetworkConfig
from network.protocols import (
    TAU_GOSSIP_TOPIC_GOVERNANCE,
    TAU_GOSSIP_TOPIC_RULES,
    TAU_GOSSIP_TOPIC_TRANSACTIONS,
    TAU_MAX_RULE_OFFER_BYTES,
    TAU_MEMPOOL_SNAPSHOT_MAX_RULE_TXS,
)
from network.service import NetworkService

A = "aa" * 48
B = "bb" * 48
RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


@pytest.fixture
def service():
    cfg = MagicMock(spec=NetworkConfig)
    cfg.listen_addrs = []
    with patch("network.service.HostManager"), \
         patch("network.service.DHTManager"), \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager"):
        return NetworkService(cfg)


# --- routing ----------------------------------------------------------------

@pytest.mark.parametrize("tx_type,topic", [
    ("user_tx", TAU_GOSSIP_TOPIC_TRANSACTIONS),
    (None, TAU_GOSSIP_TOPIC_TRANSACTIONS),
    ("consensus_rule_update", TAU_GOSSIP_TOPIC_GOVERNANCE),
    # Regression: votes used to go out on the transactions topic, whose handler
    # accepts user_tx only, so every peer dropped them. They propagated solely
    # via the mempool snapshot on a new connection.
    ("consensus_rule_vote", TAU_GOSSIP_TOPIC_GOVERNANCE),
    ("rule_offer", TAU_GOSSIP_TOPIC_RULES),
    ("rule_offer_accept", TAU_GOSSIP_TOPIC_RULES),
    ("rule_offer_reject", TAU_GOSSIP_TOPIC_RULES),
])
def test_topic_for_tx_type(tx_type, topic):
    assert NetworkService.topic_for_tx_type(tx_type) == topic


def test_broadcast_publishes_on_the_routed_topic(service):
    published = []
    service._nursery = MagicMock()
    service._nursery.start_soon.side_effect = lambda fn, topic, payload, mid: published.append(topic)
    service._trio_token = None
    service._gossip_manager = MagicMock()

    for tx_type in ("user_tx", "consensus_rule_vote", "rule_offer"):
        service.broadcast_transaction(json.dumps({"tx_type": tx_type}), "mid")

    assert published == [
        TAU_GOSSIP_TOPIC_TRANSACTIONS,
        TAU_GOSSIP_TOPIC_GOVERNANCE,
        TAU_GOSSIP_TOPIC_RULES,
    ], "the direct-scheduling fallback must honour the routed topic"


# --- topic isolation --------------------------------------------------------

def _envelope(tx):
    return {"payload": json.dumps(tx)}


def _offer(**over):
    tx = {
        "tx_type": "rule_offer",
        "sender_pubkey": A,
        "recipient_pubkey": B,
        "rule_text": RULE,
        "expire_at_height": 500,
    }
    tx.update(over)
    return tx


@pytest.mark.trio
async def test_rule_topic_accepts_rule_types(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)

    await service._on_rule_gossip(_envelope(_offer()))
    await service._on_rule_gossip(_envelope({
        "tx_type": "rule_offer_accept", "sender_pubkey": B,
        "offer_id": "ab" * 32, "rule_text": RULE}))
    await service._on_rule_gossip(_envelope({
        "tx_type": "rule_offer_reject", "sender_pubkey": B,
        "offer_id": "ab" * 32}))
    assert len(seen) == 3


@pytest.mark.trio
async def test_rule_topic_rejects_off_lane_types(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)

    await service._on_rule_gossip(_envelope({
        "tx_type": "user_tx", "sender_pubkey": A, "operations": {}}))
    await service._on_rule_gossip(_envelope({
        "tx_type": "consensus_rule_vote", "sender_pubkey": A,
        "update_id": "ab" * 32, "approve": True}))
    assert seen == []


@pytest.mark.trio
async def test_transactions_topic_rejects_rule_types(service):
    """A rule offer must not be able to dodge its lane by publishing on the
    fast topic."""
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    await service._on_transaction_gossip(_envelope(_offer()))
    assert seen == []


# --- structural checks and bounds -------------------------------------------

@pytest.mark.trio
@pytest.mark.parametrize("tx", [
    {"tx_type": "rule_offer", "sender_pubkey": A, "rule_text": RULE},          # no recipient
    {"tx_type": "rule_offer", "sender_pubkey": A, "recipient_pubkey": B},       # no text
    {"tx_type": "rule_offer", "sender_pubkey": A, "recipient_pubkey": B,
     "rule_text": RULE},                                                        # no expiry
    {"tx_type": "rule_offer_accept", "sender_pubkey": B, "offer_id": "ab" * 32},  # no text
    {"tx_type": "rule_offer_accept", "sender_pubkey": B, "rule_text": RULE},      # no id
    {"tx_type": "rule_offer_reject", "sender_pubkey": B},                         # no id
])
async def test_structurally_incomplete_payloads_are_dropped(service, tx):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    await service._on_rule_gossip(_envelope(tx))
    assert seen == []


@pytest.mark.trio
async def test_oversized_offer_is_dropped(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    huge = _offer(rule_text="x" * (TAU_MAX_RULE_OFFER_BYTES + 100))
    await service._on_rule_gossip(_envelope(huge))
    assert seen == []


@pytest.mark.trio
async def test_offer_within_the_cap_is_accepted(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    # Comfortably larger than the 8 KiB user_tx cap, which is why the rule topic
    # needs its own bound.
    sized = _offer(rule_text=RULE + " # " + "y" * 9000)
    assert len(json.dumps(sized).encode()) > 8192
    await service._on_rule_gossip(_envelope(sized))
    assert len(seen) == 1


def test_snapshot_rule_quota_is_defined():
    """A rule backlog must not become the entire snapshot a peer gets on
    connect."""
    assert TAU_MEMPOOL_SNAPSHOT_MAX_RULE_TXS > 0
    from network.protocols import TAU_MEMPOOL_SNAPSHOT_MAX_TOTAL
    assert TAU_MEMPOOL_SNAPSHOT_MAX_RULE_TXS < TAU_MEMPOOL_SNAPSHOT_MAX_TOTAL
