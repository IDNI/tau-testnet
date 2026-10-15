"""Gossip routing, bounds and snapshot replay for retractable transfers.

Every routing table must agree on both types, or peers silently drop them: each
topic's handler enforces its own allow-list, so publishing to the wrong topic
loses the transaction at every peer.
"""
import inspect
import json
from unittest.mock import MagicMock, patch

import pytest

from network import protocols
from network.config import NetworkConfig
from network.protocols import (
    TAU_GOSSIP_TOPIC_APPROVALS,
    TAU_GOSSIP_TOPIC_RETRACTABLE,
    TAU_GOSSIP_TOPIC_RULES,
    TAU_GOSSIP_TOPIC_TRANSACTIONS,
    TAU_MAX_RETRACT_TRANSFER_BYTES,
    TAU_MAX_RETRACTABLE_TRANSFER_BYTES,
    TAU_MEMPOOL_SNAPSHOT_MAX_RETRACTABLE_TXS,
)
from network.service import _SNAPSHOT_TX_TYPES, NetworkService

A = "aa" * 48
B = "bb" * 48
SIG = "cd" * 96
TYPES = ("retractable_transfer", "retract_transfer")


@pytest.fixture
def service():
    cfg = MagicMock(spec=NetworkConfig)
    cfg.listen_addrs = []
    with patch("network.service.HostManager"), \
         patch("network.service.DHTManager"), \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager"):
        return NetworkService(cfg)


def _park(**over):
    tx = {
        "tx_type": "retractable_transfer", "sender_pubkey": A, "sequence_number": 1,
        "expiration_time": 9_999_999_999, "expire_at_height": 500, "fee_limit": "10",
        "recipient_pubkey": B, "amount": 100, "release_at_height": 600,
        "signature": SIG,
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def _retract(**over):
    tx = {
        "tx_type": "retract_transfer", "sender_pubkey": A, "sequence_number": 2,
        "expiration_time": 9_999_999_999, "expire_at_height": 500, "fee_limit": "0",
        "retractable_id": "ab" * 32, "signature": SIG,
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def _envelope(tx):
    return {"payload": json.dumps(tx)}


# --- routing tables ---------------------------------------------------------

def test_topic_name_and_distinctness():
    assert TAU_GOSSIP_TOPIC_RETRACTABLE == "tau/retractable/1.0.0"
    assert len({TAU_GOSSIP_TOPIC_RETRACTABLE, TAU_GOSSIP_TOPIC_APPROVALS,
                TAU_GOSSIP_TOPIC_RULES, TAU_GOSSIP_TOPIC_TRANSACTIONS}) == 4


@pytest.mark.parametrize("tx_type", TYPES)
def test_both_types_route_to_the_retractable_topic(tx_type):
    assert NetworkService.topic_for_tx_type(tx_type) == TAU_GOSSIP_TOPIC_RETRACTABLE


@pytest.mark.parametrize("tx_type,topic", [
    ("user_tx", TAU_GOSSIP_TOPIC_TRANSACTIONS),
    ("approval_request", TAU_GOSSIP_TOPIC_APPROVALS),
    ("transfer_vote", TAU_GOSSIP_TOPIC_APPROVALS),
    ("rule_offer", TAU_GOSSIP_TOPIC_RULES),
    (None, TAU_GOSSIP_TOPIC_TRANSACTIONS),
])
def test_existing_routing_is_unchanged(tx_type, topic):
    assert NetworkService.topic_for_tx_type(tx_type) == topic


def test_both_types_are_in_the_snapshot_set():
    assert set(TYPES) <= _SNAPSHOT_TX_TYPES


def test_the_topic_is_joined_at_startup_with_its_own_handler():
    assert hasattr(NetworkService, "_on_retractable_gossip")
    src = inspect.getsource(NetworkService)
    assert "join_topic(TAU_GOSSIP_TOPIC_RETRACTABLE, self._on_retractable_gossip)" in src


def test_byte_caps_and_quota():
    assert TAU_MAX_RETRACTABLE_TRANSFER_BYTES == 4096
    assert TAU_MAX_RETRACT_TRANSFER_BYTES == 4096
    assert TAU_MEMPOOL_SNAPSHOT_MAX_RETRACTABLE_TXS == 32
    assert protocols.TAU_MEMPOOL_SNAPSHOT_MAX_RETRACTABLE_TXS < protocols.TAU_MEMPOOL_SNAPSHOT_MAX_TOTAL


def test_a_real_park_and_retract_fit_the_caps():
    assert len(json.dumps(_park(release_at_height=None, release_at_time=2_000_000_000))) \
        < TAU_MAX_RETRACTABLE_TRANSFER_BYTES
    assert len(json.dumps(_retract())) < TAU_MAX_RETRACT_TRANSFER_BYTES


def test_broadcast_publishes_on_the_routed_topic(service):
    published = []
    service._nursery = MagicMock()
    service._nursery.start_soon.side_effect = lambda fn, topic, payload, mid: published.append(topic)
    service._trio_token = None
    service._gossip_manager = MagicMock()
    for tx_type in TYPES:
        service.broadcast_transaction(json.dumps({"tx_type": tx_type}), "mid")
    assert published == [TAU_GOSSIP_TOPIC_RETRACTABLE] * 2


# --- the handler -------------------------------------------------------------

@pytest.mark.trio
async def test_the_handler_accepts_both_types(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(json.loads(payload)["tx_type"])
    await service._on_retractable_gossip(_envelope(_park()))
    await service._on_retractable_gossip(
        _envelope(_park(release_at_height=None, release_at_time=2_000_000_000)))
    await service._on_retractable_gossip(_envelope(_retract()))
    assert seen == ["retractable_transfer", "retractable_transfer", "retract_transfer"]


@pytest.mark.trio
async def test_the_handler_forwards_without_re_propagating(service):
    calls = []
    service._queue_tx = lambda payload, propagate=True: calls.append(propagate)
    await service._on_retractable_gossip(_envelope(_park()))
    assert calls == [False]


@pytest.mark.trio
@pytest.mark.parametrize("tx", [
    _park(recipient_pubkey=None),
    _park(amount=None),
    _park(release_at_height=None),
    _park(release_at_time=2_000_000_000),
    _retract(retractable_id=None),
], ids=["no-recipient", "no-amount", "no-release", "two-releases", "no-id"])
async def test_the_handler_rejects_malformed_payloads(service, tx):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    await service._on_retractable_gossip(_envelope(tx))
    assert seen == []


@pytest.mark.trio
@pytest.mark.parametrize("tx,cap", [
    (_park(padding="x" * TAU_MAX_RETRACTABLE_TRANSFER_BYTES), TAU_MAX_RETRACTABLE_TRANSFER_BYTES),
    (_retract(padding="x" * TAU_MAX_RETRACT_TRANSFER_BYTES), TAU_MAX_RETRACT_TRANSFER_BYTES),
])
async def test_the_handler_enforces_the_byte_cap(service, tx, cap):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    assert len(json.dumps(tx)) > cap
    await service._on_retractable_gossip(_envelope(tx))
    assert seen == []


@pytest.mark.trio
async def test_the_handler_rejects_other_topics_types(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    await service._on_retractable_gossip(_envelope({
        "tx_type": "user_tx", "sender_pubkey": A, "operations": {}}))
    await service._on_retractable_gossip(_envelope({
        "tx_type": "approval_request", "sender_pubkey": A, "recipient_pubkey": B,
        "amount": 1, "expire_at_height": 5, "approvers": {}}))
    assert seen == []


@pytest.mark.trio
@pytest.mark.parametrize("handler", ["_on_transaction_gossip", "_on_approval_gossip", "_on_rule_gossip"])
@pytest.mark.parametrize("tx", [_park(), _retract()])
async def test_other_topics_reject_the_retractable_types(service, handler, tx):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(payload)
    await getattr(service, handler)(_envelope(tx))
    assert seen == []


# --- snapshot replay ---------------------------------------------------------

@pytest.mark.trio
async def test_snapshot_replays_both_types_on_the_retractable_topic(service):
    published = []

    async def publish(topic, payload, **kwargs):
        published.append((topic, payload["tx_type"]))

    service.publish_gossip = publish
    txs = ["json:" + json.dumps(_park()), json.dumps(_retract())]
    with patch("db.get_mempool_txs", return_value=txs):
        await service._send_mempool_snapshot("peer")
    assert published == [
        (TAU_GOSSIP_TOPIC_RETRACTABLE, "retractable_transfer"),
        (TAU_GOSSIP_TOPIC_RETRACTABLE, "retract_transfer"),
    ]


@pytest.mark.trio
async def test_snapshot_caps_retractable_txs_without_starving_others(service):
    published = []

    async def publish(topic, payload, **kwargs):
        published.append(payload["tx_type"])

    service.publish_gossip = publish
    flood = [json.dumps(_park(sequence_number=i)) for i in range(
        TAU_MEMPOOL_SNAPSHOT_MAX_RETRACTABLE_TXS + 10)]
    ordinary = json.dumps({"tx_type": "user_tx", "sender_pubkey": A, "operations": {}})
    with patch("db.get_mempool_txs", return_value=flood + [ordinary]):
        await service._send_mempool_snapshot("peer")
    assert published.count("retractable_transfer") == TAU_MEMPOOL_SNAPSHOT_MAX_RETRACTABLE_TXS
    assert published.count("user_tx") == 1
