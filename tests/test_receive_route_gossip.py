"""Gossip routing, bounds and handlers for receive-route changes (issue #35).

Both route types travel on their own topic. Every routing table must agree on
a type, or peers silently drop it: each topic's handler enforces its own
allow-list, so a type published to the wrong topic is lost at every peer.
(Guarded route changes ride on rule_change_request; see
tests/test_rule_change_gossip.py.)
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from network.config import NetworkConfig
from network.protocols import (
    TAU_GOSSIP_TOPIC_RECEIVE_ROUTES,
    TAU_MAX_RECEIVE_ROUTE_TX_BYTES,
)
from network.service import _SNAPSHOT_TX_TYPES, NetworkService

A = "aa" * 48
B = "bb" * 48
SIG = "cd" * 96
ROUTE_TYPES = ("receive_route_set", "receive_route_clear")


@pytest.fixture
def service():
    cfg = MagicMock(spec=NetworkConfig)
    cfg.listen_addrs = []
    with patch("network.service.HostManager"), \
         patch("network.service.DHTManager"), \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager"):
        return NetworkService(cfg)


def _envelope_tx(tx_type, **fields):
    tx = {
        "tx_type": tx_type, "sender_pubkey": A, "sequence_number": 1,
        "expiration_time": 9_999_999_999, "expire_at_height": 500, "fee_limit": "10",
        "signature": SIG,
    }
    tx.update(fields)
    return {k: v for k, v in tx.items() if v is not None}


def _route_set(**over):
    return _envelope_tx("receive_route_set", **{"destination_pubkey": B, "route_bps": 2000,
                                                **over})


def _route_clear(**over):
    return _envelope_tx("receive_route_clear", **{"route_owner_pubkey": A, **over})


def _envelope(tx):
    return {"payload": json.dumps(tx)}


def _capture(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(json.loads(payload)["tx_type"])
    return seen


@pytest.mark.parametrize("tx_type", ROUTE_TYPES)
def test_route_types_use_the_receive_route_topic(tx_type):
    assert NetworkService.topic_for_tx_type(tx_type) == TAU_GOSSIP_TOPIC_RECEIVE_ROUTES


def test_both_types_are_in_the_snapshot_set():
    assert set(ROUTE_TYPES) <= _SNAPSHOT_TX_TYPES


def test_real_payloads_fit_the_cap():
    full = _route_set(min_amount=10, active_from_time=1, expires_at_time=2, locked=True)
    assert len(json.dumps(full)) < TAU_MAX_RECEIVE_ROUTE_TX_BYTES
    assert len(json.dumps(_route_clear())) < TAU_MAX_RECEIVE_ROUTE_TX_BYTES


def test_broadcast_publishes_on_the_receive_route_topic(service):
    published = []
    service._nursery = MagicMock()
    service._nursery.start_soon.side_effect = lambda fn, topic, payload, mid: published.append(topic)
    service._trio_token = None
    service._gossip_manager = MagicMock()
    for tx_type in ROUTE_TYPES:
        service.broadcast_transaction(json.dumps({"tx_type": tx_type}), "mid")
    assert published == [TAU_GOSSIP_TOPIC_RECEIVE_ROUTES] * 2


@pytest.mark.trio
async def test_the_route_handler_accepts_both_types_without_re_propagating(service):
    calls = []
    service._queue_tx = lambda payload, propagate=True: calls.append(
        (json.loads(payload)["tx_type"], propagate))
    await service._on_receive_route_gossip(_envelope(_route_set()))
    await service._on_receive_route_gossip(_envelope(_route_clear()))
    assert calls == [("receive_route_set", False), ("receive_route_clear", False)]


@pytest.mark.trio
@pytest.mark.parametrize("tx", [
    _route_set(destination_pubkey=None),
    _route_set(route_bps=None),
    _route_clear(route_owner_pubkey=None),
    _route_set(padding="x" * TAU_MAX_RECEIVE_ROUTE_TX_BYTES),
], ids=["no-destination", "no-bps", "no-owner", "oversize"])
async def test_the_route_handler_rejects_malformed_or_oversize(service, tx):
    seen = _capture(service)
    await service._on_receive_route_gossip(_envelope(tx))
    assert seen == []


@pytest.mark.trio
@pytest.mark.parametrize("handler", ["_on_transaction_gossip", "_on_approval_gossip",
                                     "_on_rule_gossip", "_on_retractable_gossip"])
@pytest.mark.parametrize("tx", [_route_set(), _route_clear()])
async def test_other_topics_reject_the_route_types(service, handler, tx):
    seen = _capture(service)
    await getattr(service, handler)(_envelope(tx))
    assert seen == []
