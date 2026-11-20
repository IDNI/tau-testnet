"""Gossip routing, bounds and handlers for rule-change requests and cancels.

These used to be on no routing table: topic_for_tx_type sent them to the
transactions topic, whose handler accepts user_tx alone, so a request reached
only the node it was submitted to. Every routing table must agree on a type, or
peers silently drop it.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from network.config import NetworkConfig
from network.protocols import (
    TAU_GOSSIP_TOPIC_APPROVALS,
    TAU_MAX_RULE_CHANGE_CANCEL_BYTES,
    TAU_MAX_RULE_CHANGE_REQUEST_BYTES,
)
from network.service import _SNAPSHOT_TX_TYPES, NetworkService

A = "aa" * 48
B = "bb" * 48
SIG = "cd" * 96
RULE_CHANGE_TYPES = ("rule_change_request", "rule_change_cancel")


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


def _request(**over):
    fields = {"kind": 1, "approvers": {"18": B}, "rule_text": "always o5[t] = 1."}
    fields.update(over)
    return _envelope_tx("rule_change_request", **fields)


def _cancel(**over):
    return _envelope_tx("rule_change_cancel", **{"request_id": "ab" * 32, **over})


def _envelope(tx):
    return {"payload": json.dumps(tx)}


def _capture(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(json.loads(payload)["tx_type"])
    return seen


@pytest.mark.parametrize("tx_type", RULE_CHANGE_TYPES)
def test_rule_change_types_use_the_approvals_topic(tx_type):
    assert NetworkService.topic_for_tx_type(tx_type) == TAU_GOSSIP_TOPIC_APPROVALS


def test_both_types_are_in_the_snapshot_set():
    assert set(RULE_CHANGE_TYPES) <= _SNAPSHOT_TX_TYPES


def test_real_payloads_fit_the_caps():
    eight = {str(18 + i): f"{i:02x}" * 48 for i in range(8)}
    assert len(json.dumps(_request(approvers=eight, rule_text="x" * 8192))) \
        < TAU_MAX_RULE_CHANGE_REQUEST_BYTES
    assert len(json.dumps(_cancel())) < TAU_MAX_RULE_CHANGE_CANCEL_BYTES


def test_broadcast_publishes_on_the_approvals_topic(service):
    published = []
    service._nursery = MagicMock()
    service._nursery.start_soon.side_effect = lambda fn, topic, payload, mid: published.append(topic)
    service._trio_token = None
    service._gossip_manager = MagicMock()
    for tx_type in RULE_CHANGE_TYPES:
        service.broadcast_transaction(json.dumps({"tx_type": tx_type}), "mid")
    assert published == [TAU_GOSSIP_TOPIC_APPROVALS] * 2


@pytest.mark.trio
async def test_the_approvals_handler_accepts_rule_change_requests_and_cancels(service):
    seen = _capture(service)
    await service._on_approval_gossip(_envelope(_request()))
    await service._on_approval_gossip(_envelope(_request(kind=2, rule_text=None)))
    await service._on_approval_gossip(_envelope(_cancel()))
    assert seen == ["rule_change_request", "rule_change_request", "rule_change_cancel"]


@pytest.mark.trio
@pytest.mark.parametrize("tx", [
    _request(kind=None),
    _request(expire_at_height=None),
    _cancel(request_id=None),
    _request(padding="x" * TAU_MAX_RULE_CHANGE_REQUEST_BYTES),
    _cancel(padding="x" * TAU_MAX_RULE_CHANGE_CANCEL_BYTES),
], ids=["no-kind", "no-deadline", "no-id", "oversize-request", "oversize-cancel"])
async def test_the_approvals_handler_rejects_malformed_rule_changes(service, tx):
    seen = _capture(service)
    await service._on_approval_gossip(_envelope(tx))
    assert seen == []


@pytest.mark.trio
@pytest.mark.parametrize("tx", [_request(), _cancel()])
async def test_the_transactions_topic_still_drops_rule_changes(service, tx):
    """Where they used to be published: proof the routing is what delivers them."""
    seen = _capture(service)
    await service._on_transaction_gossip(_envelope(tx))
    assert seen == []
