"""Gossip, snapshot replay and the admission byte cap of rule_change_request and
rule_change_cancel. Both types ride tau/transactions, like user_tx."""
import json
from unittest.mock import MagicMock, patch

import pytest

import tau_defs
from bls_keys import FAR_FUTURE, SK_ALICE, SK_BOB, pubkey_hex, sign_tx
from commands import sendtx
from consensus.approvals import MAX_APPROVERS_PER_REQUEST, MAX_RULE_CHANGE_TEXT_BYTES
from network import protocols
from network.config import NetworkConfig
from network.protocols import TAU_GOSSIP_TOPIC_TRANSACTIONS
from network.service import NetworkService

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
BIG = 2**63 - 1
CLAUSE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] ).\n#"
TYPES = ("rule_change_request", "rule_change_cancel")


@pytest.fixture
def service():
    cfg = MagicMock(spec=NetworkConfig)
    cfg.listen_addrs = []
    with patch("network.service.HostManager"), \
         patch("network.service.DHTManager"), \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager"):
        return NetworkService(cfg)


def _request(rule_text=CLAUSE[:-2], **extra):
    tx = {
        "tx_type": "rule_change_request",
        "sender_pubkey": ALICE,
        "sequence_number": BIG,
        "expiration_time": BIG,
        "expire_at_height": BIG,
        "fee_limit": str(BIG),
        "kind": tau_defs.RULE_CHANGE_KIND_SET_POLICY,
        "approvers": {str(18 + i): BOB[:-2] + "%02x" % i for i in range(MAX_APPROVERS_PER_REQUEST)},
        "rule_text": rule_text,
    }
    tx.update(extra)
    return sign_tx(tx)


def _cancel(**extra):
    tx = {
        "tx_type": "rule_change_cancel",
        "sender_pubkey": ALICE,
        "sequence_number": 1,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": 5000,
        "fee_limit": "0",
        "request_id": "ab" * 32,
    }
    tx.update(extra)
    return sign_tx(tx)


def _blob_size(tx):
    return len(sendtx._canonicalize_transaction(tx).encode("utf-8"))


def _queued(service):
    seen = []
    service._queue_tx = lambda payload, propagate=True: seen.append(json.loads(payload)["tx_type"])
    return seen


# --- gossip ------------------------------------------------------------------

def test_both_types_ride_the_transactions_topic():
    assert [NetworkService.topic_for_tx_type(t) for t in TYPES] == [TAU_GOSSIP_TOPIC_TRANSACTIONS] * 2


@pytest.mark.trio
async def test_gossiped_rule_change_types_reach_admission(service):
    seen = _queued(service)
    await service._on_transaction_gossip({"payload": sendtx._canonicalize_transaction(_request())})
    await service._on_transaction_gossip({"payload": sendtx._canonicalize_transaction(_cancel())})
    assert seen == list(TYPES)


@pytest.mark.trio
@pytest.mark.parametrize("tx", [_request(padding="x" * 30000), _cancel(padding="x" * 5000)],
                         ids=list(TYPES))
async def test_gossiped_payload_over_its_cap_is_dropped(service, tx):
    seen = _queued(service)
    await service._on_transaction_gossip({"payload": json.dumps(tx)})
    assert seen == []


def test_the_caps_of_both_types():
    assert protocols.TAU_MAX_TX_BYTES_BY_TYPE["rule_change_request"] == 24576
    assert protocols.TAU_MAX_TX_BYTES_BY_TYPE["rule_change_cancel"] == 4096


def test_every_known_type_has_a_gossip_cap():
    assert set(protocols.TAU_MAX_TX_BYTES_BY_TYPE) == set(sendtx.KNOWN_TX_TYPES)


# --- snapshot ----------------------------------------------------------------

async def _snapshot_to_receiver(service, txs):
    published = []

    async def publish(topic, payload, **kwargs):
        published.append((topic, payload))

    service.publish_gossip = publish
    blobs = [sendtx._canonicalize_transaction(tx) for tx in txs]
    with patch("db.get_mempool_txs", return_value=blobs):
        await service._send_mempool_snapshot("peer")
    seen = _queued(service)
    for _, payload in published:
        await service._on_transaction_gossip({"payload": payload})
    return published, seen


@pytest.mark.trio
async def test_snapshot_holds_both_types_and_a_receiver_admits_them(service):
    published, seen = await _snapshot_to_receiver(service, [_request(), _cancel()])
    assert [(topic, json.loads(p)["tx_type"]) for topic, p in published] == [
        (TAU_GOSSIP_TOPIC_TRANSACTIONS, t) for t in TYPES
    ]
    assert seen == list(TYPES)


@pytest.mark.trio
async def test_snapshot_sends_the_canonical_blob_so_an_entry_at_its_cap_is_admitted(service):
    tx = _at_cap_request()
    published, seen = await _snapshot_to_receiver(service, [tx])
    assert seen == ["rule_change_request"]
    assert [p for _, p in published] == [sendtx._canonicalize_transaction(tx)]


# --- admission ---------------------------------------------------------------

def _control_char_request(n_control: int, n_ascii: int = 0):
    return _request(rule_text=CLAUSE + "\x01" * n_control + "a" * n_ascii)


def test_admission_refuses_a_rule_change_request_over_its_cap():
    room = MAX_RULE_CHANGE_TEXT_BYTES - len(CLAUSE.encode())
    tx = _control_char_request(room)
    assert len(tx["rule_text"].encode()) == MAX_RULE_CHANGE_TEXT_BYTES
    assert _blob_size(tx) == 50287
    verdict = sendtx._check_tx_envelope(tx)
    assert verdict["code"] == "TX_TOO_LARGE"
    assert verdict["details"] == {"size": 50287, "limit": 24576}


def _at_cap_request(extra_bytes: int = 0):
    cap = protocols.TAU_MAX_TX_BYTES_BY_TYPE["rule_change_request"]
    n_control = (cap - _blob_size(_control_char_request(0))) // 6
    n_ascii = cap - _blob_size(_control_char_request(n_control))
    tx = _control_char_request(n_control, n_ascii + extra_bytes)
    assert _blob_size(tx) == cap + extra_bytes
    return tx


def test_admission_accepts_a_rule_change_request_at_its_cap():
    assert sendtx._check_tx_envelope(_at_cap_request()) is None
    assert sendtx._check_tx_envelope(_at_cap_request(1))["code"] == "TX_TOO_LARGE"


def test_admission_refuses_a_rule_offer_over_its_cap():
    tx = sign_tx({
        "tx_type": "rule_offer",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "expiration_time": FAR_FUTURE,
        "recipient_pubkey": BOB,
        "rule_text": CLAUSE + "\x01" * 8000,
        "expire_at_height": 500,
        "fee_limit": "100",
    })
    assert _blob_size(tx) > protocols.TAU_MAX_TX_BYTES_BY_TYPE["rule_offer"]
    assert sendtx._check_tx_envelope(tx)["code"] == "TX_TOO_LARGE"
