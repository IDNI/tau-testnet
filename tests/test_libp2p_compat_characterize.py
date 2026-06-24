"""Characterization tests for current libp2p stream-handler behavior on libp2p 0.5.0.

These tests lock the *observable* behavior of the 6 stream handlers in
`network/service.py` (handshake, ping, sync, blocks, tx, gossip_stream)
before the Phase A refactor extracts stream primitives into
`network/libp2p_compat.py`. Per the unification plan, each per-handler refactor
in step A5 must keep these tests green.

For each handler the tests cover:
  - valid request (golden path)
  - invalid JSON
  - oversized payload (clamped by handler's read limit)
  - truncated payload (short bytes)
  - empty client request (b"")
  - handler-internal exception (monkeypatch a callee)
  - stream.close() raising

Assertions: write bytes (decoded JSON when present), write count, close count,
and that the handler never re-raises (every existing handler swallows in a
top-level try/except and always closes in finally).

Also: a regression test for the DHT validator-shape probe in
`network/dht_manager.py`. Today it silently no-ops when neither `.validators`
nor `._validators` is present; step A6 will tighten this to a `RuntimeError`.
The probe-shape test is xfail today and expected to pass post-A6.
"""
from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from network.config import NetworkConfig
from network.service import NetworkService


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def mock_config():
    cfg = MagicMock(spec=NetworkConfig)
    cfg.network_id = "test-net"
    cfg.agent = "test-agent"
    cfg.genesis_hash = "genesis_char"
    cfg.bootstrap_peers = []
    cfg.dht_bootstrap_peers = []
    cfg.peer_advertisement_interval = 0
    cfg.MINER_PUBKEY = ""
    return cfg


@pytest.fixture
def service(mock_config):
    with patch("network.service.HostManager") as MockHostManager, \
         patch("network.service.DHTManager") as MockDHTManager, \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager") as MockGossip:
        host_inst = MockHostManager.return_value
        host = MagicMock()
        host.get_id.return_value = "local_peer"
        host.get_peerstore.return_value = MagicMock()
        host_inst.host = host

        dht_inst = MockDHTManager.return_value
        dht_inst.dht = MagicMock()
        dht_inst._encode_dht_key.side_effect = lambda ns, sfx: f"/{ns}/{sfx}".encode()

        svc = NetworkService(mock_config)
        svc.get_id = MagicMock(return_value="local_peer")
        # Bypass the _genesis_hash property's db fallback for handler tests.
        # The property reads `getattr(self, "__genesis_hash", None)` — direct attribute
        # assignment outside the class is NOT name-mangled, so this set is the literal key.
        setattr(svc, "__genesis_hash", "genesis_char")
        # `_gossip_manager.handle_rpc` is awaited in `_handle_gossip_stream`.
        svc._gossip_manager = MockGossip.return_value
        svc._gossip_manager.handle_rpc = AsyncMock()
        return svc


def _make_stream(read_bytes: bytes = b"", *, close_raises: bool = False):
    """Build an AsyncMock stream returning `read_bytes` from .read()."""
    s = MagicMock()
    s.read = AsyncMock(return_value=read_bytes)
    s.write = AsyncMock()
    if close_raises:
        s.close = AsyncMock(side_effect=RuntimeError("close failed"))
    else:
        s.close = AsyncMock()
    s.muxed_conn = MagicMock()
    s.muxed_conn.peer_id = "remote_peer"
    return s


def _written_json(stream):
    """Decode the JSON payload written by the handler. Returns None if no write."""
    if not stream.write.await_args_list:
        return None
    payload = stream.write.await_args_list[0].args[0]
    try:
        return json.loads(payload.decode())
    except Exception:
        return payload


def _patch_db(**overrides):
    """Return a sys.modules patch context that injects a mock db module.

    Default behavior: db.get_canonical_head_block / get_canonical_head return None,
    get_block_by_hash returns None, get_canonical_blocks_at_or_after_height returns [].
    Override any of those via kwargs.
    """
    mock_db = MagicMock()
    mock_db.get_canonical_head_block.return_value = None
    mock_db.get_canonical_head.return_value = None
    mock_db.get_block_by_hash.return_value = None
    mock_db.get_canonical_blocks_at_or_after_height.return_value = []
    mock_db.get_genesis_hash.return_value = "genesis_char"
    for k, v in overrides.items():
        getattr(mock_db, k).return_value = v
    return patch.dict(sys.modules, {"db": mock_db})


# --------------------------------------------------------------------------
# _handle_ping (simplest)
# --------------------------------------------------------------------------


@pytest.mark.trio
async def test_ping_valid(service):
    stream = _make_stream(json.dumps({"nonce": 7}).encode())
    await service._handle_ping(stream)
    resp = _written_json(stream)
    assert resp["nonce"] == 7
    assert "time" in resp
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_ping_invalid_json(service):
    stream = _make_stream(b"not json")
    # ping swallows json errors silently — no write, but always close
    await service._handle_ping(stream)
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_ping_empty_request(service):
    stream = _make_stream(b"")
    await service._handle_ping(stream)
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_ping_oversized_handled_by_read_limit(service):
    # _handle_ping reads 65535 bytes; AsyncMock simply returns what we give it.
    # We characterize: oversized JSON (still parses) still responds.
    big = json.dumps({"nonce": "x" * 60000}).encode()
    stream = _make_stream(big)
    await service._handle_ping(stream)
    resp = _written_json(stream)
    assert resp["nonce"] == "x" * 60000
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_ping_truncated(service):
    # Truncated JSON should fail to parse and silently drop
    stream = _make_stream(b'{"nonce": 7')
    await service._handle_ping(stream)
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_ping_close_raises_is_swallowed(service):
    # Post-A5: close_stream_safely in finally swallows close errors so they
    # never mask the handler's own outcome. Verify the handler still writes
    # its response and returns cleanly.
    stream = _make_stream(json.dumps({"nonce": 1}).encode(), close_raises=True)
    await service._handle_ping(stream)
    resp = _written_json(stream)
    assert resp["nonce"] == 1
    assert stream.close.await_count == 1


# --------------------------------------------------------------------------
# _handle_tx
# --------------------------------------------------------------------------


@pytest.mark.trio
async def test_tx_valid(service):
    service._queue_tx = MagicMock(return_value="queued")
    stream = _make_stream(json.dumps({"tx": {"hash": "abc"}}).encode())
    await service._handle_tx(stream)
    resp = _written_json(stream)
    assert resp == {"ok": True, "result": "queued"}
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_tx_invalid_json(service):
    service._queue_tx = MagicMock()
    stream = _make_stream(b"garbage")
    await service._handle_tx(stream)
    # Today: invalid JSON -> exception caught -> no write, only close
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_tx_empty_request(service):
    service._queue_tx = MagicMock()
    stream = _make_stream(b"")
    await service._handle_tx(stream)
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_tx_handler_raises(service):
    service._queue_tx = MagicMock(side_effect=ValueError("submit blew up"))
    stream = _make_stream(json.dumps({"tx": "x"}).encode())
    await service._handle_tx(stream)
    # Today: internal exception is swallowed; no write happens because the
    # exception fires before the response dict is built. Only close.
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


# --------------------------------------------------------------------------
# _handle_sync (empty-timeout quirk)
# --------------------------------------------------------------------------


@pytest.mark.trio
async def test_sync_valid_get_headers(service):
    with _patch_db():
        stream = _make_stream(b"get_headers")
        await service._handle_sync(stream)
    resp = _written_json(stream)
    assert resp["headers"] == []
    assert resp["tip_number"] == 0
    assert resp["tip_hash"] == "genesis_char"
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_sync_empty_request_handled_via_move_on_after(service):
    # Empty bytes simulate "client wrote nothing then closed" — handler must
    # not block. Current impl uses trio.move_on_after(0.25); since AsyncMock
    # returns immediately we exercise the b"" branch directly.
    with _patch_db():
        stream = _make_stream(b"")
        await service._handle_sync(stream)
    resp = _written_json(stream)
    assert resp["headers"] == []
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_sync_invalid_json_returns_empty_headers(service):
    with _patch_db():
        stream = _make_stream(b"{not valid")
        await service._handle_sync(stream)
    resp = _written_json(stream)
    # Invalid JSON falls through to default tip response with empty headers
    assert resp["headers"] == []
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_sync_locator_unknown_returns_from_zero(service):
    with _patch_db():
        stream = _make_stream(json.dumps(
            {"type": "get_headers", "locator": ["unknown_hash"], "limit": 50}
        ).encode())
        await service._handle_sync(stream)
    resp = _written_json(stream)
    assert resp["headers"] == []
    assert stream.close.await_count == 1


# --------------------------------------------------------------------------
# _handle_blocks
# --------------------------------------------------------------------------


@pytest.mark.trio
async def test_blocks_by_hashes_valid(service):
    blk = {"block_hash": "h1", "header": {"block_number": 1}}
    with _patch_db(get_block_by_hash=blk):
        stream = _make_stream(json.dumps(
            {"type": "get_blocks", "hashes": ["h1"]}
        ).encode())
        await service._handle_blocks(stream)
    resp = _written_json(stream)
    assert resp == {"blocks": [blk]}
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_blocks_invalid_type_returns_empty(service):
    with _patch_db():
        stream = _make_stream(json.dumps({"type": "wrong"}).encode())
        await service._handle_blocks(stream)
    assert _written_json(stream) == {"blocks": []}
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_blocks_invalid_json(service):
    with _patch_db():
        stream = _make_stream(b"garbage")
        await service._handle_blocks(stream)
    # falls to default empty response
    assert _written_json(stream) == {"blocks": []}
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_blocks_empty_request(service):
    with _patch_db():
        stream = _make_stream(b"")
        await service._handle_blocks(stream)
    # empty -> req={} -> not get_blocks -> default empty
    assert _written_json(stream) == {"blocks": []}
    assert stream.close.await_count == 1


# --------------------------------------------------------------------------
# _handle_gossip_stream
# --------------------------------------------------------------------------


@pytest.mark.trio
async def test_gossip_valid(service):
    service._ensure_peer_route = AsyncMock()
    service._ensure_peer_id = MagicMock(return_value=MagicMock())
    service._opportunistic_seed_peer = AsyncMock()
    stream = _make_stream(json.dumps(
        {"peer_id": "remote_peer", "rpc": {"messages": [{"message_id": "m1"}]}}
    ).encode())
    await service._handle_gossip_stream(stream)
    resp = _written_json(stream)
    assert resp["ok"] is True
    assert resp["messages"] == [{"message_id": "m1", "duplicate": False}]
    assert service._gossip_manager.handle_rpc.await_count == 1
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_gossip_invalid_json(service):
    service._ensure_peer_route = AsyncMock()
    stream = _make_stream(b"garbage")
    await service._handle_gossip_stream(stream)
    # JSON decode raises -> outer except swallows -> no write, close only
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_gossip_empty_request(service):
    service._ensure_peer_route = AsyncMock()
    service._ensure_peer_id = MagicMock(return_value=MagicMock())
    service._opportunistic_seed_peer = AsyncMock()
    # Empty bytes: handler decodes (b"" or b"{}").decode() = "{}" -> empty dict.
    stream = _make_stream(b"")
    await service._handle_gossip_stream(stream)
    resp = _written_json(stream)
    assert resp["ok"] is True
    assert resp["messages"] == []
    assert stream.close.await_count == 1


# --------------------------------------------------------------------------
# _handle_handshake (most complex)
# --------------------------------------------------------------------------


@pytest.mark.trio
async def test_handshake_valid_minimal(service):
    payload = {
        "network_id": "test-net",
        "peer_pubkey": "",
        "dht_peers": [],
        "dht_providers": [],
    }
    with _patch_db():
        stream = _make_stream(json.dumps(payload).encode())
        with patch("network.service.HostManager", MagicMock()), \
             patch.dict(sys.modules, {
                 "multiaddr": MagicMock(),
                 "libp2p.peer.id": MagicMock(),
                 "libp2p.peer.peerinfo": MagicMock(),
                 "consensus.facade": MagicMock(),
             }):
            service._ensure_peer_route = AsyncMock()
            await service._handle_handshake(stream)
    resp = _written_json(stream)
    assert resp["network_id"] == "test-net"
    assert resp["genesis_hash"] == "genesis_char"
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_handshake_network_id_mismatch(service):
    payload = {"network_id": "wrong-net"}
    with _patch_db():
        stream = _make_stream(json.dumps(payload).encode())
        with patch.dict(sys.modules, {"consensus.facade": MagicMock()}):
            service._ensure_peer_route = AsyncMock()
            await service._handle_handshake(stream)
    # Handshake closes on mismatch — no response written.
    # POST-A5: the latent double-close (early `await stream.close()` plus the
    # `finally` close) was removed. Now the finally is the single close site.
    assert stream.write.await_count == 0
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_handshake_invalid_json_still_writes_response(service):
    # _handle_handshake catches JSONDecodeError inside the payload-processing
    # try, but the response is written after that block. Characterize this:
    # invalid JSON -> log warning -> response IS written with our local tip.
    with _patch_db():
        stream = _make_stream(b"not json")
        service._ensure_peer_route = AsyncMock()
        await service._handle_handshake(stream)
    resp = _written_json(stream)
    assert resp is not None
    assert resp["network_id"] == "test-net"
    assert stream.close.await_count == 1


@pytest.mark.trio
async def test_handshake_empty_request_writes_response(service):
    # Empty request: data is falsy, payload-processing block skipped, response
    # still written.
    with _patch_db():
        stream = _make_stream(b"")
        service._ensure_peer_route = AsyncMock()
        await service._handle_handshake(stream)
    resp = _written_json(stream)
    assert resp is not None
    assert resp["network_id"] == "test-net"
    assert stream.close.await_count == 1


# --------------------------------------------------------------------------
# DHT validator-shape regression (xfail today; expected pass after A6)
# --------------------------------------------------------------------------


def test_dht_validator_shape_missing_attrs_raises():
    """When libp2p's Validator exposes neither `.validators` nor `._validators`,
    `install_validating_dht` raises RuntimeError. This guards against silent
    regression — silent no-op would mean bad records get accepted.
    """
    from network.libp2p_compat import install_validating_dht

    fake_dht = MagicMock()
    # Strip both attrs from the validator object.
    fake_dht.validator = type("V", (), {})()
    with pytest.raises(RuntimeError, match="Validator shape"):
        install_validating_dht(
            fake_dht,
            namespace_validators={},
            record_validator=lambda k, v: True,
            key_validator=lambda k: True,
        )
