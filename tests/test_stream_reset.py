"""A peer that resets a stream mid-reply must surface as an error, never as a short reply."""
from __future__ import annotations

import json
import logging
from typing import List

import multiaddr
import pytest
import trio
from libp2p import new_host
from libp2p.network.stream.exceptions import StreamReset
from libp2p.stream_muxer.exceptions import MuxedStreamReset

from conftest import connect_peers, wait_for_addrs
from network.libp2p_compat import bounded_stream_read, read_until_eof

pytestmark = pytest.mark.trio

RAW_PROTOCOL = "/tau/test/reset-read/1.0.0"
PARTIAL = 100 * 1024


@pytest.fixture
async def connected_hosts():
    listen_a = [multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]
    listen_b = [multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]
    host_a = new_host(listen_addrs=listen_a)
    host_b = new_host(listen_addrs=listen_b)
    async with host_a.run(listen_a), host_b.run(listen_b):
        await wait_for_addrs(host_a)
        await wait_for_addrs(host_b)
        await connect_peers(host_a, host_b)
        yield host_a, host_b


class CountingReader:
    """Reads from `inner` and sets `drained` once `need` bytes came through."""

    def __init__(self, inner, need: int, drained: trio.Event):
        self._inner = inner
        self._need = need
        self._drained = drained
        self.total = 0

    def __getattr__(self, name):
        return getattr(self._inner, name)

    async def read(self, n=None):
        data = await self._inner.read(n)
        self.total += len(data or b"")
        if self.total >= self._need:
            self._drained.set()
        return data


RESET_ERROR = {"net": StreamReset, "muxed": MuxedStreamReset}


@pytest.mark.parametrize("layer", ["net", "muxed"])
async def test_reset_after_the_reader_drained_the_buffer_raises(connected_hosts, layer):
    host_a, host_b = connected_hosts
    drained = trio.Event()

    async def handler(stream):
        await stream.write(b"a" * PARTIAL)
        await drained.wait()
        await stream.reset()

    host_b.set_stream_handler(RAW_PROTOCOL, handler)
    stream = await host_a.new_stream(host_b.get_id(), [RAW_PROTOCOL])
    inner = stream if layer == "net" else stream.muxed_stream
    reader = CountingReader(inner, PARTIAL, drained)
    with trio.fail_after(10), pytest.raises(RESET_ERROR[layer]):
        await read_until_eof(reader, 2 * PARTIAL)
    assert reader.total == PARTIAL


@pytest.mark.parametrize("layer", ["net", "muxed"])
async def test_reset_with_data_still_buffered_raises(connected_hosts, layer):
    host_a, host_b = connected_hosts

    async def handler(stream):
        await stream.write(b"b" * PARTIAL)
        await stream.reset()

    host_b.set_stream_handler(RAW_PROTOCOL, handler)
    stream = await host_a.new_stream(host_b.get_id(), [RAW_PROTOCOL])
    with trio.fail_after(5):
        while not stream.muxed_stream.reset_received:
            await trio.sleep(0.01)
    inner = stream if layer == "net" else stream.muxed_stream
    with pytest.raises(RESET_ERROR[layer]):
        await read_until_eof(inner, 2 * PARTIAL)


async def test_clean_close_after_partial_writes_returns_everything(connected_hosts):
    host_a, host_b = connected_hosts

    async def handler(stream):
        await stream.write(b"c" * PARTIAL)
        await trio.sleep(0.1)
        await stream.write(b"d" * PARTIAL)
        await stream.close()

    host_b.set_stream_handler(RAW_PROTOCOL, handler)
    stream = await host_a.new_stream(host_b.get_id(), [RAW_PROTOCOL])
    with trio.fail_after(10):
        got = await read_until_eof(stream, 4 * PARTIAL)
    await stream.close()
    assert got == b"c" * PARTIAL + b"d" * PARTIAL


# --------------------------------------------------------------------------
# Sync paths of NetworkService
# --------------------------------------------------------------------------


@pytest.fixture
async def service_and_plain_host(isolate_db):
    from network.config import NetworkConfig
    from network.service import NetworkService

    listen = [multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")]
    server = new_host(listen_addrs=listen)
    cfg = NetworkConfig(
        network_id="testnet",
        listen_addrs=[multiaddr.Multiaddr("/ip4/127.0.0.1/tcp/0")],
    )
    svc = NetworkService(cfg, tx_submitter=lambda payload: "queued")
    async with server.run(listen):
        await wait_for_addrs(server)
        await svc.start()
        await wait_for_addrs(svc.host)
        try:
            yield svc, server
        finally:
            await svc.stop()


async def _write_part_then_reset(stream, reply: bytes):
    assert len(reply) > 2 * PARTIAL
    await bounded_stream_read(stream, 65535)
    await stream.write(reply[:PARTIAL])
    # Give the client time to drain its buffer, so the RST lands on an empty buffer.
    await trio.sleep(0.5)
    await stream.reset()


def _sync_failures(caplog, message: str) -> List[logging.LogRecord]:
    return [r for r in caplog.records if message in r.getMessage()]


async def test_header_sync_does_not_take_a_reset_reply(service_and_plain_host, monkeypatch, caplog):
    from network.protocols import TAU_PROTOCOL_SYNC
    from network.service import NetworkService

    svc, server = service_and_plain_host
    headers = [{"block_hash": f"{i + 1:064x}", "block_number": i + 1} for i in range(2000)]
    reply = json.dumps({"headers": headers, "tip_number": 2000}).encode()

    async def sync_handler(stream):
        await _write_part_then_reset(stream, reply)

    server.set_stream_handler(TAU_PROTOCOL_SYNC, sync_handler)
    ingested_batches: List[int] = []
    monkeypatch.setattr(
        NetworkService,
        "_ingest_blocks",
        staticmethod(lambda blocks, peer_id: ingested_batches.append(len(blocks)) or len(blocks)),
    )

    await connect_peers(svc.host, server)
    caplog.set_level(logging.WARNING)
    with trio.fail_after(20):
        ingested = await svc._sync_and_ingest_from_peer(
            str(server.get_id()), [svc._genesis_hash], limit=2000
        )
    assert ingested == 0
    assert ingested_batches == []
    failures = _sync_failures(caplog, "Failed to sync headers")
    assert len(failures) == 1
    assert isinstance(failures[0].exc_info[1], (StreamReset, MuxedStreamReset))


async def test_block_sync_does_not_take_a_reset_reply(service_and_plain_host, monkeypatch, caplog):
    from network.protocols import TAU_PROTOCOL_BLOCKS, TAU_PROTOCOL_SYNC
    from network.service import NetworkService

    svc, server = service_and_plain_host
    hashes = [f"{i + 1:064x}" for i in range(100)]

    async def sync_handler(stream):
        await bounded_stream_read(stream, 65535)
        headers = [{"block_hash": bh, "block_number": i + 1} for i, bh in enumerate(hashes)]
        await stream.write(json.dumps({"headers": headers, "tip_number": 100}).encode())
        await stream.close()

    async def blocks_handler(stream):
        blocks = [
            {"block_hash": bh, "header": {"block_number": i + 1, "block_hash": bh}, "transactions": ["t" * 4096]}
            for i, bh in enumerate(hashes)
        ]
        await _write_part_then_reset(stream, json.dumps({"blocks": blocks}).encode())

    server.set_stream_handler(TAU_PROTOCOL_SYNC, sync_handler)
    server.set_stream_handler(TAU_PROTOCOL_BLOCKS, blocks_handler)
    ingested_batches: List[int] = []
    monkeypatch.setattr(
        NetworkService,
        "_ingest_blocks",
        staticmethod(lambda blocks, peer_id: ingested_batches.append(len(blocks)) or len(blocks)),
    )

    await connect_peers(svc.host, server)
    caplog.set_level(logging.WARNING)
    with trio.fail_after(20):
        ingested = await svc._sync_and_ingest_from_peer(
            str(server.get_id()), [svc._genesis_hash], limit=100
        )
    assert ingested == 0
    assert ingested_batches == []
    failures = _sync_failures(caplog, "Failed to fetch block bodies")
    assert len(failures) == 1
    assert isinstance(failures[0].exc_info[1], (StreamReset, MuxedStreamReset))
