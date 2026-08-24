"""Gossip ingestion must not run transaction admission on the trio event loop.

`_queue_tx` runs the whole synchronous admission path: it takes the
process-global Tau lock and, for rule-bearing transactions, spawns a compile
subprocess bounded only by `config.COMM_TIMEOUT` (60s by default). Called
inline from an `async def`, that parks the network thread's event loop, which
stops block gossip, transaction gossip, chain sync and peer discovery for the
whole duration -- remotely triggerable by a single gossiped rule transaction.

These tests pin the offload: admission runs on a worker thread and the loop
keeps making progress while it does.
"""
import json
import threading
import time
from unittest.mock import MagicMock, patch

import pytest
import trio

from network.config import NetworkConfig
from network.service import NetworkService

pytestmark = pytest.mark.trio

ADMISSION_DWELL = 0.35


@pytest.fixture
def service():
    cfg = MagicMock(spec=NetworkConfig)
    cfg.listen_addrs = []
    with patch("network.service.HostManager"), \
         patch("network.service.DHTManager"), \
         patch("network.service.DiscoveryManager"), \
         patch("network.service.GossipManager"):
        return NetworkService(cfg)


def _tx_envelope():
    return {
        "payload": json.dumps({
            "tx_type": "user_tx",
            "sender_pubkey": "ab" * 48,
            "sequence_number": 0,
            "operations": {"1": [["ab" * 48, "cd" * 48, 1]]},
        })
    }


async def test_gossip_admission_runs_off_the_event_loop(service):
    """A slow _queue_tx must not stall other tasks on the same loop."""
    calls = {}
    loop_thread = threading.get_ident()

    def slow_queue_tx(payload, propagate=True):
        calls["thread"] = threading.get_ident()
        calls["propagate"] = propagate
        # Stand in for the Tau lock / compile subprocess.
        time.sleep(ADMISSION_DWELL)
        return {"ok": True}

    service._queue_tx = slow_queue_tx

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await trio.sleep(0.01)
            ticks += 1

    started = time.monotonic()
    async with trio.open_nursery() as nursery:
        nursery.start_soon(ticker)
        await service._process_gossip_payload(
            _tx_envelope(), {"user_tx"}, {"user_tx": 8192}
        )
        nursery.cancel_scope.cancel()
    elapsed = time.monotonic() - started

    assert calls.get("thread") is not None, "_queue_tx was never called"
    assert calls["thread"] != loop_thread, (
        "admission ran on the trio event loop thread; the offload regressed"
    )
    # Gossip-sourced transactions are not re-broadcast.
    assert calls["propagate"] is False
    # The dwell really was awaited...
    assert elapsed >= ADMISSION_DWELL
    # ...and the loop stayed live throughout instead of being parked. A blocked
    # loop yields 0 ticks; a healthy one gets roughly ADMISSION_DWELL/0.01.
    assert ticks >= 5, f"event loop was starved during admission (ticks={ticks})"


async def test_gossip_admission_failure_is_contained(service):
    """A raising _queue_tx must not propagate out of the gossip handler."""
    def boom(payload, propagate=True):
        raise RuntimeError("admission exploded")

    service._queue_tx = boom
    # Must not raise.
    await service._process_gossip_payload(
        _tx_envelope(), {"user_tx"}, {"user_tx": 8192}
    )


async def test_direct_tx_stream_admission_runs_off_the_event_loop(service):
    """The /tau/tx/2.0.0 stream handler has the same requirement."""
    calls = {}
    loop_thread = threading.get_ident()

    def slow_queue_tx(payload, propagate=True):
        calls["thread"] = threading.get_ident()
        time.sleep(ADMISSION_DWELL)
        return {"ok": True}

    service._queue_tx = slow_queue_tx

    written = []

    class FakeStream:
        async def read(self, n=None):
            return json.dumps({"tx": "{}"}).encode()

        async def write(self, data):
            written.append(data)

        async def close(self):
            pass

    ticks = 0

    async def ticker():
        nonlocal ticks
        while True:
            await trio.sleep(0.01)
            ticks += 1

    async with trio.open_nursery() as nursery:
        nursery.start_soon(ticker)
        await service._handle_tx(FakeStream())
        nursery.cancel_scope.cancel()

    assert calls.get("thread") is not None, "_queue_tx was never called"
    assert calls["thread"] != loop_thread, (
        "direct-stream admission ran on the trio event loop thread"
    )
    assert ticks >= 5, f"event loop was starved during admission (ticks={ticks})"
    assert written, "no response written back to the stream"
