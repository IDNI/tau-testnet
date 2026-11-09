"""read_json_object: the end of one JSON object on a stream, without EOF."""
from __future__ import annotations

import json
from typing import List, Optional

import pytest
import trio
from libp2p.network.stream.exceptions import StreamReset
from libp2p.stream_muxer.exceptions import MuxedStreamReset

from network.libp2p_compat import (
    StreamReadTimeout,
    StreamTooLarge,
    read_json_object,
)

pytestmark = pytest.mark.trio


class FrameStream:
    """Delivers `payload` in frames of `frame` bytes, then hangs, ends or resets."""

    def __init__(self, payload: bytes, *, frame: int = 65536, end: str = "hang"):
        self._payload = payload
        self._frame = frame
        self._end = end
        self.reads = 0
        self.muxed_stream = type("Muxed", (), {"reset_received": False})()

    async def read(self, n: Optional[int] = None) -> bytes:
        self.reads += 1
        if self._payload:
            take = min(self._frame, n or self._frame)
            out, self._payload = self._payload[:take], self._payload[take:]
            return out
        if self._end == "eof":
            raise EOFError()
        if self._end == "reset-as-eof":
            self.muxed_stream.reset_received = True
            raise EOFError()
        if self._end == "reset":
            raise MuxedStreamReset("reset")
        await trio.sleep_forever()


TRICKY = {"a": 'x"}{\\', "b": {"c": [1, {"d": "\\\\"}]}, "e": "é中"}


@pytest.mark.parametrize("frame", [1, 2, 3, 7, 64, 65536])
async def test_ends_at_the_closing_brace_for_every_frame_size(frame):
    body = json.dumps(TRICKY).encode()
    stream = FrameStream(body + b"  trailing", frame=frame)
    assert await read_json_object(stream, 4096) == body


async def test_non_ascii_bytes_are_kept():
    body = json.dumps(TRICKY, ensure_ascii=False).encode()
    stream = FrameStream(body, frame=1)
    assert json.loads(await read_json_object(stream, 4096)) == TRICKY


async def test_leading_whitespace_is_kept_out_of_the_way():
    body = b' \r\n\t{"k": 1}'
    assert await read_json_object(FrameStream(body, frame=1), 64) == body


async def test_message_that_is_not_an_object_raises():
    with pytest.raises(ValueError):
        await read_json_object(FrameStream(b'["list"]'), 64)


async def test_eof_before_the_object_ends_returns_the_bytes():
    assert await read_json_object(FrameStream(b'{"a": "cut', end="eof"), 64) == b'{"a": "cut'


async def test_empty_stream_returns_empty_bytes():
    assert await read_json_object(FrameStream(b"", end="eof"), 64) == b""


async def test_object_of_exactly_the_cap_is_accepted():
    body = b'{"k": "' + b"v" * 93 + b'"}'
    assert len(body) == 102
    assert await read_json_object(FrameStream(body + b"xx", frame=10), 102) == body


async def test_object_over_the_cap_raises():
    body = json.dumps({"k": "v" * 200}).encode()
    with pytest.raises(StreamTooLarge):
        await read_json_object(FrameStream(body, frame=16), 100)


async def test_object_that_never_ends_times_out():
    with pytest.raises(StreamReadTimeout):
        await read_json_object(FrameStream(b'{"k": "never'), 1024, read_timeout=0.05)


@pytest.mark.parametrize("end, error", [("reset", MuxedStreamReset), ("reset-as-eof", StreamReset)])
async def test_reset_in_the_middle_raises(end, error):
    with pytest.raises(error):
        await read_json_object(FrameStream(b'{"k": "half', frame=4, end=end), 1024)


async def test_scan_stays_linear_for_one_byte_frames():
    body = json.dumps({"k": "x" * (512 * 1024)}).encode()
    stream = FrameStream(body, frame=1)
    with trio.fail_after(30):
        assert await read_json_object(stream, len(body)) == body
    assert stream.reads == len(body)
