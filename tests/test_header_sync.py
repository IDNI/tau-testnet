"""Header-sync transport: read-to-EOF."""
from __future__ import annotations

from typing import List, Optional

import pytest

from network.libp2p_compat import StreamTooLarge, read_until_eof

pytestmark = pytest.mark.trio

FRAME = 64 * 1024


class ChunkedStream:
    """Delivers `payload` one frame at a time, then signals EOF the given way."""

    def __init__(self, payload: bytes, eof: str = "empty", frame: int = FRAME):
        self._buf = payload
        self._eof = eof
        self._frame = frame
        self.read_sizes: List[int] = []

    async def read(self, n: Optional[int] = None):
        self.read_sizes.append(-1 if n is None else n)
        if not self._buf:
            if self._eof == "raise":
                raise EOFError()
            if self._eof == "none":
                return None
            return b""
        take = min(self._frame, n if n is not None else self._frame)
        out, self._buf = self._buf[:take], self._buf[take:]
        return out


# --------------------------------------------------------------------------
# read_until_eof
# --------------------------------------------------------------------------


@pytest.mark.parametrize("eof", ["empty", "raise", "none"])
async def test_read_until_eof_collects_every_frame(eof):
    payload = bytes(range(256)) * 800  # ~200 KB, several frames
    stream = ChunkedStream(payload, eof=eof)
    assert await read_until_eof(stream, 2 * 1024 * 1024) == payload
    assert len(stream.read_sizes) > 3


async def test_read_until_eof_empty_stream():
    assert await read_until_eof(ChunkedStream(b""), 1024) == b""


async def test_read_until_eof_accepts_exactly_the_cap():
    payload = b"x" * 1000
    assert await read_until_eof(ChunkedStream(payload, frame=300), 1000) == payload


async def test_read_until_eof_raises_over_cap():
    with pytest.raises(StreamTooLarge):
        await read_until_eof(ChunkedStream(b"x" * 1001, frame=300), 1000)


async def test_read_until_eof_propagates_other_errors():
    class Resetting:
        async def read(self, n=None):
            raise ConnectionResetError("reset")

    with pytest.raises(ConnectionResetError):
        await read_until_eof(Resetting(), 1024)
