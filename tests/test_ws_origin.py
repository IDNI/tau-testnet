"""The WebSocket Origin allowlist compares the parsed origin, not a substring."""
from unittest.mock import MagicMock

import pytest
import trio_websocket

from server import websocket_handler


class _Container:
    def __init__(self):
        self.settings = MagicMock()
        self.settings.env = "test"
        self.command_handlers = {}
        self.db = MagicMock()
        self.tau_manager = MagicMock()
        self.mempool_state = MagicMock()


async def _serve(nursery):
    container = _Container()

    async def handler(request):
        request.server_container = container
        await websocket_handler(request)

    return await nursery.start(trio_websocket.serve_websocket, handler, "127.0.0.1", 0, None)


async def _first_reply(nursery, origin):
    server = await _serve(nursery)
    headers = [] if origin is None else [("Origin", origin)]
    async with trio_websocket.open_websocket_url(
        f"ws://127.0.0.1:{server.port}", extra_headers=headers
    ) as ws:
        await ws.send_message("hello version=1")
        try:
            return await ws.get_message()
        except trio_websocket.ConnectionClosed:
            return "closed"


async def _expect_rejected(nursery, origin):
    server = await _serve(nursery)
    headers = [] if origin is None else [("Origin", origin)]
    with pytest.raises(trio_websocket.ConnectionRejected) as excinfo:
        async with trio_websocket.open_websocket_url(
            f"ws://127.0.0.1:{server.port}", extra_headers=headers
        ):
            pass
    exc = excinfo.value
    assert exc.status_code == 403
    assert exc.body == b"error disallowed_origin"


REFUSED = [
    ("https://evil.example", ""),
    ("not a url", ""),
    ("https://localhost.example.com", ""),
    ("http://127.0.0.1.example.com", ""),
    ("https://evil-localhost.com", ""),
    ("https://example.com/?localhost", ""),
    ("https://tau.net.example.com", "https://tau.net"),
    ("https://tau.net.example.com", "tau.net"),
    ("https://nottau.net", "tau.net"),
    ("http://tau.net", "https://tau.net"),
    ("https://tau.net:8443", "https://tau.net"),
    ("null", ""),
    ("", ""),
]

ALLOWED = [
    (None, ""),
    ("null", "null"),
    ("null", "*"),
    ("http://localhost:8080", ""),
    ("http://LOCALHOST", ""),
    ("http://127.0.0.1:5173", ""),
    ("http://[::1]:8080", ""),
    ("https://tau.net", "https://tau.net"),
    ("https://tau.net", "https://tau.net/"),
    ("https://tau.net:443", "https://tau.net"),
    ("https://tau.net", "tau.net"),
    ("https://wallet.example.org", "https://tau.net, https://wallet.example.org"),
    ("https://anything.example", "*"),
]


@pytest.mark.trio
@pytest.mark.parametrize("origin,allowed", REFUSED)
async def test_origin_is_refused(nursery, monkeypatch, origin, allowed):
    monkeypatch.setenv("TAU_WS_ALLOWED_ORIGINS", allowed)
    await _expect_rejected(nursery, origin)


@pytest.mark.trio
@pytest.mark.parametrize("origin,allowed", ALLOWED)
async def test_origin_is_allowed(nursery, monkeypatch, origin, allowed):
    monkeypatch.setenv("TAU_WS_ALLOWED_ORIGINS", allowed)
    assert (await _first_reply(nursery, origin)).startswith("ok version=1")
