import json
import trio
import trio_websocket
import pytest
from unittest.mock import MagicMock
from app.container import ServiceContainer

# Import the code to test
# We need to import process_command and websocket_handler from server.py
# But server.py interprets 'main' on import if we are not careful?
# server.py has if __name__ == "__main__": main(), so it should be safe to import.
from server import process_command, websocket_handler

# Mock ServiceContainer
class MockContainer:
    def __init__(self):
        self.settings = MagicMock()
        self.settings.env = "test"
        self.command_handlers = {}
        self.db = MagicMock()
        self.tau_manager = MagicMock()
        self.mempool_state = MagicMock()

# We need a wrapper to launch the handler like _start_websocket_server does, but effectively for testing.
# trio-websocket provides open_websocket_url for clients.
# We can use trio_websocket.serve_websocket in a nursery.

@pytest.fixture
def mock_container():
    return MockContainer()

@pytest.mark.trio
async def test_handshake_success(mock_container, nursery):
    # Setup server
    async def handler_with_container(request):
        request.server_container = mock_container
        await websocket_handler(request)

    server = await nursery.start(trio_websocket.serve_websocket, handler_with_container, "127.0.0.1", 0, None)
    port = server.port

    # Connect client
    async with trio_websocket.open_websocket_url(f"ws://127.0.0.1:{port}") as ws:
        # Send Handshake
        await ws.send_message("hello version=1")
        resp = await ws.get_message()
        assert resp == "ok version=1 env=test node=tau-node"

@pytest.mark.trio
async def test_handshake_failure(mock_container, nursery):
    async def handler_with_container(request):
        request.server_container = mock_container
        await websocket_handler(request)

    server = await nursery.start(trio_websocket.serve_websocket, handler_with_container, "127.0.0.1", 0, None)
    port = server.port

    async with trio_websocket.open_websocket_url(f"ws://127.0.0.1:{port}") as ws:
        await ws.send_message("hello version=99")
        resp = await ws.get_message()
        assert "error unsupported_version" in resp

@pytest.mark.trio
async def test_process_command_integration(mock_container, nursery):
    # Mock a command handler
    mock_handler = MagicMock()
    mock_handler.execute.return_value = "balance: 100"
    mock_container.command_handlers["getbalance"] = mock_handler

    async def handler_with_container(request):
        request.server_container = mock_container
        await websocket_handler(request)

    server = await nursery.start(trio_websocket.serve_websocket, handler_with_container, "127.0.0.1", 0, None)
    port = server.port

    async with trio_websocket.open_websocket_url(f"ws://127.0.0.1:{port}") as ws:
        # Handshake first (optional but good practice)
        await ws.send_message("hello version=1")
        await ws.get_message()

        # Send command
        await ws.send_message("getbalance key123")
        resp = await ws.get_message()
        assert resp == "balance: 100"
        
        # Verify handler called
        mock_handler.execute.assert_called_once()


def _serve(handler, nursery):
    return nursery.start(trio_websocket.serve_websocket, handler, "127.0.0.1", 0, None)


@pytest.mark.trio
async def test_bare_getblocks_over_ws_is_windowed(mock_container, nursery):
    mock_handler = MagicMock()
    mock_handler.execute.return_value = '{"status":"ok","command":"getblocks","data":{}}'
    mock_container.command_handlers["getblocks"] = mock_handler

    async def handler_with_container(request):
        request.server_container = mock_container
        await websocket_handler(request)

    server = await _serve(handler_with_container, nursery)
    async with trio_websocket.open_websocket_url(f"ws://127.0.0.1:{server.port}") as ws:
        await ws.send_message("getblocks")
        await ws.get_message()
    called = mock_handler.execute.call_args[0][0]
    from server import _WS_DEFAULT_GETBLOCKS_LIMIT
    assert called == f"getblocks {_WS_DEFAULT_GETBLOCKS_LIMIT}"


@pytest.mark.trio
async def test_ws_idle_timeout_disconnects(mock_container, nursery):
    async def handler_with_container(request):
        request.server_container = mock_container
        request.ws_idle_timeout = 0.2
        await websocket_handler(request)

    server = await _serve(handler_with_container, nursery)
    async with trio_websocket.open_websocket_url(f"ws://127.0.0.1:{server.port}") as ws:
        await trio.sleep(0.6)
        with pytest.raises(trio_websocket.ConnectionClosed):
            await ws.send_message("hello version=1")


@pytest.mark.trio
async def test_ws_capacity_rejects_additional_clients(mock_container, nursery):
    slots = trio.CapacityLimiter(1)

    async def handler_with_container(request):
        request.server_container = mock_container
        request.ws_slots = slots
        request.ws_idle_timeout = 5.0
        await websocket_handler(request)

    server = await _serve(handler_with_container, nursery)
    url = f"ws://127.0.0.1:{server.port}"
    async with trio_websocket.open_websocket_url(url) as held:
        await held.send_message("hello version=1")
        await held.get_message()
        with pytest.raises(trio_websocket.ConnectionRejected):
            async with trio_websocket.open_websocket_url(url) as _second:
                pass


@pytest.mark.trio
async def test_ws_oversized_response_is_payload_too_large(mock_container, nursery, monkeypatch):
    import server as server_mod

    monkeypatch.setattr(server_mod, "_WS_MAX_RESPONSE_BYTES", 32)
    mock_handler = MagicMock()
    mock_handler.execute.return_value = "x" * 200
    mock_container.command_handlers["getbalance"] = mock_handler

    async def handler_with_container(request):
        request.server_container = mock_container
        await websocket_handler(request)

    server = await _serve(handler_with_container, nursery)
    async with trio_websocket.open_websocket_url(f"ws://127.0.0.1:{server.port}") as ws:
        await ws.send_message("getbalance abc")
        resp = json.loads(await ws.get_message())
    assert resp["status"] == "error"
    assert resp["error"]["code"] == "PAYLOAD_TOO_LARGE"


@pytest.mark.trio
async def test_isolating_nursery_keeps_listener_up_after_handler_crash():
    """A connection-task exception must not cancel the parent nursery."""
    import server as server_mod

    async def boom():
        raise RuntimeError("connection boom")

    async with trio.open_nursery() as handler_n:
        isolator = server_mod._IsolatingNursery(handler_n)
        isolator.start_soon(boom)
        await trio.sleep(0.05)
        # If the isolator leaked the error, this sleep would have been cancelled.
        handler_n.cancel_scope.cancel()

