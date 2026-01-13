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
        await ws.send_message("hello version=2")
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
    
