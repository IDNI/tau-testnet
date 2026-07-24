"""TCP ingest framing for server.handle_client (issue #24 sibling bug).

The raw-TCP handler used to treat each fixed-size ``recv()`` chunk as a whole
command, so a command larger than ``BUFFER_SIZE`` (e.g. a rule-deploy ``sendtx``
carrying ``bv[384]`` pubkey constants) was truncated mid-payload. It now buffers
bytes and dispatches complete newline-delimited commands, flushing an
unterminated remainder on EOF, with an anti-DoS cap on the pending buffer.

These tests drive handle_client with a MagicMock socket (recv.side_effect feeds
the exact byte chunks), mirroring tests/test_audit_fixes.py.
"""

import json
import os
import socket
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
from server import handle_client
from app.container import ServiceContainer


def _make_container(handlers=None):
    container = MagicMock(spec=ServiceContainer)
    container.command_handlers = handlers or {}
    container.tau_manager = MagicMock()
    container.db = MagicMock()
    container.chain_state = MagicMock()
    container.mempool_state = MagicMock()
    return container


def _handler(return_value="ok"):
    h = MagicMock()
    h.execute.return_value = return_value
    return h


class TestTcpFraming(unittest.TestCase):
    def test_large_command_split_across_recvs_is_reassembled(self):
        """A command bigger than BUFFER_SIZE, delivered in pieces, is reassembled
        into a single dispatch instead of being truncated."""
        handler = _handler()
        container = _make_container({"echo": handler})

        arg = "x" * 5000  # >> BUFFER_SIZE (1024)
        full = f"echo {arg}"
        wire = (full + "\r\n").encode("utf-8")
        mid = len(wire) // 2
        conn = MagicMock()
        conn.recv.side_effect = [wire[:mid], wire[mid:], b""]

        handle_client(conn, ("127.0.0.1", 1234), container)

        self.assertEqual(handler.execute.call_count, 1)
        raw_cmd = handler.execute.call_args[0][0]
        self.assertEqual(raw_cmd, full)  # full payload, not truncated at 1024

    def test_two_commands_in_one_recv_dispatched_twice(self):
        handler = _handler()
        container = _make_container({"ping": handler})
        conn = MagicMock()
        conn.recv.side_effect = [b"ping 1\nping 2\n", b""]

        handle_client(conn, ("127.0.0.1", 1234), container)

        self.assertEqual(handler.execute.call_count, 2)
        self.assertEqual(conn.sendall.call_count, 2)
        self.assertEqual(handler.execute.call_args_list[0][0][0], "ping 1")
        self.assertEqual(handler.execute.call_args_list[1][0][0], "ping 2")

    def test_unterminated_command_flushed_on_eof(self):
        """A final command with no trailing newline is still dispatched when the
        client closes (preserves legacy no-delimiter clients + test_audit_fixes)."""
        handler = _handler("pong")
        container = _make_container({"ping": handler})
        conn = MagicMock()
        conn.recv.side_effect = [b"ping now", b""]  # no newline before EOF

        handle_client(conn, ("127.0.0.1", 1234), container)

        self.assertEqual(handler.execute.call_count, 1)
        self.assertEqual(handler.execute.call_args[0][0], "ping now")

    def test_command_reassembled_only_after_delimiter(self):
        """Partial bytes without a newline are buffered, not dispatched, until the
        delimiter arrives in a later recv."""
        handler = _handler()
        container = _make_container({"ping": handler})
        conn = MagicMock()
        conn.recv.side_effect = [b"pi", b"ng once\n", b""]

        handle_client(conn, ("127.0.0.1", 1234), container)

        self.assertEqual(handler.execute.call_count, 1)
        self.assertEqual(handler.execute.call_args[0][0], "ping once")

    def test_oversized_pending_command_rejected_and_closed(self):
        """A pending (unterminated) command exceeding MAX_RPC_COMMAND_BYTES is
        rejected with PARSE_ERROR and the connection closed, rather than buffering
        without bound."""
        container = _make_container({})
        old_cap = config.MAX_RPC_COMMAND_BYTES
        config.MAX_RPC_COMMAND_BYTES = 16  # shrink so the test stays cheap
        try:
            conn = MagicMock()
            conn.recv.side_effect = [b"x" * 64, b""]  # 64B, no newline > cap
            handle_client(conn, ("127.0.0.1", 1234), container)

            self.assertEqual(conn.sendall.call_count, 1)
            sent = conn.sendall.call_args[0][0].decode("utf-8").rstrip("\r\n")
            parsed = json.loads(sent)
            self.assertEqual(parsed["status"], "error")
            self.assertEqual(parsed["error"]["code"], "PARSE_ERROR")
            self.assertIn("maximum size", parsed["error"]["message"])
        finally:
            config.MAX_RPC_COMMAND_BYTES = old_cap

    def test_real_socketpair_reassembles_large_command(self):
        """End-to-end over a genuine socket: real recv() chunks at BUFFER_SIZE, so
        a >BUFFER_SIZE command exercises the actual reassembly path (not a mock)."""
        handler = _handler("done")
        container = _make_container({"echo": handler})
        srv, cli = socket.socketpair()
        try:
            t = threading.Thread(
                target=handle_client, args=(srv, ("127.0.0.1", 1), container)
            )
            t.start()

            arg = "y" * 4096  # >> BUFFER_SIZE (1024) -> multiple real recv() reads
            full = f"echo {arg}"
            cli.sendall((full + "\r\n").encode("utf-8"))
            cli.shutdown(socket.SHUT_WR)  # half-close so the handler's loop ends

            cli.settimeout(5)
            resp = b""
            while True:
                chunk = cli.recv(4096)
                if not chunk:
                    break
                resp += chunk
            t.join(5)
            self.assertFalse(t.is_alive())
            self.assertEqual(handler.execute.call_count, 1)
            self.assertEqual(handler.execute.call_args[0][0], full)
            self.assertTrue(resp.endswith(b"\r\n"))
            self.assertEqual(resp.decode("utf-8").rstrip("\r\n"), "done")
        finally:
            cli.close()

    def test_response_is_crlf_framed(self):
        handler = _handler("balance: 100")
        container = _make_container({"getbalance": handler})
        conn = MagicMock()
        conn.recv.side_effect = [b"getbalance abc\r\n", b""]

        handle_client(conn, ("127.0.0.1", 1234), container)

        sent = conn.sendall.call_args[0][0]
        self.assertTrue(sent.endswith(b"\r\n"))
        self.assertEqual(sent.decode("utf-8").rstrip("\r\n"), "balance: 100")


class _FakeClientSocket:
    """Captures bytes written by a raw-TCP client (context-manager socket)."""

    instances: list = []

    def __init__(self, *args, **kwargs):
        self.sent = b""
        _FakeClientSocket.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def connect(self, addr):
        self.addr = addr

    def sendall(self, payload):
        self.sent += payload

    def recv(self, _bufsize):
        return b""  # empty response -> clients terminate cleanly

    def shutdown(self, how):
        pass


class TestLegacyClientFraming(unittest.TestCase):
    """The legacy raw-TCP senders must newline-terminate their command so the
    newline-framed server dispatches instead of waiting for a delimiter that
    never arrives (verify_server did not before issue #24's fix)."""

    def _last_sent(self):
        return _FakeClientSocket.instances[-1].sent

    def test_wallet_rpc_command_newline_terminates(self):
        import wallet
        with patch("socket.socket", _FakeClientSocket):
            _FakeClientSocket.instances.clear()
            wallet.rpc_command("getbalance abc", "127.0.0.1", 65432)
        self.assertTrue(self._last_sent().endswith(b"\n"))

    def test_verify_server_send_command_newline_terminates(self):
        from scripts import verify_server
        with patch("socket.socket", _FakeClientSocket):
            _FakeClientSocket.instances.clear()
            verify_server.send_command("gettimestamp")
        self.assertTrue(self._last_sent().endswith(b"\n"))

    def test_demo_governance_rpc_command_newline_terminates(self):
        from scripts import demo_governance
        with patch("socket.socket", _FakeClientSocket):
            _FakeClientSocket.instances.clear()
            demo_governance.rpc_command("getgovernance", "127.0.0.1", 65432)
        self.assertTrue(self._last_sent().endswith(b"\n"))


if __name__ == "__main__":
    unittest.main()
