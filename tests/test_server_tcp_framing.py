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

    def settimeout(self, _timeout):
        pass

    def close(self):
        pass


class TestLegacyClientFraming(unittest.TestCase):
    """The legacy raw-TCP senders must newline-terminate their command so the
    newline-framed server dispatches instead of waiting for a delimiter that
    never arrives (verify_server did not before issue #24's fix).

    wallet and verify_server now reach the wire through
    ``tau_testnet_cli.rpc.send_command`` (which uses ``socket.create_connection``)
    so that a response larger than one recv is not truncated; they are patched at
    that layer. demo_governance still opens its own socket. The assertion is
    unchanged in all three cases: whatever the transport, the command leaves
    newline-terminated.
    """

    def _last_sent(self):
        return _FakeClientSocket.instances[-1].sent

    @staticmethod
    def _fake_connection(*_args, **_kwargs):
        return _FakeClientSocket()

    def test_wallet_rpc_command_newline_terminates(self):
        import wallet
        with patch("socket.create_connection", self._fake_connection):
            _FakeClientSocket.instances.clear()
            wallet.rpc_command("getbalance abc", "127.0.0.1", 65432)
        self.assertTrue(self._last_sent().endswith(b"\n"))

    def test_verify_server_send_command_newline_terminates(self):
        from scripts import verify_server
        with patch("socket.create_connection", self._fake_connection):
            _FakeClientSocket.instances.clear()
            verify_server.send_command("gettimestamp")
        self.assertTrue(self._last_sent().endswith(b"\n"))

    def test_demo_governance_rpc_command_newline_terminates(self):
        from scripts import demo_governance
        with patch("socket.socket", _FakeClientSocket):
            _FakeClientSocket.instances.clear()
            demo_governance.rpc_command("getgovernance", "127.0.0.1", 65432)
        self.assertTrue(self._last_sent().endswith(b"\n"))


def _serve_once(payload: bytes, ready: threading.Event) -> int:
    """Bind a loopback listener that answers one command with `payload`.

    Returns the bound port. The thread reads one newline-framed command (like
    the real server does) and then writes the payload in small chunks, closing
    to signal end-of-response.

    Reading to the newline rather than to EOF matters: a client that does not
    half-close its write side — which is exactly the pre-fix behaviour — would
    otherwise deadlock here and hang the suite instead of failing.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    srv.settimeout(10)
    port = srv.getsockname()[1]

    def run():
        ready.set()
        try:
            conn, _ = srv.accept()
            conn.settimeout(10)
            with conn:
                buf = b""
                while b"\n" not in buf:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                view = memoryview(payload)
                for off in range(0, len(view), 8192):
                    conn.sendall(view[off:off + 8192])
        except OSError:
            pass
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    return port


class TestClientReadsFullResponse(unittest.TestCase):
    """Issue #24, client side: the legacy senders did a single ``recv`` (64 KiB
    in wallet, 4 KiB in verify_server) and returned whatever arrived in it, so a
    larger response — a `getgovernance` carrying scheduled rule text, or a
    `history` on a busy account — came back truncated mid-payload and failed to
    parse. Both now read until the server closes.
    """

    # Comfortably past wallet's old 64 KiB recv and verify_server's old 4 KiB.
    PAYLOAD = json.dumps({
        "status": "ok",
        "command": "getgovernance",
        "data": {"scheduled_updates": [{"rule": "x" * 200} for _ in range(500)]},
    }).encode("utf-8") + b"\r\n"

    def setUp(self):
        self.assertGreater(len(self.PAYLOAD), 100 * 1024, "payload must exceed one recv")

    def test_wallet_rpc_command_reads_large_response(self):
        import wallet
        ready = threading.Event()
        port = _serve_once(self.PAYLOAD, ready)
        ready.wait(5)
        res = wallet.rpc_command("getgovernance", "127.0.0.1", port)
        # Whole payload, and still valid JSON — the truncated read produced a
        # JSONDecodeError here.
        self.assertEqual(len(res), len(self.PAYLOAD) - 2)  # trailing CRLF stripped
        parsed = json.loads(res)
        self.assertEqual(len(parsed["data"]["scheduled_updates"]), 500)

    def test_verify_server_send_command_reads_large_response(self):
        from scripts import verify_server
        ready = threading.Event()
        port = _serve_once(self.PAYLOAD, ready)
        ready.wait(5)
        res = verify_server.send_command("getgovernance", "127.0.0.1", port)
        self.assertEqual(len(json.loads(res)["data"]["scheduled_updates"]), 500)


if __name__ == "__main__":
    unittest.main()
