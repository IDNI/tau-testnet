"""Tests for tau_testnet_cli.rpc."""

from __future__ import annotations

import socket
from unittest.mock import patch

import pytest

from tau_testnet_cli import rpc as rpc_mod


class FakeSocket:
    """Minimal stand-in for socket.create_connection's return value."""

    def __init__(self, response_chunks, recv_raises=None):
        self._response_chunks = list(response_chunks)
        self._recv_raises = recv_raises
        self.sent: bytes = b""
        self.timeout: float | None = None
        self.closed = False

    # context manager protocol
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.closed = True
        return False

    def settimeout(self, value):
        self.timeout = value

    def shutdown(self, how):
        # Real sockets half-close; the fake has nothing to do.
        self.shutdown_called = how

    def sendall(self, payload):
        self.sent += payload

    def recv(self, _bufsize):
        if self._recv_raises is not None:
            exc = self._recv_raises
            self._recv_raises = None
            raise exc
        if self._response_chunks:
            return self._response_chunks.pop(0)
        return b""


def _patch_create_connection(fake):
    return patch("tau_testnet_cli.rpc.socket.create_connection", return_value=fake)


def test_send_command_appends_crlf_and_strips_trailing():
    fake = FakeSocket([b'{"status":"ok","command":"getbalance","data":{"address":"abc","balance":"100"}}\r\n'])
    with _patch_create_connection(fake):
        result = rpc_mod.send_command("getbalance abc", "127.0.0.1", 65432)
    assert fake.sent == b"getbalance abc\r\n"
    assert result == '{"status":"ok","command":"getbalance","data":{"address":"abc","balance":"100"}}'


def test_send_command_does_not_double_crlf():
    fake = FakeSocket([b"OK\r\n"])
    with _patch_create_connection(fake):
        rpc_mod.send_command("ping\r\n", "127.0.0.1", 65432)
    assert fake.sent == b"ping\r\n"


def test_send_command_reads_until_socket_close():
    chunks = [b"line1\r\n", b"line2\r\n", b"line3\r\n"]
    fake = FakeSocket(chunks)
    with _patch_create_connection(fake):
        result = rpc_mod.send_command("getblocks", "127.0.0.1", 65432)
    assert result == "line1\r\nline2\r\nline3"


def test_send_command_returns_error_response_verbatim():
    envelope = b'{"status":"error","command":"badcmd","error":{"code":"UNKNOWN_COMMAND","message":"Unknown command \'badcmd\'"}}\r\n'
    fake = FakeSocket([envelope])
    with _patch_create_connection(fake):
        result = rpc_mod.send_command("badcmd", "127.0.0.1", 65432)
    assert '"status":"error"' in result
    assert rpc_mod.is_error_response(result)


def test_send_command_timeout_during_recv_raises():
    fake = FakeSocket([], recv_raises=socket.timeout("read timeout"))
    with _patch_create_connection(fake), pytest.raises(rpc_mod.RpcTimeoutError):
        rpc_mod.send_command("ping", "127.0.0.1", 65432, timeout=0.1)


def test_send_command_connect_failure_raises_connection_error():
    with patch(
        "tau_testnet_cli.rpc.socket.create_connection",
        side_effect=ConnectionRefusedError("nope"),
    ):
        with pytest.raises(rpc_mod.RpcConnectionError):
            rpc_mod.send_command("ping", "127.0.0.1", 65432)


def test_send_command_size_limit_enforced():
    big = b"X" * (256 * 1024)
    chunks = [big] * 5  # 1.25 MB total
    fake = FakeSocket(chunks)
    with _patch_create_connection(fake), pytest.raises(rpc_mod.RpcSizeLimitError):
        rpc_mod.send_command(
            "getgovernance",
            "127.0.0.1",
            65432,
            max_bytes=512 * 1024,
        )


def test_handshake_sends_hello_v1():
    fake = FakeSocket([b"ok version=1 env=test node=tau-node\r\n"])
    with _patch_create_connection(fake):
        result = rpc_mod.handshake("127.0.0.1", 65432)
    assert fake.sent == b"hello version=1\r\n"
    assert result.startswith("ok version=1")


def test_is_error_response():
    assert rpc_mod.is_error_response(
        '{"status":"error","command":"sendtx","error":{"code":"TX_REJECTED","message":"nope"}}'
    )
    assert rpc_mod.is_error_response(
        '{"status":"error","command":"","error":{"code":"INVALID_PARAMS","message":"bad"}}'
    )
    # Plain-text handshake errors still flagged so callers can short-circuit.
    assert rpc_mod.is_error_response("error malformed_handshake")
    assert not rpc_mod.is_error_response(
        '{"status":"ok","command":"getbalance","data":{"address":"x","balance":"10"}}'
    )
    assert not rpc_mod.is_error_response("ok version=1 env=test")
    # Garbage / non-JSON / non-handshake bodies are not classified as errors.
    assert not rpc_mod.is_error_response("nonsense")
