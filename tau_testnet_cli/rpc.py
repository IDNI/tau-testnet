"""TCP RPC client for the Tau Testnet node.

Mirrors the on-the-wire protocol used by the existing wallet/server: each
command is a single line terminated by ``\\r\\n``; the server writes its
response (also CRLF-terminated) and closes the connection.

Improvements over ``wallet.rpc_command``:
- reads until socket close or ``max_bytes`` instead of a single 64 KiB ``recv``
  (which silently truncates large ``getgovernance`` JSON);
- honours ``timeout``;
- raises typed exceptions for transport-level failures so the CLI can map
  them to exit code 3.

Application-level ``ERROR: ...`` responses are *not* exceptions — they are
returned verbatim. The CLI command handler decides what to do with them.
"""

from __future__ import annotations

import json
import socket

DEFAULT_TIMEOUT = 10.0
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
_RECV_CHUNK = 64 * 1024


class RpcError(Exception):
    """Base class for transport-level RPC failures."""


class RpcConnectionError(RpcError):
    """Connection refused, DNS failure, reset by peer, etc."""


class RpcTimeoutError(RpcError):
    """No data received within ``timeout`` seconds."""


class RpcSizeLimitError(RpcError):
    """Response exceeded ``max_bytes``."""


def _ensure_crlf(command: str) -> bytes:
    if not command.endswith("\r\n"):
        command = command + "\r\n"
    return command.encode("utf-8")


def send_command(
    command: str,
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
) -> str:
    """Send a single command and return the server's response.

    The server runs a per-connection request loop and only closes the socket
    once the client signals end-of-input (via ``shutdown(SHUT_WR)`` or by
    closing the socket). To support large responses we therefore: send the
    command, half-close the write side, then read until the server closes
    its end of the connection.

    The trailing ``\\r\\n`` is stripped from the returned string. The raw
    bytes are returned verbatim — including responses that start with
    ``ERROR:``. Interpretation of error strings is the caller's job.
    """
    payload = _ensure_crlf(command)
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(payload)
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                # Some platforms / proxies reject half-close; fall back to a
                # plain read. The server loop will close on its own once we
                # disconnect.
                pass
            chunks: list[bytes] = []
            received = 0
            while True:
                try:
                    chunk = sock.recv(_RECV_CHUNK)
                except socket.timeout as exc:
                    raise RpcTimeoutError(
                        f"timed out reading response from {host}:{port} after {timeout}s"
                    ) from exc
                if not chunk:
                    break
                received += len(chunk)
                if received > max_bytes:
                    raise RpcSizeLimitError(
                        f"response from {host}:{port} exceeded {max_bytes} bytes"
                    )
                chunks.append(chunk)
    except RpcError:
        raise
    except socket.timeout as exc:
        raise RpcTimeoutError(
            f"timed out connecting to {host}:{port} after {timeout}s"
        ) from exc
    except OSError as exc:
        raise RpcConnectionError(f"failed to connect to {host}:{port}: {exc}") from exc

    data = b"".join(chunks).decode("utf-8", errors="replace")
    if data.endswith("\r\n"):
        data = data[:-2]
    elif data.endswith("\n"):
        data = data[:-1]
    return data


def handshake(
    host: str,
    port: int,
    *,
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Send ``hello version=1`` and return the response (expected ``ok version=1 ...``)."""
    return send_command("hello version=1", host, port, timeout=timeout)


def is_error_response(response: str) -> bool:
    """Whether a server response should map to CLI exit code 1.

    Data API responses are JSON envelopes: ``{"status":"error",...}`` -> error.
    Handshake replies (``ok version=...`` / ``error <code>``) are plain text and
    handled separately by the handshake code path; this helper still flags the
    ``error `` prefix so direct callers can short-circuit.
    """
    try:
        parsed = json.loads(response)
    except (ValueError, TypeError):
        return response.startswith("error ")
    return isinstance(parsed, dict) and parsed.get("status") == "error"
