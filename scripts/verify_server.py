#!/usr/bin/env python3
"""Smoke-check a running node's read commands over the TCP RPC port.

Usage: python scripts/verify_server.py [host] [port]

Exits non-zero on the first failure.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tau_testnet_cli import rpc  # noqa: E402

HOST = '127.0.0.1'
PORT = 65432


def send_command(cmd, host=HOST, port=PORT):
    """Send one command and return the full response.

    Delegates to the CLI's RPC client, which reads until the server closes
    instead of a single ``recv(4096)`` — that truncated any larger response
    mid-payload (issue #24).
    """
    try:
        return rpc.send_command(cmd, host, port)
    except rpc.RpcError as exc:
        return f"ERROR: {exc}"


def _ok(cmd, res, expect_command, *, expect_keys=()):
    """Assert the response is a well-formed ok envelope for `expect_command`."""
    try:
        parsed = json.loads(res)
    except ValueError as exc:
        raise AssertionError(f"{cmd}: response is not JSON ({exc}): {res[:200]!r}")
    if parsed.get("status") != "ok":
        raise AssertionError(f"{cmd}: expected status ok, got {res[:200]!r}")
    if parsed.get("command") != expect_command:
        raise AssertionError(
            f"{cmd}: expected command {expect_command!r}, got {parsed.get('command')!r}"
        )
    data = parsed.get("data")
    if not isinstance(data, dict):
        raise AssertionError(f"{cmd}: expected a data object, got {type(data).__name__}")
    for key in expect_keys:
        if key not in data:
            raise AssertionError(f"{cmd}: data is missing {key!r}: {sorted(data)}")
    return data


def verify(host=HOST, port=PORT):
    print(f"Verifying commands against {host}:{port} ...")
    genesis = ("91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d2772"
               "12e8aa23e0e10c887cb4b6340d2eebce6")

    checks = [
        ("gettimestamp", "gettimestamp", ()),
        (f"getbalance {genesis}", "getbalance", ("address", "balance")),
        (f"getsequence {genesis}", "getsequence", ("sequence_number",)),
        (f"history {genesis}", "history", ()),
        # Exercises a response large enough that the old single-recv truncated.
        ("getgovernance", "getgovernance", ("head_number", "approval_threshold")),
    ]

    for cmd, expect_command, expect_keys in checks:
        res = send_command(cmd, host, port)
        data = _ok(cmd, res, expect_command, expect_keys=expect_keys)
        preview = json.dumps(data)
        if len(preview) > 120:
            preview = preview[:117] + "..."
        print(f"  {cmd.split()[0]}: {preview}")

    print("Verification successful!")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
    try:
        verify(host, port)
    except AssertionError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        sys.exit(1)
