"""Uniform JSON envelope helpers for blockchain API responses.

Every command handler and server-layer error path returns one of two shapes:

    {"status":"ok","command":"<name>","data":{...}}
    {"status":"error","command":"<name>","error":{"code":"<CODE>","message":"<text>","details":{...}?}}

Serialization is transport-agnostic: helpers return a single-line JSON string
without `\\r\\n`. The TCP transport adds CRLF framing at the wire; WebSocket
emits the raw string. Tests and the CLI consume the unframed string directly.
"""
from __future__ import annotations

import json
from typing import Any, Mapping, Optional


def success_response(command: str, data: Mapping[str, Any]) -> str:
    return json.dumps(
        {"status": "ok", "command": command, "data": dict(data)},
        separators=(",", ":"),
    )


def error_response(
    command: str,
    message: str,
    code: str = "INTERNAL_ERROR",
    details: Optional[Mapping[str, Any]] = None,
) -> str:
    err: dict[str, Any] = {"code": code, "message": message}
    if details is not None:
        err["details"] = dict(details)
    return json.dumps(
        {"status": "error", "command": command, "error": err},
        separators=(",", ":"),
    )
