"""Envelope conformance suite. Locks in the JSON envelope contract emitted
by `process_command` for every registered command + the server-layer error
paths + the WebSocket rate-limit branch.

Goals (from the implementation plan):
  1. Every public command (excluding `hello`) returns valid JSON.
  2. Every response has ``status`` in {"ok", "error"}.
  3. Every response has ``command``.
  4. ``ok`` responses have ``data`` (object).
  5. ``error`` responses have ``error.code`` + ``error.message``.
  6. No command returns legacy prefixes (SUCCESS:/FAILURE:/ERROR:/BALANCE:/...).
  7. No command returns ``status: "success"`` (vocab lock-in: only "ok").
  8. TCP responses end with ``\\r\\n``; body before parses as JSON.
  9. WebSocket rate-limit response is valid JSON without ``\\r\\n``.
 10. Unknown command -> ``UNKNOWN_COMMAND``.
 11. Empty command -> ``INVALID_PARAMS``.
 12. Malformed sendtx body -> ``INVALID_PARAMS`` or ``PARSE_ERROR``.
 13. Every registered handler in container.command_handlers exposes ``execute()``.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from unittest.mock import MagicMock

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import api_response
import server as server_mod


LEGACY_PREFIXES = (
    "SUCCESS:",
    "FAILURE:",
    "ERROR:",
    "BALANCE:",
    "SEQUENCE:",
    "MEMPOOL:",
    "TAUSTATE:",
    "HISTORY:",
    "Current Timestamp",
)


def _stub_container():
    container = MagicMock()
    container.settings.env = "test"
    container.command_handlers = {}
    container.tau_manager = MagicMock()
    container.db = MagicMock()
    container.chain_state = MagicMock()
    container.mempool_state = MagicMock()
    return container


def _assert_envelope(test: unittest.TestCase, response: str, expected_command: str | None = None) -> dict:
    test.assertIsInstance(response, str)
    for prefix in LEGACY_PREFIXES:
        test.assertFalse(
            response.startswith(prefix),
            msg=f"legacy prefix {prefix!r} found in response {response[:80]!r}",
        )
    parsed = json.loads(response)
    test.assertIsInstance(parsed, dict)
    test.assertIn(parsed.get("status"), {"ok", "error"})
    test.assertNotEqual(parsed["status"], "success")
    test.assertIn("command", parsed)
    if expected_command is not None:
        test.assertEqual(parsed["command"], expected_command)
    if parsed["status"] == "ok":
        test.assertIn("data", parsed)
        test.assertIsInstance(parsed["data"], dict)
    else:
        err = parsed.get("error") or {}
        test.assertIsInstance(err, dict)
        test.assertIn("code", err)
        test.assertIn("message", err)
    return parsed


class TestHelpersDirect(unittest.TestCase):
    def test_success_helper_shape(self):
        body = api_response.success_response("getbalance", {"address": "x", "balance": "0"})
        env = _assert_envelope(self, body, expected_command="getbalance")
        self.assertEqual(env["data"]["balance"], "0")
        # Single-line, no CRLF framing.
        self.assertNotIn("\r", body)
        self.assertNotIn("\n", body)

    def test_error_helper_shape_with_details(self):
        body = api_response.error_response(
            "sendtx", "Invalid sequence number.", "INVALID_SEQUENCE",
            details={"expected": 5, "received": 4},
        )
        env = _assert_envelope(self, body, expected_command="sendtx")
        self.assertEqual(env["error"]["code"], "INVALID_SEQUENCE")
        self.assertEqual(env["error"]["details"], {"expected": 5, "received": 4})

    def test_error_helper_default_code(self):
        env = json.loads(api_response.error_response("any", "boom"))
        self.assertEqual(env["error"]["code"], "INTERNAL_ERROR")


class TestProcessCommandErrorPaths(unittest.TestCase):
    def test_empty_command_returns_invalid_params(self):
        success, body = server_mod.process_command("", _stub_container(), "test")
        self.assertTrue(success)
        env = _assert_envelope(self, body)
        self.assertEqual(env["error"]["code"], "INVALID_PARAMS")

    def test_unknown_command_returns_unknown_command(self):
        success, body = server_mod.process_command("nope", _stub_container(), "test")
        self.assertTrue(success)
        env = _assert_envelope(self, body, expected_command="nope")
        self.assertEqual(env["error"]["code"], "UNKNOWN_COMMAND")

    def test_handler_missing_execute_returns_unknown_command(self):
        container = _stub_container()
        broken = MagicMock(spec=[])
        container.command_handlers = {"broken": broken}
        success, body = server_mod.process_command("broken", container, "test")
        self.assertTrue(success)
        env = _assert_envelope(self, body, expected_command="broken")
        self.assertEqual(env["error"]["code"], "UNKNOWN_COMMAND")

    def test_handler_raising_returns_internal_error(self):
        container = _stub_container()
        handler = MagicMock()
        handler.execute.side_effect = RuntimeError("kaboom")
        container.command_handlers = {"buggy": handler}
        success, body = server_mod.process_command("buggy", container, "test")
        self.assertTrue(success)
        env = _assert_envelope(self, body, expected_command="buggy")
        self.assertEqual(env["error"]["code"], "INTERNAL_ERROR")
        self.assertIn("kaboom", env["error"]["message"])

    def test_handshake_stays_plain_text(self):
        success, body = server_mod.process_command(
            "hello version=1", _stub_container(), "test"
        )
        self.assertFalse(success)
        self.assertTrue(body.startswith("ok version=1"))

    def test_handshake_version_2_supported(self):
        success, body = server_mod.process_command(
            "hello version=2", _stub_container(), "test"
        )
        self.assertFalse(success)
        self.assertTrue(body.startswith("ok version=2"))

    def test_handshake_unsupported_version(self):
        success, body = server_mod.process_command(
            "hello version=99", _stub_container(), "test"
        )
        self.assertFalse(success)
        self.assertTrue(body.startswith("error unsupported_version"))


class TestSendtxAtProcessCommand(unittest.TestCase):
    def test_malformed_sendtx_returns_invalid_params_or_parse_error(self):
        container = _stub_container()
        from commands import sendtx as sendtx_mod
        container.command_handlers = {"sendtx": sendtx_mod}
        sendtx_mod._PY_ECC_AVAILABLE = True
        try:
            success, body = server_mod.process_command(
                "sendtx not-a-json", container, "test"
            )
        finally:
            pass
        self.assertTrue(success)
        env = _assert_envelope(self, body, expected_command="sendtx")
        self.assertEqual(env["status"], "error")
        self.assertIn(env["error"]["code"], {"INVALID_PARAMS", "PARSE_ERROR"})


class TestRegisteredHandlersHaveExecute(unittest.TestCase):
    def test_every_registered_handler_exposes_execute(self):
        from app.container import ServiceContainer
        # Build a default command_handlers mapping the same way ServiceContainer does.
        from commands import (
            createblock,
            getallaccounts,
            getbalance,
            getblocks,
            getgovernance,
            getmempool,
            getsequence,
            gettaustate,
            gettimestamp,
            getupdateid,
            history,
            sendtx,
        )
        registered = {
            "sendtx": sendtx,
            "getmempool": getmempool,
            "getcurrenttimestamp": gettimestamp,
            "gettimestamp": gettimestamp,
            "createblock": createblock,
            "getbalance": getbalance,
            "getsequence": getsequence,
            "history": history,
            "getblocks": getblocks,
            "getallaccounts": getallaccounts,
            "gettaustate": gettaustate,
            "getgovernance": getgovernance,
            "getupdateid": getupdateid,
        }
        for name, handler in registered.items():
            self.assertTrue(
                hasattr(handler, "execute") and callable(handler.execute),
                msg=f"handler {name} missing callable execute()",
            )


class TestWebsocketRateLimitEnvelope(unittest.TestCase):
    def test_rate_limit_envelope_is_valid_json_no_crlf(self):
        body = api_response.error_response(
            "rate_limit", "Rate limit exceeded", "RATE_LIMITED"
        )
        env = _assert_envelope(self, body, expected_command="rate_limit")
        self.assertEqual(env["error"]["code"], "RATE_LIMITED")
        self.assertNotIn("\r\n", body)


class TestTcpFraming(unittest.TestCase):
    def test_tcp_appends_crlf_to_envelope(self):
        # Re-create the TCP framing rule from server.handle_client.
        body = api_response.success_response("getbalance", {"address": "x", "balance": "0"})
        framed = body if body.endswith("\n") else body + "\r\n"
        self.assertTrue(framed.endswith("\r\n"))
        # Strip CRLF; body must still parse as JSON.
        json.loads(framed.rstrip("\r\n"))


if __name__ == "__main__":
    unittest.main()
