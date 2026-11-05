"""The Android wallet must sign the same preimage that the node verifies.

The test reads the keys of `payloadNoSig` from MainActivity.kt and builds the
preimage with a Python copy of the canonicalJson function of the app.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest

from consensus.tx_signing import signing_message_bytes, verify_tx_signature
from tests.bls_keys import SK_ALICE, pubkey_hex, sign_message

MAIN_ACTIVITY = (
    Path(__file__).resolve().parent.parent
    / "android/app/src/main/java/org/tau/wallet/MainActivity.kt"
)


def _payload_keys_of_app() -> dict:
    """Return the map of `payloadNoSig` in MainActivity.kt as {key: kotlin expression}."""
    src = MAIN_ACTIVITY.read_text(encoding="utf-8")
    m = re.search(r"val payloadNoSig = mapOf\((.*?)\n\s*\)", src, re.S)
    assert m, "payloadNoSig not found in MainActivity.kt"
    return dict(re.findall(r'"(\w+)" to ([^\n]+?),?\s*$', m.group(1), re.M))


def _kotlin_to_json(value) -> str:
    """Copy of MainActivity.toJson(value, sorted = true)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return '"' + _kotlin_escape(value) + '"'
    if isinstance(value, int):
        return str(value)
    if isinstance(value, dict):
        parts = [f'"{k}":{_kotlin_to_json(value[k])}' for k in sorted(value)]
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_kotlin_to_json(v) for v in value) + "]"
    raise TypeError(type(value))


_KOTLIN_ESCAPES = {
    ord("\\"): "\\\\",
    ord('"'): '\\"',
    ord("\n"): "\\n",
    ord("\r"): "\\r",
    ord("\t"): "\\t",
    ord("\b"): "\\b",
    ord("\f"): "\\f",
}


def _kotlin_escape(s: str) -> str:
    """Escape a string as toJson does, one UTF-16 unit at a time, as Kotlin iterates a String."""
    raw = s.encode("utf-16-be", "surrogatepass")
    units = [int.from_bytes(raw[i:i + 2], "big") for i in range(0, len(raw), 2)]
    out = []
    plain = []
    for unit in units:
        if unit in _KOTLIN_ESCAPES:
            esc = _KOTLIN_ESCAPES[unit]
        elif unit < 32:
            esc = "\\u%04x" % unit
        else:
            plain.append(unit)
            continue
        out.append(_units_to_str(plain))
        plain = []
        out.append(esc)
    out.append(_units_to_str(plain))
    return "".join(out)


def _units_to_str(units) -> str:
    return b"".join(u.to_bytes(2, "big") for u in units).decode("utf-16-be", "surrogatepass")


def _app_payload(operations: dict) -> dict:
    """The payloadNoSig of the app, with the Kotlin values replaced by test values."""
    values = {
        "sender_pubkey": pubkey_hex(SK_ALICE),
        "sequence_number": 3,
        "expiration_time": 1_900_000_000,
        "expire_at_height": 1234,
        "operations": operations,
        "fee_limit": "10",
    }
    payload = {}
    for key, expr in _payload_keys_of_app().items():
        if key in values:
            payload[key] = values[key]
        else:
            literal = re.fullmatch(r'"([^"]*)"', expr.strip())
            assert literal, f"no test value for app field {key!r} = {expr}"
            payload[key] = literal.group(1)
    return payload


def _sign_like_app(payload: dict) -> dict:
    msg = _kotlin_to_json(payload).encode("utf-8")
    signed = dict(payload)
    signed["signature"] = sign_message(SK_ALICE, hashlib.sha256(msg).digest()).hex()
    return signed


OPERATIONS = [
    pytest.param({"1": [[pubkey_hex(SK_ALICE), "b" * 96, "5"]]}, id="transfer"),
    pytest.param(
        {"0": "always (o13[t] = { #x01 }:bv[24]).", "13": "7"}, id="rule-and-custom-op"
    ),
    pytest.param({"13": "a\"b\\c\n\x01"}, id="escapes"),
]

@pytest.mark.parametrize("operations", OPERATIONS)
def test_app_preimage_is_the_node_preimage(operations):
    payload = _app_payload(operations)
    assert _kotlin_to_json(payload).encode("utf-8") == signing_message_bytes(payload)


@pytest.mark.parametrize("operations", OPERATIONS)
def test_app_signature_passes_the_node_check(operations):
    ok, reason = verify_tx_signature(_sign_like_app(_app_payload(operations)))
    assert ok, reason
