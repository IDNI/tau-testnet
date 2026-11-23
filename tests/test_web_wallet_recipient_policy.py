"""The web wallet explains a recipient-policy refusal from the node's own
envelope (#47, #76). Runs describeRecipientRefusal from web-wallet/app.js in node."""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

APP_JS = Path(__file__).resolve().parent.parent / "web-wallet/app.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _describe(code, details):
    src = APP_JS.read_text(encoding="utf-8")
    m = re.search(r"^function describeRecipientRefusal\(.*?^\}\n", src, re.S | re.M)
    assert m, "describeRecipientRefusal not found in app.js"
    script = m.group(0) + (
        "const a = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n"
        "process.stdout.write(JSON.stringify(describeRecipientRefusal(a[0], a[1])));\n"
    )
    out = subprocess.run(["node", "-e", script], input=json.dumps([code, details]).encode(),
                         capture_output=True, check=True)
    return json.loads(out.stdout)


def test_a_seconds_cap_is_printed():
    text = _describe("RECIPIENT_MAX_HOLD", {"max_hold_seconds": 600, "hold_seconds": 3600})
    assert "up to 600 seconds" in text


def test_a_blocks_cap_is_printed():
    text = _describe("RECIPIENT_MAX_HOLD", {"max_hold_blocks": 10, "hold_blocks": 50})
    assert "up to 10 blocks" in text


def test_instant_only():
    assert "instantly" in _describe("RECIPIENT_MAX_HOLD", {"max_hold_seconds": 0, "hold_seconds": 5})


def test_a_hold_in_another_unit():
    assert "held in blocks" in _describe("RECIPIENT_MAX_HOLD", {"max_hold_blocks": None, "hold_blocks": 5})


def test_allow_list_and_inactive_and_other_codes():
    assert "does not accept payments from this account" in _describe("RECIPIENT_POLICY", {})
    assert "never run" in _describe("RECIPIENT_POLICY_INACTIVE", {})
    assert _describe("TX_REJECTED", {}) is None


def test_the_node_envelope_shape_is_what_the_wallet_reads():
    """The keys the wallet reads are the keys sendtx puts in `details`."""
    import commands.sendtx as sendtx
    env = sendtx._qt_err("RECIPIENT_MAX_HOLD", "x", transfer_index=1,
                         max_hold_seconds=600, hold_seconds=3600)
    assert "up to 600 seconds" in _describe(env["code"], env["details"])


# --- the wallet's clause composer is the CLI's, byte for byte ---------------

A = "a1" * 48
B = "b2" * 48


def _compose_js(opts):
    src = APP_JS.read_text(encoding="utf-8")
    m = re.search(r"^function composeReceiveClause\(.*?^\}\n", src, re.S | re.M)
    assert m, "composeReceiveClause not found in app.js"
    script = m.group(0) + (
        "const o = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n"
        "let out; try { out = {rule: composeReceiveClause(o)}; } catch (e) { out = {error: e.message}; }\n"
        "process.stdout.write(JSON.stringify(out));\n"
    )
    res = subprocess.run(["node", "-e", script], input=json.dumps(opts).encode(),
                         capture_output=True, check=True)
    return json.loads(res.stdout)


@pytest.mark.parametrize("py, js", [
    (dict(allow=[A]), dict(allow=[A])),
    (dict(allow=[A, B]), dict(allow=[A, B])),
    (dict(max_hold_seconds=0), dict(maxHoldSeconds=0)),
    (dict(max_hold_seconds=600), dict(maxHoldSeconds=600)),
    (dict(max_hold_blocks=10), dict(maxHoldBlocks=10)),
    (dict(max_hold_seconds=600, max_hold_blocks=10), dict(maxHoldSeconds=600, maxHoldBlocks=10)),
    (dict(allow=[A], max_hold_seconds=600, send_only_to=[B]),
     dict(allow=[A], maxHoldSeconds=600, sendOnlyTo=[B])),
    (dict(send_only_to=[B]), dict(sendOnlyTo=[B])),
    (dict(allow=["0x" + A.upper()]), dict(allow=["0x" + A.upper()])),
])
def test_wallet_and_cli_compose_the_same_clause(py, js):
    from tau_testnet_cli.recipient_rules import compose_receive_clause
    assert _compose_js(js)["rule"] == compose_receive_clause(**py)


@pytest.mark.parametrize("js", [{}, {"maxHoldSeconds": -1}, {"allow": ["nope"]}, {"maxHoldSeconds": 1.5}])
def test_wallet_composer_refuses_what_the_cli_refuses(js):
    assert "error" in _compose_js(js)
