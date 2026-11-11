"""The web wallet must sign the same preimage that the node verifies.

The test runs the canonicalize function of web-wallet/app.js in node.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from consensus.tx_signing import signing_message_bytes

APP_JS = Path(__file__).resolve().parent.parent / "web-wallet/app.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _function_source(src: str, name: str) -> str:
    m = re.search(rf"^function {name}\(.*?^\}}\n", src, re.S | re.M)
    assert m, f"function {name} not found in app.js"
    return m.group(0)


def _js_canonicalize(value) -> bytes:
    src = APP_JS.read_text(encoding="utf-8")
    script = (
        _function_source(src, "asciiJson")
        + _function_source(src, "canonicalize")
        + "const fs = require('fs');\n"
        + "const v = JSON.parse(fs.readFileSync(0, 'utf8'));\n"
        + "const s = canonicalize(v);\n"
        + "process.stdout.write(Buffer.from(new TextEncoder().encode(s)));\n"
    )
    res = subprocess.run(
        ["node", "-e", script],
        input=json.dumps(value).encode(),
        capture_output=True,
        check=True,
        timeout=60,
    )
    return res.stdout


ENVELOPE = {
    "sender_pubkey": "a" * 96,
    "sequence_number": 4,
    "expiration_time": 1_900_000_000,
    "expire_at_height": 77,
    "fee_limit": "0",
}

PAYLOADS = [
    pytest.param(
        {"tx_type": "user_tx", "operations": {"1": [["a" * 96, "b" * 96, "5"]], "13": "7"}},
        id="transfer",
    ),
    pytest.param(
        {"tx_type": "user_tx", "operations": {"0": "always (o13[t] = i13[t]). # café \U0001F600 \x7f \x01"}},
        id="non-ascii",
    ),
    pytest.param(
        {
            "tx_type": "consensus_rule_update",
            "rule_revisions": ["always (o9[t] = { #x01 }:bv[24])."],
            "activate_at_height": 10,
            "host_contract_patch": {"z": [{"b": 1, "a": "é"}], "a": None},
        },
        id="rule-update-nested",
    ),
    pytest.param(
        {"tx_type": "consensus_rule_vote", "update_id": "f" * 64, "approve": True},
        id="rule-vote",
    ),
]


@pytest.mark.parametrize("body", PAYLOADS)
def test_web_wallet_preimage_is_the_node_preimage(body):
    # The wallet signs exactly the envelope plus the body, so its keys are the node allowlist.
    payload = {**ENVELOPE, **body}
    assert _js_canonicalize(payload) == signing_message_bytes(payload)
