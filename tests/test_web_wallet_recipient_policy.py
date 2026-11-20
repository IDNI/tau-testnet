"""Issues #47, #76: the web wallet knows an inbound rule when it sees one.

The wallet refuses to send an o5 rule that reads i17 while the network has
recipient-side policy off, and tells the owner in the review dialog that a rule
judges incoming payments. Its test for "reads i17" must agree with the node's
(`sender_policy.reads_recipient_input`), or the wallet would block rules the node
treats as outbound-only, or wave through ones that would never run.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from consensus.sender_policy import reads_recipient_input

APP_JS = Path(__file__).resolve().parent.parent / "web-wallet/app.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

TEXTS = [
    "always ((i17[t]:bv[64] > { #x0000000000000001 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])).",
    "always ((i4[t]:bv[384] = { #x" + "2" * 96 + " }:bv[384]) ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24])).",
    "# a comment about i17 only\nalways ((i1[t]:bv[24] > { #x000000 }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])).",
    "always ((i170[t]:bv[24] > { #x000000 }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])).",
    "o5[t]:bv[24] = i17[t]:bv[64]",
]


def _function_source(src: str, name: str) -> str:
    m = re.search(rf"^function {name}\(.*?^\}}\n", src, re.S | re.M)
    assert m, f"function {name} not found in app.js"
    return m.group(0)


def _run(expr: str, payload):
    src = APP_JS.read_text(encoding="utf-8")
    script = (
        "".join(_function_source(src, n) for n in
                ("liveTauLines", "readsRecipientInput", "inboundRuleProblem"))
        + "const fs = require('fs');\n"
        + "const input = JSON.parse(fs.readFileSync(0, 'utf8'));\n"
        + f"process.stdout.write(JSON.stringify({expr}));\n"
    )
    res = subprocess.run(["node", "-e", script], input=json.dumps(payload).encode(),
                         capture_output=True, check=True, timeout=60)
    return json.loads(res.stdout)


def test_wallet_and_node_agree_on_which_rules_read_i17():
    wallet = _run("input.map(readsRecipientInput)", TEXTS)
    node = [reads_recipient_input(t) for t in TEXTS]
    assert wallet == node
    assert any(node) and not all(node)


def test_wallet_refuses_an_inbound_rule_only_while_the_feature_is_off():
    inbound, outbound = TEXTS[0], TEXTS[1]
    cases = [[1, inbound, False], [1, inbound, True], [1, outbound, False],
             [3, inbound, False], [4, inbound, False]]
    problems = _run("input.map(([k, t, a]) => inboundRuleProblem(k, t, a))", cases)
    assert [bool(p) for p in problems] == [True, False, False, True, False]
    assert "not active" in problems[0]


def test_every_shipped_inbound_template_reads_i17():
    src = APP_JS.read_text(encoding="utf-8")
    names = re.findall(r'^\s*"([^"]*\(inbound\))": `', src, re.M)
    assert len(names) == 3
    for name in names:
        body = re.search(re.escape(f'"{name}": `') + r"(.*?)`", src, re.S).group(1)
        assert reads_recipient_input(body), name
