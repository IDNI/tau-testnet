"""Reads the rule templates the web wallet ships out of web-wallet/app.js."""
import os
import re

from consensus.rule_offers import strip_clause_comments

APP_JS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web-wallet", "app.js"
)

_ENTRY = re.compile(r'^    "(?P<name>[^"]+)": `(?P<rest>.*)$')


def _block_lines(block="ruleTemplates"):
    with open(APP_JS, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    start = next((i for i, l in enumerate(lines) if f"const {block} =" in l), None)
    assert start is not None, f"{block} block not found in web-wallet/app.js"
    block = []
    for line in lines[start + 1:]:
        if line.startswith("};"):
            break
        block.append(line)
    return block


def template_names(block="ruleTemplates"):
    """Names of every entry in the block, read from entry headers alone."""
    return [m.group("name") for m in map(_ENTRY.match, _block_lines(block)) if m]


def shipped_guard_templates():
    """The rule-change guard templates, in the same form as shipped_templates."""
    return shipped_templates("guardTemplates")


def shipped_templates(block="ruleTemplates"):
    """{name: text} with the text exactly as the wallet loads it into the editor."""
    out = {}
    name = None
    buf = []
    for line in _block_lines(block):
        if name is None:
            m = _ENTRY.match(line)
            if not m:
                continue
            name, line = m.group("name"), m.group("rest")
            buf = []
        closes = line.rstrip().endswith(("`,", "`")) and not line.rstrip().endswith(("\\`,", "\\`"))
        if closes:
            line = line.rstrip()
            line = line[:-2] if line.endswith("`,") else line[:-1]
        buf.append(line)
        if closes:
            out[name] = "\n".join(buf).replace("\\`", "`")
            name = None
    assert name is None, f"unterminated template {name!r}"
    return out


def live_rule(text):
    """The Tau of a template: comments dropped, one flat line."""
    return re.sub(r"\s+", " ", strip_clause_comments(text)).strip()


def writes(text, stream):
    return re.search(rf"\b{stream}\s*\[", live_rule(text)) is not None
