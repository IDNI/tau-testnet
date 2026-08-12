"""Every rule template the web wallet ships must pass node admission.

Issue #24 ask 3 made sender-scoping on o5/o8 an enforced admission rule rather
than an author convention. The shipped templates already comply — their comments
have always warned about exactly this ("we must scope this rule strictly to your
own public key (i12) so we don't accidentally block the whole network!") — so
this locks docs and screen together: a template that a user copies out of the
wallet must not be one the node then rejects.

Textual only: no native engine needed, so it runs in the mock CI job (unlike
tests/test_web_wallet_examples.py, which CI ignores).
"""
import os
import re
import sys

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

APP_JS = os.path.join(project_root, "web-wallet", "app.js")

# Template bodies are the one line of each backtick string that is actual Tau:
# everything else in them is '#' commentary.
_RULE_LINE = re.compile(r"^\s*(always\s*\(.*\.)\s*`?,?\s*$")


def _shipped_templates():
    with open(APP_JS, encoding="utf-8") as fh:
        lines = fh.readlines()

    start = next((i for i, l in enumerate(lines) if "const ruleTemplates" in l), None)
    assert start is not None, "ruleTemplates block not found in web-wallet/app.js"

    rules = []
    for line in lines[start:]:
        if line.startswith("};"):
            break
        m = _RULE_LINE.match(line)
        if m:
            rules.append(m.group(1))
    return rules


def test_templates_were_extracted():
    """Guard the guard: if the extraction silently matches nothing, every
    assertion below would vacuously pass."""
    rules = _shipped_templates()
    assert len(rules) >= 5, f"expected the shipped template set, extracted {len(rules)}"


@pytest.mark.parametrize("rule", _shipped_templates())
def test_shipped_template_passes_admission_screens(rule):
    from consensus.admission import validate_user_tx_reserved_domains
    from consensus.facade import TipAdmissionView

    result = validate_user_tx_reserved_domains(
        {"operations": {"0": rule}}, TipAdmissionView()
    )
    assert result.is_valid, (
        f"a template the wallet offers would be rejected by the node "
        f"({getattr(result, 'code', None)}): {result.error}\nrule: {rule}"
    )


@pytest.mark.parametrize("rule", _shipped_templates())
def test_shipped_policy_template_is_sender_scoped(rule):
    """Narrower and more explicit than the screen pass above, so a future change
    to the screen cannot quietly stop checking this."""
    from consensus.admission import _streams_referenced

    if not _streams_referenced(rule, ("o5", "o8")):
        pytest.skip("template does not write a shared policy stream")
    assert _streams_referenced(rule, ("i12", "i3")), (
        f"policy template lacks a sender scope: {rule}"
    )
