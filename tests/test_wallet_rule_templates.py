"""Every rule template the web wallet ships must pass node admission.

A policy template (o5) is a clause: the node evaluates it only for transfers
sent by the account that submits it, so it must not mention the sender key. A
fee template (o8) accumulates on the shared interpreter, so it must be scoped to
the sender. Textual only: no native engine needed, so it runs in the mock CI job.
"""
import os
import sys

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from wallet_templates import live_rule, shipped_templates, template_names, writes

SENDER = "ab" * 48
NOT_DEPLOYABLE = "Time-Decaying Multi-Signature Vault (NOT DEPLOYABLE)"

TEMPLATES = shipped_templates()
O5_TEMPLATES = {n: t for n, t in TEMPLATES.items() if writes(t, "o5")}
O8_TEMPLATES = {n: t for n, t in TEMPLATES.items() if writes(t, "o8")}


def test_every_template_was_extracted():
    """Guard the guard: if extraction silently drops entries, every assertion
    below would vacuously pass."""
    assert sorted(TEMPLATES) == sorted(template_names())
    assert len(TEMPLATES) >= 5


def test_every_template_with_live_tau_writes_a_policy_or_fee_stream():
    live = {n for n, t in TEMPLATES.items() if live_rule(t)}
    assert live == set(O5_TEMPLATES) | set(O8_TEMPLATES)
    assert set(TEMPLATES) - live == {NOT_DEPLOYABLE}
    assert len(O5_TEMPLATES) == len(TEMPLATES) - 1 - len(O8_TEMPLATES)


@pytest.mark.parametrize("name", sorted(O5_TEMPLATES))
def test_shipped_template_passes_admission_screens(name):
    from consensus.admission import validate_user_tx_reserved_domains
    from consensus.facade import TipAdmissionView

    text = TEMPLATES[name]
    result = validate_user_tx_reserved_domains(
        {"sender_pubkey": SENDER, "operations": {"0": text}}, TipAdmissionView()
    )
    assert result.is_valid, (
        f"a template the wallet offers would be rejected by the node "
        f"({getattr(result, 'code', None)}): {result.error}\nrule: {live_rule(text)}"
    )


@pytest.mark.parametrize("name", sorted(O5_TEMPLATES))
def test_shipped_template_is_a_clause_body(name):
    from consensus.rule_offers import clause_body_v1
    from consensus.admission import _screen_clause_domains

    body = clause_body_v1(TEMPLATES[name])
    assert _screen_clause_domains(body) is None


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_shipped_policy_template_is_sender_scoped(name):
    """A fee template names the sender; a policy clause must not, because it is
    evaluated only for its owner."""
    from consensus.admission import _streams_referenced

    rule = live_rule(TEMPLATES[name])
    if name in O8_TEMPLATES:
        assert _streams_referenced(rule, ("i12", "i3")), (
            f"fee template lacks a sender scope: {rule}"
        )
    elif name in O5_TEMPLATES:
        assert not _streams_referenced(rule, ("i12",)), (
            f"policy clause carries a sender guard: {rule}"
        )
    else:
        pytest.skip("template carries no live rule")
