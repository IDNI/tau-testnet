"""W8 wiring: how sendtx maps a preflight verdict.

The preflight is an ADDITIONAL screen on top of the canonical compile. It may
reject a transaction apply would have refused anyway -- that is the point -- but
an inability to RUN it must never become a verdict about someone's rule.
"""
from unittest.mock import MagicMock, patch

import pytest

import commands.sendtx as sendtx
import tau_preflight as pf

RULE = "always ( i12[t]:bv[384] = { #xaa }:bv[384] -> ( o5[t]:bv[24] = { #x000001 }:bv[24] ) )."


class _Prepared:
    runtime_text = "always ( i12[t]:bv[8] = { 1 }:bv[8] -> ( o5[t]:bv[24] = { #x000001 }:bv[24] ) )."


def _wire(verdict, *, detail="", test_mode=False, baseline="always ( x ).",
          prepare_exc=None, has_interface=True):
    manager = MagicMock()
    manager.tau_test_mode = test_mode
    manager.tau_direct_interface = object() if has_interface else None
    manager.last_known_tau_spec = baseline
    if prepare_exc is not None:
        manager._prepare_rule_for_tau.side_effect = prepare_exc
    else:
        manager._prepare_rule_for_tau.return_value = _Prepared()
    result = pf.PreflightResult(verdict, detail=detail)
    # The suite runs under TAU_ENV=test; these cases are about a PRODUCTION node,
    # where an absent native evaluator is an operational failure rather than an
    # exemption.
    with patch.dict("sys.modules", {"tau_manager": manager}), \
         patch.object(sendtx, "_test_mode_was_requested", return_value=test_mode), \
         patch.object(pf, "preflight_rule", return_value=result) as called:
        return sendtx._preflight_prepared_rule(RULE), called


def test_a_rejection_becomes_a_structured_refusal():
    out, _ = _wire(pf.REJECT, detail="Incompatible type information in i12")
    assert out is not None
    assert out["code"] == "TX_REJECTED"
    assert "Incompatible type information in i12" in out["message"]


def test_an_admit_lets_the_transaction_through():
    out, _ = _wire(pf.ADMIT)
    assert out is None


def test_unavailable_is_reported_not_swallowed():
    """"Could not validate" is not "validated". The caller gets a distinct
    operational code and can resubmit; returning the previous successful-looking
    verdict would let an unvalidated rule into the mempool while reporting that it
    passed."""
    out, _ = _wire(pf.UNAVAILABLE, detail="worker would not spawn")
    assert out is not None
    assert out["code"] == "ADMISSION_UNAVAILABLE"
    assert "TX_REJECTED" not in out["code"], "an operational failure is not a verdict"


def test_a_production_node_without_a_native_evaluator_is_unavailable():
    """Expected-but-absent is operational, not exempt."""
    out, called = _wire(pf.REJECT, has_interface=False)
    assert out is not None and out["code"] == "ADMISSION_UNAVAILABLE"
    assert called.call_count == 0


def test_only_an_explicitly_requested_test_mode_skips_the_preflight():
    """`tau_manager` flips tau_test_mode on when the native interface fails to
    build, so reading that flag alone would turn a broken production node into one
    that silently stops validating."""
    out, called = _wire(pf.REJECT, test_mode=True)
    assert out is None
    assert called.call_count == 0


def test_an_empty_baseline_still_validates_the_candidate():
    """The first rule on a fresh chain is the one least likely to have been seen
    before. An empty baseline used to skip the check entirely -- validating
    nothing precisely when there is nothing to validate against."""
    out, called = _wire(pf.REJECT, baseline="")
    assert called.call_count == 1, "the candidate was not validated at all"
    assert out is not None and out["code"] == "TX_REJECTED"


def test_a_representation_conflict_is_node_local_not_a_rule_rejection():
    """`ShrinkTypeConflict`: THIS process cannot represent the rule; another node,
    or this one after a restart, can. That is not a verdict about the rule."""
    import tau_shrink
    out, called = _wire(pf.ADMIT, prepare_exc=tau_shrink.ShrinkTypeConflict("i12 pinned"))
    assert out is not None
    assert out["code"] == "ADMISSION_UNAVAILABLE"
    assert called.call_count == 0


def test_a_revision_refusal_reaches_the_client_as_plain_text():
    """The isolated admission context refuses with the engine's own diagnostic,
    which the engine colours. The wallet shows the message verbatim, so the
    escape codes must not reach it."""
    out = sendtx._revision_refusal({
        "accepted": False,
        "outcome": "REJECTED_RULE",
        "diagnostics": "(\x1b[31;1mError\x1b[0m) Incompatible type information in i1, "
                       "expected :bv[24], found :bv[16]\n",
    })
    assert out["code"] == "TX_REJECTED"
    assert "\x1b" not in out["message"]
    assert "(Error) Incompatible type information in i1" in out["message"]
    assert out["details"] == {"outcome": "REJECTED_RULE"}


def test_an_accepted_revision_is_not_a_refusal():
    assert sendtx._revision_refusal({"accepted": True, "outcome": "ACCEPTED_CHANGED"}) is None
