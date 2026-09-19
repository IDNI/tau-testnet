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
          prepare_exc=None):
    manager = MagicMock()
    manager.tau_test_mode = test_mode
    manager.last_known_tau_spec = baseline
    if prepare_exc is not None:
        manager._prepare_rule_for_tau.side_effect = prepare_exc
    else:
        manager._prepare_rule_for_tau.return_value = _Prepared()
    result = pf.PreflightResult(verdict, detail=detail)
    with patch.dict("sys.modules", {"tau_manager": manager}), \
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


def test_unavailable_does_not_reject_the_transaction():
    """An extra screen that cannot run leaves the existing verdict alone."""
    out, _ = _wire(pf.UNAVAILABLE, detail="native tau unavailable")
    assert out is None


def test_mock_mode_skips_the_preflight_entirely():
    out, called = _wire(pf.REJECT, test_mode=True)
    assert out is None
    assert called.call_count == 0, "mock mode has no interpreter to be compatible with"


def test_no_baseline_means_nothing_to_be_compatible_with():
    out, called = _wire(pf.REJECT, baseline="")
    assert out is None
    assert called.call_count == 0


def test_a_representation_conflict_is_node_local_not_a_rule_rejection():
    """`ShrinkTypeConflict`: THIS process cannot represent the rule; another node,
    or this one after a restart, can. That is not a verdict about the rule."""
    import tau_shrink
    out, called = _wire(pf.ADMIT, prepare_exc=tau_shrink.ShrinkTypeConflict("i12 pinned"))
    assert out is not None
    assert out["code"] == "ADMISSION_UNAVAILABLE"
    assert called.call_count == 0
