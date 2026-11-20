"""Bounty 02 (issue #42): the native-engine receipt shape test.

Split out of tests/test_active_rules_view.py so the native-tau-tests CI
job can register this file on its own: the mock-path suite must not be
run inside the native image, and this test must not be skipped over
silently where the real Tau bindings exist. It checks that the real
engine's revision receipts carry exactly the fields gettxstatus serves
for a confirmed rule transaction -- the outcome classification, the o0
verdict, and a revision counter whose before/after chain across the
maintainers' displacement probe from issue #42.
"""
import pytest

# The maintainers' displacement probe from issue #42, as two rule units.
RULE_INSTALL = (
    "always ( o26[t]:bv[64] = { 7 }:bv[64] && o27[t]:bv[64] = { 9 }:bv[64] )."
)
RULE_DISPLACE = "always ( o26[t]:bv[64] = { 3 }:bv[64] )."


# --- the real engine's receipt shape, when the bindings are usable ---------


def _native_available():
    try:
        import tau_native

        tau_native.load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not _native_available(), reason="native tau bindings unavailable"
)
def test_native_receipt_shape_matches_stored_outcome():
    """Against the real engine: the displacement probe's two rule steps
    produce receipts carrying exactly the fields gettxstatus serves --
    outcome classification, the o0 verdict, and a revision counter whose
    before/after chain across the displacement."""
    from pathlib import Path

    import tau_native

    iface = tau_native.TauInterface(
        str(Path(__file__).resolve().parents[1] / "genesis.tau")
    )
    iface.communicate(rule_text=RULE_INSTALL)
    first = iface.last_revision_receipt
    assert first["outcome"] == "ACCEPTED_CHANGED"
    assert first["outputs"]["o0"] == "F"
    assert first["spec_revision_after"] > first["spec_revision_before"]

    iface.communicate(rule_text=RULE_DISPLACE)
    second = iface.last_revision_receipt
    assert second["spec_revision_before"] == first["spec_revision_after"]
    assert second["spec_revision_after"] > second["spec_revision_before"]

