"""Issue #42: the maintainers' probe on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the probe needs the native bindings, which the mock test job does
not have. The skip below is environment-driven -- in the real-Tau job's
image the bindings are present (its preflight imports them), so the
skip lifts and the probe runs for real. Everywhere else it skips,
exactly as it did when it lived in test_active_rules_issue42.py.
"""
import hashlib

import pytest


def _native_available():
    try:
        from tau_native import load_tau_module

        load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_displacement_probe_on_native_engine(tmp_path):
    """The Sep 27 probe on the real engine: two fresh interpreters fed the
    same units must run the same spec (o26 = 3, o27 = 9), with identical
    text and hash -- the determinism premise the snapshot view relies on."""
    from tau_native import TauInterface

    unit1 = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
             "o27[t]:bv[24] = { 9 }:bv[24] ).")
    unit2 = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
    specs = []
    for _ in range(2):
        ti = TauInterface("genesis.tau")
        ti.communicate(rule_text=unit1, target_output_stream_index=0)
        ti.communicate(rule_text=unit2, target_output_stream_index=0)
        specs.append(ti.get_current_spec())
    assert specs[0] == specs[1]
    assert hashlib.sha256(specs[0].encode()).hexdigest() == \
        hashlib.sha256(specs[1].encode()).hexdigest()
    assert "o26" in specs[0] and "{ 3 }" in specs[0]
    assert "{ 7 }" not in specs[0].split("o27")[0]
