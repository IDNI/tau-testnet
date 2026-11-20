"""Bounty 02 (issue #42), PR #151: the Sep 27 displacement probe and its
two companion proofs, run against the REAL Tau engine.

tests/test_active_rules_view_native.py already proves the revision
receipt SHAPE on the real engine. This file adds the three proofs the
maintainers named on #42 that otherwise exist only on the mock path
(tests/test_active_rules_view.py::test_displacement_probe_view_matches_engine
and ::test_view_text_and_hash_equal_across_nodes_and_replay):

  1. the Sep 27 displacement probe on the real engine:
     o26 = {7} && o27 = {9}, then o26 = {3}  ->  the spec the engine
     itself reports as current carries o26 = 3 and o27 = 9, and no
     assignment in it carries 7;
  2. a second process and a fresh-process re-feed from genesis give
     the same spec text and the same sha256;
  3. the live apply seam (tau_manager's own communicate_with_tau,
     backed by a real TauInterface -- the InProcessSession path
     consensus/engine.py steps through) ends on exactly the same spec,
     and its revision receipts chain across the displacement.

Gate: idiom C (subprocess probe, as in tests/test_rule_scoping_native.py),
because test 2 spawns engine children. Locally (no bindings) every test
skips; in the native-tau-tests CI job the preflight step hard-fails if
the module is missing, so a green job cannot be a disguised skip.

Landing resolutions (each was a TODO-VERIFY in the prep pack; resolved
against this branch's code, not assumed):

  * Spec accessor: the "no 7 in force" claim reads
    iface.interpreter.current_spec() -- the native interpreter's own
    composed spec, the text the engine runs. It deliberately does NOT
    read TauInterface.get_current_spec(), whose contract is the
    Python-side accumulated text (tau_native.py: "Returns the full
    accumulated specification"); tau_native.py itself re-syncs that
    accumulation FROM interpreter.current_spec() after a revision.
    The value assertions parse the current-[t] assignments out of the
    spec text with the same regex shape the mock suite uses for the
    composed text (tests/test_active_rules_view.py's _ASSIGNMENT_RE),
    so they pin WHICH assignments are in force, spacing-tolerant,
    instead of pinning the printer's byte rendering.
  * Genesis: the probe builds TauInterface on the checked-in
    genesis.tau at the repo root. It never reads data/genesis.json
    (the CI job generates that file for the chain_state suites; this
    file does not need it).
  * Fees: this file applies no blocks and touches no accounts, so no
    balance assertion exists and no scripted-fee assumption had to be
    restated; every asserted number is a rule literal or a hash.
  * Application-rules state: chain_state.get_application_rules_state
    is read by consensus/engine.py's apply path, which this file never
    runs; tau_manager.communicate_with_tau does not consult it. In the
    native job's process tau_manager._rules_handler is None (only the
    server/container startup registers one), so test 3's communicate
    calls fire no persistence side effect. Test 3 restores every
    tau_manager global it deliberately changes (direct interface,
    test mode, ready flag's prior state).
  * Revisions: the receipts are asserted as a CHAIN (each before ==
    the previous after, strictly increasing), never as absolute
    values. What revision the probe lands on is the engine's fact.
"""
import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENESIS_TAU = os.path.join(REPO_ROOT, "genesis.tau")

# The maintainers' displacement probe from issue #42, as two rule units.
# Copied verbatim from tests/test_active_rules_view_native.py.
RULE_INSTALL = (
    "always ( o26[t]:bv[64] = { 7 }:bv[64] && o27[t]:bv[64] = { 9 }:bv[64] )."
)
RULE_DISPLACE = "always ( o26[t]:bv[64] = { 3 }:bv[64] )."

# Current-[t] constant assignments in a composed spec text -- the same
# pattern the mock suite parses its composed text with
# (tests/test_active_rules_view.py's _ASSIGNMENT_RE). Spacing-tolerant;
# the literal is captured whole, so 17 never reads as 7.
_ASSIGNMENT_RE = re.compile(
    r"(o\d+)\[t\]:(bv\[\d+\])\s*=\s*\{\s*([0-9]+|#x[0-9a-fA-F]+)\s*\}:bv\[\d+\]"
)


def _assignments_in_force(spec_text):
    """Map of output stream -> the set of literals its current [t]
    assignments carry in the composed spec text."""
    in_force = {}
    for stream, _width, literal in _ASSIGNMENT_RE.findall(spec_text):
        in_force.setdefault(stream, set()).add(literal)
    return in_force


def _native_python():
    """Interpreter for engine children (pattern: tests/test_rule_scoping_native.py)."""
    return os.environ.get("TAU_NATIVE_PYTHON") or sys.executable


def _child_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["REPO_ROOT"] = REPO_ROOT
    if extra:
        env.update(extra)
    return env


def _native_available():
    try:
        proc = subprocess.run(
            [_native_python(), "-c",
             "import tau_native; assert tau_native.load_tau_module() is not None"],
            capture_output=True, text=True, env=_child_env(), timeout=120,
        )
        return proc.returncode == 0
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built"
)


def _probe_spec_in_this_process():
    """Feed the probe to a fresh real interpreter; return its spec views."""
    import tau_native

    iface = tau_native.TauInterface(GENESIS_TAU)
    iface.communicate(rule_text=RULE_INSTALL)
    first = iface.last_revision_receipt
    iface.communicate(rule_text=RULE_DISPLACE)
    second = iface.last_revision_receipt
    return iface, first, second


def test_the_probe_of_sep_27_reads_what_the_engine_runs():
    """Genesis rules, then o26={7} && o27={9}, then o26={3}: the spec the
    engine itself reports as current assigns o26 = 3 and o27 = 9, no
    assignment in it carries 7, and the revision counter chained across
    the displacement."""
    iface, first, second = _probe_spec_in_this_process()

    # The receipts chain, as in the existing native receipt-shape test:
    # each step's before is the previous step's after, and the counter
    # strictly advances. No absolute revision is asserted -- the value
    # is the engine's fact, the chain is the claim.
    assert first["outcome"] == "ACCEPTED_CHANGED"
    assert second["spec_revision_before"] == first["spec_revision_after"]
    assert second["spec_revision_after"] > second["spec_revision_before"]

    # The interpreter's OWN current spec -- not get_current_spec()'s
    # accumulated text (see the module docstring). Assertions are on
    # the parsed assignments in force, not on the printer's bytes.
    in_force = _assignments_in_force(iface.interpreter.current_spec())
    assert in_force.get("o26") == {"3"}
    assert in_force.get("o27") == {"9"}
    assert all("7" not in literals for literals in in_force.values())


# Child program for test 2: a fresh interpreter in a clean process, fed
# the same two units from genesis, prints {text, sha256} as JSON and
# hard-exits (the native engine can segfault on interpreter teardown --
# see tests/test_replay_determinism_native.py's harness notes).
_CHILD_PROBE = r"""
import hashlib, json, os, sys
sys.path.insert(0, os.environ["REPO_ROOT"])
import tau_native

iface = tau_native.TauInterface(os.path.join(os.environ["REPO_ROOT"], "genesis.tau"))
iface.communicate(rule_text="always ( o26[t]:bv[64] = { 7 }:bv[64] && o27[t]:bv[64] = { 9 }:bv[64] ).")
iface.communicate(rule_text="always ( o26[t]:bv[64] = { 3 }:bv[64] ).")
text = iface.interpreter.current_spec()
sys.stdout.write(json.dumps({
    "text": text,
    "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    "revision": iface.last_revision_receipt["spec_revision_after"],
}))
sys.stdout.flush()
os._exit(0)
"""


def _run_child_probe():
    proc = subprocess.run(
        [_native_python(), "-c", _CHILD_PROBE],
        capture_output=True, text=True, env=_child_env(), timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout)


def test_a_second_node_and_a_replay_give_the_same_text_and_hash():
    """A second process (second node) and a fresh-process re-feed of the
    two units from genesis give the same spec text and sha256 as this
    process's live interpreter. The re-feed is the interpreter-level
    equivalent of replay from block 0 FOR THIS PROBE -- two units, no
    chain state; it is not chain_state's rebuild from the blockchain,
    and this file does not claim that."""
    iface, _first, _second = _probe_spec_in_this_process()
    live_text = iface.interpreter.current_spec()
    live = {
        "text": live_text,
        "sha256": hashlib.sha256(live_text.encode("utf-8")).hexdigest(),
    }

    second_node = _run_child_probe()
    replay = _run_child_probe()  # fresh process, genesis -> unit1 -> unit2

    assert second_node["text"] == live["text"]
    assert second_node["sha256"] == live["sha256"]
    assert replay["text"] == live["text"]
    assert replay["sha256"] == live["sha256"]


def test_the_live_apply_path_reports_the_revision_and_ends_on_the_same_spec():
    """tau_manager's own communicate seam, backed by a real TauInterface
    (the InProcessSession path consensus/engine.py uses at apply), fed
    the same two units as apply feeds them, ends on exactly the spec the
    direct interpreter reports, and the revision receipts the interface
    recorded carry the displacement as a chain.

    The receipts are read from the interface object -- the object apply
    itself reads (tau_manager copies it into its own receipt slot after
    every call). The manager also refreshes its last_known_tau_spec
    debug aid from the interface after each call; that aid is not
    asserted here, because it is not the spec source the view serves.
    """
    import tau_manager
    import tau_native

    iface = tau_native.TauInterface(GENESIS_TAU)
    old_iface = tau_manager.tau_direct_interface
    old_mode = tau_manager.tau_test_mode
    was_ready = tau_manager.tau_ready.is_set()
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_test_mode = False
    tau_manager.tau_ready.set()
    try:
        tau_manager.communicate_with_tau(
            rule_text=RULE_INSTALL, target_output_stream_index=0,
            apply_rules_update=True, source="native-probe",
        )
        first = tau_manager.tau_direct_interface.last_revision_receipt
        tau_manager.communicate_with_tau(
            rule_text=RULE_DISPLACE, target_output_stream_index=0,
            apply_rules_update=True, source="native-probe",
        )
        second = tau_manager.tau_direct_interface.last_revision_receipt
    finally:
        tau_manager.tau_direct_interface = old_iface
        tau_manager.tau_test_mode = old_mode
        if was_ready:
            tau_manager.tau_ready.set()
        else:
            tau_manager.tau_ready.clear()

    assert first["outcome"] == "ACCEPTED_CHANGED"
    assert second["spec_revision_before"] == first["spec_revision_after"]
    assert second["spec_revision_after"] > second["spec_revision_before"]

    direct, _f, _s = _probe_spec_in_this_process()
    assert iface.interpreter.current_spec() == direct.interpreter.current_spec()
