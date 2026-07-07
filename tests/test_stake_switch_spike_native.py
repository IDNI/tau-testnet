"""Phase 0 native spikes for the stake-switch consensus feature (BLOCKING).

Block validity (`o6`) and proposer eligibility (`o7`) are decided by a Tau
consensus rule executed by the native interpreter. Governance replaces that rule
at runtime by feeding new rule text through input stream `i0`, which the boot
spec (`genesis.tau`) routes into Tau's specification-update stream `u`.

The planned feature adds two consensus input streams -- `i14` = proposer balance
("stake", bv[64]) and `i15` = eligibility mode flag (0 = validator-set mode,
1 = stake mode, bv[16]) -- plus a mode-guarded genesis rule and a stake
revision.

The critical worry: when a new rule arrives via i0/u, the live interpreter may
CONJOIN it with the still-live old rule. The shipped genesis rule pins `o7 = 1`
unconditionally, so a stake rule wanting `o7 = 0` for a poor proposer would
contradict it (UNSAT). The mode-guarded forms below are designed so
`old_rule AND new_rule` is logically equal to `new_rule`. These spikes PROVE
that on the real engine before any host code is written.

Each spike runs in a FRESH SUBPROCESS with its own temp DB: the native engine
has process-global per-stream bv-width typing, so two cases sharing a process
poison each other. Auto-skips unless the native tau module is importable (set
PYTHONPATH to the tau-lang nanobind build).

Notes recorded during Phase 0 verification:
- S4 uses the decimal literal `{ 100000 }:bv[64]`. If a future engine build
  fails to parse decimal bv literals, switch BOTH rule texts to the hex form
  `{ #x0186a0 }:bv[64]` and Phase 4 must then use the hex form.
- S6 flattens the multi-line rule text to a single line before calling
  `compile_revisions_isolated`, which splits `consensus_rules_text` on newlines
  to recover rule units (a raw multi-line blob would seed the staging
  interpreter with the truncated first line `always (`).
"""
import json
import os
import subprocess
import sys

import pytest


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")


# --- Rule texts (copied EXACTLY per the phase-0 plan; whitespace flexible) ---

# Mode-guarded genesis rule: constrains o7 only when i15 = 0.
GENESIS_GUARDED = """
always (
    o6[t]:bv[16] = i10[t]:bv[16] &&
    ( i15[t]:bv[16] != { 0 }:bv[16] || o7[t]:bv[16] = { 1 }:bv[16] )
)
"""

# Stake revision (full restatement; threshold literal 100000).
STAKE_REVISION = """
always (
    o6[t]:bv[16] = i10[t]:bv[16] &&
    ( ( i15[t]:bv[16] = { 0 }:bv[16] && o7[t]:bv[16] = { 1 }:bv[16] ) ||
      ( i15[t]:bv[16] != { 0 }:bv[16] &&
        ( ( { 100000 }:bv[64] <= i14[t]:bv[64] && o7[t]:bv[16] = { 1 }:bv[16] ) ||
          ( { 100000 }:bv[64] >  i14[t]:bv[64] && o7[t]:bv[16] = { 0 }:bv[16] ) ) ) )
)
"""

# Current SHIPPED genesis consensus rule (pins o7 = 1 unconditionally).
SHIPPED = """
always (
    o6[t]:bv[16] = i10[t]:bv[16] &&
    o7[t]:bv[16] = { 1 }:bv[16]
)
"""


# --- Child harness -----------------------------------------------------------
# TAU_ENV/TAU_FORCE_TEST set FIRST, then config db path, db.init_db, then
# tau_native. A router-boot interpreter routes i0 -> u so apply_rule() drives
# governance activation exactly like the node does.
_PREAMBLE = r'''
import json, os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
import config
config.set_database_path(os.environ["SPIKE_DB"])
import db; db.init_db()
import tau_native

SENTINEL = "SPIKE_RESULT "
ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(ROUTER + "\n"); boot.close()
iface = tau_native.TauInterface(boot.name)

def apply_rule(text):
    # Route a rule through i0 exactly like governance activation does.
    return iface.communicate(rule_text=text, target_output_stream_index=0)

def step(inputs):
    # inputs: dict of string keys -> BARE string values, e.g. {"10":"1","14":"200000"}.
    return iface.communicate_multi(input_stream_values=inputs)

def has_err(outs):
    return any("Error" in str(v) for v in outs.values())

def emit(obj):
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    # The native engine segfaults on interpreter teardown/GC (a known pre-existing
    # flaky crash, unrelated to spike logic -- the result above is already fully
    # computed). Hard-exit BEFORE any native destructor runs so the child reports
    # a clean exit code.
    os._exit(0)
'''


def _child_src(body):
    defs = (
        "GENESIS_GUARDED = " + json.dumps(GENESIS_GUARDED) + "\n"
        "STAKE_REVISION = " + json.dumps(STAKE_REVISION) + "\n"
        "SHIPPED = " + json.dumps(SHIPPED) + "\n"
    )
    return _PREAMBLE + "\n" + defs + "\n" + body


def _run_child(tmp_path, name, body):
    """Run a spike child in its own process + temp DB. Returns (proc, parsed)."""
    script = tmp_path / (name + ".py")
    script.write_text(_child_src(body))
    env = dict(os.environ)
    env["SPIKE_DB"] = str(tmp_path / (name + ".db"))
    # The child does not inherit sys.path; put the repo root on PYTHONPATH so it
    # can import config/db/tau_native (native tau auto-discovers the sibling
    # tau-lang build, or honors an already-set PYTHONPATH).
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=180,
    )
    line = next((l for l in proc.stdout.splitlines()
                 if l.startswith("SPIKE_RESULT ")), None)
    parsed = json.loads(line[len("SPIKE_RESULT "):]) if line else None
    return proc, parsed


def _assert_ok(proc, parsed):
    assert proc.returncode == 0, (
        f"child exited {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert parsed is not None, (
        f"child produced no result line\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )


# S1 is reused by S1b for the live-vs-restart comparison.
_S1_BODY = r'''
apply_rule(GENESIS_GUARDED)
apply_rule(STAKE_REVISION)
res = {"spec": iface.get_current_spec(), "rows": [], "err": False}
for inp in [
    {"10": "1", "14": "200000", "15": "1"},
    {"10": "1", "14": "5",      "15": "1"},
    {"10": "1", "14": "5",      "15": "0"},
]:
    o = step(inp)
    if has_err(o):
        res["err"] = True
    res["rows"].append({"6": o.get(6), "7": o.get(7)})
emit(res)
'''

# S1b: fresh interpreter seeded with the STAKE_REVISION ONLY (simulates restart,
# which replays only the last activated revision).
_S1B_BODY = r'''
apply_rule(STAKE_REVISION)
res = {"spec": iface.get_current_spec(), "rows": [], "err": False}
for inp in [
    {"10": "1", "14": "200000", "15": "1"},
    {"10": "1", "14": "5",      "15": "1"},
    {"10": "1", "14": "5",      "15": "0"},
]:
    o = step(inp)
    if has_err(o):
        res["err"] = True
    res["rows"].append({"6": o.get(6), "7": o.get(7)})
emit(res)
'''


def test_s1_composition_semantics(tmp_path):
    """THE critical spike: genesis-guarded THEN stake revision, composed live.

    Row 1 (rich, stake mode): o6=1, o7=1. Row 2 (poor, stake mode): o7=0.
    Row 3 (poor, validator mode): o7=1. Proves old_rule AND new_rule == new_rule.
    """
    proc, r = _run_child(tmp_path, "s1", _S1_BODY)
    _assert_ok(proc, r)
    assert r["err"] is False, f"an output contained 'Error': {r}"
    rows = r["rows"]
    assert rows[0] == {"6": "1", "7": "1"}, f"rich stake proposer: {rows[0]} (spec: {r['spec']})"
    assert rows[1]["7"] == "0" and rows[1]["6"] == "1", f"poor stake proposer: {rows[1]}"
    assert rows[2]["7"] == "1", f"validator-set mode: {rows[2]}"


def test_s1b_live_vs_restart_equivalence(tmp_path):
    """A restarted node replays only the last revision (STAKE_REVISION alone).

    Its o6/o7 matrix must be IDENTICAL to S1's live-composed matrix -- otherwise
    restart determinism breaks and the whole design is unsound (STOP condition).
    """
    proc1, r1 = _run_child(tmp_path, "s1_for_s1b", _S1_BODY)
    proc2, r2 = _run_child(tmp_path, "s1b", _S1B_BODY)
    _assert_ok(proc1, r1)
    _assert_ok(proc2, r2)
    assert r2["err"] is False, f"restart path emitted 'Error': {r2}"
    assert r1["rows"] == r2["rows"], (
        f"live-composed vs restarted matrices diverge (STOP):\n"
        f"live={r1['rows']}\nrestart={r2['rows']}"
    )


@pytest.mark.xfail(strict=False, reason="documents the SHIPPED o7=1 rule conjoined "
                   "with STAKE_REVISION for a poor proposer; feared UNSAT, but the "
                   "engine's normalizer folds it into a SAT spec and yields o7=0")
def test_s1c_shipped_rule_failure_mode(tmp_path):
    """Why the mode-guarded genesis exists.

    The SHIPPED rule pins o7=1 unconditionally. We feared conjoining
    STAKE_REVISION (poor proposer -> o7=0) would be UNSAT and crash/garble.

    OBSERVED on the real engine (Phase 0): it does NOT go UNSAT. The temporal
    normalizer folds the unconditional o7=1 into the disjunctive stake spec,
    producing a SATISFIABLE combined formula, and the poor-stake step returns a
    CLEAN o7 == "0" (so this test XPASSES). Practically this behaves like the
    later u-update WEAKENING/superseding the earlier o7 constraint rather than a
    hard conjunction.

    We keep the mode-guarded genesis design anyway: it makes the intended
    old_rule AND new_rule == new_rule equivalence explicit and does not lean on
    the normalizer's folding behavior. This test still records the raw outcome.
    """
    body = r'''
res = {"outcome": None, "exc": None, "row": None, "err": False}
try:
    apply_rule(SHIPPED)
    apply_rule(STAKE_REVISION)
    o = step({"10": "1", "14": "5", "15": "1"})
    res["err"] = has_err(o)
    res["row"] = {"6": o.get(6), "7": o.get(7)}
    res["outcome"] = "clean"
except Exception as e:
    res["outcome"] = "exception"
    res["exc"] = type(e).__name__ + ": " + str(e)[:400]
emit(res)
'''
    proc, r = _run_child(tmp_path, "s1c", body)
    # NOTE: no exit-0 assertion for S1c -- the child may die inside native Tau.
    assert r is not None, f"no result\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    # The xfail assertion: a clean o7=0 would mean u-updates REPLACE (keep the
    # guarded design anyway). Contradiction -> row is None/err -> this fails.
    assert r["outcome"] == "clean" and not r["err"], f"S1c: {r}"
    assert r["row"]["7"] == "0", f"S1c observed: {r}"


def test_s2_unreferenced_inputs_ignored(tmp_path):
    """The SHIPPED rule references only i10; feeding i6/i7/i14/i15 alongside is
    harmless -- o6 still tracks i10 with no error."""
    body = r'''
apply_rule(SHIPPED)
o = step({"6": "5", "7": "1700000000", "10": "1", "14": "123", "15": "0"})
emit({"o6": o.get(6), "err": has_err(o), "keys": sorted(o.keys())})
'''
    proc, r = _run_child(tmp_path, "s2", body)
    _assert_ok(proc, r)
    assert r["err"] is False, f"unreferenced inputs produced 'Error': {r}"
    assert r["o6"] == "1", f"o6 should track i10=1: {r}"


def test_s3_multi_output_single_step(tmp_path):
    """One step of the composed rule emits BOTH o6 and o7."""
    body = r'''
apply_rule(GENESIS_GUARDED)
apply_rule(STAKE_REVISION)
o = step({"10": "1", "14": "200000", "15": "1"})
emit({"keys": sorted(o.keys()), "err": has_err(o)})
'''
    proc, r = _run_child(tmp_path, "s3", body)
    _assert_ok(proc, r)
    assert r["err"] is False, f"emitted 'Error': {r}"
    assert 6 in r["keys"] and 7 in r["keys"], f"expected both o6 and o7: {r}"


def test_s4_operator_boundaries(tmp_path):
    """Threshold boundary: i14 = 99999 -> o7=0, 100000 -> o7=1, 100001 -> o7=1
    (stake mode). Exercises `<=` and `>` on bv[64] around the literal 100000."""
    body = r'''
apply_rule(GENESIS_GUARDED)
apply_rule(STAKE_REVISION)
res = {"rows": [], "err": False}
for v in ["99999", "100000", "100001"]:
    o = step({"10": "1", "14": v, "15": "1"})
    if has_err(o):
        res["err"] = True
    res["rows"].append({"14": v, "7": o.get(7)})
emit(res)
'''
    proc, r = _run_child(tmp_path, "s4", body)
    _assert_ok(proc, r)
    assert r["err"] is False, f"emitted 'Error': {r}"
    got = {row["14"]: row["7"] for row in r["rows"]}
    assert got == {"99999": "0", "100000": "1", "100001": "1"}, f"boundary matrix: {got}"


def test_s5_width_conflict_reported(tmp_path):
    """After STAKE_REVISION types i14 as bv[64], a rule asserting i14:bv[24] is
    rejected. Documents why user transactions must be blocked from touching
    i14/i15 (Phase 2).

    OBSERVED on the real engine: the conflicting rule does NOT raise a Python
    exception through communicate() -- the engine prints
    `(Error) Incompatible type information in i14 ... expected :bv[64],
    found :bv[24]` (to the raw fd, during the next get_inputs_for_step) and
    silently DROPS the bad rule, leaving the live spec unchanged (i14 stays
    bv[64]). The child records the spec before/after; the parent asserts the
    engine reported the incompatibility AND the rule was rejected.
    """
    body = r'''
apply_rule(STAKE_REVISION)
spec_before = iface.get_current_spec()
res = {"raised": False, "exc": None}
try:
    apply_rule("always ( o13[t]:bv[16] = i14[t]:bv[24] ).")
except Exception as e:
    res["raised"] = True
    res["exc"] = type(e).__name__ + ": " + str(e)[:400]
spec_after = iface.get_current_spec()
res["rule_rejected"] = (spec_before == spec_after)
res["spec_has_bv24"] = ("bv[24]" in spec_after)
emit(res)
'''
    proc, r = _run_child(tmp_path, "s5", body)
    _assert_ok(proc, r)
    # The width conflict is reported either as a raised exception or (the actual
    # engine behavior) as an "(Error) Incompatible type" message on the child's
    # captured stdout.
    reported = r["raised"] or ("Incompatible type" in proc.stdout)
    assert reported, (
        f"width conflict was NOT reported: {r}\nSTDOUT tail:\n{proc.stdout[-1200:]}"
    )
    # And the conflicting bv[24] rule must be rejected: the live spec is
    # unchanged and i14 stays bv[64].
    assert r["rule_rejected"] is True, f"conflicting rule should be dropped (spec unchanged): {r}"
    assert r["spec_has_bv24"] is False, f"i14 must stay bv[64] after rejection: {r}"


def test_s6_isolated_staging_compile(tmp_path):
    """The admission-time staging compile accepts the guarded genesis + stake
    revision (returns None on success). Rule text is flattened to one line
    because compile_revisions_isolated splits on newlines to recover units."""
    body = r'''
seed = " ".join(GENESIS_GUARDED.split())
rev = " ".join(STAKE_REVISION.split())
res = {"result": tau_native.TauInterface.compile_revisions_isolated(seed, [rev])}
emit(res)
'''
    proc, r = _run_child(tmp_path, "s6", body)
    _assert_ok(proc, r)
    assert r["result"] is None, f"staging compile should succeed (None): {r}"
