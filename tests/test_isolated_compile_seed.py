"""Real-engine tests for TauInterface.compile_revisions_isolated seeding.

Guards two fixes:
  1. The staging interpreter is seeded from the FIRST rule unit and the remaining
     units are replayed via i0. The seed source (chain_state.get_rules_state()) is
     the raw newline accumulation -- genesis conditional (no trailing '.') +
     builtin units -- which is NOT a single parseable spec. Seeding
     get_interpreter() with the whole blob fails at the first ') always'; the
     unit-by-unit replay avoids that (regression: every rule sendtx would be
     rejected with "Failed to construct staging Tau interpreter").
  2. compile_revisions_isolated_subprocess propagates the parent's resolved native
     tau dir to the child via PYTHONPATH, so the child can import the SAME native
     module instead of reporting "native tau unavailable" and forcing the live
     fallback on every rule.

Runs the engine in a FRESH SUBPROCESS (native per-stream bv-width typing is
process-global). Auto-skips unless the native tau module is importable.
"""
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

# Realistic application accumulation: genesis i0->u conditional + a builtin. The
# genesis line has NO trailing '.', so the joined blob is not a parseable spec.
_ACCUM = (
    "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)\n"
    "always ( ((i1[t]:bv[24] > i2[t]:bv[24]) && o2[t] = { #x000000 }:bv[24]) "
    "|| ((i1[t]:bv[24] <= i2[t]:bv[24]) && o2[t] = { #x000001 }:bv[24]) )."
)
_CONS = "always ( o6[t]:bv[64] = i10[t]:bv[64] && o7[t]:bv[64] = { 1 }:bv[64] )."
_GOOD_APP = "always (o5[t]:bv[24] = i1[t]:bv[24])."

_CHILD = r'''
import os, sys, json
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import tau_native
tau_native.load_tau_module()
ACCUM = %r; CONS = %r; GOOD = %r
app = tau_native.TauInterface.compile_revisions_isolated(ACCUM, [GOOD])
cons = tau_native.TauInterface.compile_revisions_isolated(CONS, [CONS])
print("SEED_RESULT " + json.dumps({"app": app, "cons": cons,
      "native_dir": bool(tau_native.native_tau_dir())}))
'''


def _run_child(tmp_path, body):
    script = tmp_path / "seed_child.py"
    script.write_text(body)
    env = dict(os.environ)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("SEED_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    import json
    return json.loads(line[len("SEED_RESULT "):])


def test_multi_unit_accumulation_seed_builds_and_validates(tmp_path):
    """A multi-unit accumulation seed (genesis + builtin) must build via the
    unit-by-unit replay, and a valid rule must compile clean (None)."""
    res = _run_child(tmp_path, _CHILD % (_ACCUM, _CONS, _GOOD_APP))
    assert res["app"] is None, f"good rule on multi-unit seed should compile: {res['app']!r}"
    assert res["cons"] is None, f"single-unit consensus seed should compile: {res['cons']!r}"
    assert res["native_dir"] is True, "native_tau_dir() should be populated after load"


def test_subprocess_compile_imports_native_without_pythonpath_env(tmp_path):
    """compile_revisions_isolated_subprocess must propagate the native dir so the
    child imports tau even when PYTHONPATH does not point at it."""
    import tau_native
    nd = tau_native.native_tau_dir()
    if not nd:
        pytest.skip("native module dir not resolvable in this build layout")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    body = (
        "import os, sys, json\n"
        f"sys.path.insert(0, {nd!r}); sys.path.insert(0, {repo_root!r})\n"
        "os.environ.pop('PYTHONPATH', None)\n"  # force reliance on propagation
        "import tau_native; tau_native.load_tau_module()\n"
        f"err = tau_native.compile_revisions_isolated_subprocess({_ACCUM!r}, [{_GOOD_APP!r}], timeout=90)\n"
        "print('SUBPROC_RESULT ' + json.dumps({'err': err}))\n"
    )
    script = tmp_path / "subproc_child.py"
    script.write_text(body)
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, env=env, timeout=150)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("SUBPROC_RESULT")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    import json
    res = json.loads(line[len("SUBPROC_RESULT "):])
    assert res["err"] is None, f"isolated subprocess compile should succeed (native imported via propagation): {res['err']!r}"
