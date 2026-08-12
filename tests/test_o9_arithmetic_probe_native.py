"""Issue #19 probe: is a computed (percentage) consensus fee expressible?

#19 states that "the deployed tau-lang does not verify multiplication", so a
proportional `o9` cannot be authored. That premise needs re-testing before any
production work is scoped around it: `bf_mul`, `bf_div`, `bf_shl` and `bf_shr`
are all in the tau grammar, and tau-lang ships a bv[64] multiply-plus-shift unit
test. If these probes pass, #19 is a TOOLING issue (gen_genesis can only emit a
flat `o9`), not an engine limitation, and needs no consensus change at all.

Everything is probed at **bv[24]**, which is what the live network runs: the
deployed genesis carries `o9[t]:bv[24] = { #x00000a }:bv[24]`, and the shipped
rules type `i1` the same way. Tau arithmetic unifies operands within one bv
family, so a computed `o9` over `i1` is already width-consistent — no widening
is needed, and widening would be a chain split anyway (rule files accumulate
into `_application_rules_state`, which is hashed into every block).

Read the results as a decision tree, not a pass/fail suite:

  P1/P2 pass ................. proportional fees are expressible; #19 becomes a
                               gen_genesis renderer plus docs.
  P3 fails (no division) ..... ship shift-only percentages (1/128, 1/256, ...)
                               and say so plainly on the issue.
  P5 fails (co-residency) .... the blocker is spec composition, not arithmetic.
                               Escalate to tau-lang; do not work around it here.
  P6 too slow ................ hard stop. A fee rule that takes seconds per
                               evaluation can wedge block production.
  P7 truncates silently ...... the host-side amount clamp is then a correctness
                               fix, not hygiene (it already landed: the host
                               now rejects anything above 2^24-1).

Each probe runs in a FRESH SUBPROCESS with its own temp DB: the native engine
carries process-global per-stream bv-width typing, so two cases sharing a
process poison each other. Auto-skips unless the native tau module imports.

KNOWN ENVIRONMENT GAP: the checked-in build at
tau-lang/build-Release/bindings/python/nanobind is `tau.cpython-314-*.so` while
the tau-testnet venv is Python 3.13, so the module cannot be imported here and
every probe skips. Answering #19 needs a build matching the interpreter that
runs the suite; until then the issue's premise is UNVERIFIED, not disproven.
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


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="native tau module not importable (see KNOWN ENVIRONMENT GAP in docstring)",
)

SENTINEL = "PROBE_RESULT "

# Router boot spec: routes rule text arriving on i0 into Tau's spec-update stream,
# exactly as genesis.tau does, so a probe activates rules the way governance does.
_PREAMBLE = '''
import json, os, sys, tempfile
os.environ.setdefault("TAU_ENV", "test")
os.environ["TAU_DB_PATH"] = os.environ.get("PROBE_DB", "probe.db")

import tau_native

SENTINEL = "PROBE_RESULT "
ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(ROUTER + "\\n"); boot.close()
iface = tau_native.TauInterface(boot.name)

def apply_rule(text):
    return iface.communicate(rule_text=text, target_output_stream_index=0)

def step(inputs):
    # BARE string values, e.g. {"1": "1280"} — not wrapped literals.
    return iface.communicate_multi(input_stream_values=inputs)

def fee_for(amount):
    outs = step({"1": str(amount)})
    return outs.get(9)

def emit(obj):
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    # The engine segfaults during interpreter teardown (pre-existing, unrelated
    # to the probe). The result is already computed, so hard-exit before any
    # native destructor runs and the child reports a clean exit code.
    os._exit(0)
'''


def _run_probe(tmp_path, name, body):
    script = tmp_path / (name + ".py")
    script.write_text(_PREAMBLE + "\n" + body)
    env = dict(os.environ)
    env["PROBE_DB"] = str(tmp_path / (name + ".db"))
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=180,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith(SENTINEL)), None)
    parsed = json.loads(line[len(SENTINEL):]) if line else None
    assert parsed is not None, (
        f"probe produced no result (exit={proc.returncode})\n"
        f"stdout tail: {proc.stdout[-800:]}\nstderr tail: {proc.stderr[-800:]}"
    )
    return parsed


SHIFT_RULE = "always (o9[t]:bv[24] = (i1[t]:bv[24] >> { #x000007 }:bv[24]))."
MUL_RULE = "always (o9[t]:bv[24] = (i1[t]:bv[24] * { #x000002 }:bv[24]))."
DIV_RULE = "always (o9[t]:bv[24] = (i1[t]:bv[24] / { #x000064 }:bv[24]))."
PCT5_RULE = ("always (o9[t]:bv[24] = "
             "((i1[t]:bv[24] * { #x000005 }:bv[24]) / { #x000064 }:bv[24])).")


def test_p1_shift_is_expressible(tmp_path):
    """o9 = i1 >> 7, i.e. ~0.78%. Shift-only is the cheapest proportional form
    and needs no multiplication at all."""
    res = _run_probe(tmp_path, "p1_shift", f'''
err = apply_rule({SHIFT_RULE!r})
emit({{"apply_err": str(err), "fee_1280": str(fee_for(1280)), "fee_127": str(fee_for(127))}})
''')
    assert "Error" not in res["apply_err"], res
    assert res["fee_1280"] == "10", res
    assert res["fee_127"] == "0", res


def test_p2_multiplication_is_expressible(tmp_path):
    """The claim #19 rests on. If this passes, the issue's premise is stale."""
    res = _run_probe(tmp_path, "p2_mul", f'''
err = apply_rule({MUL_RULE!r})
emit({{"apply_err": str(err), "fee_50": str(fee_for(50))}})
''')
    assert "Error" not in res["apply_err"], res
    assert res["fee_50"] == "100", res


def test_p3_division_is_expressible(tmp_path):
    """Needed for an arbitrary denominator (1%). Without it, only power-of-two
    percentages via shift are available."""
    res = _run_probe(tmp_path, "p3_div", f'''
err = apply_rule({DIV_RULE!r})
emit({{"apply_err": str(err), "fee_1000": str(fee_for(1000))}})
''')
    assert "Error" not in res["apply_err"], res
    assert res["fee_1000"] == "10", res


def test_p4_five_percent_is_expressible(tmp_path):
    """The literal ask in #25's body: 5% of every transfer."""
    res = _run_probe(tmp_path, "p4_pct5", f'''
err = apply_rule({PCT5_RULE!r})
emit({{"apply_err": str(err), "fee_1000": str(fee_for(1000))}})
''')
    assert "Error" not in res["apply_err"], res
    assert res["fee_1000"] == "50", res


def test_p7_overflow_behaviour_is_recorded(tmp_path):
    """Not a pass/fail: records what the engine does when i1 * 5 exceeds bv[24].
    2^24-1 * 5 wraps. The host now clamps amounts at 2^24-1, so this documents
    what that clamp is protecting against."""
    res = _run_probe(tmp_path, "p7_overflow", f'''
err = apply_rule({PCT5_RULE!r})
emit({{"apply_err": str(err), "fee_at_ceiling": str(fee_for(16777215))}})
''')
    # Record, do not assert a value: the point is to learn the semantics.
    assert "fee_at_ceiling" in res
    print(f"P7 overflow behaviour at i1=16777215: {res['fee_at_ceiling']}")
