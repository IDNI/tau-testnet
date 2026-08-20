"""Real-engine characterization of rule-composition semantics (no mocks).

These tests pin down four engine behaviours that the rule-sharing design rests
on. All four were empirically discovered; none was previously covered, and the
first one is a live latent bug in the `o5` user-policy convention documented in
`tau_defs.py`.

1. ERROR DETECTION. The engine routes `(Error)` diagnostics to **fd 2** and
   ANSI-colours the marker (`tau-lang src/logging.h` renders
   `"(" << LOG_ERROR_COLOR << "Error" << TC.CLEAR() << ") "`). A capture of
   fd 1 screened with a literal `"(Error)"` substring test therefore sees
   nothing, and every rule-validation gate built on it silently passes. Covered
   here unmocked, unlike `test_invalid_rule_regression.py` which stubs the
   subprocess out.

2. IMPLICATION GUARDS DO NOT ISOLATE USERS. An output stream that no clause
   constrains for a given input materializes anyway, with an arbitrary witness
   -- observed as `0`, which for `o5` is exactly USER_POLICY_BLOCK_VALUE. So
   `always ( (i12 = A) -> (o5 = 1) ).` yields `o5=1` for A and `o5=0` for
   everyone else: a network-wide transfer block.

3. TWO TOTAL-FORM RULES ON ONE STREAM DO NOT COMPOSE. Conjoined, the spec is
   unsatisfiable and `get_interpreter` returns None. Fed sequentially through
   `i0`, the later rule silently SUPERSEDES the earlier one. Either way,
   "append one rule unit per user" cannot work for a shared stream.

4. A SINGLE COMPOSITE TOTAL-FORM RULE DOES WORK, and applying it through `i0`
   is equivalent to building it conjoined -- which is what makes replay after
   restart match a live node.
"""
import json
import os
import subprocess
import sys

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _native_python():
    """Interpreter used for the engine children.

    Defaults to the one running pytest (correct in CI, where the nanobind
    module is built against it). Override with TAU_NATIVE_PYTHON when the
    checkout's venv and the built `tau.cpython-3XX-*.so` disagree on ABI --
    otherwise the module is simply unimportable and every case silently skips.
    """
    return os.environ.get("TAU_NATIVE_PYTHON") or sys.executable


def _child_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
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


_NATIVE = _native_available()
requires_native = pytest.mark.skipif(not _NATIVE, reason="native tau module not importable")

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48

_PREAMBLE = r'''
import json, os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "false"
# Deliberately no config/db import: with shrink disabled these cases exercise
# TauInterface at the raw layer, which never reaches the intern table. That
# keeps the child runnable under a bare interpreter that only has the built
# nanobind module on PYTHONPATH.
import tau_native

SENTINEL = "SPIKE_RESULT "
ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
BASE = "o1[t]:bv[24] = i1[t]:bv[24]"


def guard(pk):
    return "(i12[t]:bv[384] = { #x" + pk + " }:bv[384])"


def o5(val):
    return "(o5[t]:bv[24] = { #x" + val + " }:bv[24])"


def new_iface():
    boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
    boot.write(ROUTER + "\n")
    boot.close()
    return tau_native.TauInterface(boot.name)


# Amounts are passed as bare decimal digits: _normalize_assignment_value only
# prefixes "#x" when the text actually contains a hex letter, so "000064" would
# be read as decimal 64, not 0x64.
AMOUNT = "100"


def sender_step(iface, pk, amount=AMOUNT):
    """Step with i12 = pk. Returns {stream_index: value} with absent streams omitted."""
    return iface.communicate_multi(input_stream_values={"12": pk, "1": amount})


def emit(obj):
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    # The native engine segfaults on interpreter teardown (known pre-existing
    # flaky crash). The result above is already computed; hard-exit before any
    # native destructor runs so the child reports a clean exit code.
    os._exit(0)
'''


def _run_child(tmp_path, name, body):
    script = tmp_path / (name + ".py")
    script.write_text(_PREAMBLE + "\n" + body)
    proc = subprocess.run(
        [_native_python(), str(script)],
        capture_output=True, text=True,
        env=_child_env({"SPIKE_DB": str(tmp_path / (name + ".db"))}),
        timeout=300,
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


# ---------------------------------------------------------------------------
# 1. Error detection (the fd-2 + ANSI bug)
# ---------------------------------------------------------------------------

@requires_native
def test_engine_error_marker_is_detected(tmp_path):
    """A malformed rule must be REJECTED by the isolated compile gate.

    Before the fd-2/ANSI fix this returned None (clean) for every case below,
    so invalid rules were admitted, charged fees, and appended to the persisted
    application-rules state.
    """
    proc, parsed = _run_child(tmp_path, "err_marker", r'''
ACCUM = ("always ( " + ROUTER + " ).\n"
         "always ( " + BASE + " ).")

cases = {
    "garbage":       "always ( garbage nonsense (",
    "width_clash":   "always ( o1[t]:bv[8] = i1[t]:bv[8] ).",
    "valid":         "always ( " + o5("000001") + " ).",
}
res = {}
for name, rule in cases.items():
    try:
        r = tau_native.TauInterface.compile_revisions_isolated(ACCUM, [rule])
    except Exception as e:
        r = "EXC: %s: %s" % (type(e).__name__, e)
    res[name] = tau_native.strip_ansi(r) if r else None
emit(res)
''')
    _assert_ok(proc, parsed)

    assert parsed["garbage"], "malformed rule was silently accepted by the compile gate"
    assert "Error" in parsed["garbage"] or "rejected" in parsed["garbage"]
    assert parsed["width_clash"], "bv-width conflict was silently accepted"
    assert parsed["valid"] is None, f"valid rule wrongly rejected: {parsed['valid']}"


def test_error_marker_regex_tolerates_ansi():
    """Pure unit check on the marker screen -- no engine needed."""
    import tau_native
    coloured = "(\x1b[31;1mError\x1b[0m) [tau] Syntax Error: boom"
    assert tau_native.tau_reports_error(coloured)
    assert tau_native.tau_reports_error("(Error) plain")
    assert not tau_native.tau_reports_error("Temporal normalization reached fixpoint")
    assert not tau_native.tau_reports_error("")
    assert tau_native.strip_ansi(coloured).startswith("(Error)")


# ---------------------------------------------------------------------------
# 2. Implication guards leak to third parties
# ---------------------------------------------------------------------------

@requires_native
def test_implication_guard_does_not_isolate_users(tmp_path):
    """`guard -> o5=1` gives the guarded sender 1 and EVERYONE ELSE 0 (= block).

    This is why accepted rules are composed into one total-form composite per
    stream instead of being appended as individually guarded units.
    """
    proc, parsed = _run_child(tmp_path, "impl_guard", r'''
res = {}

# Baseline: nothing mentions o5 -> o5 is absent -> allow.
iface = new_iface()
iface.communicate(rule_text="always ( " + BASE + " ).", target_output_stream_index=0)
res["baseline"] = {who: sender_step(iface, pk).get(5) for who, pk in (("A", A), ("C", C))}

# Implication-guarded allow for A only.
iface2 = new_iface()
iface2.communicate(
    rule_text="always ( (" + BASE + ") && (" + guard(A) + " -> " + o5("000001") + ") ).",
    target_output_stream_index=0,
)
res["implication"] = {who: sender_step(iface2, pk).get(5) for who, pk in (("A", A), ("C", C))}
emit(res)
''')
    _assert_ok(proc, parsed)

    # With no o5 clause at all, the stream never materializes.
    assert parsed["baseline"]["A"] in (None, ""), parsed["baseline"]
    assert parsed["baseline"]["C"] in (None, ""), parsed["baseline"]

    # The guarded sender gets its intended value...
    assert str(parsed["implication"]["A"]) == "1", parsed["implication"]
    # ...and the unguarded third party gets a materialized 0 == BLOCK.
    assert str(parsed["implication"]["C"]) == "0", (
        "engine no longer materializes unconstrained o5 as 0; the composite "
        "design's premise changed and the scoping model must be revisited: "
        f"{parsed['implication']}"
    )


# ---------------------------------------------------------------------------
# 3. Two total-form rules on one stream do not compose
# ---------------------------------------------------------------------------

@requires_native
def test_two_total_form_rules_do_not_compose(tmp_path):
    """Conjoined -> unsatisfiable. Sequential -> the later rule supersedes."""
    proc, parsed = _run_child(tmp_path, "no_compose", r'''
res = {}

def total(pk, val):
    return "(" + guard(pk) + " ? " + o5(val) + " : " + o5("000001") + ")"

# (a) Conjoined in a single spec: expect the interpreter build to fail.
tau_mod = tau_native.load_tau_module()
spec = ("always ( (" + BASE + ") && " + total(A, "000000")
        + " && " + total(B, "000000") + " ).")
with tau_native.StdOutCapture() as cap:
    built = tau_mod.get_interpreter(tau_native.TauInterface.preprocess_spec_text(spec))
res["conjoined_built"] = built is not None
res["conjoined_err"] = tau_native.strip_ansi(cap.output)[:400]

# (b) Applied sequentially through i0: does A's own clause survive B's?
iface = new_iface()
iface.communicate(
    rule_text="always ( (" + BASE + ") && " + total(A, "000000") + " ).",
    target_output_stream_index=0)
iface.communicate(
    rule_text="always ( " + total(B, "000000") + " ).",
    target_output_stream_index=0)
res["sequential"] = {who: sender_step(iface, pk).get(5)
                     for who, pk in (("A", A), ("B", B), ("C", C))}
emit(res)
''')
    _assert_ok(proc, parsed)

    assert parsed["conjoined_built"] is False, (
        "two total-form o5 rules now conjoin successfully; re-evaluate whether "
        "per-user clauses could be appended independently after all"
    )

    seq = parsed["sequential"]
    # B applied last, so B's own block is in force...
    assert str(seq["B"]) == "0", seq
    # ...while A's clause has been superseded -- A is no longer blocked.
    assert str(seq["A"]) == "1", (
        "the later i0 rule no longer supersedes the earlier one for the same "
        f"stream; the composite design's premise changed: {seq}"
    )


# ---------------------------------------------------------------------------
# 4. The composite works, and i0 replay matches a conjoined build
# ---------------------------------------------------------------------------

@requires_native
def test_composite_isolates_and_is_replay_equivalent(tmp_path):
    """One nested total-form unit per stream: each acceptor keeps its own policy."""
    proc, parsed = _run_child(tmp_path, "composite", r'''
res = {}

# Composite: A blocked, B blocked, everyone else allowed.
composite = ("(" + guard(A) + " ? " + o5("000000")
             + " : (" + guard(B) + " ? " + o5("000000")
             + " : " + o5("000001") + "))")

# (a) Conjoined build.
tau_mod = tau_native.load_tau_module()
spec = "always ( (" + BASE + ") && " + composite + " )."
with tau_native.StdOutCapture() as cap:
    built = tau_mod.get_interpreter(tau_native.TauInterface.preprocess_spec_text(spec))
res["conjoined_built"] = built is not None
res["conjoined_err"] = tau_native.strip_ansi(cap.output)[:300]

# (b) Sequential i0 application -- the path a live node and a replaying node
#     both take.
iface = new_iface()
iface.communicate(rule_text="always ( " + BASE + " ).", target_output_stream_index=0)
iface.communicate(rule_text="always ( " + composite + " ).", target_output_stream_index=0)
res["sequential"] = {who: sender_step(iface, pk).get(5)
                     for who, pk in (("A", A), ("B", B), ("C", C))}
res["sequential_o1"] = sender_step(iface, C).get(1)
emit(res)
''')
    _assert_ok(proc, parsed)

    assert parsed["conjoined_built"] is True, (
        f"composite failed to build: {parsed['conjoined_err']}"
    )

    seq = parsed["sequential"]
    assert str(seq["A"]) == "0", seq   # A's policy in force
    assert str(seq["B"]) == "0", seq   # B's policy ALSO in force (the whole point)
    assert str(seq["C"]) == "1", seq   # third party unaffected -> allowed
    # The unrelated base rule still applies: o1 echoes the amount unchanged.
    assert str(parsed["sequential_o1"]) == "100", parsed["sequential_o1"]


# ---------------------------------------------------------------------------
# 5. The real emitter output, on the real engine
# ---------------------------------------------------------------------------

@requires_native
def test_emitted_composite_isolates_acceptors_on_the_engine(tmp_path):
    """End-to-end check of `compose_stream_rule`'s actual output.

    The cases above use hand-written text to characterize the engine. This one
    closes the loop: it feeds exactly what the production emitter produces and
    asserts each acceptor's policy applies to that acceptor only.

    The composite is built in the parent (which has the repo's dependencies)
    and passed to the child as text, so the child needs nothing but the
    nanobind module on PYTHONPATH.
    """
    from consensus.rule_offers import compose_stream_rule, normalize_offer_rule_text

    block_body, target = normalize_offer_rule_text(
        "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
    )
    allow_body, _ = normalize_offer_rule_text(
        "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
    )
    # A blocks itself, B explicitly allows itself, C has no clause at all.
    composite = compose_stream_rule(target, {A: block_body, B: allow_body})
    solo = compose_stream_rule(target, {A: block_body})

    body = (
        "COMPOSITE = " + json.dumps(composite) + "\n"
        "SOLO = " + json.dumps(solo) + "\n"
        + r'''
def probe(composite):
    iface = new_iface()
    iface.communicate(rule_text="always ( " + BASE + " ).", target_output_stream_index=0)
    iface.communicate(rule_text=composite, target_output_stream_index=0)
    return {who: sender_step(iface, pk).get(5) for who, pk in (("A", A), ("B", B), ("C", C))}

emit({"multi": probe(COMPOSITE), "solo": probe(SOLO)})
'''
    )
    proc, parsed = _run_child(tmp_path, "emitted_composite", body)
    _assert_ok(proc, parsed)

    multi = parsed["multi"]
    assert str(multi["A"]) == "0", multi   # A's own block clause
    assert str(multi["B"]) == "1", multi   # B's own allow clause
    assert str(multi["C"]) == "1", multi   # no clause -> neutral (allow)

    solo_res = parsed["solo"]
    assert str(solo_res["A"]) == "0", solo_res
    # With only A's clause registered, B falls through to neutral rather than
    # inheriting A's policy.
    assert str(solo_res["B"]) == "1", solo_res
    assert str(solo_res["C"]) == "1", solo_res
