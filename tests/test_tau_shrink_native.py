"""Real-engine end-to-end test for the shrink layer.

Auto-skips unless the native tau module is importable (set PYTHONPATH to the
tau-lang nanobind build). Proves that a SHRUNK spec + production-style wrapped
i12 input, driven through tau_manager against the REAL interpreter, yields the
correct equality verdicts, and that the persisted spec stays full-width.

The actual engine call runs in a FRESH SUBPROCESS: the native engine has
process-global per-stream bv-width typing, so a sibling real-engine test in the
same process can poison the shared type table. A subprocess gives a clean one.
"""
import os
import subprocess
import sys
import tempfile

import pytest


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

HEX = "ab" * 48
OTHER = "cd" * 48

_CHILD = r'''
import os, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"   # opt in (OFF by default)
import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

HEX = "%s"; OTHER = "%s"
RULE = ("always ( ((i12[t]:bv[384] = { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 1 }:bv[64]) "
        "|| ((i12[t]:bv[384] != { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 0 }:bv[64]) ).")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager.last_known_tau_spec = None
tau_manager._current_prepared_spec = None
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

tau_manager.restore_full_tau_spec(RULE)
streams = sorted(tau_manager._runtime_shrunk_streams)
m = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=2, input_stream_values={12: "{ #x"+HEX+" }:bv[384]"})))
n = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=2, input_stream_values={12: "{ #x"+OTHER+" }:bv[384]"})))
cur = tau_manager.tau_direct_interface.get_current_spec() or ""
import tau_shrink
W = tau_shrink.current_shrink_width()
runtime_shrunk = ("bv[384]" not in cur) and (("i12[t]:bv[" + str(W) + "]") in cur)
print("SHRINK_RESULT", streams, m, n, runtime_shrunk, "W=" + str(W))
'''


def test_shrunk_equality_verdicts_match_real_engine(tmp_path):
    child = _CHILD % (HEX, OTHER)
    script = tmp_path / "child.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "shrink_native.db")
    # The spawned subprocess does not inherit sys.path; put the repo root on
    # PYTHONPATH so it can import tau_shrink/tau_manager (native tau auto-discovers
    # the sibling tau-lang build, or honors an already-set PYTHONPATH).
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("SHRINK_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    # SHRINK_RESULT [12] 1 0 True W=8
    _, streams, match, nomatch, runtime_shrunk, width = line.split(maxsplit=5)
    assert streams == "[12]", line
    # The core proof: the SHRUNK spec yields the SAME verdicts as full-width would.
    assert match == "1", f"matching i12 should pass (o2=1): {line}"
    assert nomatch == "0", f"non-matching i12 should fail (o2=0): {line}"
    # The interpreter is running the shrunk spec at the smallest dynamic width.
    assert runtime_shrunk == "True", f"interpreter should hold the shrunk spec: {line}"
    assert width == "W=8", f"tiny table should pick bv[8]: {line}"


# --- rule 02 (src==dest) with FULL pubkeys on i3/i4 via the real engine --------
_CHILD_SRC_EQ = r'''
import os, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"
import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

HEX = "%s"; OTHER = "%s"
# The actual src==dest rule, now bv[384] on i3/i4 (shrunk for eval).
RULE = ("always ( ((i3[t]:bv[384] = i4[t]:bv[384]) && o3[t] = { #x0000 }:bv[16]) "
        "|| ((i3[t]:bv[384] != i4[t]:bv[384]) && o3[t] = { #x0001 }:bv[16]) ).")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

tau_manager.restore_full_tau_spec(RULE)
streams = sorted(tau_manager._runtime_shrunk_streams)
# from == to  -> o3 = 0 (src==dest fails the check)
same = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=3,
    input_stream_values={3: "{ #x"+HEX+" }:bv[384]", 4: "{ #x"+HEX+" }:bv[384]"})))
# from != to  -> o3 = 1
diff = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=3,
    input_stream_values={3: "{ #x"+HEX+" }:bv[384]", 4: "{ #x"+OTHER+" }:bv[384]"})))
print("SRC_EQ_RESULT", "/".join(str(s) for s in streams), same, diff)
'''


# --- shrunk set accumulates across replayed builtins; transfer validates --------
# Regression for the "Unexpected '{'" transfer error: builtins are replayed one
# by one via i0. Builtin 02 (i3/i4 bv[384]) shrinks {3,4}; the later echo builtin
# shrinks nothing. If the runtime shrunk-set REPLACED per rule it would end up
# empty, and a transfer feeding `{ #x.. }:bv[384]` on i3/i4 would be rejected.
# It must ACCUMULATE so the address streams stay shrunk.
_CHILD_ACCUM = r'''
import os, tempfile, json
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"
import config; config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

FROM = "%s"; TO = "%s"
GEN = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
BUILTINS = [
 "always ( ((i1[t]:bv[24] > i2[t]:bv[24]) && o2[t] = { #x000000 }:bv[24]) || ((i1[t]:bv[24] <= i2[t]:bv[24]) && o2[t] = { #x000001 }:bv[24]) ).",
 "always ( ((i3[t]:bv[384] = i4[t]:bv[384]) && o3[t] = { #x0000 }:bv[16]) || ((i3[t]:bv[384] != i4[t]:bv[384]) && o3[t] = { #x0001 }:bv[16]) ).",
 "always (o1[t]:bv[24] = ((i1[t]:bv[24] + { #x000000 }:bv[24]) & ((i1[t]:bv[24] + { #x000000 }:bv[24]) | { #x000000 }:bv[24]))).",
]
boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False); boot.write(GEN+"\n"); boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()
for b in BUILTINS:
    tau_manager.communicate_with_tau(rule_text=b, target_output_stream_index=0, apply_rules_update=True)
streams = sorted(tau_manager._runtime_shrunk_streams)
err = None
try:
    out = tau_manager.communicate_with_tau_multi(input_stream_values={
        1: "1", 2: "100000",
        3: "{ #x"+FROM+" }:bv[384]", 4: "{ #x"+TO+" }:bv[384]"})
    o3 = tau_manager.parse_tau_output(str(out.get(3)))
except Exception as e:
    err = type(e).__name__ + ": " + str(e)[:60]; o3 = None
print("ACCUM_RESULT " + json.dumps({"streams": streams, "o3": o3, "err": err}))
'''


def test_shrunk_set_accumulates_over_builtins_then_transfer(tmp_path):
    from_hex = "91" * 48
    to_hex = "93" * 48
    child = _CHILD_ACCUM % (from_hex, to_hex)
    script = tmp_path / "child_accum.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "accum.db")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, env=env, timeout=120)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("ACCUM_RESULT")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    import json
    res = json.loads(line[len("ACCUM_RESULT "):])
    assert res["err"] is None, f"transfer must not raise a parse error: {res['err']}"
    assert res["streams"] == [3, 4], f"address streams must stay shrunk after all builtins: {res}"
    assert str(res["o3"]) == "1", f"from != to -> o3=1 (src!=dest passes): {res}"


# --- sendtx restore must NOT desync the shrunk-stream set (regression) ----------
# Repro of the live validate-then-restore path: a rule sendtx snapshots the
# interpreter's (shrunk) spec + shrunk-stream set, validates a user rule via i0
# (mutating the interpreter), then restores. restore_full_tau_spec on the
# already-shrunk snapshot re-classifies nothing (bv[W<128]) and WIPES the set;
# passing runtime_shrunk_streams= re-pins it so a following transfer that feeds a
# wide bv[384] literal still shrinks correctly and yields the right verdict.
_CHILD_RESTORE = r'''
import os, tempfile
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"
import config; config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

HEX = "%s"; KEY = "11" * 48
BASE = ("always ( ((i12[t]:bv[384] = { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 1 }:bv[64]) "
        "|| ((i12[t]:bv[384] != { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 0 }:bv[64]) ).")
USER = ("always ((i12[t]:bv[384] = { #x"+KEY+" }:bv[384] && i1[t]:bv[24] > { 5000 }:bv[24]) "
        "-> o5[t]:bv[24] = { #x000000 }:bv[24]).")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

def verdict():
    return tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
        target_output_stream_index=2, input_stream_values={12: "{ #x"+HEX+" }:bv[384]"})))

tau_manager.restore_full_tau_spec(BASE)
spec0 = tau_manager.tau_direct_interface.get_current_spec()
set0 = tau_manager.get_runtime_shrunk_streams()
tau_manager.communicate_with_tau(rule_text=USER, target_output_stream_index=0, apply_rules_update=False)

# WITHOUT the kwarg: set wipes (the bug this guards against).
tau_manager.restore_full_tau_spec(spec0)
wiped = sorted(tau_manager._runtime_shrunk_streams)

# WITH the kwarg (the fix): set re-pinned, verdict correct.
tau_manager.restore_full_tau_spec(spec0, runtime_shrunk_streams=set0)
fixed = sorted(tau_manager._runtime_shrunk_streams)
v = verdict()
print("RESTORE_RESULT", "/".join(map(str, wiped)) or "EMPTY", "/".join(map(str, fixed)), v)
'''


def test_sendtx_restore_repins_shrunk_streams_real_engine(tmp_path):
    """restore_full_tau_spec(runtime_shrunk_streams=...) keeps the shrunk-stream
    set consistent with the restored interpreter; without it the set wipes and a
    later bv[384] input mis-validates."""
    child = _CHILD_RESTORE % (HEX,)
    script = tmp_path / "child_restore.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "restore.db")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("RESTORE_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, wiped, fixed, verdict = line.split(maxsplit=3)
    assert wiped == "EMPTY", f"without the kwarg the set should wipe (proves the hazard): {line}"
    assert fixed == "12", f"with the kwarg the shrunk set must be re-pinned to [12]: {line}"
    assert verdict == "1", f"matching i12 must still verify (o2=1) after restore: {line}"


def test_src_eq_dest_rule_full_pubkeys_real_engine(tmp_path):
    """Rule 02 with bv[384] i3/i4 fed FULL pubkeys: shrink interns both, equality
    is preserved (same -> o3=0, different -> o3=1) on the real interpreter."""
    child = _CHILD_SRC_EQ % (HEX, OTHER)
    script = tmp_path / "child_srceq.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "srceq.db")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("SRC_EQ_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, streams, same, diff = line.split(maxsplit=3)
    assert streams == "3/4", line          # both address streams shrunk
    assert same == "0", f"from==to must fail src!=dest (o3=0): {line}"
    assert diff == "1", f"from!=to must pass (o3=1): {line}"


# --- W1: the incident, end to end on the real engine --------------------------
#
# Pin i12 at the shrink width with a composite (the rule-sharing shape, which
# always shrank correctly), then apply the UNPARENTHESIZED implication rule the
# monitoring swarm submitted. Before the supported-subset rewrite this produced
# `i12[t]:bv[8] = { #x<pk> }:bv[384]` and the engine refused it with
# "Incompatible type information in i12, expected :bv[384], found :bv[8]" --
# admitted by sendtx, then rejected at apply, with a crash dump each time.
#
# Driven through the RAW tau API on purpose: `spec_revision` is the engine's own
# acknowledgement, and tau_manager rebuilds its interpreter after each revision,
# which resets that counter.
_CHILD_INCIDENT = r'''
import os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"
import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau, tau_shrink as S

A = "%s"; B = "%s"
S.reset_shrink_width(8); S.set_shrink_width(8, pin=True)

def cap(fn):
    s1, s2 = os.dup(1), os.dup(2)
    t1, t2 = tempfile.TemporaryFile(), tempfile.TemporaryFile()
    os.dup2(t1.fileno(), 1); os.dup2(t2.fileno(), 2)
    try: r = fn()
    except BaseException: r = None
    finally:
        os.dup2(s1, 1); os.dup2(s2, 2); os.close(s1); os.close(s2)
    return r

router = open(os.path.join(os.environ["REPO_ROOT"], "genesis.tau")).read().strip()
itp = cap(lambda: tau.get_interpreter("always ( " + router + " )."))

def send(rule=None, i12=None):
    ins = cap(lambda: tau.get_inputs_for_step(itp))
    vals = {}
    for s in ins:
        if s.name == "i0": vals[s] = rule if rule is not None else "F"
        elif s.name == "i12" and i12 is not None: vals[s] = i12
        else: vals[s] = "0"
    before = itp.spec_revision
    outs = cap(lambda: tau.step(itp, vals))
    o = {k.name: v for k, v in outs.items()} if outs else {}
    return (itp.spec_revision > before), o.get("o5")

comp = ("always ( (i12[t]:bv[384] = { #x" + A + " }:bv[384]) ? "
        "( o5[t]:bv[24] = { #x000001 }:bv[24] ) : "
        "( o5[t]:bv[24] = { #x000001 }:bv[24] ) ).")
pinned, _ = send(S.prepare_rule(comp).runtime_text)

incident = ("always ( i12[t]:bv[384] = { #x" + B + " }:bv[384] -> "
            "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")
prep = S.prepare_rule(incident)
applied, _ = send(prep.runtime_text)

_, blocked = send(None, str(S.intern_value(B, 384)))
_, allowed = send(None, str(S.intern_value(A, 384)))
mixed = ("bv[384]" in prep.runtime_text and "bv[8]" in prep.runtime_text)
print("INCIDENT_RESULT", pinned, applied, blocked, allowed, mixed)
sys.stdout.flush()
os._exit(0)
'''


def test_unparenthesized_implication_applies_against_a_pinned_stream(tmp_path):
    child = _CHILD_INCIDENT % ("aa" * 48, "bb" * 48)
    script = tmp_path / "child_incident.py"
    script.write_text(child)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "incident.db")
    env["REPO_ROOT"] = repo_root
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("INCIDENT_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, pinned, applied, blocked, allowed, mixed = line.split()
    assert pinned == "True", f"composite should pin i12: {line}"
    assert mixed == "False", f"prepared text must not mix widths: {line}"
    # The regression itself: pre-fix the engine rejected this outright.
    assert applied == "True", f"implication rule must apply against a pinned i12: {line}"
    # And it must actually MEAN something: the guarded sender is blocked.
    assert blocked == "0", f"guarded sender should be blocked (o5=0): {line}"
    assert allowed == "1", f"unrelated sender should be allowed (o5=1): {line}"


# --- W6: the engine's own verdict, through the live wrapper -------------------
_CHILD_RECEIPT = r'''
import os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(open(os.path.join(os.environ["REPO_ROOT"], "genesis.tau")).read())
boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager.tau_ready.set()

def outcome(rule):
    tau_manager.communicate_with_tau(rule_text=rule, target_output_stream_index=0)
    r = tau_manager.get_last_revision_receipt() or {}
    return r.get("outcome"), r.get("accepted")

changed = outcome("always ( o5[t]:bv[24] = { #x000007 }:bv[24] ).")
noop    = outcome("always ( o5[t]:bv[24] = o5[t]:bv[24] ).")
unsat   = outcome("always ( o5[t]:bv[24] = { #x000001 }:bv[24] && o5[t]:bv[24] = { #x000002 }:bv[24] ).")
print("RECEIPT_RESULT", changed[0], changed[1], noop[0], noop[1], unsat[0], unsat[1])
sys.stdout.flush()
os._exit(0)
'''


def test_the_engines_own_verdict_reaches_the_caller(tmp_path):
    """The wrapper rebuilds its interpreter from stdout after a revision, which
    resets `spec_revision` to 0 -- so the evidence has to be captured before that
    happens. Without it the caller can only parse a formatted string, which reads
    an unsatisfiable rule (never routed) as success."""
    script = tmp_path / "child_receipt.py"
    script.write_text(_CHILD_RECEIPT)
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "receipt.db")
    env["REPO_ROOT"] = repo_root
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True,
                          text=True, env=env, timeout=120)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("RECEIPT_RESULT")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, ch_out, ch_acc, np_out, np_acc, un_out, un_acc = line.split()
    assert (ch_out, ch_acc) == ("ACCEPTED_CHANGED", "True"), line
    assert (np_out, np_acc) == ("ACCEPTED_NOOP", "True"), line
    # the one the string heuristic gets wrong
    assert (un_out, un_acc) == ("REJECTED_NOT_ROUTED", "False"), line
