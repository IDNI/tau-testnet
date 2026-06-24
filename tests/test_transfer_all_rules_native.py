"""Real-engine end-to-end test: ALL built-in transfer rules + a full transfer.

This is the bv[384]/shrink proof at the transfer layer. It loads every shipped
rule from `rules/` (via the production loader `load_builtin_rules_from_disk`),
composes them into one spec, and feeds that spec to the REAL interpreter through
`tau_manager.restore_full_tau_spec` -- a genuine startup/recovery entry point.
A complete transfer is then validated by driving the exact stream convention the
node uses at admission/apply time (`commands/sendtx.py`):

    i1 = amount (bv[24])           i3 = from pubkey (full bv[384])
    i2 = sender balance (bv[24])   i4 = to   pubkey (full bv[384])

and asserting every rule's output stream for the valid case and each failure
mode:

    o1 = echoed amount (rule 04)   o3 = src != dest flag (rule 02)
    o2 = sufficient-funds flag      o4 = non-zero-amount flag

The address streams i3/i4 carry FULL 384-bit BLS pubkeys; the shrink layer
interns them to a small bv for evaluation. The test also asserts the
consensus-safety invariant: the persisted/hashed CANONICAL spec stays full
bv[384] while the interpreter runs the narrowed (shrunk) spec.

The native engine has process-global per-stream bv-width typing, so the engine
work runs in a FRESH SUBPROCESS (a sibling real-engine test in the same process
can poison the shared type table). Auto-skips unless the native tau module is
importable (set PYTHONPATH to the tau-lang nanobind build).
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

# Two distinct 96-hex (384-bit) addresses. The transfer rules only do equality
# (rule 02) and arithmetic (rules 01/03/04) over these, so any distinct hex
# pair exercises the shrink interning -- no real BLS key material required.
FROM = "ab" * 48
TO = "cd" * 48

_CHILD = r'''
import json, os, re, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"   # opt in (OFF by default)
import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager, chain_state

FROM = "%s"; TO = "%s"

# Load EVERY shipped built-in rule the production way, then compose the bodies
# into a single spec (the interpreter ANDs i0-injected rules the same way).
rules = chain_state.load_builtin_rules_from_disk()
def _body(rule):
    r = re.sub(r"^\s*always\s*", "", rule.strip()).strip()
    return r[:-1].strip() if r.endswith(".") else r   # drop trailing '.'
composed = "always ( " + " && ".join(_body(r) for r in rules) + " )."

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager.last_known_tau_spec = None
tau_manager._current_prepared_spec = None
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

# restore_full_tau_spec re-prepares the WHOLE composed spec, so the shrunk-stream
# set covers every address stream (i3/i4) -- the recovery/snapshot path.
tau_manager.restore_full_tau_spec(composed)

canonical = tau_manager._current_prepared_spec.canonical_text or ""
runtime = tau_manager.tau_direct_interface.get_current_spec() or ""

def _run(amount, balance, frm, to):
    sv = {
        1: str(amount),
        2: str(balance),
        3: "{ #x" + frm + " }:bv[384]",
        4: "{ #x" + to + " }:bv[384]",
    }
    outs = tau_manager.communicate_with_tau_multi(
        input_stream_values=sv, source=frm, apply_rules_update=False)
    p = tau_manager.parse_tau_output
    return {k: (int(p(str(outs.get(k)))) if outs.get(k) is not None else None)
            for k in (1, 2, 3, 4)}

result = {
    "n_rules": len(rules),
    "shrunk_streams": sorted(int(s) for s in tau_manager._runtime_shrunk_streams),
    "canonical_full_width": ("i3[t]:bv[384]" in canonical and "i4[t]:bv[384]" in canonical),
    "runtime_has_384": ("bv[384]" in runtime),
    "valid":  _run(5, 10, FROM, TO),
    "insuff": _run(10, 5, FROM, TO),
    "src_eq": _run(5, 10, FROM, FROM),
    "zero":   _run(0, 10, FROM, TO),
}
print("TRANSFER_RESULT " + json.dumps(result))
'''


def _run_child(tmp_path):
    child = _CHILD % (FROM, TO)
    script = tmp_path / "child_transfer_all_rules.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "transfer_all_rules.db")
    # The spawned subprocess does not inherit sys.path; put the repo root on
    # PYTHONPATH so it can import tau_manager/chain_state (native tau auto-
    # discovers the sibling tau-lang build, or honors an already-set PYTHONPATH).
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=180,
    )
    line = next((l for l in proc.stdout.splitlines()
                 if l.startswith("TRANSFER_RESULT ")), None)
    assert line is not None, (
        f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    return json.loads(line[len("TRANSFER_RESULT "):])


def test_all_builtin_rules_validate_transfer_real_engine(tmp_path):
    """All shipped rules loaded together validate a full transfer end-to-end on
    the real interpreter, with bv[384] pubkeys on i3/i4 driven through shrink."""
    r = _run_child(tmp_path)

    # Every numeric-prefixed rule file was loaded (01..04; the `_05` file is
    # intentionally excluded by the loader's numeric-prefix convention).
    assert r["n_rules"] == 4, r
    # The two 384-bit address streams were interned by the shrink layer.
    assert r["shrunk_streams"] == [3, 4], r

    # JSON object keys are strings; the stream outputs are keyed "1".."4".
    # Valid transfer (amount=5, balance=10, distinct addresses): all checks pass.
    assert r["valid"] == {"1": 5, "2": 1, "3": 1, "4": 1}, f"valid transfer: {r['valid']}"
    # Insufficient funds (amount=10 > balance=5): rule 01 fails (o2=0).
    assert r["insuff"]["2"] == 0, f"insufficient funds should set o2=0: {r['insuff']}"
    # Source == destination (same pubkey on i3/i4): rule 02 fails (o3=0).
    assert r["src_eq"]["3"] == 0, f"src==dest should set o3=0: {r['src_eq']}"
    # Zero amount: rule 03 fails (o4=0) and rule 04 echoes 0 on o1.
    assert r["zero"]["4"] == 0, f"zero amount should set o4=0: {r['zero']}"
    assert r["zero"]["1"] == 0, f"zero amount should echo 0 on o1: {r['zero']}"


def test_transfer_rules_shrink_is_consensus_safe(tmp_path):
    """The interpreter runs the narrowed (shrunk) spec while the persisted/hashed
    CANONICAL spec stays full bv[384] -- so the consensus state hash is
    independent of the node-local shrink width."""
    r = _run_child(tmp_path)
    assert r["canonical_full_width"] is True, (
        f"canonical (hashed) spec must keep full bv[384] on i3/i4: {r}"
    )
    assert r["runtime_has_384"] is False, (
        f"interpreter should run the shrunk spec, not bv[384]: {r}"
    )
