"""W8: admission validates the text apply will actually feed.

`sendtx` used to compile the CANONICAL full-width rule in a fresh subprocess.
A fresh process has no type commitments and does no shrinking, so it always
compiled and the transaction was admitted; apply then prepared the rule in the
live process, where the engine had already typed its streams, and refused it.
That is the whole shape of the incident: ok, then silence.
"""
import os
import textwrap

import pytest

import tau_preflight as pf
import tau_speculation


def _worker(tmp_path, body, name="pf_worker.py"):
    src = textwrap.dedent('''
        import json, os, struct, sys
        _HDR = struct.Struct("!I")
        FD = int(os.environ["TAU_WORKER_RESULT_FD"])
        def read():
            head = sys.stdin.buffer.read(_HDR.size)
            if not head or len(head) < _HDR.size: return None
            (n,) = _HDR.unpack(head)
            return json.loads(sys.stdin.buffer.read(n).decode())
        def write(payload):
            blob = json.dumps(payload).encode()
            os.write(FD, _HDR.pack(len(blob)) + blob)
    ''') + textwrap.dedent(body)
    path = tmp_path / name
    path.write_text(src)
    return str(path)


def _canned(tmp_path, revise_body):
    return _worker(tmp_path, '''
        n = 0
        while True:
            req = read()
            if req is None: break
            n += 1
            op = req.get("op")
            if op == "init":
                write({"ok": True, "request_id": req["request_id"], "state_revision": n})
            elif op == "revise":
                body = %s
                body.update({"request_id": req["request_id"], "state_revision": n,
                             "candidate_id": req.get("candidate_id", "")})
                write(body)
            elif op == "close":
                write({"ok": True, "request_id": req["request_id"], "state_revision": n})
                break
            else:
                write({"ok": True, "request_id": req["request_id"], "state_revision": n})
    ''' % revise_body)


SPEC = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
RULE = "always ( i12[t]:bv[8] = { 2 }:bv[8] -> ( o5[t]:bv[24] = { #x000000 }:bv[24] ) )."


def test_an_accepted_rule_is_admitted(tmp_path):
    w = _canned(tmp_path, '{"ok": True, "outcome": "ACCEPTED_CHANGED", "capture_complete": True}')
    result = pf.preflight_rule(SPEC, RULE, worker=w)
    assert result.verdict == pf.ADMIT and result.ok


def test_a_refused_rule_is_rejected_with_the_engine_diagnostic(tmp_path):
    w = _canned(tmp_path, '''{"ok": False, "outcome": "REJECTED_RULE", "capture_complete": True,
            "diagnostics": "(Error) Incompatible type information in i12, expected :bv[384], found :bv[8]\\n"}''')
    result = pf.preflight_rule(SPEC, RULE, worker=w)
    assert result.verdict == pf.REJECT
    assert "Incompatible type information" in result.detail


def test_an_incomplete_capture_is_operational_not_acceptance(tmp_path):
    """Acceptance that rests on diagnostics nobody could read is not acceptance."""
    w = _canned(tmp_path, '{"ok": True, "outcome": "ACCEPTED_CHANGED", "capture_complete": False}')
    result = pf.preflight_rule(SPEC, RULE, worker=w)
    assert result.verdict == pf.UNAVAILABLE
    assert "capture" in result.detail


def test_an_unavailable_worker_is_operational_not_a_rejection(tmp_path):
    w = _worker(tmp_path, '''
        req = read()
        write({"ok": False, "unavailable": True, "error": "native tau unavailable",
               "request_id": req["request_id"], "state_revision": 1})
    ''')
    result = pf.preflight_rule(SPEC, RULE, worker=w)
    assert result.verdict == pf.UNAVAILABLE
    assert result.outcome is None


def test_a_dead_worker_is_operational(tmp_path):
    w = _worker(tmp_path, "sys.exit(9)")
    result = pf.preflight_rule(SPEC, RULE, worker=w)
    assert result.verdict == pf.UNAVAILABLE


@pytest.mark.parametrize("outcome", ["REJECTED_NOT_ROUTED", "INCOMPLETE"])
def test_inconclusive_outcomes_do_not_narrow_admissibility(tmp_path, outcome):
    """An unsatisfiable rule lands in the no-revision branch rather than being
    refused, and 'the engine never asked for i0' says nothing about the
    candidate. Both were admissible before; narrowing that is a separate call."""
    w = _canned(tmp_path, '{"ok": False, "outcome": "%s", "capture_complete": True}' % outcome)
    result = pf.preflight_rule(SPEC, RULE, worker=w)
    assert result.verdict == pf.ADMIT
    assert "revalidates" in result.detail


# --- the context the answer is scoped to --------------------------------------

def test_context_carries_more_than_an_interface_generation():
    import tau_evaluator_state as st
    state = st.EvaluatorState()
    ctx = pf.capture_context(state, mapping_epoch=4)
    assert ctx["generation"] == 0 and ctx["state_revision"] == 0
    assert ctx["mapping_epoch"] == 4


def test_execution_advancing_changes_the_context_without_a_new_interface():
    import tau_evaluator_state as st
    state = st.EvaluatorState()
    before = pf.capture_context(state, mapping_epoch=1)
    state.advance()
    after = pf.capture_context(state, mapping_epoch=1)
    assert before["generation"] == after["generation"]
    assert pf.context_changed(before, after)


def test_a_moved_mapping_epoch_changes_the_context():
    import tau_evaluator_state as st
    state = st.EvaluatorState()
    before = pf.capture_context(state, mapping_epoch=1)
    after = pf.capture_context(state, mapping_epoch=2)
    assert pf.context_changed(before, after)


# --- the real engine ----------------------------------------------------------

def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


def _composed_baseline(repo_root, extra):
    """A baseline shaped like the node's composed spec: the router conjoined with
    an already-applied rule, which is what types the streams in a fresh process."""
    with open(os.path.join(repo_root, "genesis.tau")) as fh:
        router = fh.read().strip()
    return f"always ( {router} && {extra} )."


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_preflight_catches_what_a_canonical_compile_misses(tmp_path):
    """The incident's asymmetry, both halves, against the real engine.

    Baseline already carries i12 at the shrunk width, as the live process would.
    A canonical full-width rule compiles clean in a FRESH process -- which is why
    admission passed it -- and is refused against this baseline, which is what
    apply actually does.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")

    shrunk_baseline = _composed_baseline(
        repo_root, "( i12[t]:bv[8] = { 1 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] )"
    )
    full_width_rule = ("always ( i12[t]:bv[384] = { #x" + "bb" * 48 + " }:bv[384] -> "
                       "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")

    # What admission used to do: compile the canonical rule from a bare baseline.
    with open(os.path.join(repo_root, "genesis.tau")) as fh:
        bare = f"always ( {fh.read().strip()} )."
    lenient = pf.preflight_rule(bare, full_width_rule, cwd=repo_root, env=env)
    assert lenient.verdict == pf.ADMIT, lenient.receipt

    # What apply actually faces: the same rule against a baseline that already
    # typed i12 at the shrunk width.
    strict = pf.preflight_rule(shrunk_baseline, full_width_rule, cwd=repo_root, env=env)
    assert strict.verdict == pf.REJECT, strict.receipt
    assert "i12" in strict.detail, strict.detail


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_a_correctly_prepared_rule_passes_the_same_baseline(tmp_path):
    """Guard the guard: the strict baseline must not reject everything."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    shrunk_baseline = _composed_baseline(
        repo_root, "( i12[t]:bv[8] = { 1 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] )"
    )
    prepared_rule = ("always ( i12[t]:bv[8] = { 2 }:bv[8] -> "
                     "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")
    result = pf.preflight_rule(shrunk_baseline, prepared_rule, cwd=repo_root, env=env)
    assert result.verdict == pf.ADMIT, result.receipt
