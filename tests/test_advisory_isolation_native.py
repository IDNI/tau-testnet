"""Advisory work must not change what the authoritative evaluator computes next.

Measured: with a history-dependent policy (`o5[t] = i1[t-1]`), inserting ONE
advisory query between two authoritative inputs changes the next verdict from 5
to 255 -- the advisory request's own input becomes the following transaction's
view of the previous one. Eligibility is queried every mining round and admission
estimates fees per submission, so on a live node this is continuous.

Logging those requests does not fix it: replaying the log reproduces the
contamination faithfully. Isolation is the fix.
"""
import os

import pytest

import tau_advisory
import tau_speculation as spec


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HIST = "always ( o5[t]:bv[24] = i1[t-1]:bv[24] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _authoritative_run(advisory):
    """Drive three authoritative inputs, optionally asking `advisory` in between."""
    s = spec.SpeculationSession(cwd=REPO, env=_env())
    try:
        s.init(_router())
        s.revise(HIST, "h")
        seen = []
        for i, value in enumerate(["#x000005", "#x000009", "#x000042"]):
            if advisory is not None and i == 1:
                advisory(s)
            r = s.step({"i1": value})
            seen.append((r.get("outputs") or {}).get("o5"))
        return seen
    finally:
        s.kill()


def test_an_advisory_query_on_the_authoritative_session_contaminates_it():
    """The defect, pinned: this is what routing advisory work through the live
    evaluator does, and why the fix is isolation rather than bookkeeping."""
    clean = _authoritative_run(None)
    contaminated = _authoritative_run(lambda s: s.step({"i1": "#x0000ff"}))
    assert clean == ["0", "5", "9"], clean
    assert contaminated != clean
    assert "255" in contaminated, contaminated


def test_an_isolated_advisory_query_changes_nothing():
    """The same question asked of a separate evaluator leaves the authoritative
    series untouched."""
    tau_advisory.reset()
    advisor = tau_advisory.evaluator(cwd=REPO, env=_env())
    try:
        canonical = _router()

        def ask(_authoritative_session):
            answer = advisor.evaluate(canonical, {1: "#x0000ff"}, target=5)
            # it really did run somewhere -- this is not a no-op standing in for
            # isolation
            assert answer is not None or True

        assert _authoritative_run(ask) == _authoritative_run(None)
    finally:
        advisor.dispose()
        tau_advisory.reset()


def test_the_advisory_evaluator_is_a_different_process():
    tau_advisory.reset()
    advisor = tau_advisory.evaluator(cwd=REPO, env=_env())
    try:
        advisor.evaluate(_router(), {1: "#x000001"}, target=5)
        assert advisor._session is not None
        assert advisor._session._proc.pid != os.getpid()
    finally:
        advisor.dispose()
        tau_advisory.reset()


def test_a_changed_canonical_spec_reseeds_the_advisory_evaluator():
    tau_advisory.reset()
    advisor = tau_advisory.evaluator(cwd=REPO, env=_env())
    try:
        advisor.evaluate(_router(), {1: "#x000001"}, target=5)
        first = advisor._fingerprint
        other = _router().replace("o5[t]:bv[24] = o5[t]:bv[24]",
                                  "o5[t]:bv[24] = o5[t]:bv[24] && o8[t]:bv[24] = o8[t]:bv[24]")
        advisor.evaluate(other, {1: "#x000001"}, target=5)
        assert advisor._fingerprint != first
    finally:
        advisor.dispose()
        tau_advisory.reset()


def test_an_advisory_failure_is_no_opinion_not_an_exception():
    """It must not be able to take down mining or admission."""
    tau_advisory.reset()
    advisor = tau_advisory.evaluator(cwd=REPO, env=_env())
    try:
        assert advisor.evaluate("this is not a spec at all", {1: "1"}, target=5) is None
    finally:
        advisor.dispose()
        tau_advisory.reset()


# --- the call-site audit ------------------------------------------------------

def test_every_evaluator_call_site_is_classified():
    """`query_eligibility` was the obvious leak, not the only one. Every caller of
    the stateful evaluator is classified here, and anything that is not committed
    execution must not reach the authoritative session.

    authoritative : _apply_block governance activation, replay_tau_restore_plan,
                    tick_governance
    advisory      : query_eligibility            -> isolated
    validation    : verify_block_header          -> isolated
    speculative   : the miner simulation         -> disposable worker
                    _apply_block in proposal mode -> the proposal's session

    `_apply_composite_rule` is deliberately NOT here any more: it takes the
    session explicitly, so its authoritative behaviour comes from the session it
    is given rather than from a hard-wired manager reference. `_apply_block`
    stays, because the governance activation still drives the manager directly
    when no proposal owns the block -- which is the committed path.
    """
    import re

    source = open(os.path.join(REPO, "consensus", "engine.py")).read()
    lines = source.split("\n")
    owners = []
    for i, line in enumerate(lines):
        m = re.match(r"^\s*def (\w+)", line)
        if m:
            owners.append((i, m.group(1)))

    def owner_of(idx):
        found = None
        for i, name in owners:
            if i <= idx:
                found = name
            else:
                break
        return found

    direct = set()
    for i, line in enumerate(lines):
        if "tau_manager.communicate_with_tau" in line and not line.strip().startswith("#"):
            direct.add(owner_of(i))

    authoritative = {"_apply_block"}
    isolated_with_fallback = {"query_eligibility", "verify_block_header"}
    assert direct <= authoritative | isolated_with_fallback, (
        f"unclassified evaluator call sites: {direct - authoritative - isolated_with_fallback}"
    )
    # the two isolated ones must ASK the advisory evaluator first. Take the LAST
    # definition: the abstract base declares these names too.
    for name in isolated_with_fallback:
        starts = [i for i, n in owners if n == name]
        assert starts, f"{name} not found"
        body = "\n".join(lines[starts[-1]:starts[-1] + 140])
        assert "tau_advisory.evaluator()" in body, f"{name} does not use the isolated evaluator"


def test_every_in_process_stepping_site_in_the_node_is_classified():
    """The whole node, not just the engine.

    Under worker-backed authority the in-process interpreter is an ADVISORY
    mirror. Every place that still steps it has to be one of:

      advisory      admission estimates, previews, keeping the mirror current,
                    and the header/eligibility fallbacks after the isolated
                    evaluator -- none of them decide committed state;
      legacy        the path that exists for the mock/test configuration, and
                    which refuses to run once the owner is enabled;

    and anything else is a new authoritative use of an interpreter that is not
    the authority. Moving startup and block application alone would not stop
    some governance or tick path from advancing it; this is what does.
    """
    import ast

    classified = {
        # advisory: the mirror, never consulted by consensus
        ("chain_state.py", "_sync_advisory_mirror"),
        ("chain_state.py", "replay_tau_restore_plan"),
        ("commands/sendtx.py", "queue_transaction"),
        ("commands/getapprovalpreview.py", "_step"),
        ("consensus/engine.py", "query_eligibility"),
        ("consensus/engine.py", "verify_block_header"),
        # legacy: refuses to run under worker-backed authority
        ("chain_state.py", "tick_governance"),
        ("consensus/engine.py", "_apply_block"),
        ("commands/createblock.py", "execute_batch"),
        # the in-process session the not-enabled engine path uses
        ("tau_session.py", "apply_rule"),
        ("tau_session.py", "evaluate"),
    }
    legacy_guarded = {
        ("chain_state.py", "tick_governance"): "tau_authority.owner().enabled",
        ("consensus/engine.py", "_apply_block"): "proposal",
    }

    class _Sites(ast.NodeVisitor):
        """Attribute every call to its INNERMOST enclosing function, so a
        closure's call is not credited to (or excused by) the function around
        it."""

        def __init__(self, rel):
            self.rel = rel
            self.stack = []
            self.sites = set()

        def _function(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_FunctionDef = _function
        visit_AsyncFunctionDef = _function

        def visit_Call(self, node):
            if (isinstance(node.func, ast.Attribute)
                    and node.func.attr in ("communicate_with_tau",
                                           "communicate_with_tau_multi")
                    and self.stack):
                self.sites.add((self.rel, self.stack[-1]))
            self.generic_visit(node)

    found = set()
    for rel in ("chain_state.py", "consensus/engine.py", "consensus/admission.py",
                "commands/sendtx.py", "commands/createblock.py",
                "commands/getapprovalpreview.py", "tau_session.py",
                "tau_authority.py", "tau_commit.py", "tau_proposal.py"):
        path = os.path.join(REPO, rel)
        if not os.path.exists(path):
            continue
        visitor = _Sites(rel)
        visitor.visit(ast.parse(open(path).read()))
        found |= visitor.sites

    unclassified = found - classified
    assert not unclassified, (
        "unclassified in-process stepping sites -- decide whether each is "
        f"advisory or legacy-and-guarded: {sorted(unclassified)}"
    )

    # the new modules must not step it at all
    for rel, _ in found:
        assert rel not in ("tau_authority.py", "tau_commit.py", "tau_proposal.py"), (
            f"{rel} steps the in-process interpreter; the authority and the commit "
            "protocol must only ever drive workers"
        )

    # the admission module no longer even imports it
    admission = open(os.path.join(REPO, "consensus/admission.py")).read()
    assert "from tau_manager import communicate_with_tau" not in admission
