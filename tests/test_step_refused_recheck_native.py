"""Real engine: the recheck of a refused step on a fresh full-width evaluator."""
import os

import pytest


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "a1" * 48
WIDE = ("always ( i13[t]:bv[384] = { #x" + KEY + " }:bv[384]"
        " -> o5[t]:bv[24] = { #x000001 }:bv[24] ).")


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def test_the_recheck_passes_what_a_hand_built_plan_with_no_widths_refuses(
        temp_database):
    """The encoder interns each custom value since the plan has declared widths, so
    a shrink-only refusal needs a plan built by hand without them."""
    import tau_authority
    import tau_reconstruction
    import tau_session

    owner = tau_authority.AuthoritativeTauOwner(program_baseline=_router())
    proposal = owner.build_proposal(candidate_rules=[WIDE], cwd=REPO, env=_env(),
                                    lend=False)
    try:
        hand = tau_reconstruction.RepresentationPlan(width=proposal.plan.width,
                                                     interned=frozenset({13}))
        proposal.session.dispose()
        proposal.session = tau_session.WorkerSession.spawn(
            _router(), cwd=REPO, env=_env(), plan=hand, allocation=proposal.allocator)
        proposal.plan = hand
        branch = proposal.transaction("tx1")
        proposal.session.apply_rule(WIDE)
        assert proposal.session.last_receipt()["accepted"]
        with pytest.raises(tau_session.StepRefused):
            proposal.session.evaluate({13: "300"}, multi=True)
        session, entries = proposal.session, len(proposal.journal)
        delta = proposal.allocator.delta()

        assert proposal.recheck_step({13: "300"}, branch=branch).get(5) == "0"
        # The rule is only in the branch journal, so this o5 shows its replay.
        key = "{ #x" + KEY + " }:bv[384]"
        assert proposal.recheck_step({13: key}, branch=branch).get(5) == "1"
        with pytest.raises(tau_session.StepRefused):
            proposal.recheck_step({13: "#x1" + "0" * 96}, branch=branch)

        assert proposal.session is session and len(proposal.journal) == entries
        assert proposal.allocator.delta() == delta
        assert proposal.session.evaluate({13: key}, multi=True, record=False).get(5) == "1"
    finally:
        proposal.dispose()
