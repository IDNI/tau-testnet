"""Admission: a refused step is TX_REJECTED only when a full-width evaluator
refuses it too. A refusal of the shrunk evaluator only is ADMISSION_UNAVAILABLE."""
import json
from unittest.mock import PropertyMock, patch

import pytest

import chain_state
import tau_admission
import tau_reconstruction as tr
import test_checktx_estimate as ce
from bls_keys import sign_payload
from commands import checktx, sendtx
from consensus.admission import TipAdmissionView

ANCHOR = {"journal_head": "h", "journal_sequence": 0, "epoch": 0, "high_water": 0}
PLAN = tr.RepresentationPlan(width=8, interned=frozenset({13}), widths=((13, 384),))


class Session:
    """A worker that refuses each step whose i1 is in `refuses`."""

    def __init__(self, refuses=()):
        self.refuses = set(refuses)
        self.fed = []
        self.disposed = False

    def apply_rule(self, rule_text, *, target, record):
        self.fed.append(("rule", rule_text))

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def evaluate(self, inputs, *, multi, record):
        assert record is False
        self.fed.append(("step", dict(inputs)))
        if str(inputs.get(1)) in self.refuses:
            raise tau_admission.StepRefused("the engine refused the step's inputs")
        return {1: str(inputs.get(1)), 5: "1", 8: "0", 9: "0"}

    def dispose(self):
        self.disposed = True


def _context(shrunk, rebuild):
    return tau_admission.AdmissionContext(
        shrunk, anchor=ANCHOR, plan=PLAN, label="admission", deadline=None,
        release=None, rebuild=rebuild)


def _rebuild_to(fresh, anchor=ANCHOR, calls=None):
    def rebuild(plan):
        if calls is not None:
            calls.append(plan)
        return fresh, dict(anchor), plan
    return rebuild


# --- the context ---

def test_a_refusal_that_the_recheck_confirms_is_a_refusal():
    fresh = Session(refuses={"9"})
    calls = []
    ctx = _context(Session(refuses={"9"}), _rebuild_to(fresh, calls=calls))
    with pytest.raises(tau_admission.StepRefused):
        ctx.step({1: "9"}, recheck=True)
    assert calls == [tr.RepresentationPlan.no_shrink(8)]
    assert fresh.disposed


def test_a_refusal_of_the_shrunk_evaluator_only_is_unavailable():
    fresh = Session()
    ctx = _context(Session(refuses={"9"}), _rebuild_to(fresh))
    with pytest.raises(tau_admission.AdmissionUnavailable, match="only the shrunk") as info:
        ctx.step({1: "9"}, recheck=True)
    assert not isinstance(info.value, tau_admission.StepRefused)
    assert fresh.disposed


def test_the_recheck_feeds_the_same_revisions_and_steps_again():
    fresh = Session(refuses={"9"})
    ctx = _context(Session(refuses={"9"}), _rebuild_to(fresh))
    ctx.revise("always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")
    ctx.step({1: "1"})
    with pytest.raises(tau_admission.StepRefused):
        ctx.step({1: "9"}, recheck=True)
    assert fresh.fed == [("rule", "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."),
                         ("step", {1: "1"}), ("step", {1: "9"})]


def test_without_recheck_a_refusal_is_a_refusal():
    calls = []
    ctx = _context(Session(refuses={"9"}), _rebuild_to(Session(), calls=calls))
    with pytest.raises(tau_admission.StepRefused):
        ctx.step({1: "9"})
    assert calls == []


@pytest.mark.parametrize("exc", [tau_admission.AdmissionTimeout("budget ran out"),
                                 OSError(28, "No space left on device")])
def test_a_recheck_that_fails_or_times_out_is_unavailable(exc):
    def rebuild(plan):
        raise exc

    ctx = _context(Session(refuses={"9"}), rebuild)
    with pytest.raises(tau_admission.AdmissionUnavailable) as info:
        ctx.step({1: "9"}, recheck=True)
    assert type(info.value) is tau_admission.AdmissionUnavailable


def test_a_recheck_at_another_committed_head_is_unavailable():
    fresh = Session(refuses={"9"})
    moved = dict(ANCHOR, journal_sequence=1)
    ctx = _context(Session(refuses={"9"}), _rebuild_to(fresh, anchor=moved))
    with pytest.raises(tau_admission.AdmissionUnavailable, match="committed during"):
        ctx.step({1: "9"}, recheck=True)
    assert fresh.fed == [] and fresh.disposed


def test_a_context_with_no_rebuild_cannot_recheck():
    ctx = _context(Session(refuses={"9"}), None)
    with pytest.raises(tau_admission.AdmissionUnavailable, match="cannot be checked"):
        ctx.step({1: "9"}, recheck=True)


def test_a_recheck_context_is_built_under_the_plan_it_is_given(monkeypatch):
    from types import SimpleNamespace

    import tau_session

    spawned = []

    def spawn(cls, baseline, **kwargs):
        spawned.append(kwargs["plan"])
        return Session()

    monkeypatch.setattr(tau_session.WorkerSession, "spawn", classmethod(spawn))
    store = SimpleNamespace(committed_anchor=lambda: dict(ANCHOR, rows=[], plan_json=None))
    plan = tr.RepresentationPlan.no_shrink(16)
    session, anchor, used = tau_admission._build(
        candidate_rules=(), label="admission-recheck", deadline=None, cwd=None,
        env=None, store=store, plan=plan)
    assert used is plan and spawned == [plan]
    assert anchor["journal_sequence"] == 0


# --- sendtx and the fee estimate ---

@pytest.fixture
def node(temp_database, mock_policy_evaluators, monkeypatch):
    """Worker-backed admission: the shrunk and the full-width worker refuse
    the transfer of 100 as each test says."""
    script = {"shrunk": set(), "full": set(), "plans": []}

    def build(**kwargs):
        plan = kwargs.get("plan")
        script["plans"].append(plan)
        refuses = script["full"] if plan is not None else script["shrunk"]
        return Session(refuses=refuses), dict(ANCHOR), plan or PLAN

    patches = [
        patch("tau_admission.enabled", return_value=True),
        patch("tau_admission._build", side_effect=build),
        patch("tau_admission._standby", ce._Standby()),
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau_multi",
              side_effect=AssertionError("the in-process evaluator was used")),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch("tau_native.compile_revisions_isolated_subprocess", return_value=None),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
        patch.object(TipAdmissionView, "next_block_height",
                     new_callable=PropertyMock, return_value=ce.NEXT_HEIGHT),
        patch.object(TipAdmissionView, "tip_timestamp",
                     new_callable=PropertyMock, return_value=ce.TIP_TS),
    ]
    mocks = [p.start() for p in patches]
    mocks[3].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, ce.SENDER, 1_000_000)
    yield script
    for p in reversed(patches):
        p.stop()


def _send(payload):
    sign_payload(payload, ce.SECRET_KEYS[payload["sender_pubkey"]])
    return sendtx.queue_transaction(json.dumps(payload), propagate=False)


@pytest.mark.parametrize("full_refuses, code", [(True, "TX_REJECTED"),
                                                (False, "ADMISSION_UNAVAILABLE")])
def test_sendtx_answers_by_the_full_width_recheck(node, full_refuses, code):
    import db

    node["shrunk"].add("100")
    if full_refuses:
        node["full"].add("100")
    out = _send(ce._payload("user_tx"))
    assert out["code"] == code, out
    assert tr.RepresentationPlan.no_shrink(8) in node["plans"]
    assert db.count_mempool_txs() == 0


def test_the_fee_estimate_follows_admission(node):
    node["shrunk"].add("100")
    env = ce._check(ce._payload("user_tx"))
    assert env["error"]["code"] == "ADMISSION_UNAVAILABLE", env
