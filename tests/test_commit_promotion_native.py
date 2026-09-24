"""Step 5, closed: the A/B/C/D block committed, promoted, and continued.

The block is the Step 4 one unchanged -- A accepted, B contaminates then is
rejected, C accepted and sensitive to B, D an accepted lifecycle operation. What
is new is what happens after: the exact worker that computed that state becomes
authoritative, and a continuation fed to it depends on the pre-block history,
the accepted changes, the ABSENCE of the rejected one, and an allocator value
minted inside the block.

The same continuation is then required of a node that lost the worker between
durable commit and promotion and had to rebuild from the committed anchors.
"""
import os

import pytest
from unittest.mock import MagicMock

import db
import tau_allocator as alloc
import tau_commit as tc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import RuleOffer
from consensus.state import TauStateSnapshot


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(),
                                reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A_KEY, B_KEY, C_KEY, D_KEY = "a1" * 48, "b2" * 48, "c3" * 48, "e5" * 48
PROPOSER = "d4" * 48
STREAM = tau_defs.USER_POLICY_STREAM_INDEX
OFFER_RULE = f"always ( o{STREAM}[t]:bv[24] = {{ #x000000 }}:bv[24] )."

#: Fed before the block, so the evaluator carries history the continuation
#: depends on. `[t-1]` makes the continuation sensitive to it.
HISTORY_RULE = "always ( o8[t]:bv[24] = i1[t-1]:bv[24] )."


def _clause(value):
    return f"always ( o{STREAM}[t]:bv[24] = {{ #x{value} }}:bv[24] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _lifecycle():
    lm = ConsensusLifecycleManager(active_validators=[A_KEY])
    lm.approval_slots_active = True
    return lm


def _plan():
    return tr.plan_representation(
        candidate_rules=[HISTORY_RULE, _clause("000002"), _clause("000003"),
                         _clause("000004")])


def _spawn(plan, snapshot, journal_entries=()):
    session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env(), plan=plan)
    session.begin_proposal(alloc.Allocator(snapshot, width=plan.width))
    for entry in journal_entries:
        if entry.kind == tj.REVISION:
            session.apply_rule(entry.rule_text, record=False,
                               accumulate=entry.accumulate)
        else:
            session.evaluate(entry.inputs, multi=True, record=False)
    return session


def _proposal(lifecycle, *, history=True):
    """A proposal whose committed prefix already carries temporal history."""
    plan = _plan()
    snapshot = alloc.DbMappingSnapshot()

    def rebuild(proposal_journal, current_plan):
        return _spawn(current_plan, snapshot, proposal_journal.entries())

    ctx = tp.ProposalContext(
        session=_spawn(plan, snapshot), journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan, rebuild=rebuild, lifecycle=lifecycle,
    )
    if history:
        # Pre-block: a history-dependent rule and two input steps, all recorded,
        # so the committed journal defines them and a reconstruction reproduces
        # them.
        ctx.session.apply_rule(HISTORY_RULE, target=0)
        ctx.session.evaluate({1: "{ #x000005 }:bv[24]"}, multi=True)
        ctx.session.evaluate({1: "{ #x000009 }:bv[24]"}, multi=True)
    return ctx


def _rule_tx(tx_id, sender, rule, transfer=None):
    tx = {"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": sender,
          "sequence_number": 0, "fee_limit": "10000", "operations": {"0": rule}}
    if transfer:
        tx["operations"]["1"] = [transfer]
    return tx


OFFER = RuleOffer(offerer_pubkey=D_KEY, recipient_pubkey=A_KEY,
                  rule_text=OFFER_RULE, expire_at_height=500)
TX_A = _rule_tx("A", A_KEY, _clause("000002"))
TX_B = _rule_tx("B", B_KEY, _clause("000003"), transfer=[B_KEY, C_KEY, "999999"])
TX_C = _rule_tx("C", C_KEY, _clause("000004"))
TX_D = {"tx_id": "D", "tx_type": "rule_offer", "sender_pubkey": D_KEY,
        "sequence_number": 0, "recipient_pubkey": OFFER.recipient_pubkey,
        "rule_text": OFFER.rule_text, "expire_at_height": OFFER.expire_at_height,
        "fee_limit": "10000"}
BALANCES = {A_KEY: 5000, B_KEY: 5000, C_KEY: 5000, D_KEY: 5000}


def _run_block(transactions):
    lifecycle = _lifecycle()
    ctx = _proposal(lifecycle)
    engine = TauConsensusEngine(state_store=MagicMock())
    result = engine.apply(
        TauStateSnapshot(b"hash", b"rules", {}), transactions, 1700000000,
        target_balances=dict(BALANCES), target_sequences={},
        target_last_transfer_ts={}, target_lifecycle=lifecycle,
        proposer_pubkey=PROPOSER, block_height=1,
        proposal=ctx, session=ctx.session,
    )
    if ctx.dirty:
        ctx.reconstruct()
    return ctx, result, lifecycle


#: The continuation. o8 carries `i1[t-1]`, so the series depends on the
#: PRE-BLOCK temporal history: it is 0, then each previous value in turn.
#:
#: Fed one stream at a time on purpose. Inputs are requested lazily, and a step
#: carrying a stream the engine did not ask for comes back with no outputs at
#: all -- which would make the comparison below vacuous rather than wrong.
CONTINUATION = [
    {1: "{ #x000011 }:bv[24]"},
    {1: "{ #x000022 }:bv[24]"},
    {1: "{ #x000033 }:bv[24]"},
]


def _continue(session):
    series = []
    for step in CONTINUATION:
        series.append(session.evaluate(step, multi=True, record=False))
    state = session._spec.state()
    out = {"series": series, "time_point": state["time_point"],
           "spec_revision": state["spec_revision"]}
    # The series has to carry signal, or every assertion built on it is
    # satisfied by two evaluators that both answer nothing.
    assert any(step for step in series), (
        f"the continuation produced no outputs at all: {series}"
    )
    return out


def _commit(ctx, owner, *, reconstruct=None, break_promotion=False):
    prepared = tc.PreparedBlockCommit.freeze(
        ctx, execution_id=tc.block_execution_id(
            parent="H", height=1, timestamp=1700000000, proposer=PROPOSER,
            transactions=[TX_A, TX_B, TX_C, TX_D]),
        next_snapshot=object(), parent_tip_id=None,
    )
    if break_promotion:
        def _die(proposal, prep):
            raise RuntimeError("the worker died between commit and promotion")
        owner.promote = _die
    coord = tc.PreparedCommitCoordinator(owner, reconstruct=reconstruct)
    return prepared, coord, coord.commit(prepared, proposal=ctx, tip="H+1")


# --- the healthy path ---------------------------------------------------------

def test_the_block_commits_and_its_own_worker_serves_it(temp_database):
    ctx, result, lifecycle = _run_block([TX_A, TX_B, TX_C, TX_D])
    worker = ctx.session
    owner = tc.EvaluatorOwner(None)
    try:
        assert sorted(t["tx_id"] for t in result.rejected_transactions) == ["B"]

        before_head = db.committed_journal_head()
        assert before_head == (None, 0), "something was committed before the commit"

        prepared, coord, out = _commit(ctx, owner)

        assert out["state"] == tc.ACTIVE
        # committed == prepared, in every anchor
        assert db.committed_journal_head()[0] == prepared.journal_final_head
        assert db.committed_journal_head()[1] == len(prepared.journal_delta)
        for key, value in prepared.allocation.items():
            assert db.lookup_shrink_id(key) == value, f"{key} was not published"
        assert db.find_block_commit(prepared.execution_id)["tip"] == "H+1"

        # the EXACT worker, not an equivalent one
        assert owner.session is worker
        state = owner.session._spec.state()
        assert state["spec_revision"] == prepared.proposal_spec_revision
        assert state["time_point"] == prepared.proposal_time_point

        # and the committed journal replays back to the same chain
        tj.journal_from_rows(db.committed_journal_entries()).verify_chain()
    finally:
        if owner.session is not None:
            owner.session.dispose()
        ctx.dispose()


def test_the_continuation_after_promotion_matches_a_clean_control(temp_database):
    """The continuation depends on the pre-block history, the accepted changes,
    the absence of the rejected one, and an allocator value minted in the block.
    A control block of A/C/D must answer it identically."""
    control_ctx, control_result, _ = _run_block([TX_A, TX_C, TX_D])
    control = _continue(control_ctx.session)
    control_ctx.dispose()

    ctx, result, lifecycle = _run_block([TX_A, TX_B, TX_C, TX_D])
    owner = tc.EvaluatorOwner(None)
    try:
        prepared, coord, out = _commit(ctx, owner)
        assert out["state"] == tc.ACTIVE
        promoted = _continue(owner.session)
        assert promoted == control, (
            "the promoted worker's continuation differs from a block that never "
            f"contained B:\n  promoted={promoted}\n  control ={control}"
        )
    finally:
        if owner.session is not None:
            owner.session.dispose()
        ctx.dispose()


# --- the same thing, with promotion broken ------------------------------------

def test_a_lost_worker_reconstructs_to_the_same_continuation(temp_database):
    """Durable state commits, the worker does not survive to serve it. The node
    is COMMITTED_BUT_UNAVAILABLE, rebuilds from the committed anchors, and
    answers the continuation the same way."""
    control_ctx, _, _ = _run_block([TX_A, TX_C, TX_D])
    control = _continue(control_ctx.session)
    control_ctx.dispose()

    ctx, result, lifecycle = _run_block([TX_A, TX_B, TX_C, TX_D])
    owner = tc.EvaluatorOwner(None)
    rebuilt = {}

    def _from_committed(store):
        """Exactly what a restarted node has: the committed journal, the
        committed mapping, and the representation plan."""
        journal = tj.journal_from_rows(store.committed_journal_entries())
        journal.verify_chain()
        session = _spawn(_plan(), alloc.DbMappingSnapshot(), journal.entries())
        rebuilt["session"] = session
        return session

    try:
        prepared, coord, out = _commit(ctx, owner, reconstruct=_from_committed,
                                       break_promotion=True)
        assert out["state"] == tc.COMMITTED_BUT_UNAVAILABLE
        assert not owner.serving, "the node kept serving something"
        assert db.find_block_commit(prepared.execution_id) is not None, \
            "the block must stay committed throughout"

        assert coord.recover()["state"] == tc.ACTIVE
        assert owner.session is rebuilt["session"]
        assert owner.session is not ctx.session, "recovery reused the lost worker"

        recovered = _continue(owner.session)
        assert recovered == control, (
            "the reconstructed evaluator's continuation differs from the "
            f"control:\n  recovered={recovered}\n  control  ={control}"
        )
    finally:
        for session in (owner.session, rebuilt.get("session")):
            if session is not None:
                try:
                    session.dispose()
                except Exception:
                    pass
        ctx.dispose()
