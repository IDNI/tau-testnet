"""Family 3: a routed o5 clause must not survive its transaction's rejection.

The routed path mutates lifecycle state that no verdict check can protect,
because the mutation happens BEFORE the transaction's later stages run:

    resolve_all_for_sender(sender, FAILED)   # open approvals terminated
    accepted_clauses[key] = body             # registered policy replaced
    _apply_composite_rule(composite)         # evaluator takes the new policy
    ... transfer / fee settlement ...        # and only NOW can it reject

The existing verdict guard closes the case where the transaction was already
rejected on arrival. It cannot close this one: at the moment of mutation the
transaction is still live. The remedy is ownership, not ordering -- the
transaction mutates a CLONE of the proposal's lifecycle, derives its composite
from that clone, and the proposal adopts it only on acceptance.
"""
import copy
import os

import pytest
from unittest.mock import MagicMock

import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
from consensus.approvals import ApprovalRequestEntry, ApprovalRequestLifecycleManager
from consensus.engine import TauConsensusEngine
from consensus.rule_offers import RuleOfferLifecycleManager
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
SENDER_B = "b2" * 48
SENDER_C = "c3" * 48
PROPOSER = "d4" * 48
STREAM = tau_defs.USER_POLICY_STREAM_INDEX

#: What B has registered before the block. A registered clause carries no i12
#: guard -- the composer supplies the scope -- and `clause_body_v1` returns it
#: without the outer parentheses, which is the spelling the registry holds.
PREVIOUS_BODY = f"o{STREAM}[t]:bv[24] = {{ #x000000 }}:bv[24]"
#: What B's transaction tries to register instead.
NEW_CLAUSE = f"always ( o{STREAM}[t]:bv[24] = {{ #x000002 }}:bv[24] )."
NEW_BODY = f"o{STREAM}[t]:bv[24] = {{ #x000002 }}:bv[24]"

REQUEST_ID = b"\x11" * 32


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


class _Lifecycle:
    """The parts of the lifecycle manager the routed path touches, for real.

    Real `RuleOfferLifecycleManager` and `ApprovalRequestLifecycleManager`, so
    `resolve_all_for_sender` and `composite_for_stream` behave as they do in
    production; the governance queues around them are not what this exercises.
    """

    def __init__(self):
        self.approval_slots_active = True
        self.rule_offers = RuleOfferLifecycleManager(
            accepted_clauses={(SENDER_B.lower(), STREAM): PREVIOUS_BODY}
        )
        self.approval_requests = ApprovalRequestLifecycleManager(
            open_requests={
                REQUEST_ID: ApprovalRequestEntry(
                    sender_pubkey=SENDER_B.lower(),
                    recipient_pubkey=SENDER_C.lower(),
                    amount=10,
                    expire_at_height=9999,
                    approvers={0: PROPOSER.lower()},
                )
            }
        )

    def effective_fee_beneficiary(self):
        return ""

    def effective_eligibility_mode(self):
        return ""


def _proposal(lifecycle):
    plan = tr.plan_representation(candidate_rules=[NEW_CLAUSE])
    snapshot = alloc.DbMappingSnapshot()

    def rebuild(proposal_journal, current_plan):
        session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env(),
                                         plan=current_plan)
        session.begin_proposal(alloc.Allocator(snapshot, width=current_plan.width))
        for entry in proposal_journal.entries():
            if entry.kind == tj.REVISION:
                session.apply_rule(entry.rule_text, record=False,
                                   accumulate=entry.accumulate)
            else:
                session.evaluate(entry.inputs, multi=True, record=False)
        return session

    return tp.ProposalContext(
        session=rebuild(tj.Journal(authoritative=False), plan),
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan, rebuild=rebuild, lifecycle=lifecycle,
    )


def _tx(tx_id, sender, rule=None, transfer=None, sequence_number=0):
    tx = {"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": sender,
          "sequence_number": sequence_number, "fee_limit": "1000",
          "operations": {}}
    if rule:
        tx["operations"]["0"] = rule
    if transfer:
        tx["operations"]["1"] = [transfer]
    return tx


def _run(transactions):
    engine = TauConsensusEngine(state_store=MagicMock())
    lifecycle = _Lifecycle()
    ctx = _proposal(lifecycle)
    try:
        result = engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            transactions, 1700000000,
            target_balances={SENDER_B: 5000, SENDER_C: 5000},
            target_sequences={},
            target_lifecycle=lifecycle,
            proposer_pubkey=PROPOSER,
            block_height=1,
            proposal=ctx,
            session=ctx.session,
        )
        return ctx, result, lifecycle
    except Exception:
        ctx.dispose()
        raise


# --- the decisive case --------------------------------------------------------

def test_a_routed_clause_rejected_at_a_later_stage_leaves_the_registry_alone(
        temp_database):
    """B registers a clause, then cannot afford its transfer.

    The registration, the approval resolution and the composite application all
    happened while B was still live. Only ownership can take them back.
    """
    ctx, result, lifecycle = _run([
        _tx("B", SENDER_B, rule=NEW_CLAUSE,
            transfer=[SENDER_B, SENDER_C, "999999"]),
    ])
    try:
        assert "B" in [t.get("tx_id") for t in result.rejected_transactions], \
            "B was supposed to be rejected at the transfer stage"

        assert lifecycle.rule_offers.accepted_clauses == {
            (SENDER_B.lower(), STREAM): PREVIOUS_BODY
        }, "a rejected transaction replaced the sender's registered clause"

        assert REQUEST_ID in lifecycle.approval_requests.open_requests, \
            "a rejected transaction terminated the sender's open approval request"
        assert REQUEST_ID not in lifecycle.approval_requests.resolved
    finally:
        ctx.dispose()


def test_a_routed_clause_that_is_accepted_does_land(temp_database):
    """Guard the guard: ownership must not stop an accepted clause landing.

    An isolation mechanism that also isolates the accepted path would pass the
    test above while registering nothing at all, forever.
    """
    ctx, result, lifecycle = _run([_tx("B", SENDER_B, rule=NEW_CLAUSE)])
    try:
        assert "B" in [t.get("tx_id") for t in result.accepted_transactions], \
            f"B should have been accepted: {result.receipts.get('B')}"

        assert lifecycle.rule_offers.accepted_clauses == {
            (SENDER_B.lower(), STREAM): NEW_BODY
        }, "an accepted transaction did not register its clause"

        assert REQUEST_ID not in lifecycle.approval_requests.open_requests, \
            "an accepted policy change must still resolve the open request"
        assert REQUEST_ID in lifecycle.approval_requests.resolved
    finally:
        ctx.dispose()


def _revisions(session):
    """How many revisions this evaluator has taken.

    Representation-independent on purpose. Probing the policy by feeding a
    sender and reading o5 does NOT work here: inputs are requested lazily, so a
    single step after a revision returns no o5 at all -- and even when it does,
    a runtime id is private to the context that minted it, so a fresh probe
    against a rebuilt session mints a different one and matches nothing. The
    revision count is visible to both sessions and means the same thing in each.
    """
    return session._spec.state()["spec_revision"]


def test_the_rejected_clause_is_gone_from_the_evaluator_too(temp_database):
    """Canonical state is only half of it: the composite was EVALUATED.

    A rejected transaction whose composite is still in the proposal's evaluator
    would price and police every later transaction in the block under a policy
    the block does not contain. There is no in-process undo, so the branch marks
    the proposal dirty and the evaluator is REBUILT from the accepted journal --
    which by construction never held the rejected composite.

    B is deliberately the last transaction in the block, because that is the
    case nothing else covers: a later transaction would have triggered the
    rebuild on its way in, and the contract would look satisfied by accident.
    """
    ctx, result, lifecycle = _run([
        _tx("B", SENDER_B, rule=NEW_CLAUSE,
            transfer=[SENDER_B, SENDER_C, "999999"]),
    ])
    try:
        # The proposal journal is what defines the evaluator after resolution,
        # and a rejected branch contributes nothing to it.
        assert len(ctx.journal) == 0, (
            "the rejected transaction left entries in the proposal journal: "
            f"{[e.kind for e in ctx.journal.entries()]}"
        )
        ctx.journal.verify_chain()

        # The evaluator itself is NOT clean yet, and says so. Asserting this is
        # the point: a caller that promotes a dirty proposal's worker would be
        # promoting an evaluator holding a rule the block rejected.
        assert ctx.dirty, (
            "the proposal ran a rejected transaction's composite and did not "
            "mark itself for reconstruction"
        )
        contaminated = _revisions(ctx.session)
        assert contaminated > 0, (
            "expected the un-rebuilt session to still carry B's composite; it "
            "reports no revisions at all, so this test would pass for a "
            "proposal that never ran the composite either"
        )

        ctx.reconstruct()
        assert not ctx.dirty
        rebuilt = _revisions(ctx.session)
        assert rebuilt == 0, (
            f"B's rejected composite survived reconstruction: {rebuilt} "
            f"revision(s) in an evaluator whose accepted journal is empty"
        )
    finally:
        ctx.dispose()
