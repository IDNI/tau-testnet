"""Family 3: a routed o5 clause must not survive its transaction's rejection.

The routed path mutates lifecycle state that no verdict check can protect,
because the mutation happens BEFORE the transaction's later stages run:

    resolve_all_for_sender(sender, FAILED)   # open approvals terminated
    accepted_clauses[key] = body             # registered policy replaced
    ... transfer / fee settlement ...        # and only NOW can it reject

The existing verdict guard closes the case where the transaction was already
rejected on arrival. It cannot close this one: at the moment of mutation the
transaction is still live. The remedy is ownership, not ordering -- the
transaction mutates a CLONE of the proposal's lifecycle, and the proposal adopts
it only on acceptance.
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
from bls_keys import SK_BOB, SK_CAROL, pubkey_hex, sign_tx
from consensus.approvals import ApprovalRequestEntry, ApprovalRequestLifecycleManager
from consensus.engine import TauConsensusEngine
from consensus.retractable import RetractableBook
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
SENDER_B = pubkey_hex(SK_BOB)
SENDER_C = pubkey_hex(SK_CAROL)
_SK = {SENDER_B: SK_BOB, SENDER_C: SK_CAROL}
PROPOSER = "d4" * 48
STREAM = tau_defs.USER_POLICY_STREAM_INDEX

#: What B has registered before the block. A registered clause carries no i12
#: guard -- the node supplies the scope -- and `clause_body_v1` returns it
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
        return f"always ( {fh.read().strip()} && (o9[t]:bv[24] = {{ #x000007 }}:bv[24]) )."


class _Lifecycle:
    """The parts of the lifecycle manager the routed path touches, for real.

    Real `RuleOfferLifecycleManager` and `ApprovalRequestLifecycleManager`, so
    `resolve_all_for_sender` and the clause registry behave as they do in
    production; the governance queues around them are not what this exercises.
    """

    def __init__(self):
        self.approval_slots_active = True
        self.retractable_transfers = RetractableBook()
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


def _tx(tx_id, sender, rule=None, transfer=None, sequence_number=0, fee_limit="1000"):
    tx = {"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": sender,
          "sequence_number": sequence_number, "fee_limit": fee_limit,
          "operations": {}}
    if rule:
        tx["operations"]["0"] = rule
    if transfer:
        tx["operations"]["1"] = [transfer]
    return sign_tx(tx, _SK[sender])


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
    """B registers a clause, then cannot meet its fee.

    The registration and the approval resolution happened while B was still
    live. Only ownership can take them back.
    """
    ctx, result, lifecycle = _run([
        _tx("B", SENDER_B, rule=NEW_CLAUSE, fee_limit="1"),
    ])
    try:
        assert "B" in [t.get("tx_id") for t in result.rejected_transactions], \
            "B was supposed to be rejected at fee settlement"

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

    Representation-independent on purpose: the revision count is visible to
    every session and means the same thing in each, where a probe by feeding a
    sender and reading o5 depends on lazily requested inputs and private ids.
    """
    return session._spec.state()["spec_revision"]


def test_a_routed_clause_is_never_fed_to_the_evaluator(temp_database):
    """The clause lives in the registry and is built in the policy evaluator, so
    neither an accepted nor a rejected registration revises the proposal's
    evaluator, and a rejected one leaves nothing in its journal."""
    for fee_limit in ("1", "1000"):
        ctx, result, lifecycle = _run([
            _tx("B", SENDER_B, rule=NEW_CLAUSE, fee_limit=fee_limit),
        ])
        try:
            assert not [e for e in ctx.journal.entries() if e.kind == tj.REVISION], (
                "a clause registration revised the evaluator: "
                f"{[e.kind for e in ctx.journal.entries()]}"
            )
            ctx.journal.verify_chain()
            assert _revisions(ctx.session) == 0
            if fee_limit == "1":
                assert len(ctx.journal) == 0
            if ctx.dirty:
                ctx.reconstruct()
            assert _revisions(ctx.session) == 0
        finally:
            ctx.dispose()
