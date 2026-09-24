"""The Step 4 closing test: a mixed-lifecycle block must not depend on B.

    A  accepted rule transaction
    B  changes policy, lifecycle, allocator and evaluator -- then is rejected
    C  accepted, and SENSITIVE to B: its composite is composed from the clause
       registry, so a surviving B clause changes the very text C installs
    D  accepted lifecycle operation (a rule offer)

The control block is A, C, D with B never submitted. Every observable is
compared: transaction outcomes, balances, sequences, transfer history, the
clause registry, the offer book, the approval book, application-rule state, the
journal head, the allocator delta, and the evaluator's own counters.

B is a genuine contaminant rather than a no-op. It registers a clause (lifecycle
+ registry), interns its own pubkey (allocator), installs a recomposed composite
(evaluator), and only then fails on an unaffordable transfer.
"""
import os

import pytest
from unittest.mock import MagicMock, patch

import db
import tau_allocator as alloc
import tau_defs
import tau_guard
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
A_KEY = "a1" * 48
B_KEY = "b2" * 48
C_KEY = "c3" * 48
D_KEY = "e5" * 48
PROPOSER = "d4" * 48
STREAM = tau_defs.USER_POLICY_STREAM_INDEX

OFFER_RULE = f"always ( o{STREAM}[t]:bv[24] = {{ #x000000 }}:bv[24] )."


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


def _proposal(lifecycle):
    plan = tr.plan_representation(
        candidate_rules=[_clause("000002"), _clause("000003"), _clause("000004")])
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


def _rule_tx(tx_id, sender, rule, transfer=None, fee_limit="10000"):
    tx = {"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": sender,
          "sequence_number": 0, "fee_limit": fee_limit,
          "operations": {"0": rule}}
    if transfer:
        tx["operations"]["1"] = [transfer]
    return tx


def _offer_tx(tx_id, offer):
    return {"tx_id": tx_id, "tx_type": "rule_offer",
            "sender_pubkey": offer.offerer_pubkey, "sequence_number": 0,
            "recipient_pubkey": offer.recipient_pubkey,
            "rule_text": offer.rule_text,
            "expire_at_height": offer.expire_at_height,
            "fee_limit": "10000"}


OFFER = RuleOffer(offerer_pubkey=D_KEY, recipient_pubkey=A_KEY,
                  rule_text=OFFER_RULE, expire_at_height=500)

TX_A = _rule_tx("A", A_KEY, _clause("000002"))
TX_B = _rule_tx("B", B_KEY, _clause("000003"),
                transfer=[B_KEY, C_KEY, "999999"])
TX_C = _rule_tx("C", C_KEY, _clause("000004"))
TX_D = _offer_tx("D", OFFER)

BALANCES = {A_KEY: 5000, B_KEY: 5000, C_KEY: 5000, D_KEY: 5000}


def _observe(proposal, result, lifecycle, balances, sequences, transfer_ts):
    entries = proposal.journal.entries()
    offers = lifecycle.rule_offers
    approvals = lifecycle.approval_requests
    return {
        "accepted": sorted(t["tx_id"] for t in result.accepted_transactions),
        # B's own outcome is the one thing that MUST differ -- the control never
        # saw it -- so it is asserted separately rather than compared.
        "fees": {k: v.get("fee_charged")
                 for k, v in result.receipts.items() if k != "B"},
        "statuses": {k: v.get("status")
                     for k, v in result.receipts.items() if k != "B"},
        "balances": dict(balances),
        "sequences": dict(sequences),
        "transfer_ts": dict(transfer_ts),
        "clauses": dict(offers.accepted_clauses),
        "offers": sorted(offers.offered),
        "offers_resolved": sorted(offers.resolved),
        "approvals_open": sorted(approvals.open_requests),
        "approvals_resolved": sorted(approvals.resolved),
        "application_rules": proposal.state.get("application_rules", ""),
        "journal_head": entries[-1].link if entries else None,
        "journal_kinds": [e.kind for e in entries],
        "journal_rules": [e.rule_text for e in entries],
        "allocator_delta": dict(proposal.allocator.delta()),
        "spec_revision": proposal.session._spec.state()["spec_revision"],
        "time_point": proposal.session._spec.state()["time_point"],
    }


def _run(transactions):
    lifecycle = _lifecycle()
    proposal = _proposal(lifecycle)
    engine = TauConsensusEngine(state_store=MagicMock())
    balances = dict(BALANCES)
    sequences = {}
    transfer_ts = {}
    # A recording guard alongside the strict one apply installs: the strict one
    # aborts on the first breach, this one is what the test reads afterwards.
    watcher = tau_guard.ProposalIsolationGuard(strict=False)
    with watcher:
        result = engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            transactions, 1700000000,
            target_balances=balances,
            target_sequences=sequences,
            target_last_transfer_ts=transfer_ts,
            target_lifecycle=lifecycle,
            proposer_pubkey=PROPOSER,
            block_height=1,
            proposal=proposal,
            session=proposal.session,
        )
    # A rejection that stepped the evaluator leaves the proposal owing a
    # reconstruction. Doing it here is what the block builder would do before
    # promoting the worker, and it is the point at which the two runs become
    # comparable at all.
    if proposal.dirty:
        proposal.reconstruct()
    return (proposal,
            _observe(proposal, result, lifecycle, balances, sequences, transfer_ts),
            watcher, result)


def test_a_rejected_transaction_leaves_the_block_identical(temp_database):
    epoch_before = db.shrink_mapping_epoch()

    dirty_proposal, dirty, dirty_watch, dirty_result = _run([TX_A, TX_B, TX_C, TX_D])
    control_proposal, control, control_watch, control_result = _run([TX_A, TX_C, TX_D])
    try:
        assert sorted(t["tx_id"] for t in dirty_result.rejected_transactions) == ["B"], (
            "B was supposed to be the only rejection"
        )
        assert control_result.rejected_transactions == []
        assert dirty["accepted"] == ["A", "C", "D"]

        differences = {
            key: (control[key], dirty[key])
            for key in control
            if control[key] != dirty[key]
        }
        assert not differences, (
            "the block differs from one that never contained B: "
            + "; ".join(f"{k}: control={c!r} dirty={d!r}"
                        for k, (c, d) in sorted(differences.items()))
        )

        # Nothing committed was touched by EITHER run.
        for name, watch in (("dirty", dirty_watch), ("control", control_watch)):
            assert watch.calls() == [], (
                f"the {name} run reached committed state: {watch.calls()}"
            )
        assert db.shrink_mapping_epoch() == epoch_before, (
            "speculation advanced the committed allocator"
        )
    finally:
        dirty_proposal.dispose()
        control_proposal.dispose()


def test_b_really_did_contaminate_before_it_was_rejected(temp_database):
    """Guard the guard. If B were rejected before touching anything, the block
    would match the control for reasons that have nothing to do with ownership."""
    lifecycle = _lifecycle()
    proposal = _proposal(lifecycle)
    engine = TauConsensusEngine(state_store=MagicMock())
    session_before = proposal.session
    try:
        result = engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [TX_A, TX_B, TX_C, TX_D], 1700000000,
            target_balances=dict(BALANCES), target_sequences={},
            target_last_transfer_ts={}, target_lifecycle=lifecycle,
            proposer_pubkey=PROPOSER, block_height=1,
            proposal=proposal, session=proposal.session,
        )
        logs = " ".join(result.receipts["B"]["logs"])
        assert "o5 clause registered" in logs, (
            f"B never registered its clause, so it contaminated nothing: {logs}"
        )
        assert "Tau(composite)" in logs, (
            f"B never installed a composite, so the evaluator was untouched: {logs}"
        )
        # The evaluator was rebuilt: C's branch found the proposal dirty on its
        # way in and reconstructed before running. `dirty` is therefore already
        # False by the end of the block -- asserting on the flag would be
        # asserting that the repair did NOT happen.
        assert proposal.session is not session_before, (
            "B stepped the evaluator and nothing rebuilt it"
        )
    finally:
        proposal.dispose()
