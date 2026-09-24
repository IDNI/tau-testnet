"""A/B/C through the ACTUAL apply(), under the isolation guard.

The original remaining atomicity failure: a rule accepted by Tau whose
transaction is later rejected by fee settlement. The block must end up identical
to one that executed only the accepted transactions, and nothing committed may be
touched while it is decided.
"""
import os

import pytest
from unittest.mock import MagicMock

import db
import tau_allocator as alloc
import tau_guard
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
import tau_shrink as tshrink
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENDER_A = "a1" * 48
SENDER_B = "b2" * 48
SENDER_C = "c3" * 48
PROPOSER = "d4" * 48


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _allow(sender):
    return (f"always ( i12[t]:bv[384] = {{ #x{sender} }}:bv[384] -> "
            f"o5[t]:bv[24] = {{ #x000001 }}:bv[24] ).")


def _tx(tx_id, sender, rule=None, fee_limit="1000", transfer=None):
    tx = {"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": sender,
          "sequence_number": 0, "fee_limit": fee_limit, "operations": {}}
    if rule:
        tx["operations"]["0"] = rule
    if transfer:
        tx["operations"]["1"] = [transfer]
    return tx


def _proposal():
    plan = tr.plan_representation(
        candidate_rules=[_allow(SENDER_A), _allow(SENDER_B), _allow(SENDER_C)])
    snapshot = alloc.DbMappingSnapshot()

    def rebuild(proposal_journal, current_plan):
        session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env(),
                                         plan=current_plan)
        session.begin_proposal(alloc.Allocator(snapshot, width=current_plan.width))
        for entry in proposal_journal.entries():
            if entry.kind == tj.REVISION:
                session.apply_rule(entry.rule_text, record=False)
            else:
                session.evaluate(entry.inputs, multi=True, record=False)
        return session

    ctx = tp.ProposalContext(
        session=rebuild(tj.Journal(authoritative=False), plan),
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan, rebuild=rebuild,
    )
    return ctx


def _run(transactions, balances):
    """Drive apply() in proposal mode, guarded."""
    engine = TauConsensusEngine(state_store=MagicMock())
    ctx = _proposal()
    guard = tau_guard.ProposalIsolationGuard(strict=False)
    try:
        with guard:
            result = engine.apply(
                TauStateSnapshot(b"hash", b"rules", {}),
                transactions, 1700000000,
                target_balances=dict(balances),
                target_sequences={},
                target_lifecycle=MagicMock(approval_slots_active=False),
                proposer_pubkey=PROPOSER,
                block_height=1,
                proposal=ctx,
                session=ctx.session,
            )
        return ctx, result, guard
    except Exception:
        ctx.dispose()
        raise


def _policy(session, senders):
    seen = {}
    for name, sender in senders.items():
        out = session.evaluate({12: "{ #x" + sender + " }:bv[384]"},
                               multi=True, record=False)
        seen[name] = out.get(5)
    return seen


def test_a_rule_rejected_at_a_later_stage_leaves_no_trace(temp_database):
    balances = {SENDER_A: 5000, SENDER_B: 5000, SENDER_C: 5000}
    epoch_before = db.shrink_mapping_epoch()

    dirty_ctx, dirty_result, dirty_guard = _run([
        _tx("A", SENDER_A, _allow(SENDER_A)),
        # B's rule is accepted by Tau; the transfer it carries cannot be
        # afforded, so the TRANSACTION is rejected at a later stage -- the
        # original atomicity failure in its natural shape
        _tx("B", SENDER_B, _allow(SENDER_B),
            transfer=[SENDER_B, SENDER_C, "999999"]),
        _tx("C", SENDER_C, _allow(SENDER_C)),
    ], balances)
    control_ctx, control_result, control_guard = _run([
        _tx("A", SENDER_A, _allow(SENDER_A)),
        _tx("C", SENDER_C, _allow(SENDER_C)),
    ], balances)

    try:
        rejected = [t.get("tx_id") for t in dirty_result.rejected_transactions]
        assert "B" in rejected, f"B was supposed to be rejected later: {rejected}"
        assert [t.get("tx_id") for t in dirty_result.accepted_transactions] == ["A", "C"]

        # Snapshot the proposal state BEFORE probing: the probe addresses senders
        # canonically, and the session interns what it is asked about, so probing
        # first would add the very key being asserted absent.
        d, c = dirty_ctx.summary(), control_ctx.summary()
        assert d["allocation_delta"] == c["allocation_delta"]
        assert d["state"].get("application_rules") == c["state"].get("application_rules")
        assert tshrink.canonical_intern_key(SENDER_B, 384) not in d["allocation_delta"], (
            "a rejected transaction's allocation survived"
        )

        # The discriminating check. Probing by SENDER does not work here: a
        # runtime id is private to the allocation context that minted it, and B's
        # id died with its discarded child, so a fresh probe would mint a
        # different one and B's surviving rule would not match it -- the test
        # would pass whether or not the rule survived. Compare the evaluator's own
        # revision count instead, which is representation-independent.
        dirty_state = dirty_ctx.session._spec.state()
        control_state = control_ctx.session._spec.state()
        assert dirty_state["spec_revision"] == control_state["spec_revision"], (
            f"a rejected transaction's rule is still in the evaluator: "
            f"{dirty_state} vs {control_state}"
        )
    finally:
        dirty_ctx.dispose()
        control_ctx.dispose()

    # nothing committed was touched while any of that was decided
    dirty_guard.assert_clean()
    control_guard.assert_clean()
    assert db.shrink_mapping_epoch() == epoch_before


def test_proposal_mode_refuses_to_run_without_owned_state(temp_database):
    """The `x if x is not None else <global>` conveniences are how committed
    state leaks back in. In proposal mode a missing owned value is a programming
    error, not a fallback."""
    engine = TauConsensusEngine(state_store=MagicMock())
    ctx = _proposal()
    try:
        with pytest.raises(ValueError) as exc:
            engine.apply(
                TauStateSnapshot(b"hash", b"rules", {}),
                [_tx("A", SENDER_A)], 1700000000,
                target_balances=None,          # not owned
                target_sequences={},
                target_lifecycle=MagicMock(approval_slots_active=False),
                proposer_pubkey=PROPOSER, block_height=1,
                proposal=ctx, session=ctx.session,
            )
        assert "target_balances" in str(exc.value)
    finally:
        ctx.dispose()


def test_proposal_mode_does_not_commit_the_snapshot(temp_database):
    """A proposal RETURNS a snapshot; publishing it is the commit owner's
    decision, made once, later."""
    engine = TauConsensusEngine(state_store=MagicMock())
    ctx = _proposal()
    try:
        result = engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [_tx("A", SENDER_A)], 1700000000,
            target_balances={SENDER_A: 1000}, target_sequences={},
            target_lifecycle=MagicMock(approval_slots_active=False),
            proposer_pubkey=PROPOSER, block_height=1,
            proposal=ctx, session=ctx.session,
        )
        assert result.snapshot is not None
        engine._state_store.commit.assert_not_called()
    finally:
        ctx.dispose()
