"""The transaction atomicity boundary, end to end on the real engine.

A accepted, B rejected after its rule was accepted by Tau, C accepted. The result
must equal a clean control that executed only A and C from the same committed
state -- verdicts, outputs, counters, hidden type behaviour, journal head,
allocation mapping -- while the committed anchors are untouched throughout.
"""
import os

import pytest

import db
import tau_allocator as alloc
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
import tau_shrink as tshrink


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADDR_X = "1a" * 48
ADDR_Z = "2b" * 48
ADDR_Q = "3c" * 48
HIST = "always ( o8[t]:bv[24] = i1[t-3]:bv[24] )."
DEPTH1 = "always ( o9[t]:bv[24] = i1[t-1]:bv[24] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _allow(address):
    return (f"always ( i12[t]:bv[384] = {{ #x{address} }}:bv[384] -> "
            f"o5[t]:bv[24] = {{ #x000001 }}:bv[24] ).")


def _committed_anchor():
    """Committed history H: temporal depth plus a committed allocation."""
    journal = tj.Journal()
    tshrink.intern_value(ADDR_X, 384)
    session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env())
    try:
        for rule in (_allow(ADDR_X), HIST, DEPTH1):
            session.apply_rule(rule, record=False)
            receipt = session.last_outcome or {}
            journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text=rule,
                           outcome=receipt.get("outcome"), result=receipt.get("outputs"))
        for value in ("#x000005", "#x000009", "#x000042"):
            out = session.evaluate({1: value}, multi=True, record=False)
            journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: value}, result=out)
    finally:
        session.dispose()
    return journal


def _make_context(committed_journal, plan, snapshot, label):
    """A proposal whose reconstruction replays committed history then the
    accepted proposal prefix."""
    def rebuild(proposal_journal, current_plan):
        session = ts.WorkerSession.reconstruct(
            _router(), journal=committed_journal, plan=current_plan,
            snapshot=snapshot, cwd=REPO, env=_env(),
        )
        session.begin_proposal(alloc.Allocator(snapshot, width=current_plan.width))
        for entry in proposal_journal.entries():
            if entry.kind == tj.REVISION:
                session.apply_rule(entry.rule_text, record=False)
            else:
                session.evaluate(entry.inputs, multi=True, record=False)
        return session

    session = rebuild(tj.Journal(authoritative=False), plan)
    return tp.ProposalContext(
        session=session,
        journal=committed_journal.branch(),
        allocator=alloc.Allocator(snapshot, width=plan.width, label=label),
        plan=plan,
        rebuild=rebuild,
        label=label,
    )


def _observe(session):
    seen = []
    for value in ("#x000001", "#x000002"):
        out = session.evaluate({1: value}, multi=True, record=False)
        seen.append((out.get(8), out.get(9)))
    return seen


def _run(ctx, script):
    """Drive transactions through the proposal. `script` is (name, address, accept)."""
    verdicts, ids = {}, {}
    for name, address, accept in script:
        with ctx.transaction(name) as tx:
            verdicts[name] = ctx.session.apply_rule(_allow(address))
            ids[name] = address
            if accept:
                tx.accept()
            else:
                tx.reject("fee settlement failed")
    return verdicts, ids


def _policy_for(session, senders):
    """o5 for each sender, addressed CANONICALLY -- the session encodes.

    This is what a contaminating rule actually changes: comparing only the
    temporal outputs passes whether or not the rejected transaction's rule
    survived.
    """
    seen = {}
    for name, address in senders.items():
        out = session.evaluate({12: "{ #x" + address + " }:bv[384]"},
                               multi=True, record=False)
        seen[name] = out.get(5)
    return seen


def test_a_dirty_rejection_leaves_the_proposal_equal_to_a_clean_control(temp_database):
    committed = _committed_anchor()
    plan = tr.plan_representation(
        history_rules=[e.rule_text for e in committed.entries() if e.rule_text],
        candidate_rules=[_allow(ADDR_Z), _allow(ADDR_Q)],
    )
    snapshot = alloc.DbMappingSnapshot()
    epoch_before = db.shrink_mapping_epoch()
    committed_head = committed.entries()[-1].link
    committed_len = len(committed)

    dirty = _make_context(committed, plan, snapshot, "dirty")
    control = _make_context(committed, plan, snapshot, "control")
    try:
        _, dirty_ids = _run(dirty, [("A", ADDR_Z, True), ("B", ADDR_Q, False),
                                    ("C", ADDR_Z, True)])
        _, control_ids = _run(control, [("A", ADDR_Z, True), ("C", ADDR_Z, True)])

        assert not dirty.poisoned and not control.poisoned
        d, c = dirty.summary(), control.summary()
        assert d["journal_entries"] == c["journal_entries"]
        assert d["allocation_delta"] == c["allocation_delta"]
        assert _observe(dirty.session) == _observe(control.session)
        # The discriminating check: B's rule granted its own sender. If the
        # rejected transaction's effect survived, that sender is still allowed.
        probe = {"A": dirty_ids["A"], "B": dirty_ids["B"]}
        assert _policy_for(dirty.session, probe) == _policy_for(control.session, probe), (
            "a rejected transaction's rule is still in effect"
        )
        # B left nothing behind
        assert tshrink.canonical_intern_key(ADDR_Q, 384) not in d["allocation_delta"]
    finally:
        dirty.dispose()
        control.dispose()

    # the committed anchors are untouched throughout
    assert db.shrink_mapping_epoch() == epoch_before
    assert len(committed) == committed_len
    assert committed.entries()[-1].link == committed_head
    assert db.lookup_shrink_id(tshrink.canonical_intern_key(ADDR_Z, 384)) is None


def test_a_failed_reconstruction_aborts_the_proposal_operationally(temp_database):
    """Separates "transaction B was invalid" from "the node can no longer prove
    the proposal evaluator is coherent". A is not published, C is not attempted,
    and the committed anchor stays usable."""
    committed = _committed_anchor()
    plan = tr.plan_representation(
        history_rules=[e.rule_text for e in committed.entries() if e.rule_text])
    snapshot = alloc.DbMappingSnapshot()
    epoch_before = db.shrink_mapping_epoch()

    ctx = _make_context(committed, plan, snapshot, "broken")
    try:
        with ctx.transaction("A") as tx:
            ctx.session.apply_rule(_allow(ADDR_Z))
            tx.accept()

        def broken(journal, current_plan):
            raise tr.ReconstructionMismatch("the anchors disagree")

        ctx._rebuild = broken
        with ctx.transaction("B") as tx:
            ctx.session.apply_rule(_allow(ADDR_Q))
            tx.reject("fee settlement failed")

        with pytest.raises(tr.ReconstructionMismatch):
            ctx.transaction("C")          # C is never attempted
        assert ctx.poisoned
    finally:
        ctx.dispose()

    # nothing published, and the committed anchor is still usable
    assert db.shrink_mapping_epoch() == epoch_before
    assert db.lookup_shrink_id(tshrink.canonical_intern_key(ADDR_Z, 384)) is None
    rebuilt = ts.WorkerSession.reconstruct(_router(), journal=committed, plan=plan,
                                           snapshot=snapshot, cwd=REPO, env=_env())
    try:
        assert _observe(rebuilt)
    finally:
        rebuilt.dispose()
