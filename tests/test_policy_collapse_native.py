"""The collapsed evaluator on the real engine.

A block whose accepted execution revised the o5 registry ends with the evaluator
rebuilt from the restore plan. The collapse is only sound if the rebuilt evaluator
answers every transfer like the layered one it replaces, if the journal's RESET is
what a replay starts from, and if an emptied registry still lets a transfer through.
"""
import json
import os
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

import chain_state
import tau_allocator as alloc
import tau_authority
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
from block import Block
from consensus import admission
from consensus import rule_offers as ro
from consensus.engine import ActiveConsensusView, TauConsensusEngine, _apply_composite_rule
from consensus.governance import ConsensusLifecycleManager
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


@pytest.fixture(autouse=True)
def _signatures_not_under_test():
    with patch("consensus.engine.verify_tx_signature", return_value=(True, "")):
        yield


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENESIS = os.path.join(REPO, "networks", "tau-testnet-v2", "genesis.json")
STREAM = tau_defs.USER_POLICY_STREAM_INDEX
PROPOSER = "d4" * 48
HEIGHT = 20
T2, T3 = 10000, 100000
A, B = 1, 2
RECIPIENT = ("ee" + "7777") * 16
STRANGER = ("fe" + "9999") * 16


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


# --- the three-tier clause ------------------------------------------------------
# Hex-letter keys: an all-digit pubkey is read as a decimal and the i12 guard
# never matches.

def _bv24(n):
    return "{ #x" + format(n, "06x") + " }:bv[24]"


def _bv384(h):
    return "{ #x" + h + " }:bv[384]"


def _o5(v):
    return "(o5[t]:bv[24] = " + _bv24(v) + ")"


def author_key(i):
    return ("ab" + f"{i:04x}") * 16


def approver_keys(i):
    return tuple((p + f"{i:04x}") * 16 for p in ("ca", "cb", "cc"))


def threshold(version):
    return 1000 + version


def _clause_text(author, version):
    auth, scan, partner = approver_keys(author)
    blocked = (
        " (i1[t]:bv[24] > " + _bv24(T3) + " && !(i20[t]:bv[384] = " + _bv384(partner) + "))"
        " || (i1[t]:bv[24] > " + _bv24(T2) + " && !(i19[t]:bv[384] = " + _bv384(scan) + "))"
        " || (i1[t]:bv[24] > " + _bv24(threshold(version)) + " && !(i18[t]:bv[384] = "
        + _bv384(auth) + ")) "
    )
    return "always ( ( (" + blocked + ") ? " + _o5(0) + " : " + _o5(1) + " ) )."


def _clause_body(author, version):
    body = ro.clause_body_v1(_clause_text(author, version))
    assert admission._screen_clause_domains(body) is None
    return body


def _lifecycle(registry):
    lm = ConsensusLifecycleManager(active_validators=[PROPOSER])
    lm.approval_slots_active = True
    for author, version in registry.items():
        lm.rule_offers.accepted_clauses[(author_key(author), STREAM)] = (
            _clause_body(author, version))
    return lm


def _composite(registry):
    return _lifecycle(registry).rule_offers.composite_for_stream(STREAM)


def _units(consensus, application, registry):
    plan = chain_state.restore_plan_for(consensus, application,
                                        lifecycle=_lifecycle(registry))
    return [u for u in plan if str(u["text"]).strip()]


# --- the battery ----------------------------------------------------------------

def _cases(registry):
    """(name, sender, amount, recipient, approvals) for every verdict the registry can give."""
    cases = []
    for author, version in sorted(registry.items()):
        key = author_key(author)
        name = "AB"[author - 1]
        cases.append((f"{name}-above", key, threshold(version) + 1, RECIPIENT, {}))
        cases.append((f"{name}-below", key, threshold(version) - 1, RECIPIENT, {}))
        cases.append((f"{name}-above-approved", key, threshold(version) + 1, RECIPIENT,
                      {18: approver_keys(author)[0]}))
    cases.append(("stranger-big", STRANGER, 200000, RECIPIENT, {}))
    cases.append(("stranger-small", STRANGER, 500, RECIPIENT, {}))
    cases.append(("stranger-zero", STRANGER, 0, RECIPIENT, {}))
    first = author_key(sorted(registry)[0]) if registry else STRANGER
    cases.append(("self-transfer", first, 50, first, {}))
    return cases


def _step(session, sender, amount, recipient, approvals):
    inputs = {
        1: str(amount), 2: "100000",
        3: _bv384(sender), 4: _bv384(recipient),
        5: "1700000000", 12: _bv384(sender),
    }
    for index in range(18, 26):
        inputs[index] = "0"
    for index, key in approvals.items():
        inputs[index] = _bv384(key)
    out = session.evaluate(inputs, multi=True, apply_rules_update=False, record=False)
    return {f"o{k}": str(v) for k, v in sorted(out.items()) if k != 0}


def _battery(session, registry):
    return {name: _step(session, *rest) for name, *rest in _cases(registry)}


def _blocking(registry):
    """The o5 each case must carry: only an author over their threshold, unapproved."""
    return {name: ("0" if name.endswith("-above") else "1")
            for name, *_ in _cases(registry)}


def _assert_same_verdicts(left, right):
    assert left.keys() == right.keys()
    different = {name: (left[name], right[name]) for name in left if left[name] != right[name]}
    assert not different, f"the evaluators disagree: {different}"


# --- layered against collapsed --------------------------------------------------

REPLACEMENTS = [(A, 1), (B, 2), (A, 3), (B, 4), (A, 5), (B, 6)]


def test_a_collapsed_evaluator_gives_the_verdicts_of_the_layered_one(temp_database):
    with open(GENESIS) as fh:
        genesis = json.load(fh)
    consensus, application = genesis["consensus_rules"], genesis["application_rules"]

    registry = {A: 0, B: 0}
    states = [{A: 0}, dict(registry)]
    for author, version in REPLACEMENTS:
        registry[author] = version
        states.append(dict(registry))

    base = _units(consensus, application, {})
    final = _units(consensus, application, registry)
    plan = tr.plan_representation(
        history_rules=[u["text"] for u in base],
        candidate_rules=[_composite(state) for state in states])
    allocator = alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                label="collapse")

    def spawn(units):
        session = ts.WorkerSession.spawn(tau_authority.program_baseline(), cwd=REPO,
                                         env=_env(), plan=plan, allocation=allocator)
        session.journal = tj.Journal(authoritative=False)
        for unit in units:
            session.apply_rule(unit["text"], record=False, accumulate=bool(unit["persist"]))
            assert (session.last_receipt() or {}).get("accepted"), unit["label"]
        return session

    layered = spawn(base)
    collapsed = None
    try:
        for state in states:
            ok, detail = _apply_composite_rule(_composite(state), {"logs": []},
                                               session=layered)
            assert ok, detail
        collapsed = spawn(final)

        on_layered = _battery(layered, registry)
        on_collapsed = _battery(collapsed, registry)
        _assert_same_verdicts(on_layered, on_collapsed)

        expected = _blocking(registry)
        assert {n: out["o5"] for n, out in on_collapsed.items()} == expected, (
            "the registry is not what the equivalence was measured on")
    finally:
        layered.dispose()
        if collapsed is not None:
            collapsed.dispose()


# --- a block through the real proposal path -------------------------------------

Applied = namedtuple("Applied", "proposal result lifecycle plan units")


def _clause_tx(tx_id, author, rule_text, seq):
    return {"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": author_key(author),
            "sequence_number": seq, "fee_limit": "10000",
            "operations": {"0": rule_text}}


def _apply_block(steps):
    """Apply one block of o5 clause registrations to a real proposal evaluator.

    `steps` are (author, version) pairs, version None revoking the author's clause.
    """
    registry, states, txs, seqs = {}, [], [], {}
    for index, (author, version) in enumerate(steps):
        if version is None:
            registry.pop(author)
            text = "always ( %s )." % ro.NEUTRAL_O5_CLAUSE_BODY
        else:
            registry[author] = version
            text = _clause_text(author, version)
        states.append(dict(registry))
        seq = seqs.get(author, 0)
        seqs[author] = seq + 1
        txs.append(_clause_tx(f"clause-{index}", author, text, seq))

    base = _units("", "", {})
    final = _units("", "", registry)
    plan = tr.plan_representation(
        history_rules=[u["text"] for u in base],
        candidate_rules=[c for c in (_composite(s) for s in states) if c])
    allocator = alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                label="proposal")

    def respawn(current_plan):
        return ts.WorkerSession.spawn(tau_authority.program_baseline(), cwd=REPO,
                                      env=_env(), plan=current_plan, allocation=allocator)

    def rebuild(proposal_journal, current_plan):
        return ts.replay_entries(None, proposal_journal.entries(),
                                 respawn=lambda: respawn(current_plan))

    session = respawn(plan)
    for unit in base:
        session.apply_rule(unit["text"], record=False, accumulate=bool(unit["persist"]))
    proposal = tp.ProposalContext(
        session=session, journal=tj.Journal(authoritative=False),
        allocator=allocator, plan=plan, rebuild=rebuild, respawn=respawn)

    lm = _lifecycle({})
    parent = TauStateSnapshot(
        state_hash="0" * 64, tau_bytes=b"",
        metadata={"balances": {PROPOSER: 1000}, "sequence_numbers": {},
                  "last_transfer_ts": {}, "lifecycle_manager": lm,
                  "active_consensus_id": ""})
    block = Block.create(block_number=HEIGHT, previous_hash="0" * 64, transactions=txs,
                         proposer_pubkey=PROPOSER, timestamp=1700000000)
    view = ActiveConsensusView(target_height=HEIGHT, consensus_rules="",
                               active_validators=[bytes.fromhex(PROPOSER)])
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    result = engine.apply_block(view, block, parent, session=proposal.session,
                                proposal=proposal)
    post = result.next_snapshot.metadata["lifecycle_manager"]
    assert sorted(result.accepted_tx_ids) == sorted(t["tx_id"] for t in txs), result.outcomes
    assert post.rule_offers.accepted_clauses == _lifecycle(registry).rule_offers.accepted_clauses
    return Applied(proposal, result, post, plan, final), registry, states


def _replay_from_last_reset(applied):
    """Replay the proposal's journal; returns (worker, rule texts the replay applied)."""
    fed = []

    class Counting(ts.WorkerSession):
        def apply_rule(self, rule_text, **kwargs):
            fed.append(rule_text)
            return super().apply_rule(rule_text, **kwargs)

    allocator = alloc.Allocator(alloc.DbMappingSnapshot(), width=applied.plan.width,
                                label="replay")

    def respawn():
        return Counting.spawn(tau_authority.program_baseline(), cwd=REPO, env=_env(),
                              plan=applied.plan, allocation=allocator)

    journal = applied.proposal.journal
    worker = ts.replay_entries(None, journal.entries(), respawn=respawn,
                               expected=journal.fingerprints(), start_at_last_reset=True)
    return worker, fed


def test_a_block_that_changes_the_registry_ends_in_a_reset_the_replay_starts_from(
        temp_database):
    applied, registry, states = _apply_block([(A, 0), (B, 0), (A, 1)])
    proposal = applied.proposal
    replayed = None
    try:
        entries = proposal.journal.entries()
        resets = [e for e in entries if e.kind == tj.RESET]
        composites = [e for e in entries if e.kind == tj.REVISION and not e.accumulate]
        assert entries[-1].kind == tj.RESET and len(resets) == 1, [e.kind for e in entries]
        assert len(composites) == len(states), "a composite never reached the journal"
        assert [(text, persist) for text, persist in resets[0].units] == [
            (str(u["text"]), bool(u["persist"])) for u in applied.units]

        replayed, fed = _replay_from_last_reset(applied)
        assert fed == [text for text, _ in resets[0].units], (
            "the replay applied something other than the RESET's units")
        for stale in (_composite(s) for s in states[:-1]):
            assert stale not in fed, "the replay re-applied a composite the RESET replaced"

        on_proposal = _battery(proposal.session, registry)
        _assert_same_verdicts(on_proposal, _battery(replayed, registry))
        assert {n: out["o5"] for n, out in on_proposal.items()} == _blocking(registry)
    finally:
        proposal.dispose()
        if replayed is not None:
            replayed.dispose()


def test_an_emptied_registry_still_allows_a_transfer(temp_database):
    applied, registry, states = _apply_block([(A, 0), (A, None)])
    proposal = applied.proposal
    replayed = None
    try:
        assert registry == {} and applied.lifecycle.rule_offers.accepted_clauses == {}
        assert proposal.journal.entries()[-1].kind == tj.RESET

        replayed, _ = _replay_from_last_reset(applied)
        cases = _cases({A: 0})
        for session in (proposal.session, replayed):
            for name, sender, amount, recipient, approvals in cases:
                out = _step(session, sender, amount, recipient, approvals)
                assert out.get("o5") in (None, "1"), (name, out)
                assert out["o1"] == str(amount), (name, out)
    finally:
        proposal.dispose()
        if replayed is not None:
            replayed.dispose()
