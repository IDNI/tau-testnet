"""A block that activated a governance revision ends with the evaluator collapsed.

An activation layers through i0 on top of the hashed state, so apply and step
cost would grow unless the proposal's evaluator is rebuilt from the restore plan
once the block's transactions are done. The collapse is recorded as a RESET, so
a reconstruction collapses at the same point, and the advisory mirror follows it.
Registering a clause touches no evaluator, so it triggers no collapse.
"""
import hashlib
import itertools
from unittest.mock import MagicMock, patch

import pytest
from py_ecc.bls import G2Basic

import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from block import Block
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.fees import FeeRuleError
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import RuleOffer, clause_body_v1
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
PROPOSER = "d4" * 48
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
NON_POLICY_RULE = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
ACTIVATION_RULE = "always ( o9[t]:bv[16] = { #x0005 }:bv[16] )."
_TX_SEQ = itertools.count()


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


class _Session:
    """A scripted evaluator that journals revisions the way a worker does."""

    is_speculative = True

    def __init__(self, rule_accepted=True, rules_seen=None):
        self.rule_accepted = rule_accepted
        self.rules_seen = rules_seen if rules_seen is not None else []
        self.allocation = None
        self.journal = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        self.rules_seen.append((rule_text, accumulate))
        outcome = "ACCEPTED_CHANGED" if self.rule_accepted else "REJECTED_RULE"
        if record:
            self.journal.record(
                tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text=rule_text,
                target=target, outcome=outcome, accumulate=accumulate,
            )
        return "ok" if self.rule_accepted else "error: REJECTED_RULE"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        if multi:
            return {tau_defs.CONSENSUS_FEE_STREAM_INDEX: "0"}
        return ""

    def last_receipt(self):
        return {"accepted": self.rule_accepted,
                "outcome": "ACCEPTED_CHANGED" if self.rule_accepted else "REJECTED_RULE"}

    def dispose(self):
        pass


def _proposal(session, *, reset_accepted=True):
    plan = tr.plan_representation(candidate_rules=[OFFER_RULE])
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan,
        respawn=lambda current_plan: _Session(rule_accepted=reset_accepted,
                                              rules_seen=session.rules_seen),
    )


def _lifecycle(*, slots=False, update=None):
    lm = ConsensusLifecycleManager(active_validators=[PROPOSER])
    if slots:
        lm.activate_approval_slots()
    if update is not None:
        lm.update_payloads[update.update_id] = update
        lm.scheduled_updates = [(update.activate_at_height, update.update_id)]
    return lm


def _update():
    return ConsensusRuleUpdate(rule_revisions=[ACTIVATION_RULE],
                               activate_at_height=HEIGHT, proposer_pubkey=PROPOSER)


def _run(txs, *, lm=None, rule_accepted=True, reset_accepted=True):
    session = _Session(rule_accepted=rule_accepted)
    proposal = _proposal(session, reset_accepted=reset_accepted)
    lm = lm if lm is not None else _lifecycle()
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always ( o0[t]=1 ).",
        metadata={
            "balances": {ALICE: 1000, BOB: 1000, CAROL: 1000, PROPOSER: 1000},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(target_height=HEIGHT, consensus_rules="",
                               active_validators=[bytes.fromhex(PROPOSER)])
    block = Block.create(block_number=HEIGHT, previous_hash="0" * 64,
                         transactions=txs, proposer_pubkey=PROPOSER,
                         timestamp=1700000000)
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply_block(view, block, parent, session=session,
                                    proposal=proposal)
    return proposal, session, result


def _offer(recipient=BOB, offerer=ALICE):
    return RuleOffer(offerer_pubkey=offerer, recipient_pubkey=recipient,
                     rule_text=OFFER_RULE, expire_at_height=EXPIRE)


def _offer_tx(offer, seq=0):
    return _sign({
        "tx_id": f"offer-{next(_TX_SEQ)}",
        "tx_type": "rule_offer",
        "sender_pubkey": offer.offerer_pubkey,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "recipient_pubkey": offer.recipient_pubkey,
        "rule_text": offer.rule_text,
        "expire_at_height": offer.expire_at_height,
        "fee_limit": "10000",
    }, SK_ALICE)


def _accept_tx(offer, sk):
    return _sign({
        "tx_id": f"accept-{next(_TX_SEQ)}",
        "tx_type": "rule_offer_accept",
        "sender_pubkey": offer.recipient_pubkey,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "offer_id": offer.offer_id_hex,
        "rule_text": offer.rule_text,
        "fee_limit": "10000",
    }, sk)


def _accepted_offer_txs(recipient=BOB, sk=SK_BOB, offerer_seq=0):
    offer = _offer(recipient=recipient)
    return [_offer_tx(offer, seq=offerer_seq), _accept_tx(offer, sk)]


def _routed_o5_tx(sk=SK_ALICE, sender=ALICE, rule=OFFER_RULE):
    return _sign({
        "tx_id": f"o5-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "fee_limit": "10000",
        "operations": {"0": rule},
    }, sk)


def _rule_tx(seq=0):
    return _sign({
        "tx_id": f"rule-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "operations": {"0": NON_POLICY_RULE},
    }, SK_ALICE)


def _transfer_tx(seq=0):
    return _sign({
        "tx_id": f"transfer-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 5]]},
    }, SK_ALICE)


def _resets(proposal):
    return [e for e in proposal.journal.entries() if e.kind == tj.RESET]


def _expected_units(result):
    import chain_state
    meta = result.next_snapshot.metadata
    plan = chain_state.restore_plan_for(
        meta["consensus_rules_state"],
        result.next_snapshot.tau_bytes.decode("utf-8"),
    )
    return [(str(u["text"]), bool(u["persist"])) for u in plan if str(u["text"]).strip()]


# --- the collapse -------------------------------------------------------------

def test_an_activation_ends_the_block_with_one_reset(temp_database):
    proposal, session, result = _run([], lm=_lifecycle(update=_update()))

    resets = _resets(proposal)
    assert len(resets) == 1, [e.kind for e in proposal.journal.entries()]
    assert proposal.journal.entries()[-1].kind == tj.RESET
    texts = [text for text, _ in resets[0].units]
    assert any("o9" in text for text in texts), "the activated rule is missing"
    assert list(resets[0].units) == _expected_units(result)
    assert proposal.session is not session, "the evaluator was not re-initialized"


def test_the_collapse_after_an_activation_carries_no_clause(temp_database):
    proposal, session, result = _run(
        _accepted_offer_txs(), lm=_lifecycle(update=_update()),
    )

    assert len(result.accepted_tx_ids) == 2, result.outcomes
    resets = _resets(proposal)
    assert len(resets) == 1
    assert not any("i12" in text for text, _ in resets[0].units)
    assert list(resets[0].units) == _expected_units(result)


# --- no collapse --------------------------------------------------------------

def test_transfers_and_an_op_zero_rule_leave_the_evaluator_alone(temp_database):
    proposal, session, result = _run([_transfer_tx(seq=0), _rule_tx(seq=1)])

    assert len(result.accepted_tx_ids) == 2, result.outcomes
    assert (NON_POLICY_RULE, True) in session.rules_seen, (
        "the rule never reached the evaluator, so this proves nothing"
    )
    assert _resets(proposal) == []
    assert proposal.session is session


def test_an_empty_block_leaves_the_evaluator_alone(temp_database):
    proposal, session, result = _run([])

    assert _resets(proposal) == []
    assert proposal.session is session


def test_an_accepted_offer_leaves_the_evaluator_alone(temp_database):
    proposal, session, result = _run(_accepted_offer_txs())

    assert len(result.accepted_tx_ids) == 2, result.outcomes
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    assert lm.rule_offers.clause_for(BOB, tau_defs.USER_POLICY_STREAM_INDEX) is not None
    assert session.rules_seen == []
    assert proposal.journal.entries() == []
    assert proposal.session is session


def test_a_routed_o5_clause_leaves_the_evaluator_alone(temp_database):
    proposal, session, result = _run([_routed_o5_tx()], lm=_lifecycle(slots=True))

    assert result.accepted_tx_ids, result.outcomes
    assert session.rules_seen == []
    assert proposal.journal.entries() == []
    assert proposal.session is session


def test_a_clause_that_does_not_build_is_rejected_and_leaves_the_evaluator_alone(
        temp_database):
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.fail_build(clause_body_v1(OFFER_RULE), "Syntax Error")
    sender_policy.set_evaluator("apply", evaluator)
    try:
        proposal, session, result = _run(_accepted_offer_txs())
    finally:
        sender_policy.set_evaluator("apply", None)

    assert result.invalid_tx_ids, "a clause that does not build must hard-reject"
    assert evaluator.validate_calls, "the clause was never built, so this proves nothing"
    assert proposal.journal.entries() == []
    assert proposal.session is session


# --- a refused collapse -------------------------------------------------------

def test_a_refused_collapse_after_an_activation_fails_the_block(temp_database):
    with pytest.raises(FeeRuleError, match="governance activation"):
        _run([], lm=_lifecycle(update=_update()), reset_accepted=False)


# --- the advisory mirror ------------------------------------------------------

def _entry(kind, text=None, units=()):
    return tj.JournalEntry(seq=1, kind=kind, phase=tj.PHASE_APPLY, rule_text=text,
                           units=tuple(units))


class _Mirror:
    """Records what the in-process interpreter was asked to do, in order."""

    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def restore_full_tau_spec(self, spec_text, **kwargs):
        self.calls.append(("restore", spec_text))

    def communicate_with_tau(self, **kwargs):
        if kwargs["rule_text"] == self.fail_on:
            raise RuntimeError("engine refused")
        self.calls.append(("feed", kwargs["rule_text"], kwargs["apply_rules_update"],
                           kwargs["source"]))
        return "ok"


def _sync(entries, mirror):
    import chain_state
    prepared = MagicMock(journal_delta=tuple(entries))
    with patch.object(chain_state.tau_manager, "tau_test_mode", False), \
         patch.object(chain_state.tau_manager, "tau_direct_interface", object()), \
         patch.object(chain_state.tau_manager, "restore_full_tau_spec",
                      side_effect=mirror.restore_full_tau_spec), \
         patch.object(chain_state.tau_manager, "communicate_with_tau",
                      side_effect=mirror.communicate_with_tau):
        chain_state._sync_inprocess_consensus(prepared)


def test_the_mirror_restarts_from_the_last_reset_and_skips_what_came_before(tmp_path):
    import config
    program = tmp_path / "program.tau"
    program.write_text("always ( o0[t] = 1 ).")
    entries = [
        _entry(tj.REVISION, "a"),
        _entry(tj.REVISION, "b"),
        _entry(tj.RESET, units=[("u1", False), ("u2", True)]),
        _entry(tj.REVISION, "c"),
    ]
    mirror = _Mirror()
    with patch.object(config, "TAU_PROGRAM_FILE", str(program)):
        _sync(entries, mirror)

    assert [c[0] for c in mirror.calls] == ["restore", "feed", "feed", "feed"]
    assert mirror.calls[0] == ("restore", "always ( o0[t] = 1 ).")
    assert [c[1] for c in mirror.calls[1:]] == ["u1", "u2", "c"]
    assert all(c[2] is False and c[3] == "advisory_mirror" for c in mirror.calls[1:])


def test_the_mirror_takes_only_the_last_of_several_resets(tmp_path):
    import config
    program = tmp_path / "program.tau"
    program.write_text("always ( o0[t] = 1 ).")
    entries = [
        _entry(tj.RESET, units=[("old", False)]),
        _entry(tj.REVISION, "between"),
        _entry(tj.RESET, units=[("new", False)]),
    ]
    mirror = _Mirror()
    with patch.object(config, "TAU_PROGRAM_FILE", str(program)):
        _sync(entries, mirror)

    assert [c[0] for c in mirror.calls] == ["restore", "feed"]
    assert mirror.calls[1][1] == "new"


def test_the_mirror_without_a_reset_feeds_revisions_in_order(tmp_path):
    entries = [
        _entry(tj.REVISION, "a"),
        _entry(tj.STEP),
        _entry(tj.REVISION, ""),
        _entry(tj.REVISION, "b"),
    ]
    mirror = _Mirror()
    _sync(entries, mirror)

    assert [c[0] for c in mirror.calls] == ["feed", "feed"], "a restore ran without a RESET"
    assert [c[1] for c in mirror.calls] == ["a", "b"]


def test_the_mirror_stops_at_a_refused_revision_and_does_not_raise():
    entries = [_entry(tj.REVISION, "a"), _entry(tj.REVISION, "bad"),
               _entry(tj.REVISION, "c")]
    mirror = _Mirror(fail_on="bad")
    _sync(entries, mirror)

    assert [c[1] for c in mirror.calls] == ["a"]


def test_the_mirror_is_left_alone_in_test_mode():
    import chain_state
    prepared = MagicMock(journal_delta=(_entry(tj.RESET, units=[("u", False)]),))
    with patch.object(chain_state.tau_manager, "tau_test_mode", True), \
         patch.object(chain_state.tau_manager, "restore_full_tau_spec") as restore, \
         patch.object(chain_state.tau_manager, "communicate_with_tau") as feed:
        chain_state._sync_inprocess_consensus(prepared)

    assert restore.call_count == 0 and feed.call_count == 0
