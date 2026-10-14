"""User rules and clause bodies may reference [t] only, at admission and at apply.

One unit that reads another step gives the evaluator a lookback, and every
output is then 0 for the steps after each later revision or rebuild, for every
account. So the screen covers every unit that can reach the evaluator -- op-0
rules on any stream, routed o5 clauses, offered and accepted clauses -- and
apply repeats it unconditionally, because a proposer can include a transaction
that never went through admission. A governance update whose revisions read
another step is not recorded at apply, since activation would reset the
evaluator into a spec with lookback.
"""
import hashlib

import pytest
from py_ecc.bls import G2Basic
from unittest.mock import MagicMock, patch

from block import Block
from consensus.admission import (
    TEMPORAL_REFERENCE_CODE,
    TipAdmissionView,
    _screen_clause_domains,
    is_temporal_reference_error,
    screen_temporal_rule,
    validate_mempool_admission,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import STATUS_OFFERED, RuleOffer
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
REASON = "temporal_reference"


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)      # rule author and acceptor
SK_MALLORY, MALLORY = _key(66666)  # offerer and block proposer

# Each spelling of a reference to a step other than the current one.
# OUT stands for the rule's own output stream.
TEMPORAL_REFS = ["i1[t-1]", "i1[t - 1]", "i1[ t -  3 ]", "i1[0]", "i1[3]", "OUT[t-1]"]
FREE_STREAM = "o13"
POLICY_STREAM = "o5"
CURRENT_FREE = f"always ( {FREE_STREAM}[t]:bv[24] = i1[t]:bv[24] )."
CURRENT_POLICY = f"always ( {POLICY_STREAM}[t]:bv[24] = i1[t]:bv[24] )."


def _rule(stream, ref):
    return f"always ( {stream}[t]:bv[24] = {ref.replace('OUT', stream)}:bv[24] )."


def _free(ref):
    return _rule(FREE_STREAM, ref)


def _policy(ref):
    return _rule(POLICY_STREAM, ref)


# --- the shared screen --------------------------------------------------------

@pytest.mark.parametrize("ref", TEMPORAL_REFS)
def test_every_spelling_of_another_step_is_caught(ref):
    error = screen_temporal_rule(_free(ref))
    assert error is not None
    assert is_temporal_reference_error(error)
    assert ref.replace("OUT", FREE_STREAM).split("[")[0] in error


@pytest.mark.parametrize("rule", [
    CURRENT_FREE,
    CURRENT_POLICY,
    "always ( o13[ t ]:bv[24] = i1[ t ]:bv[24] ).",
    "# i1[t-1] was considered and dropped\n" + CURRENT_FREE,
])
def test_current_step_rules_pass(rule):
    assert screen_temporal_rule(rule) is None


def test_a_stream_the_scanner_cannot_resolve_fails_closed():
    assert screen_temporal_rule("always ( o13[t]:bv[24] = i1:bv[24] ).") is not None


def test_the_clause_screen_carries_the_same_check():
    body = "o5[t]:bv[24] = i1[t-1]:bv[24]"
    assert is_temporal_reference_error(_screen_clause_domains(body))
    assert _screen_clause_domains("o5[t]:bv[24] = i1[t]:bv[24]") is None


# --- admission ----------------------------------------------------------------

@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {ALICE}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = False
    view.get_offer_lifecycle_state.return_value = None
    view.get_offer.return_value = None
    view.pending_offers_for_recipient.return_value = 0
    view.pending_offers_for_offerer.return_value = 0
    view.clause_for.return_value = None
    view.clause_author_count.return_value = 0
    view.clauses_for_stream.return_value = {}
    return view


def _user_tx(rule, sender=ALICE):
    return {"tx_type": "user_tx", "expire_at_height": 500, "sender_pubkey": sender,
            "operations": {"0": rule}}


def _offer(text):
    return RuleOffer(offerer_pubkey=MALLORY, recipient_pubkey=ALICE,
                     rule_text=text, expire_at_height=500)


def _offer_payload(text):
    return {"tx_type": "rule_offer", "expire_at_height": 500, "sender_pubkey": MALLORY,
            "recipient_pubkey": ALICE, "rule_text": text}


def _accept_payload(text):
    return {"tx_type": "rule_offer_accept", "expire_at_height": 5000,
            "sender_pubkey": ALICE, "offer_id": _offer(text).offer_id_hex,
            "rule_text": text}


def _open_offer_row(text):
    return {"offer_id": _offer(text).offer_id_hex, "offerer_pubkey": MALLORY,
            "recipient_pubkey": ALICE, "rule_text": text, "expire_at_height": 500,
            "status": STATUS_OFFERED}


def _admit(kind, text, tip_view):
    if kind == "op0":
        return validate_mempool_admission(_user_tx(text), tip_view)
    if kind == "op0_routed":
        tip_view.approval_slots_active = True
        return validate_mempool_admission(_user_tx(text), tip_view)
    if kind == "offer":
        return validate_mempool_admission(_offer_payload(text), tip_view)
    tip_view.get_offer.return_value = _open_offer_row(text)
    return validate_mempool_admission(_accept_payload(text), tip_view)


# op0 takes any stream; the other kinds write o5, the only offerable stream.
def _text_for(kind, ref):
    return _free(ref) if kind == "op0" else _policy(ref)


KINDS = ["op0", "op0_routed", "offer", "accept"]


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("ref", TEMPORAL_REFS)
def test_admission_refuses_a_rule_reading_another_step(tip_view, kind, ref):
    result = _admit(kind, _text_for(kind, ref), tip_view)
    assert result.is_valid is False
    assert result.code == TEMPORAL_REFERENCE_CODE, result.error
    assert "[t]" in result.error


@pytest.mark.parametrize("kind", KINDS)
def test_admission_keeps_current_step_rules(tip_view, kind):
    result = _admit(kind, _text_for(kind, "i1[t]"), tip_view)
    assert result.is_valid is True, (result.code, result.error)


def test_admission_refuses_a_sender_guarded_history_policy(tip_view):
    rule = (
        f"always ((i12[t]:bv[384] = {{ #x{ALICE} }}:bv[384]) ? "
        f"(o5[t]:bv[24] = i1[t-1]:bv[24]) : (o5[t]:bv[24] = {{ #x000001 }}:bv[24]))."
    )
    result = validate_mempool_admission(_user_tx(rule), tip_view)
    assert result.is_valid is False
    assert result.code == TEMPORAL_REFERENCE_CODE


def test_admission_refuses_a_history_rule_on_a_fee_stream(tip_view):
    rule = (
        f"always ((i12[t]:bv[384] = {{ #x{ALICE} }}:bv[384]) ? "
        f"(o8[t]:bv[24] = i1[t-1]:bv[24]) : (o8[t]:bv[24] = {{ #x000000 }}:bv[24]))."
    )
    result = validate_mempool_admission(_user_tx(rule), tip_view)
    assert result.is_valid is False
    assert result.code == TEMPORAL_REFERENCE_CODE


# --- apply --------------------------------------------------------------------

def _sign(tx, sk):
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def _base(tx_id, tx_type, sender, seq):
    return {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
    }


def _rule_tx(text):
    tx = _base("rule", "user_tx", ALICE, 0)
    tx["operations"] = {"0": text}
    return _sign(tx, SK_ALICE)


def _offer_tx(text):
    offer = _offer(text)
    tx = _base("offer", "rule_offer", MALLORY, 0)
    tx.update(recipient_pubkey=ALICE, rule_text=text,
              expire_at_height=offer.expire_at_height)
    return _sign(tx, SK_MALLORY)


def _accept_tx(text):
    tx = _base("accept", "rule_offer_accept", ALICE, 0)
    tx.update(offer_id=_offer(text).offer_id_hex, rule_text=text)
    return _sign(tx, SK_ALICE)


def _lifecycle(*, slots, open_offer=None):
    lm = ConsensusLifecycleManager(active_validators=[MALLORY])
    if slots:
        lm.activate_approval_slots()
    if open_offer is not None:
        assert lm.rule_offers.submit_offer(_offer(open_offer))
    return lm


def _apply(tx, lm, *, replay_mode=False):
    """Apply one transaction; returns (result, post lifecycle, rule texts the evaluator saw)."""
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: 100000, MALLORY: 100000},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={
            "poa": True, "approval_slots_active": lm.approval_slots_active is True},
    )
    block = Block.create(block_number=HEIGHT, previous_hash="00" * 32, transactions=[tx],
                         proposer_pubkey=MALLORY, timestamp=1234567890)
    fed = []
    persisted = []

    def _single(**kw):
        text = str(kw.get("rule_text") or "")
        if text:
            fed.append(text)
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def _multi(**kw):
        return {1: "0", 5: "1", 8: "0", 9: "0"}

    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = TauConsensusEngine().apply_block(
            view, block, parent, replay_mode=replay_mode)
    return result, result.next_snapshot.metadata["lifecycle_manager"], fed


def _outcome(result, tx_id):
    return next(o for o in result.outcomes if o.tx_id == tx_id)


def _never_fed(fed, ref, stream):
    return not any(ref.replace("OUT", stream) in text for text in fed)


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize("ref", TEMPORAL_REFS)
def test_apply_hard_rejects_an_op0_rule_reading_another_step(ref, slots, replay_mode):
    result, _, fed = _apply(_rule_tx(_free(ref)), _lifecycle(slots=slots),
                            replay_mode=replay_mode)
    assert "rule" in result.invalid_tx_ids
    assert result.accepted_tx_ids == []
    outcome = _outcome(result, "rule")
    assert outcome.reason == REASON
    assert "[t]" in " | ".join(str(x) for x in outcome.receipt_logs)
    assert _never_fed(fed, ref, FREE_STREAM)


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("ref", TEMPORAL_REFS)
def test_apply_hard_rejects_a_routed_o5_clause_reading_another_step(ref, replay_mode):
    lm = _lifecycle(slots=True)
    result, post, fed = _apply(_rule_tx(_policy(ref)), lm, replay_mode=replay_mode)
    assert "rule" in result.invalid_tx_ids
    assert _outcome(result, "rule").reason == REASON
    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert _never_fed(fed, ref, POLICY_STREAM)


@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize("ref", TEMPORAL_REFS)
def test_apply_hard_rejects_an_offer_reading_another_step(ref, slots):
    text = _policy(ref)
    result, post, fed = _apply(_offer_tx(text), _lifecycle(slots=slots))
    assert "offer" in result.invalid_tx_ids
    assert _outcome(result, "offer").reason == REASON
    assert post.rule_offers.get_offer(_offer(text).offer_id) is None
    assert _never_fed(fed, ref, POLICY_STREAM)


@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize("ref", TEMPORAL_REFS)
def test_apply_hard_rejects_an_accept_reading_another_step(ref, slots):
    text = _policy(ref)
    lm = _lifecycle(slots=slots, open_offer=text)
    result, post, fed = _apply(_accept_tx(text), lm)
    assert "accept" in result.invalid_tx_ids
    assert _outcome(result, "accept").reason == REASON
    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert post.rule_offers.get_offer(_offer(text).offer_id) is not None
    assert _never_fed(fed, ref, POLICY_STREAM)


# --- governance updates -------------------------------------------------------

def _update_tx(revision):
    tx = _base("update", "consensus_rule_update", MALLORY, 0)
    tx.update(rule_revisions=[revision], activate_at_height=HEIGHT + 10)
    return _sign(tx, SK_MALLORY)


def _consensus_rule(ref):
    return f"always ( o6[t]:bv[16] = {ref}:bv[16] )."


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("ref", ["i10[t-1]", "i10[t - 1]", "i10[0]", "o6[t-1]"])
def test_apply_does_not_record_a_consensus_update_reading_another_step(ref, replay_mode):
    lm = _lifecycle(slots=False)
    result, post, _ = _apply(_update_tx(_consensus_rule(ref)), lm, replay_mode=replay_mode)
    assert "update" not in result.invalid_tx_ids
    logs = " | ".join(str(x) for x in _outcome(result, "update").receipt_logs)
    assert "reads a previous step" in logs
    assert post.pending_updates == set()
    assert post.update_payloads == {}


@pytest.mark.parametrize("replay_mode", [False, True])
def test_apply_records_a_current_step_consensus_update(replay_mode):
    lm = _lifecycle(slots=False)
    result, post, _ = _apply(_update_tx(_consensus_rule("i10[t]")), lm,
                             replay_mode=replay_mode)
    assert "update" not in result.invalid_tx_ids
    assert len(post.pending_updates) == 1


# --- current-step rules still apply -------------------------------------------

def test_apply_keeps_a_current_step_op0_rule():
    result, _, fed = _apply(_rule_tx(CURRENT_FREE), _lifecycle(slots=False))
    assert result.accepted_tx_ids == ["rule"]
    assert fed


def test_apply_keeps_a_current_step_routed_clause():
    result, post, _ = _apply(_rule_tx(CURRENT_POLICY), _lifecycle(slots=True))
    assert result.accepted_tx_ids == ["rule"]
    assert post.rule_offers.clause_for(ALICE, 5) is not None


def test_apply_keeps_a_current_step_offer():
    result, post, _ = _apply(_offer_tx(CURRENT_POLICY), _lifecycle(slots=True))
    assert result.accepted_tx_ids == ["offer"]
    assert post.rule_offers.get_offer(_offer(CURRENT_POLICY).offer_id) is not None


def test_apply_keeps_a_current_step_accept():
    lm = _lifecycle(slots=True, open_offer=CURRENT_POLICY)
    result, post, _ = _apply(_accept_tx(CURRENT_POLICY), lm)
    assert result.accepted_tx_ids == ["accept"]
    assert post.rule_offers.clause_for(ALICE, 5) is not None


# --- admission and apply agree ------------------------------------------------

_APPLY_TX = {"op0": _rule_tx, "op0_routed": _rule_tx, "offer": _offer_tx, "accept": _accept_tx}


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("ref", TEMPORAL_REFS + ["i1[t]"])
def test_admission_and_apply_reach_the_same_verdict(tip_view, kind, ref):
    text = _text_for(kind, ref)
    admitted = _admit(kind, text, tip_view)

    lm = _lifecycle(slots=kind != "op0", open_offer=text if kind == "accept" else None)
    result, _, _ = _apply(_APPLY_TX[kind](text), lm)
    tx_id = {"op0": "rule", "op0_routed": "rule", "offer": "offer", "accept": "accept"}[kind]
    refused_at_apply = tx_id in result.invalid_tx_ids
    refused_with_reason = refused_at_apply and _outcome(result, tx_id).reason == REASON

    assert (not admitted.is_valid) == refused_at_apply
    assert (admitted.code == TEMPORAL_REFERENCE_CODE) == refused_with_reason
