"""A proposer can include offers and accepts that never passed admission, so apply
repeats the admission screens on the clause body: a refused body is neither
recorded nor registered.
"""
import pytest
from unittest.mock import MagicMock, patch

from block import Block
from consensus.admission import (
    TEMPORAL_REFERENCE_CODE,
    TipAdmissionView,
    _screen_clause_domains,
    _width_mismatch_details,
    validate_mempool_admission,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import STATUS_OFFERED, RuleOffer
from consensus.state import TauStateSnapshot
from bls_keys import FAR_FUTURE, SK_ALICE, SK_MALLORY, pubkey_hex, sign_tx

HEIGHT = 20
WIDTH_MISMATCH = "width_mismatch"
NOT_APPLIED = "rule_not_applied"
TEMPORAL = "temporal_reference"


ALICE = pubkey_hex(SK_ALICE)      # recipient and acceptor
MALLORY = pubkey_hex(SK_MALLORY)  # offerer and block proposer

_ON = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
_OFF = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def _cond(condition):
    return f"always ( ({condition}) ? {_ON} : {_OFF} )."


# Each body is a well-formed o5 clause that admission refuses on one domain screen.
BAD_BODIES = {
    "i13": _cond("i13[t]:bv[24] = { #x000001 }:bv[24]"),
    "i14": _cond("i14[t]:bv[24] = { #x000001 }:bv[24]"),
    "i15": _cond("i15[t]:bv[24] = { #x000001 }:bv[24]"),
    "slot_bv24": _cond("i18[t]:bv[24] = { #x000001 }:bv[24]"),
    "slot_untyped": _cond("i18[t] = { #x000001 }:bv[24]"),
    "o5_bv16": "always ( o5[t]:bv[16] = { #x0001 }:bv[16] ).",
    "o5_bare_int": "always ( o5[t]:bv[24] = 1 ).",
}

# Only the o5/o8 width errors carry a WIDTH_MISMATCH payload; the other screens
# are plain rejections at admission and "rule_not_applied" at apply.
EXPECTED_REASON = {
    "i13": NOT_APPLIED,
    "i14": NOT_APPLIED,
    "i15": NOT_APPLIED,
    "slot_bv24": NOT_APPLIED,
    "slot_untyped": NOT_APPLIED,
    "o5_bv16": WIDTH_MISMATCH,
    "o5_bare_int": WIDTH_MISMATCH,
}

TEMPORAL_BODY = "always ( o5[t]:bv[24] = i1[t-1]:bv[24] )."
CONTROL_I1 = _cond("i1[t]:bv[24] > { #x000064 }:bv[24]")
CONTROL_I2 = _cond("i2[t]:bv[24] > { #x000064 }:bv[24]")
CONTROL_SLOT = _cond("i18[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]")


@pytest.mark.parametrize("name", BAD_BODIES)
def test_the_expected_reason_follows_the_admission_screen(name):
    error = _screen_clause_domains(BAD_BODIES[name])
    assert error is not None
    assert bool(_width_mismatch_details(error)) == (EXPECTED_REASON[name] == WIDTH_MISMATCH)


@pytest.mark.parametrize("body", [CONTROL_I1, CONTROL_I2, CONTROL_SLOT])
def test_the_controls_pass_the_screen(body):
    assert _screen_clause_domains(body) is None


# --- harness ------------------------------------------------------------------

@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {ALICE}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = True
    view.get_offer_lifecycle_state.return_value = None
    view.get_offer.return_value = None
    view.pending_offers_for_recipient.return_value = 0
    view.pending_offers_for_offerer.return_value = 0
    view.clause_for.return_value = None
    view.clauses_for_stream.return_value = {}
    return view


def _user_tx(rule):
    return {"tx_type": "user_tx", "expire_at_height": 500, "sender_pubkey": ALICE,
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


def _admit(door, text, tip_view):
    if door == "routed":
        return validate_mempool_admission(_user_tx(text), tip_view)
    if door == "offer":
        return validate_mempool_admission(_offer_payload(text), tip_view)
    tip_view.get_offer.return_value = _open_offer_row(text)
    return validate_mempool_admission(_accept_payload(text), tip_view)


def _base(tx_id, tx_type, sender, seq):
    return {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": 5000,
        "fee_limit": "100",
    }


def _rule_tx(text):
    tx = _base("rule", "user_tx", ALICE, 0)
    tx["operations"] = {"0": text}
    return sign_tx(tx, SK_ALICE)


def _offer_tx(text):
    offer = _offer(text)
    tx = _base("offer", "rule_offer", MALLORY, 0)
    tx.update(recipient_pubkey=ALICE, rule_text=text,
              expire_at_height=offer.expire_at_height)
    return sign_tx(tx, SK_MALLORY)


def _accept_tx(text):
    tx = _base("accept", "rule_offer_accept", ALICE, 0)
    tx.update(offer_id=_offer(text).offer_id_hex, rule_text=text)
    return sign_tx(tx, SK_ALICE)


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


def _fed_a_sender_guard(fed):
    return any("i12[t]:bv[384]" in text for text in fed)


# --- apply refuses what admission refuses -------------------------------------

@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize("name", BAD_BODIES)
def test_apply_hard_rejects_an_offer_the_domain_screens_refuse(name, slots):
    text = BAD_BODIES[name]
    result, post, fed = _apply(_offer_tx(text), _lifecycle(slots=slots))
    assert "offer" in result.invalid_tx_ids
    assert result.accepted_tx_ids == []
    assert _outcome(result, "offer").reason == EXPECTED_REASON[name]
    assert post.rule_offers.get_offer(_offer(text).offer_id) is None
    assert not _fed_a_sender_guard(fed)


@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize("name", BAD_BODIES)
def test_apply_hard_rejects_an_accept_the_domain_screens_refuse(name, slots):
    text = BAD_BODIES[name]
    result, post, fed = _apply(_accept_tx(text), _lifecycle(slots=slots, open_offer=text))
    assert "accept" in result.invalid_tx_ids
    assert result.accepted_tx_ids == []
    assert _outcome(result, "accept").reason == EXPECTED_REASON[name]
    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert post.rule_offers.get_offer(_offer(text).offer_id) is not None
    assert not _fed_a_sender_guard(fed)


@pytest.mark.parametrize("kind", ["offer", "accept"])
@pytest.mark.parametrize("name", ["i13", "o5_bv16"])
def test_apply_screens_in_replay_mode_too(kind, name):
    text = BAD_BODIES[name]
    if kind == "offer":
        result, _, _ = _apply(_offer_tx(text), _lifecycle(slots=True), replay_mode=True)
    else:
        result, _, _ = _apply(_accept_tx(text), _lifecycle(slots=True, open_offer=text),
                              replay_mode=True)
    assert kind in result.invalid_tx_ids
    assert _outcome(result, kind).reason == EXPECTED_REASON[name]


# --- admission and apply agree ------------------------------------------------

_APPLY_DOOR = {
    "routed": ("rule", _rule_tx),
    "offer": ("offer", _offer_tx),
    "accept": ("accept", _accept_tx),
}

PARITY_BODIES = {**BAD_BODIES, "temporal": TEMPORAL_BODY, "control_i1": CONTROL_I1,
                 "control_i2": CONTROL_I2}


@pytest.mark.parametrize("door", list(_APPLY_DOOR))
@pytest.mark.parametrize("name", PARITY_BODIES)
def test_admission_and_apply_reach_the_same_verdict(tip_view, door, name):
    text = PARITY_BODIES[name]
    admitted = _admit(door, text, tip_view)

    tx_id, make_tx = _APPLY_DOOR[door]
    lm = _lifecycle(slots=True, open_offer=text if door == "accept" else None)
    result, _, _ = _apply(make_tx(text), lm)
    refused = tx_id in result.invalid_tx_ids
    reason = _outcome(result, tx_id).reason if refused else None

    assert (not admitted.is_valid) == refused
    assert (admitted.code == "WIDTH_MISMATCH") == (reason == WIDTH_MISMATCH)
    assert (admitted.code == TEMPORAL_REFERENCE_CODE) == (reason == TEMPORAL)


# --- clean bodies still land --------------------------------------------------

@pytest.mark.parametrize("body", [CONTROL_I1, CONTROL_I2, CONTROL_SLOT],
                         ids=["i1", "i2", "slot_bv384"])
def test_apply_keeps_a_clean_offer(body):
    result, post, _ = _apply(_offer_tx(body), _lifecycle(slots=True))
    assert result.accepted_tx_ids == ["offer"]
    assert post.rule_offers.get_offer(_offer(body).offer_id) is not None


@pytest.mark.parametrize("body", [CONTROL_I1, CONTROL_I2, CONTROL_SLOT],
                         ids=["i1", "i2", "slot_bv384"])
def test_apply_keeps_a_clean_accept(body):
    result, post, fed = _apply(_accept_tx(body), _lifecycle(slots=True, open_offer=body))
    assert result.accepted_tx_ids == ["accept"]
    assert post.rule_offers.clause_for(ALICE, 5) is not None
    assert not _fed_a_sender_guard(fed)
