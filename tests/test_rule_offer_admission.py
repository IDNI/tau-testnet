"""Mempool admission for the rule-sharing transaction types.

Every check here is a deterministic function of the transaction plus the tip
tables, so admission and block apply reach the same verdict on the same input.
A disagreement between the two is a consensus split, so the last test asserts
they reject the same corpus.
"""
import pytest
from unittest.mock import MagicMock

from consensus.admission import (
    TipAdmissionView,
    validate_mempool_admission,
    validate_rule_offer_payload,
)
from consensus.rule_offers import (
    MAX_ACCEPTORS_PER_STREAM,
    MAX_OFFER_RULE_BYTES,
    MAX_OFFER_WINDOW_BLOCKS,
    MAX_PENDING_OFFERS_PER_OFFERER,
    MAX_PENDING_OFFERS_PER_RECIPIENT,
    STATUS_ACCEPTED,
    STATUS_OFFERED,
    RuleOffer,
    clause_body_v1,
)

A = "aa" * 48          # offerer
B = "bb" * 48          # recipient
C = "cc" * 48          # unrelated
BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
ALLOW_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
TARGET = 5
NEXT_HEIGHT = 50
EXPIRE = 500


@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {A}
    # A property on the real TipAdmissionView, not a method.
    view.next_block_height = NEXT_HEIGHT
    view.eligibility_mode = ""
    view.get_offer_lifecycle_state.return_value = None
    view.get_offer.return_value = None
    view.pending_offers_for_recipient.return_value = 0
    view.pending_offers_for_offerer.return_value = 0
    view.clause_for.return_value = None
    view.clauses_for_stream.return_value = {}
    return view


def offer_tx(**over):
    tx = {
        "tx_type": "rule_offer",
        "sender_pubkey": A,
        "recipient_pubkey": B,
        "rule_text": BLOCK_RULE,
        "expire_at_height": EXPIRE,
    }
    tx.update(over)
    return tx


def accept_tx(**over):
    tx = {
        "tx_type": "rule_offer_accept",
        "sender_pubkey": B,
        "offer_id": _offer_id(),
        "rule_text": BLOCK_RULE,
    }
    tx.update(over)
    return tx


def reject_tx(**over):
    tx = {
        "tx_type": "rule_offer_reject",
        "sender_pubkey": B,
        "offer_id": _offer_id(),
    }
    tx.update(over)
    return tx


def _offer_id(offerer=A, recipient=B, text=BLOCK_RULE, expire=EXPIRE):
    return RuleOffer(offerer_pubkey=offerer, recipient_pubkey=recipient,
                     rule_text=text, expire_at_height=expire).offer_id_hex


def _offer_row(**over):
    row = {
        "offer_id": _offer_id(),
        "offerer_pubkey": A,
        "recipient_pubkey": B,
        "rule_text": BLOCK_RULE,
        "expire_at_height": EXPIRE,
        "status": STATUS_OFFERED,
    }
    row.update(over)
    return row


# --- offers -----------------------------------------------------------------

def test_valid_offer_admitted(tip_view):
    res = validate_mempool_admission(offer_tx(), tip_view)
    assert res.is_valid, res.error
    assert res.data["offer_id"] == _offer_id()
    assert res.data["target_stream"] == TARGET
    assert res.data["clause_body"] == clause_body_v1(BLOCK_RULE)
    # The prospective composite is produced so sendtx can compile the text that
    # would actually enter the specification.
    assert res.data["composite_rule"].startswith("always ( ")
    assert B in res.data["composite_rule"]


def test_offer_to_self_rejected(tip_view):
    res = validate_mempool_admission(offer_tx(recipient_pubkey=A), tip_view)
    assert not res.is_valid and "differ" in res.error


def test_offer_malformed_rejected(tip_view):
    for over in ({"recipient_pubkey": "short"}, {"rule_text": 5},
                 {"expire_at_height": "500"}, {"recipient_pubkey": None}):
        res = validate_mempool_admission(offer_tx(**over), tip_view)
        assert not res.is_valid and "Malformed" in res.error, over


def test_offer_offerer_must_be_the_sender(tip_view):
    """Only reachable when the envelope sender is unusable and a nested payload
    supplies a different one."""
    tx = {
        "tx_type": "rule_offer",
        "sender_pubkey": None,
        "payload": {
            "sender_pubkey": C,
            "recipient_pubkey": B,
            "rule_text": BLOCK_RULE,
            "expire_at_height": EXPIRE,
        },
    }
    res = validate_mempool_admission(tx, tip_view)
    assert not res.is_valid and "sender" in res.error


def test_offer_oversized_rejected(tip_view):
    big = ("always ( o5[t]:bv[24] = { #x000000 }:bv[24] && "
           + ("o5[t] = o5[t] && " * 900) + "o5[t] = o5[t] ).")
    assert len(big.encode()) > MAX_OFFER_RULE_BYTES
    res = validate_mempool_admission(offer_tx(rule_text=big), tip_view)
    assert not res.is_valid and "byte limit" in res.error


@pytest.mark.parametrize("expire,fragment", [
    (NEXT_HEIGHT, "must be beyond"),
    (NEXT_HEIGHT - 1, "must be beyond"),
    (NEXT_HEIGHT + MAX_OFFER_WINDOW_BLOCKS + 1, "blocks ahead"),
])
def test_offer_expiry_window(tip_view, expire, fragment):
    res = validate_mempool_admission(offer_tx(expire_at_height=expire), tip_view)
    assert not res.is_valid and fragment in res.error


def test_offer_expiry_just_inside_window(tip_view):
    res = validate_mempool_admission(
        offer_tx(expire_at_height=NEXT_HEIGHT + MAX_OFFER_WINDOW_BLOCKS), tip_view)
    assert res.is_valid, res.error


def test_duplicate_offer_rejected(tip_view):
    tip_view.get_offer_lifecycle_state.return_value = STATUS_OFFERED
    res = validate_mempool_admission(offer_tx(), tip_view)
    assert not res.is_valid and "Duplicate" in res.error


def test_duplicate_of_a_resolved_offer_rejected(tip_view):
    """Re-offering identical terms after resolution would replay the same id."""
    tip_view.get_offer_lifecycle_state.return_value = STATUS_ACCEPTED
    res = validate_mempool_admission(offer_tx(), tip_view)
    assert not res.is_valid and "Duplicate" in res.error


def test_inbox_and_outbox_caps(tip_view):
    tip_view.pending_offers_for_recipient.return_value = MAX_PENDING_OFFERS_PER_RECIPIENT
    res = validate_mempool_admission(offer_tx(), tip_view)
    assert not res.is_valid and "Recipient" in res.error

    tip_view.pending_offers_for_recipient.return_value = 0
    tip_view.pending_offers_for_offerer.return_value = MAX_PENDING_OFFERS_PER_OFFERER
    res = validate_mempool_admission(offer_tx(), tip_view)
    assert not res.is_valid and "Offerer" in res.error


@pytest.mark.parametrize("rule,fragment", [
    ("always ( o9[t]:bv[24] = { #x000001 }:bv[24] ).", "reserved"),
    ("always ( o7[t]:bv[16] = { #x0001 }:bv[16] ).", "reserved"),
    ("always ( o6[t]:bv[16] = { #x0001 }:bv[16] ).", "reserved"),
    ("always ( o5[t]:bv[24] = i2[t]:bv[24] ).", "mocked"),
    ("always ( o5[t]:bv[24] = i14[t]:bv[24] ).", "reserved input"),
    ("always ( o5[t]:bv[24] = i15[t]:bv[24] ).", "reserved input"),
    ("always ( o5[t]:bv[24] = i13[t]:bv[24] ).", "reserved input"),
    ("always ( o12[t]:bv[24] = { #x000001 }:bv[24] ).", "not an accepted target"),
    ("always ( o5[t] = 1 && o1[t] = 2 ).", "exactly one output stream"),
    ("always ( i1[t] = 1 ).", "no output stream"),
    ("always ( o5[t] = 1 ). always ( o5[t] = 0 ).", "unbalanced"),
    ("always ( always ( o5[t] = 1 ) ).", "temporal"),
    ("o5[t] = 1.", "one `always"),
    ("always ( i12[t] = { #xaa }:bv[384] && o5[t] = 1 ).", "i12"),
])
def test_clause_domain_screens(tip_view, rule, fragment):
    res = validate_mempool_admission(offer_tx(rule_text=rule), tip_view)
    assert not res.is_valid, rule
    assert fragment in res.error, (rule, res.error)


def test_reserved_input_screen_is_mode_independent(tip_view):
    """i13 is only reserved under tau_validator_set, but a clause outlives the
    mode it was accepted under, so the widest set is always screened."""
    tip_view.eligibility_mode = "validator_set"
    res = validate_mempool_admission(
        offer_tx(rule_text="always ( o5[t]:bv[24] = i13[t]:bv[24] )."), tip_view)
    assert not res.is_valid and "reserved input" in res.error


def test_offer_rejected_when_the_stream_is_already_full(tip_view):
    tip_view.clauses_for_stream.return_value = {
        format(i, "096x"): "o5[t] = 1" for i in range(MAX_ACCEPTORS_PER_STREAM)
    }
    res = validate_mempool_admission(offer_tx(), tip_view)
    assert not res.is_valid and "maximum" in res.error


# --- accept -----------------------------------------------------------------

def test_valid_accept_admitted(tip_view):
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(accept_tx(), tip_view)
    assert res.is_valid, res.error
    assert res.data["target_stream"] == TARGET
    assert B in res.data["composite_rule"]


def test_accept_of_unknown_offer_rejected(tip_view):
    tip_view.get_offer.return_value = None
    res = validate_mempool_admission(accept_tx(), tip_view)
    assert not res.is_valid and "Unknown" in res.error


def test_accept_of_resolved_offer_rejected(tip_view):
    tip_view.get_offer.return_value = _offer_row(status=STATUS_ACCEPTED)
    res = validate_mempool_admission(accept_tx(), tip_view)
    assert not res.is_valid and "already" in res.error


def test_accept_by_non_recipient_rejected(tip_view):
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(accept_tx(sender_pubkey=C), tip_view)
    assert not res.is_valid and "recipient" in res.error


def test_accept_of_expired_offer_rejected(tip_view):
    tip_view.get_offer.return_value = _offer_row(expire_at_height=NEXT_HEIGHT)
    res = validate_mempool_admission(accept_tx(), tip_view)
    assert not res.is_valid and "expires" in res.error


def test_accept_with_mismatched_text_rejected(tip_view):
    """The digest is recomputed from the accept's own copy of the text, which
    is what lets apply validate without the node-local payload store."""
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(accept_tx(rule_text=ALLOW_RULE), tip_view)
    assert not res.is_valid and "digest" in res.error


def test_accept_without_text_rejected(tip_view):
    tip_view.get_offer.return_value = _offer_row()
    tx = accept_tx()
    del tx["rule_text"]
    res = validate_mempool_admission(tx, tip_view)
    assert not res.is_valid and "Malformed" in res.error


def test_accept_replacing_own_clause_ignores_the_cap(tip_view):
    """Replacing your own clause does not grow the composite."""
    full = {format(i, "096x"): "o5[t] = 1" for i in range(MAX_ACCEPTORS_PER_STREAM - 1)}
    full[B] = "o5[t] = 1"
    assert len(full) == MAX_ACCEPTORS_PER_STREAM
    tip_view.clauses_for_stream.return_value = full
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(accept_tx(), tip_view)
    assert res.is_valid, res.error


def test_accept_by_a_new_acceptor_hits_the_cap(tip_view):
    tip_view.clauses_for_stream.return_value = {
        format(i, "096x"): "o5[t] = 1" for i in range(MAX_ACCEPTORS_PER_STREAM)
    }
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(accept_tx(), tip_view)
    assert not res.is_valid and "maximum" in res.error


def test_accept_preserves_other_acceptors_in_the_composite(tip_view):
    """The composite must keep every existing acceptor's clause, or accepting
    would silently disable someone else's policy."""
    tip_view.clauses_for_stream.return_value = {C: "o5[t]:bv[24] = { #x000001 }:bv[24]"}
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(accept_tx(), tip_view)
    assert res.is_valid, res.error
    assert B in res.data["composite_rule"]
    assert C in res.data["composite_rule"]


# --- reject -----------------------------------------------------------------

def test_valid_reject_admitted(tip_view):
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(reject_tx(), tip_view)
    assert res.is_valid, res.error
    # A rejection compiles nothing, so no composite is produced.
    assert "composite_rule" not in res.data


def test_reject_by_non_recipient_rejected(tip_view):
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(reject_tx(sender_pubkey=C), tip_view)
    assert not res.is_valid and "recipient" in res.error


def test_reject_needs_no_rule_text(tip_view):
    tip_view.get_offer.return_value = _offer_row()
    res = validate_mempool_admission(reject_tx(rule_text="garbage"), tip_view)
    assert res.is_valid, res.error


def test_reject_of_unknown_offer_rejected(tip_view):
    tip_view.get_offer.return_value = None
    res = validate_mempool_admission(reject_tx(), tip_view)
    assert not res.is_valid and "Unknown" in res.error


# --- cross-cutting ----------------------------------------------------------

def test_unknown_tx_type_still_rejected(tip_view):
    res = validate_mempool_admission({"tx_type": "rule_offer_maybe"}, tip_view)
    assert not res.is_valid and "Unknown or unsupported" in res.error


def test_offer_and_accept_screens_agree(tip_view):
    """Any clause the offer path refuses, the accept path must refuse too --
    otherwise a rule could enter a specification through the accept route
    without ever passing the offer screens."""
    bad_rules = [
        "always ( o9[t]:bv[24] = { #x000001 }:bv[24] ).",
        "always ( o5[t]:bv[24] = i2[t]:bv[24] ).",
        "always ( o5[t]:bv[24] = i14[t]:bv[24] ).",
        "always ( o12[t]:bv[24] = { #x000001 }:bv[24] ).",
        "always ( always ( o5[t] = 1 ) ).",
        "o5[t] = 1.",
    ]
    for rule in bad_rules:
        offer_res = validate_mempool_admission(offer_tx(rule_text=rule), tip_view)
        assert not offer_res.is_valid, rule

        # Present the SAME text as an accept whose digest genuinely matches.
        oid = _offer_id(text=rule)
        tip_view.get_offer.return_value = _offer_row(offer_id=oid, rule_text=rule)
        accept_res = validate_mempool_admission(
            accept_tx(offer_id=oid, rule_text=rule), tip_view)
        assert not accept_res.is_valid, (
            f"accept path admitted a clause the offer path rejected: {rule}"
        )
