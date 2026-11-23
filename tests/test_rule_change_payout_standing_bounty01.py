"""Bounty 01, FIX 5B: rule-change kinds 7..12 for the payment books.

The gap (differential audit vs #178 @ 47a110e, sub-point ST-3): in FIX 5
the rule-change guard judged only o5 policy changes. A guarded account's
payout rule and standing authorizations could be installed, replaced,
removed and cancelled by the owner key alone — the co-signers the guard
names were never consulted — while #178 judges payout changes as kinds
6/7/8 with a request-and-approvals path.

Kinds 7..12 close that gap in our numbering: 7 set payout, 8 update
payout, 9 revoke payout, 10 set standing, 11 update standing, 12 cancel
standing (the authorization is named in offer_id). The direct
transactions are guard-consulted in admission and at apply; the request
path parks under a blocking guard and releases on a co-signer vote or
the time escape, applying the books' own can_* checks at the tip.

Covered: the guard blocks each direct operation; granularity (a guard
blocking only kind 8 blocks the update, not the install); the request
lifecycle for payout (set, update by vote, update by escape, revoke)
and standing (set, update, cancel); the admission preconditions (kind 7
refused when a rule exists, kind 8 when none, kind 10/11 the same for a
series, kind 12 naming another payer's authorization); canonical
payload spelling; an unguarded account's direct operations unchanged.
"""
import itertools

import pytest

import tau_defs
from bls_keys import FAR_FUTURE, SK_ALICE, SK_BOB, sign_tx
from consensus import sender_policy
from consensus.admission import (
    validate_cancel_standing_payment_payload,
    validate_create_standing_payment_payload,
    validate_install_payout_rule_payload,
    validate_mempool_admission,
    validate_remove_payout_rule_payload,
)
from consensus.approvals import (
    STATUS_EXECUTED,
    STATUS_OPEN,
    parse_rule_change_request_checked,
    payout_payload_text,
    standing_payload_text,
)
from consensus.facade import TipAdmissionView
from consensus.payout_rules import parse_install_payout_rule
from consensus.policy_mock import MockPolicyEvaluator
from consensus.standing_payments import parse_create_standing_payment

from test_rule_change_release import Chain
from test_rule_change_requests import (
    ALICE,
    BOB,
    GUARD_BODY,
    GUARD_KEY,
    HEIGHT,
    _lm,
    _request,
    _tx,
    _view as _rc_view,
)

KIND_SET_PAYOUT = tau_defs.RULE_CHANGE_KIND_SET_PAYOUT
KIND_UPDATE_PAYOUT = tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT
KIND_REVOKE_PAYOUT = tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT
KIND_SET_STANDING = tau_defs.RULE_CHANGE_KIND_SET_STANDING
KIND_UPDATE_STANDING = tau_defs.RULE_CHANGE_KIND_UPDATE_STANDING
KIND_CANCEL_STANDING = tau_defs.RULE_CHANGE_KIND_CANCEL_STANDING
D = tau_defs.RULE_CHANGE_DELAY_BLOCKS
TS = 1234567890  # the block timestamp _apply stamps
ANCHOR = TS - 100

_IDS = itertools.count()


@pytest.fixture(autouse=True)
def evaluators():
    """The seeded guard allows a change only once slot i18 holds a pubkey."""
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _vote(request_id, *, seq, sk=SK_BOB, voter=BOB):
    rid = request_id.hex() if isinstance(request_id, bytes) else request_id
    return sign_tx({
        "tx_id": f"vote5b-{next(_IDS)}", "tx_type": "transfer_vote",
        "sender_pubkey": voter, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "0", "request_id": rid, "approve": True,
    }, sk)


def _guarded_chain():
    return Chain(_lm(guard=True))


class _LmView(TipAdmissionView):
    """The real facade view bound to one test lifecycle manager."""

    def __init__(self, lm):
        self._lm = lm

    @property
    def next_block_timestamp(self):
        return TS

    def _tip_payout_book(self):
        return self._lm.payout_rules

    def _tip_standing_book(self):
        return self._lm.standing_payments

    def clause_for(self, who, idx):
        return self._lm.rule_offers.accepted_clauses.get((who, idx))


def _admit_request(tx, lm):
    """Mempool admission for a rule-change request: the rule-change mock
    view, with the payment-book lookups patched to the real facade rows."""
    view = _rc_view(lm)
    facade = _LmView(lm)
    view.get_payout_rule_for_owner.side_effect = facade.get_payout_rule_for_owner
    view.get_standing_payment_for_series.side_effect = (
        facade.get_standing_payment_for_series)
    view.get_standing_payment.side_effect = facade.get_standing_payment
    view.next_block_timestamp = TS
    return validate_mempool_admission(tx, view)


def _payout_fields(**over):
    fields = {
        "sender_pubkey": ALICE,
        "payout_recipients": [BOB],
        "payout_legs": [[BOB, 2, 500]],
        "payout_max_per_execution": 0,
        "payout_max_per_period": 0,
        "payout_period_seconds": 604800,
        "payout_period_anchor_ts": ANCHOR,
        "payout_version": 1,
    }
    fields.update(over)
    return fields


def _payout_entry(**over):
    return parse_install_payout_rule(_payout_fields(**over))


def _install_tx(seq, **over):
    fields = _payout_fields(**over)
    fields.pop("sender_pubkey")
    return sign_tx({
        "tx_id": f"payout5b-{next(_IDS)}", "tx_type": "install_payout_rule",
        "sender_pubkey": ALICE, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100", **fields,
    }, SK_ALICE)


def _remove_tx(seq):
    return sign_tx({
        "tx_id": f"payout5b-rm-{next(_IDS)}", "tx_type": "remove_payout_rule",
        "sender_pubkey": ALICE, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100",
    }, SK_ALICE)


def _standing_fields(**over):
    fields = {
        "sender_pubkey": ALICE,
        "standing_recipient_pubkey": BOB,
        "standing_amount": 500,
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": ANCHOR,
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": 100000,
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
    }
    fields.update(over)
    return fields


def _standing_entry(**over):
    return parse_create_standing_payment(_standing_fields(**over))


def _create_tx(seq, **over):
    fields = _standing_fields(**over)
    fields.pop("sender_pubkey")
    return sign_tx({
        "tx_id": f"standing5b-{next(_IDS)}", "tx_type": "create_standing_payment",
        "sender_pubkey": ALICE, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100", **fields,
    }, SK_ALICE)


def _cancel_tx(seq, auth_id):
    return sign_tx({
        "tx_id": f"standing5b-cx-{next(_IDS)}",
        "tx_type": "cancel_standing_payment",
        "sender_pubkey": ALICE, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100", "standing_auth_id": auth_id.hex(),
    }, SK_ALICE)


def _payout_book(chain):
    return chain.lm.payout_rules


def _standing_book(chain):
    return chain.lm.standing_payments


def _install_v1_via_request(chain, *, seq=0):
    """A guarded account's first rule, through kind 7 + a co-signer vote."""
    req = _request(KIND_SET_PAYOUT, text=payout_payload_text(_payout_entry()),
                   seq=seq, expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=0))
    assert chain.entry(req).status == STATUS_EXECUTED
    return req


# --- the guard judges the direct transactions ------------------------------------


def test_guard_blocks_a_direct_payout_install():
    chain = _guarded_chain()
    tx = _install_tx(0)
    result = validate_install_payout_rule_payload(tx, _LmView(chain.lm))
    assert not result.is_valid
    assert "guard requires approval" in (result.error or "")
    applied = chain.block(tx)
    assert tx["tx_id"] not in applied.accepted_tx_ids
    assert _payout_book(chain).get(ALICE) is None


def test_guard_blocks_a_direct_standing_create():
    chain = _guarded_chain()
    tx = _create_tx(0)
    result = validate_create_standing_payment_payload(tx, _LmView(chain.lm))
    assert not result.is_valid
    assert "guard requires approval" in (result.error or "")
    applied = chain.block(tx)
    assert tx["tx_id"] not in applied.accepted_tx_ids
    assert _standing_book(chain).authorization_count() == 0


def test_guard_blocks_direct_update_remove_and_cancel():
    chain = _guarded_chain()
    _install_v1_via_request(chain, seq=0)
    # seq: the request took ALICE seq 0; BOB's vote took his seq 0.
    update = _install_tx(1, payout_version=2, payout_legs=[[BOB, 2, 900]])
    applied = chain.block(update)
    assert update["tx_id"] not in applied.accepted_tx_ids
    assert _payout_book(chain).get(ALICE).version == 1

    remove = _remove_tx(2)
    applied = chain.block(remove)
    assert remove["tx_id"] not in applied.accepted_tx_ids
    assert _payout_book(chain).get(ALICE) is not None


def test_guard_blocks_direct_standing_update_and_cancel():
    chain = _guarded_chain()
    _standing_v1_via_request(chain, seq=0)
    v1 = _standing_book(chain).get_for_series(_standing_entry().series_key)
    # seq: the kind 10 request took ALICE seq 0; BOB's vote took his seq 0.
    update = _create_tx(1, standing_version=2, standing_amount=750)
    result = validate_create_standing_payment_payload(update, _LmView(chain.lm))
    assert not result.is_valid
    assert "guard requires approval" in (result.error or "")
    applied = chain.block(update)
    assert update["tx_id"] not in applied.accepted_tx_ids
    current = _standing_book(chain).get_for_series(_standing_entry().series_key)
    assert current.version == 1 and current.amount == 500

    cancel = _cancel_tx(2, v1.auth_id)
    result = validate_cancel_standing_payment_payload(cancel, _LmView(chain.lm))
    assert not result.is_valid
    assert "guard requires approval" in (result.error or "")
    applied = chain.block(cancel)
    assert cancel["tx_id"] not in applied.accepted_tx_ids
    ok, _ = _standing_book(chain).can_cancel(v1.auth_id, TS)
    assert ok


def test_granularity_a_guard_blocking_only_kind_8(evaluators):
    for pool in ("apply", "admission"):
        evaluators[pool].set_verdict(
            GUARD_BODY,
            lambda inputs: "0" if inputs.get("i1") == str(KIND_UPDATE_PAYOUT) else "1")
    chain = _guarded_chain()
    install = _install_tx(0)
    applied = chain.block(install)
    assert install["tx_id"] in applied.accepted_tx_ids
    assert _payout_book(chain).get(ALICE).version == 1
    update = _install_tx(1, payout_version=2)
    applied = chain.block(update)
    assert update["tx_id"] not in applied.accepted_tx_ids
    assert _payout_book(chain).get(ALICE).version == 1


# --- the payout request lifecycle ---------------------------------------------------


def test_kind8_request_updates_the_rule_by_vote_and_the_guard_survives():
    chain = _guarded_chain()
    _install_v1_via_request(chain, seq=0)
    req = _request(
        KIND_UPDATE_PAYOUT,
        text=payout_payload_text(_payout_entry(
            payout_version=2, payout_legs=[[BOB, 2, 900]])),
        seq=1, expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=1))
    assert chain.entry(req).status == STATUS_EXECUTED
    rule = _payout_book(chain).get(ALICE)
    assert rule.version == 2
    assert rule.legs[0].value == 900
    # The guard itself was never touched by the payout change.
    assert chain.lm.rule_offers.accepted_clauses.get(GUARD_KEY) is not None


def test_kind8_request_releases_on_the_time_escape():
    chain = _guarded_chain()
    _install_v1_via_request(chain, seq=0)
    req = _request(
        KIND_UPDATE_PAYOUT,
        text=payout_payload_text(_payout_entry(payout_version=2)), seq=1,
        expire=3000)
    created = chain.height
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(height=created + D - 1)
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(height=created + D)
    assert chain.entry(req).status == STATUS_EXECUTED
    assert _payout_book(chain).get(ALICE).version == 2


def test_kind9_request_revokes_the_rule_by_vote():
    chain = _guarded_chain()
    _install_v1_via_request(chain, seq=0)
    req = _request(KIND_REVOKE_PAYOUT, seq=1, expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=1))
    assert chain.entry(req).status == STATUS_EXECUTED
    assert _payout_book(chain).get(ALICE) is None


def test_kind7_and_kind8_admission_preconditions():
    lm = _lm(guard=True)
    text_v1 = payout_payload_text(_payout_entry())
    refused = _admit_request(_tx(_request(KIND_UPDATE_PAYOUT, text=text_v1)), lm)
    assert not refused.is_valid
    assert "no payout rule to update" in (refused.error or "")
    assert _admit_request(
        _tx(_request(KIND_SET_PAYOUT, text=text_v1)), lm).is_valid

    chain = _guarded_chain()
    _install_v1_via_request(chain, seq=0)
    refused = _admit_request(
        _tx(_request(KIND_SET_PAYOUT, text=text_v1, seq=1)), chain.lm)
    assert not refused.is_valid
    assert "already exists" in (refused.error or "")


# --- the standing request lifecycle ---------------------------------------------------


def _standing_v1_via_request(chain, *, seq=0):
    req = _request(KIND_SET_STANDING,
                   text=standing_payload_text(_standing_entry()), seq=seq,
                   expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=0))
    assert chain.entry(req).status == STATUS_EXECUTED
    return req


def test_kind11_request_updates_standing_and_supersedes_the_old_version():
    chain = _guarded_chain()
    _standing_v1_via_request(chain, seq=0)
    v1 = _standing_book(chain).get_for_series(_standing_entry().series_key)
    assert v1 is not None and v1.version == 1

    req = _request(
        KIND_UPDATE_STANDING,
        text=standing_payload_text(_standing_entry(
            standing_version=2, standing_amount=750)),
        seq=1, expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=1))
    assert chain.entry(req).status == STATUS_EXECUTED
    book = _standing_book(chain)
    current = book.get_for_series(_standing_entry().series_key)
    assert current.version == 2 and current.amount == 750
    # Supersession is wholesale, exactly as a direct create: version 1's
    # entry leaves the book (its paid-for-period facts are a separate
    # record and are not rewritten).
    assert book.get(v1.auth_id) is None


def test_kind12_request_cancels_the_authorization_by_vote():
    chain = _guarded_chain()
    _standing_v1_via_request(chain, seq=0)
    v1 = _standing_book(chain).get_for_series(_standing_entry().series_key)
    req = _request(KIND_CANCEL_STANDING, offer_id=v1.auth_id.hex(), seq=1,
                   expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=1))
    assert chain.entry(req).status == STATUS_EXECUTED
    # Cancellation is a flag on the entry, not a removal: the book now
    # refuses a second cancel and every later execution.
    ok, reason = _standing_book(chain).can_cancel(v1.auth_id, TS)
    assert not ok and reason == "authorization is already cancelled"


def test_kind10_and_kind11_admission_preconditions():
    lm = _lm(guard=True)
    text_v1 = standing_payload_text(_standing_entry())
    refused = _admit_request(
        _tx(_request(KIND_UPDATE_STANDING, text=text_v1)), lm)
    assert not refused.is_valid
    assert "no standing authorization to update" in (refused.error or "")
    assert _admit_request(
        _tx(_request(KIND_SET_STANDING, text=text_v1)), lm).is_valid


def test_kind12_refuses_an_authorization_of_another_payer():
    chain = _guarded_chain()
    _standing_v1_via_request(chain, seq=0)
    v1 = _standing_book(chain).get_for_series(_standing_entry().series_key)
    # BOB asks to cancel ALICE's authorization: not his to cancel.
    req = _request(KIND_CANCEL_STANDING, offer_id=v1.auth_id.hex(),
                   sender=BOB, approvers={18: ALICE})
    result = _admit_request(_tx(req, sk=SK_BOB), chain.lm)
    assert not result.is_valid
    assert "only the payer may cancel" in (result.error or "")


# --- payload spelling -----------------------------------------------------------------


def test_payload_requests_parse_and_noncanonical_spelling_is_refused():
    text = payout_payload_text(_payout_entry())
    req, why = parse_rule_change_request_checked(
        _tx(_request(KIND_SET_PAYOUT, text=text)))
    assert req is not None and why == ""
    assert req.body == text
    spaced = text.replace(":", ": ", 1)
    req, why = parse_rule_change_request_checked(
        _tx(_request(KIND_SET_PAYOUT, text=spaced)))
    assert req is None and "canonical" in why
    req, why = parse_rule_change_request_checked(
        _tx(_request(KIND_SET_PAYOUT, text="not json")))
    assert req is None and "not a valid payload" in why


# --- the CLI builds the new kinds ---------------------------------------------------


def test_the_cli_builds_payment_kind_requests():
    from tau_testnet_cli.tx import build_rule_change_request_tx

    base = dict(sender_pubkey=ALICE, sequence_number=0,
                expiration_time=9999999999, expire_at_height=5000)
    text = payout_payload_text(_payout_entry())
    tx = build_rule_change_request_tx(kind=KIND_SET_PAYOUT, rule_text=text, **base)
    assert tx["kind"] == KIND_SET_PAYOUT and tx["rule_text"] == text
    tx = build_rule_change_request_tx(kind=KIND_REVOKE_PAYOUT, **base)
    assert tx["kind"] == KIND_REVOKE_PAYOUT and "rule_text" not in tx
    auth_id = _standing_entry().auth_id.hex()
    tx = build_rule_change_request_tx(
        kind=KIND_CANCEL_STANDING, offer_id=auth_id, **base)
    assert tx["offer_id"] == auth_id
    for bad in (dict(kind=13), dict(kind=KIND_CANCEL_STANDING),
                dict(kind=KIND_REVOKE_PAYOUT, rule_text="x"),
                dict(kind=KIND_SET_PAYOUT, rule_text=text, offer_id=auth_id)):
        with pytest.raises(ValueError):
            build_rule_change_request_tx(**bad, **base)


# --- unguarded accounts are untouched ---------------------------------------------------


def test_unguarded_direct_operations_are_unchanged():
    chain = Chain(_lm())
    install = _install_tx(0)
    applied = chain.block(install)
    assert install["tx_id"] in applied.accepted_tx_ids
    update = _install_tx(1, payout_version=2)
    applied = chain.block(update)
    assert update["tx_id"] in applied.accepted_tx_ids
    assert _payout_book(chain).get(ALICE).version == 2
    remove = _remove_tx(2)
    applied = chain.block(remove)
    assert remove["tx_id"] in applied.accepted_tx_ids
    assert _payout_book(chain).get(ALICE) is None

    create = _create_tx(3)
    applied = chain.block(create)
    assert create["tx_id"] in applied.accepted_tx_ids
    entry = _standing_book(chain).get_for_series(_standing_entry().series_key)
    cancel = _cancel_tx(4, entry.auth_id)
    applied = chain.block(cancel)
    assert cancel["tx_id"] in applied.accepted_tx_ids
    ok, reason = _standing_book(chain).can_cancel(entry.auth_id, TS)
    assert not ok and reason == "authorization is already cancelled"
