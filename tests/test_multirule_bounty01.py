"""Bounty 01, FIX 7: multi-rule payout books — the mock-level suite.

The native counterpart (tests/test_multirule_native.py) proves the same
six cases against real Tau clauses; this file proves the bookkeeping at
book, parse/signing, admission and engine level with the mock policy
evaluator: slot addressing, per-slot version chains, the slot bound,
per-rule settlement isolation, restore round-trips (including pre-FIX7
12-field rows), the signed slot on install/remove transactions, and the
guard request path (kinds 7/8/9) acting on the named slot only.
"""
import itertools

import pytest

import tau_defs
from bls_keys import FAR_FUTURE, SK_ALICE, sign_tx
from consensus import sender_policy
from consensus.admission import (
    validate_install_payout_rule_payload,
    validate_mempool_admission,
    validate_remove_payout_rule_payload,
)
from consensus.approvals import STATUS_EXECUTED, STATUS_OPEN, payout_payload_text
from consensus.payout_rules import (
    LEG_BPS_OF_BASE,
    LEG_FIXED,
    MAX_RULES_PER_OWNER,
    PayoutLeg,
    PayoutRuleBook,
    PayoutRuleEntry,
    parse_install_payout_rule,
    parse_remove_payout_rule,
    payout_rule_capabilities,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_signing import signing_message_bytes

from test_rule_change_release import Chain
from test_rule_change_requests import (
    ALICE,
    BOB,
    GUARD_BODY,
    HEIGHT,
    _lm,
    _request,
    _tx,
)
from test_rule_change_payout_standing_bounty01 import (
    _LmView,
    _admit_request,
    _install_tx,
    _payout_entry,
    _vote,
)

OWNER = ALICE
ARTIST = "b" * 96
WORKER = "c" * 96
OTHER = "d" * 96

ANCHOR = 1_700_000_000
WEEK = 604_800
TS = ANCHOR + 1000
SID_1 = bytes.fromhex("11" * 32)

KIND_SET_PAYOUT = tau_defs.RULE_CHANGE_KIND_SET_PAYOUT
KIND_UPDATE_PAYOUT = tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT
KIND_REVOKE_PAYOUT = tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT

_IDS = itertools.count()


@pytest.fixture(autouse=True)
def evaluators():
    """The seeded guard allows a change only once slot i18 holds a pubkey
    (the FIX 5B harness fixture, restated so this file is self-contained)."""
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def rule(index=0, *, owner=OWNER, amount=100, version=1, max_period=0,
         recipient=ARTIST):
    return PayoutRuleEntry(
        owner_pubkey=owner,
        recipients=(recipient,),
        legs=(PayoutLeg(recipient, LEG_FIXED, amount),),
        max_per_execution=0,
        max_per_period=max_period,
        period_seconds=WEEK,
        period_anchor_ts=ANCHOR,
        version=version,
        rule_index=index,
    )


def full_book():
    book = PayoutRuleBook()
    for i in range(MAX_RULES_PER_OWNER):
        book.install(rule(i, amount=100 + i), TS)
    return book


# --- Slot addressing and the bound ----------------------------------------------


def test_eight_slots_hold_independent_rules_and_a_ninth_is_refused():
    book = full_book()
    assert book.rule_count() == MAX_RULES_PER_OWNER
    assert book.rule_count_for_owner(OWNER) == MAX_RULES_PER_OWNER
    assert [e.rule_index for e in book.get_all(OWNER)] == list(range(8))
    ok, reason = book.can_install(rule(MAX_RULES_PER_OWNER), TS)
    assert not ok and "at most" in reason


def test_identical_terms_at_different_slots_are_different_rules():
    a, b = rule(0), rule(1)
    assert a.rule_id != b.rule_id
    book = PayoutRuleBook()
    book.install(a, TS)
    # The same terms at slot 1 are a first rule there, not a collision.
    ok, reason = book.can_install(b, TS)
    assert ok, reason
    book.install(b, TS)
    assert book.get(OWNER, 0).rule_id == a.rule_id
    assert book.get(OWNER, 1).rule_id == b.rule_id


def test_version_chains_run_per_slot():
    book = PayoutRuleBook()
    book.install(rule(0), TS)
    book.install(rule(1), TS)
    # Slot 1 advances to version 2 while slot 0 stays at version 1.
    book.install(rule(1, version=2), TS)
    assert book.get(OWNER, 1).version == 2
    assert book.get(OWNER, 0).version == 1
    # A wrong version at slot 0 is judged against slot 0's chain alone.
    ok, reason = book.can_install(rule(0, version=3), TS)
    assert not ok and "(2)" in reason
    ok, _ = book.can_install(rule(0, version=2), TS)
    assert ok


def test_remove_one_slot_leaves_the_others_and_the_slot_is_reusable():
    book = full_book()
    removed = book.remove(OWNER, TS, 3)
    assert removed.rule_index == 3
    assert book.get(OWNER, 3) is None
    assert book.rule_count() == MAX_RULES_PER_OWNER - 1
    for i in (0, 1, 2, 4, 5, 6, 7):
        assert book.get(OWNER, i) is not None
    # The freed slot takes a fresh version-1 rule.
    ok, reason = book.can_install(rule(3), TS)
    assert ok, reason


def test_the_same_settlement_id_settles_once_per_rule():
    book = PayoutRuleBook()
    a, b = rule(0), rule(1, recipient=WORKER)
    book.install(a, TS)
    book.install(b, TS)
    # Settlement ids are scoped by rule id: the same id settles under
    # each rule, once each — and a repeat under either refuses.
    assert book.execute(a.rule_id, SID_1, 100, TS, 10_000).executed
    assert book.execute(b.rule_id, SID_1, 100, TS, 10_000).executed
    assert not book.execute(a.rule_id, SID_1, 100, TS, 10_000).executed
    assert not book.execute(b.rule_id, SID_1, 100, TS, 10_000).executed


def test_restore_round_trips_a_full_book_and_refuses_duplicate_slots():
    book = full_book()
    book.execute(book.get(OWNER, 2).rule_id, SID_1, 100, TS, 10_000)
    clone = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert clone.root() == book.root()
    assert clone.rule_count() == MAX_RULES_PER_OWNER
    rows = book.rows()
    with pytest.raises(ValueError):
        PayoutRuleBook.restore(rows + [rows[0]], book.settlement_rows())


def test_a_pre_fix7_row_restores_as_slot_zero():
    book = PayoutRuleBook()
    book.install(rule(0), TS)
    legacy_row = book.rows()[0][:12]  # no slot term, as written pre-FIX7
    clone = PayoutRuleBook.restore([legacy_row], [])
    assert clone.get(OWNER, 0).rule_id == book.get(OWNER, 0).rule_id


def test_capabilities_report_the_multi_rule_bound():
    caps = payout_rule_capabilities()
    assert caps["max_rules_per_owner"] == MAX_RULES_PER_OWNER


# --- Parsing and signing ----------------------------------------------------------


def test_parse_reads_the_slot_and_defaults_to_zero():
    base = {
        "sender_pubkey": OWNER,
        "payout_recipients": [ARTIST],
        "payout_legs": [[ARTIST, LEG_BPS_OF_BASE, 500]],
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": ANCHOR,
    }
    assert parse_install_payout_rule(base).rule_index == 0
    assert parse_install_payout_rule(
        {**base, "payout_rule_index": 5}).rule_index == 5
    assert parse_remove_payout_rule({"sender_pubkey": OWNER}) == (OWNER, 0)
    assert parse_remove_payout_rule(
        {"sender_pubkey": OWNER, "payout_rule_index": 7}) == (OWNER, 7)


def test_the_slot_is_inside_the_install_and_remove_signatures():
    common = {
        "sender_pubkey": OWNER, "sequence_number": 0,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100",
    }
    install = {
        **common, "tx_type": "install_payout_rule",
        "payout_recipients": [ARTIST],
        "payout_legs": [[ARTIST, LEG_FIXED, 100]],
        "payout_period_seconds": WEEK, "payout_period_anchor_ts": ANCHOR,
        "payout_version": 1,
    }
    assert signing_message_bytes(install) != signing_message_bytes(
        {**install, "payout_rule_index": 1})
    remove = {**common, "tx_type": "remove_payout_rule"}
    assert signing_message_bytes(remove) != signing_message_bytes(
        {**remove, "payout_rule_index": 1})


# --- Admission and the direct engine path -----------------------------------------


def _remove_tx(seq, index):
    return sign_tx({
        "tx_id": f"multirule-rm-{next(_IDS)}",
        "tx_type": "remove_payout_rule",
        "sender_pubkey": ALICE, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100", "payout_rule_index": index,
    }, SK_ALICE)


def test_direct_install_and_remove_address_one_slot():
    chain = Chain(_lm())
    install = _install_tx(0, payout_rule_index=2)
    result = validate_install_payout_rule_payload(install, _LmView(chain.lm))
    assert result.is_valid, result.error
    chain.block(install)
    # The chain replaces its lifecycle manager per block: always re-read.
    assert chain.lm.payout_rules.get(ALICE, 2) is not None
    assert chain.lm.payout_rules.get(ALICE) is None  # slot 0 stayed empty

    remove = _remove_tx(1, 2)
    result = validate_remove_payout_rule_payload(remove, _LmView(chain.lm))
    assert result.is_valid, result.error
    chain.block(remove)
    assert chain.lm.payout_rules.get(ALICE, 2) is None


def test_admission_judges_the_target_slot_not_the_owner():
    chain = Chain(_lm())
    chain.block(_install_tx(0))  # slot 0, version 1
    # A first rule at slot 1 is admissible although the owner has a rule.
    result = validate_install_payout_rule_payload(
        _install_tx(1, payout_rule_index=1), _LmView(chain.lm))
    assert result.is_valid, result.error
    # A second version-1 rule at slot 0 is refused by slot 0's chain.
    result = validate_install_payout_rule_payload(
        _install_tx(1), _LmView(chain.lm))
    assert not result.is_valid
    # A removal naming an empty slot is refused; slot 0's rule is intact.
    result = validate_remove_payout_rule_payload(
        _remove_tx(1, 5), _LmView(chain.lm))
    assert not result.is_valid


# --- The guard request path acts per rule ------------------------------------------


def _guarded_chain_with_two_rules():
    chain = Chain(_lm(guard=True))
    for slot in (0, 1):
        entry = _payout_entry(payout_rule_index=slot)
        req = _request(KIND_SET_PAYOUT,
                       text=payout_payload_text(entry), seq=slot, expire=3000)
        chain.block(_tx(req))
        chain.block(_vote(req.request_id, seq=slot))
        assert chain.entry(req).status == STATUS_EXECUTED
    return chain


def test_kind7_request_installs_at_the_named_slot_only():
    chain = _guarded_chain_with_two_rules()
    book = chain.lm.payout_rules
    assert book.get(ALICE, 0) is not None
    assert book.get(ALICE, 1) is not None
    assert book.get(ALICE, 2) is None
    # Kind 7 for the occupied slot 0 is refused at admission now.
    text = payout_payload_text(_payout_entry())
    refused = _admit_request(
        _tx(_request(KIND_SET_PAYOUT, text=text, seq=5)), chain.lm)
    assert not refused.is_valid
    assert "already exists" in (refused.error or "")


def test_kind9_request_revokes_only_the_named_rule():
    chain = _guarded_chain_with_two_rules()
    target = chain.lm.payout_rules.get(ALICE, 1)
    req = _request(KIND_REVOKE_PAYOUT, seq=2,
                   offer_id=target.rule_id.hex(), expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=2))
    assert chain.entry(req).status == STATUS_EXECUTED
    # Re-read: each block replaces the chain's lifecycle manager.
    assert chain.lm.payout_rules.get(ALICE, 1) is None
    assert chain.lm.payout_rules.get(ALICE, 0) is not None


def test_kind9_request_naming_another_owners_rule_is_refused():
    chain = _guarded_chain_with_two_rules()
    foreign = rule(0, owner=OTHER)
    chain.lm.payout_rules.install(foreign, TS)
    req = _request(KIND_REVOKE_PAYOUT, seq=8,
                   offer_id=foreign.rule_id.hex(), expire=3000)
    refused = _admit_request(_tx(req), chain.lm)
    assert not refused.is_valid
    assert chain.lm.payout_rules.get(OTHER, 0) is not None
