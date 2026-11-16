"""Votes on rule-change requests, the ready flag, and the end-of-block release
sweep: gate, guard verdicts, escape, side effects, soft failures, cap, root,
persistence and fork isolation."""
import copy
import itertools

import pytest

import chain_state
import tau_defs
from bls_keys import FAR_FUTURE, SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_tx
from consensus import sender_policy
from consensus.admission import TipAdmissionView
from consensus.approvals import (
    parse_rule_change_request,
    STATUS_CANCELLED,
    STATUS_EXECUTED,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_OPEN,
    ApprovalRequestLifecycleManager,
    TransferVote,
)
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import RuleOfferDecision, clause_body_v1
from consensus.serialization import compute_approval_request_book_root

from test_rule_change_requests import (  # noqa: F401  (fixtures and helpers)
    ALICE,
    BOB,
    CAROL,
    GUARD_BODY,
    GUARD_KEY,
    GUARD_TEXT,
    HEIGHT,
    KIND_ACCEPT,
    KIND_REVOKE,
    KIND_REVOKE_GUARD,
    KIND_SET,
    KIND_SET_GUARD,
    MALLORY,
    OFFER,
    OFFER_ID,
    OFFER_TEXT,
    OTHER_TEXT,
    POLICY_KEY,
    SET_TEXT,
    _admit,
    _apply,
    _cancel_tx,
    _lm,
    _logs,
    _request,
    _transfer_req,
    _tx,
)

D = tau_defs.RULE_CHANGE_DELAY_BLOCKS
LATE = 3000
NEW_GUARD_TEXT = (
    "always ( (i19[t]:bv[384] = { #x" + "cd" * 48 + " }:bv[384]) ? "
    "(o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
NEW_GUARD_BODY = clause_body_v1(NEW_GUARD_TEXT)
SET_BODY = clause_body_v1(SET_TEXT)
OFFER_BODY = clause_body_v1(OFFER_TEXT)

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


def _vote(request_id, *, approve=True, sk=SK_BOB, voter=BOB, seq=0, tx_id=None):
    rid = request_id.hex() if isinstance(request_id, bytes) else request_id
    return sign_tx({
        "tx_id": tx_id or f"vote-{next(_IDS)}", "tx_type": "transfer_vote",
        "sender_pubkey": voter, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "0", "request_id": rid, "approve": approve,
    }, sk)


class Chain:
    """Successive blocks over one lifecycle, carrying balances and sequences."""

    def __init__(self, lm, height=HEIGHT):
        self.lm = lm
        self.height = height
        self.balances = None
        self.sequences = None

    def block(self, *txs, height=None):
        if height is not None:
            self.height = height
        result, self.lm, meta = _apply(
            list(txs), self.lm, height=self.height,
            balances=self.balances, sequences=self.sequences)
        self.balances = meta["balances"]
        self.sequences = meta["sequence_numbers"]
        self.height += 1
        return result

    @property
    def book(self):
        return self.lm.approval_requests

    def entry(self, req):
        return self.book.get_rule_change(req.request_id)

    def clause(self, key):
        return self.lm.rule_offers.clause_for(*key)


def _guarded(**kw):
    return _lm(guard=True, **kw)


def _slot_inputs(evs, pool="apply"):
    return evs[pool].verdict_calls


# --- the slot gate ---------------------------------------------------------------

def test_a_request_naming_approvers_needs_active_slots_at_admission():
    lm = _lm(slots=False)
    result = _admit(_tx(_request(approvers={18: BOB})), lm)
    assert not result.is_valid
    assert result.code == "FEATURE_INACTIVE"


def test_a_request_without_approvers_is_admitted_with_slots_inactive():
    assert _admit(_tx(_request(approvers={})), _lm(slots=False)).is_valid


def test_a_request_naming_approvers_is_soft_ignored_at_apply_while_slots_are_inactive():
    lm = _lm(slots=False)
    req = _request(approvers={18: BOB})
    result, post, _ = _apply(_tx(req), lm)
    assert post.approval_requests.rule_change_requests == {}
    assert _tx(req)["tx_id"] not in result.accepted_tx_ids
    assert "approval slots are not active" in _logs(result)


def test_a_request_without_approvers_applies_with_slots_inactive():
    req = _request(approvers={})
    chain = Chain(_lm(slots=False))
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.clause(POLICY_KEY) == SET_BODY


def test_a_vote_on_a_rule_change_request_is_gated_on_active_slots():
    lm = _lm(slots=False)
    req = _request(approvers={18: BOB})
    lm.approval_requests.submit_rule_change(req, HEIGHT)
    tx = _vote(req.request_id)
    assert _admit(tx, lm).code == "FEATURE_INACTIVE"
    result, post, _ = _apply(tx, lm)
    assert tx["tx_id"] not in result.accepted_tx_ids
    assert "slots are not active" in _logs(result)
    assert post.approval_requests.get_rule_change(req.request_id).voted == {}


# --- no guard: every kind executes in its own block ------------------------------

NO_GUARD_CASES = {
    "set_policy": (KIND_SET, {}, lambda c: c.clause(POLICY_KEY) == SET_BODY),
    "revoke_policy": (KIND_REVOKE, {"policy": True}, lambda c: c.clause(POLICY_KEY) is None),
    "accept_offer": (KIND_ACCEPT, {"offer": True},
                     lambda c: c.clause(POLICY_KEY) == OFFER_BODY
                     and bytes.fromhex(OFFER_ID) in c.lm.rule_offers.resolved),
    "set_guard": (KIND_SET_GUARD, {}, lambda c: c.clause(GUARD_KEY) == GUARD_BODY),
}


@pytest.mark.parametrize("name", list(NO_GUARD_CASES))
def test_without_a_guard_every_kind_executes_in_its_own_block(name):
    kind, setup, landed = NO_GUARD_CASES[name]
    req = _request(kind)
    chain = Chain(_lm(**setup))
    result = chain.block(_tx(req))
    assert _tx(req)["tx_id"] in result.accepted_tx_ids
    assert chain.entry(req).status == STATUS_EXECUTED
    assert landed(chain)
    assert chain.book.ready_rule_change_ids() == []


def test_revoking_a_guard_the_guard_allows_executes_in_its_own_block(evaluators):
    for ev in evaluators.values():
        ev.set_verdict(GUARD_BODY, "1")
    req = _request(KIND_REVOKE_GUARD)
    chain = Chain(_guarded())
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.clause(GUARD_KEY) is None


# --- guard blocks until an approver's slot is filled ------------------------------

def _parked(kind=KIND_SET, *, setup=None, **req_kw):
    req = _request(kind, expire=LATE, **req_kw)
    chain = Chain(_guarded(**(setup or {})))
    chain.block(_tx(req))
    return chain, req


@pytest.mark.parametrize("kind,setup", [
    (KIND_SET, {}), (KIND_REVOKE, {"policy": True}), (KIND_ACCEPT, {"offer": True}),
    (KIND_SET_GUARD, {}), (KIND_REVOKE_GUARD, {}),
])
def test_a_blocking_guard_parks_the_request_with_empty_slots(kind, setup):
    chain, req = _parked(kind, setup=setup)
    entry = chain.entry(req)
    assert entry.status == STATUS_OPEN and not entry.ready
    assert chain.clause(GUARD_KEY) == GUARD_BODY
    assert chain.clause(POLICY_KEY) is None or kind == KIND_REVOKE


def test_an_approving_vote_fills_the_slot_and_executes_in_that_block():
    chain, req = _parked()
    result = chain.block(_vote(req.request_id))
    entry = chain.entry(req)
    assert entry.voted == {18: BOB}
    assert entry.status == STATUS_EXECUTED
    assert chain.clause(POLICY_KEY) == SET_BODY
    assert "Rule-change request ready" in _logs(result)


def test_the_guard_is_fed_the_kind_the_timestamp_and_the_approver(evaluators):
    chain, req = _parked(KIND_REVOKE, setup={"policy": True})
    chain.block(_vote(req.request_id))
    last = evaluators["apply"].verdict_calls[-1][1]
    assert last["i1"] == str(KIND_REVOKE)
    assert last["i5"] == "1234567890"
    assert last["i18"] == "#x" + BOB
    assert last["i19"] == "0"


def test_a_decline_is_recorded_leaves_the_slot_empty_and_the_request_open():
    chain, req = _parked()
    chain.block(_vote(req.request_id, approve=False))
    entry = chain.entry(req)
    assert entry.status == STATUS_OPEN and not entry.ready
    assert entry.voted == {} and entry.declined == {18}
    assert chain.clause(POLICY_KEY) is None


def test_a_declining_approver_cannot_vote_again():
    chain, req = _parked()
    chain.block(_vote(req.request_id, approve=False))
    again = _vote(req.request_id, seq=1)
    assert not _admit(again, chain.lm).is_valid
    result = chain.block(again)
    assert again["tx_id"] not in result.accepted_tx_ids
    assert "already voted" in _logs(result)
    assert chain.entry(req).voted == {}


def test_a_second_approver_may_still_complete_after_a_decline():
    approvers = {18: BOB, 19: CAROL}
    chain, req = _parked(approvers=approvers)
    chain.block(_vote(req.request_id, approve=False))
    chain.block(_vote(req.request_id, sk=SK_CAROL, voter=CAROL))
    entry = chain.entry(req)
    assert entry.voted == {19: CAROL}
    # The seeded guard reads i18 only, so a slot-19 approval leaves it blocked.
    assert entry.status == STATUS_OPEN and not entry.ready


def test_only_a_declared_approver_may_vote_on_a_rule_change_request():
    chain, req = _parked()
    tx = _vote(req.request_id, sk=SK_CAROL, voter=CAROL)
    assert _admit(tx, chain.lm).code == "NOT_AN_APPROVER"
    result = chain.block(tx)
    assert tx["tx_id"] not in result.accepted_tx_ids
    assert chain.entry(req).voted == {}


def test_a_request_with_no_approvers_and_a_guard_waits_for_the_delay():
    req = _request(approvers={}, expire=LATE)
    chain = Chain(_guarded())
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN


# --- the time escape -----------------------------------------------------------------

def test_the_escape_releases_at_exactly_created_plus_delay_and_not_before():
    chain, req = _parked()
    chain.block(height=HEIGHT + D - 1)
    assert chain.entry(req).status == STATUS_OPEN and not chain.entry(req).ready
    chain.block(height=HEIGHT + D)
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.clause(POLICY_KEY) == SET_BODY


def test_cancelling_before_the_delay_stops_the_escape():
    chain, req = _parked()
    chain.block(_cancel_tx(req.request_id, seq=1), height=HEIGHT + 5)
    chain.block(height=HEIGHT + D + 3)
    assert chain.entry(req).status == STATUS_CANCELLED
    assert chain.clause(POLICY_KEY) is None


def test_a_request_that_expires_before_the_delay_expires():
    req = _request(expire=HEIGHT + 50)
    chain = Chain(_guarded())
    chain.block(_tx(req))
    chain.block(height=HEIGHT + 50)
    assert chain.entry(req).status == STATUS_EXPIRED
    chain.block(height=HEIGHT + D)
    assert chain.entry(req).status == STATUS_EXPIRED
    assert chain.clause(POLICY_KEY) is None


def test_cancelling_a_ready_request_removes_it_from_the_release_queue():
    chain, req = _parked()
    chain.book.mark_rule_change_ready(req.request_id)
    assert chain.book.ready_rule_change_ids() == [req.request_id]
    chain.block(_cancel_tx(req.request_id, seq=1))
    assert chain.entry(req).status == STATUS_CANCELLED
    assert chain.book.ready_rule_change_ids() == []
    assert chain.clause(POLICY_KEY) is None


# --- a guard change goes through the current guard --------------------------------

def test_a_guard_replacement_is_judged_by_the_current_guard():
    chain, req = _parked(KIND_SET_GUARD, text=NEW_GUARD_TEXT)
    assert chain.clause(GUARD_KEY) == GUARD_BODY
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.clause(GUARD_KEY) == NEW_GUARD_BODY


def test_a_guard_revocation_is_judged_by_the_current_guard():
    chain, req = _parked(KIND_REVOKE_GUARD)
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id))
    assert chain.clause(GUARD_KEY) is None


def test_the_new_guard_governs_the_next_request(evaluators):
    for ev in evaluators.values():
        ev.set_verdict(NEW_GUARD_BODY, "0")
    chain, first = _parked(KIND_SET_GUARD, text=NEW_GUARD_TEXT)
    chain.block(_vote(first.request_id))
    second = _request(KIND_SET, seq=1, expire=LATE)
    chain.block(_tx(second))
    assert chain.entry(second).status == STATUS_OPEN
    assert chain.clause(GUARD_KEY) == NEW_GUARD_BODY


# --- side effects --------------------------------------------------------------------

def _sibling(chain, seq=7):
    other = _request(KIND_SET, seq=seq, text=OTHER_TEXT, expire=LATE)
    assert chain.book.submit_rule_change(other, HEIGHT)
    return other


@pytest.mark.parametrize("kind,setup", [
    (KIND_SET, {}), (KIND_REVOKE, {"policy": True}), (KIND_ACCEPT, {"offer": True}),
])
def test_policy_kinds_fail_transfer_requests_but_not_rule_change_requests(kind, setup):
    chain = Chain(_lm(**setup))
    transfer = _transfer_req(0)
    chain.book.submit_request(transfer)
    other = _sibling(chain)
    req = _request(kind)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_EXECUTED
    assert transfer.request_id not in chain.book.open_requests
    assert chain.book.terminal_status[transfer.request_id] == STATUS_FAILED
    assert chain.entry(other).status == STATUS_OPEN


@pytest.mark.parametrize("kind", [KIND_SET_GUARD, KIND_REVOKE_GUARD])
def test_guard_kinds_fail_sibling_rule_change_requests_but_not_transfers_or_themselves(kind, evaluators):
    for ev in evaluators.values():
        ev.set_verdict(GUARD_BODY, "1")
    chain = Chain(_guarded())
    transfer = _transfer_req(0)
    chain.book.submit_request(transfer)
    other = _sibling(chain)
    req = _request(kind, expire=LATE)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.entry(other).status == STATUS_FAILED
    assert transfer.request_id in chain.book.open_requests


def test_a_sibling_failed_earlier_in_the_sweep_is_skipped(evaluators):
    for ev in evaluators.values():
        ev.set_verdict(GUARD_BODY, "1")
    chain = Chain(_guarded())
    guard_req, policy_req = next(
        (g, p)
        for g, p in (
            (_request(KIND_SET_GUARD, seq=n, text=NEW_GUARD_TEXT, expire=LATE),
             _request(KIND_SET, seq=n, expire=LATE))
            for n in range(1, 200))
        if g.request_id < p.request_id
    )
    for r in (guard_req, policy_req):
        chain.book.submit_rule_change(r, HEIGHT)
        chain.book.mark_rule_change_ready(r.request_id)
    chain.block()
    assert chain.entry(guard_req).status == STATUS_EXECUTED
    assert chain.entry(policy_req).status == STATUS_FAILED
    assert chain.clause(POLICY_KEY) is None
    assert chain.clause(GUARD_KEY) == NEW_GUARD_BODY


# --- soft failures at release -------------------------------------------------------

def test_a_body_that_no_longer_builds_fails_the_request_not_the_block(evaluators):
    chain, req = _parked()
    evaluators["apply"].fail_build(SET_BODY)
    tx = _vote(req.request_id)
    result = chain.block(tx)
    assert tx["tx_id"] in result.accepted_tx_ids
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.clause(POLICY_KEY) is None
    assert not result.invalid_tx_ids


def test_a_guard_body_that_no_longer_builds_fails_the_request(evaluators):
    chain, req = _parked(KIND_SET_GUARD, text=NEW_GUARD_TEXT)
    evaluators["apply"].fail_build(NEW_GUARD_BODY)
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.clause(GUARD_KEY) == GUARD_BODY


def test_an_offer_accepted_meanwhile_fails_the_request():
    chain, req = _parked(KIND_ACCEPT, setup={"offer": True})
    chain.lm.rule_offers.submit_decision(RuleOfferDecision(
        offer_id=bytes.fromhex(OFFER_ID), actor_pubkey=ALICE, accept=True,
        rule_text=OFFER_TEXT))
    chain.lm.rule_offers.accepted_clauses.pop(POLICY_KEY)
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.clause(POLICY_KEY) is None


def test_an_offer_expired_by_the_release_block_fails_the_request():
    chain, req = _parked(KIND_ACCEPT, setup={"offer": True})
    chain.block(_vote(req.request_id), height=OFFER.expire_at_height)
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.clause(POLICY_KEY) is None


def test_an_accept_releases_from_its_own_text_without_the_node_local_payloads():
    chain, req = _parked(KIND_ACCEPT, setup={"offer": True})
    chain.lm.rule_offers.offer_payloads.clear()
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.clause(POLICY_KEY) == OFFER_BODY
    assert bytes.fromhex(OFFER_ID) in chain.lm.rule_offers.resolved


def test_an_accept_request_without_the_offer_text_is_refused():
    tx = _tx(_request(KIND_ACCEPT))
    del tx["rule_text"]
    assert parse_rule_change_request(tx) is None


def test_an_accept_request_whose_text_does_not_match_the_offer_is_refused_everywhere():
    lm = _lm(offer=True)
    req = _request(KIND_ACCEPT, text=OTHER_TEXT)
    tx = _tx(req)
    admitted = _admit(tx, lm)
    result, post, _ = _apply(tx, lm)
    assert not admitted.is_valid
    assert "offer digest" in admitted.error
    assert tx["tx_id"] not in result.accepted_tx_ids
    assert post.approval_requests.rule_change_requests == {}
    assert "offer digest" in _logs(result)


def test_an_accept_request_stores_the_exact_offered_text_and_the_id_binds_it():
    req = _request(KIND_ACCEPT)
    chain = Chain(_guarded(offer=True))
    chain.block(_tx(req))
    assert chain.entry(req).body == OFFER_TEXT
    assert _request(KIND_ACCEPT, text=OFFER_TEXT + " ").request_id != req.request_id


def test_a_revoke_with_nothing_left_to_revoke_fails_the_request():
    chain, req = _parked(KIND_REVOKE, setup={"policy": True})
    chain.lm.rule_offers.accepted_clauses.pop(POLICY_KEY)
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED


def test_a_guard_revoke_with_no_guard_left_fails_the_request():
    chain, req = _parked(KIND_REVOKE_GUARD)
    chain.lm.rule_offers.accepted_clauses.pop(GUARD_KEY)
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED


def test_a_failed_release_writes_nothing_and_fails_no_siblings():
    chain, req = _parked()
    transfer = _transfer_req(0)
    chain.book.submit_request(transfer)
    chain.lm.rule_offers.accepted_clauses[POLICY_KEY] = SET_BODY
    sibling = _sibling(chain)
    chain.entry(req).body = "o5[t]:bv[24] = i13[t]:bv[24]"
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.clause(POLICY_KEY) == SET_BODY
    assert transfer.request_id in chain.book.open_requests
    assert chain.entry(sibling).status == STATUS_OPEN


# --- the per-block cap -------------------------------------------------------------

def _nine_ready(chain, *, expire=LATE):
    reqs = [
        _request(KIND_SET, seq=i, text=f"always ( o5[t]:bv[24] = {{ #x{i + 1:06x} }}:bv[24] ).",
                 expire=expire)
        for i in range(9)
    ]
    for r in reqs:
        assert chain.book.submit_rule_change(r, HEIGHT)
        chain.book.mark_rule_change_ready(r.request_id)
    return sorted(reqs, key=lambda r: r.request_id)


def test_nine_ready_requests_release_eight_in_id_order_and_the_ninth_next_block():
    chain = Chain(_lm())
    ordered = _nine_ready(chain)
    chain.block()
    assert [chain.entry(r).status for r in ordered[:8]] == [STATUS_EXECUTED] * 8
    assert chain.entry(ordered[8]).status == STATUS_OPEN
    assert chain.entry(ordered[8]).ready
    assert tau_defs.MAX_RULE_CHANGE_RELEASES_PER_BLOCK == 8
    chain.block()
    assert chain.entry(ordered[8]).status == STATUS_EXECUTED
    assert chain.clause(POLICY_KEY) == ordered[8].body


def test_a_deferred_request_whose_expiry_arrives_expires():
    chain = Chain(_lm())
    ordered = _nine_ready(chain)
    chain.entry(ordered[8]).expire_at_height = HEIGHT
    chain.block()
    assert [chain.entry(r).status for r in ordered[:8]] == [STATUS_EXECUTED] * 8
    assert chain.entry(ordered[8]).status == STATUS_EXPIRED
    assert chain.clause(POLICY_KEY) == ordered[7].body


def test_a_ready_request_with_cap_to_spare_releases_in_its_expiry_block():
    chain = Chain(_lm())
    req = _request(KIND_SET, expire=HEIGHT)
    chain.book.submit_rule_change(req, HEIGHT - 5)
    chain.book.mark_rule_change_ready(req.request_id)
    chain.block()
    assert chain.entry(req).status == STATUS_EXECUTED


def test_failures_count_against_the_cap():
    chain = Chain(_lm())
    ordered = _nine_ready(chain)
    for r in ordered[:8]:
        chain.entry(r).body = "o5[t]:bv[24] = i13[t]:bv[24]"
    chain.block()
    assert [chain.entry(r).status for r in ordered[:8]] == [STATUS_FAILED] * 8
    assert chain.entry(ordered[8]).status == STATUS_OPEN


# --- the root ------------------------------------------------------------------------

def _root(approvals):
    return approvals.requests_root()


def test_the_root_moves_on_vote_decline_ready_executed_and_failed():
    def fresh():
        approvals = ApprovalRequestLifecycleManager()
        req = _request(approvers={18: BOB, 19: CAROL})
        approvals.submit_rule_change(req, HEIGHT)
        return approvals, req

    base_a, req = fresh()
    base = _root(base_a)
    roots = {"base": base}

    a, req = fresh()
    a.commit_rule_change_vote(TransferVote(req.request_id, BOB, True))
    roots["voted"] = _root(a)
    a.mark_rule_change_ready(req.request_id)
    roots["voted+ready"] = _root(a)
    a.resolve_rule_change(req.request_id, STATUS_EXECUTED)
    roots["executed"] = _root(a)

    a, req = fresh()
    a.commit_rule_change_vote(TransferVote(req.request_id, BOB, False))
    roots["declined"] = _root(a)

    a, req = fresh()
    a.mark_rule_change_ready(req.request_id)
    roots["ready"] = _root(a)
    a.resolve_rule_change(req.request_id, STATUS_FAILED)
    roots["failed"] = _root(a)

    assert len(set(roots.values())) == len(roots)


def test_the_empty_book_root_is_unchanged_by_the_ready_encoding():
    empty = compute_approval_request_book_root([], [])
    assert compute_approval_request_book_root([], [], []) == empty
    assert ApprovalRequestLifecycleManager().requests_root() == empty


def test_a_vote_changes_the_meta_hash_through_apply():
    chain, req = _parked()
    before = chain.lm.consensus_meta_hash()
    chain.block(_vote(req.request_id, approve=False))
    assert chain.lm.consensus_meta_hash() != before


# --- admission and apply agree on votes ----------------------------------------------

def _vote_scenarios():
    def valid(lm, req):
        return _vote(req.request_id)

    def stranger(lm, req):
        return _vote(req.request_id, sk=SK_CAROL, voter=CAROL)

    def unknown(lm, req):
        return _vote(b"\x07" * 32)

    def repeat(lm, req):
        lm.approval_requests.commit_rule_change_vote(TransferVote(req.request_id, BOB, True))
        return _vote(req.request_id)

    def repeat_decline(lm, req):
        lm.approval_requests.commit_rule_change_vote(TransferVote(req.request_id, BOB, False))
        return _vote(req.request_id)

    def cancelled(lm, req):
        lm.approval_requests.resolve_rule_change(req.request_id, STATUS_CANCELLED)
        return _vote(req.request_id)

    def expired(lm, req):
        lm.approval_requests.get_rule_change(req.request_id).expire_at_height = 50
        return _vote(req.request_id)

    return {f.__name__: f for f in
            (valid, stranger, unknown, repeat, repeat_decline, cancelled, expired)}


@pytest.mark.parametrize("name", list(_vote_scenarios()))
def test_admission_and_apply_agree_on_a_vote_for_a_rule_change_id(name):
    req = _request(expire=LATE)
    lm = _guarded()
    lm.approval_requests.submit_rule_change(req, HEIGHT)
    tx = _vote_scenarios()[name](lm, req)
    admitted = _admit(tx, lm).is_valid
    result, post, _ = _apply(tx, lm, height=50)
    assert admitted is (tx["tx_id"] in result.accepted_tx_ids)
    assert admitted is (name == "valid")


# --- persistence and forks -----------------------------------------------------------

def _seed_state(lm):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances["acct"] = 1
    chain_state._sequence_numbers["acct"] = 0
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    return lm


def _reload():
    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


def test_ready_votes_and_declines_round_trip_through_a_reload(
        isolated_chain_state, temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    book = lm.approval_requests
    ready = _request(KIND_SET, seq=1, approvers={18: BOB, 19: CAROL})
    declined = _request(KIND_SET, seq=2, text=OTHER_TEXT, approvers={18: BOB})
    for r in (ready, declined):
        book.submit_rule_change(r, 12)
    book.commit_rule_change_vote(TransferVote(ready.request_id, CAROL, True))
    book.mark_rule_change_ready(ready.request_id)
    book.commit_rule_change_vote(TransferVote(declined.request_id, BOB, False))
    before_root = book.requests_root()
    before_hash = lm.consensus_meta_hash()
    before = copy.deepcopy(book.rule_change_requests)

    reloaded = _reload()
    assert reloaded.approval_requests.rule_change_requests == before
    assert reloaded.approval_requests.requests_root() == before_root
    assert reloaded.consensus_meta_hash() == before_hash
    entry = reloaded.approval_requests.get_rule_change(ready.request_id)
    assert entry.ready and entry.voted == {19: CAROL}
    assert reloaded.approval_requests.get_rule_change(declined.request_id).declined == {18}

    row = TipAdmissionView().get_rule_change_request(declined.request_id_hex)
    assert row["declined"] == [18] and row["ready"] is False
    assert TipAdmissionView().get_rule_change_request(ready.request_id_hex)["ready"] is True


def test_a_fork_does_not_leak_votes_ready_or_release_into_its_parent():
    parent = _guarded()
    req = _request(expire=LATE)
    parent.approval_requests.submit_rule_change(req, HEIGHT)
    root = parent.approval_requests.requests_root()

    fork = parent.fork()
    fork.approval_requests.commit_rule_change_vote(TransferVote(req.request_id, BOB, True))
    fork.approval_requests.mark_rule_change_ready(req.request_id)
    fork.approval_requests.resolve_rule_change(req.request_id, STATUS_EXECUTED)

    entry = parent.approval_requests.get_rule_change(req.request_id)
    assert entry.voted == {} and not entry.ready and entry.status == STATUS_OPEN
    assert parent.approval_requests.requests_root() == root


def test_an_apply_does_not_mutate_the_parent_lifecycle():
    chain, req = _parked()
    parent = chain.lm
    root = parent.approval_requests.requests_root()
    _apply(_vote(req.request_id), parent)
    assert parent.approval_requests.get_rule_change(req.request_id).status == STATUS_OPEN
    assert parent.rule_offers.clause_for(*POLICY_KEY) is None
    assert parent.approval_requests.requests_root() == root
