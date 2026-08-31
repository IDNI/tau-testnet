"""Unit tests for the approval-request lifecycle: pure, no engine, no database.

The two properties worth stating up front, because they are design decisions
rather than mechanics:

  * A DECLINE IS NOT A VETO. The declared approver list is routing -- it decides
    whose inbox is filled -- while the sender's own o5 clause decides what is
    required. If a decline resolved the request, an over-declared approver would
    hold terminal veto power and the declaration would be authority after all.
  * VOTES ARE EVALUATED PROSPECTIVELY, THEN COMMITTED. `hard_reject` in the
    engine suppresses staged balances and nonces but does not roll back
    lifecycle-manager mutations, so a Tau failure after a recorded vote would
    leave the vote behind. See engine.py:1067 vs :1083 for the same hazard in the
    rule-offer path.
"""
import pytest

import tau_defs
from consensus.approvals import (
    MAX_APPROVERS_PER_REQUEST,
    MAX_APPROVAL_WINDOW_BLOCKS,
    MAX_CUSTOM_INPUT_BYTES,
    MAX_PENDING_REQUESTS_PER_SENDER,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_OPEN,
    ApprovalRequest,
    ApprovalRequestLifecycleManager,
    TransferVote,
    parse_approval_request,
    parse_transfer_vote,
    screen_slot_widths,
)

A = "1a" * 48          # sender
B = "2b" * 48          # recipient
AUTH = "aa" * 48
SCAN = "bb" * 48
PARTNER = "cc" * 48
STRANGER = "de" * 48


def _req(sender=A, amount=200000, seq=1, expire=500, approvers=None, customs=None):
    return ApprovalRequest(
        sender_pubkey=sender, recipient_pubkey=B, amount=amount, sequence_number=seq,
        expire_at_height=expire,
        approvers=approvers if approvers is not None else {18: AUTH, 19: SCAN, 20: PARTNER},
        custom_inputs=customs if customs is not None else {},
    )


def _mgr(*requests):
    m = ApprovalRequestLifecycleManager()
    for r in requests:
        assert m.submit_request(r) is True
    return m


# --- admission ---------------------------------------------------------------

def test_a_well_formed_request_is_admissible():
    m = ApprovalRequestLifecycleManager()
    assert m.can_admit_request(_req(), next_height=100) == (True, "")


@pytest.mark.parametrize("approvers,expected", [
    ({}, "at least one approver"),
    ({17: AUTH}, "not an approval slot"),
    ({26: AUTH}, "not an approval slot"),
    ({18: AUTH, 19: AUTH}, "distinct accounts"),
    ({18: A}, "may not be their own approver"),
])
def test_approver_declaration_is_validated(approvers, expected):
    m = ApprovalRequestLifecycleManager()
    ok, reason = m.can_admit_request(_req(approvers=approvers), next_height=100)
    assert ok is False and expected in reason


def test_too_many_approvers_is_refused():
    slots = tau_defs.approval_slot_indices()
    approvers = {slot: ("%02x" % (i + 1)) * 48 for i, slot in enumerate(slots)}
    m = ApprovalRequestLifecycleManager()
    assert m.can_admit_request(_req(approvers=approvers), next_height=100)[0] is True
    approvers[max(slots) + 1] = STRANGER
    ok, reason = m.can_admit_request(_req(approvers=approvers), next_height=100)
    assert ok is False
    # It trips the slot screen before the count, which is fine: both are refusals.
    assert "not an approval slot" in reason or str(MAX_APPROVERS_PER_REQUEST) in reason


@pytest.mark.parametrize("amount", [0, tau_defs.MAX_TRANSFER_VALUE + 1])
def test_amount_must_be_in_range(amount):
    m = ApprovalRequestLifecycleManager()
    ok, reason = m.can_admit_request(_req(amount=amount), next_height=100)
    assert ok is False and "amount must be in" in reason


def test_custom_inputs_must_clear_the_slot_block():
    """i13/i16 are not reliably writable -- they become reserved under
    tau_validator_set and cooldown activation -- and a parked request can outlive
    the mode it was admitted under."""
    m = ApprovalRequestLifecycleManager()
    for idx in (13, 16, 17, 25):
        ok, reason = m.can_admit_request(_req(customs={idx: "x"}), next_height=100)
        assert ok is False, f"i{idx} should be refused as a request custom input"
        assert "below i%d" % tau_defs.REQUEST_CUSTOM_INPUT_MIN in reason
    assert m.can_admit_request(_req(customs={26: "x"}), next_height=100)[0] is True


def test_oversized_custom_input_is_refused():
    m = ApprovalRequestLifecycleManager()
    ok, reason = m.can_admit_request(
        _req(customs={26: "x" * (MAX_CUSTOM_INPUT_BYTES + 1)}), next_height=100)
    assert ok is False and "exceeds" in reason


@pytest.mark.parametrize("expire,ok_expected", [
    (100, False), (101, True), (100 + MAX_APPROVAL_WINDOW_BLOCKS, True),
    (101 + MAX_APPROVAL_WINDOW_BLOCKS, False),
])
def test_expiry_window(expire, ok_expected):
    m = ApprovalRequestLifecycleManager()
    assert m.can_admit_request(_req(expire=expire), next_height=100)[0] is ok_expected


def test_duplicate_request_is_refused():
    r = _req()
    m = _mgr(r)
    assert m.can_admit_request(r, next_height=100)[1] == "duplicate request"
    assert m.submit_request(r) is False


def test_per_sender_cap():
    m = ApprovalRequestLifecycleManager()
    for seq in range(MAX_PENDING_REQUESTS_PER_SENDER):
        assert m.submit_request(_req(seq=seq)) is True
    ok, reason = m.can_admit_request(_req(seq=99), next_height=100)
    assert ok is False and "too many open requests" in reason


# --- inbox scoping -----------------------------------------------------------

def test_inbox_holds_only_declared_approvers():
    """This IS the tier scoping: a request names only the approvers its amount
    needs, so an approver whose vote is not needed never sees it."""
    m = _mgr(_req(approvers={18: AUTH}))
    assert len(m.inbox_for(AUTH)) == 1
    assert m.inbox_for(SCAN) == []
    assert m.inbox_for(PARTNER) == []
    assert m.inbox_for(STRANGER) == []


# --- votes -------------------------------------------------------------------

def test_only_a_declared_approver_may_vote():
    r = _req()
    m = _mgr(r)
    ok, reason = m.can_admit_vote(
        TransferVote(request_id=r.request_id, voter_pubkey=STRANGER, approve=True), 100)
    assert ok is False and "only a declared approver" in reason


def test_vote_on_unknown_or_resolved_request_is_refused():
    r = _req()
    m = _mgr(r)
    v = TransferVote(request_id=b"\x00" * 32, voter_pubkey=AUTH, approve=True)
    assert m.can_admit_vote(v, 100) == (False, "unknown request")
    m.resolve(r.request_id, STATUS_FAILED)
    v2 = TransferVote(request_id=r.request_id, voter_pubkey=AUTH, approve=True)
    assert m.can_admit_vote(v2, 100) == (False, "request already resolved")


def test_vote_at_the_expiry_height_is_refused():
    """process_height_transitions runs AFTER the transaction loop, so the sweep
    cannot be relied on to stop a vote included at exactly the expiry height."""
    r = _req(expire=120)
    m = _mgr(r)
    v = TransferVote(request_id=r.request_id, voter_pubkey=AUTH, approve=True)
    assert m.can_admit_vote(v, 119)[0] is True
    assert m.can_admit_vote(v, 120) == (False, "request has expired")
    assert m.can_admit_vote(v, 121) == (False, "request has expired")


def test_one_vote_per_approver():
    r = _req()
    m = _mgr(r)
    v = TransferVote(request_id=r.request_id, voter_pubkey=AUTH, approve=True)
    assert m.commit_vote(v) == 18
    assert m.can_admit_vote(v, 100) == (False, "this approver has already voted")
    assert m.commit_vote(v) is None


def test_prospective_evaluation_does_not_mutate():
    r = _req()
    m = _mgr(r)
    root_before = m.requests_root()
    v = TransferVote(request_id=r.request_id, voter_pubkey=AUTH, approve=True)

    values = m.prospective_slot_values(r.request_id, v)
    assert values[18] == AUTH, "the prospective feed shows the vote"
    assert m.get_request(r.request_id).voted == {}, "but nothing is recorded yet"
    assert m.requests_root() == root_before, "and the hash has not moved"

    m.commit_vote(v)
    assert m.get_request(r.request_id).voted == {18: AUTH}
    assert m.requests_root() != root_before


def test_unvoted_slots_read_zero():
    """0 equals no approver pubkey, so the sender's clause keeps blocking."""
    r = _req()
    m = _mgr(r)
    m.commit_vote(TransferVote(request_id=r.request_id, voter_pubkey=SCAN, approve=True))
    values = m.get_request(r.request_id).slot_values()
    assert values[19] == SCAN
    assert values[18] == "0" and values[20] == "0"
    assert set(values) == set(tau_defs.approval_slot_indices())


def test_a_decline_is_not_a_veto():
    r = _req()
    m = _mgr(r)
    m.commit_vote(TransferVote(request_id=r.request_id, voter_pubkey=PARTNER,
                               approve=False, reason="not my problem"))
    assert r.request_id in m.open_requests, "a decline must not resolve the request"
    entry = m.get_request(r.request_id)
    assert entry.declined == {20}
    assert entry.slot_values()[20] == "0"
    assert entry.all_answered() is False
    # the remaining approvers can still release it
    m.commit_vote(TransferVote(request_id=r.request_id, voter_pubkey=AUTH, approve=True))
    m.commit_vote(TransferVote(request_id=r.request_id, voter_pubkey=SCAN, approve=True))
    assert m.get_request(r.request_id).all_answered() is True
    assert r.request_id in m.open_requests


# --- terminal transitions ----------------------------------------------------

def test_expiry_sweep_is_boundary_exact():
    r = _req(expire=120)
    m = _mgr(r)
    assert m.expire_at_height(119) == []
    assert m.expire_at_height(120) == [r.request_id]
    assert m.terminal_status[r.request_id] == STATUS_EXPIRED
    assert m.expire_at_height(121) == [], "already resolved, not swept twice"


def test_clause_replacement_resolves_that_senders_open_requests():
    """A request snapshots its approvers but re-evaluates the CURRENT clause, so
    leaving requests open across a replacement would silently change what the
    recorded votes mean, or strand them until expiry."""
    mine = [_req(seq=1), _req(seq=2)]
    theirs = _req(sender=STRANGER, seq=1, approvers={18: AUTH})
    m = _mgr(*mine, theirs)
    doomed = m.resolve_all_for_sender(A, STATUS_FAILED)
    assert set(doomed) == {r.request_id for r in mine}
    assert doomed == sorted(doomed), "canonical id order, so every node agrees"
    assert set(m.open_requests) == {theirs.request_id}, "other senders untouched"


def test_resolved_is_never_pruned_back_to_empty():
    """Shrinking back to empty would flip the hash gate and revert the meta hash
    to the pre-feature preimage."""
    r = _req()
    m = _mgr(r)
    assert m.is_empty() is False
    m.resolve(r.request_id, STATUS_FAILED)
    assert m.open_requests == {}
    assert m.is_empty() is False


def test_root_is_insertion_order_independent():
    a, b = _req(seq=1), _req(seq=2)
    fwd = _mgr(a, b).requests_root()
    rev = _mgr(b, a).requests_root()
    assert fwd == rev


# --- parsing -----------------------------------------------------------------

def test_request_parser_normalizes_numeric_keys_and_string_amount():
    tx = {"tx_type": "approval_request", "sender_pubkey": A, "sequence_number": 4,
          "payload": {"recipient_pubkey": B, "amount": "50000", "expire_at_height": 900,
                      "approvers": {"19": SCAN, "18": AUTH},
                      "custom_inputs": {"26": "hi"}}}
    r = parse_approval_request(tx)
    assert r is not None
    assert list(r.approvers) == [18, 19], "ascending NUMERIC order, not string order"
    assert r.amount == 50000 and isinstance(r.amount, int)


def test_vote_parser_requires_a_real_bool():
    """Accepting 1/0 would let a wallet bug turn a decline into an approval."""
    base = {"tx_type": "transfer_vote", "sender_pubkey": AUTH,
            "payload": {"request_id": "ab" * 32}}
    assert parse_transfer_vote(base).approve is True
    base["payload"]["approve"] = False
    assert parse_transfer_vote(base).approve is False
    base["payload"]["approve"] = 1
    assert parse_transfer_vote(base) is None


def test_vote_parser_rejects_a_malformed_request_id():
    for bad in ("nothex", "ab", "ab" * 31):
        tx = {"tx_type": "transfer_vote", "sender_pubkey": AUTH,
              "payload": {"request_id": bad}}
        assert parse_transfer_vote(tx) is None


def test_parsers_ignore_other_tx_types():
    assert parse_approval_request({"tx_type": "user_tx"}) is None
    assert parse_transfer_vote({"tx_type": "rule_offer"}) is None


# --- slot width screen -------------------------------------------------------

_CLAUSE = ("( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && !(i18[t]:bv[384] = { #x%s }:bv[384]))"
           " ? (o5[t]:bv[24] = { #x000000 }:bv[24])"
           " : (o5[t]:bv[24] = { #x000001 }:bv[24]) )" % AUTH)


def test_correctly_typed_clause_passes_the_screen():
    assert screen_slot_widths(_CLAUSE) is None


def test_a_clause_without_slots_passes():
    assert screen_slot_widths("( (i1[t]:bv[24] > { #x01 }:bv[24]) ? "
                              "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
                              "(o5[t]:bv[24] = { #x000001 }:bv[24]) )") is None


def test_wrong_slot_width_is_rejected():
    body = _CLAUSE.replace("i18[t]:bv[384]", "i18[t]:bv[24]")
    reason = screen_slot_widths(body)
    assert reason is not None and "must be typed bv[384]" in reason


def test_untyped_slot_mention_is_rejected():
    """_WIDTH_RE alone only finds ANNOTATED occurrences; an unannotated mention
    is exactly what lets the engine infer a conflicting width process-wide."""
    body = _CLAUSE.replace("i18[t]:bv[384]", "i18[t]")
    reason = screen_slot_widths(body)
    assert reason is not None and "must be written" in reason


def test_a_second_untyped_mention_is_rejected():
    body = _CLAUSE + " && (i19[t]:bv[384] = i20[t])"
    assert screen_slot_widths(body) is not None


def test_a_slot_named_only_in_a_comment_is_not_a_hazard():
    assert screen_slot_widths("# see i18 for the cosigner\n" + _CLAUSE) is None


def test_non_slot_streams_are_not_screened():
    assert screen_slot_widths(_CLAUSE + " && (i26[t] = { #x01 }:bv[8])") is None
