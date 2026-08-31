"""Read RPCs for co-signature approvals.

The inbox is the interesting one. A request declares only the approvers its
amount requires, so `incoming` being EMPTY for an account is the tier scoping
working -- an approver whose vote a given amount does not need must not see it.
Both directions are asserted, because only checking that the right approver sees
it would pass just as happily if everyone saw everything.

The two discovery RPCs are advisory: they exist because a client must declare the
right approver set, the wallet that wrote the rule knows it and a fresh CLI does
not, and guessing means over-declaring.
"""
import json

import pytest
from unittest.mock import patch

import api_response
import db
import tau_defs
from commands import (
    getapprovalpreview,
    getapprovalrequest,
    getapprovalrequests,
    getapprovalslots,
    getrequestid,
)
from consensus.approvals import (
    MAX_PREVIEW_SLOTS,
    STATUS_EXECUTED,
    ApprovalRequest,
    ApprovalRequestLifecycleManager,
    TransferVote,
)

A = "1a" * 48          # sender
B = "2b" * 48          # recipient
AUTH = "aa" * 48
SCAN = "bb" * 48
PARTNER = "cc" * 48
STRANGER = "de" * 48

CLAUSE = (
    "( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && !(i18[t]:bv[384] = { #x" + AUTH + " }:bv[384]))"
    " || (i1[t]:bv[24] > { #x002710 }:bv[24] && !(i19[t]:bv[384] = { #x" + SCAN + " }:bv[384]))"
    " ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )"
)


def _activate(on=True):
    db.set_chain_state_value("approval_slots_active", "1" if on else "0")


def _request(amount=200000, seq=1, approvers=None, customs=None, sender=A):
    return ApprovalRequest(
        sender_pubkey=sender, recipient_pubkey=B, amount=amount, sequence_number=seq,
        expire_at_height=900,
        approvers=approvers if approvers is not None else {18: AUTH, 19: SCAN},
        custom_inputs=customs or {},
    )


def _persist(*requests, votes=()):
    """Write requests straight to the table, as a mined block would."""
    mgr = ApprovalRequestLifecycleManager()
    for r in requests:
        mgr.submit_request(r)
    for v in votes:
        mgr.commit_vote(v)
    db.save_canonical_state_atomically(
        head_hash="h", head_num=1, balances={A: 100000}, sequences={A: 1},
        application_rules="", consensus_rules="", active_consensus_id="",
        pending_updates=[], votes=[], scheduled=[], archival=[],
        approval_requests=mgr.snapshot_requests(), approval_slots_active=True,
    )
    return mgr


def _data(resp):
    parsed = json.loads(resp)
    assert parsed.get("status") == "ok", parsed
    return parsed["data"]


def _err(resp):
    parsed = json.loads(resp)
    assert parsed.get("status") == "error", parsed
    return parsed["error"]


# --- the activation gate -----------------------------------------------------

@pytest.mark.parametrize("mod,cmd", [
    (getapprovalrequests, "getapprovalrequests " + A),
    (getapprovalrequest, "getapprovalrequest " + "ab" * 32),
    (getapprovalslots, "getapprovalslots " + A),
])
def test_read_rpcs_report_inactive(temp_database, mod, cmd):
    _activate(False)
    assert _err(mod.execute(cmd, None))["code"] == "FEATURE_INACTIVE"


# --- the inbox, in both directions ------------------------------------------

def test_the_inbox_holds_only_declared_approvers(temp_database):
    _activate()
    req = _request(approvers={18: AUTH})
    _persist(req)

    seen = _data(getapprovalrequests.execute("getapprovalrequests " + AUTH + " in", None))
    assert [r["request_id"] for r in seen["incoming"]] == [req.request_id_hex]

    # The scoping IS the point: an approver this amount does not need sees nothing.
    for other in (SCAN, PARTNER, STRANGER):
        empty = _data(getapprovalrequests.execute(
            "getapprovalrequests " + other + " in", None))
        assert empty["incoming"] == [], f"{other[:6]} should not be notified"


def test_outgoing_lists_the_senders_own_requests(temp_database):
    _activate()
    req = _request()
    _persist(req)
    mine = _data(getapprovalrequests.execute("getapprovalrequests " + A + " out", None))
    assert [r["request_id"] for r in mine["outgoing"]] == [req.request_id_hex]
    theirs = _data(getapprovalrequests.execute(
        "getapprovalrequests " + STRANGER + " out", None))
    assert theirs["outgoing"] == []


def test_approver_state_distinguishes_awaiting_approved_and_declined(temp_database):
    _activate()
    req = _request(approvers={18: AUTH, 19: SCAN, 20: PARTNER})
    _persist(req, votes=[
        TransferVote(request_id=req.request_id, voter_pubkey=AUTH, approve=True),
        TransferVote(request_id=req.request_id, voter_pubkey=SCAN, approve=False),
    ])
    row = _data(getapprovalrequests.execute(
        "getapprovalrequests " + AUTH + " in", None))["incoming"][0]
    assert row["approvers"]["18"]["state"] == "approved"
    assert row["approvers"]["19"]["state"] == "declined"
    assert row["approvers"]["20"]["state"] == "awaiting"


def test_custom_inputs_are_surfaced_to_the_approver(temp_database):
    """A comment to a partner is the point of the field."""
    _activate()
    req = _request(customs={26: "rent for Q3"})
    _persist(req)
    row = _data(getapprovalrequests.execute(
        "getapprovalrequests " + AUTH + " in", None))["incoming"][0]
    assert row["custom_inputs"]["26"] == "rent for Q3"


def test_a_bad_address_is_rejected(temp_database):
    _activate()
    assert _err(getapprovalrequests.execute("getapprovalrequests nothex", None))["code"] \
        == "INVALID_PARAMS"


def test_a_bad_role_is_rejected(temp_database):
    _activate()
    assert _err(getapprovalrequests.execute(
        "getapprovalrequests " + A + " sideways", None))["code"] == "INVALID_PARAMS"


# --- one request in full ----------------------------------------------------

def test_a_single_request_reports_who_is_still_holding_it_up(temp_database):
    _activate()
    req = _request(approvers={18: AUTH, 19: SCAN})
    _persist(req, votes=[TransferVote(request_id=req.request_id,
                                      voter_pubkey=AUTH, approve=True)])
    row = _data(getapprovalrequest.execute(
        "getapprovalrequest " + req.request_id_hex, None))
    assert row["awaiting_slots"] == [19]
    assert row["all_answered"] is False
    assert row["status"] == "open"


def test_an_unknown_request_is_reported(temp_database):
    _activate()
    _persist()
    assert _err(getapprovalrequest.execute(
        "getapprovalrequest " + "ab" * 32, None))["code"] == "REQUEST_UNKNOWN"


# --- the id calculator ------------------------------------------------------

def test_the_request_id_matches_the_canonical_computation(temp_database):
    req = _request()
    payload = json.dumps({
        "sender_pubkey": A, "recipient_pubkey": B, "amount": req.amount,
        "sequence_number": req.sequence_number,
        "expire_at_height": req.expire_at_height,
        "approvers": {"18": AUTH, "19": SCAN},
    })
    data = _data(getrequestid.execute("getrequestid " + payload, None))
    assert data["request_id"] == req.request_id_hex
    assert "shape_error" not in data


def test_the_id_calculator_reports_shape_problems_without_failing(temp_database):
    """The id is still well defined, and a client computing it up front may not
    have chosen an expiry height yet."""
    payload = json.dumps({
        "sender_pubkey": A, "recipient_pubkey": B, "amount": 5000,
        "sequence_number": 1, "expire_at_height": 0, "approvers": {},
    })
    data = _data(getrequestid.execute("getrequestid " + payload, None))
    assert data["request_id"]
    assert "at least one approver" in data["shape_error"]


def test_the_id_calculator_tolerates_quoted_json(temp_database):
    payload = json.dumps({
        "sender_pubkey": A, "recipient_pubkey": B, "amount": 5000,
        "sequence_number": 1, "expire_at_height": 900, "approvers": {"18": AUTH},
    })
    quoted = _data(getrequestid.execute("getrequestid '" + payload + "'", None))
    plain = _data(getrequestid.execute("getrequestid " + payload, None))
    assert quoted["request_id"] == plain["request_id"]


# --- advisory: who sits in which slot ---------------------------------------

def test_slots_are_read_from_the_registered_clause(temp_database):
    _activate()
    db.save_canonical_state_atomically(
        head_hash="h", head_num=1, balances={}, sequences={},
        application_rules="", consensus_rules="", active_consensus_id="",
        pending_updates=[], votes=[], scheduled=[], archival=[],
        rule_clauses=[{"acceptor_pubkey": A, "target_stream": 5, "clause_body": CLAUSE}],
        approval_slots_active=True,
    )
    data = _data(getapprovalslots.execute("getapprovalslots " + A, None))
    assert data["advisory"] is True
    assert data["has_clause"] is True
    assert data["slots"] == {"18": AUTH, "19": SCAN}


def test_an_unreadable_clause_returns_an_empty_map_not_an_error(temp_database):
    """Never consensus-binding, so an unrecognised shape must degrade, not fail:
    the client falls back to explicit flags."""
    _activate()
    db.save_canonical_state_atomically(
        head_hash="h", head_num=1, balances={}, sequences={},
        application_rules="", consensus_rules="", active_consensus_id="",
        pending_updates=[], votes=[], scheduled=[], archival=[],
        rule_clauses=[{"acceptor_pubkey": A, "target_stream": 5,
                       "clause_body": "(o5[t]:bv[24] = { #x000000 }:bv[24])"}],
        approval_slots_active=True,
    )
    data = _data(getapprovalslots.execute("getapprovalslots " + A, None))
    assert data["slots"] == {} and data["unreadable"] is True


def test_no_clause_at_all(temp_database):
    _activate()
    _persist()
    data = _data(getapprovalslots.execute("getapprovalslots " + A, None))
    assert data["has_clause"] is False and data["slots"] == {}


# --- advisory: which approvers does this transfer need ----------------------

def _draft(amount, approvers):
    return json.dumps({
        "sender_pubkey": A, "recipient_pubkey": B, "amount": amount,
        "approvers": {str(k): v for k, v in approvers.items()},
    })


def _fake_policy(**kwargs):
    """A tier-1 policy: over 1000 needs slot 18 filled with AUTH."""
    vals = kwargs.get("input_stream_values") or {}
    amount = int(str(vals.get(1, "0")) or 0)
    blocked = amount > 1000 and AUTH not in str(vals.get(18, "0"))
    return {1: str(amount), 5: "0" if blocked else "1"}


def test_the_preview_returns_the_minimal_required_set(temp_database):
    _activate()
    _persist()
    with patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_policy), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        data = _data(getapprovalpreview.execute(
            "getapprovalpreview " + _draft(5000, {18: AUTH, 19: SCAN}), None))
    assert data["required_slots"] == [18], data
    assert data["satisfiable"] is True
    assert data["needs_no_approval"] is False


def test_the_preview_says_when_no_approval_is_needed(temp_database):
    _activate()
    _persist()
    with patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_policy), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        data = _data(getapprovalpreview.execute(
            "getapprovalpreview " + _draft(500, {18: AUTH}), None))
    assert data["required_slots"] == [] and data["needs_no_approval"] is True


def test_the_preview_reports_an_unsatisfiable_policy(temp_database):
    """"Your own rule will never let this through" is exactly what a wallet wants
    to know before parking funds."""
    _activate()
    _persist()
    with patch("tau_manager.communicate_with_tau_multi",
               side_effect=lambda **k: {5: "0"}), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        data = _data(getapprovalpreview.execute(
            "getapprovalpreview " + _draft(5000, {18: AUTH}), None))
    assert data["satisfiable"] is False and data["required_slots"] is None


def test_the_preview_refuses_to_guess_above_the_subset_cap(temp_database):
    _activate()
    _persist()
    too_many = {18 + i: ("%02x" % (i + 1)) * 48 for i in range(MAX_PREVIEW_SLOTS + 1)}
    data = _data(getapprovalpreview.execute(
        "getapprovalpreview " + _draft(5000, too_many), None))
    assert data["available"] is False
    assert str(MAX_PREVIEW_SLOTS) in data["reason"]


def test_the_preview_needs_the_engine(temp_database):
    _activate()
    _persist()
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = False
        assert _err(getapprovalpreview.execute(
            "getapprovalpreview " + _draft(5000, {18: AUTH}), None))["code"] \
            == "TAU_UNAVAILABLE"


# --- gossip routing ---------------------------------------------------------
#
# Publishing to the wrong topic silently drops the transaction at EVERY peer,
# because each topic's handler enforces its own allow-list. That is exactly what
# used to happen to consensus_rule_vote. So the routing table and the snapshot
# set are asserted rather than assumed.

def test_approval_types_route_to_their_own_topic():
    from network.protocols import TAU_GOSSIP_TOPIC_APPROVALS
    from network.service import NetworkService

    for tx_type in ("approval_request", "transfer_vote"):
        assert NetworkService.topic_for_tx_type(tx_type) == TAU_GOSSIP_TOPIC_APPROVALS


def test_existing_routing_is_unchanged():
    from network.protocols import (
        TAU_GOSSIP_TOPIC_GOVERNANCE,
        TAU_GOSSIP_TOPIC_RULES,
        TAU_GOSSIP_TOPIC_TRANSACTIONS,
    )
    from network.service import NetworkService

    assert NetworkService.topic_for_tx_type("user_tx") == TAU_GOSSIP_TOPIC_TRANSACTIONS
    assert NetworkService.topic_for_tx_type("rule_offer") == TAU_GOSSIP_TOPIC_RULES
    assert NetworkService.topic_for_tx_type("consensus_rule_vote") == TAU_GOSSIP_TOPIC_GOVERNANCE
    assert NetworkService.topic_for_tx_type(None) == TAU_GOSSIP_TOPIC_TRANSACTIONS


def test_approval_types_are_in_the_mempool_snapshot_set():
    """Missing from here and a newly connected peer never learns about a parked
    request until it is mined -- which for a vote is too late to matter."""
    from network.service import _SNAPSHOT_TX_TYPES

    assert {"approval_request", "transfer_vote"} <= _SNAPSHOT_TX_TYPES


def test_the_approvals_topic_has_its_own_byte_caps_and_quota():
    from network import protocols

    assert protocols.TAU_MAX_APPROVAL_REQUEST_BYTES > 0
    assert protocols.TAU_MAX_TRANSFER_VOTE_BYTES > 0
    # A vote is small; a request carries an approver map and custom inputs.
    assert protocols.TAU_MAX_TRANSFER_VOTE_BYTES < protocols.TAU_MAX_APPROVAL_REQUEST_BYTES
    assert protocols.TAU_MEMPOOL_SNAPSHOT_MAX_APPROVAL_TXS > 0


def test_the_gossip_handler_exists_and_is_bound_to_the_topic():
    import inspect

    from network.service import NetworkService

    assert hasattr(NetworkService, "_on_approval_gossip")
    src = inspect.getsource(NetworkService)
    # Joined at startup, or the node publishes to a topic nobody listens on.
    assert "join_topic(TAU_GOSSIP_TOPIC_APPROVALS, self._on_approval_gossip)" in src
