"""Approval-request state survives a restart with a byte-identical meta hash.

The request book -- including which approvers have voted -- is bound into
`consensus_meta_hash`. If it fails to round-trip through `commit_state_to_db` /
`load_state_from_db`, a restarted node computes a different state hash than a
peer replaying from genesis and the next block it mines is rejected by everyone.

`voted` matters most here: it decides whether the parked transfer executes, so
losing it on restart would let a node disagree with its peers about which
approvers have signed. The decline *reason* is the counterpart -- node-local
colour that must NOT affect the hash.
"""
import chain_state
from consensus.approvals import (
    STATUS_EXECUTED,
    STATUS_EXPIRED,
    STATUS_FAILED,
    ApprovalRequest,
    TransferVote,
)
from consensus.governance import ConsensusLifecycleManager

A = "1a" * 48        # sender
B = "2b" * 48        # recipient
AUTH = "aa" * 48
SCAN = "bb" * 48
PARTNER = "cc" * 48


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


def _request(sender=A, amount=200000, seq=1, expire=500, approvers=None, customs=None):
    return ApprovalRequest(
        sender_pubkey=sender,
        recipient_pubkey=B,
        amount=amount,
        sequence_number=seq,
        expire_at_height=expire,
        approvers=approvers if approvers is not None else {18: AUTH, 19: SCAN, 20: PARTNER},
        custom_inputs=customs if customs is not None else {26: "rent Q3"},
    )


def _reload():
    """Commit, clobber the manager as a restart would, then reload."""
    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


def test_open_request_round_trips(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    req = _request()
    assert lm.approval_requests.submit_request(req) is True
    before = lm.consensus_meta_hash()

    reloaded = _reload()
    entry = reloaded.approval_requests.get_request(req.request_id)
    assert entry is not None
    assert entry.sender_pubkey == A
    assert entry.recipient_pubkey == B
    assert entry.amount == 200000
    assert entry.expire_at_height == 500
    assert entry.approvers == {18: AUTH, 19: SCAN, 20: PARTNER}
    assert entry.custom_inputs == {26: "rent Q3"}
    assert reloaded.consensus_meta_hash() == before


def test_recorded_votes_round_trip(temp_database):
    """The votes are what release the funds, so they must survive verbatim."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    req = _request()
    lm.approval_requests.submit_request(req)
    lm.approval_requests.commit_vote(
        TransferVote(request_id=req.request_id, voter_pubkey=AUTH, approve=True))
    lm.approval_requests.commit_vote(
        TransferVote(request_id=req.request_id, voter_pubkey=SCAN, approve=False,
                     reason="recipient never seen before"))
    before = lm.consensus_meta_hash()

    reloaded = _reload()
    entry = reloaded.approval_requests.get_request(req.request_id)
    assert entry.voted == {18: AUTH}, "the YES vote must survive"
    assert entry.declined == {19}, "the decline must survive, so all_answered stays decidable"
    assert entry.slot_values()[18] == AUTH
    assert entry.slot_values()[19] == "0", "a decline never fills its slot"
    assert reloaded.consensus_meta_hash() == before


def test_decline_reason_is_not_hash_bound(temp_database):
    """The reason is signed and inside the block merkle root, but carries no
    consensus meaning, so it must not move the state hash."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    req = _request()
    lm.approval_requests.submit_request(req)
    lm.approval_requests.commit_vote(
        TransferVote(request_id=req.request_id, voter_pubkey=AUTH, approve=False, reason="one"))
    with_reason = lm.consensus_meta_hash()

    lm2 = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm2.activate_approval_slots()
    lm2.approval_requests.submit_request(_request())
    lm2.approval_requests.commit_vote(
        TransferVote(request_id=req.request_id, voter_pubkey=AUTH, approve=False,
                     reason="a completely different explanation"))
    assert lm2.consensus_meta_hash() == with_reason


def test_terminal_requests_round_trip(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    executed = _request(seq=1)
    expired = _request(seq=2)
    failed = _request(seq=3)
    for r in (executed, expired, failed):
        lm.approval_requests.submit_request(r)
    lm.approval_requests.resolve(executed.request_id, STATUS_EXECUTED)
    lm.approval_requests.resolve(expired.request_id, STATUS_EXPIRED)
    lm.approval_requests.resolve(failed.request_id, STATUS_FAILED)
    before = lm.consensus_meta_hash()

    reloaded = _reload()
    assert reloaded.approval_requests.open_requests == {}
    assert reloaded.approval_requests.resolved == {
        executed.request_id, expired.request_id, failed.request_id}
    assert reloaded.consensus_meta_hash() == before
    # Resolved history stays queryable by address (rule_offers blanks it -- see
    # the playbook's open items; this table deliberately does not).
    rows = {r["request_id"]: r for r in reloaded.approval_requests.snapshot_requests()}
    assert rows[executed.request_id.hex()]["sender_pubkey"] == A


def test_activation_flag_round_trips(temp_database):
    """A restart must not silently un-reserve i18..i25."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.approval_slots_active is True
    assert reloaded.consensus_meta_hash() == before


def test_inactive_empty_state_round_trips(temp_database):
    """The whole feature off must be byte-identical to a node without it."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    assert lm.approval_requests.is_empty()
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.approval_slots_active is False
    assert reloaded.approval_requests.is_empty()
    assert reloaded.consensus_meta_hash() == before


def test_malformed_rows_are_skipped(temp_database):
    """A junk row must not take the node down on boot."""
    import db

    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    req = _request()
    lm.approval_requests.submit_request(req)
    chain_state.commit_state_to_db("head-hash", 20)

    with db._db_lock:
        with db._db_conn:
            db._db_conn.execute(
                "INSERT OR REPLACE INTO approval_requests_v1 "
                "(request_id, sender_pubkey, recipient_pubkey, amount, "
                "expire_at_height, approvers_json, custom_inputs_json, voted_json, "
                "declined_json, status) VALUES "
                "('not-hex', ?, ?, 1, 2, '{}', '{}', '{}', '[]', 0)", (A, B))
            db._db_conn.execute(
                "INSERT OR REPLACE INTO approval_requests_v1 "
                "(request_id, sender_pubkey, recipient_pubkey, amount, "
                "expire_at_height, approvers_json, custom_inputs_json, voted_json, "
                "declined_json, status) VALUES "
                "('abcd', ?, ?, 1, 2, '{}', '{}', '{}', '[]', 0)", (A, B))

    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    lm2 = chain_state._lifecycle_manager
    assert set(lm2.approval_requests.open_requests) == {req.request_id}
