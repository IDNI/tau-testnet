"""Block-apply semantics for approval requests and votes.

Design constraints these tests encode:

- Signatures are verified AT APPLY for these types. Everywhere else in the chain
  they are checked at mempool admission only, which is tolerable for an ordinary
  transfer (forging one forges a transfer the sender could have made anyway) but
  not for a feature whose promise is independent co-signatures: a malicious
  proposer could otherwise mint a vote bearing an approver's pubkey. The forged
  transactions here carry REAL BLS keys and a genuinely invalid signature.
- A forged transaction is discarded but the BLOCK STAYS VALID. Every node reaches
  that verdict from the block bytes alone, so there is no fork risk and no new
  block-rejection path.
- Votes are evaluated PROSPECTIVELY and committed after, because hard_reject
  suppresses staged balances and nonces but does not roll back lifecycle
  mutations.
- A decline does not resolve the request. Otherwise an over-declared approver
  holds a veto and the declared approver list becomes authority rather than
  routing.
"""
import hashlib
import itertools

import pytest
from unittest.mock import patch
from py_ecc.bls import G2Basic

from block import Block
from consensus.approvals import (
    STATUS_EXECUTED,
    STATUS_FAILED,
    ApprovalRequest,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
TIER_1 = 1000          # the fake policy blocks above this without slot 18


def _key(seed: int):
    sk = seed
    return sk, G2Basic.SkToPk(sk).hex()


SK_ALICE, ALICE = _key(11111)
SK_AUTH, AUTH = _key(22222)
SK_SCAN, SCAN = _key(33333)
SK_BOB, BOB = _key(44444)          # recipient
SK_STRANGER, STRANGER = _key(55555)

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def _request(amount=5000, seq=0, approvers=None, customs=None, expire=EXPIRE):
    return ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=amount,
        sequence_number=seq, expire_at_height=expire,
        approvers=approvers if approvers is not None else {18: AUTH, 19: SCAN},
        custom_inputs=customs or {},
    )


def request_tx(request=None, sk=SK_ALICE, sender=None, forge=False):
    req = request or _request()
    tx = {
        "tx_id": f"req-{next(_TX_SEQ)}",
        "tx_type": "approval_request",
        "sender_pubkey": sender or req.sender_pubkey,
        "sequence_number": req.sequence_number,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "recipient_pubkey": req.recipient_pubkey,
        "amount": req.amount,
        "expire_at_height": req.expire_at_height,
        "approvers": {str(k): v for k, v in req.approvers.items()},
        "custom_inputs": {str(k): v for k, v in req.custom_inputs.items()},
    }
    _sign(tx, sk)
    if forge:
        # A signature that is well-formed and verifies against nobody: signed by
        # a different key than the one claimed.
        _sign(dict(tx), SK_STRANGER)
        tx["signature"] = G2Basic.Sign(SK_STRANGER, hashlib.sha256(
            signing_message_bytes(tx)).digest()).hex()
    return tx


def vote_tx(request, voter=AUTH, sk=SK_AUTH, approve=True, forge=False, reason="",
            seq=0):
    tx = {
        "tx_id": f"vote-{next(_TX_SEQ)}",
        "tx_type": "transfer_vote",
        "sender_pubkey": voter,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "fee_limit": "0",
        "request_id": request.request_id_hex,
        "approve": approve,
    }
    if reason:
        tx["reason"] = reason
    _sign(tx, SK_STRANGER if forge else sk)
    return tx


def _lm(active=True, balances=None):
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    if active:
        lm.activate_approval_slots()
    return lm


def _apply(txs, lm=None, height=HEIGHT, balances=None):
    """Apply a block and return (result, post_lifecycle_manager, tau_calls).

    The fake engine emulates a tier-1 co-signature policy: any amount over
    TIER_1 is blocked unless approval slot i18 carries AUTH's pubkey.
    """
    lm = lm if lm is not None else _lm()
    bal = balances if balances is not None else {ALICE: 100000, AUTH: 10, SCAN: 10, BOB: 0}
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": dict(bal),
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    active_view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(ALICE)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block_obj = Block.create(
        block_number=height, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=ALICE, timestamp=1234567890,
    )

    calls = []

    def _fake_multi(**kwargs):
        calls.append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        slot18 = str(vals.get(18, "0"))
        blocked = amount > TIER_1 and AUTH not in slot18
        out = {1: str(amount), 8: "0", 9: "0"}
        out[5] = "0" if blocked else "1"
        return out

    single_calls = []

    def _fake_single(**kwargs):
        single_calls.append(kwargs)
        return "T"

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", side_effect=_fake_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply_block(active_view, block_obj, parent_snapshot)

    _apply.single_calls = single_calls
    return result, result.next_snapshot.metadata["lifecycle_manager"], calls


def _logs(result):
    out = []
    for outcome in result.outcomes:
        out.extend(outcome.receipt_logs or [])
    return " | ".join(str(x) for x in out)


def _balances(result):
    return result.next_snapshot.metadata["balances"]


# --- requests ---------------------------------------------------------------

def test_a_request_is_parked():
    req = _request()
    result, lm, _ = _apply([request_tx(req)])
    entry = lm.approval_requests.get_request(req.request_id)
    assert entry is not None
    assert entry.amount == req.amount
    assert entry.approvers == {18: AUTH, 19: SCAN}
    assert "Approval request parked" in _logs(result)


def test_a_request_the_policy_does_not_gate_is_refused():
    """Parking it would strand funds behind approvers the policy never asks for."""
    req = _request(amount=500)          # below TIER_1, so the fake policy allows
    result, lm, _ = _apply([request_tx(req)])
    assert lm.approval_requests.get_request(req.request_id) is None
    assert "allows this transfer with no votes" in _logs(result)


def test_parking_charges_exactly_one_fee_measurement():
    """The request prices itself with the REAL transfer inputs, so the generic
    transfer-less fee step (canonical mocked i1=i2=i3=i4=0) must not also run."""
    req = _request()
    _, _, calls = _apply([request_tx(req)])
    amounts = [str((c.get("input_stream_values") or {}).get(1)) for c in calls]
    assert amounts.count(str(req.amount)) == 1, calls
    assert "0" not in amounts, "the mocked fee-query step must not run as well"


def test_a_forged_request_is_discarded_but_the_block_stays_valid():
    req = _request()
    result, lm, _ = _apply([request_tx(req, forge=True)])
    assert lm.approval_requests.get_request(req.request_id) is None
    assert "signature invalid" in _logs(result)
    assert result.next_snapshot is not None, "the block still applies"


def test_requests_are_ignored_before_activation():
    req = _request()
    result, lm, _ = _apply([request_tx(req)], lm=_lm(active=False))
    assert lm.approval_requests.get_request(req.request_id) is None
    assert "not active" in _logs(result)


# --- votes and release ------------------------------------------------------

def test_an_approving_vote_releases_the_transfer():
    req = _request()
    result, lm, _ = _apply([request_tx(req), vote_tx(req)])

    assert lm.approval_requests.get_request(req.request_id) is None
    assert lm.approval_requests.terminal_status[req.request_id] == STATUS_EXECUTED
    assert "Parked transfer executed" in _logs(result)
    bal = _balances(result)
    assert bal[BOB] == req.amount
    assert bal[ALICE] == 100000 - req.amount


def test_the_released_transfer_stamps_the_senders_transfer_history():
    """The generic site keys off this tx's signer (the approver) and its transfer
    list (empty for a vote), so it would skip a released transfer entirely."""
    req = _request()
    result, _, _ = _apply([request_tx(req), vote_tx(req)])
    stamps = result.next_snapshot.metadata.get("last_transfer_ts") or {}
    assert stamps.get(ALICE) == 1234567890
    assert AUTH not in stamps, "the approver did not make a transfer"


def test_a_forged_vote_neither_records_nor_releases():
    req = _request()
    result, lm, _ = _apply([request_tx(req), vote_tx(req, forge=True)])
    entry = lm.approval_requests.get_request(req.request_id)
    assert entry is not None, "the request must still be open"
    assert entry.voted == {}, "a forged vote must not be recorded"
    assert _balances(result)[BOB] == 0, "and must not move funds"
    assert "signature invalid" in _logs(result)


def test_an_undeclared_account_cannot_vote():
    req = _request()
    forged_voter = vote_tx(req, voter=STRANGER, sk=SK_STRANGER)
    result, lm, _ = _apply([request_tx(req), forged_voter])
    entry = lm.approval_requests.get_request(req.request_id)
    assert entry.voted == {}
    assert "only a declared approver" in _logs(result)


def test_a_decline_does_not_resolve_the_request():
    """The declared list is routing, not authority: an approver the policy does
    not need must not be able to kill the request."""
    req = _request()
    result, lm, _ = _apply([request_tx(req),
                            vote_tx(req, voter=SCAN, sk=SK_SCAN, approve=False,
                                    reason="unknown recipient")])
    entry = lm.approval_requests.get_request(req.request_id)
    assert entry is not None, "still open"
    assert entry.declined == {19}
    assert _balances(result)[BOB] == 0


def test_a_decline_then_the_needed_approval_still_releases():
    req = _request()
    result, lm, _ = _apply([
        request_tx(req),
        vote_tx(req, voter=SCAN, sk=SK_SCAN, approve=False),
        vote_tx(req, voter=AUTH, sk=SK_AUTH, approve=True),
    ])
    assert lm.approval_requests.terminal_status[req.request_id] == STATUS_EXECUTED
    assert _balances(result)[BOB] == req.amount


def test_all_answered_and_still_blocked_fails_the_request():
    req = _request()
    result, lm, _ = _apply([
        request_tx(req),
        vote_tx(req, voter=AUTH, sk=SK_AUTH, approve=False),
        vote_tx(req, voter=SCAN, sk=SK_SCAN, approve=False),
    ])
    assert lm.approval_requests.get_request(req.request_id) is None
    assert lm.approval_requests.terminal_status[req.request_id] == STATUS_FAILED
    assert "still blocks" in _logs(result)
    assert _balances(result)[BOB] == 0


def test_a_vote_at_the_expiry_height_is_ignored():
    """process_height_transitions runs AFTER this loop, so the sweep cannot stop
    a vote included at exactly the expiry height."""
    req = _request(expire=HEIGHT)
    result, lm, _ = _apply([vote_tx(req)], lm=_seeded(req))
    assert "expired" in _logs(result)
    assert _balances(result)[BOB] == 0


def _seeded(req, active=True):
    lm = _lm(active=active)
    lm.approval_requests.submit_request(req)
    return lm


def test_release_with_insufficient_funds_fails_the_request_softly():
    """Nothing is escrowed, so the sender may have spent the money meanwhile.
    The VOTE was valid and stands; the request cannot be honoured."""
    req = _request(amount=5000)
    lm = _seeded(req)
    result, post, _ = _apply([vote_tx(req)], lm=lm,
                             balances={ALICE: 10, AUTH: 10, SCAN: 10, BOB: 0})
    assert post.approval_requests.get_request(req.request_id) is None
    assert post.approval_requests.terminal_status[req.request_id] == STATUS_FAILED
    assert _balances(result)[BOB] == 0
    assert _balances(result)[ALICE] == 10, "no partial movement"


def test_one_vote_per_approver_at_apply():
    """Uses SCAN, whose slot the fake policy does not need: an approving vote
    from AUTH would release and resolve the request, so the second vote would
    report "already resolved" rather than exercising the per-approver guard.

    Two votes from one signer in a block also need increasing sequence numbers,
    or the second is rejected on the nonce before it is ever seen.
    """
    req = _request()
    result, lm, _ = _apply([
        request_tx(req),
        vote_tx(req, voter=SCAN, sk=SK_SCAN, approve=True),
        vote_tx(req, voter=SCAN, sk=SK_SCAN, approve=True, seq=1),
    ])
    assert "already voted" in _logs(result)
    entry = lm.approval_requests.get_request(req.request_id)
    assert entry is not None and entry.voted == {19: SCAN}


def test_a_vote_after_resolution_is_ignored():
    req = _request()
    result, lm, _ = _apply([
        request_tx(req),
        vote_tx(req, voter=AUTH, sk=SK_AUTH, approve=True),   # releases it
        vote_tx(req, voter=SCAN, sk=SK_SCAN, approve=True),
    ])
    assert "already resolved" in _logs(result)


def test_votes_are_ignored_before_activation():
    req = _request()
    result, lm, _ = _apply([vote_tx(req)], lm=_seeded(req, active=False))
    assert "not active" in _logs(result)


# --- routing an o5 policy rule into the clause registry ---------------------

TIER_CLAUSE_BODY = (
    "( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && "
    "!(i18[t]:bv[384] = { #x" + AUTH + " }:bv[384])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )"
)
UNGUARDED_RULE = "always ( %s )." % TIER_CLAUSE_BODY
GUARDED_RULE = (
    "always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
NEUTRAL_RULE = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."


def rule_tx(rule, sk=SK_ALICE, sender=None, seq=0):
    tx = {
        "tx_id": f"rule-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender or ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "operations": {"0": rule},
    }
    return _sign(tx, sk)


def _composite_feeds():
    return [c for c in _apply.single_calls if "always" in str(c.get("rule_text", ""))]


def test_an_o5_rule_registers_a_clause_instead_of_accumulating():
    result, lm, _ = _apply([rule_tx(UNGUARDED_RULE)])
    assert lm.rule_offers.clause_for(ALICE, 5) is not None
    logs = _logs(result)
    assert "o5 clause registered" in logs
    assert "Rule applied" not in logs, "it must not take the accumulation path"


def test_the_registered_clause_is_composed_with_the_sender_guard():
    _apply([rule_tx(UNGUARDED_RULE)])
    feeds = _composite_feeds()
    assert feeds, "a composite must be fed"
    text = str(feeds[-1]["rule_text"])
    assert ALICE in text, "the node supplies the i12 guard"
    assert "i18[t]:bv[384]" in text
    # Never accumulated: save_effective_tau_spec dedups exact units only, so
    # appending regenerated composites would leave every earlier one in place.
    assert feeds[-1].get("apply_rules_update") is False


def test_the_old_guarded_form_is_ignored_softly():
    result, lm, _ = _apply([rule_tx(GUARDED_RULE)])
    assert lm.rule_offers.clause_for(ALICE, 5) is None
    assert "o5 clause ignored" in _logs(result)


def test_revocation_removes_the_clause_and_feeds_a_neutral_composite():
    """Feeding nothing would leave the previous composite in force on a running
    interpreter while a restarted node allowed the transfer -- one block, two
    verdicts."""
    lm = _lm()
    result, post, _ = _apply([rule_tx(UNGUARDED_RULE), rule_tx(NEUTRAL_RULE, seq=1)], lm=lm)
    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert "o5 clause revoked" in _logs(result)
    text = str(_composite_feeds()[-1]["rule_text"])
    assert "o5[t]:bv[24] = { #x000001 }:bv[24]" in text
    assert ALICE not in text, "nobody is guarded any more"


def test_revoking_nothing_is_a_no_op():
    result, lm, _ = _apply([rule_tx(NEUTRAL_RULE)])
    assert "nothing registered" in _logs(result)


def test_a_policy_change_fails_that_senders_open_requests():
    """A request snapshots its approvers but re-evaluates the CURRENT clause."""
    req = _request()
    lm = _lm()
    lm.rule_offers.accepted_clauses[(ALICE, 5)] = TIER_CLAUSE_BODY
    lm.approval_requests.submit_request(req)
    result, post, _ = _apply([rule_tx(NEUTRAL_RULE)], lm=lm)
    assert post.approval_requests.get_request(req.request_id) is None
    assert post.approval_requests.terminal_status[req.request_id] == STATUS_FAILED
    assert "failed 1 open approval request" in _logs(result)


def test_another_senders_requests_are_untouched_by_a_policy_change():
    mine = _request(seq=0)
    lm = _lm()
    lm.rule_offers.accepted_clauses[(ALICE, 5)] = TIER_CLAUSE_BODY
    lm.approval_requests.submit_request(mine)
    result, post, _ = _apply([rule_tx(NEUTRAL_RULE, sk=SK_SCAN, sender=SCAN)], lm=lm)
    assert post.approval_requests.get_request(mine.request_id) is not None


def test_the_author_cap_is_enforced_at_apply():
    from consensus.approvals import MAX_TIER_AUTHORS

    lm = _lm()
    for i in range(MAX_TIER_AUTHORS):
        lm.rule_offers.accepted_clauses[(("%02x" % (i + 1)) * 48, 5)] = TIER_CLAUSE_BODY
    result, post, _ = _apply([rule_tx(UNGUARDED_RULE)], lm=lm)
    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert "registry full" in _logs(result)


def test_an_existing_author_may_replace_when_full():
    from consensus.approvals import MAX_TIER_AUTHORS

    lm = _lm()
    lm.rule_offers.accepted_clauses[(ALICE, 5)] = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
    for i in range(MAX_TIER_AUTHORS - 1):
        lm.rule_offers.accepted_clauses[(("%02x" % (i + 1)) * 48, 5)] = TIER_CLAUSE_BODY
    result, post, _ = _apply([rule_tx(UNGUARDED_RULE)], lm=lm)
    assert post.rule_offers.clause_for(ALICE, 5) == TIER_CLAUSE_BODY


def test_routing_is_inactive_before_activation():
    result, lm, _ = _apply([rule_tx(GUARDED_RULE)], lm=_lm(active=False))
    assert lm.rule_offers.clause_for(ALICE, 5) is None
    assert "Rule applied" in _logs(result), "the ordinary accumulation path runs"


def test_slot_values_are_fed_as_wrapped_bv384_literals():
    """The WIRE SHAPE matters, and a mocked engine cannot tell you so.

    tau_shrink interns the bv[384] pubkey literals inside a clause down to bv[8]
    ids, and it recognises a value to intern by the `{ #x.. }:bv[384]` shape that
    i3/i4/i12 are fed in. Fed as bare hex, an approver's key skips interning and a
    384-bit constant lands on a bv[8] stream: "overflow in bit-vector
    construction", the block fails simulation, and block production wedges with
    MINING_BUSY forever.

    The substring-matching fake in this file passes either way, which is exactly
    how the bug survived to a live node.
    """
    req = _request()
    lm = _seeded(req)
    _result, _post, calls = _apply([vote_tx(req)], lm=lm)

    slot_feeds = [
        (k, v)
        for c in calls
        for k, v in (c.get("input_stream_values") or {}).items()
        if isinstance(k, int) and 18 <= k <= 25 and str(v) != "0"
    ]
    assert slot_feeds, "a voted slot should have been fed"
    for slot, value in slot_feeds:
        assert value.startswith("{ #x"), (slot, value)
        assert value.endswith("}:bv[384]"), (slot, value)
        assert AUTH in value


def test_unvoted_slots_are_fed_as_plain_zero():
    """0 is the intern store's reserved 'empty' id, and it needs no wrapper."""
    req = _request()
    lm = _seeded(req)
    _result, _post, calls = _apply([vote_tx(req)], lm=lm)
    zeros = [
        v for c in calls
        for k, v in (c.get("input_stream_values") or {}).items()
        if isinstance(k, int) and 18 <= k <= 25 and str(v) == "0"
    ]
    assert zeros, "unvoted slots should be fed 0"
