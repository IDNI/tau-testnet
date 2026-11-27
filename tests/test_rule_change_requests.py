"""rule_change_request and rule_change_cancel: parse and id, admission, apply,
the shared request cap, fees, cancellation, expiry, state root, persistence,
fork isolation and signatures."""
import copy
from unittest.mock import MagicMock, patch

import pytest

import chain_state
import tau_defs
from block import Block
from bls_keys import FAR_FUTURE, SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_tx
from consensus import engine as engine_module
from consensus.admission import TipAdmissionView, validate_mempool_admission
from consensus.approvals import (
    MAX_APPROVERS_PER_REQUEST,
    MAX_PENDING_REQUESTS_PER_SENDER,
    MAX_RULE_CHANGE_TEXT_BYTES,
    STATUS_CANCELLED,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_OPEN,
    ApprovalRequest,
    ApprovalRequestLifecycleManager,
    RuleChangeRequest,
    TransferVote,
    parse_rule_change_cancel,
    parse_rule_change_request,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus import sender_policy
from consensus.policy_mock import MockPolicyEvaluator
from consensus.lanes import LANE_FAST, LANE_SLOW, TAU_EVALUATING_TX_TYPES, classify_lane
from consensus.rule_offers import (
    NEUTRAL_O5_CLAUSE_BODY,
    STATUS_OFFERED,
    RuleOffer,
)
from consensus.serialization import compute_approval_request_book_root
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)
MALLORY = pubkey_hex(SK_MALLORY)

_ON = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
_OFF = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
SET_TEXT = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
OTHER_TEXT = "always ( o5[t]:bv[24] = { #x000002 }:bv[24] )."
GUARD_TEXT = (
    "always ( (i18[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]) ? "
    f"{_ON} : {_OFF} )."
)
BAD_POLICY_TEXT = f"always ( (i13[t]:bv[24] = {{ #x000001 }}:bv[24]) ? {_ON} : {_OFF} )."
BAD_GUARD_TEXT = f"always ( (i2[t]:bv[24] = {{ #x000001 }}:bv[24]) ? {_ON} : {_OFF} )."
OFFER_TEXT = "always ( o5[t]:bv[24] = { #x000003 }:bv[24] )."
GUARD_KEY = (ALICE, tau_defs.RULE_CHANGE_GUARD_INDEX)
POLICY_KEY = (ALICE, tau_defs.USER_POLICY_STREAM_INDEX)

KIND_SET = tau_defs.RULE_CHANGE_KIND_SET_POLICY
KIND_REVOKE = tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY
KIND_ACCEPT = tau_defs.RULE_CHANGE_KIND_ACCEPT_OFFER
KIND_SET_GUARD = tau_defs.RULE_CHANGE_KIND_SET_GUARD
KIND_REVOKE_GUARD = tau_defs.RULE_CHANGE_KIND_REVOKE_GUARD

OFFER = RuleOffer(offerer_pubkey=MALLORY, recipient_pubkey=ALICE,
                  rule_text=OFFER_TEXT, expire_at_height=EXPIRE)
OFFER_ID = OFFER.offer_id_hex


def _request(kind=KIND_SET, *, sender=ALICE, seq=0, text=None, offer_id="",
             approvers=None, expire=EXPIRE):
    if text is None:
        text = {KIND_SET: SET_TEXT, KIND_SET_GUARD: GUARD_TEXT,
                KIND_ACCEPT: OFFER_TEXT}.get(kind, "")
    if kind == KIND_ACCEPT and not offer_id:
        offer_id = OFFER_ID
    return RuleChangeRequest(
        sender_pubkey=sender, sequence_number=seq, kind=kind, rule_text=text,
        offer_id=offer_id, approvers=approvers if approvers is not None else {18: BOB},
        expire_at_height=expire,
    )


def _tx(req, *, sk=SK_ALICE, tx_id=None, fee_limit="100", signer=None):
    tx = {
        "tx_id": tx_id or f"rc-{req.sequence_number}-{req.kind}",
        "tx_type": "rule_change_request",
        "sender_pubkey": signer or req.sender_pubkey,
        "sequence_number": req.sequence_number,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": req.expire_at_height,
        "fee_limit": fee_limit,
        "kind": req.kind,
        "approvers": {str(k): v for k, v in req.approvers.items()},
    }
    if req.rule_text:
        tx["rule_text"] = req.rule_text
    if req.offer_id:
        tx["offer_id"] = req.offer_id
    return sign_tx(tx, sk)


def _cancel_tx(request_id, *, sender=ALICE, sk=SK_ALICE, seq=0, tx_id="cancel",
               fee_limit="0"):
    return sign_tx({
        "tx_id": tx_id,
        "tx_type": "rule_change_cancel",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "request_id": request_id.hex() if isinstance(request_id, bytes) else request_id,
    }, sk)


GUARD_BODY = GUARD_TEXT[len("always ( "):-3]


@pytest.fixture(autouse=True)
def evaluators():
    """The seeded guard blocks every change, so a request parks."""
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(GUARD_BODY, "0")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _lm(*, slots=True, guard=False, policy=False, offer=False):
    lm = ConsensusLifecycleManager(active_validators=[MALLORY])
    if slots:
        lm.activate_approval_slots()
    if guard:
        lm.rule_offers.accepted_clauses[GUARD_KEY] = GUARD_TEXT[len("always ( "):-3]
    if policy:
        lm.rule_offers.accepted_clauses[POLICY_KEY] = _OFF
    if offer:
        assert lm.rule_offers.submit_offer(OFFER)
    return lm


def _apply(txs, lm=None, *, height=HEIGHT, fee=0, balances=None, sequences=None):
    lm = lm if lm is not None else _lm()
    txs = txs if isinstance(txs, list) else [txs]
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": dict(balances or {ALICE: 100000, MALLORY: 100000, BOB: 0}),
            "sequence_numbers": dict(sequences or {}),
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={
            "poa": True, "approval_slots_active": lm.approval_slots_active is True},
    )
    block = Block.create(block_number=height, previous_hash="00" * 32, transactions=txs,
                         proposer_pubkey=MALLORY, timestamp=1234567890)
    persisted = []

    def _single(**kw):
        text = str(kw.get("rule_text") or "")
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def _multi(**kw):
        return {1: "0", 5: "1", 8: "0", 9: str(fee)}

    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = TauConsensusEngine().apply_block(view, block, parent)
    meta = result.next_snapshot.metadata
    return result, meta["lifecycle_manager"], meta


def _outcome(result, tx_id):
    return next(o for o in result.outcomes if o.tx_id == tx_id)


def _logs(result):
    return " | ".join(str(x) for o in result.outcomes for x in (o.receipt_logs or []))


def _view(lm, height=50):
    """An admission view that answers from `lm`, as the tip tables would."""
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = height
    view.eligibility_mode = ""
    view.approval_slots_active = lm.approval_slots_active is True
    approvals = lm.approval_requests

    def _rc_row(rid):
        entry = approvals.rule_change_requests.get(bytes.fromhex(rid))
        if entry is None:
            return None
        return {"request_id": rid, "sender_pubkey": entry.sender_pubkey,
                "kind": entry.kind, "expire_at_height": entry.expire_at_height,
                "status": entry.status, "approvers": dict(entry.approvers),
                "voted": dict(entry.voted), "declined": sorted(entry.declined),
                "ready": entry.ready, "created_height": entry.created_height}

    def _offer_row(oid):
        entry = lm.rule_offers.offered.get(bytes.fromhex(oid))
        if entry is None:
            return None
        return {"offer_id": oid, "offerer_pubkey": entry.offerer_pubkey,
                "recipient_pubkey": entry.recipient_pubkey,
                "expire_at_height": entry.expire_at_height, "status": STATUS_OFFERED}

    view.clause_for.side_effect = (
        lambda who, idx: lm.rule_offers.accepted_clauses.get((who, idx)))
    view.get_rule_change_request.side_effect = _rc_row
    view.get_offer.side_effect = _offer_row
    view.get_approval_request.return_value = None
    view.open_requests_for_sender.side_effect = approvals.pending_count_for_sender
    view.open_requests_for_approver.side_effect = approvals.pending_count_for_approver
    return view


def _admit(tx, lm):
    return validate_mempool_admission(tx, _view(lm))


# --- parse and id --------------------------------------------------------------

def test_a_well_formed_request_parses_with_a_deterministic_id():
    tx = _tx(_request())
    parsed = parse_rule_change_request(tx)
    assert parsed is not None
    assert parsed.request_id == _request().request_id
    assert len(parsed.request_id) == 32


def test_every_field_changes_the_id():
    base = _request()
    variants = {
        "sender": _request(sender=CAROL),
        "sequence": _request(seq=1),
        "kind": _request(KIND_SET_GUARD, text=SET_TEXT),
        "body": _request(text=OTHER_TEXT),
        "offer_id": _request(KIND_ACCEPT),
        "offer_id_2": _request(KIND_ACCEPT, offer_id="ab" * 32),
        "approver_added": _request(approvers={18: BOB, 19: CAROL}),
        "approver_slot": _request(approvers={19: BOB}),
        "approver_key": _request(approvers={18: CAROL}),
        "approvers_none": _request(approvers={}),
        "expire": _request(expire=EXPIRE + 1),
    }
    ids = {name: v.request_id for name, v in variants.items()}
    ids["base"] = base.request_id
    assert len(set(ids.values())) == len(ids)


def test_the_id_binds_the_normalized_body_not_its_spelling():
    spaced = _request(text="  always (  o5[t]:bv[24]  =  { #x000000 }:bv[24] ) .  # note\n")
    assert spaced.body == _request().body
    assert spaced.request_id == _request().request_id
    assert _request(text=OTHER_TEXT).body_hash != _request().body_hash


def test_kinds_without_a_body_hash_the_empty_string():
    from consensus.serialization import compute_rule_change_body_hash

    assert _request(KIND_REVOKE).body == ""
    assert _request(KIND_REVOKE).body_hash == compute_rule_change_body_hash("")


@pytest.mark.parametrize("mutate", [
    lambda t: t.update(kind=0),
    lambda t: t.update(kind=6),
    lambda t: t.update(kind=True),
    lambda t: t.update(kind="1"),
    lambda t: t.update(sequence_number="0"),
    lambda t: t.update(rule_text=""),
    lambda t: t.pop("rule_text"),
    lambda t: t.update(rule_text=7),
    lambda t: t.update(rule_text="x" * (MAX_RULE_CHANGE_TEXT_BYTES + 1)),
    lambda t: t.update(rule_text="always ( o5[t]:bv[24] = { #x000000 }:bv[24] ). always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."),
    lambda t: t.update(rule_text="always ( (o5[t]:bv[24] = { #x000000 }:bv[24]) && (o6[t]:bv[16] = { #x0000 }:bv[16]) )."),
    lambda t: t.update(rule_text=f"always {NEUTRAL_O5_CLAUSE_BODY}."),
    lambda t: t.update(offer_id=OFFER_ID),
    lambda t: t.update(approvers=[BOB]),
    lambda t: t.update(approvers={"x": BOB}),
    lambda t: t.update(approvers={"18": "zz"}),
    lambda t: t.update(approvers={"18": BOB, "018": CAROL}),
    lambda t: t.update(expire_at_height="500"),
    lambda t: t.update(sender_pubkey="nope"),
    lambda t: t.update(tx_type="user_tx"),
])
def test_malformed_requests_do_not_parse(mutate):
    tx = _tx(_request())
    mutate(tx)
    assert parse_rule_change_request(tx) is None


@pytest.mark.parametrize("kind", [KIND_REVOKE, KIND_REVOKE_GUARD])
def test_kinds_without_a_body_refuse_rule_text(kind):
    tx = _tx(_request(kind))
    assert parse_rule_change_request(tx) is not None
    tx["rule_text"] = SET_TEXT
    assert parse_rule_change_request(tx) is None


@pytest.mark.parametrize("bad", ["", "ab" * 31, "zz" * 32, "ab" * 33])
def test_an_accept_request_needs_a_32_byte_hex_offer_id(bad):
    tx = _tx(_request(KIND_ACCEPT))
    tx["offer_id"] = bad
    assert parse_rule_change_request(tx) is None


def test_only_root_fields_are_read():
    tx = _tx(_request())
    tx["payload"] = {"rule_text": OTHER_TEXT}
    assert parse_rule_change_request(tx).body == _request().body
    del tx["rule_text"]
    assert parse_rule_change_request(tx) is None


def test_zero_approvers_parse():
    assert parse_rule_change_request(_tx(_request(approvers={}))) is not None


def test_a_text_at_the_byte_limit_parses_and_one_over_does_not():
    pad = "# " + "x" * (MAX_RULE_CHANGE_TEXT_BYTES - len(SET_TEXT) - 3) + "\n"
    tx = _tx(_request())
    tx["rule_text"] = pad + SET_TEXT
    assert len(tx["rule_text"].encode()) == MAX_RULE_CHANGE_TEXT_BYTES
    assert parse_rule_change_request(tx) is not None
    tx["rule_text"] += " "
    assert parse_rule_change_request(tx) is None


def test_cancel_parses_root_fields_only():
    rid = _request().request_id
    tx = _cancel_tx(rid)
    parsed = parse_rule_change_cancel(tx)
    assert parsed.request_id == rid and parsed.sender_pubkey == ALICE
    for bad in ("zz", "ab" * 31, 5, None):
        broken = dict(tx, request_id=bad)
        assert parse_rule_change_cancel(broken) is None
    assert parse_rule_change_cancel(dict(tx, tx_type="transfer_vote")) is None


# --- admission -----------------------------------------------------------------

CASES = {
    "set_ok": (lambda: _request(KIND_SET), {}, True),
    "set_bad_body": (lambda: _request(KIND_SET, text=BAD_POLICY_TEXT), {}, False),
    "guard_ok": (lambda: _request(KIND_SET_GUARD), {}, True),
    "guard_bad_body": (lambda: _request(KIND_SET_GUARD, text=BAD_GUARD_TEXT), {}, False),
    "guard_replaces_guard": (lambda: _request(KIND_SET_GUARD), {"guard": True}, True),
    "revoke_without_policy": (lambda: _request(KIND_REVOKE), {}, False),
    "revoke_with_policy": (lambda: _request(KIND_REVOKE), {"policy": True}, True),
    "revoke_guard_without_guard": (lambda: _request(KIND_REVOKE_GUARD), {}, False),
    "revoke_guard_with_guard": (lambda: _request(KIND_REVOKE_GUARD), {"guard": True}, True),
    "accept_without_offer": (lambda: _request(KIND_ACCEPT), {}, False),
    "accept_open_offer": (lambda: _request(KIND_ACCEPT), {"offer": True}, True),
    "accept_for_someone_else": (
        lambda: _request(KIND_ACCEPT, sender=CAROL), {"offer": True}, False),
    "zero_approvers": (lambda: _request(KIND_SET, approvers={}), {}, True),
    "eight_approvers": (
        lambda: _request(KIND_SET, approvers={
            18 + i: pubkey_hex(0x1000 + i) for i in range(MAX_APPROVERS_PER_REQUEST)}),
        {}, True),
    "approver_is_sender": (lambda: _request(KIND_SET, approvers={18: ALICE}), {}, False),
    "bad_slot": (lambda: _request(KIND_SET, approvers={17: BOB}), {}, False),
    "duplicate_approver": (
        lambda: _request(KIND_SET, approvers={18: BOB, 19: BOB}), {}, False),
    "expired_window": (lambda: _request(KIND_SET, expire=10), {}, False),
    "window_too_long": (lambda: _request(KIND_SET, expire=50 + 10_001), {}, False),
}


@pytest.mark.parametrize("name", list(CASES))
def test_admission_and_apply_reach_the_same_verdict(name):
    make, setup, expected = CASES[name]
    req = make()
    lm = _lm(**setup)
    tx = _tx(req, signer=req.sender_pubkey,
             sk={CAROL: SK_CAROL}.get(req.sender_pubkey, SK_ALICE))
    admitted = _admit(tx, lm)
    result, post, _ = _apply(tx, lm, height=50 if name == "expired_window" else HEIGHT)
    applied = tx["tx_id"] in result.accepted_tx_ids
    assert admitted.is_valid is expected, admitted.error
    if name in ("expired_window", "window_too_long"):
        return
    assert applied is expected, _logs(result)
    stored = post.approval_requests.get_rule_change(req.request_id)
    assert (stored is not None) is expected


def test_admission_reports_a_rule_change_code_for_shape_failures():
    result = _admit(_tx(_request(KIND_SET, approvers={17: BOB})), _lm())
    assert result.code == "INVALID_RULE_CHANGE_REQUEST"
    tx = _tx(_request())
    tx["kind"] = 9
    assert _admit(tx, _lm()).code == "INVALID_RULE_CHANGE_REQUEST"


def test_a_duplicate_is_refused_at_admission_and_apply():
    req = _request()
    lm = _lm()
    lm.approval_requests.submit_rule_change(req, HEIGHT)
    admitted = _admit(_tx(req), lm)
    assert admitted.code == "DUPLICATE_REQUEST"
    result, post, _ = _apply(_tx(req), lm)
    assert result.invalid_tx_ids == [_tx(req)["tx_id"]]
    assert "duplicate" in _logs(result)


def test_a_terminal_request_still_blocks_its_own_id():
    req = _request()
    lm = _lm()
    lm.approval_requests.submit_rule_change(req, HEIGHT)
    lm.approval_requests.resolve_rule_change(req.request_id, STATUS_CANCELLED)
    assert _admit(_tx(req), lm).code == "DUPLICATE_REQUEST"


def test_the_guard_is_not_consulted_at_admission_of_a_request():
    lm = _lm(guard=True, policy=True)
    with patch("consensus.sender_policy.rule_change_blocked",
               side_effect=AssertionError("guard consulted")):
        assert _admit(_tx(_request()), lm).is_valid


def test_a_request_without_approvers_needs_no_slot_activation():
    lm = _lm(slots=False)
    assert _admit(_tx(_request(approvers={})), lm).is_valid


# --- the shared cap ------------------------------------------------------------

def _transfer_req(i):
    return ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=CAROL, amount=5000 + i,
        sequence_number=100 + i, expire_at_height=EXPIRE,
        approvers={18: BOB}, custom_inputs={},
    )


def _fill(lm, transfers, rule_changes):
    for i in range(transfers):
        assert lm.approval_requests.submit_request(_transfer_req(i))
    for i in range(rule_changes):
        assert lm.approval_requests.submit_rule_change(
            _request(seq=200 + i, approvers={}), HEIGHT)


def test_transfer_and_rule_change_requests_share_one_cap():
    lm = _lm()
    _fill(lm, 5, 3)
    approvals = lm.approval_requests
    assert approvals.pending_count_for_sender(ALICE) == MAX_PENDING_REQUESTS_PER_SENDER

    ninth = _request(seq=0, approvers={})
    assert _admit(_tx(ninth), lm).code == "TOO_MANY_REQUESTS"
    result, post, _ = _apply(_tx(ninth), lm)
    assert "too many" in _logs(result)
    assert post.approval_requests.get_rule_change(ninth.request_id) is None

    assert approvals.can_admit_request(_transfer_req(50), HEIGHT) == (
        False, "sender has too many open requests")


def test_the_cap_is_open_requests_only():
    lm = _lm()
    _fill(lm, 5, 3)
    first = next(iter(lm.approval_requests.rule_change_requests))
    lm.approval_requests.resolve_rule_change(first, STATUS_CANCELLED)
    assert lm.approval_requests.pending_count_for_sender(ALICE) == 7
    assert _admit(_tx(_request(seq=0, approvers={})), lm).is_valid
    result, post, _ = _apply(_tx(_request(seq=0, approvers={})), lm)
    assert result.accepted_tx_ids


def test_a_transfer_request_is_refused_by_the_shared_cap_at_admission():
    lm = _lm()
    _fill(lm, 2, 6)
    tx = {
        "tx_type": "approval_request", "sender_pubkey": ALICE, "expire_at_height": EXPIRE,
        "recipient_pubkey": CAROL, "amount": 9000, "sequence_number": 9,
        "approvers": {"18": BOB}, "custom_inputs": {},
    }
    result = _admit(tx, lm)
    assert result.code == "TOO_MANY_REQUESTS"


def test_the_approver_cap_counts_both_kinds():
    lm = _lm()
    approvals = lm.approval_requests
    approvals.submit_request(_transfer_req(0))
    approvals.submit_rule_change(_request(seq=1, approvers={18: BOB}), HEIGHT)
    assert approvals.pending_count_for_approver(BOB) == 2
    assert [rid for rid, _ in approvals.inbox_for(BOB)] == [_transfer_req(0).request_id]


# --- apply: storage and fee ----------------------------------------------------

@pytest.mark.parametrize("name", ["set_ok", "guard_ok", "revoke_with_policy",
                                  "revoke_guard_with_guard", "accept_open_offer"])
def test_apply_stores_an_open_request(name):
    make, setup, _ = CASES[name]
    req = make()
    result, post, _ = _apply(_tx(req), _lm(**{**setup, "guard": True}))
    entry = post.approval_requests.get_rule_change(req.request_id)
    assert entry.status == STATUS_OPEN
    assert entry.kind == req.kind
    assert entry.body == req.body
    assert entry.offer_id == req.offer_id
    assert entry.approvers == req.approvers
    assert entry.created_height == HEIGHT
    assert entry.expire_at_height == req.expire_at_height
    assert entry.sender_pubkey == ALICE
    assert entry.voted == {}


def test_a_request_changes_no_policy_and_no_transfer_request():
    lm = _lm(policy=True, guard=True)
    before = dict(lm.rule_offers.accepted_clauses.items())
    result, post, _ = _apply(_tx(_request()), lm)
    assert dict(post.rule_offers.accepted_clauses.items()) == before
    assert post.approval_requests.open_requests == {}


def test_the_fee_is_charged_once_and_the_sequence_is_consumed():
    req = _request()
    result, post, meta = _apply(_tx(req), fee=7)
    assert "Fee charged: 7" in _logs(result)
    assert meta["balances"][ALICE] == 100000 - 7
    assert meta["balances"][MALLORY] == 100000 + 7
    assert meta["sequence_numbers"][ALICE] == 1
    assert sum(1 for line in _logs(result).split(" | ") if line.startswith("Fee charged")) == 1


def test_a_request_that_cannot_pay_is_not_parked_and_keeps_its_sequence():
    req = _request()
    result, post, meta = _apply(
        _tx(req), fee=7, balances={ALICE: 2, MALLORY: 5, BOB: 0})
    assert post.approval_requests.get_rule_change(req.request_id) is None
    assert "un-parked" in _logs(result)
    assert _outcome(result, _tx(req)["tx_id"]).reason == "insufficient_funds_for_fee"
    assert meta["balances"][ALICE] == 2
    assert meta["sequence_numbers"].get(ALICE, 0) == 0


def test_a_request_over_its_fee_limit_is_not_parked():
    req = _request()
    result, post, _ = _apply(_tx(req, fee_limit="3"), fee=7)
    assert post.approval_requests.get_rule_change(req.request_id) is None
    assert _outcome(result, _tx(req, fee_limit="3")["tx_id"]).reason == "fee_limit_exceeded"


def test_the_fee_is_never_refunded_on_cancel():
    req = _request()
    result, lm, meta = _apply(_tx(req), _lm(guard=True), fee=7)
    result2, post, meta2 = _apply(
        _cancel_tx(req.request_id, seq=1), lm, fee=7,
        balances=meta["balances"], sequences=meta["sequence_numbers"])
    assert meta2["balances"][ALICE] == 100000 - 7
    assert post.approval_requests.get_rule_change(req.request_id).status == STATUS_CANCELLED


def test_a_request_with_zero_approvers_is_stored():
    req = _request(approvers={})
    result, post, _ = _apply(_tx(req))
    assert post.approval_requests.get_rule_change(req.request_id).approvers == {}


# --- cancel --------------------------------------------------------------------

def _parked(req=None):
    req = req or _request()
    lm = _lm()
    lm.approval_requests.submit_rule_change(req, HEIGHT)
    return req, lm


def test_the_sender_cancels_an_open_request():
    req, lm = _parked()
    tx = _cancel_tx(req.request_id)
    assert _admit(tx, lm).is_valid
    result, post, meta = _apply(tx, lm)
    assert result.accepted_tx_ids == ["cancel"]
    assert post.approval_requests.get_rule_change(req.request_id).status == STATUS_CANCELLED
    assert meta["sequence_numbers"][ALICE] == 1
    assert post.approval_requests.pending_count_for_sender(ALICE) == 0


def test_cancel_is_feeless():
    req, lm = _parked()
    result, post, meta = _apply(_cancel_tx(req.request_id), lm, fee=9)
    assert result.accepted_tx_ids == ["cancel"]
    assert meta["balances"][ALICE] == 100000
    assert meta["balances"][MALLORY] == 100000
    assert "Fee charged" not in _logs(result)
    assert engine_module.FEE_BEARING_TX_TYPES.isdisjoint({"rule_change_cancel"})


def test_only_the_requests_sender_may_cancel():
    req, lm = _parked()
    tx = _cancel_tx(req.request_id, sender=CAROL, sk=SK_CAROL, tx_id="thief")
    assert _admit(tx, lm).code == "NOT_REQUEST_SENDER"
    result, post, _ = _apply(tx, lm)
    assert result.invalid_tx_ids == ["thief"]
    assert post.approval_requests.get_rule_change(req.request_id).status == STATUS_OPEN


def test_an_approver_cannot_cancel():
    req, lm = _parked()
    tx = _cancel_tx(req.request_id, sender=BOB, sk=SK_BOB, tx_id="approver")
    assert _admit(tx, lm).code == "NOT_REQUEST_SENDER"
    result, post, _ = _apply(tx, lm)
    assert result.invalid_tx_ids == ["approver"]


def test_a_second_cancel_is_refused():
    req, lm = _parked()
    _, once, meta = _apply(_cancel_tx(req.request_id), lm)
    again = _cancel_tx(req.request_id, seq=1, tx_id="again")
    assert _admit(again, once).code == "REQUEST_RESOLVED"
    result, post, _ = _apply(again, once, balances=meta["balances"],
                             sequences=meta["sequence_numbers"])
    assert result.invalid_tx_ids == ["again"]
    assert "already resolved" in _logs(result)


def test_the_same_cancel_cannot_be_replayed_in_one_block():
    req, lm = _parked()
    first = _cancel_tx(req.request_id, tx_id="c1")
    second = _cancel_tx(req.request_id, tx_id="c2")
    result, post, _ = _apply([first, second], lm)
    assert result.accepted_tx_ids == ["c1"]
    assert result.invalid_tx_ids == ["c2"]


def test_cancel_after_expiry_is_refused():
    req, lm = _parked(_request(expire=60))
    tx = _cancel_tx(req.request_id)
    view = _view(lm, height=60)
    assert validate_mempool_admission(tx, view).code == "REQUEST_EXPIRED"
    result, post, _ = _apply(tx, lm, height=60)
    assert result.invalid_tx_ids == ["cancel"]
    assert "expired" in _logs(result)
    assert post.approval_requests.get_rule_change(req.request_id).status != STATUS_CANCELLED


def test_cancelling_an_unknown_or_transfer_request_is_refused():
    lm = _lm()
    lm.approval_requests.submit_request(_transfer_req(0))
    for rid in (b"\x01" * 32, _transfer_req(0).request_id):
        assert _admit(_cancel_tx(rid), lm).code == "UNKNOWN_REQUEST"
        result, post, _ = _apply(_cancel_tx(rid), lm)
        assert result.invalid_tx_ids == ["cancel"]
    assert _transfer_req(0).request_id in post.approval_requests.open_requests


# --- expiry sweep --------------------------------------------------------------

def test_the_expiry_sweep_expires_rule_change_requests():
    lm = _lm()
    early, late = _request(seq=1, expire=100), _request(seq=2, expire=300)
    lm.approval_requests.submit_rule_change(early, 10)
    lm.approval_requests.submit_rule_change(late, 10)
    lm.process_height_transitions(99)
    assert lm.approval_requests.get_rule_change(early.request_id).status == STATUS_OPEN
    lm.process_height_transitions(100)
    assert lm.approval_requests.get_rule_change(early.request_id).status == STATUS_EXPIRED
    assert lm.approval_requests.get_rule_change(late.request_id).status == STATUS_OPEN
    assert lm.approval_requests.pending_count_for_sender(ALICE) == 1


def test_the_sweep_does_not_revive_or_overwrite_a_cancelled_request():
    lm = _lm()
    req = _request(expire=100)
    lm.approval_requests.submit_rule_change(req, 10)
    lm.approval_requests.resolve_rule_change(req.request_id, STATUS_CANCELLED)
    lm.process_height_transitions(150)
    assert lm.approval_requests.get_rule_change(req.request_id).status == STATUS_CANCELLED


def test_the_sweep_returns_transfer_and_rule_change_ids_together():
    approvals = ApprovalRequestLifecycleManager()
    transfer = _transfer_req(0)
    transfer.expire_at_height = 100
    rc = _request(expire=100)
    approvals.submit_request(transfer)
    approvals.submit_rule_change(rc, 10)
    assert approvals.expire_at_height(100) == sorted([transfer.request_id, rc.request_id])


# --- resolvers and the transfer book -------------------------------------------

def test_resolve_all_for_sender_fails_only_transfer_requests():
    approvals = ApprovalRequestLifecycleManager()
    approvals.submit_request(_transfer_req(0))
    rc = _request()
    approvals.submit_rule_change(rc, 10)
    doomed = approvals.resolve_all_for_sender(ALICE, STATUS_FAILED)
    assert doomed == [_transfer_req(0).request_id]
    assert approvals.get_rule_change(rc.request_id).status == STATUS_OPEN


def test_the_rule_change_resolver_leaves_transfer_requests_alone():
    approvals = ApprovalRequestLifecycleManager()
    approvals.submit_request(_transfer_req(0))
    mine, other, keep = _request(seq=1), _request(seq=2, sender=CAROL), _request(seq=3)
    for r in (mine, other, keep):
        approvals.submit_rule_change(r, 10)
    doomed = approvals.resolve_open_rule_changes_for_sender(
        ALICE, STATUS_FAILED, except_id=keep.request_id)
    assert doomed == [mine.request_id]
    assert approvals.get_rule_change(mine.request_id).status == STATUS_FAILED
    assert approvals.get_rule_change(other.request_id).status == STATUS_OPEN
    assert approvals.get_rule_change(keep.request_id).status == STATUS_OPEN
    assert _transfer_req(0).request_id in approvals.open_requests


def test_a_resolved_request_is_not_resolved_twice():
    approvals = ApprovalRequestLifecycleManager()
    rc = _request()
    approvals.submit_rule_change(rc, 10)
    assert approvals.resolve_rule_change(rc.request_id, STATUS_FAILED)
    assert not approvals.resolve_rule_change(rc.request_id, STATUS_CANCELLED)
    assert approvals.get_rule_change(rc.request_id).status == STATUS_FAILED


# --- votes on a rule-change id ----------------------------------------

def _vote_tx(request_id, sk=SK_BOB, voter=BOB):
    return sign_tx({
        "tx_id": "vote", "tx_type": "transfer_vote", "sender_pubkey": voter,
        "sequence_number": 0, "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "0", "request_id": request_id.hex(), "approve": True,
    }, sk)


def test_a_transfer_vote_naming_a_rule_change_request_is_admitted():
    req, lm = _parked()
    tx = _vote_tx(req.request_id)
    assert _admit(tx, lm).is_valid

    applied, post, _ = _apply(tx, lm)
    assert applied.accepted_tx_ids == ["vote"]
    assert post.approval_requests.get_rule_change(req.request_id).voted == {18: BOB}


def test_an_unknown_id_is_still_unknown_to_a_vote():
    lm = _lm()
    assert _admit(_vote_tx(b"\x02" * 32), lm).code == "UNKNOWN_REQUEST"


# --- lanes, budget, fee sets, signing ------------------------------------------

def test_lanes_and_budget():
    request, cancel = _tx(_request()), _cancel_tx(_request().request_id)
    assert classify_lane(request) == LANE_SLOW
    assert classify_lane(cancel) == LANE_FAST
    assert TauConsensusEngine._counts_against_rule_budget(request) is True
    assert TauConsensusEngine._counts_against_rule_budget(cancel) is False
    assert "rule_change_request" in TAU_EVALUATING_TX_TYPES
    assert "rule_change_cancel" not in TAU_EVALUATING_TX_TYPES


def test_the_fee_sets_agree_and_cover_the_request_only():
    from commands import sendtx

    assert sendtx.FEE_BEARING_TX_TYPES == engine_module.FEE_BEARING_TX_TYPES
    assert "rule_change_request" in sendtx.FEE_BEARING_TX_TYPES
    assert "rule_change_cancel" not in sendtx.FEE_BEARING_TX_TYPES
    assert {"rule_change_request", "rule_change_cancel"} <= sendtx.KNOWN_TX_TYPES


@pytest.mark.parametrize("field,value", [
    ("kind", 4), ("rule_text", OTHER_TEXT), ("offer_id", "ab" * 32),
    ("approvers", {"19": BOB}), ("expire_at_height", EXPIRE + 1),
    ("sequence_number", 5), ("fee_limit", "99"),
])
def test_every_request_field_is_signed(field, value):
    tx = _tx(_request())
    changed = dict(tx, **{field: value})
    assert signing_message_bytes(changed) != signing_message_bytes(tx)


def test_the_cancel_request_id_is_signed():
    tx = _cancel_tx(b"\x03" * 32)
    assert signing_message_bytes(dict(tx, request_id="04" * 32)) != signing_message_bytes(tx)


def test_a_forged_request_is_rejected_at_apply():
    req = _request()
    forged = _tx(req, sk=SK_MALLORY)
    result, post, meta = _apply(forged)
    assert result.invalid_tx_ids == [forged["tx_id"]]
    assert _outcome(result, forged["tx_id"]).reason == "invalid_signature"
    assert post.approval_requests.get_rule_change(req.request_id) is None
    assert meta["sequence_numbers"].get(ALICE, 0) == 0


def test_a_request_altered_after_signing_is_rejected_at_apply():
    tx = _tx(_request())
    tx["approvers"] = {"18": MALLORY}
    result, post, _ = _apply(tx)
    assert result.invalid_tx_ids == [tx["tx_id"]]
    assert post.approval_requests.rule_change_requests == {}


def test_a_forged_cancel_is_rejected_at_apply():
    req, lm = _parked()
    forged = _cancel_tx(req.request_id, sk=SK_MALLORY)
    result, post, _ = _apply(forged, lm)
    assert result.invalid_tx_ids == ["cancel"]
    assert _outcome(result, "cancel").reason == "invalid_signature"
    assert post.approval_requests.get_rule_change(req.request_id).status == STATUS_OPEN


def test_an_approver_that_is_not_a_valid_key_is_rejected_at_apply():
    req = _request(approvers={18: "11" * 48})
    result, post, _ = _apply(_tx(req))
    assert result.invalid_tx_ids == [_tx(req)["tx_id"]]
    assert post.approval_requests.rule_change_requests == {}


# --- state root ----------------------------------------------------------------

EMPTY_BOOK_ROOT = "71e0a99173564931c0b8acc52d2685a8e39c64dc52e3d02390fdac2a12b155cb"
TRANSFER_BOOK_ROOT = "c0d528c69aeaa699a98a0043cefc89aefafb11239e0f955cbf9bb885563fe8c8"
EMPTY_META_HASH = "5ac78566bf25d349b41e533bfbdb46bc0d3da9faa503eb90e122aa5ea88b46ea"
TRANSFER_META_HASH = "d4010e0fbe9ca7f7d64b171c9206604dbd919dd23a7d38724c805560b4589bcc"

_PIN_A, _PIN_B, _PIN_AUTH = "1a" * 48, "2b" * 48, "aa" * 48


def _pinned_transfers(approvals):
    first = ApprovalRequest(
        sender_pubkey=_PIN_A, recipient_pubkey=_PIN_B, amount=200000, sequence_number=1,
        expire_at_height=500, approvers={18: _PIN_AUTH}, custom_inputs={26: "rent"})
    second = ApprovalRequest(
        sender_pubkey=_PIN_A, recipient_pubkey=_PIN_B, amount=300000, sequence_number=2,
        expire_at_height=600, approvers={18: _PIN_AUTH}, custom_inputs={})
    approvals.submit_request(first)
    approvals.submit_request(second)
    approvals.commit_vote(
        TransferVote(request_id=first.request_id, voter_pubkey=_PIN_AUTH, approve=True))
    approvals.resolve(second.request_id, STATUS_FAILED)
    return first


def test_without_rule_change_requests_the_roots_and_meta_hash_are_the_pinned_ones():
    assert ApprovalRequestLifecycleManager().requests_root().hex() == EMPTY_BOOK_ROOT
    assert compute_approval_request_book_root([], []).hex() == EMPTY_BOOK_ROOT

    approvals = ApprovalRequestLifecycleManager()
    _pinned_transfers(approvals)
    assert approvals.requests_root().hex() == TRANSFER_BOOK_ROOT

    lm = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert lm.consensus_meta_hash().hex() == EMPTY_META_HASH
    first = _pinned_transfers(ApprovalRequestLifecycleManager())
    lm.approval_requests.submit_request(first)
    lm.approval_requests.commit_vote(
        TransferVote(request_id=first.request_id, voter_pubkey=_PIN_AUTH, approve=True))
    assert lm.consensus_meta_hash().hex() == TRANSFER_META_HASH


def test_a_fresh_manager_is_empty_and_a_rule_change_request_ends_that():
    approvals = ApprovalRequestLifecycleManager()
    assert approvals.is_empty()
    approvals.submit_rule_change(_request(), 10)
    assert not approvals.is_empty()


def test_the_root_commits_to_submit_vote_cancel_and_expire():
    approvals = ApprovalRequestLifecycleManager()
    roots = [approvals.requests_root()]
    req = _request(expire=100)
    approvals.submit_rule_change(req, 10)
    roots.append(approvals.requests_root())
    approvals.rule_change_requests[req.request_id].voted[18] = BOB
    roots.append(approvals.requests_root())
    del approvals.rule_change_requests[req.request_id].voted[18]

    cancelled = copy.deepcopy(approvals)
    cancelled.resolve_rule_change(req.request_id, STATUS_CANCELLED)
    expired = copy.deepcopy(approvals)
    expired.expire_at_height(100)
    failed = copy.deepcopy(approvals)
    failed.resolve_rule_change(req.request_id, STATUS_FAILED)
    roots += [cancelled.requests_root(), expired.requests_root(), failed.requests_root()]
    assert len(set(roots)) == len(roots)


def test_the_root_commits_to_the_body_the_kind_and_the_created_height():
    def root(req, height=10):
        approvals = ApprovalRequestLifecycleManager()
        approvals.submit_rule_change(req, height)
        return approvals.requests_root()

    base = root(_request())
    assert root(_request(text=OTHER_TEXT)) != base
    assert root(_request(), height=11) != base
    assert root(_request(KIND_REVOKE)) != root(_request(KIND_REVOKE_GUARD))


def test_the_root_ignores_insertion_order():
    one, two = _request(seq=1), _request(seq=2)
    a, b = ApprovalRequestLifecycleManager(), ApprovalRequestLifecycleManager()
    a.submit_rule_change(one, 10)
    a.submit_rule_change(two, 10)
    b.submit_rule_change(two, 10)
    b.submit_rule_change(one, 10)
    assert a.requests_root() == b.requests_root()


def test_the_state_root_in_the_meta_hash_moves_with_a_request():
    lm = ConsensusLifecycleManager(active_validators=["d" * 96])
    before = lm.consensus_meta_hash()
    lm.approval_requests.submit_rule_change(_request(), 10)
    assert lm.consensus_meta_hash() != before


def test_apply_moves_the_meta_hash_for_submit_and_cancel():
    lm = _lm(guard=True)
    empty = lm.consensus_meta_hash()
    req = _request()
    _, parked, meta = _apply(_tx(req), lm)
    parked_hash = parked.consensus_meta_hash()
    _, cancelled, _ = _apply(_cancel_tx(req.request_id, seq=1), parked,
                             balances=meta["balances"],
                             sequences=meta["sequence_numbers"])
    assert len({empty, parked_hash, cancelled.consensus_meta_hash()}) == 3


# --- persistence ---------------------------------------------------------------

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


def test_every_status_round_trips_through_a_reload(isolated_chain_state, temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_approval_slots()
    approvals = lm.approval_requests
    reqs = {
        "open": _request(KIND_SET, seq=1),
        "guard": _request(KIND_SET_GUARD, seq=2, approvers={18: BOB, 19: CAROL}),
        "accept": _request(KIND_ACCEPT, seq=3),
        "revoke": _request(KIND_REVOKE, seq=4, approvers={}),
        "cancelled": _request(KIND_REVOKE_GUARD, seq=5),
        "expired": _request(KIND_SET, seq=6, text=OTHER_TEXT, expire=100),
        "failed": _request(KIND_SET, seq=7, expire=300),
    }
    for req in reqs.values():
        assert approvals.submit_rule_change(req, 12)
    approvals.submit_request(_transfer_req(0))
    approvals.rule_change_requests[reqs["guard"].request_id].voted[19] = CAROL
    approvals.resolve_rule_change(reqs["cancelled"].request_id, STATUS_CANCELLED)
    approvals.resolve_rule_change(reqs["failed"].request_id, STATUS_FAILED)
    approvals.expire_at_height(100)
    before_hash = lm.consensus_meta_hash()
    before_root = approvals.requests_root()
    before_entries = copy.deepcopy(approvals.rule_change_requests)

    reloaded = _reload()
    assert reloaded.approval_requests.rule_change_requests == before_entries
    assert reloaded.approval_requests.requests_root() == before_root
    assert reloaded.consensus_meta_hash() == before_hash
    assert _transfer_req(0).request_id in reloaded.approval_requests.open_requests
    statuses = {n: reloaded.approval_requests.get_rule_change(r.request_id).status
                for n, r in reqs.items()}
    assert statuses["cancelled"] == STATUS_CANCELLED
    assert statuses["expired"] == STATUS_EXPIRED
    assert statuses["failed"] == STATUS_FAILED
    assert statuses["open"] == STATUS_OPEN
    assert reloaded.approval_requests.get_rule_change(
        reqs["guard"].request_id).voted == {19: CAROL}


def test_a_reload_of_a_chain_without_requests_stays_empty(isolated_chain_state, temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.approval_requests.is_empty()
    assert reloaded.consensus_meta_hash() == before


def test_a_cancelled_request_stays_cancelled_after_a_second_commit(
        isolated_chain_state, temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    req = _request()
    lm.approval_requests.submit_rule_change(req, 12)
    _reload()
    chain_state._lifecycle_manager.approval_requests.resolve_rule_change(
        req.request_id, STATUS_CANCELLED)
    reloaded = _reload()
    assert reloaded.approval_requests.get_rule_change(req.request_id).status == STATUS_CANCELLED


def test_the_admission_view_reads_rule_change_rows_and_counts_them(
        isolated_chain_state, temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    req = _request()
    lm.approval_requests.submit_rule_change(req, 12)
    lm.approval_requests.submit_rule_change(_request(seq=2, approvers={19: CAROL}), 12)
    lm.approval_requests.submit_request(_transfer_req(0))
    lm.approval_requests.resolve_rule_change(
        _request(seq=2, approvers={19: CAROL}).request_id, STATUS_CANCELLED)
    _reload()

    view = TipAdmissionView()
    row = view.get_rule_change_request(req.request_id_hex)
    assert row["kind"] == KIND_SET and row["status"] == STATUS_OPEN
    assert row["approvers"] == {18: BOB} and row["created_height"] == 12
    assert view.get_rule_change_request("00" * 32) is None
    assert view.open_requests_for_sender(ALICE) == 2
    assert view.open_requests_for_approver(BOB) == 2
    assert view.get_approval_request(req.request_id_hex) is None


# --- fork and clone isolation ----------------------------------------------------

def test_a_fork_does_not_leak_into_its_parent():
    parent = _lm()
    req = _request()
    parent.approval_requests.submit_rule_change(req, 10)
    root = parent.approval_requests.requests_root()

    fork = parent.fork()
    fork.approval_requests.resolve_rule_change(req.request_id, STATUS_CANCELLED)
    fork.approval_requests.submit_rule_change(_request(seq=9), 10)

    assert parent.approval_requests.get_rule_change(req.request_id).status == STATUS_OPEN
    assert len(parent.approval_requests.rule_change_requests) == 1
    assert parent.approval_requests.requests_root() == root
    assert fork.approval_requests.requests_root() != root


def test_an_apply_does_not_mutate_the_parent_lifecycle():
    req, lm = _parked()
    root = lm.approval_requests.requests_root()
    _apply(_cancel_tx(req.request_id), lm)
    assert lm.approval_requests.get_rule_change(req.request_id).status == STATUS_OPEN
    assert lm.approval_requests.requests_root() == root

    fresh = _lm()
    _apply(_tx(_request()), fresh)
    assert fresh.approval_requests.rule_change_requests == {}


def test_a_rejected_transaction_leaves_no_request_behind():
    lm = _lm()
    forged = _tx(_request(), sk=SK_MALLORY)
    _, post, _ = _apply([forged], lm)
    assert post.approval_requests.rule_change_requests == {}
    assert post.approval_requests.is_empty()
