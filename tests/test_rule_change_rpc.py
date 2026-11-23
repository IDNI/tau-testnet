"""Read side of rule-change requests: the approval RPCs, the preview, the rule
RPCs that must not leak the guard, and the codes sendtx forwards."""
import json
import types

import pytest

import chain_state
import db
import tau_defs
from bls_keys import FAR_FUTURE, SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_tx
from commands import (
    getapprovalpreview,
    getapprovalrequest,
    getapprovalrequests,
    getapprovalslots,
    getruleconflict,
    getruleoffers,
    sendtx,
)
from consensus import sender_policy
from consensus.approvals import (
    MAX_PENDING_REQUESTS_PER_SENDER,
    MAX_PREVIEW_SLOTS,
    STATUS_CANCELLED,
    STATUS_EXECUTED,
    ApprovalRequest,
    ApprovalRequestLifecycleManager,
    RuleChangeRequest,
)
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import RuleOffer
from tau_speculation import WorkerLost, WorkerTimeout

HEIGHT = 20
EXPIRE = 500
ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)
MALLORY = pubkey_hex(SK_MALLORY)
GUARD_INDEX = tau_defs.RULE_CHANGE_GUARD_INDEX

_ON = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
_OFF = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
SET_TEXT = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
OFFER_TEXT = "always ( o5[t]:bv[24] = { #x000003 }:bv[24] )."
GUARD_TEXT = (
    "always ( (i18[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]) ? "
    f"{_ON} : {_OFF} )."
)
GUARD_BODY = GUARD_TEXT[len("always ( "):-3]
BAD_POLICY_TEXT = f"always ( (i13[t]:bv[24] = {{ #x000001 }}:bv[24]) ? {_ON} : {_OFF} )."
BAD_GUARD_TEXT = f"always ( (i2[t]:bv[24] = {{ #x000001 }}:bv[24]) ? {_ON} : {_OFF} )."

KIND_SET = tau_defs.RULE_CHANGE_KIND_SET_POLICY
KIND_REVOKE = tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY
KIND_ACCEPT = tau_defs.RULE_CHANGE_KIND_ACCEPT_OFFER
KIND_SET_GUARD = tau_defs.RULE_CHANGE_KIND_SET_GUARD
KIND_REVOKE_GUARD = tau_defs.RULE_CHANGE_KIND_REVOKE_GUARD

OFFER = RuleOffer(offerer_pubkey=MALLORY, recipient_pubkey=ALICE,
                  rule_text=OFFER_TEXT, expire_at_height=EXPIRE)
OFFER_ID = OFFER.offer_id_hex


@pytest.fixture(autouse=True)
def _tip(temp_database, monkeypatch):
    monkeypatch.setattr(chain_state, "_lifecycle_manager", ConsensusLifecycleManager())
    chain_state._lifecycle_manager.activate_approval_slots()
    yield


@pytest.fixture
def container():
    return types.SimpleNamespace(db=db)


@pytest.fixture
def evaluator():
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _set_verdict(evs, decide):
    for ev in evs.values():
        ev.set_verdict(GUARD_BODY, decide)


def _needs(slot_pubkey, slot="i18"):
    return lambda inputs: "1" if slot_pubkey in str(inputs.get(slot, "")) else "0"


def _req(kind=KIND_SET, *, sender=ALICE, seq=0, text=None, offer_id="",
         approvers=None, expire=EXPIRE):
    if text is None:
        text = {KIND_SET: SET_TEXT, KIND_SET_GUARD: GUARD_TEXT,
                KIND_ACCEPT: OFFER_TEXT}.get(kind, "")
    if kind == KIND_ACCEPT and not offer_id:
        offer_id = OFFER_ID
    return RuleChangeRequest(
        sender_pubkey=sender, sequence_number=seq, kind=kind, rule_text=text,
        offer_id=offer_id, approvers={18: BOB} if approvers is None else approvers,
        expire_at_height=expire,
    )


def _persist(mgr=None, *, guard=True, policy=False, offer=True, head=HEIGHT):
    mgr = mgr or ApprovalRequestLifecycleManager()
    clauses = []
    if guard:
        clauses.append({"acceptor_pubkey": ALICE, "target_stream": GUARD_INDEX,
                        "clause_body": GUARD_BODY})
    if policy:
        clauses.append({"acceptor_pubkey": ALICE, "target_stream": 5,
                        "clause_body": _OFF})
    offers = []
    if offer:
        offers.append({"offer_id": OFFER_ID, "offerer_pubkey": MALLORY,
                       "recipient_pubkey": ALICE, "rule_text": OFFER_TEXT,
                       "expire_at_height": EXPIRE, "status": "offered"})
    db.save_canonical_state_atomically(
        head_hash="h", head_num=head, balances={ALICE: 100000}, sequences={},
        application_rules="", consensus_rules="", active_consensus_id="",
        pending_updates=[], votes=[], scheduled=[], archival=[],
        rule_offers=offers, rule_clauses=clauses,
        approval_requests=mgr.snapshot_requests(),
        rule_change_requests=mgr.snapshot_rule_change_requests(),
        approval_slots_active=True,
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


# --- getapprovalrequest(s) -----------------------------------------------------

def test_lookup_by_id_finds_a_rule_change_request():
    req = _req(KIND_SET_GUARD, approvers={18: BOB, 19: CAROL})
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(req, 12)
    mgr.rule_change_requests[req.request_id].voted[19] = CAROL
    _persist(mgr)

    row = _data(getapprovalrequest.execute(
        "getapprovalrequest " + req.request_id_hex, None))
    assert row["request_type"] == "rule_change"
    assert row["request_id"] == req.request_id_hex
    assert row["sender"] == ALICE
    assert row["kind"] == KIND_SET_GUARD and row["kind_name"] == "set_guard"
    assert row["body"] == req.body
    assert row["body_hash"] == req.body_hash.hex()
    assert row["offer_id"] == ""
    assert row["approvers"] == {
        "18": {"pubkey": BOB, "state": "awaiting"},
        "19": {"pubkey": CAROL, "state": "approved"},
    }
    assert row["voted"] == [19] and row["declined"] == []
    assert row["ready"] is False
    assert row["created_height"] == 12
    assert row["escape_height"] == 12 + tau_defs.RULE_CHANGE_DELAY_BLOCKS
    assert row["expire_at_height"] == EXPIRE
    assert row["status"] == "open"
    assert row["awaiting_slots"] == [18]
    assert row["all_answered"] is False


@pytest.mark.parametrize("kind,name", [
    (KIND_SET, "set_policy"), (KIND_REVOKE, "revoke_policy"),
    (KIND_ACCEPT, "accept_offer"), (KIND_SET_GUARD, "set_guard"),
    (KIND_REVOKE_GUARD, "revoke_guard"),
])
def test_every_kind_has_a_name(kind, name):
    req = _req(kind, approvers={} if kind in (KIND_REVOKE, KIND_REVOKE_GUARD) else None)
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(req, 12)
    _persist(mgr)
    row = _data(getapprovalrequest.execute(
        "getapprovalrequest " + req.request_id_hex, None))
    assert row["kind_name"] == name


def test_an_accept_request_shows_the_raw_offered_text():
    req = _req(KIND_ACCEPT)
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(req, 12)
    _persist(mgr)
    row = _data(getapprovalrequest.execute(
        "getapprovalrequest " + req.request_id_hex, None))
    assert row["body"] == OFFER_TEXT
    assert row["offer_id"] == OFFER_ID


def test_lookup_still_finds_transfer_requests_and_marks_them():
    transfer = ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=5, sequence_number=1,
        expire_at_height=EXPIRE, approvers={18: CAROL}, custom_inputs={})
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_request(transfer)
    _persist(mgr)
    row = _data(getapprovalrequest.execute(
        "getapprovalrequest " + transfer.request_id_hex, None))
    assert row["request_type"] == "transfer"
    assert row["amount"] == 5 and row["status"] == "open"
    assert "kind" not in row


def test_cancelled_and_executed_requests_are_listed_with_their_status():
    cancelled = _req(KIND_SET, seq=1)
    executed = _req(KIND_SET, seq=2, text=SET_TEXT.replace("000000", "000002"))
    still_open = _req(KIND_SET, seq=3, text=SET_TEXT.replace("000000", "000004"))
    mgr = ApprovalRequestLifecycleManager()
    for r in (cancelled, executed, still_open):
        mgr.submit_rule_change(r, 12)
    mgr.resolve_rule_change(cancelled.request_id, STATUS_CANCELLED)
    mgr.resolve_rule_change(executed.request_id, STATUS_EXECUTED)
    _persist(mgr)

    out = _data(getapprovalrequests.execute(
        "getapprovalrequests " + ALICE + " out", None))["outgoing"]
    status = {r["request_id"]: r["status"] for r in out}
    assert status == {
        cancelled.request_id_hex: "cancelled",
        executed.request_id_hex: "executed",
        still_open.request_id_hex: "open",
    }
    assert {r["request_type"] for r in out} == {"rule_change"}

    inbox = _data(getapprovalrequests.execute(
        "getapprovalrequests " + BOB + " in", None))["incoming"]
    assert [r["request_id"] for r in inbox] == [still_open.request_id_hex]


def test_the_inbox_lists_rule_change_requests_beside_transfers():
    rc = _req(KIND_SET, approvers={18: BOB})
    transfer = ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=CAROL, amount=5, sequence_number=1,
        expire_at_height=EXPIRE, approvers={18: BOB}, custom_inputs={})
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(rc, 12)
    mgr.submit_request(transfer)
    _persist(mgr)

    seen = _data(getapprovalrequests.execute(
        "getapprovalrequests " + BOB + " in", None))["incoming"]
    assert {(r["request_type"], r["request_id"]) for r in seen} == {
        ("transfer", transfer.request_id_hex), ("rule_change", rc.request_id_hex)}
    assert [rid for rid, _e in mgr.rule_change_inbox_for(BOB)] == [rc.request_id]

    for stranger in (CAROL, MALLORY):
        empty = _data(getapprovalrequests.execute(
            "getapprovalrequests " + stranger + " in", None))
        assert empty["incoming"] == []


def test_transfer_rows_keep_every_existing_field():
    transfer = ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=5, sequence_number=1,
        expire_at_height=EXPIRE, approvers={18: CAROL}, custom_inputs={})
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_request(transfer)
    _persist(mgr)
    row = _data(getapprovalrequests.execute(
        "getapprovalrequests " + CAROL + " in", None))["incoming"][0]
    assert set(row) == {"request_type", "request_id", "sender_pubkey",
                        "recipient_pubkey", "amount", "expire_at_height", "status",
                        "approvers", "custom_inputs"}
    assert row["request_type"] == "transfer"


# --- getapprovalpreview, rule-change mode ---------------------------------------

def _draft(kind, **over):
    d = {"request_type": "rule_change", "sender_pubkey": ALICE, "kind": kind}
    if kind in (KIND_SET, KIND_ACCEPT, KIND_SET_GUARD):
        d["rule_text"] = {KIND_SET: SET_TEXT, KIND_SET_GUARD: GUARD_TEXT,
                          KIND_ACCEPT: OFFER_TEXT}[kind]
    if kind == KIND_ACCEPT:
        d["offer_id"] = OFFER_ID
    d.update(over)
    return d


def _preview(draft):
    return getapprovalpreview.execute("getapprovalpreview " + json.dumps(draft), None)


def test_preview_with_no_guard_executes_immediately():
    _persist(guard=False)
    data = _data(_preview(_draft(KIND_SET)))
    assert data["request_type"] == "rule_change"
    assert data["has_guard"] is False
    assert data["executes_immediately"] is True
    assert data["escape_delay_blocks"] == tau_defs.RULE_CHANGE_DELAY_BLOCKS
    assert data["screen"] == {"ok": True, "error": None}


def test_preview_selected_by_kind_alone():
    _persist(guard=False)
    draft = _draft(KIND_SET)
    del draft["request_type"]
    assert _data(_preview(draft))["request_type"] == "rule_change"


def test_preview_with_a_permissive_guard_executes_immediately(evaluator):
    _persist()
    _set_verdict(evaluator, lambda inputs: "1")
    data = _data(_preview(_draft(KIND_SET, approvers={"18": BOB})))
    assert data["has_guard"] is True
    assert data["executes_immediately"] is True
    assert data["required_slots"] == []


def test_preview_names_the_slot_subsets_that_satisfy_the_guard(evaluator):
    _persist()
    _set_verdict(evaluator, _needs(BOB))
    data = _data(_preview(_draft(KIND_SET, approvers={"18": BOB, "19": CAROL})))
    assert data["has_guard"] is True
    assert data["executes_immediately"] is False
    assert data["satisfiable"] is True
    assert data["required_slots"] == [18]
    assert data["required_approvers"] == {"18": BOB}
    assert data["allowing_subsets"] == [[18]]
    assert data["escape_delay_blocks"] == tau_defs.RULE_CHANGE_DELAY_BLOCKS


def test_preview_feeds_the_guard_the_change_kind(evaluator):
    _persist()
    seen = []
    _set_verdict(evaluator, lambda inputs: seen.append(inputs.get("i1")) or "0")
    _preview(_draft(KIND_SET_GUARD))
    assert set(seen) == {str(KIND_SET_GUARD)}


def test_preview_reports_when_the_candidates_cannot_satisfy_the_guard(evaluator):
    _persist()
    _set_verdict(evaluator, _needs(BOB))
    data = _data(_preview(_draft(KIND_SET, approvers={"19": CAROL})))
    assert data["satisfiable"] is False
    assert data["required_slots"] is None and data["allowing_subsets"] == []
    assert data["escape_delay_blocks"] == tau_defs.RULE_CHANGE_DELAY_BLOCKS


def test_preview_refuses_to_guess_above_the_subset_cap(evaluator):
    _persist()
    too_many = {str(18 + i): pubkey_hex(0x100 + i) for i in range(MAX_PREVIEW_SLOTS + 1)}
    data = _data(_preview(_draft(KIND_SET, approvers=too_many)))
    assert data["available"] is False
    assert str(MAX_PREVIEW_SLOTS) in data["reason"]


@pytest.mark.parametrize("make_exc", [
    lambda: WorkerTimeout("budget ran out"),
    lambda: WorkerLost("worker gone"),
])
def test_preview_is_no_answer_when_the_evaluator_is_unavailable(evaluator, make_exc):
    _persist()

    def fail(_inputs):
        raise make_exc()

    _set_verdict(evaluator, fail)
    data = _data(_preview(_draft(KIND_SET, approvers={"18": BOB})))
    assert data["advisory"] is True and data["available"] is False
    assert "required_slots" not in data


@pytest.mark.parametrize("kind,over,ok", [
    (KIND_SET, {}, True),
    (KIND_SET, {"rule_text": BAD_POLICY_TEXT}, False),
    (KIND_SET_GUARD, {}, True),
    (KIND_SET_GUARD, {"rule_text": BAD_GUARD_TEXT}, False),
    (KIND_ACCEPT, {}, True),
    (KIND_ACCEPT, {"offer_id": "ab" * 32}, False),
    (KIND_ACCEPT, {"rule_text": SET_TEXT}, False),
    (KIND_REVOKE, {}, False),
    (KIND_REVOKE_GUARD, {}, True),
])
def test_preview_screens_the_body(kind, over, ok):
    _persist(guard=True, policy=False)
    data = _data(_preview(_draft(kind, **over)))
    assert data["screen"]["ok"] is ok, data["screen"]
    assert (data["screen"]["error"] is None) is ok


def test_preview_revoke_policy_passes_the_screen_with_a_policy():
    _persist(guard=False, policy=True)
    assert _data(_preview(_draft(KIND_REVOKE)))["screen"]["ok"] is True


@pytest.mark.parametrize("draft", [
    _draft(13),
    _draft(KIND_SET, rule_text=""),
    _draft(KIND_REVOKE, rule_text=SET_TEXT),
    _draft(KIND_ACCEPT, offer_id="nothex"),
    _draft(KIND_SET, sender_pubkey="short"),
])
def test_preview_rejects_malformed_drafts(draft):
    _persist()
    assert _err(_preview(draft))["code"] == "INVALID_PARAMS"


def test_preview_naming_approvers_is_inactive_before_activation():
    chain_state._lifecycle_manager = ConsensusLifecycleManager()
    _persist()
    draft = _draft(KIND_SET, approvers={"18": BOB})
    assert _err(_preview(draft))["code"] == "FEATURE_INACTIVE"


def test_preview_without_approvers_works_before_activation():
    chain_state._lifecycle_manager = ConsensusLifecycleManager()
    _persist(guard=False)
    data = _data(_preview(_draft(KIND_SET)))
    assert data["executes_immediately"] is True


def test_a_transfer_draft_takes_the_transfer_path():
    _persist()
    draft = {"sender_pubkey": ALICE, "recipient_pubkey": BOB, "amount": 5,
             "approvers": {str(i + 18): pubkey_hex(0x100 + i)
                           for i in range(MAX_PREVIEW_SLOTS + 1)}}
    data = _data(getapprovalpreview.execute(
        "getapprovalpreview " + json.dumps(draft), None))
    assert "request_type" not in data and data["available"] is False


# --- getapprovalslots ------------------------------------------------------------

def test_slots_report_the_guard_beside_the_unchanged_fields():
    _persist(guard=True, policy=True)
    data = _data(getapprovalslots.execute("getapprovalslots " + ALICE, None))
    assert data["has_rule_change_guard"] is True
    assert data["rule_change_guard"] == GUARD_BODY
    assert data["has_clause"] is True
    assert {"advisory", "slots", "unreadable", "note", "address"} <= set(data)


def test_slots_report_no_guard():
    _persist(guard=False, policy=True)
    data = _data(getapprovalslots.execute("getapprovalslots " + ALICE, None))
    assert data["has_rule_change_guard"] is False
    assert data["rule_change_guard"] is None


def test_the_guard_is_not_mistaken_for_the_policy_clause():
    _persist(guard=True, policy=False)
    data = _data(getapprovalslots.execute("getapprovalslots " + ALICE, None))
    assert data["has_clause"] is False and data["has_rule_change_guard"] is True


# --- getruleoffers / getruleconflict ---------------------------

def test_getruleoffers_returns_the_guard_separately(container):
    _persist(guard=True, policy=True)
    data = _data(getruleoffers.execute("getruleoffers " + ALICE, container))
    assert data["rule_change_guard"] == GUARD_BODY
    assert data["accepted_clauses"] == [{"target_stream": 5, "clause_body": _OFF}]
    assert GUARD_INDEX not in data["supported_target_streams"]
    assert GUARD_INDEX not in [c["target_stream"] for c in data["accepted_clauses"]]


def test_getruleoffers_without_a_guard(container):
    _persist(guard=False, policy=True)
    data = _data(getruleoffers.execute("getruleoffers " + ALICE, container))
    assert data["rule_change_guard"] is None
    assert len(data["accepted_clauses"]) == 1


def test_getruleoffers_guard_only_account_has_no_accepted_clauses(container):
    _persist(guard=True, policy=False)
    data = _data(getruleoffers.execute("getruleoffers " + ALICE, container))
    assert data["accepted_clauses"] == []
    assert data["rule_change_guard"] == GUARD_BODY


def test_getruleconflict_never_reports_the_guard(container):
    _persist(guard=True, policy=True)
    data = _data(getruleconflict.execute("getruleconflict " + OFFER_ID, container))
    assert GUARD_INDEX not in data["supported_target_streams"]
    assert data["target_stream"] == 5
    collision = next(layer for layer in data["layers"] if layer["layer"] == "registry_collision")
    assert GUARD_BODY not in json.dumps(collision)
    assert str(GUARD_INDEX) not in json.dumps(data)


def test_getruleconflict_other_acceptors_exclude_a_guard_holder(container):
    """A guard held by someone else must not read as another acceptor of o5."""
    db.save_canonical_state_atomically(
        head_hash="h", head_num=HEIGHT, balances={}, sequences={},
        application_rules="", consensus_rules="", active_consensus_id="",
        pending_updates=[], votes=[], scheduled=[], archival=[],
        rule_offers=[{"offer_id": OFFER_ID, "offerer_pubkey": MALLORY,
                      "recipient_pubkey": ALICE, "rule_text": OFFER_TEXT,
                      "expire_at_height": EXPIRE, "status": "offered"}],
        rule_clauses=[{"acceptor_pubkey": CAROL, "target_stream": GUARD_INDEX,
                       "clause_body": GUARD_BODY}],
    )
    data = _data(getruleconflict.execute(
        "getruleconflict " + OFFER_ID, types.SimpleNamespace(db=db)))
    collision = next(layer for layer in data["layers"] if layer["layer"] == "registry_collision")
    assert collision["status"] == "ok"
    assert CAROL not in json.dumps(collision)


# --- error codes through sendtx ----------------------------------------------------

def _rc_tx(req, *, sk=SK_ALICE, tx_id=None):
    tx = {
        "tx_id": tx_id or f"rc-{req.sequence_number}-{req.kind}",
        "tx_type": "rule_change_request",
        "sender_pubkey": req.sender_pubkey,
        "sequence_number": req.sequence_number,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": req.expire_at_height,
        "fee_limit": "100",
        "kind": req.kind,
        "approvers": {str(k): v for k, v in req.approvers.items()},
    }
    if req.rule_text:
        tx["rule_text"] = req.rule_text
    if req.offer_id:
        tx["offer_id"] = req.offer_id
    return sign_tx(tx, sk)


def _cancel_tx(request_id, *, sender=ALICE, sk=SK_ALICE):
    return sign_tx({
        "tx_id": "cancel",
        "tx_type": "rule_change_cancel",
        "sender_pubkey": sender,
        "sequence_number": 0,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": 5000,
        "fee_limit": "0",
        "request_id": request_id,
    }, sk)


def _send(tx):
    return sendtx.execute("sendtx " + json.dumps(tx), None)


def _assert_code(resp, code):
    err = _err(resp)
    assert err["code"] == code, err


def test_sendtx_forwards_invalid_rule_change_request(evaluator):
    _persist()
    bad = _rc_tx(_req(KIND_REVOKE_GUARD))
    bad["rule_text"] = SET_TEXT
    _assert_code(_send(sign_tx(bad, SK_ALICE)), "INVALID_RULE_CHANGE_REQUEST")


def test_sendtx_forwards_duplicate_request(evaluator):
    req = _req(KIND_SET)
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(req, 12)
    _persist(mgr)
    _assert_code(_send(_rc_tx(req)), "DUPLICATE_REQUEST")


def test_sendtx_forwards_too_many_requests(evaluator):
    mgr = ApprovalRequestLifecycleManager()
    for i in range(MAX_PENDING_REQUESTS_PER_SENDER):
        mgr.submit_rule_change(
            _req(KIND_SET, seq=i + 1, text=SET_TEXT.replace("000000", "%06x" % (i + 10))), 12)
    _persist(mgr)
    _assert_code(_send(_rc_tx(_req(KIND_SET, seq=0))), "TOO_MANY_REQUESTS")


def test_sendtx_forwards_feature_inactive(evaluator):
    chain_state._lifecycle_manager = ConsensusLifecycleManager()
    _persist()
    _assert_code(_send(_rc_tx(_req(KIND_SET))), "FEATURE_INACTIVE")


def test_sendtx_forwards_rule_change_needs_approval(evaluator):
    _persist(guard=True, policy=False)
    _set_verdict(evaluator, lambda inputs: "0")
    tx = sign_tx({
        "tx_id": "door",
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"0": SET_TEXT},
    }, SK_ALICE)
    _assert_code(_send(tx), "RULE_CHANGE_NEEDS_APPROVAL")


def test_sendtx_forwards_invalid_rule_change_cancel(evaluator):
    _persist()
    _assert_code(_send(_cancel_tx("abcd")), "INVALID_RULE_CHANGE_CANCEL")


def test_sendtx_forwards_unknown_request_on_cancel(evaluator):
    _persist()
    _assert_code(_send(_cancel_tx("ab" * 32)), "UNKNOWN_REQUEST")


def test_sendtx_forwards_not_request_sender_on_cancel(evaluator):
    req = _req(KIND_SET)
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(req, 12)
    _persist(mgr)
    _assert_code(_send(_cancel_tx(req.request_id_hex, sender=BOB, sk=SK_BOB)),
                 "NOT_REQUEST_SENDER")


def test_sendtx_forwards_request_resolved_on_cancel(evaluator):
    req = _req(KIND_SET)
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(req, 12)
    mgr.resolve_rule_change(req.request_id, STATUS_CANCELLED)
    _persist(mgr)
    _assert_code(_send(_cancel_tx(req.request_id_hex)), "REQUEST_RESOLVED")


def test_sendtx_forwards_request_expired_on_cancel(evaluator):
    req = _req(KIND_SET, expire=1)
    mgr = ApprovalRequestLifecycleManager()
    mgr.submit_rule_change(req, 0)
    _persist(mgr)
    _assert_code(_send(_cancel_tx(req.request_id_hex)), "REQUEST_EXPIRED")
