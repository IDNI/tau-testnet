"""Mempool admission for the co-signature transaction types.

Every check is a deterministic function of the transaction plus the tip tables,
so admission and block apply reach the same verdict on the same input -- the
stateless half is literally the same function (`validate_request_shape`), which
is why a shape corpus is asserted against both paths at the end.

NOTE on the fixture: `MagicMock(spec=TipAdmissionView)` returns a truthy Mock for
any attribute left unset, so `approval_slots_active` is set EXPLICITLY here. A
test that forgets would silently run as if the feature were activated.
"""
import pytest
from unittest.mock import MagicMock

import tau_defs
from consensus.admission import (
    TipAdmissionView,
    validate_approval_request_payload,
    validate_mempool_admission,
    validate_transfer_vote_payload,
    validate_user_tx_reserved_domains,
)
from consensus.approvals import (
    MAX_PENDING_REQUESTS_PER_APPROVER,
    MAX_PENDING_REQUESTS_PER_SENDER,
    STATUS_EXECUTED,
    STATUS_OPEN,
    ApprovalRequest,
    ApprovalRequestLifecycleManager,
    validate_request_shape,
)

A = "1a" * 48          # sender
B = "2b" * 48          # recipient
AUTH = "aa" * 48
SCAN = "bb" * 48
PARTNER = "cc" * 48
STRANGER = "de" * 48
NEXT_HEIGHT = 50
EXPIRE = 500


@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {A}
    view.next_block_height = NEXT_HEIGHT
    view.eligibility_mode = ""
    view.approval_slots_active = True
    view.get_approval_request.return_value = None
    view.open_requests_for_sender.return_value = 0
    view.open_requests_for_approver.return_value = 0
    return view


def _request(**over):
    kwargs = dict(sender_pubkey=A, recipient_pubkey=B, amount=200000,
                  sequence_number=1, expire_at_height=EXPIRE,
                  approvers={18: AUTH, 19: SCAN, 20: PARTNER}, custom_inputs={})
    kwargs.update(over)
    return ApprovalRequest(**kwargs)


def request_tx(**over):
    req = _request(**{k: v for k, v in over.items() if k in {
        "sender_pubkey", "recipient_pubkey", "amount", "sequence_number",
        "expire_at_height", "approvers", "custom_inputs"}})
    tx = {
        "tx_type": "approval_request",
        "sender_pubkey": req.sender_pubkey,
        "sequence_number": req.sequence_number,
        "recipient_pubkey": req.recipient_pubkey,
        "amount": req.amount,
        "expire_at_height": req.expire_at_height,
        "approvers": {str(k): v for k, v in req.approvers.items()},
        "custom_inputs": {str(k): v for k, v in req.custom_inputs.items()},
    }
    for k, v in over.items():
        if k not in {"approvers", "custom_inputs"}:
            tx[k] = v
    return tx


def vote_tx(request_id=None, voter=AUTH, approve=True, **over):
    tx = {
        "tx_type": "transfer_vote",
        "sender_pubkey": voter,
        "request_id": request_id or _request().request_id_hex,
        "approve": approve,
    }
    tx.update(over)
    return tx


def _open_row(request=None, voted=None, declined=None, status=STATUS_OPEN,
              expire=EXPIRE):
    req = request or _request()
    return {
        "request_id": req.request_id_hex,
        "sender_pubkey": req.sender_pubkey,
        "recipient_pubkey": req.recipient_pubkey,
        "amount": req.amount,
        "expire_at_height": expire,
        "approvers": dict(req.approvers),
        "custom_inputs": dict(req.custom_inputs),
        "voted": voted or {},
        "declined": declined or [],
        "status": status,
    }


# --- the activation gate -----------------------------------------------------

@pytest.mark.parametrize("tx_builder", [request_tx, vote_tx])
def test_both_types_are_refused_before_activation(tip_view, tx_builder):
    tip_view.approval_slots_active = False
    result = validate_mempool_admission(tx_builder(), tip_view)
    assert result.is_valid is False
    assert result.code == "FEATURE_INACTIVE"


# --- request admission -------------------------------------------------------

def test_a_well_formed_request_is_admitted(tip_view):
    result = validate_mempool_admission(request_tx(), tip_view)
    assert result.is_valid is True, result.error
    assert result.data["request_id"] == _request().request_id_hex
    assert result.data["approvers"] == {18: AUTH, 19: SCAN, 20: PARTNER}


@pytest.mark.parametrize("over,fragment", [
    ({"approvers": {}}, "at least one approver"),
    ({"approvers": {17: AUTH}}, "not an approval slot"),
    ({"approvers": {18: AUTH, 19: AUTH}}, "distinct accounts"),
    ({"approvers": {18: A}}, "their own approver"),
    ({"amount": 0}, "amount must be in"),
    ({"custom_inputs": {13: "x"}}, "below i26"),
    ({"expire_at_height": NEXT_HEIGHT}, "must be in the future"),
])
def test_shape_errors_are_surfaced(tip_view, over, fragment):
    result = validate_mempool_admission(request_tx(**over), tip_view)
    assert result.is_valid is False
    assert fragment in result.error


def test_malformed_request_is_refused(tip_view):
    result = validate_approval_request_payload(
        {"tx_type": "approval_request", "sender_pubkey": A, "sequence_number": 1}, tip_view)
    assert result.is_valid is False and "Malformed approval_request" in result.error


def test_a_request_without_a_root_sender_is_refused(tip_view):
    """The signer is the ROOT sender_pubkey; the parser tolerates a nested
    payload for the other fields but the signature covers the root. A request
    that only declares its sender inside the payload has nobody accountable for
    it, so the signer check refuses it rather than trusting the nested value."""
    tx = {
        "tx_type": "approval_request",
        "sequence_number": 1,
        "payload": {
            "sender_pubkey": A,
            "recipient_pubkey": B,
            "amount": 200000,
            "expire_at_height": EXPIRE,
            "approvers": {"18": AUTH},
        },
    }
    result = validate_approval_request_payload(tx, tip_view)
    assert result.is_valid is False
    assert "must match the signer" in result.error


def test_a_vote_without_a_root_sender_is_refused(tip_view):
    tip_view.get_approval_request.return_value = _open_row()
    tx = {"tx_type": "transfer_vote",
          "payload": {"sender_pubkey": AUTH, "request_id": _request().request_id_hex}}
    result = validate_transfer_vote_payload(tx, tip_view)
    assert result.is_valid is False
    assert "must match the signer" in result.error


def test_duplicate_request_is_refused(tip_view):
    tip_view.get_approval_request.return_value = _open_row()
    result = validate_mempool_admission(request_tx(), tip_view)
    assert result.is_valid is False and result.code == "DUPLICATE_REQUEST"


def test_per_sender_cap_is_enforced(tip_view):
    tip_view.open_requests_for_sender.return_value = MAX_PENDING_REQUESTS_PER_SENDER
    result = validate_mempool_admission(request_tx(), tip_view)
    assert result.is_valid is False and result.code == "TOO_MANY_REQUESTS"


def test_per_approver_cap_is_enforced(tip_view):
    tip_view.open_requests_for_approver.return_value = MAX_PENDING_REQUESTS_PER_APPROVER
    result = validate_mempool_admission(request_tx(), tip_view)
    assert result.is_valid is False and result.code == "TOO_MANY_REQUESTS"


# --- vote admission ---------------------------------------------------------

def test_a_declared_approvers_vote_is_admitted(tip_view):
    tip_view.get_approval_request.return_value = _open_row()
    result = validate_mempool_admission(vote_tx(), tip_view)
    assert result.is_valid is True, result.error
    assert result.data["slot"] == 18 and result.data["approve"] is True


def test_a_decline_is_admitted_too(tip_view):
    """A decline is a legitimate vote -- it just does not fill its slot."""
    tip_view.get_approval_request.return_value = _open_row()
    result = validate_mempool_admission(
        vote_tx(voter=PARTNER, approve=False, reason="unknown recipient"), tip_view)
    assert result.is_valid is True, result.error
    assert result.data["slot"] == 20 and result.data["approve"] is False


def test_vote_on_unknown_request_is_refused(tip_view):
    tip_view.get_approval_request.return_value = None
    result = validate_mempool_admission(vote_tx(), tip_view)
    assert result.is_valid is False and result.code == "UNKNOWN_REQUEST"


def test_vote_on_resolved_request_is_refused(tip_view):
    tip_view.get_approval_request.return_value = _open_row(status=STATUS_EXECUTED)
    result = validate_mempool_admission(vote_tx(), tip_view)
    assert result.is_valid is False and result.code == "REQUEST_RESOLVED"


def test_vote_at_the_expiry_height_is_refused(tip_view):
    """The sweep runs AFTER the transaction loop, so admission must catch this."""
    tip_view.get_approval_request.return_value = _open_row(expire=NEXT_HEIGHT)
    result = validate_mempool_admission(vote_tx(), tip_view)
    assert result.is_valid is False and result.code == "REQUEST_EXPIRED"

    tip_view.get_approval_request.return_value = _open_row(expire=NEXT_HEIGHT + 1)
    assert validate_mempool_admission(vote_tx(), tip_view).is_valid is True


def test_an_undeclared_account_may_not_vote(tip_view):
    tip_view.get_approval_request.return_value = _open_row()
    result = validate_mempool_admission(vote_tx(voter=STRANGER), tip_view)
    assert result.is_valid is False and result.code == "NOT_AN_APPROVER"


def test_one_vote_per_approver(tip_view):
    tip_view.get_approval_request.return_value = _open_row(voted={18: AUTH})
    assert validate_mempool_admission(vote_tx(voter=AUTH), tip_view).code == "ALREADY_VOTED"
    tip_view.get_approval_request.return_value = _open_row(declined=[19])
    assert validate_mempool_admission(vote_tx(voter=SCAN), tip_view).code == "ALREADY_VOTED"


def test_malformed_vote_is_refused(tip_view):
    for bad in ({"request_id": "nothex"}, {"request_id": "ab"}, {"approve": 1}):
        tx = vote_tx()
        tx.update(bad)
        assert validate_transfer_vote_payload(tx, tip_view).is_valid is False


# --- the write/read split on the slot streams -------------------------------

def _user_tx(**over):
    tx = {"tx_type": "user_tx", "sender_pubkey": A, "operations": {"1": []}}
    tx.update(over)
    return tx


def test_a_sender_may_not_write_an_approval_slot(tip_view):
    """Without this the sender forges their own approval and the whole feature
    is decorative."""
    for slot in tau_defs.approval_slot_indices():
        tx = _user_tx(operations={str(slot): "1"})
        result = validate_user_tx_reserved_domains(tx, tip_view)
        assert result.is_valid is False, f"operations[{slot}] must be refused"
        assert "reserved" in result.error


def test_slots_are_writable_before_activation(tip_view):
    """They were ordinary custom streams, so pre-activation behaviour is
    unchanged -- that is what makes the cut safe for an existing chain."""
    tip_view.approval_slots_active = False
    tx = _user_tx(operations={"18": "1"})
    assert validate_user_tx_reserved_domains(tx, tip_view).is_valid is True


def test_a_plain_user_rule_may_not_type_a_slot(tip_view):
    rule = ("always ( (i12[t]:bv[384] = { #x" + A + " }:bv[384] && "
            "i18[t]:bv[384] = { #x" + AUTH + " }:bv[384]) -> "
            "(o5[t]:bv[24] = { #x000001 }:bv[24]) ).")
    result = validate_user_tx_reserved_domains(_user_tx(operations={"0": rule}), tip_view)
    assert result.is_valid is False
    assert "reserved consensus input stream" in result.error


# --- admission and apply must reject the same inputs ------------------------

SHAPE_CORPUS = [
    _request(approvers={}),
    _request(approvers={17: AUTH}),
    _request(approvers={18: AUTH, 19: AUTH}),
    _request(approvers={18: A}),
    _request(amount=0),
    _request(amount=tau_defs.MAX_TRANSFER_VALUE + 1),
    _request(custom_inputs={13: "x"}),
    _request(custom_inputs={25: "x"}),
    _request(expire_at_height=NEXT_HEIGHT),
    _request(expire_at_height=NEXT_HEIGHT + 10 ** 9),
    _request(),                      # the one valid entry
]


def test_admission_and_apply_agree_on_the_shape_corpus():
    """The stateless half is one function, so this is a guard against someone
    later re-implementing it on one side."""
    manager = ApprovalRequestLifecycleManager()
    for req in SHAPE_CORPUS:
        shape_ok = validate_request_shape(req, NEXT_HEIGHT) is None
        apply_ok = manager.can_admit_request(req, NEXT_HEIGHT)[0]
        assert shape_ok == apply_ok, f"divergence on {req.approvers} {req.amount}"
    assert validate_request_shape(SHAPE_CORPUS[-1], NEXT_HEIGHT) is None


# --- the signing preimage ---------------------------------------------------
#
# These transactions are applied LATER, from hash-bound state, by a DIFFERENT
# transaction. So any field omitted from the preimage is a field a proposer can
# rewrite between submission and execution -- redirecting funds the sender never
# agreed to send. The first version of this feature omitted all of them.

def test_every_request_field_is_signed():
    from consensus.tx_signing import signing_message_bytes

    req = {"sender_pubkey": A, "sequence_number": 1, "expiration_time": 1,
           "fee_limit": "0", "tx_type": "approval_request", "recipient_pubkey": B,
           "amount": 5000, "expire_at_height": 900,
           "approvers": {"18": AUTH}, "custom_inputs": {"26": "rent"}}
    base = signing_message_bytes(req)
    for field, tampered in [
        ("amount", 999999),
        ("recipient_pubkey", STRANGER),
        ("expire_at_height", 5),
        ("approvers", {"18": SCAN}),
        ("custom_inputs", {"26": "something else"}),
    ]:
        assert signing_message_bytes(dict(req, **{field: tampered})) != base, (
            f"{field} is not covered by the signature; a proposer could rewrite it"
        )


def test_request_approver_map_keys_sign_identically_as_int_or_str():
    """Wallets differ on whether JSON object keys come back as ints; the
    signature must not depend on which."""
    from consensus.tx_signing import signing_message_bytes

    req = {"sender_pubkey": A, "sequence_number": 1, "expiration_time": 1,
           "fee_limit": "0", "tx_type": "approval_request", "recipient_pubkey": B,
           "amount": 5000, "expire_at_height": 900, "approvers": {"18": AUTH},
           "custom_inputs": {}}
    assert (signing_message_bytes(req)
            == signing_message_bytes(dict(req, approvers={18: AUTH})))


def test_every_vote_field_is_signed():
    from consensus.tx_signing import signing_message_bytes

    vote = {"sender_pubkey": AUTH, "sequence_number": 0, "expiration_time": 1,
            "fee_limit": "0", "tx_type": "transfer_vote", "request_id": "ab" * 32,
            "approve": True, "reason": "looks fine"}
    base = signing_message_bytes(vote)
    for field, tampered in [("request_id", "cd" * 32), ("approve", False),
                            ("reason", "words the approver never wrote")]:
        assert signing_message_bytes(dict(vote, **{field: tampered})) != base, (
            f"{field} is not covered by the signature"
        )
