"""Receive routes behind a rule-change guard (#35): kinds 8 and 9.

A guarded account cannot set, replace or remove its receive route directly; it
files a rule-change request that releases on co-signatures or after the time
escape, exactly like an o5 change. One stolen key therefore cannot silently
redirect what the account is paid (acceptance case 5).

A lock is not the owner's to lift: a remove released while the route is locked
fails, however many of the owner's co-signers approved it.
"""
import json

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from consensus import sender_policy
from consensus.approvals import (
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_OPEN,
    parse_rule_change_request,
    parse_rule_change_request_checked,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.receive_route import RouteTerms, route_spec_text
from consensus.tx_checks import apply_tx_error

from test_rule_change_requests import ALICE, BOB, GUARD_BODY, HEIGHT, _request, _tx
from test_rule_change_release import D, LATE, Chain, _guarded, _vote

KIND_SET = tau_defs.RULE_CHANGE_KIND_SET_ROUTE
KIND_REMOVE = tau_defs.RULE_CHANGE_KIND_REMOVE_ROUTE
DAVE = G2Basic.SkToPk(77777).hex()
TS = 1234567890            # the block timestamp the rule-change harness uses
LOCK_END = TS + 30 * 86400


def spec(**over):
    fields = {"destination_pubkey": DAVE, "share_bps": 2000}
    fields.update(over)
    return route_spec_text(fields)


@pytest.fixture(autouse=True)
def evaluators():
    """The guard allows a change only once slot i18 holds a pubkey."""
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _parked(kind, text="", seq=0, chain=None):
    req = _request(kind, text=text, seq=seq, expire=LATE)
    chain = chain or Chain(_guarded())
    chain.block(_tx(req))
    return chain, req


def _events(result):
    return result.next_snapshot.metadata["route_events"]


def test_a_request_body_carries_the_spec_and_its_sequence():
    req = parse_rule_change_request(_tx(_request(KIND_SET, text=spec(), seq=4)))
    assert req is not None
    assert json.loads(req.body) == {"destination_pubkey": DAVE, "share_bps": 2000,
                                    "sequence_number": 4}


@pytest.mark.parametrize("text, why", [
    ("{}", "destination_pubkey"),
    (spec().replace(",", ", "), "canonical"),
    (json.dumps({"destination_pubkey": DAVE, "min_amount": 0, "share_bps": 2000},
                separators=(",", ":")), "canonical"),
    (json.dumps({"destination_pubkey": DAVE, "locked": False, "share_bps": 2000},
                separators=(",", ":")), "canonical"),
    (json.dumps({"destination_pubkey": DAVE, "share_bps": 2000, "x": 1}), "may carry only"),
])
def test_a_request_with_a_bad_spec_is_refused_up_front(text, why):
    req, error = parse_rule_change_request_checked(_tx(_request(KIND_SET, text=text)))
    assert req is None and why in error


def test_a_destination_that_is_not_a_key_is_refused_at_apply():
    tx = _tx(_request(KIND_SET, text=spec(destination_pubkey="ab" * 48)))
    assert "destination_pubkey" in apply_tx_error(tx)[1]


def test_a_set_parks_then_releases_on_the_co_signature():
    chain, req = _parked(KIND_SET, spec())
    assert chain.entry(req).status == STATUS_OPEN
    assert chain.lm.receive_routes.get(ALICE) is None
    result = chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_EXECUTED
    terms = chain.lm.receive_routes.get(ALICE)
    assert (terms.destination_pubkey, terms.share_bps, terms.sequence_number) == (DAVE, 2000, 0)
    assert [e["outcome"] for e in _events(result)] == ["installed"]


def test_a_set_releases_by_the_time_escape():
    chain, req = _parked(KIND_SET, spec())
    chain.block(height=HEIGHT + D - 1)
    assert chain.lm.receive_routes.get(ALICE) is None
    chain.block(height=HEIGHT + D)
    assert chain.entry(req).status == STATUS_EXECUTED
    assert chain.lm.receive_routes.get(ALICE) is not None


def test_a_remove_releases_like_any_change():
    chain, install = _parked(KIND_SET, spec())
    chain.block(_vote(install.request_id))
    remove = _request(KIND_REMOVE, seq=1, expire=LATE)
    chain.block(_tx(remove))
    assert chain.lm.receive_routes.get(ALICE) is not None
    result = chain.block(_vote(remove.request_id, seq=1))
    assert chain.entry(remove).status == STATUS_EXECUTED
    assert chain.lm.receive_routes.get(ALICE) is None
    assert [e["outcome"] for e in _events(result)] == ["removed"]


def test_a_remove_request_needs_a_route():
    chain = Chain(_guarded())
    req = _request(KIND_REMOVE, expire=LATE)
    chain.block(_tx(req))
    assert chain.book.get_rule_change(req.request_id) is None


def test_a_remove_request_of_a_locked_route_is_refused_up_front():
    chain = Chain(_guarded())
    chain.lm.receive_routes.install(
        RouteTerms(ALICE, 0, DAVE, 2000, expires_at=LOCK_END, locked=True))
    req = _request(KIND_REMOVE, expire=LATE)
    chain.block(_tx(req))
    assert chain.book.get_rule_change(req.request_id) is None


def test_a_lock_set_after_a_parked_remove_still_holds_at_release():
    """The remove parks while the route is free; a locked route released first
    replaces it; the co-signed remove then fails: the lock is the destination's."""
    chain, install = _parked(KIND_SET, spec())
    chain.block(_vote(install.request_id))
    remove = _request(KIND_REMOVE, seq=1, expire=LATE)
    chain.block(_tx(remove))
    lock = _request(KIND_SET, text=spec(locked=True, expires_at=LOCK_END), seq=2,
                    expire=LATE)
    chain.block(_tx(lock))
    chain.block(_vote(lock.request_id, seq=1))
    assert chain.lm.receive_routes.get(ALICE).locked
    chain.block(_vote(remove.request_id, seq=2))
    assert chain.entry(remove).status == STATUS_FAILED
    assert chain.lm.receive_routes.get(ALICE).locked


def test_a_set_that_became_unsafe_before_release_fails():
    """DAVE -> ALICE appears while ALICE -> DAVE waits: the loop check runs again."""
    chain, req = _parked(KIND_SET, spec())
    chain.lm.receive_routes.install(RouteTerms(DAVE, 0, ALICE, 1000))
    chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_FAILED
    assert chain.lm.receive_routes.get(ALICE) is None


def test_a_set_that_has_already_ended_is_refused_up_front():
    chain = Chain(_guarded())
    req = _request(KIND_SET, text=spec(expires_at=TS), expire=LATE)
    chain.block(_tx(req))
    assert chain.book.get_rule_change(req.request_id) is None


def test_the_kinds_have_names():
    from commands.getapprovalrequests import KIND_NAMES

    assert KIND_NAMES[KIND_SET] == "set_receive_route"
    assert KIND_NAMES[KIND_REMOVE] == "remove_receive_route"
    assert BOB != ALICE
