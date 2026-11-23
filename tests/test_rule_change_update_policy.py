"""Bounty 01, FIX 5: rule-change kind 6 UPDATE_POLICY.

A guarded update of an account's existing o5 policy: unlike
revoke+set, an update never leaves the account without a policy, so
the lineage is one unbroken chain — SET, then UPDATE, then UPDATE...
— and a per-policy version recorded on the rule-offers book counts
its writes. The hole this closes is the one #178 itself admits:
revoke+set loses lineage.

Covered: parse (kind 6 carries a body, same shape checks as a set:
o5-only, never neutral, no offer id; kind 7 is refused); admission
(the precondition "a policy must exist"); the release flow (a set
then an update executes in its own blocks, the policy is never
absent between them, the version counts 1 then 2); an update with no
policy is refused at admission and at apply, and an update after a
revoke is refused the same way; the per-policy version record
(counting, roots, snapshot round-trip, meta-hash gating).
"""
import pytest

import tau_defs
from consensus import sender_policy
from consensus.approvals import (
    STATUS_EXECUTED,
    parse_rule_change_request_checked,
)
from consensus.governance import build_mechanism_metadata
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import RuleOfferLifecycleManager, clause_body_v1
from consensus.serialization import compute_policy_versions_root

from test_rule_change_release import Chain  # noqa: F401
from test_rule_change_requests import (  # noqa: F401
    ALICE,
    BOB,
    HEIGHT,
    KIND_REVOKE,
    KIND_SET,
    OTHER_TEXT,
    POLICY_KEY,
    SET_TEXT,
    _admit,
    _lm,
    _request,
    _tx,
)

KIND_UPDATE = tau_defs.RULE_CHANGE_KIND_UPDATE_POLICY
UPDATE_BODY = clause_body_v1(OTHER_TEXT)
SET_BODY = clause_body_v1(SET_TEXT)


@pytest.fixture(autouse=True)
def evaluators():
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


# --- parse ------------------------------------------------------------------------


def test_parse_accepts_kind_6_with_a_policy_body():
    req, why = parse_rule_change_request_checked(
        _tx(_request(KIND_UPDATE, text=OTHER_TEXT)))
    assert req is not None and why == ""
    assert req.kind == KIND_UPDATE
    assert req.body == UPDATE_BODY


def test_parse_refuses_kind_13_and_an_empty_or_neutral_update():
    _, why = parse_rule_change_request_checked(
        _tx(_request(13, text=OTHER_TEXT)))
    assert "kind must be 1..12" in why
    _, why = parse_rule_change_request_checked(
        _tx(_request(KIND_UPDATE, text="")))
    assert "needs a non-empty rule_text" in why
    _, why = parse_rule_change_request_checked(
        _tx(_request(KIND_UPDATE, text="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")))
    assert "revoke (kind 2), not a set" in why


def test_parse_refuses_an_update_that_writes_more_than_o5():
    _, why = parse_rule_change_request_checked(
        _tx(_request(KIND_UPDATE, text=(
            "always ( (o5[t]:bv[24] = { #x000002 }:bv[24]) && "
            "(o6[t]:bv[16] = { #x0001 }:bv[16]) )."))))
    assert "must write o5 and nothing else" in why


def test_parse_refuses_an_update_carrying_an_offer_id():
    _, why = parse_rule_change_request_checked(
        _tx(_request(KIND_UPDATE, text=OTHER_TEXT, offer_id="ab" * 32)))
    assert "carries no offer_id" in why


# --- admission ----------------------------------------------------------------------


def test_admission_refuses_an_update_with_no_policy_to_update():
    lm = _lm()
    result = _admit(_tx(_request(KIND_UPDATE, text=OTHER_TEXT)), lm)
    assert not result.is_valid
    assert "no registered o5 policy to update" in (result.error or "")


def test_admission_accepts_an_update_when_a_policy_exists():
    lm = _lm(policy=True)
    result = _admit(_tx(_request(KIND_UPDATE, text=OTHER_TEXT)), lm)
    assert result.is_valid


# --- release flow ---------------------------------------------------------------------


def test_set_then_update_executes_and_the_policy_is_never_absent():
    chain = Chain(_lm())
    set_req = _request(KIND_SET)
    chain.block(_tx(set_req))
    assert chain.entry(set_req).status == STATUS_EXECUTED
    assert chain.clause(POLICY_KEY) == SET_BODY
    assert chain.lm.rule_offers.policy_version(ALICE) == 1

    update_req = _request(KIND_UPDATE, text=OTHER_TEXT, seq=1)
    chain.block(_tx(update_req))
    assert chain.entry(update_req).status == STATUS_EXECUTED
    # The update replaced the body in place: the account was never
    # without a policy between the two blocks, and the version counts
    # the write.
    assert chain.clause(POLICY_KEY) == UPDATE_BODY
    assert chain.lm.rule_offers.policy_version(ALICE) == 2


def test_a_second_update_counts_a_third_version():
    chain = Chain(_lm())
    chain.block(_tx(_request(KIND_SET)))
    chain.block(_tx(_request(KIND_UPDATE, text=OTHER_TEXT, seq=1)))
    chain.block(_tx(_request(KIND_UPDATE, text=SET_TEXT, seq=2)))
    assert chain.clause(POLICY_KEY) == SET_BODY
    assert chain.lm.rule_offers.policy_version(ALICE) == 3


def test_update_with_no_policy_is_refused_at_apply():
    chain = Chain(_lm())
    update_req = _request(KIND_UPDATE, text=OTHER_TEXT)
    result = chain.block(_tx(update_req))
    assert _tx(update_req)["tx_id"] not in result.accepted_tx_ids
    assert chain.clause(POLICY_KEY) is None
    assert chain.lm.rule_offers.policy_version(ALICE) == 0


def test_update_after_a_revoke_is_refused_at_admission_and_apply():
    chain = Chain(_lm(policy=True))
    revoke_req = _request(KIND_REVOKE)
    chain.block(_tx(revoke_req))
    assert chain.clause(POLICY_KEY) is None
    # The revoke removed the policy; the lineage is broken, and an
    # update cannot restart it — only a fresh set can.
    assert not _admit(
        _tx(_request(KIND_UPDATE, text=OTHER_TEXT, seq=1)), chain.lm).is_valid
    update_req = _request(KIND_UPDATE, text=OTHER_TEXT, seq=1)
    result = chain.block(_tx(update_req))
    assert _tx(update_req)["tx_id"] not in result.accepted_tx_ids
    assert chain.lm.rule_offers.policy_version(ALICE) == 0


# --- the per-policy version record ------------------------------------------------------


def test_policy_version_counts_writes_and_nothing_else():
    mgr = RuleOfferLifecycleManager()
    assert mgr.policy_version(ALICE) == 0
    assert mgr.policy_versions_root() == b""
    assert mgr.is_empty()
    assert mgr.record_policy_write(ALICE) == 1
    assert mgr.policy_version(ALICE) == 1
    assert mgr.record_policy_write(ALICE) == 2
    assert mgr.policy_version(ALICE) == 2
    assert mgr.policy_version(BOB) == 0
    assert not mgr.is_empty()


def test_policy_versions_root_is_deterministic_and_version_sensitive():
    a = RuleOfferLifecycleManager()
    b = RuleOfferLifecycleManager()
    a.record_policy_write(ALICE)
    b.record_policy_write(ALICE)
    assert a.policy_versions_root() == b.policy_versions_root()
    assert len(a.policy_versions_root()) == 32
    b.record_policy_write(ALICE)
    assert a.policy_versions_root() != b.policy_versions_root()
    c = RuleOfferLifecycleManager()
    c.record_policy_write(BOB)
    assert a.policy_versions_root() != c.policy_versions_root()


def test_policy_versions_snapshot_round_trips():
    mgr = RuleOfferLifecycleManager()
    mgr.record_policy_write(ALICE)
    mgr.record_policy_write(ALICE)
    mgr.record_policy_write(BOB)
    rows = mgr.snapshot_policy_versions()
    assert rows == [
        {"acceptor_pubkey": ALICE, "target_stream": 5, "version": 2},
        {"acceptor_pubkey": BOB, "target_stream": 5, "version": 1},
    ]
    rebuilt = RuleOfferLifecycleManager(
        policy_versions={
            (r["acceptor_pubkey"], r["target_stream"]): r["version"]
            for r in rows
        }
    )
    assert rebuilt.policy_versions_root() == mgr.policy_versions_root()
    assert rebuilt.policy_version(ALICE) == 2


def test_compute_policy_versions_root_sorts_its_inputs():
    forward = compute_policy_versions_root([(ALICE, 5, 1), (BOB, 5, 2)])
    reversed_ = compute_policy_versions_root([(BOB, 5, 2), (ALICE, 5, 1)])
    assert forward == reversed_
    assert len(forward) == 32


def test_mechanism_metadata_emits_the_versions_root_only_when_set():
    plain = build_mechanism_metadata("quorum", rule_offers_root="ab" * 32,
                                     rule_clauses_root="cd" * 32)
    assert "rule_policy_versions_root" not in plain
    with_versions = build_mechanism_metadata(
        "quorum", rule_offers_root="ab" * 32, rule_clauses_root="cd" * 32,
        rule_policy_versions_root="ef" * 32)
    assert with_versions["rule_policy_versions_root"] == "ef" * 32
