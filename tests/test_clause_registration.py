"""Clause registration: one engine build per clause, judged per account.

A clause lives in the registry and is evaluated on its own for its owner. The
only engine call at registration is "does `always ( body ).` build", at admission
and at apply, so the number of authors costs nothing at either. Mock evaluator
throughout; the real one is in test_clause_registration_native.py.
"""
import itertools
import json
import time
from contextlib import ExitStack
from unittest.mock import patch

import pytest

import chain_state
import db
import tau_defs
from block import Block
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_payload
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import RuleOffer, clause_body_v1
from consensus.state import TauStateSnapshot
from commands import sendtx
from tau_speculation import SpeculationError, WorkerLost, WorkerTimeout

import test_approval_apply as ap

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
HEIGHT = 20
LIMIT = 1000
AUTHORS = 70
RULE_BUDGET = 8

BLOCK_RULE = "always ( (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
LIMIT_RULE = (
    "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
OPEN_RULE = (
    "always ( (i1[t]:bv[24] > { #xfffff0 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
BLOCK_BODY = clause_body_v1(BLOCK_RULE)
LIMIT_BODY = clause_body_v1(LIMIT_RULE)
OPEN_BODY = clause_body_v1(OPEN_RULE)
RULES = (BLOCK_RULE, LIMIT_RULE, OPEN_RULE)

_SEQ = itertools.count()


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def verdict_evaluator(pool="apply"):
    """Blocks everything, nothing above LIMIT, or nothing, by clause body."""
    evaluator = MockPolicyEvaluator(pool=pool)
    evaluator.set_verdict(BLOCK_BODY, "0")
    evaluator.set_verdict(
        LIMIT_BODY, lambda inputs: "0" if int(inputs.get("i1", "0")) > LIMIT else "1")
    evaluator.set_verdict(OPEN_BODY, "1")
    return evaluator


def expected_blocked(rule, amount):
    return rule is BLOCK_RULE or (rule is LIMIT_RULE and amount > LIMIT)


# --- a block-apply harness with a main interpreter that allows everything -------

class Chain:
    """Applies blocks one after another through the real engine."""

    def __init__(self, keys, extra_balances=None):
        self.height = HEIGHT
        self.lifecycle = ConsensusLifecycleManager(active_validators=[ap.ALICE])
        self.lifecycle.activate_approval_slots()
        balances = {pk: 1_000_000 for _, pk in keys}
        balances.update(extra_balances or {})
        balances[ap.ALICE] = 1_000_000
        self.snapshot = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": balances,
                "sequence_numbers": {},
                "last_transfer_ts": {},
                "lifecycle_manager": self.lifecycle,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        self.rule_feeds = []

    def apply(self, txs):
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=self.snapshot.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ap.ALICE)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash="00" * 32, transactions=txs,
            proposer_pubkey=ap.ALICE, timestamp=1234567890,
        )
        persisted = []

        def single(**kwargs):
            if kwargs.get("rule_text"):
                self.rule_feeds.append(kwargs["rule_text"])
                if kwargs.get("apply_rules_update"):
                    persisted.append(str(kwargs["rule_text"]).strip())
            return "T"

        def multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            return {1: str(vals.get(1, "0")), 5: "1", 8: "0", 9: "0"}

        with patch("tau_manager.communicate_with_tau", side_effect=single), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=multi), \
             patch("chain_state.get_application_rules_state",
                   side_effect=lambda: "\n".join(persisted)), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = TauConsensusEngine().apply_block(view, block, self.snapshot)
        self.snapshot = result.next_snapshot
        self.lifecycle = self.snapshot.metadata["lifecycle_manager"]
        self.height += 1
        return result

    def apply_in_budget(self, txs):
        """Blocks of at most the per-block rule budget; returns all results."""
        results = []
        for start in range(0, len(txs), RULE_BUDGET):
            results.append(self.apply(txs[start:start + RULE_BUDGET]))
        return results

    def clause(self, pubkey):
        return self.lifecycle.rule_offers.clause_for(pubkey, STREAM)


def _base(tx_type, sender, seq, fee_limit="0"):
    return {
        "tx_id": f"{tx_type}-{next(_SEQ)}", "tx_type": tx_type,
        "sender_pubkey": sender, "sequence_number": seq,
        "expiration_time": 9999999999, "expire_at_height": 5000,
        "fee_limit": fee_limit,
    }


def routed_tx(sk, pubkey, rule, seq=0):
    tx = _base("user_tx", pubkey, seq, fee_limit="100")
    tx["operations"] = {"0": rule}
    return sign_payload(tx, sk)


def accept_tx(sk, offer, seq=0):
    tx = _base("rule_offer_accept", offer.recipient_pubkey, seq)
    tx.update(offer_id=offer.offer_id_hex, rule_text=offer.rule_text)
    return sign_payload(tx, sk)


def transfer_tx(sk, pubkey, amount, seq):
    tx = _base("user_tx", pubkey, seq, fee_limit="100")
    tx["operations"] = {"1": [[pubkey, ap.BOB, str(amount)]]}
    return sign_payload(tx, sk)


def offer_to(chain, recipient, rule):
    offer = RuleOffer(offerer_pubkey=ap.STRANGER, recipient_pubkey=recipient,
                      rule_text=rule, expire_at_height=5000)
    assert chain.lifecycle.rule_offers.submit_offer(offer)
    return offer


# --- 1. many authors, each judged by its own clause ---------------------------

def test_seventy_authors_register_and_each_is_judged_by_its_own_clause():
    keys = [(7000 + i, pubkey_hex(7000 + i)) for i in range(AUTHORS)]
    chain = Chain(keys)
    evaluator = verdict_evaluator()
    sender_policy.set_evaluator("apply", evaluator)

    rules = {}
    registrations = []
    for i, (sk, pk) in enumerate(keys):
        rules[pk] = RULES[i % len(RULES)]
        if i % 2 == 0:
            registrations.append(routed_tx(sk, pk, rules[pk]))
        else:
            registrations.append(accept_tx(sk, offer_to(chain, pk, rules[pk])))

    for result in chain.apply_in_budget(registrations):
        assert not result.invalid_tx_ids, result.outcomes

    registry = chain.lifecycle.rule_offers.clauses_for_stream(STREAM)
    assert len(registry) == AUTHORS
    assert {pk: registry[pk] for _, pk in keys} == {
        pk: clause_body_v1(rule) for pk, rule in rules.items()}
    assert evaluator.validate_calls.count(BLOCK_BODY) + \
        evaluator.validate_calls.count(LIMIT_BODY) + \
        evaluator.validate_calls.count(OPEN_BODY) == AUTHORS
    assert chain.rule_feeds == [], "a clause reached the main interpreter"

    amounts = {pk: 2000 if i % 4 < 2 else 500 for i, (_, pk) in enumerate(keys)}
    stranger_sk = 9999
    stranger = pubkey_hex(stranger_sk)
    chain.snapshot.metadata["balances"][stranger] = 1_000_000
    transfers = [transfer_tx(sk, pk, amounts[pk], seq=1) for sk, pk in keys]
    transfers.append(transfer_tx(stranger_sk, stranger, 2000, seq=0))
    evaluator.verdict_calls.clear()
    result = chain.apply(transfers)

    blocked = {tx["sender_pubkey"] for tx in transfers
               if tx["tx_id"] in result.invalid_tx_ids}
    assert blocked == {pk for _, pk in keys if expected_blocked(rules[pk], amounts[pk])}
    assert 0 < len(blocked) < AUTHORS
    assert stranger not in blocked

    asked = [(body, inputs["i12"]) for body, inputs in evaluator.verdict_calls]
    assert sorted(asked) == sorted(
        (clause_body_v1(rules[pk]), "#x" + pk) for _, pk in keys)
    assert all(who != "#x" + stranger for _, who in asked), \
        "a sender with no clause was sent to the evaluator"


def test_a_clause_that_reads_the_balance_is_fed_the_parent_balance():
    floor_rule = (
        "always ( ((i2[t]:bv[24] - i1[t]:bv[24]) < { #x0003e8 }:bv[24]) "
        "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )
    body = clause_body_v1(floor_rule)
    sk, pk = 7500, pubkey_hex(7500)
    chain = Chain([(sk, pk)])
    chain.snapshot.metadata["balances"][pk] = 5000
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.set_verdict(
        body, lambda inputs: "0" if int(inputs["i2"]) - int(inputs["i1"]) < 1000 else "1")
    sender_policy.set_evaluator("apply", evaluator)

    (result,) = chain.apply_in_budget([routed_tx(sk, pk, floor_rule)])
    assert not result.invalid_tx_ids
    assert chain.clause(pk) == body

    evaluator.verdict_calls.clear()
    keeps = transfer_tx(sk, pk, 3000, seq=1)
    drains = transfer_tx(sk, pk, 4500, seq=2)
    result = chain.apply([keeps, drains])

    assert [inputs["i2"] for _, inputs in evaluator.verdict_calls] == ["5000", "5000"]
    assert result.invalid_tx_ids == [drains["tx_id"]]


# --- 2. apply: one build per registration, hard reject when it fails -------------

def _open_request_lifecycle():
    lm = ap._lm()
    lm.rule_offers.accepted_clauses[(ap.ALICE, STREAM)] = BLOCK_BODY
    request = ap._request()
    assert lm.approval_requests.submit_request(request)
    return lm, request


def test_registration_builds_the_clause_once_and_feeds_nothing():
    evaluator = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", evaluator)
    result, lm, _calls = ap._apply([ap.rule_tx(LIMIT_RULE)])
    assert lm.rule_offers.clause_for(ap.ALICE, STREAM) == LIMIT_BODY
    assert evaluator.validate_calls == [LIMIT_BODY]
    assert not [c for c in ap._apply.single_calls if c.get("rule_text")]


@pytest.mark.parametrize("door", ["routed", "accept"])
def test_a_clause_that_does_not_build_is_hard_rejected(door):
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.fail_build(LIMIT_BODY, "Incompatible type information")
    sender_policy.set_evaluator("apply", evaluator)
    lm, request = _open_request_lifecycle()
    if door == "routed":
        tx = ap.rule_tx(LIMIT_RULE)
    else:
        offer = RuleOffer(offerer_pubkey=ap.STRANGER, recipient_pubkey=ap.ALICE,
                          rule_text=LIMIT_RULE, expire_at_height=5000)
        assert lm.rule_offers.submit_offer(offer)
        tx = accept_tx(ap.SK_ALICE, offer)
    before = dict(lm.rule_offers.accepted_clauses)

    result, post, _calls = ap._apply([tx], lm=lm)

    assert tx["tx_id"] in result.invalid_tx_ids
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    assert outcome.reason == "rule_not_applied"
    assert "Incompatible type information" in ap._logs(result)
    assert post.rule_offers.accepted_clauses == before
    assert post.approval_requests.get_request(request.request_id) is not None
    assert request.request_id not in post.approval_requests.resolved
    if door == "accept":
        assert post.rule_offers.get_offer(offer.offer_id) is not None


def test_a_revocation_makes_no_evaluator_call():
    evaluator = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", evaluator)
    lm, _request = _open_request_lifecycle()
    result, post, _calls = ap._apply([ap.rule_tx(ap.NEUTRAL_RULE)], lm=lm)
    assert post.rule_offers.clause_for(ap.ALICE, STREAM) is None
    assert evaluator.validate_calls == [] and evaluator.verdict_calls == []


def test_a_lost_evaluator_is_not_a_rejection_at_registration():
    class _Lost:
        def validate(self, *a, **k):
            raise WorkerLost("gone")

    sender_policy.set_evaluator("apply", _Lost())
    with pytest.raises(WorkerLost):
        ap._apply([ap.rule_tx(LIMIT_RULE)])


# --- 3. admission: one build in the admission pool ------------------------------

SENDER_SK, SENDER = SK_ALICE, pubkey_hex(SK_ALICE)
RECIPIENT_SK, RECIPIENT = SK_BOB, pubkey_hex(SK_BOB)


@pytest.fixture
def node(temp_database):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state.load_genesis("data/genesis.json")
    db.clear_mempool()
    chain_state._balances[SENDER] = 100000
    chain_state._balances[RECIPIENT] = 100000
    db.set_chain_state_value("approval_slots_active", "1")
    with ExitStack() as stack:
        for target, kwargs in (
            ("commands.sendtx._validate_bls12_381_pubkey", {"return_value": (True, None)}),
            ("tau_manager.is_force_test_enabled", {"return_value": False}),
            ("tau_manager.communicate_with_tau_multi", {"return_value": {1: "1", 5: "1"}}),
        ):
            stack.enter_context(patch(target, **kwargs))
        ready = stack.enter_context(patch("tau_manager.tau_ready"))
        ready.is_set.return_value = True
        yield


def _seed_offer(rule):
    offer = RuleOffer(offerer_pubkey=SENDER, recipient_pubkey=RECIPIENT,
                      rule_text=rule, expire_at_height=5000)
    db.save_canonical_state_atomically(
        "head", 1, {}, {}, "", "", "", [], [], [], [],
        rule_offers=[{
            "offer_id": offer.offer_id_hex, "offerer_pubkey": SENDER,
            "recipient_pubkey": RECIPIENT, "rule_text": rule,
            "expire_at_height": 5000, "status": "offered",
        }],
        approval_slots_active=True,
    )
    return offer


def _envelope(tx_type, sender):
    return {
        "tx_type": tx_type, "sender_pubkey": sender,
        "sequence_number": chain_state.get_sequence_number(sender),
        "expiration_time": int(time.time()) + 1000, "expire_at_height": 5000,
        "fee_limit": "1000",
    }


def _submit_offer(rule):
    tx = _envelope("rule_offer", SENDER)
    tx.update(recipient_pubkey=RECIPIENT, rule_text=rule, expire_at_height=5000)
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, SENDER_SK)))


def _submit_accept(rule):
    offer = _seed_offer(rule)
    tx = _envelope("rule_offer_accept", RECIPIENT)
    tx.update(offer_id=offer.offer_id_hex, rule_text=rule)
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, RECIPIENT_SK)))


def _submit_routed(rule):
    tx = _envelope("user_tx", SENDER)
    tx["operations"] = {"0": rule}
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, SENDER_SK)))


DOORS = {"offer": _submit_offer, "accept": _submit_accept, "routed": _submit_routed}


def _admission_pools(evaluator):
    applied = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("admission", evaluator)
    sender_policy.set_evaluator("apply", applied)
    return applied


@pytest.mark.parametrize("door", DOORS)
def test_admission_builds_the_clause_once_in_the_admission_pool(node, door):
    evaluator = MockPolicyEvaluator(pool="admission")
    applied = _admission_pools(evaluator)
    res = DOORS[door](LIMIT_RULE)
    assert res["ok"] is True, res
    assert evaluator.validate_calls == [LIMIT_BODY]
    assert applied.validate_calls == []


@pytest.mark.parametrize("door", DOORS)
def test_admission_rejects_a_clause_that_does_not_build(node, door):
    evaluator = MockPolicyEvaluator(pool="admission")
    evaluator.fail_build(LIMIT_BODY, "Incompatible type information")
    _admission_pools(evaluator)
    res = DOORS[door](LIMIT_RULE)
    assert res["ok"] is False and res["code"] == "TX_REJECTED"
    assert "Incompatible type information" in res["message"]
    assert db.get_mempool_txs() == []


@pytest.mark.parametrize("door", DOORS)
@pytest.mark.parametrize("exc, code", [
    (WorkerTimeout("slow"), "ADMISSION_TIMEOUT"),
    (WorkerLost("gone"), "ADMISSION_UNAVAILABLE"),
    (SpeculationError("protocol"), "ADMISSION_UNAVAILABLE"),
])
def test_an_unavailable_evaluator_is_operational_at_admission(node, door, exc, code):
    class _Failing:
        def validate(self, *a, **k):
            raise exc

    _admission_pools(_Failing())
    res = DOORS[door](LIMIT_RULE)
    assert res["ok"] is False and res["code"] == code
    assert db.get_mempool_txs() == []


def test_admission_of_a_revocation_makes_no_evaluator_call(node):
    evaluator = MockPolicyEvaluator(pool="admission")
    _admission_pools(evaluator)
    db.save_canonical_state_atomically(
        "head", 1, {}, {}, "", "", "", [], [], [], [],
        rule_clauses=[{"acceptor_pubkey": SENDER, "target_stream": STREAM,
                       "clause_body": LIMIT_BODY}],
        approval_slots_active=True,
    )
    res = _submit_routed(ap.NEUTRAL_RULE)
    assert res["ok"] is True, res
    assert evaluator.validate_calls == []


# --- 4. boot: the restore plan does not know the registry -----------------------

def test_the_restore_plan_is_the_same_with_an_empty_and_a_large_registry(
        temp_database, monkeypatch):
    lifecycle = ConsensusLifecycleManager(active_validators=[ap.ALICE])
    monkeypatch.setattr(chain_state, "_lifecycle_manager", lifecycle)
    empty = chain_state.get_tau_restore_plan()
    assert empty, "the plan carries at least the consensus unit"

    for i in range(200):
        lifecycle.rule_offers.accepted_clauses[(format(i + 1, "096x"), STREAM)] = LIMIT_BODY
    assert chain_state.get_tau_restore_plan() == empty
