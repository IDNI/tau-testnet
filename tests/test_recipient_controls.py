"""Exercise the signed rule, wallet dry run and block paths with the same payments."""
import json
import time

import pytest

import chain_state
import db
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from commands import checktx, sendtx
from consensus import sender_policy
from consensus.admission import TipAdmissionView
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import parse_retractable_transfer
from consensus.rule_offers import clause_body_v1
from test_checktx_estimate import node  # noqa: F401 -- worker-backed admission fixture
from test_clause_registration import routed_tx
from test_retractable_apply import Chain

A, B, C = map(pubkey_hex, (SK_ALICE, SK_BOB, SK_CAROL))
KEYS = {A: SK_ALICE, B: SK_BOB, C: SK_CAROL}
HEIGHT = 50
INBOUND = (
    f"always ( (i3[t]:bv[384] = {{ #x{A} }}:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
OUTBOUND = (
    "always ( (i1[t]:bv[24] > { #x000064 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def deploy(owner=B, seq=0, **policy):
    rule = "recipient_v1 o5[t] " + json.dumps(policy)
    return routed_tx(KEYS[owner], owner, rule, seq=seq)


def new_chain(*, active=True, slots=False):
    chain = Chain({A: 100_000, B: 100_000, C: 100_000}, fee=7, slots=slots)
    chain.lm.recipient_controls_active = active
    return chain


def transaction(sender, seq, tx_type="user_tx", **fields):
    return sign_payload({
        "tx_id": f"{sender[:8]}-{seq}-{tx_type}", "tx_type": tx_type,
        "sender_pubkey": sender, "sequence_number": seq,
        "expire_at_height": HEIGHT + 5, "expiration_time": 9_999_999_999,
        "fee_limit": "100", **fields,
    }, KEYS[sender])


def transfer(sender, seq, *legs):
    return transaction(sender, seq, operations={
        "1": [[sender, recipient, str(amount)] for recipient, amount in legs]
    })


def park(sender, seq, now, *, seconds=None, blocks=None):
    release = (
        {"release_at_time": now + seconds, "expiration_time": now + seconds - 1}
        if seconds is not None else
        {"release_at_height": HEIGHT + blocks, "expire_at_height": HEIGHT + 1}
    )
    return transaction(sender, seq, "retractable_transfer", recipient_pubkey=B,
                       amount=17, **release)


def install(chain, tx, *, replay=False):
    result = chain.block([tx], height=HEIGHT - 1, replay=replay)
    assert result.accepted_tx_ids == [tx["tx_id"]], result.outcomes


def publish_tip(chain, monkeypatch, now):
    monkeypatch.setattr(chain_state, "_lifecycle_manager", chain.lm)
    monkeypatch.setattr(TipAdmissionView, "next_block_timestamp", property(lambda _: now))
    db.save_canonical_state_atomically(
        "head", HEIGHT - 1, chain.bal, chain.seq, "", "", "", [], [], [], [],
        rule_clauses=chain.lm.rule_offers.clause_plan(),
        retractable_transfers=chain_state._retractable_state(chain.lm),
    )


def estimate(tx):
    return json.loads(checktx.execute("checktx estimate " + json.dumps(tx), None))


@pytest.fixture(autouse=True)
def recipient_workers():
    pools = ("recipient-admission", "recipient-apply")
    try:
        for pool in pools:
            worker = MockPolicyEvaluator(pool=pool)
            worker.set_verdict(clause_body_v1(INBOUND), lambda values: (
                "1" if values["i3"] == "#x" + A else "0"
            ))
            sender_policy.set_evaluator(pool, worker)
        yield
    finally:
        for pool in pools:
            sender_policy.set_evaluator(pool, None)


def set_mock_outbound():
    for pool in ("apply", "admission"):
        evaluator = sender_policy.evaluator(pool)
        evaluator.set_verdict(clause_body_v1(OUTBOUND), lambda values: (
            "1" if int(values["i1"]) <= 100 else "0"
        ))


@pytest.mark.parametrize("slots", [False, True])
def test_allowlist_and_outbound_rule_share_an_account(node, monkeypatch, slots):
    set_mock_outbound()
    chain = new_chain(slots=slots)
    now = int(time.time())
    install(chain, deploy(inbound=INBOUND, outbound=OUTBOUND))
    publish_tip(chain, monkeypatch, now)

    cases = [
        (A, (B, 300), True),   # B's outbound spending cap cannot limit A's payment
        (C, (B, 20), False),
        (B, (C, 101), False),
        (B, (C, 100), True),
    ]
    # Each call uses the same parent state at admission and apply.
    for sender, leg, allowed in cases:
        monkeypatch.setitem(chain_state._balances, sender, chain.bal[sender])
        chain_state.get_sequence_number.side_effect = lambda key: chain.seq.get(key, 0)
        tx = transfer(sender, chain.seq.get(sender, 0), leg)
        dry_run = estimate(tx)
        verdict = chain.block([tx], height=HEIGHT, ts=now)
        assert (tx["tx_id"] in verdict.accepted_tx_ids) is allowed, verdict.outcomes
        assert (dry_run["status"] == "ok") is allowed, dry_run
        if sender == C:
            assert "recipient" in dry_run["error"]["message"].lower()
    assert db.count_mempool_txs() == 0


def test_batch_refusal_discards_earlier_credit_and_fee(node, monkeypatch):
    now = int(time.time())
    chain = new_chain()
    install(chain, deploy(inbound=INBOUND))
    publish_tip(chain, monkeypatch, now)
    chain_state.get_sequence_number.return_value = 0
    monkeypatch.setitem(chain_state._balances, C, chain.bal[C])
    tx = transfer(C, 0, (A, 5), (B, 7))
    before = chain.snapshot()
    dry_run = estimate(tx)
    queued = sendtx.queue_transaction(json.dumps(tx), propagate=False)
    assert dry_run["error"]["code"] == queued["code"]
    assert dry_run["error"]["details"]["transfer_index"] == 2
    assert db.count_mempool_txs() == 0
    result = chain.block([tx], height=HEIGHT, ts=now)
    assert result.invalid_tx_ids == [tx["tx_id"]], result.outcomes
    assert result.outcomes[0].reason == queued["code"]
    assert chain.snapshot() == before


@pytest.mark.parametrize("policy,release,allowed,limit_key", [
    ({"max_hold_seconds": 0}, {}, True, None),
    ({"max_hold_seconds": 0}, {"seconds": 10}, False, "max_hold_seconds"),
    ({"max_hold_seconds": 0}, {"blocks": 2}, False, "max_hold_seconds"),
    ({"max_hold_seconds": 600}, {"seconds": 600}, True, None),
    ({"max_hold_seconds": 600}, {"seconds": 601}, False, "max_hold_seconds"),
    ({"max_hold_blocks": 2}, {"blocks": 2}, True, None),
    ({"max_hold_blocks": 2}, {"blocks": 3}, False, "max_hold_blocks"),
    ({}, {"seconds": 3600}, True, None),
])
def test_hold_boundaries_match_wallet_and_apply(
        node, monkeypatch, policy, release, allowed, limit_key):
    chain = new_chain()
    now = int(time.time())
    if policy:
        install(chain, deploy(**policy))
    publish_tip(chain, monkeypatch, now)
    chain_state.get_sequence_number.return_value = 0
    tx = park(A, 0, now, **release) if release else transfer(A, 0, (B, 17))
    before = chain.snapshot()
    wallet = estimate(tx)
    included = chain.block([tx], height=HEIGHT, ts=now)
    if allowed:
        assert wallet["status"] == "ok" and wallet["data"]["admissible"], wallet
        assert included.accepted_tx_ids == [tx["tx_id"]], included.outcomes
    else:
        error = wallet["error"]
        assert error["code"] == "RECIPIENT_MAX_HOLD", wallet
        assert error["details"][limit_key] == policy[limit_key]
        assert included.outcomes[0].reason == error["code"]
        assert chain.snapshot() == before


@pytest.mark.parametrize("retract", [True, False])
def test_tightening_hold_cap_preserves_open_park_and_replay(mock_policy_evaluators, retract):
    now = int(time.time())
    payment = park(A, 0, now, blocks=4)
    tighten = deploy(max_hold_blocks=0)
    rid = parse_retractable_transfer(payment).retractable_id.hex()
    action = [transaction(A, 1, "retract_transfer", retractable_id=rid, fee_limit="0")] if retract else []
    blocks = [[payment], [tighten], action, [], []]
    snapshots = []
    for replay in (False, True):
        chain = new_chain()
        hashes = []
        for step, txs in enumerate(blocks):
            result = chain.block(txs, HEIGHT + step, now + step, replay=replay)
            assert not result.invalid_tx_ids, result.outcomes
            hashes.append(result.next_snapshot.state_hash)
        assert chain.book.escrow_total() == 0
        assert chain.bal[B] == 100_000 - 7 + (0 if retract else 17)
        assert chain.bal[A] == 100_000 - 7 - (0 if retract else 17)
        snapshots.append((hashes, chain.snapshot()))
    assert snapshots[0] == snapshots[1]


def test_policy_update_preserves_registered_outbound_clause(mock_policy_evaluators):
    set_mock_outbound()
    chain = new_chain()
    install(chain, routed_tx(SK_BOB, B, OUTBOUND))
    chain.block([deploy(seq=1, inbound=INBOUND)], height=HEIGHT)
    refused = transfer(C, 0, (B, 5))
    assert chain.block([refused], height=HEIGHT + 1).invalid_tx_ids == [refused["tx_id"]]

    cleared = deploy(seq=2)
    result = chain.block([cleared], height=HEIGHT + 2)
    assert result.accepted_tx_ids == [cleared["tx_id"]], result.outcomes
    allowed_in = transfer(C, 0, (B, 5))
    refused_out = transfer(B, 3, (A, 101))
    result = chain.block([allowed_in, refused_out], height=HEIGHT + 3)
    assert result.accepted_tx_ids == [allowed_in["tx_id"]], result.outcomes
    assert result.invalid_tx_ids == [refused_out["tx_id"]]


def test_legacy_guarded_policy_and_inbound_allowlist_both_apply(mock_policy_evaluators):
    chain = new_chain()
    # The existing global evaluator routes using i12 (actual sender). Its o5
    # blocks A's sends above 100. B has an independently installed receive rule.
    step = chain._multi

    def guarded(**kwargs):
        result = step(**kwargs)
        streams = kwargs.get("input_stream_values", {})
        if A in str(streams.get(12, "")) and int(streams.get(1, 0)) > 100:
            result[5] = "0"
        return result

    chain._multi = guarded
    install(chain, deploy(inbound=INBOUND))
    outgoing = transfer(A, 0, (B, 101))
    incoming = transfer(C, 0, (B, 20))
    valid = transfer(A, 0, (B, 100))
    for tx, allowed in ((outgoing, False), (incoming, False), (valid, True)):
        result = chain.block([tx], height=HEIGHT)
        assert (tx["tx_id"] in result.accepted_tx_ids) is allowed, result.outcomes


def test_inbound_allowlist_does_not_gate_offers(node, monkeypatch):
    chain = new_chain()
    install(chain, deploy(inbound=INBOUND))
    now = int(time.time())
    publish_tip(chain, monkeypatch, now)
    chain_state.get_sequence_number.return_value = 0
    monkeypatch.setitem(chain_state._balances, C, chain.bal[C])
    offer = transaction(C, 0, "rule_offer", recipient_pubkey=B, rule_text=OUTBOUND)
    dry = estimate(offer)
    assert dry["status"] == "ok" and dry["data"]["admissible"], dry
    included = chain.block([offer], height=HEIGHT, ts=now)
    assert included.accepted_tx_ids == [offer["tx_id"]], included.outcomes


def test_failed_outbound_build_preserves_both_directions(node, monkeypatch):
    chain = new_chain()
    install(chain, deploy(inbound=INBOUND, max_hold_seconds=0))
    now = int(time.time())
    publish_tip(chain, monkeypatch, now)
    chain_state.get_sequence_number.side_effect = lambda key: chain.seq.get(key, 0)
    for pool in ("apply", "admission"):
        sender_policy.evaluator(pool).fail_build(clause_body_v1(OUTBOUND), "compile failed")
    tx = deploy(seq=1, outbound=OUTBOUND, max_hold_seconds=600)
    before = dict(chain.lm.rule_offers.accepted_clauses)
    wallet = estimate(tx)
    assert wallet["status"] == "error" and "compile failed" in wallet["error"]["message"], wallet
    rejected = chain.block([tx], HEIGHT, now)
    assert rejected.invalid_tx_ids == [tx["tx_id"]], rejected.outcomes
    assert dict(chain.lm.rule_offers.accepted_clauses) == before


def test_inbound_hold_inputs_describe_the_payment_itself(node, monkeypatch):
    chain = new_chain()
    # A wallet may already use custom i17 and i27 for its outgoing rules.
    # In the recipient worker a plain transfer must present zero on both.
    rule = ("always ( (i17[t]:bv[64] = { 0 }:bv[64] && i27[t]:bv[64] = { 0 }:bv[64]) "
            "? (o5[t]:bv[24] = { 1 }:bv[24]) : (o5[t]:bv[24] = { 0 }:bv[24]) ).")
    body = clause_body_v1(rule)
    for pool in ("recipient-admission", "recipient-apply"):
        sender_policy.evaluator(pool).set_verdict(body, lambda v: (
            "1" if v["i17"] == v["i27"] == "0" else "0"
        ))
    install(chain, deploy(inbound=rule))
    now = int(time.time())
    publish_tip(chain, monkeypatch, now)
    chain_state.get_sequence_number.return_value = 0
    tx = transaction(A, 0, operations={"1": [[A, B, "17"]], "17": "42", "27": "20"})
    assert estimate(tx)["data"]["admissible"]
    result = chain.block([tx], HEIGHT, now)
    assert result.accepted_tx_ids == [tx["tx_id"]], result.outcomes


def test_approval_request_is_admitted_but_release_requires_recipient_consent(
        mock_policy_evaluators):
    import test_approval_apply as approvals

    owner = approvals.BOB
    chain = new_chain(slots=True)
    chain.bal[owner] = 100_000
    setup = routed_tx(approvals.SK_BOB, owner,
                      "recipient_v1 o5[t] " + json.dumps({"inbound": INBOUND}))
    install(chain, setup)
    request = approvals._request()
    proposal = approvals.request_tx(request)
    voter = approvals.vote_tx(request)
    result, _, _ = approvals._apply([proposal, voter], lm=chain.lm)
    assert proposal["tx_id"] in result.accepted_tx_ids, result.outcomes
    assert voter["tx_id"] in result.accepted_tx_ids, result.outcomes
    assert not result.invalid_tx_ids
    assert result.next_snapshot.metadata["lifecycle_manager"].approval_requests.terminal_status[
        request.request_id] == approvals.STATUS_FAILED
    assert result.outcomes[-1].reason == "RECIPIENT_POLICY_BLOCKED"
    assert result.next_snapshot.metadata["balances"][owner] == 0


def test_sender_can_retract_through_checktx_and_sendtx_after_cap_changes(node, monkeypatch):
    chain = new_chain()
    now = int(time.time())
    payment = park(A, 0, now, blocks=4)
    assert chain.block([payment], HEIGHT - 2, now).accepted_tx_ids == [payment["tx_id"]]
    tighter = deploy(max_hold_blocks=0)
    assert chain.block([tighter], HEIGHT - 1, now).accepted_tx_ids == [tighter["tx_id"]]
    publish_tip(chain, monkeypatch, now)
    chain_state.get_sequence_number.return_value = 1
    rid = parse_retractable_transfer(payment).retractable_id.hex()
    tx = transaction(A, 1, "retract_transfer", retractable_id=rid, fee_limit="0")
    checks_before = len(sender_policy.evaluator("recipient-admission").verdict_calls)
    dry = estimate(tx)
    assert dry["status"] == "ok" and dry["data"]["admissible"], dry
    assert db.count_mempool_txs() == 0
    queued = sendtx.queue_transaction(json.dumps(tx), propagate=False)
    assert queued["ok"], queued
    entry = db.get_mempool_entry(queued["tx_hash"])
    assert int(entry["estimated_fee"]) == 0 and int(entry["fee_limit"]) == 0
    assert len(sender_policy.evaluator("recipient-admission").verdict_calls) == checks_before
