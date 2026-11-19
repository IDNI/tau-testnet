"""Independent acceptance verification for recipient controls (#47/#76).

Written from the issue specs, NOT from the implementation's own tests: the
clause bodies and decision models here are constructed independently, so a
shared wrong assumption between body and model in the feature tests cannot
hide a bug here. Focus: exact cap boundaries (hold == cap, cap + 1, strict
inequality), batch atomicity with balance assertions, the release/retract
exemptions, outbound neutrality, and admission/apply agreement.

Harness: the real apply_block chain from tests/test_retractable_apply.py and
the admission node fixture from tests/test_recipient_policy.py, mock policy
evaluator, real BLS signatures.
"""
import pytest

import tau_defs
from consensus import recipient_policy, sender_policy
from consensus.policy_mock import MockPolicyEvaluator

from test_retractable_apply import (
    ALICE, BOB, CAROL, MALLORY, PROPOSER, HEIGHT, TS, FAR,
    Chain, park_tx, retract_tx, spend_tx, rid_of, _sign, SK_ALICE,
)
# Admission harness (fixture + identities + payload helpers) from the feature
# tests; the bodies, models and assertions below are independent.
from test_recipient_policy import (
    node, ev, SENDER, RECIPIENT, THIRD, NOW, NEXT_HEIGHT,
    _park, _queue, _transfer,
)
from bls_keys import SK_CAROL, sign_payload

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
FEE = 7

ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def _key_lit(stream, key):
    return "(%s[t]:bv[384] = { #x%s }:bv[384])" % (stream, key)


# --- independently constructed rule bodies + models --------------------------

def v_allowlist_body(*keys):
    cond = " || ".join(_key_lit("i3", k) for k in keys)
    return "( ( %s ) ? %s : %s )" % (cond, ALLOW, BLOCK)


def v_allowlist_model(*keys):
    keys = set(keys)
    # The bare i3 value keeps the '#x' literal prefix (WorkerSession._bare).
    return lambda inp: "1" if str(inp.get("i3", "")).removeprefix("#x") in keys else "0"


def v_cap_body(seconds=None, blocks=None, strict=False):
    op = "<" if strict else "<="
    terms = []
    if seconds is not None:
        terms.append("(i17[t]:bv[64] %s { %d }:bv[64])" % (op, seconds))
    if blocks is not None:
        terms.append("(i27[t]:bv[64] %s { %d }:bv[64])" % (op, blocks))
    return "( ( %s ) ? %s : %s )" % (" && ".join(terms), ALLOW, BLOCK)


def v_cap_model(seconds=None, blocks=None, strict=False):
    def decide(inp):
        s = int(str(inp.get("i17", "0")) or 0)
        b = int(str(inp.get("i27", "0")) or 0)
        if seconds is not None and (s >= seconds if strict else s > seconds):
            return "0"
        if blocks is not None and (b >= blocks if strict else b > blocks):
            return "0"
        return "1"
    return decide


@pytest.fixture
def aev():
    evaluator = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", evaluator)
    yield evaluator
    sender_policy.set_evaluator("apply", None)


def _chain(ev, clauses=None, *, active=True):
    ch = Chain({ALICE: 10_000, BOB: 10_000, CAROL: 10_000, MALLORY: 10_000,
                PROPOSER: 0}, fee=FEE)
    if active:
        ch.lm.activate_recipient_policy()
    for account, (body, model) in (clauses or {}).items():
        ch.lm.rule_offers.accepted_clauses[(account, STREAM)] = body
        ev.set_verdict(body, model)
    return ch


def _outcome(result, tx):
    (o,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return o


# --- #47 case 1: allow-list, exact identities ---------------------------------

def test_v_listed_sender_pays_stranger_refused_nothing_moves(aev):
    body = v_allowlist_body(ALICE, BOB)  # owner BOB listed for outbound neutrality
    ch = _chain(aev, {BOB: (body, v_allowlist_model(ALICE, BOB))})
    ok = spend_tx(ALICE, BOB, 40, 0)
    assert not ch.block([ok]).invalid_tx_ids
    assert ch.bal[BOB] == 10_040 and ch.bal[ALICE] == 10_000 - 40 - FEE

    bad = spend_tx(CAROL, BOB, 40, 0)
    before = ch.snapshot()
    result = ch.block([bad], height=HEIGHT + 1, ts=TS + 1)
    assert bad["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, bad).reason == recipient_policy.REASON
    assert ch.snapshot() == before  # no amount, no fee, no sequence


def test_v_neutral_recipient_takes_everything(aev):
    ch = _chain(aev)
    park = park_tx(amount=90, seq=0, at_time=TS + 7_000_000)
    assert not ch.block([park]).invalid_tx_ids


# --- #47 case 3: batch atomicity at apply -------------------------------------

def test_v_batch_one_refusing_output_fails_whole_tx(aev):
    # BOB accepts ALICE; CAROL accepts only herself and MALLORY.
    b_body = v_allowlist_body(ALICE, BOB)
    c_body = v_allowlist_body(CAROL, MALLORY)
    ch = _chain(aev, {
        BOB: (b_body, v_allowlist_model(ALICE, BOB)),
        CAROL: (c_body, v_allowlist_model(CAROL, MALLORY)),
    })
    batch = _sign({
        "tx_id": "v-batch-1", "tx_type": "user_tx", "sender_pubkey": ALICE,
        "sequence_number": 0, "expiration_time": FAR, "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 10], [ALICE, CAROL, 20]]},
    }, SK_ALICE)
    before = ch.snapshot()
    result = ch.block([batch])
    assert batch["tx_id"] in result.invalid_tx_ids
    assert ch.snapshot() == before  # BOB's leg did NOT apply in part
    assert ch.bal[BOB] == 10_000

    # Both recipients willing -> both legs move.
    c2_body = v_allowlist_body(ALICE, CAROL)
    ch.lm.rule_offers.accepted_clauses[(CAROL, STREAM)] = c2_body
    aev.set_verdict(c2_body, v_allowlist_model(ALICE, CAROL))
    batch2 = _sign({
        "tx_id": "v-batch-2", "tx_type": "user_tx", "sender_pubkey": ALICE,
        "sequence_number": 0, "expiration_time": FAR, "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 10], [ALICE, CAROL, 20]]},
    }, SK_ALICE)
    assert not ch.block([batch2], height=HEIGHT + 1, ts=TS + 1).invalid_tx_ids
    assert ch.bal[BOB] == 10_010 and ch.bal[CAROL] == 10_020


# --- #76 cases 1-2: exact cap boundaries --------------------------------------

def test_v_cap600_boundary_hold_equal_passes_plus_one_refused(aev):
    body = v_cap_body(seconds=600)
    ch = _chain(aev, {BOB: (body, v_cap_model(seconds=600))})
    at_cap = park_tx(amount=50, seq=0, at_time=TS + 600)
    assert not ch.block([at_cap]).invalid_tx_ids  # hold == cap admits

    over = park_tx(amount=50, seq=1, at_time=TS + 601)
    before = ch.snapshot()
    # Same block timestamp TS: hold = (TS + 601) - TS = 601, one past the cap.
    result = ch.block([over], height=HEIGHT + 1, ts=TS)
    assert over["tx_id"] in result.invalid_tx_ids
    o = _outcome(result, over)
    assert o.reason == recipient_policy.REASON_MAX_HOLD
    assert o.receipt["recipient_max_hold_seconds"] == 600
    assert o.receipt["recipient_hold_seconds"] == 601
    assert ch.snapshot() == before


def test_v_strict_cap_reports_value_minus_one(aev):
    body = v_cap_body(seconds=600, strict=True)  # i17 < 600
    ch = _chain(aev, {BOB: (body, v_cap_model(seconds=600, strict=True))})
    inside = park_tx(amount=50, seq=0, at_time=TS + 599)
    assert not ch.block([inside]).invalid_tx_ids

    at = park_tx(amount=50, seq=1, at_time=TS + 600)
    result = ch.block([at], height=HEIGHT + 1, ts=TS)  # hold = 600, not < 600
    assert at["tx_id"] in result.invalid_tx_ids
    o = _outcome(result, at)
    assert o.reason == recipient_policy.REASON_MAX_HOLD
    assert o.receipt["recipient_max_hold_seconds"] == 599  # strict -> N-1


def test_v_cap_zero_plain_passes_every_park_kind_refused(aev):
    body = v_cap_body(seconds=0, blocks=0)
    ch = _chain(aev, {BOB: (body, v_cap_model(seconds=0, blocks=0))})
    plain = spend_tx(ALICE, BOB, 25, 0)
    assert not ch.block([plain]).invalid_tx_ids
    assert ch.bal[BOB] == 10_025

    tp = park_tx(amount=50, seq=1, at_time=TS + 60)
    r1 = ch.block([tp], height=HEIGHT + 1, ts=TS)  # hold = 60 > 0
    assert tp["tx_id"] in r1.invalid_tx_ids
    assert _outcome(r1, tp).reason == recipient_policy.REASON_MAX_HOLD

    hp = park_tx(amount=50, seq=1, at_height=HEIGHT + 7)
    r2 = ch.block([hp], height=HEIGHT + 2, ts=TS)  # hold = 7 - 2 = 5 blocks
    assert hp["tx_id"] in r2.invalid_tx_ids
    o2 = _outcome(r2, hp)
    assert o2.reason == recipient_policy.REASON_MAX_HOLD
    assert o2.receipt["recipient_max_hold_blocks"] == 0
    assert o2.receipt["recipient_hold_blocks"] == 5


def test_v_height_park_capped_in_blocks_boundary(aev):
    body = v_cap_body(blocks=10)
    ch = _chain(aev, {BOB: (body, v_cap_model(blocks=10))})
    at_cap = park_tx(amount=50, seq=0, at_height=HEIGHT + 10)
    assert not ch.block([at_cap]).invalid_tx_ids  # hold == 10 blocks admits

    over = park_tx(amount=50, seq=1, at_height=HEIGHT + 12)
    result = ch.block([over], height=HEIGHT + 1, ts=TS + 1)
    assert over["tx_id"] in result.invalid_tx_ids
    o = _outcome(result, over)
    assert o.reason == recipient_policy.REASON_MAX_HOLD
    assert o.receipt["recipient_max_hold_blocks"] == 10
    assert o.receipt["recipient_hold_blocks"] == 11


# --- #76 case 4 + release regression ------------------------------------------

def test_v_retract_ungated_release_not_rechecked_after_tightening(aev):
    loose = v_cap_body(seconds=600)
    ch = _chain(aev, {BOB: (loose, v_cap_model(seconds=600))})
    back = park_tx(amount=70, seq=0, at_time=TS + 500)
    stays = park_tx(amount=30, seq=1, at_time=TS + 400)
    assert not ch.block([back, stays]).invalid_tx_ids

    tight = v_cap_body(seconds=0, blocks=0)
    ch.lm.rule_offers.accepted_clauses[(BOB, STREAM)] = tight
    aev.set_verdict(tight, v_cap_model(seconds=0, blocks=0))
    calls_before = len(aev.verdict_calls)

    r = ch.block([retract_tx(rid_of(back), seq=2)], height=HEIGHT + 1, ts=TS + 10)
    assert not r.invalid_tx_ids
    assert ch.bal[ALICE] == 10_000 - 100 - 2 * FEE + 70

    ch.block([], height=HEIGHT + 2, ts=TS + 400)  # matured release
    assert ch.bal[BOB] == 10_030
    assert len(aev.verdict_calls) == calls_before, \
        "retract and matured release must never ask the recipient"


# --- outbound neutrality + inactive chain --------------------------------------

def test_v_owner_outbound_under_cap_clause_passes(aev):
    body = v_cap_body(seconds=0, blocks=0)  # instant-only inbound
    ch = _chain(aev, {BOB: (body, v_cap_model(seconds=0, blocks=0))})
    out = spend_tx(BOB, ALICE, 15, 0)
    assert not ch.block([out]).invalid_tx_ids
    assert ch.bal[ALICE] == 10_015


def test_v_inactive_chain_gate_does_not_run(aev):
    body = v_allowlist_body(BOB)  # would refuse ALICE if active
    ch = _chain(aev, {BOB: (body, v_allowlist_model(BOB))}, active=False)
    tx = spend_tx(ALICE, BOB, 40, 0)
    assert not ch.block([tx]).invalid_tx_ids
    assert ch.bal[BOB] == 10_040


def test_v_refused_park_replays_identically(aev):
    body = v_cap_body(seconds=0, blocks=0)
    ch = _chain(aev, {BOB: (body, v_cap_model(seconds=0, blocks=0))})
    park = park_tx(amount=50, seq=0, at_time=TS + 60)
    r1 = ch.block([park])
    assert park["tx_id"] in r1.invalid_tx_ids
    # The canonical block filters the refused tx out; a twin chain replaying
    # that canonical block must reach the identical state hash and snapshot.
    canonical = [tx for tx in [park] if tx["tx_id"] not in r1.invalid_tx_ids]
    assert canonical == []
    twin = _chain(aev, {BOB: (body, v_cap_model(seconds=0, blocks=0))})
    twin.block(canonical, HEIGHT, TS, replay=True)
    assert twin.history[-1][-1] == ch.history[-1][-1]
    assert twin.snapshot() == ch.snapshot()


# --- admission side: same rules, same verdicts ---------------------------------

def test_v_admission_cap_boundary_and_reason(node, ev):
    sendtx, script, lm, clauses = node
    body = v_cap_body(seconds=600)
    clauses[(str(RECIPIENT).lower(), STREAM)] = body
    ev.set_verdict(body, v_cap_model(seconds=600))

    at_cap = _park(release_at_time=NOW + 600)
    ok = _queue(sendtx, at_cap)
    assert ok["ok"], ok

    over = _park(release_at_time=NOW + 601, seq=2)
    res = _queue(sendtx, over)
    assert res["ok"] is False
    assert res["code"] == "RECIPIENT_MAX_HOLD"
    assert res["details"]["max_hold_seconds"] == 600
    assert res["details"]["hold_seconds"] == 601
    assert "600" in res["message"] and "601" in res["message"]


def test_v_admission_allowlist_stranger_and_checktx(node, ev):
    sendtx, script, lm, clauses = node
    body = v_allowlist_body(SENDER, RECIPIENT)
    clauses[(str(RECIPIENT).lower(), STREAM)] = body
    ev.set_verdict(body, v_allowlist_model(SENDER, RECIPIENT))

    ok = _queue(sendtx, _transfer((RECIPIENT, 30)))
    assert ok["ok"], ok

    bad = sign_payload({
        "tx_type": "user_tx", "sender_pubkey": THIRD, "sequence_number": 1,
        "expiration_time": NOW + 3600, "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "100", "operations": {"1": [[THIRD, RECIPIENT, "30"]]},
    }, SK_CAROL)
    res = _queue(sendtx, bad)
    assert res["ok"] is False
    assert res["code"] == "TX_REJECTED"
    assert "recipient policy" in res["message"]
    dry = _queue(sendtx, bad, dry_run=True)
    assert dry["ok"] is False
    assert dry["code"] == "TX_REJECTED"
