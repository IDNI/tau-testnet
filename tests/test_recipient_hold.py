"""Recipient controls at block apply (issues #47/#76), through the real
`apply_block` with the mock policy evaluator.

Acceptance cases of both issues on the apply side, plus the exemptions that
make the feature safe: retracts are never gated, matured releases are never
re-checked, a refused transaction moves nothing and pays no fee, and replay
reaches the identical state. The admission twins live in
tests/test_recipient_policy.py; the rule shapes and models are shared from
there.
"""
from unittest.mock import patch

import pytest

import tau_defs
import tau_manager
from consensus import recipient_policy, sender_policy
from consensus.approvals import STATUS_FAILED
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import MAX_RELEASE_WINDOW_SECONDS

import test_approval_apply as ap
import test_retractable_apply as rt
from test_retractable_apply import (
    ALICE, BOB, CAROL, HEIGHT, MALLORY, PROPOSER, TS, Chain, park_tx,
    retract_tx, rid_of, spend_tx,
)
from test_recipient_policy import (
    HOLDB5_BODY, HOLDB5_MODEL,
    HOLD600_BODY, HOLD600_MODEL, INSTANT_BODY, INSTANT_MODEL,
    OUTBOUND_BODY, STREAM,
    allow_list_body, allow_list_model, hold_cap_body, hold_cap_model,
    one_unit_body, one_unit_model,
)

FEE = 7


@pytest.fixture
def ev():
    evaluator = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", evaluator)
    yield evaluator
    sender_policy.set_evaluator("apply", None)


def _chain(ev, clauses=None, *, active=True, fee=FEE):
    """A chain with funded accounts; `clauses` is account -> (body, model)."""
    ch = Chain({ALICE: 10_000, BOB: 10_000, CAROL: 10_000, MALLORY: 10_000,
                PROPOSER: 0}, fee=fee)
    if active:
        ch.lm.activate_recipient_policy()
    for account, (body, model) in (clauses or {}).items():
        ch.lm.rule_offers.accepted_clauses[(account, STREAM)] = body
        ev.set_verdict(body, model)
    return ch


def _reason(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.reason


def _receipt(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.receipt or {}


def _refused(ch, result, tx, before):
    """The transaction is out of the block and nothing at all moved: no
    amount, no fee, no sequence number."""
    assert tx["tx_id"] in result.invalid_tx_ids
    assert ch.snapshot() == before


def _asked_about(ev, body):
    return [inputs for called, inputs in ev.verdict_calls if called == body]


# --- #47: inbound allow-list at apply -------------------------------------------

def test_the_listed_sender_pays_and_a_stranger_is_refused(ev):
    """#47 case 1: A -> R passes apply; B -> R is refused with the recipient
    reason; A's own send policy is untouched."""
    body = allow_list_body(ALICE, BOB)
    ch = _chain(ev, {BOB: (body, allow_list_model(ALICE, BOB))})

    result = ch.block([spend_tx(ALICE, BOB, 300, seq=0)])
    assert not result.invalid_tx_ids
    assert ch.bal[BOB] == 10_300 and ch.bal[ALICE] == 10_000 - 300 - FEE

    before = ch.snapshot()
    stranger = spend_tx(CAROL, BOB, 300, seq=0)
    result = ch.block([stranger], height=HEIGHT + 1)
    assert _reason(result, stranger) == recipient_policy.REASON
    assert "rejected by recipient policy" in rt._logs(result)
    _refused(ch, result, stranger, before)

    # The stranger's own payments elsewhere are untouched, and so are Alice's.
    result = ch.block([spend_tx(CAROL, ALICE, 5, seq=0),
                       spend_tx(ALICE, CAROL, 5, seq=1)], height=HEIGHT + 2)
    assert not result.invalid_tx_ids


def test_an_account_without_a_policy_is_paid_by_everyone(ev):
    """#47 case 2: the neutral default."""
    ch = _chain(ev)
    result = ch.block([spend_tx(ALICE, BOB, 1, seq=0),
                       spend_tx(CAROL, BOB, 1, seq=0),
                       spend_tx(MALLORY, BOB, 1, seq=0)])
    assert not result.invalid_tx_ids
    assert ch.bal[BOB] == 10_003
    assert ev.verdict_calls == []


def test_an_outbound_only_clause_is_never_asked_inbound(ev):
    """A pre-existing pure i4 whitelist keeps its exact meaning."""
    ch = _chain(ev, {BOB: (OUTBOUND_BODY, lambda inputs: "0")})
    result = ch.block([spend_tx(ALICE, BOB, 5_000, seq=0)])
    assert not result.invalid_tx_ids and ch.bal[BOB] == 15_000
    assert ev.verdict_calls == [], "the opt-in screen must skip a pure i4 clause"


def test_one_refusing_recipient_fails_the_whole_batch(ev):
    """#47 case 3: no partial apply, no fee, no sequence consumed."""
    ch = _chain(ev, {CAROL: (allow_list_body(MALLORY, CAROL),
                             allow_list_model(MALLORY, CAROL))})
    batch = rt._sign({
        "tx_id": "batch-1", "tx_type": "user_tx", "sender_pubkey": ALICE,
        "sequence_number": 0, "expiration_time": rt.FAR, "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 100], [ALICE, CAROL, 100]]},
    }, rt.SK_ALICE)
    before = ch.snapshot()
    result = ch.block([batch])
    assert _reason(result, batch) == recipient_policy.REASON
    _refused(ch, result, batch, before)
    assert ch.bal[BOB] == 10_000, "the leg to Bob must not survive the refusal"
    assert ch.bal[PROPOSER] == 0, "no fee is charged for a refused tx"
    assert ch.seq.get(ALICE, 0) == 0


def test_each_leg_of_a_batch_is_judged_by_its_own_recipient(ev):
    bob_rule = allow_list_body(ALICE, BOB)
    carol_rule = allow_list_body(ALICE, MALLORY, CAROL)
    ch = _chain(ev, {BOB: (bob_rule, allow_list_model(ALICE, BOB)),
                     CAROL: (carol_rule, allow_list_model(ALICE, MALLORY, CAROL))})
    batch = rt._sign({
        "tx_id": "batch-2", "tx_type": "user_tx", "sender_pubkey": ALICE,
        "sequence_number": 0, "expiration_time": rt.FAR, "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 10], [ALICE, CAROL, 20]]},
    }, rt.SK_ALICE)
    result = ch.block([batch])
    assert not result.invalid_tx_ids
    assert (ch.bal[BOB], ch.bal[CAROL]) == (10_010, 10_020)
    assert len(_asked_about(ev, bob_rule)) == 1
    assert len(_asked_about(ev, carol_rule)) == 1


def test_inbound_and_outbound_rules_live_in_one_unit_and_both_enforce(ev):
    """#47 case 4: Bob pays only Carol, and is paid only by Alice — one clause,
    direction discriminated on i3."""
    body = one_unit_body(BOB, CAROL, ALICE)
    model = one_unit_model(BOB, CAROL, ALICE)
    ch = _chain(ev, {BOB: (body, model)})

    result = ch.block([spend_tx(BOB, CAROL, 10, seq=0),
                       spend_tx(ALICE, BOB, 10, seq=0)])
    assert not result.invalid_tx_ids

    outbound = spend_tx(BOB, MALLORY, 10, seq=1)
    result = ch.block([outbound], height=HEIGHT + 1)
    assert _reason(result, outbound) == "user_policy_block"

    before = ch.snapshot()
    inbound = spend_tx(MALLORY, BOB, 10, seq=0)
    result = ch.block([inbound], height=HEIGHT + 2)
    assert _reason(result, inbound) == recipient_policy.REASON
    _refused(ch, result, inbound, before)


def test_a_block_on_the_senders_side_wins_and_the_recipient_is_not_asked(ev):
    body = allow_list_body(ALICE, BOB)
    spend = "( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? " \
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : " \
            "(o5[t]:bv[24] = { #x000001 }:bv[24]) )"
    ch = _chain(ev, {BOB: (body, allow_list_model(ALICE, BOB)),
                     CAROL: (spend, lambda inputs:
                             "0" if int(str(inputs.get("i1", "0"))) > 1000 else "1")})
    tx = spend_tx(CAROL, BOB, 5_000, seq=0)
    result = ch.block([tx])
    assert _reason(result, tx) == "user_policy_block"
    assert _asked_about(ev, body) == []


def test_nothing_is_asked_while_the_feature_is_inactive(ev):
    body = allow_list_body(ALICE, BOB)
    ch = _chain(ev, {BOB: (body, allow_list_model(ALICE, BOB))}, active=False)
    result = ch.block([spend_tx(CAROL, BOB, 300, seq=0)])
    assert not result.invalid_tx_ids and ch.bal[BOB] == 10_300
    assert _asked_about(ev, body) == []


def test_owner_outbound_under_a_cap_clause_passes(ev):
    """The sender pass feeds i17=0/i27=0 while active: the owner's own cap
    clause never blocks its outbound transfers (cap 600, instant-only, and an
    allow-list that includes the owner)."""
    for body, model in ((HOLD600_BODY, HOLD600_MODEL),
                        (INSTANT_BODY, INSTANT_MODEL),
                        (allow_list_body(ALICE, BOB), allow_list_model(ALICE, BOB))):
        ch = _chain(ev, {BOB: (body, model)})
        result = ch.block([spend_tx(BOB, CAROL, 25, seq=0)])
        assert not result.invalid_tx_ids, body
        assert ch.bal[CAROL] == 10_025
        (inputs,) = _asked_about(ev, body)
        assert inputs["i17"] == "0" and inputs["i27"] == "0", \
            "the sender pass must feed explicit zeros on the hold streams"


def test_a_recipient_clause_the_engine_cannot_step_refuses(ev):
    """Fail closed, as on the sender's side, so every node agrees."""
    body = allow_list_body(ALICE, BOB)
    ch = _chain(ev, {BOB: (body, allow_list_model(ALICE, BOB))})
    ev.fail_step(body, "engine says no")
    tx = spend_tx(ALICE, BOB, 1, seq=0)
    before = ch.snapshot()
    result = ch.block([tx])
    assert _reason(result, tx) == recipient_policy.REASON
    _refused(ch, result, tx, before)


# --- #76: hold caps at apply ------------------------------------------------------

def test_instant_only_takes_a_transfer_and_refuses_every_park(ev):
    """#76 case 1: cap 0 admits plain transfers, refuses every park with the
    recipient_max_hold reason carrying the cap."""
    ch = _chain(ev, {BOB: (INSTANT_BODY, INSTANT_MODEL)})
    result = ch.block([spend_tx(ALICE, BOB, 50, seq=0)])
    assert not result.invalid_tx_ids and ch.bal[BOB] == 10_050

    for n, release in enumerate((dict(at_time=TS + 1), dict(at_time=TS + 86_400),
                                 dict(at_height=HEIGHT + 30))):
        before = ch.snapshot()
        park = park_tx(amount=50, seq=1, **release)
        result = ch.block([park], height=HEIGHT + 1 + n)
        assert _reason(result, park) == recipient_policy.REASON_MAX_HOLD
        receipt = _receipt(result, park)
        assert receipt["recipient_max_hold_seconds"] == 0
        assert receipt["recipient_max_hold_blocks"] == 0
        assert "RECIPIENT_MAX_HOLD" in rt._logs(result)
        _refused(ch, result, park, before)
        assert ch.book.escrow_total() == 0


def test_a_cap_admits_a_park_inside_it_and_refuses_one_beyond(ev):
    """#76 case 2: 600 s takes ten minutes and refuses an hour."""
    ch = _chain(ev, {BOB: (HOLD600_BODY, HOLD600_MODEL)})

    ten_minutes = park_tx(amount=50, seq=0, at_time=TS + 600)
    result = ch.block([ten_minutes])
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 50
    assert _asked_about(ev, HOLD600_BODY)[-1]["i17"] == "600"
    assert _asked_about(ev, HOLD600_BODY)[-1]["i27"] == "0"

    for release in (TS + 601, TS + 3_600):
        before = ch.snapshot()
        park = park_tx(amount=50, seq=1, at_time=release)
        result = ch.block([park])
        assert _reason(result, park) == recipient_policy.REASON_MAX_HOLD
        receipt = _receipt(result, park)
        assert receipt["recipient_max_hold_seconds"] == 600
        assert receipt["recipient_hold_seconds"] == release - TS
        _refused(ch, result, park, before)


def test_a_height_park_is_capped_in_blocks(ev):
    ch = _chain(ev, {BOB: (HOLDB5_BODY, HOLDB5_MODEL)})
    inside = park_tx(amount=50, seq=0, at_height=HEIGHT + 5)
    result = ch.block([inside])
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 50
    assert _asked_about(ev, HOLDB5_BODY)[-1]["i27"] == "5"
    assert _asked_about(ev, HOLDB5_BODY)[-1]["i17"] == "0"

    before = ch.snapshot()
    over = park_tx(amount=50, seq=1, at_height=HEIGHT + 6)
    result = ch.block([over])
    assert _reason(result, over) == recipient_policy.REASON_MAX_HOLD
    receipt = _receipt(result, over)
    assert receipt["recipient_max_hold_blocks"] == 5
    assert receipt["recipient_hold_blocks"] == 6
    _refused(ch, result, over, before)

    # A seconds-only cap does not bound a height park: it feeds i17 = 0.
    ch2 = _chain(ev, {BOB: (HOLD600_BODY, HOLD600_MODEL)})
    result = ch2.block([park_tx(amount=50, seq=0, at_height=HEIGHT + 50)])
    assert not result.invalid_tx_ids


def test_the_hold_is_counted_from_the_blocks_own_clock(ev):
    """Apply measures against the block being applied: the same park can be
    refused at one timestamp and admitted at a later one."""
    ch = _chain(ev, {BOB: (HOLD600_BODY, HOLD600_MODEL)})
    park = park_tx(amount=50, seq=0, at_time=TS + 700)
    before = ch.snapshot()
    result = ch.block([park], ts=TS)
    assert _reason(result, park) == recipient_policy.REASON_MAX_HOLD
    _refused(ch, result, park, before)
    result = ch.block([park], height=HEIGHT + 1, ts=TS + 100)
    assert not result.invalid_tx_ids and ch.book.escrow_total() == 50


def test_without_a_cap_parks_of_any_length_pass(ev):
    """#76 case 3: the neutral default, also beside an allow-list with no cap."""
    ch = _chain(ev, {CAROL: (allow_list_body(ALICE, CAROL),
                             allow_list_model(ALICE, CAROL))})
    result = ch.block([
        park_tx(amount=10, seq=0, at_time=TS + MAX_RELEASE_WINDOW_SECONDS),
        park_tx(amount=10, seq=1, at_height=HEIGHT + 50),
        park_tx(amount=10, seq=2, recipient=CAROL,
                at_time=TS + MAX_RELEASE_WINDOW_SECONDS),
        park_tx(amount=10, seq=3, recipient=CAROL, at_height=HEIGHT + 50),
    ])
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 40


def test_a_retract_is_never_gated_and_a_release_is_not_asked_again(ev):
    """#76 case 4 + the release regression: Bob tightens his cap to
    instant-only while two parks are open. Alice still takes one back, and
    the other still releases — the matured credit is never re-checked."""
    loose = hold_cap_body(seconds=600)
    tight = INSTANT_BODY
    ch = _chain(ev, {BOB: (loose, hold_cap_model(seconds=600))})
    back = park_tx(amount=70, seq=0, at_time=TS + 500)
    stays = park_tx(amount=30, seq=1, at_time=TS + 400)
    assert not ch.block([back, stays]).invalid_tx_ids

    ch.lm.rule_offers.accepted_clauses[(BOB, STREAM)] = tight
    ev.set_verdict(tight, INSTANT_MODEL)
    asked = len(ev.verdict_calls)

    result = ch.block([retract_tx(rid_of(back), seq=2)],
                      height=HEIGHT + 1, ts=TS + 10)
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 30
    assert ch.bal[ALICE] == 10_000 - 100 - 2 * FEE + 70

    # The matured release credits Bob directly, without asking his new clause.
    ch.block([], height=HEIGHT + 2, ts=TS + 400)
    assert ch.book.escrow_total() == 0 and ch.bal[BOB] == 10_030
    assert len(ev.verdict_calls) == asked, \
        "neither a retract nor a release asks the recipient"


def test_a_refused_park_costs_the_sender_nothing(ev):
    ch = _chain(ev, {BOB: (INSTANT_BODY, INSTANT_MODEL)}, fee=9)
    park = park_tx(amount=50, seq=0, at_time=TS + 60)
    before = ch.snapshot()
    result = ch.block([park])
    assert _reason(result, park) == recipient_policy.REASON_MAX_HOLD
    _refused(ch, result, park, before)
    assert ch.bal[ALICE] == 10_000 and ch.bal[PROPOSER] == 0
    assert ch.seq.get(ALICE, 0) == 0


def test_an_allowlist_refusal_of_a_park_is_not_a_hold_refusal(ev):
    body = allow_list_body(CAROL, BOB)  # Alice is not listed
    ch = _chain(ev, {BOB: (body, allow_list_model(CAROL, BOB))})
    park = park_tx(amount=50, seq=0, at_time=TS + 600)
    result = ch.block([park])
    assert _reason(result, park) == recipient_policy.REASON
    assert "recipient_max_hold_seconds" not in _receipt(result, park)


# --- guarded mode at apply ---------------------------------------------------------

class GuardedChain(Chain):
    """The scripted evaluator also answers the guarded recipient pass: o5
    blocks when i12 names an owner in `guarded_block_keys`."""

    guarded_block_keys = set()

    def _multi(self, **kwargs):
        self.calls.append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        amount = str(vals.get(1, "0"))
        owner = str(vals.get(12, ""))
        blocked = self.block_o5 or any(
            key in owner for key in self.guarded_block_keys)
        return {1: amount, 8: "0", 9: str(self.fee),
                5: "0" if blocked else "1"}


def test_a_guarded_recipient_unit_blocks_inbound_at_apply(ev):
    ch = GuardedChain({ALICE: 10_000, BOB: 10_000, PROPOSER: 0}, fee=FEE)
    ch.lm.activate_recipient_policy()
    ch.guarded_block_keys = {BOB}
    spec = ("always ( (i12[t]:bv[384] = { #x" + BOB + " }:bv[384]) "
            "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) ).")
    tx = spend_tx(ALICE, BOB, 25, seq=0)
    before = ch.snapshot()
    with patch.object(tau_manager, "last_known_tau_spec", spec):
        result = ch.block([tx])
    assert _reason(result, tx) == recipient_policy.REASON
    assert "guarded" in rt._logs(result)
    _refused(ch, result, tx, before)
    # Two steps: sender pass (i12 = Alice) then recipient pass (i12 = Bob).
    owners = [str(c["input_stream_values"].get(12, "")) for c in ch.calls]
    assert any(ALICE in o for o in owners) and any(BOB in o for o in owners)


def test_the_guarded_prescreen_skips_the_extra_step_at_apply(ev):
    ch = GuardedChain({ALICE: 10_000, BOB: 10_000, PROPOSER: 0}, fee=FEE)
    ch.lm.activate_recipient_policy()
    ch.guarded_block_keys = {BOB}
    # Bob's key is absent from the spec: no recipient unit, no extra step.
    with patch.object(tau_manager, "last_known_tau_spec",
                      "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."):
        result = ch.block([spend_tx(ALICE, BOB, 25, seq=0)])
    assert not result.invalid_tx_ids
    assert len(ch.calls) == 1, "only the sender pass stepped"


# --- approval-vote release: the recipient is asked at execution ---------------------

def test_an_approved_transfer_is_judged_by_the_recipient_when_it_executes(ev):
    """Creating the request is not gated; the transfer it parks is a payment
    like any other. Refused at execution: the request fails, the vote stands,
    nothing moves. The recipient pass sees hold None (final-now)."""
    body = allow_list_body(ap.SCAN, ap.BOB)
    lm = ap._lm()
    lm.activate_recipient_policy()
    lm.rule_offers.accepted_clauses[(ap.BOB, STREAM)] = body
    ev.set_verdict(body, allow_list_model(ap.SCAN, ap.BOB))

    request = ap._request(amount=5000, approvers={18: ap.AUTH})
    result, lm, _ = ap._apply([ap.request_tx(request)], lm=lm)
    assert lm.approval_requests.get_request(request.request_id) is not None
    assert _asked_about(ev, body) == [], "parking the request does not ask the recipient"

    vote = ap.vote_tx(request)
    result, lm, _ = ap._apply([vote], lm=lm, height=ap.HEIGHT + 1)
    assert vote["tx_id"] in result.accepted_tx_ids
    assert lm.approval_requests.terminal_status[request.request_id] == STATUS_FAILED
    assert ap._balances(result)[ap.BOB] == 0
    assert "rejected by recipient policy" in ap._logs(result)
    (inputs,) = _asked_about(ev, body)
    assert inputs["i17"] == "0" and inputs["i27"] == "0", \
        "the release is final-now, not the original park's hold"


def test_an_approved_transfer_to_a_willing_recipient_executes(ev):
    body = allow_list_body(ap.ALICE, ap.BOB)
    lm = ap._lm()
    lm.activate_recipient_policy()
    lm.rule_offers.accepted_clauses[(ap.BOB, STREAM)] = body
    ev.set_verdict(body, allow_list_model(ap.ALICE, ap.BOB))

    request = ap._request(amount=5000, approvers={18: ap.AUTH})
    _result, lm, _ = ap._apply([ap.request_tx(request)], lm=lm)
    result, lm, _ = ap._apply([ap.vote_tx(request)], lm=lm, height=ap.HEIGHT + 1)
    assert ap._balances(result)[ap.BOB] == 5000


# --- replay determinism --------------------------------------------------------------

def test_a_replay_reaches_the_same_state(ev):
    body = one_unit_body(BOB, CAROL, ALICE)
    model = one_unit_model(BOB, CAROL, ALICE)
    ch = _chain(ev, {BOB: (body, model)})
    ch.block([spend_tx(ALICE, BOB, 100, seq=0),
              park_tx(amount=40, seq=1, at_time=TS + 300)])
    ch.block([spend_tx(BOB, CAROL, 5, seq=0)], height=HEIGHT + 1, ts=TS + 300)

    twin = _chain(ev, {BOB: (body, model)})
    for txs, height, ts, proposer, fee, block_o5, state_hash in ch.history:
        twin.block(txs, height, ts, replay=True, proposer=proposer)
        assert twin.history[-1][-1] == state_hash
    assert twin.snapshot() == ch.snapshot()


def test_a_refused_park_replays_to_the_same_state(ev):
    """A refused park leaves no trace: the canonical block the proposer
    produces (the refused tx filtered out, exactly as for a sender-o5 block)
    replays to the identical state hash and snapshot."""
    ch = _chain(ev, {BOB: (INSTANT_BODY, INSTANT_MODEL)})
    park = park_tx(amount=50, seq=0, at_time=TS + 60)
    result = ch.block([park])
    assert park["tx_id"] in result.invalid_tx_ids
    canonical = [tx for tx in [park] if tx["tx_id"] not in result.invalid_tx_ids]
    assert canonical == []
    twin = _chain(ev, {BOB: (INSTANT_BODY, INSTANT_MODEL)})
    twin.block(canonical, HEIGHT, TS, replay=True)
    assert twin.history[-1][-1] == ch.history[-1][-1]
    assert twin.snapshot() == ch.snapshot()