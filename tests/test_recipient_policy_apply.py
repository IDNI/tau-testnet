"""Recipient-side policy at block apply: the allow-list of #47 and the hold cap
of #76, through the real `apply_block`.

The clause verdicts come from the Python models in `recipient_rules`, which the
native tests hold to the real engine.
"""
import re

import pytest

import tau_defs
from commands import getrecipientpolicy
from consensus import recipient_policy, sender_policy
from consensus.approvals import STATUS_FAILED
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import MAX_RELEASE_WINDOW_SECONDS

import recipient_rules as rules
import test_approval_apply as ap
import test_retractable_apply as rt
from test_retractable_apply import (
    ALICE, BOB, CAROL, HEIGHT, MALLORY, PROPOSER, TS, Chain, park_tx, retract_tx,
    rid_of, spend_tx,
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
        ch.lm.rule_offers.accepted_clauses[(account, 5)] = body
        ev.set_verdict(body, model)
    return ch


def _reason(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.reason


def _refused(ch, result, tx, before):
    """The transaction is out of the block and nothing at all moved: no amount,
    no fee, no sequence number."""
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == recipient_policy.RECIPIENT_POLICY_BLOCK_REASON
    assert "rejected by recipient policy" in rt._logs(result)
    assert ch.snapshot() == before


def _asked_about(ev, body):
    return [inputs for called, inputs in ev.verdict_calls if called == body]


RECORD = ["i%d" % index for index in tau_defs.RECEIVE_RECORD_INDICES]
NEVER = str(tau_defs.RECEIVE_NEVER)


def _record(inputs):
    """The receive record one evaluation was asked with: kind, hold, recall,
    limit, period, refund."""
    return tuple(inputs.get(name) for name in RECORD)


def _park_record(kind, length):
    """A park: held, and open to a recall, until its release. No limit, and
    nothing that goes back by itself."""
    return (str(kind), str(length), str(length), "0", "0", NEVER)


# --- #47: inbound allow-list --------------------------------------------------

def test_the_listed_sender_pays_and_a_stranger_is_refused(ev):
    """Acceptance case 1 of #47."""
    body = rules.allow_list(ALICE)
    ch = _chain(ev, {BOB: (body, rules.allow_list_model(ALICE))})

    result = ch.block([spend_tx(ALICE, BOB, 300, seq=0)])
    assert not result.invalid_tx_ids
    assert ch.bal[BOB] == 10_300 and ch.bal[ALICE] == 10_000 - 300 - FEE

    before = ch.snapshot()
    stranger = spend_tx(CAROL, BOB, 300, seq=0)
    _refused(ch, ch.block([stranger], height=HEIGHT + 1), stranger, before)

    # The stranger's own payments elsewhere are untouched, and so are Alice's.
    result = ch.block([spend_tx(CAROL, ALICE, 5, seq=0), spend_tx(ALICE, CAROL, 5, seq=1)],
                      height=HEIGHT + 2)
    assert not result.invalid_tx_ids


def test_the_owner_of_an_allow_list_still_pays_anyone(ev):
    """The list is about payments TO the account. What it sends reads i17 = 0."""
    body = rules.allow_list(ALICE)
    ch = _chain(ev, {BOB: (body, rules.allow_list_model(ALICE))})
    result = ch.block([spend_tx(BOB, CAROL, 40, seq=0), spend_tx(BOB, MALLORY, 2, seq=1)])
    assert not result.invalid_tx_ids
    assert ch.bal[CAROL] == 10_040 and ch.bal[MALLORY] == 10_002
    sent = [name for i in _asked_about(ev, body) for name in RECORD if name in i]
    assert sent == [], "the sender pass must not feed the receive record"


def test_an_account_without_a_policy_is_paid_by_everyone(ev):
    """Acceptance case 2 of #47."""
    ch = _chain(ev)
    result = ch.block([spend_tx(ALICE, BOB, 1, seq=0), spend_tx(CAROL, BOB, 1, seq=0),
                       spend_tx(MALLORY, BOB, 1, seq=0)])
    assert not result.invalid_tx_ids
    assert ch.bal[BOB] == 10_003
    assert ev.verdict_calls == []


def test_a_clause_that_does_not_read_the_receive_stream_is_never_asked(ev):
    """Every clause written before the feature keeps its meaning: a spend limit
    on what Bob sends says nothing about what Bob receives."""
    ch = _chain(ev, {BOB: (rules.SPEND_LIMIT, rules.spend_limit_model)})
    result = ch.block([spend_tx(ALICE, BOB, 5_000, seq=0)])
    assert not result.invalid_tx_ids and ch.bal[BOB] == 15_000
    assert ev.verdict_calls == []

    # ... and it still limits what Bob sends.
    too_much = spend_tx(BOB, ALICE, 5_000, seq=0)
    result = ch.block([too_much], height=HEIGHT + 1)
    assert _reason(result, too_much) == "user_policy_block"


def test_one_refusing_recipient_fails_the_whole_batch(ev):
    """Acceptance case 3 of #47: no partial apply."""
    ch = _chain(ev, {CAROL: (rules.allow_list(MALLORY), rules.allow_list_model(MALLORY))})
    batch = rt._sign({
        "tx_id": "batch-1", "tx_type": "user_tx", "sender_pubkey": ALICE,
        "sequence_number": 0, "expiration_time": rt.FAR, "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 100], [ALICE, CAROL, 100]]},
    }, rt.SK_ALICE)
    before = ch.snapshot()
    _refused(ch, ch.block([batch]), batch, before)
    assert ch.bal[BOB] == 10_000, "the leg to Bob must not survive the refusal"


def test_each_leg_of_a_batch_is_judged_by_its_own_recipient(ev):
    bob_rule, carol_rule = rules.allow_list(ALICE), rules.allow_list(ALICE, MALLORY)
    ch = _chain(ev, {BOB: (bob_rule, rules.allow_list_model(ALICE)),
                     CAROL: (carol_rule, rules.allow_list_model(ALICE, MALLORY))})
    batch = rt._sign({
        "tx_id": "batch-2", "tx_type": "user_tx", "sender_pubkey": ALICE,
        "sequence_number": 0, "expiration_time": rt.FAR, "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 10], [ALICE, CAROL, 20]]},
    }, rt.SK_ALICE)
    result = ch.block([batch])
    assert not result.invalid_tx_ids
    assert (ch.bal[BOB], ch.bal[CAROL]) == (10_010, 10_020)
    assert len(_asked_about(ev, bob_rule)) == 1 and len(_asked_about(ev, carol_rule)) == 1


def test_inbound_and_outbound_rules_live_in_one_unit_and_both_enforce(ev):
    """Acceptance case 4 of #47: Bob pays only Carol, and is paid only by Alice."""
    body = rules.one_unit(CAROL, ALICE, MAX_RELEASE_WINDOW_SECONDS)
    ch = _chain(ev, {BOB: (body, rules.one_unit_model(CAROL, ALICE, MAX_RELEASE_WINDOW_SECONDS))})

    result = ch.block([spend_tx(BOB, CAROL, 10, seq=0), spend_tx(ALICE, BOB, 10, seq=0)])
    assert not result.invalid_tx_ids

    outbound = spend_tx(BOB, MALLORY, 10, seq=1)
    result = ch.block([outbound], height=HEIGHT + 1)
    assert _reason(result, outbound) == "user_policy_block"

    before = ch.snapshot()
    inbound = spend_tx(MALLORY, BOB, 10, seq=0)
    _refused(ch, ch.block([inbound], height=HEIGHT + 2), inbound, before)


def test_the_recipient_reads_the_transfer_the_sender_made(ev):
    """Same inputs as the sender's side, approval slots emptied, the record set."""
    body = rules.allow_list(ALICE)
    ch = _chain(ev, {BOB: (body, rules.allow_list_model(ALICE))})
    ch.block([spend_tx(ALICE, BOB, 300, seq=0)])
    main = [c["input_stream_values"] for c in ch.calls
            if str(c["input_stream_values"].get(1)) == "300"][-1]
    (inputs,) = _asked_about(ev, body)
    assert inputs == sender_policy.clause_inputs(
        recipient_policy.receive_inputs(main, recipient_policy.FINAL))
    assert _record(inputs) == ("1", "0", "0", "0", "0", NEVER)
    assert inputs["i3"] == "#x" + ALICE and inputs["i4"] == "#x" + BOB
    assert all(inputs[f"i{slot}"] == "0" for slot in tau_defs.approval_slot_indices())


def _spend_with(sender_sk, sender, to, amount, seq, custom):
    return rt._sign({
        "tx_id": "spend-ref-%s-%s" % (seq, sorted(custom.items())),
        "tx_type": "user_tx", "sender_pubkey": sender, "sequence_number": seq,
        "expiration_time": rt.FAR, "expire_at_height": 1000, "fee_limit": "100",
        "operations": {"1": [[sender, to, amount]], **custom},
    }, sender_sk)


def test_the_recipient_can_ask_for_a_custom_input_of_the_payer(ev):
    """The payer's custom inputs reach the recipient's clause on their own
    streams: "pay me only with a reference"."""
    body = rules.needs_reference(30)
    ch = _chain(ev, {BOB: (body, rules.needs_reference_model(30))})
    before = ch.snapshot()
    bare = spend_tx(ALICE, BOB, 300, seq=0)
    _refused(ch, ch.block([bare]), bare, before)

    with_ref = _spend_with(rt.SK_ALICE, ALICE, BOB, 300, 0, {"30": "4711"})
    result = ch.block([with_ref])
    assert result.invalid_tx_ids == []
    assert ch.bal[BOB] == 10_000 + 300
    assert _asked_about(ev, body)[-1]["i30"] == "4711"


def test_a_block_on_the_senders_side_wins_and_the_recipient_is_not_asked(ev):
    body = rules.allow_list(ALICE)
    ch = _chain(ev, {BOB: (body, rules.allow_list_model(ALICE)),
                     CAROL: (rules.SPEND_LIMIT, rules.spend_limit_model)})
    tx = spend_tx(CAROL, BOB, 5_000, seq=0)
    result = ch.block([tx])
    assert _reason(result, tx) == "user_policy_block"
    assert _asked_about(ev, body) == []


def test_a_recipient_clause_the_engine_cannot_step_refuses(ev):
    """Fail closed, as on the sender's side, so every node agrees."""
    body = rules.allow_list(ALICE)
    ch = _chain(ev, {BOB: (body, rules.allow_list_model(ALICE))})
    ev.fail_step(body, "engine says no")
    tx = spend_tx(ALICE, BOB, 1, seq=0)
    before = ch.snapshot()
    _refused(ch, ch.block([tx]), tx, before)


def test_nothing_is_asked_while_the_feature_is_inactive(ev):
    """Before activation the record's inputs are ordinary streams and apply is
    unchanged."""
    body = rules.allow_list(ALICE)
    ch = _chain(ev, {BOB: (body, rules.allow_list_model(ALICE))}, active=False)
    result = ch.block([spend_tx(CAROL, BOB, 300, seq=0)])
    assert not result.invalid_tx_ids and ch.bal[BOB] == 10_300
    assert _asked_about(ev, body) == []


# --- #76: maximum hold time ---------------------------------------------------

def test_instant_only_takes_a_transfer_and_refuses_every_park(ev):
    """Acceptance case 1 of #76."""
    ch = _chain(ev, {BOB: (rules.final_only(), rules.final_only_model())})
    result = ch.block([spend_tx(ALICE, BOB, 50, seq=0)])
    assert not result.invalid_tx_ids and ch.bal[BOB] == 10_050

    for n, release in enumerate((dict(at_time=TS + 1), dict(at_time=TS + 86_400),
                                 dict(at_height=HEIGHT + 30))):
        before = ch.snapshot()
        park = park_tx(amount=50, seq=1, **release)
        _refused(ch, ch.block([park], height=HEIGHT + 1 + n), park, before)
        assert ch.book.escrow_total() == 0


def test_a_cap_admits_a_park_inside_it_and_refuses_one_beyond(ev):
    """Acceptance case 2 of #76: 600 s takes ten minutes and refuses an hour."""
    body = rules.max_hold(600)
    ch = _chain(ev, {BOB: (body, rules.max_hold_model(600))})

    ten_minutes = park_tx(amount=50, seq=0, at_time=TS + 600)
    result = ch.block([ten_minutes])
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 50
    assert _record(_asked_about(ev, body)[-1]) == _park_record(2, 600)

    for release in (TS + 601, TS + 3_600):
        before = ch.snapshot()
        park = park_tx(amount=50, seq=1, at_time=release)
        _refused(ch, ch.block([park]), park, before)


def test_a_park_released_at_a_height_has_no_length_in_seconds(ev):
    """Its length is in blocks, on a clock of its own, so a cap written in
    seconds alone refuses it, however long that cap is."""
    body = rules.max_hold(MAX_RELEASE_WINDOW_SECONDS)
    ch = _chain(ev, {BOB: (body, rules.max_hold_model(MAX_RELEASE_WINDOW_SECONDS))})
    park = park_tx(amount=50, seq=0, at_height=HEIGHT + 1)
    before = ch.snapshot()
    _refused(ch, ch.block([park]), park, before)
    assert _record(_asked_about(ev, body)[-1]) == _park_record(3, 1)


def test_a_cap_in_blocks_admits_a_height_release_inside_it_and_refuses_one_beyond(ev):
    """The hold is counted from the height of the block that parks it."""
    body = rules.max_hold_either(600, 100)
    ch = _chain(ev, {BOB: (body, rules.max_hold_either_model(600, 100))})
    inside = park_tx(amount=50, seq=0, at_height=HEIGHT + 100)
    result = ch.block([inside], height=HEIGHT)
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 50
    assert _record(_asked_about(ev, body)[-1]) == _park_record(3, 100)

    # The same release point, one block later, is one block shorter.
    again = park_tx(amount=50, seq=1, at_height=HEIGHT + 100)
    assert not ch.block([again], height=HEIGHT + 1).invalid_tx_ids
    assert _record(_asked_about(ev, body)[-1]) == _park_record(3, 99)

    before = ch.snapshot()
    beyond = park_tx(amount=50, seq=2, at_height=HEIGHT + 2 + 101)
    _refused(ch, ch.block([beyond], height=HEIGHT + 2), beyond, before)
    assert _record(_asked_about(ev, body)[-1]) == _park_record(3, 101)


def test_the_hold_is_counted_from_the_blocks_own_timestamp(ev):
    ch = _chain(ev, {BOB: (rules.max_hold(600), rules.max_hold_model(600))})
    park = park_tx(amount=50, seq=0, at_time=TS + 700)
    before = ch.snapshot()
    _refused(ch, ch.block([park], ts=TS), park, before)
    result = ch.block([park], height=HEIGHT + 1, ts=TS + 100)
    assert not result.invalid_tx_ids and ch.book.escrow_total() == 50


def test_the_recall_window_is_judged_apart_from_the_hold(ev):
    """Held at most 30 days, taken back within an hour at most: a park is open
    to a recall until its release, so two hours are refused though the hold is
    far inside its bound."""
    body = rules.hold_and_recall(2_592_000, 3_600)
    ch = _chain(ev, {BOB: (body, rules.hold_and_recall_model(2_592_000, 3_600))})
    hour = park_tx(amount=50, seq=0, at_time=TS + 3_600)
    assert not ch.block([hour]).invalid_tx_ids
    assert ch.book.escrow_total() == 50

    before = ch.snapshot()
    two_hours = park_tx(amount=50, seq=1, at_time=TS + 7_200)
    _refused(ch, ch.block([two_hours]), two_hours, before)
    assert _record(_asked_about(ev, body)[-1]) == _park_record(2, 7_200)


def test_every_condition_must_pass_in_one_evaluation(ev):
    """A rule that ties the hold to the recall window: the block asks it once,
    with the whole record, and applies its one verdict."""
    body = rules.hold_plus_recall(3_600)
    ch = _chain(ev, {BOB: (body, rules.hold_plus_recall_model(3_600))})
    inside = park_tx(amount=50, seq=0, at_time=TS + 1_800)
    assert not ch.block([inside]).invalid_tx_ids
    assert len(_asked_about(ev, body)) == 1

    before = ch.snapshot()
    beyond = park_tx(amount=50, seq=1, at_time=TS + 2_400)
    _refused(ch, ch.block([beyond]), beyond, before)
    assert len(_asked_about(ev, body)) == 2, "one evaluation a payment, at apply"


def test_without_a_cap_parks_of_any_length_pass(ev):
    """Acceptance case 3 of #76, also next to an allow-list with no cap in it."""
    ch = _chain(ev, {CAROL: (rules.allow_list(ALICE), rules.allow_list_model(ALICE))})
    result = ch.block([
        park_tx(amount=10, seq=0, at_time=TS + MAX_RELEASE_WINDOW_SECONDS),
        park_tx(amount=10, seq=1, at_height=HEIGHT + 50),
        park_tx(amount=10, seq=2, recipient=CAROL, at_time=TS + MAX_RELEASE_WINDOW_SECONDS),
        park_tx(amount=10, seq=3, recipient=CAROL, at_height=HEIGHT + 50),
    ])
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 40


def test_a_retract_is_never_gated_and_a_release_is_not_asked_again(ev):
    """Acceptance case 4 of #76. Bob tightens his cap to instant-only after two
    parks are open: Alice still takes one back, and the other still releases."""
    loose, tight = rules.max_hold(600), rules.final_only()
    ch = _chain(ev, {BOB: (loose, rules.max_hold_model(600))})
    back = park_tx(amount=70, seq=0, at_time=TS + 500)
    stays = park_tx(amount=30, seq=1, at_time=TS + 400)
    assert not ch.block([back, stays]).invalid_tx_ids

    ch.lm.rule_offers.accepted_clauses[(BOB, 5)] = tight
    ev.set_verdict(tight, rules.final_only_model())
    asked = len(ev.verdict_calls)

    result = ch.block([retract_tx(rid_of(back), seq=2)], height=HEIGHT + 1, ts=TS + 10)
    assert not result.invalid_tx_ids
    assert ch.book.escrow_total() == 30

    ch.block([], height=HEIGHT + 2, ts=TS + 400)
    assert ch.book.escrow_total() == 0 and ch.bal[BOB] == 10_030
    assert len(ev.verdict_calls) == asked, "neither a retract nor a release asks the recipient"


def test_a_refused_park_costs_the_sender_nothing(ev):
    ch = _chain(ev, {BOB: (rules.final_only(), rules.final_only_model())}, fee=9)
    park = park_tx(amount=50, seq=0, at_time=TS + 60)
    before = ch.snapshot()
    result = ch.block([park])
    _refused(ch, result, park, before)
    assert ch.bal[ALICE] == 10_000 and ch.bal[PROPOSER] == 0
    assert ch.seq.get(ALICE, 0) == 0
    # The log carries the payment's terms as getrecipientpolicy takes them, so
    # the condition can be asked for; the verdict itself stays one evaluation.
    asked_as = re.search(r"asked as: ([^|]+)", rt._logs(result)).group(1).strip()
    record = getrecipientpolicy.parse_terms(asked_as.split())
    assert record.kind == 2 and record.hold == record.recall > 0
    assert len(ev.verdict_calls) == 1


# --- parked transfers that wait for co-signatures -------------------------------

def test_an_approved_transfer_is_judged_by_the_recipient_when_it_executes(ev):
    """Creating an approval request is not gated (#47). The transfer it parks is
    a payment to the recipient like any other: refused when it executes, the
    request fails, the vote stands and nothing moves."""
    body = rules.allow_list(ap.SCAN)
    lm = ap._lm()
    lm.activate_recipient_policy()
    lm.rule_offers.accepted_clauses[(ap.BOB, 5)] = body
    ev.set_verdict(body, rules.allow_list_model(ap.SCAN))

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
    assert "asked as: final at once" in ap._logs(result)
    (inputs,) = _asked_about(ev, body)
    assert _record(inputs) == ("1", "0", "0", "0", "0", NEVER) and inputs["i18"] == "0"


def test_an_approved_transfer_to_a_willing_recipient_executes(ev):
    body = rules.allow_list(ap.ALICE)
    lm = ap._lm()
    lm.activate_recipient_policy()
    lm.rule_offers.accepted_clauses[(ap.BOB, 5)] = body
    ev.set_verdict(body, rules.allow_list_model(ap.ALICE))

    request = ap._request(amount=5000, approvers={18: ap.AUTH})
    _result, lm, _ = ap._apply([ap.request_tx(request)], lm=lm)
    result, lm, _ = ap._apply([ap.vote_tx(request)], lm=lm, height=ap.HEIGHT + 1)
    assert ap._balances(result)[ap.BOB] == 5000


# --- replay -------------------------------------------------------------------

def test_a_replay_reaches_the_same_state(ev):
    body = rules.one_unit(CAROL, ALICE, 600)
    model = rules.one_unit_model(CAROL, ALICE, 600)
    ch = _chain(ev, {BOB: (body, model)})
    ch.block([spend_tx(ALICE, BOB, 100, seq=0), park_tx(amount=40, seq=1, at_time=TS + 300)])
    ch.block([spend_tx(BOB, CAROL, 5, seq=0)], height=HEIGHT + 1, ts=TS + 300)

    twin = _chain(ev, {BOB: (body, model)})
    for txs, height, ts, proposer, fee, block_o5, state_hash in ch.history:
        twin.block(txs, height, ts, replay=True, proposer=proposer)
        assert twin.history[-1][-1] == state_hash
    assert twin.snapshot() == ch.snapshot()
