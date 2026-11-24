"""Payout rules and the account's o5 clause (#63).

Every payment a payout rule makes is asked of the account's CURRENT o5 clause,
like a transfer the account sends: in an execution someone sends, at a due
point, in a retry and in a run on arrival. One blocked payment refuses the
whole run, and a refused run moves nothing. A rule signed with `policy_exempt`
is not asked: that is the one exception, and it is part of the signed terms
and of the rule id.

No engine here: block apply runs through the real `apply_block` with scripted
evaluators (the o5 clause in the `apply` pool, the payout rule in
`payout_apply`), admission through the real validator. The same behaviour runs
on the real engine in tests/test_payout_policy_native.py.
"""
import pytest

import chain_state
import tau_admission
import tau_defs
from consensus import sender_policy
from consensus.admission import (
    validate_payout_execute_payload,
    validate_payout_rule_set_payload,
)
from consensus.governance import ConsensusLifecycleManager
from consensus.payout import (
    PayoutBook,
    PayoutPolicyBlocked,
    PayoutRefused,
    PayoutShapeError,
    PayoutShort,
    check_policy,
    describe,
    parse_payout_rule_set,
    parse_payout_spec,
    payout_spec_text,
    policy_inputs,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_signing import signing_message_bytes
from tau_speculation import SpeculationError, WorkerLost

from tests.bls_keys import pubkey_hex
from tests.chain_harness import (
    ALICE, BOB, CAROL, CLAUSE, FAR, HEIGHT, PROPOSER, TS, Chain, _logs, spend_tx,
)
from tests.test_payout_apply import (
    BODY, DAVE, TWO, TWO_BODY, _data_rule, _events, _executed, _installed, _reason,
    exec_tx, rid, set_tx,
)
from tests.test_payout_options import NOW, fields, seconds, terms
from tests.test_payout_triggers import RECURRING, RECURRING_BODY, ROUTE, ROUTE_BODY, STEP

A, B, C = pubkey_hex(0x1A), pubkey_hex(0x2B), pubkey_hex(0x3C)
SLOTS = [f"i{k}" for k in tau_defs.approval_slot_indices()]

ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
# A freeze: no transfer leaves the account.
FREEZE = BLOCK
# At most 50 a payment.
CAP_50 = f"((i1[t]:bv[24] <= {{ 50 }}:bv[24]) ? {ALLOW} : {BLOCK})"
# Bob and nobody else.
ONLY_BOB = f"((i4[t]:bv[384] = {{ #x{BOB} }}:bv[384]) ? {ALLOW} : {BLOCK})"
# 100 seconds between two sends.
COOLDOWN = f"((i16[t]:bv[64] >= {{ 100 }}:bv[64]) ? {ALLOW} : {BLOCK})"
BLOCKED = "the account's o5 clause blocks the payment of slot"


def _script(o5: MockPolicyEvaluator) -> None:
    o5.set_verdict(CLAUSE, 1)
    o5.set_verdict(FREEZE, 0)
    o5.set_verdict(CAP_50, lambda i: int(int(i["i1"]) <= 50))
    o5.set_verdict(ONLY_BOB, lambda i: int(i["i4"] == "#x" + BOB))
    o5.set_verdict(COOLDOWN, lambda i: int(int(i["i16"]) >= 100))


@pytest.fixture
def evs():
    out = {}
    for pool in ("apply", "payout_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    pay = out["payout_apply"]
    pay.set_outputs(BODY, _data_rule)
    pay.set_outputs(TWO_BODY, _data_rule)
    pay.set_outputs(RECURRING_BODY, lambda i: {"o30": "100" if i.get("i13") == "0" else "0"})
    pay.set_outputs(ROUTE_BODY, lambda i: {"o30": str(int(i.get("i27", "0")) // 5)})
    _script(out["apply"])
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


def _bal(**over):
    return dict({ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0}, **over)


def _clause(ch, body, who=ALICE):
    """Register `body` as the account's o5 clause, or remove it."""
    if body is None:
        ch.lm.rule_offers.accepted_clauses.pop((who, 5), None)
    else:
        ch.lm.rule_offers.accepted_clauses[(who, 5)] = body


def _recurring(balances=None, **kw):
    kw.setdefault("due_at", HEIGHT + 5)
    kw.setdefault("due_every", STEP)
    kw.setdefault("expires_at", HEIGHT + 5 + 10 * STEP)
    ch = Chain(balances or _bal())
    tx = set_tx(rule=RECURRING, cap_exec=100, cap_period=100,
                **{k: v for k, v in kw.items() if v is not None})
    ch.block([tx])
    assert ch.lm.payout_rules.get(ALICE) is not None, _reason(ch.last, tx)
    return ch, tx


def _routed(**kw):
    ch = Chain(_bal())
    tx = set_tx(rule=ROUTE, per_sale=True, on_arrival=True, cap_exec=1_000,
                cap_period=10_000, **kw)
    ch.block([tx])
    assert ch.lm.payout_rules.get(ALICE) is not None, _reason(ch.last, tx)
    return ch, tx


# --- the term ----------------------------------------------------------------------------

@pytest.mark.parametrize("value", [False, 1, 0, "true", "yes", None])
def test_the_term_is_true_or_left_out(value):
    tx = fields()
    tx["policy_exempt"] = value
    with pytest.raises(PayoutShapeError):
        parse_payout_rule_set(tx)
    assert terms(policy_exempt=True).policy_exempt is True
    assert terms().policy_exempt is False


def test_the_term_is_signed_and_carried_by_a_guarded_install():
    with_it, without = fields(policy_exempt=True), fields()
    assert signing_message_bytes(with_it) != signing_message_bytes(without)
    text = payout_spec_text(with_it)
    assert '"policy_exempt":true' in text and "policy_exempt" not in payout_spec_text(without)
    assert parse_payout_spec(text, A, 9).policy_exempt is True
    assert parse_payout_spec(payout_spec_text(without), A, 9).policy_exempt is False


def test_the_term_is_part_of_the_id_and_a_rule_without_it_keeps_its_id():
    """The ids without the term were computed by the code before the term
    existed, from exactly these rules."""
    shapes = [{}, {"due_at": NOW + 5}, {"due_at": NOW + 5, "due_retry": 4, "rule_index": 2},
              {"sealed": True}, seconds()]
    before = [terms(**shape).rule_id.hex() for shape in shapes]
    assert before == [
        "2218f5e475a2058a961d5026ec07b25a830c2c06b85f53dff1457fafdcd4b55b",
        "a9189f00e80c167851427b6a4b253334109fe348fe3d5f6e5874a4f0c3b89785",
        "1e192921297de5291eb2564d0c0ea193b8bd93a04995a390152159d155bb8adf",
        "bddcd752d02b7249533d4672b93d85354ad8a7d921334bcd40518a482f78521d",
        "8df64adfc601a41a0362ddf9589624bf718896febb419008305fbb289ee747aa"]
    exempt = [terms(policy_exempt=True, **shape).rule_id.hex() for shape in shapes]
    assert exempt == [
        "e1a50a27fa9cf7915c27599003223e55e762ef8b7d2d4d175fe7f8dfe26decc5",
        "6b26d255594178a56f7d544311a1e90a6c69ec2882533ebffdad55ed884934a4",
        "a968b3052eb45c03b1b49fbe038b6880d03830388accc42a43e3884464e30d67",
        "3876a9a8b3266cca32e7200cc36b12ab5c93b3d4078997536273e3ceef9fba2d",
        "72d8c97386ad5a5833a90881a2713c823b2c756e8ed5cbdcd86c719886882aec"]
    assert len(set(before + exempt)) == 10


def test_the_rows_carry_the_term_and_restore_it():
    book, plain = PayoutBook(), PayoutBook()
    book.install(terms(policy_exempt=True), NOW)
    book.install(terms(sender_pubkey=B, slots=[C], policy_exempt=True, due_at=NOW + 5,
                       due_retry=4, rule_index=2), NOW)
    book.install(terms(sender_pubkey=C), NOW)
    rows = {row[1]: row for row in book.store_rows()}
    assert rows[A][17] == (None, None, 0, False, None, None, False, False, 0,
                           None, None, 0, 0, True)
    assert rows[f"{B}/2"][17] == (None, NOW + 5, 0, False, None, None, False, False, 0,
                                  2, 4, 0, 0, True)
    assert len(rows[C]) == 16                                    # as a rule was stored before
    again = PayoutBook.restore(book.store_rows(), *book.resolved_state())
    assert again.root() == book.root() and again.store_rows() == book.store_rows()
    assert again.get(A).policy_exempt and again.get(f"{B}/2").policy_exempt
    assert not again.get(C).policy_exempt
    plain.install(terms(), NOW)
    plain.install(terms(sender_pubkey=B, slots=[C], due_at=NOW + 5, due_retry=4,
                        rule_index=2), NOW)
    plain.install(terms(sender_pubkey=C), NOW)
    assert plain.root() != book.root()                           # the term moves the root
    assert describe(book.get(A), book.state_of(A))["policy_exempt"] is True
    assert "policy_exempt" not in describe(book.get(C), book.state_of(C))


@pytest.mark.parametrize("change, why", [
    (lambda m: m[:13] + (False,), "malformed"),
    (lambda m: m[:13] + (2,), "malformed"),
    (lambda m: m[:13] + (None,), "malformed"),
    (lambda m: m + (True,), "malformed"),
    (lambda m: m[:13], "does not match its terms"),              # the term dropped
])
def test_a_row_that_does_not_fit_the_term_refuses_to_load(change, why):
    book = PayoutBook()
    book.install(terms(policy_exempt=True), NOW)
    row, = book.store_rows()
    with pytest.raises(ValueError, match=why):
        PayoutBook.restore([row[:17] + (change(row[17]),)], *book.resolved_state())


def test_a_row_cannot_gain_the_term():
    book = PayoutBook()
    book.install(terms(due_at=NOW + 5, due_retry=4), NOW)
    row, = book.store_rows()
    with pytest.raises(ValueError, match="does not match its terms"):
        PayoutBook.restore([row[:17] + (row[17] + (True,),)], *book.resolved_state())


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_database_round_trips_the_term(temp_database):
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.faucet_amount = chain_state._genesis_faucet_amount
    if chain_state._genesis_approval_slots_active:
        lm.activate_approval_slots()
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 500})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    lm.payout_rules.install(terms(policy_exempt=True), NOW)
    lm.payout_rules.install(terms(rule_index=3, due_at=NOW + 5, due_retry=4), NOW)
    lm.payout_rules.install(terms(sender_pubkey=B, slots=[C]), NOW)
    chain_state._lifecycle_manager = lm
    meta, book = lm.consensus_meta_hash(), lm.payout_rules
    chain_state.commit_state_to_db("head-hash", 60)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager.payout_rules
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded.get(A).policy_exempt and not reloaded.get(f"{A}/3").policy_exempt
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


# --- the question ------------------------------------------------------------------------

def test_the_inputs_of_a_payment_are_those_of_a_transfer_in_that_order():
    feed = dict(parent_balance=700, since_last=None, slots_active=False, timestamp=TS)
    plain = policy_inputs(A, B, 30, **feed)
    assert list(plain.items()) == [
        (1, "30"), (2, "700"), (3, "{ #x" + A + " }:bv[384]"),
        (4, "{ #x" + B + " }:bv[384]"), (12, "{ #x" + A + " }:bv[384]"), (5, str(TS))]
    full = policy_inputs(A, B, 30, **dict(feed, since_last=41, slots_active=True))
    assert list(full) == [1, 2, 16, 3, 4, 12, *tau_defs.approval_slot_indices(), 5]
    assert full[16] == "41"
    assert all(full[k] == "0" for k in tau_defs.approval_slot_indices())


def test_no_clause_and_an_exempt_rule_ask_nothing():
    asked = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", asked)
    try:
        feed = dict(pool="apply", timeout=None, parent_balance=0, since_last=None,
                    slots_active=False, timestamp=TS)
        legs = [(0, B, 30)]
        check_policy(terms(), legs, None, **feed)
        check_policy(terms(), legs, "", **feed)
        check_policy(terms(policy_exempt=True), legs, FREEZE, **feed)
        assert asked.verdict_calls == []
        asked.set_verdict(FREEZE, 0)
        with pytest.raises(PayoutPolicyBlocked, match=BLOCKED + " 0") as caught:
            check_policy(terms(), legs, FREEZE, **feed)
        assert isinstance(caught.value, PayoutRefused)
        assert not isinstance(caught.value, PayoutShort)           # so it is owed no retry
    finally:
        sender_policy.set_evaluator("apply", None)


def test_a_clause_that_does_not_build_or_step_blocks_as_it_does_for_a_transfer():
    asked = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", asked)
    try:
        feed = dict(pool="apply", timeout=None, parent_balance=0, since_last=None,
                    slots_active=False, timestamp=TS)
        asked.fail_build(CAP_50, "type error")
        with pytest.raises(PayoutPolicyBlocked):
            check_policy(terms(), [(0, B, 30)], CAP_50, **feed)
        asked.fail_step(ONLY_BOB, "no step")
        with pytest.raises(PayoutPolicyBlocked):
            check_policy(terms(), [(0, B, 30)], ONLY_BOB, **feed)
    finally:
        sender_policy.set_evaluator("apply", None)


@pytest.mark.parametrize("cooldown", [False, True])
def test_an_execution_is_asked_exactly_what_a_transfer_in_the_same_block_is(
        evs, monkeypatch, cooldown):
    monkeypatch.setattr(tau_defs, "COOLDOWN_STREAM_ACTIVE", cooldown)
    ch, oracle, tx = _installed()
    ch.lts[ALICE] = TS - 40                    # the account last sent 41 s before the block
    _clause(ch, CLAUSE)
    ch.block([spend_tx(ALICE, BOB, 30, 1), exec_tx(rule_id=rid(tx), data={"0": 30})],
             height=HEIGHT + 1, ts=TS + 1)
    assert ch.bal[BOB] == 60
    (body, transfer), (again, payment) = evs["apply"].verdict_calls
    assert body == again == CLAUSE
    assert list(payment.items()) == list(transfer.items())       # same keys, values, order
    assert list(payment) == (["i1", "i2"] + (["i16"] if cooldown else [])
                             + ["i3", "i4", "i12"] + SLOTS + ["i5"])
    assert (payment["i1"], payment["i2"], payment["i5"]) == ("30", "1000", str(TS + 1))
    assert (payment["i3"], payment["i4"], payment["i12"]) == (
        "#x" + ALICE, "#x" + BOB, "#x" + ALICE)
    assert all(payment[k] == "0" for k in SLOTS)
    if cooldown:
        assert payment["i16"] == "41"


@pytest.mark.parametrize("cooldown", [False, True])
def test_a_run_of_the_node_is_asked_exactly_what_a_transfer_in_the_same_block_is(
        evs, monkeypatch, cooldown):
    monkeypatch.setattr(tau_defs, "COOLDOWN_STREAM_ACTIVE", cooldown)
    ch, tx = _recurring()
    ch.lts[ALICE] = TS - 40
    _clause(ch, CLAUSE)
    ch.block([spend_tx(ALICE, BOB, 100, 1)], height=HEIGHT + 5, ts=TS + 1)
    assert ch.bal[BOB] == 200 and [e["outcome"] for e in _events(ch)] == ["executed"]
    (_, transfer), (_, payment) = evs["apply"].verdict_calls
    assert list(payment.items()) == list(transfer.items())
    assert payment["i2"] == "1000"             # the parent's balance, not what the block reached
    if cooldown:
        assert payment["i16"] == "41"          # the parent's clock, not the transfer's stamp


def test_without_approval_slots_none_is_fed(evs):
    ch = Chain(_bal(), slots=False)
    tx = set_tx()
    ch.block([tx])
    _clause(ch, CLAUSE)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 1, ts=TS + 1)
    (_, payment), = evs["apply"].verdict_calls
    assert list(payment) == ["i1", "i2", "i3", "i4", "i12", "i5"]


# --- an execution someone sends --------------------------------------------------------------

def test_a_freeze_installed_after_the_rule_stops_it_and_lifting_it_lets_it_pay(evs):
    ch, oracle, tx = _installed(fee=7)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, fee=7, legs=[(BOB, 30)], ts=TS + 1)
    oracle.check(ch)
    _clause(ch, FREEZE)
    frozen = exec_tx(seq=1, rule_id=rid(tx), data={"0": 30})
    result = ch.block([frozen], height=HEIGHT + 2, ts=TS + 2)
    assert _reason(result, frozen) == "payout_not_executed"
    assert BLOCKED + " 0" in _logs(result)
    oracle.check(ch)                           # nothing moved, no fee, no sequence number
    state = ch.lm.payout_rules.state_of(ALICE)
    assert (state.executions, state.paid_total, state.spent_in_period) == (1, 30, 30)
    assert _events(ch) == []
    _clause(ch, None)
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, fee=7, legs=[(BOB, 30)], ts=TS + 3)
    oracle.check(ch)


def test_the_clause_judges_the_real_amount_and_the_real_recipient(evs):
    ch, oracle, tx = _installed(slots=[""])
    _clause(ch, CAP_50)
    over = exec_tx(rule_id=rid(tx), data={"0": 51}, recipients={"0": DAVE})
    assert _reason(ch.block([over], height=HEIGHT + 1, ts=TS + 1), over) == "payout_not_executed"
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 50}, recipients={"0": DAVE})],
             height=HEIGHT + 2, ts=TS + 2)
    _executed(oracle, legs=[(DAVE, 50)], ts=TS + 2)
    _clause(ch, ONLY_BOB)                      # a stricter clause, installed later
    other = exec_tx(seq=1, rule_id=rid(tx), data={"0": 10}, recipients={"0": DAVE})
    assert _reason(ch.block([other], height=HEIGHT + 3, ts=TS + 3), other) == "payout_not_executed"
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 10}, recipients={"0": BOB})],
             height=HEIGHT + 4, ts=TS + 4)
    _executed(oracle, legs=[(BOB, 10)], ts=TS + 4)
    oracle.check(ch)
    assert [(i["i1"], i["i4"]) for _, i in evs["apply"].verdict_calls] == [
        ("51", "#x" + DAVE), ("50", "#x" + DAVE), ("10", "#x" + DAVE), ("10", "#x" + BOB)]


def test_one_blocked_payment_refuses_the_whole_run(evs):
    ch, oracle, tx = _installed(rule=TWO, slots=[BOB, ""])
    _clause(ch, ONLY_BOB)
    both = exec_tx(rule_id=rid(tx), data={"0": 30, "1": 20}, recipients={"1": DAVE})
    result = ch.block([both], height=HEIGHT + 1, ts=TS + 1)
    assert _reason(result, both) == "payout_not_executed"
    assert BLOCKED + " 1" in _logs(result)
    oracle.check(ch)                           # slot 0 would have passed: it is not paid either
    assert [(i["i4"], i["i1"]) for _, i in evs["apply"].verdict_calls] == [
        ("#x" + BOB, "30"), ("#x" + DAVE, "20")]
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 2, ts=TS + 2)
    _executed(oracle, legs=[(BOB, 30)], ts=TS + 2)
    oracle.check(ch)                           # without the blocked payment the run pays


def test_each_payment_of_a_run_is_asked_once(evs):
    ch, oracle, tx = _installed(rule=TWO, slots=[BOB, DAVE])
    _clause(ch, CLAUSE)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 30, "1": 20})], height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(BOB, 30), (DAVE, 20)], ts=TS + 1)
    oracle.check(ch)
    assert [(i["i4"], i["i1"]) for _, i in evs["apply"].verdict_calls] == [
        ("#x" + BOB, "30"), ("#x" + DAVE, "20")]
    assert len(evs["payout_apply"].output_calls) == 1            # the rule itself: one step


def test_a_run_the_rule_or_a_cap_refuses_never_reaches_the_clause(evs):
    ch, oracle, tx = _installed()
    _clause(ch, FREEZE)
    for data in ({"0": 0}, {"0": 101}):        # pays nothing; over the cap per execution
        refused = exec_tx(rule_id=rid(tx), data=data)
        assert _reason(ch.block([refused], height=HEIGHT + 1, ts=TS + 1), refused) == \
            "payout_not_executed"
        assert BLOCKED not in _logs(ch.last)
    assert evs["apply"].verdict_calls == []
    oracle.check(ch)


def test_a_cooldown_clause_counts_a_paid_run_as_one_send(evs, monkeypatch):
    monkeypatch.setattr(tau_defs, "COOLDOWN_STREAM_ACTIVE", True)
    ch, oracle, tx = _installed(rule=TWO, slots=[BOB, DAVE])
    _clause(ch, COOLDOWN)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 30, "1": 20})], height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(BOB, 30), (DAVE, 20)], ts=TS + 1)   # both payments of the one run
    oracle.check(ch)
    assert [i["i16"] for _, i in evs["apply"].verdict_calls] == [
        str(tau_defs.COOLDOWN_NEVER_SENT)] * 2
    soon = exec_tx(seq=1, rule_id=rid(tx), data={"0": 5})
    assert _reason(ch.block([soon], height=HEIGHT + 2, ts=TS + 100), soon) == \
        "payout_not_executed"                  # 99 s after the run
    assert evs["apply"].verdict_calls[-1][1]["i16"] == "99"
    oracle.check(ch)                           # a refused run does not stamp the clock
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 3, ts=TS + 101)
    _executed(oracle, legs=[(BOB, 5)], ts=TS + 101)
    oracle.check(ch)


# --- runs the node makes ---------------------------------------------------------------------

def test_a_blocked_due_point_pays_nothing_and_is_not_tried_again(evs):
    ch, tx = _recurring(due_retry=20)
    _clause(ch, FREEZE)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    event, = _events(ch)
    assert event["outcome"] == "due_not_paid" and event["reason"] == BLOCKED + " 0"
    assert "retry_at" not in event             # a retry is owed only to a short account
    assert not ch.lm.payout_rules.has_retry(FAR, FAR)
    assert (ch.bal[ALICE], ch.bal[BOB]) == (1_000, 0) and ch.lts == {}
    state = ch.lm.payout_rules.state_of(ALICE)
    assert (state.executions, state.paid_total, state.due_index) == (0, 0, 1)
    _clause(ch, None)
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    assert _events(ch) == []                   # lifted later: nothing is made up
    ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 7)
    assert [e["outcome"] for e in _events(ch)] == ["executed"]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (900, 100) and ch.lts == {ALICE: TS + 7}


def test_a_due_point_is_judged_by_the_clause_of_its_own_block(evs):
    ch, tx = _recurring()
    _clause(ch, CAP_50)                        # the rule pays 100
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert [e["outcome"] for e in _events(ch)] == ["due_not_paid"]
    _clause(ch, ONLY_BOB)                      # replaced: Bob may be paid any amount
    ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 6)
    assert [e["outcome"] for e in _events(ch)] == ["executed"] and ch.bal[BOB] == 100


def test_a_retry_the_clause_blocks_is_done(evs):
    ch, tx = _recurring(balances=_bal(**{ALICE: 60}), due_every=None, due_retry=20,
                        expires_at=HEIGHT + 200)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert _events(ch)[0]["retry_at"] == HEIGHT + 6               # short: owed a retry
    _clause(ch, FREEZE)
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    assert _events(ch)[0]["retry_at"] == HEIGHT + 7               # still short: still owed
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 7, ts=TS + 7)
    event, = _events(ch)
    assert (event["outcome"], event["retry"]) == ("due_not_paid", True)
    assert event["reason"] == BLOCKED + " 0" and "retry_at" not in event
    assert ch.lm.payout_rules.state_of(ALICE).retry_at == 0
    _clause(ch, None)
    ch.block([], height=HEIGHT + 8, ts=TS + 8)
    assert _events(ch) == [] and (ch.bal[ALICE], ch.bal[BOB]) == (260, 0)


def test_a_blocked_run_on_arrival_closes_the_sale_unpaid(evs):
    ch, tx = _routed()
    _clause(ch, FREEZE)
    buy = spend_tx(CAROL, ALICE, 101, 0)       # Carol's own transfer is not Alice's to judge
    ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
    event, = _events(ch)
    assert event["outcome"] == "arrival_not_paid" and event["reason"] == BLOCKED + " 0"
    assert (ch.bal[ALICE], ch.bal[BOB], ch.bal[CAROL]) == (1_101, 0, 399)
    assert ch.lm.payout_rules.state_of(ALICE).open_sales == ()
    _clause(ch, None)
    ch.block([spend_tx(CAROL, ALICE, 50, 1)], height=HEIGHT + 2, ts=TS + 2)
    assert [(e["outcome"], e["total"]) for e in _events(ch)] == [("executed", 10)]
    assert ch.bal[BOB] == 10                   # the next payment is routed; the closed one is not


@pytest.mark.parametrize("install, run", [
    (lambda: _recurring(policy_exempt=True),
     lambda ch: ch.block([], height=HEIGHT + 5, ts=TS + 5)),
    (lambda: _routed(policy_exempt=True),
     lambda ch: ch.block([spend_tx(CAROL, ALICE, 500, 0)], height=HEIGHT + 1, ts=TS + 1)),
])
def test_an_exempt_rule_is_not_asked_in_a_run_of_the_node(evs, install, run):
    ch, tx = install()
    _clause(ch, FREEZE)
    run(ch)
    assert [e["outcome"] for e in _events(ch)] == ["executed"] and ch.bal[BOB] == 100
    assert evs["apply"].verdict_calls == []
    assert ch.lm.payout_rules.get(ALICE).policy_exempt


def test_a_frozen_account_still_cannot_send_what_its_exempt_rule_may_pay(evs):
    """An escrow: the clause blocks the key, the rule signed with the term pays."""
    ch, oracle, tx = _installed(policy_exempt=True)
    _clause(ch, FREEZE)
    own = spend_tx(ALICE, BOB, 30, 1)
    result = ch.block([own, exec_tx(rule_id=rid(tx), data={"0": 30})],
                      height=HEIGHT + 1, ts=TS + 1)
    assert _reason(result, own) == "user_policy_block"
    assert (ch.bal[ALICE], ch.bal[BOB]) == (970, 30)
    assert [i["i1"] for _, i in evs["apply"].verdict_calls] == ["30"]   # the transfer only


# --- an evaluator that is gone ---------------------------------------------------------------

def _no_engine(_inputs):
    raise SpeculationError("no engine on this node")


def _gone(_inputs):
    raise WorkerLost("the policy worker is gone")


def test_replay_without_an_evaluator_for_the_clause_moves_nothing(evs):
    ch, tx = _recurring()
    _clause(ch, CAP_50)
    evs["apply"].set_verdict(CAP_50, _no_engine)
    ch.block([], height=HEIGHT + 5, ts=TS + 5, replay=True)
    event, = _events(ch)
    assert event["outcome"] == "due_not_paid" and "no evaluator during replay" in event["reason"]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (1_000, 0)
    assert ch.lm.payout_rules.state_of(ALICE).due_index == 1


def test_replay_without_an_evaluator_does_not_run_an_execution(evs):
    ch, oracle, tx = _installed()
    _clause(ch, CAP_50)
    evs["apply"].set_verdict(CAP_50, _no_engine)
    lost = exec_tx(rule_id=rid(tx), data={"0": 30})
    result = ch.block([lost], height=HEIGHT + 1, ts=TS + 1, replay=True)
    assert "no evaluator during replay" in _logs(result)
    assert (ch.bal[ALICE], ch.bal[BOB]) == (1_000, 0)
    assert ch.lm.payout_rules.state_of(ALICE).executions == 0


@pytest.mark.parametrize("lost, error", [(_no_engine, SpeculationError), (_gone, WorkerLost)])
def test_outside_replay_a_lost_evaluator_is_not_a_verdict(evs, lost, error):
    ch, tx = _recurring()
    _clause(ch, CAP_50)
    evs["apply"].set_verdict(CAP_50, lost)
    with pytest.raises(error):
        ch.block([], height=HEIGHT + 5, ts=TS + 5)


# --- the same blocks, the same state -----------------------------------------------------------

def test_the_same_blocks_give_the_same_state_and_the_clause_moves_it(evs):
    def run(clause, exempt=False):
        ch, tx = _recurring(**({"policy_exempt": True} if exempt else {}))
        _clause(ch, clause)
        ch.block([], height=HEIGHT + 5, ts=TS + 5)
        ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 6)
        return ch.hashes, ch.bal[BOB]

    frozen, again = run(FREEZE), run(FREEZE)
    free, exempt = run(None), run(FREEZE, exempt=True)
    assert frozen == again and frozen[1] == 0
    assert free[1] == exempt[1] == 200
    assert frozen[0][1:] != free[0][1:]        # the blocked runs are in the state
    assert exempt[0][0] != free[0][0]          # and so is the term


# --- admission --------------------------------------------------------------------------------

from tests.test_payout_integration import (  # noqa: E402,F401  (fixtures)
    A as ADM_A, B as ADM_B, NEXT_HEIGHT as ADM_HEIGHT, TIP_TS, _installed as _adm_installed,
    book, evaluator, execute, rule_set, tip_view,
)


@pytest.fixture
def o5():
    mock = MockPolicyEvaluator(pool="admission")
    _script(mock)
    sender_policy.set_evaluator("admission", mock)
    yield mock
    sender_policy.set_evaluator("admission", None)


def test_admission_refuses_an_execution_the_clause_blocks(tip_view, book, o5):
    rule = _adm_installed(book)
    tip_view.clause_for.return_value = CAP_50
    fits = validate_payout_execute_payload(execute(rule.rule_id.hex(), data={"0": 40}), tip_view)
    assert fits.is_valid, fits.error
    over = validate_payout_execute_payload(execute(rule.rule_id.hex(), data={"0": 51}), tip_view)
    assert not over.is_valid and over.code == "PAYOUT_REFUSED"
    assert BLOCKED + " 0" in over.error
    tip_view.clause_for.assert_called_with(ADM_A, tau_defs.USER_POLICY_STREAM_INDEX)
    (body, inputs), _ = o5.verdict_calls
    assert body == CAP_50
    # what a transfer is asked at admission: the tip's balance, no i16
    assert list(inputs.items()) == [
        ("i1", "40"), ("i2", "1000"), ("i3", "#x" + ADM_A), ("i4", "#x" + ADM_B),
        ("i12", "#x" + ADM_A), ("i5", str(TIP_TS))]


def test_admission_feeds_the_approval_slots_once_they_are_active(tip_view, book, o5):
    rule = _adm_installed(book)
    tip_view.clause_for.return_value = CLAUSE
    tip_view.approval_slots_active = True
    result = validate_payout_execute_payload(execute(rule.rule_id.hex()), tip_view)
    assert result.is_valid, result.error
    (_, inputs), = o5.verdict_calls
    assert list(inputs) == ["i1", "i2", "i3", "i4", "i12"] + SLOTS + ["i5"]


def test_admission_does_not_ask_for_an_exempt_rule_and_reports_the_term(tip_view, book, o5):
    rule = _adm_installed(book, policy_exempt=True)
    tip_view.clause_for.return_value = FREEZE
    result = validate_payout_execute_payload(execute(rule.rule_id.hex()), tip_view)
    assert result.is_valid, result.error
    assert o5.verdict_calls == []
    book.revoke(ADM_A)
    tip_view.clause_for.return_value = None
    exempt = validate_payout_rule_set_payload(rule_set(policy_exempt=True), tip_view)
    assert exempt.is_valid, exempt.error
    assert exempt.data["policy_exempt"] is True
    assert "policy_exempt" not in validate_payout_rule_set_payload(rule_set(), tip_view).data


def test_admission_does_not_take_a_lost_evaluator_for_a_verdict(tip_view, book, o5):
    rule = _adm_installed(book)
    tip_view.clause_for.return_value = CAP_50
    o5.set_verdict(CAP_50, _gone)
    with pytest.raises(tau_admission.AdmissionUnavailable):
        validate_payout_execute_payload(execute(rule.rule_id.hex()), tip_view)


# --- the command line --------------------------------------------------------------------------

def test_the_cli_builds_the_term_the_node_parses():
    from tau_testnet_cli import tx as tx_mod
    from tau_testnet_cli.cli import build_parser

    common = dict(sender_pubkey=ADM_A, sequence_number=1, expiration_time=FAR,
                  expire_at_height=ADM_HEIGHT + 5, rule_text=RECURRING, slots=[BOB],
                  cap_per_execution=100, cap_per_period=100, period_blocks=10,
                  expires_at=ADM_HEIGHT + 1000)
    built = tx_mod.build_payout_rule_set_tx(policy_exempt=True, **common)
    assert built["policy_exempt"] is True and parse_payout_rule_set(built).policy_exempt
    assert "policy_exempt" not in tx_mod.build_payout_rule_set_tx(**common)
    line = ["payout", "set", "--key", "k", "--body", RECURRING, "--slot", BOB,
            "--cap-per-execution", "5", "--cap-per-period", "9", "--period-blocks", "10",
            "--ends-in", "100"]
    parser = build_parser()
    assert parser.parse_args(line + ["--policy-exempt"]).policy_exempt is True
    assert parser.parse_args(line).policy_exempt is False
