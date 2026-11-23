"""Payout rules: several rules per account, and a due point that is tried again (#63).

Two signed terms, both optional, both open to every payout rule:

- `rule_index` (1..7) puts a rule in another place on the account than the
  first. Each place holds one rule; a set installs or replaces the rule in its
  own place only, a revoke names the place, an execution names the rule by its
  id. A sealed rule in any place seals the account.
- `due_retry` (with `due_at`) makes the node run a due point again when the run
  found the account short: in later blocks, after their due points, until the
  rule pays or the window closes.

A rule without them keeps its id, its book entry, the root and its stored row
byte for byte: tests/test_payout_options.py and tests/test_payout_triggers.py
pin those values, computed by the code before.

No engine here: block apply runs through the real `apply_block` with scripted
evaluators. The same rules run on the real engine in
tests/test_payout_places_native.py.
"""
import pytest

import chain_state
import db
from consensus import sender_policy
from consensus.governance import ConsensusLifecycleManager
from consensus.payout import (
    MAX_PAYOUT_RETRY_RUNS_PER_BLOCK,
    MAX_PERIOD_BLOCKS,
    MAX_RULES_PER_ACCOUNT,
    MIN_DUE_EVERY_BLOCKS,
    PayoutBook,
    PayoutExecution,
    PayoutRefused,
    PayoutShapeError,
    PayoutShort,
    parse_payout_rule_revoke_place,
    parse_payout_rule_set,
    parse_payout_spec,
    payout_key,
    payout_revoke_place,
    payout_rule_body,
    payout_spec_text,
    settle,
    validate_terms_shape,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_signing import signing_message_bytes

from tests.test_payout_apply import _events, _reason, exec_tx, rid, set_tx
from tests.test_payout_options import NOW, NOW_TS, fields, seconds, terms
from tests.chain_harness import (
    ALICE, BOB, CAROL, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, _sign, spend_tx,
)

STEP = MIN_DUE_EVERY_BLOCKS
RECURRING = ("always ( (i13[t]:bv[384] = { 0 }:bv[384]) "
             "? (o30[t]:bv[24] = { 100 }:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).")
DATA = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
ROUTE = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 5 }:bv[24] )."
HALF = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 2 }:bv[24] )."
A1 = payout_key(ALICE, 1)


def place(k):
    return payout_key(ALICE, k)


def revoke_tx(sender=ALICE, seq=1, **extra):
    tx = {"tx_id": f"revoke-{seq}-{extra.get('rule_index')}", "tx_type": "payout_rule_revoke",
          "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
          "expire_at_height": 1000, "fee_limit": "0"}
    tx.update(extra)
    return _sign(tx, SKS[sender])


@pytest.fixture
def evs():
    out = {}
    for pool in ("apply", "payout_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    pay = out["payout_apply"]
    pay.set_outputs(payout_rule_body(RECURRING),
                    lambda i: {"o30": "100" if i.get("i13") == "0" else "0"})
    pay.set_outputs(payout_rule_body(DATA), lambda i: {"o30": i.get("i40", "0")})
    pay.set_outputs(payout_rule_body(ROUTE), lambda i: {"o30": str(int(i.get("i27", "0")) // 5)})
    pay.set_outputs(payout_rule_body(HALF), lambda i: {"o30": str(int(i.get("i27", "0")) // 2)})
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


def _bal(**over):
    return dict({ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0}, **over)


def _outcomes(ch):
    return [e["outcome"] for e in _events(ch)]


# --- terms -------------------------------------------------------------------------------

def test_the_new_terms_are_part_of_the_id_and_a_rule_without_them_keeps_it():
    base = terms(due_at=NOW + 5)
    ids = {terms(due_at=NOW + 5, **over).rule_id for over in (
        {"rule_index": 1}, {"rule_index": 2}, {"due_retry": 5}, {"due_retry": 6},
        {"rule_index": 1, "due_retry": 5})}
    assert len(ids) == 5 and base.rule_id not in ids
    # the values the code before these terms computed for the same rules
    assert terms().rule_id.hex() == parse_payout_rule_set(fields()).rule_id.hex()
    assert base.key == base.account_pubkey and terms(rule_index=3).key.endswith("/3")


@pytest.mark.parametrize("value", [0, 8, -1, "1", True, 1.0, None])
def test_a_place_is_1_to_7_or_left_out(value):
    tx = fields(rule_index=value) if value is not None else dict(fields(), rule_index=None)
    with pytest.raises(PayoutShapeError):
        parse_payout_rule_set(tx)


@pytest.mark.parametrize("over, why", [
    ({"due_retry": 5}, "due_retry needs a due point"),
    ({"due_at": NOW + 5, "due_retry": 0}, "due_retry must be in 1.."),
    ({"due_at": NOW + 5, "due_retry": MAX_PERIOD_BLOCKS + 1}, "due_retry must be in 1.."),
])
def test_retry_terms_the_node_refuses(over, why):
    assert why in validate_terms_shape(terms(**over), NOW, NOW_TS)


def test_retry_terms_the_node_accepts():
    assert validate_terms_shape(terms(due_at=NOW + 5, due_retry=1), NOW, NOW_TS) is None
    assert validate_terms_shape(terms(due_at=NOW + 5, due_every=STEP, due_retry=MAX_PERIOD_BLOCKS,
                                      rule_index=7), NOW, NOW_TS) is None
    assert validate_terms_shape(terms(**seconds(due_at=NOW_TS + 60, due_retry=3600)),
                                NOW, NOW_TS) is None


@pytest.mark.parametrize("field, value, base", [
    ("rule_index", 2, {}),
    ("due_retry", 9, {"due_at": NOW + 5}),
])
def test_each_new_term_is_signed_and_carried_by_a_guarded_install(field, value, base):
    with_it, without = fields(**base, **{field: value}), fields(**base)
    assert signing_message_bytes(with_it) != signing_message_bytes(without)
    text = payout_spec_text(with_it)
    assert f'"{field}":{value}' in text
    assert parse_payout_spec(text, with_it["sender_pubkey"], 1) == parse_payout_rule_set(with_it)


def test_a_revoke_names_its_place_signed():
    tx = {"tx_type": "payout_rule_revoke", "sender_pubkey": ALICE, "sequence_number": 1,
          "expiration_time": FAR, "expire_at_height": 9, "fee_limit": "0"}
    assert parse_payout_rule_revoke_place(tx) == (ALICE, 0)
    assert parse_payout_rule_revoke_place(dict(tx, rule_index=3)) == (ALICE, 3)
    assert signing_message_bytes(dict(tx, rule_index=3)) != signing_message_bytes(tx)
    assert signing_message_bytes(dict(tx, rule_index=3)) != \
        signing_message_bytes(dict(tx, rule_index=4))
    for bad in (0, 8, "3", None, True):
        with pytest.raises(PayoutShapeError, match="rule_index must be 1..7"):
            parse_payout_rule_revoke_place(dict(tx, rule_index=bad))


def test_a_revoke_request_names_its_place_in_its_rule_text():
    assert [payout_revoke_place(t) for t in ("", None, "1", "7")] == [0, 0, 1, 7]
    for bad in ("0", "8", "01", " 1", "x", "1.0", 1):
        with pytest.raises(PayoutShapeError):
            payout_revoke_place(bad)


def test_a_short_balance_is_its_own_refusal():
    rule = terms(rule_text=RECURRING, due_at=NOW + 5)
    exe = PayoutExecution("", ALICE, rule.rule_id, (), ())
    from consensus.payout import PayoutState

    with pytest.raises(PayoutShort, match="holds 60"):
        settle(rule, PayoutState(anchor=NOW), exe, {"o30": "100"}, height=NOW + 5, ts=NOW_TS,
               balance=60)
    with pytest.raises(PayoutRefused) as err:
        settle(rule, PayoutState(anchor=NOW), exe, {"o30": "0"}, height=NOW + 5, ts=NOW_TS,
               balance=60)
    assert not isinstance(err.value, PayoutShort)


# --- the book ----------------------------------------------------------------------------

A = fields()["sender_pubkey"]


def _places_book():
    book = PayoutBook()
    book.install(terms(), NOW)
    book.install(terms(rule_index=1, cap_per_execution=50), NOW)
    book.install(terms(rule_index=5, due_at=NOW + 5, due_retry=4), NOW)
    return book


def test_each_place_holds_one_rule_and_a_set_replaces_only_its_own():
    book = _places_book()
    assert book.keys_of(A) == [A, f"{A}/1", f"{A}/5"] and book.count() == 3
    old = book.get(f"{A}/1").rule_id
    assert book.install(terms(rule_index=1, cap_per_execution=60), NOW + 1) == old
    assert book.get(A).cap_per_execution == 100 and book.get(f"{A}/1").cap_per_execution == 60
    gone = book.revoke(f"{A}/1")
    assert gone.rule_index == 1 and book.keys_of(A) == [A, f"{A}/5"]
    assert book.can_admit_revoke(A, 1) == (False, "the account has no payout rule in place 1")
    assert book.can_admit_revoke(A) == (True, "")


def test_an_execution_finds_its_rule_by_id_in_any_place():
    book = _places_book()
    second = book.get(f"{A}/1")
    exe = PayoutExecution(pubkey_c := "cc" * 48, A, second.rule_id, (), ((0, 40),))
    rule, _ = book.check_execution(exe, NOW + 1, NOW_TS)
    assert rule.key == f"{A}/1" and pubkey_c
    with pytest.raises(PayoutRefused, match="none of the account's payout rules"):
        book.check_execution(PayoutExecution("", A, b"\x01" * 32, (), ()), NOW + 1, NOW_TS)


def test_a_sealed_rule_in_any_place_seals_the_account():
    book = _places_book()
    book.install(terms(rule_index=6, sealed=True), NOW)
    assert book.sealed(A)
    ok, why = book.can_admit_set(terms(rule_index=2), NOW, NOW_TS)
    assert not ok and "sealed" in why
    assert "sealed" in book.can_admit_revoke(A)[1]


def test_retry_window_and_queue():
    book = _places_book()
    key = f"{A}/5"
    assert book.due(NOW + 5, NOW_TS) == [key]
    assert book.due_ran(key, NOW + 5, short=True) == NOW + 6
    state = book.state_of(key)
    assert (state.retry_at, state.retry_until) == (NOW + 6, NOW + 9)
    assert not book.has_retry(NOW + 5, NOW_TS) and book.has_retry(NOW + 6, NOW_TS)
    assert book.retries(NOW + 6, NOW_TS) == ([key], [])
    assert book.retry_ran(key, NOW + 6, short=True) == NOW + 7
    assert book.retry_ran(key, NOW + 7, short=True) == NOW + 8
    assert book.retry_ran(key, NOW + 8, short=True) is None      # NOW + 9 is the end
    assert book.state_of(key).retry_at == 0 and not book.has_retry(FAR, FAR)


def test_a_retry_the_chain_slept_through_ends_unpaid():
    book = _places_book()
    key = f"{A}/5"
    book.due_ran(key, NOW + 5, short=True)
    assert book.retries(NOW + 40, NOW_TS) == ([], [key])
    book.retry_ended(key)
    assert book.state_of(key).retry_at == 0 and not book.has_retry(FAR, FAR)


def test_a_run_refused_for_another_reason_or_without_the_term_owes_no_retry():
    book = _places_book()
    assert book.due_ran(f"{A}/5", NOW + 5, short=False) is None
    plain = PayoutBook()
    plain.install(terms(due_at=NOW + 5), NOW)
    before = plain.store_rows()
    assert plain.due_ran(A, NOW + 5, short=True) is None
    assert plain.store_rows()[0][17] == before[0][17][:3] + (True,)   # only the due point ran


def test_the_next_due_point_closes_the_window_of_the_one_before():
    book = PayoutBook()
    book.install(terms(due_at=NOW + 5, due_every=STEP, due_retry=10 * STEP), NOW)
    book.due_ran(A, NOW + 5, short=True)
    assert book.state_of(A).retry_until == NOW + 5 + STEP
    book.due_ran(A, NOW + 5 + STEP, short=False)                  # the next one paid
    assert (book.state_of(A).retry_at, book.state_of(A).retry_until) == (0, 0)
    assert book._retry == {0: [], 1: []}


def test_at_most_four_retries_a_block_longest_waiting_first():
    book = PayoutBook()
    for k in range(MAX_RULES_PER_ACCOUNT - 1):
        book.install(terms(rule_index=k + 1, due_at=NOW + 5 + (k % 2), due_retry=50), NOW)
    for key in book.due(NOW + 5, NOW_TS):
        book.due_ran(key, NOW + 5, short=True)
    for key in book.due(NOW + 6, NOW_TS):
        book.due_ran(key, NOW + 6, short=True)
    run, ended = book.retries(NOW + 7, NOW_TS)
    assert len(run) == MAX_PAYOUT_RETRY_RUNS_PER_BLOCK and ended == []
    assert run == [f"{A}/1", f"{A}/3", f"{A}/5", f"{A}/7"]         # waiting since NOW + 6


def test_the_rows_carry_places_and_retries_and_restore_them():
    book = _places_book()
    book.due_ran(f"{A}/5", NOW + 5, short=True)
    rows = {row[1]: row for row in book.store_rows()}
    assert set(rows) == {A, f"{A}/1", f"{A}/5"}
    assert len(rows[A]) == 16                                     # as a rule was stored before
    assert rows[f"{A}/1"][17] == (None, None, 0, False, None, None, False, False, 0,
                                  1, None, 0, 0)
    assert rows[f"{A}/5"][17] == (None, NOW + 5, 0, True, None, None, False, False, 0,
                                  5, 4, NOW + 6, NOW + 9)
    again = PayoutBook.restore(book.store_rows(), *book.resolved_state())
    assert again.root() == book.root() and again.store_rows() == book.store_rows()
    assert again._retry == book._retry and again._due == book._due


@pytest.mark.parametrize("key, change, why", [
    (lambda a: f"{a}/1", lambda r: r[:1] + (r[1][:-1] + "2",) + r[2:], "wrong place"),
    (lambda a: f"{a}/5", lambda r: r[:17] + (r[17][:11] + (NOW + 9, NOW + 9),), "retry"),
    (lambda a: f"{a}/5", lambda r: r[:17] + (r[17][:11] + (0, NOW + 9),), "retry"),
    (lambda a: f"{a}/1", lambda r: r[:17] + (r[17][:11] + (NOW, NOW + 1),), "retry"),
    (lambda a: f"{a}/1", lambda r: r[:17] + (r[17][:9] + (9,) + r[17][10:],), "bad place"),
])
def test_a_row_that_does_not_fit_its_place_or_retry_refuses_to_load(key, change, why):
    book = _places_book()
    book.due_ran(f"{A}/5", NOW + 5, short=True)
    rows = [change(tuple(r)) if r[1] == key(A) else r for r in book.store_rows()]
    with pytest.raises(ValueError, match=why):
        PayoutBook.restore(rows, *book.resolved_state())


def test_two_rows_for_one_place_refuse_to_load():
    book = _places_book()
    rows = book.store_rows()
    with pytest.raises(ValueError, match="two stored payout rules for one place"):
        PayoutBook.restore(rows + rows[:1], *book.resolved_state())


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_database_round_trips_places_and_retries_and_a_retry_wakes_no_miner(temp_database):
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
    lm.payout_rules = _places_book()
    lm.payout_rules.due_ran(f"{A}/5", NOW + 5, short=True)
    chain_state._lifecycle_manager = lm
    meta, book = lm.consensus_meta_hash(), lm.payout_rules
    chain_state.commit_state_to_db("head-hash", 60)
    assert not db.has_due_payouts(NOW + 7, NOW_TS)                # a retry runs in blocks made anyway
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager.payout_rules
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded._retry == book._retry
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


# --- block apply: several rules per account ----------------------------------------------

def test_two_rules_on_one_account_are_installed_side_by_side_and_executed_by_id(evs):
    ch = Chain(_bal())
    first = set_tx(rule=DATA)
    second = set_tx(seq=1, rule=DATA, slots=[CAROL], rule_index=1)
    ch.block([first, second])
    assert ch.lm.payout_rules.keys_of(ALICE) == [ALICE, A1], _reason(ch.last, second)
    assert _events(ch) == [
        {"account_pubkey": ALICE, "rule_id": rid(first), "outcome": "installed",
         "tx_id": first["tx_id"]},
        {"account_pubkey": ALICE, "rule_id": rid(second), "rule_index": 1,
         "outcome": "installed", "tx_id": second["tx_id"]}]
    one = exec_tx(rule_id=rid(first), data={"0": 30})
    two = exec_tx(CAROL, 1, rule_id=rid(second), data={"0": 40})
    ch.block([one, two], height=HEIGHT + 1, ts=TS + 1)
    assert (ch.bal[ALICE], ch.bal[BOB], ch.bal[CAROL]) == (930, 30, 540)
    assert [(e.get("rule_index"), e["total"]) for e in _events(ch)] == [(None, 30), (1, 40)]
    assert ch.lm.payout_rules.state_of(ALICE).paid_total == 30
    assert ch.lm.payout_rules.state_of(A1).paid_total == 40


def test_a_set_replaces_and_a_revoke_removes_only_its_own_place(evs):
    ch = Chain(_bal())
    first, second = set_tx(rule=DATA), set_tx(seq=1, rule=DATA, rule_index=1)
    ch.block([first, second])
    again = set_tx(seq=2, rule=DATA, rule_index=1, cap_exec=90)
    ch.block([again], height=HEIGHT + 1, ts=TS + 1)
    assert _events(ch)[0]["replaced"] == rid(second)
    assert ch.lm.payout_rules.get(ALICE).rule_id.hex() == rid(first)
    gone = revoke_tx(seq=3, rule_index=1)
    ch.block([gone], height=HEIGHT + 2, ts=TS + 2)
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(again), "rule_index": 1,
                            "outcome": "revoked", "tx_id": gone["tx_id"]}]
    assert ch.lm.payout_rules.keys_of(ALICE) == [ALICE]
    empty = revoke_tx(seq=4, rule_index=2)
    ch.block([empty], height=HEIGHT + 3, ts=TS + 3)
    assert _reason(ch.last, empty) == "payout_rule_not_revoked"
    ch.block([revoke_tx(seq=4)], height=HEIGHT + 4, ts=TS + 4)
    assert ch.lm.payout_rules.keys_of(ALICE) == []


def test_a_sealed_rule_in_another_place_seals_the_account(evs):
    ch = Chain(_bal())
    ch.block([set_tx(rule=DATA), set_tx(seq=1, rule=DATA, rule_index=2, sealed=True,
                                        expires_at=HEIGHT + 5)])
    assert ch.lm.payout_rules.sealed(ALICE)
    late = set_tx(seq=2, rule=DATA, rule_index=3)
    ch.block([late, spend_tx(ALICE, BOB, 10, 2)], height=HEIGHT + 1, ts=TS + 1)
    assert _reason(ch.last, late) == "account_sealed" and ch.bal[ALICE] == 1_000
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert _outcomes(ch) == ["expired"] and not ch.lm.payout_rules.sealed(ALICE)


def test_due_points_of_two_places_run_in_one_block_first_place_first(evs):
    ch = Chain(_bal())
    ch.block([set_tx(rule=RECURRING, cap_exec=100, cap_period=100, due_at=HEIGHT + 5,
                     rule_index=4, slots=[CAROL]),
              set_tx(seq=1, rule=RECURRING, cap_exec=100, cap_period=100, due_at=HEIGHT + 5)])
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert [(e.get("rule_index"), e["outcome"]) for e in _events(ch)] == [
        (None, "executed"), (4, "executed")]
    assert (ch.bal[ALICE], ch.bal[BOB], ch.bal[CAROL]) == (800, 100, 600)


def test_a_payment_that_arrives_is_a_sale_of_each_per_sale_rule(evs):
    ch = Chain(_bal())
    ch.block([set_tx(rule=ROUTE, per_sale=True, on_arrival=True),
              set_tx(seq=1, rule=HALF, per_sale=True, on_arrival=True, rule_index=1)])
    ch.block([spend_tx(CAROL, ALICE, 100, 0)], height=HEIGHT + 1, ts=TS + 1)
    assert [(e.get("rule_index"), e["total"]) for e in _events(ch)] == [(None, 20), (1, 50)]
    assert (ch.bal[ALICE], ch.bal[BOB], ch.bal[CAROL]) == (1_030, 70, 400)


# --- block apply: a due point tried again --------------------------------------------------

def _retrying(balances=None, **kw):
    kw.setdefault("due_at", HEIGHT + 5)
    kw.setdefault("due_retry", 20)
    kw.setdefault("expires_at", HEIGHT + 200)
    ch = Chain(balances or _bal(**{ALICE: 60}))
    tx = set_tx(rule=RECURRING, cap_exec=100, cap_period=100,
                **{k: v for k, v in kw.items() if v is not None})
    ch.block([tx])
    assert ch.lm.payout_rules.get(payout_key(ALICE, kw.get("rule_index") or 0)) is not None, \
        _reason(ch.last, tx)
    return ch, tx


def test_a_short_due_point_is_paid_in_the_block_that_brings_the_money(evs):
    ch, tx = _retrying()
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    event, = _events(ch)
    assert (event["outcome"], event["retry_at"]) == ("due_not_paid", HEIGHT + 6)
    assert "holds 60" in event["reason"]
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    assert [(e["outcome"], e["retry"], e["retry_at"]) for e in _events(ch)] == [
        ("due_not_paid", True, HEIGHT + 7)]
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 9, ts=TS + 9)
    assert _events(ch) == [{
        "account_pubkey": ALICE, "rule_id": rid(tx), "retry": True, "outcome": "executed",
        "executor_pubkey": None, "total": 100,
        "legs": [{"slot": 0, "recipient_pubkey": BOB, "amount": 100}]}]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (160, 100)
    assert ch.lm.payout_rules.state_of(ALICE).retry_at == 0
    ch.block([spend_tx(CAROL, ALICE, 100, 1)], height=HEIGHT + 10, ts=TS + 10)
    assert _events(ch) == []                                      # paid once
    assert ch.seq == {ALICE: 1, CAROL: 2}                         # nobody signed for a run


def test_a_short_due_point_without_the_term_is_not_tried_again(evs):
    ch, tx = _retrying(due_retry=None)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert "retry_at" not in _events(ch)[0]
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 6, ts=TS + 6)
    assert _events(ch) == [] and ch.bal[BOB] == 0


def test_the_retry_window_closes_and_nothing_is_owed(evs):
    ch, tx = _retrying(due_retry=3)
    for h in (5, 6, 7):
        ch.block([], height=HEIGHT + h, ts=TS + h)
    assert [(e["outcome"], e.get("retry_at")) for e in _events(ch)] == [("due_not_paid", None)]
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 8, ts=TS + 8)
    assert _events(ch) == [] and (ch.bal[ALICE], ch.bal[BOB]) == (260, 0)


def test_a_retry_the_chain_slept_through_ends_with_an_event(evs):
    ch, tx = _retrying(due_retry=3)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 30, ts=TS + 30)
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                            "outcome": "due_retry_ended"}]
    assert ch.bal[BOB] == 0 and ch.lm.payout_rules.state_of(ALICE).retry_at == 0


def test_a_run_refused_for_another_reason_is_not_tried_again(evs):
    ch = Chain(_bal())
    ch.block([set_tx(rule=DATA, due_at=HEIGHT + 5, due_retry=20)])
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    event, = _events(ch)
    assert "pays nothing" in event["reason"] and "retry_at" not in event
    assert not ch.lm.payout_rules.has_retry(FAR, FAR)


def test_the_next_due_point_takes_over_from_an_unpaid_one(evs):
    ch, tx = _retrying(due_every=STEP, due_retry=10 * STEP, expires_at=HEIGHT + 5 + 5 * STEP)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 6)
    assert [(e.get("due_index"), e["outcome"], e.get("retry")) for e in _events(ch)] == [
        (1, "due_not_paid", None)]
    assert ch.lm.payout_rules.state_of(ALICE).retry_until == HEIGHT + 5 + 2 * STEP
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 6 + STEP, ts=TS + 7)
    assert [(e["outcome"], e["total"]) for e in _events(ch)] == [("executed", 100)]
    assert ch.bal[BOB] == 100                                      # one payment, not two


def test_four_retries_a_block_and_the_rest_in_the_next(evs):
    ch = Chain(_bal(**{ALICE: 50}))
    ch.block([set_tx(seq=k, rule=RECURRING, cap_exec=100, cap_period=100, due_at=HEIGHT + 5,
                     due_retry=50, expires_at=HEIGHT + 200, **({"rule_index": k} if k else {}))
              for k in range(5)])
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert [e["retry_at"] for e in _events(ch)] == [HEIGHT + 6] * 5
    ch.block([spend_tx(CAROL, ALICE, 500, 0)], height=HEIGHT + 6, ts=TS + 6)
    assert [(e.get("rule_index"), e["outcome"]) for e in _events(ch)] == [
        (None, "executed"), (1, "executed"), (2, "executed"), (3, "executed")]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (150, 400)
    ch.block([], height=HEIGHT + 7, ts=TS + 7)
    assert [(e.get("rule_index"), e["outcome"]) for e in _events(ch)] == [(4, "executed")]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (50, 500)


def test_a_retry_on_the_time_clock(evs):
    ch, tx = _retrying(period_seconds=60, clock="period_seconds", period=60,
                       due_at=TS + 50, due_retry=600, expires_at=TS + 6000)
    ch.block([], height=HEIGHT + 1, ts=TS + 50)
    assert _events(ch)[0]["retry_at"] == TS + 51
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 2, ts=TS + 70)
    assert [(e["outcome"], e["total"]) for e in _events(ch)] == [("executed", 100)]


def test_the_same_blocks_give_the_same_state_and_replay_moves_nothing(evs):
    runs = []
    for _ in range(2):
        ch, tx = _retrying(rule_index=3)
        ch.block([], height=HEIGHT + 5, ts=TS + 5)
        ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 6, ts=TS + 6)
        runs.append((ch.hashes, ch.lm.payout_rules.root()))
    assert runs[0] == runs[1]
    ch, tx = _retrying()
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    sender_policy.set_evaluator("payout_apply", None)
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 6, ts=TS + 6, replay=True)
    assert ch.bal[BOB] == 0


# --- admission -----------------------------------------------------------------------------

from tests.test_payout_integration import (  # noqa: E402,F401  (fixtures)
    A as ADM_A, NEXT_HEIGHT as ADM_HEIGHT, book, evaluator, revoke, rule_set, tip_view,
)


def test_admission_reports_the_place_and_the_retry(tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    result = validate_payout_rule_set_payload(
        rule_set(rule_index=2, due_at=ADM_HEIGHT + 50, due_retry=30), tip_view)
    assert result.is_valid, result.error
    assert (result.data["rule_index"], result.data["due_retry"]) == (2, 30)
    plain = validate_payout_rule_set_payload(rule_set(), tip_view)
    assert "rule_index" not in plain.data and "due_retry" not in plain.data


def test_admission_revokes_the_place_named(tip_view, book):
    from consensus.admission import validate_payout_rule_revoke_payload

    book.install(parse_payout_rule_set(rule_set(rule_index=2)), ADM_HEIGHT - 1)
    assert not validate_payout_rule_revoke_payload(revoke(), tip_view).is_valid
    result = validate_payout_rule_revoke_payload(dict(revoke(), rule_index=2), tip_view)
    assert result.is_valid, result.error
    missing = validate_payout_rule_revoke_payload(dict(revoke(), rule_index=3), tip_view)
    assert "place 3" in missing.error and missing.code == "NO_PAYOUT_RULE"
    bad = validate_payout_rule_revoke_payload(dict(revoke(), rule_index=0), tip_view)
    assert not bad.is_valid and "rule_index" in bad.error


def test_admission_takes_nothing_an_account_sealed_in_another_place_signs(tip_view, book):
    from consensus.admission import validate_mempool_admission

    book.install(parse_payout_rule_set(rule_set(rule_index=6, sealed=True)), ADM_HEIGHT - 1)
    result = validate_mempool_admission(rule_set(sequence_number=2), tip_view)
    assert not result.is_valid and result.code == "ACCOUNT_SEALED"


# --- the command line ------------------------------------------------------------------------

def test_the_cli_builds_places_and_retries_the_node_parses():
    from tau_testnet_cli import tx as tx_mod

    built = tx_mod.build_payout_rule_set_tx(
        sender_pubkey=ADM_A, sequence_number=1, expiration_time=FAR,
        expire_at_height=ADM_HEIGHT + 5, rule_text=RECURRING, slots=[BOB],
        cap_per_execution=100, cap_per_period=100, period_blocks=10,
        expires_at=ADM_HEIGHT + 1000, due_at=ADM_HEIGHT + 10, due_retry=30, rule_index=4)
    rule = parse_payout_rule_set(built)
    assert (rule.rule_index, rule.due_retry, rule.key) == (4, 30, f"{ADM_A}/4")
    gone = tx_mod.build_payout_rule_revoke_tx(
        sender_pubkey=ADM_A, sequence_number=2, expiration_time=FAR,
        expire_at_height=ADM_HEIGHT + 5, rule_index=4)
    assert parse_payout_rule_revoke_place(gone) == (ADM_A, 4)
    plain = tx_mod.build_payout_rule_revoke_tx(
        sender_pubkey=ADM_A, sequence_number=2, expiration_time=FAR,
        expire_at_height=ADM_HEIGHT + 5)
    assert "rule_index" not in plain
    req = tx_mod.build_rule_change_request_tx(
        sender_pubkey=ADM_A, sequence_number=4, expiration_time=FAR,
        expire_at_height=ADM_HEIGHT + 5, kind=7, rule_text="4")
    assert req["rule_text"] == "4"
    for bad in ("x", "0", "8"):
        with pytest.raises(ValueError, match="place 1..7"):
            tx_mod.build_rule_change_request_tx(
                sender_pubkey=ADM_A, sequence_number=4, expiration_time=FAR,
                expire_at_height=ADM_HEIGHT + 5, kind=7, rule_text=bad)


def test_the_cli_parses_the_place_and_the_retry():
    from tau_testnet_cli.cli import build_parser

    parser = build_parser()
    args = parser.parse_args(["payout", "set", "--key", "k", "--body", RECURRING, "--slot", BOB,
                              "--cap-per-execution", "5", "--cap-per-period", "9",
                              "--period-blocks", "10", "--ends-in", "100", "--due-at", "60",
                              "--due-retry", "20", "--rule-index", "2"])
    assert (args.rule_index, args.due_retry) == (2, 20)
    assert parser.parse_args(["payout", "revoke", "--key", "k", "--rule-index", "3"]).rule_index == 3
    assert parser.parse_args(["payout", "revoke", "--key", "k"]).rule_index is None
    assert parser.parse_args(["payout", "execute", "--key", "k", "--account", ADM_A,
                              "--rule-index", "5"]).rule_index == 5


def test_the_cli_finds_the_rule_of_a_place_from_the_wallet_rpc(monkeypatch):
    import json as _json

    from tau_testnet_cli import cli

    data = {"installed": True, "rule": {"rule_id": "aa" * 32},
            "rules": [{"rule_id": "aa" * 32}, {"rule_id": "bb" * 32, "rule_index": 2}]}
    monkeypatch.setattr(cli, "_send", lambda *_a, **_k: _json.dumps({"data": data}))
    args = cli.build_parser().parse_args(["payout", "show", ADM_A])
    assert cli._installed_rule_id(args, ADM_A) == "aa" * 32
    assert cli._installed_rule_id(args, ADM_A, 2) == "bb" * 32
    with pytest.raises(cli._PayloadError, match="place 3"):
        cli._installed_rule_id(args, ADM_A, 3)
    old = {"installed": True, "rule": {"rule_id": "cc" * 32}}      # a node from before
    monkeypatch.setattr(cli, "_send", lambda *_a, **_k: _json.dumps({"data": old}))
    assert cli._installed_rule_id(args, ADM_A) == "cc" * 32


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_wallet_rpc_lists_every_place(temp_database, monkeypatch):
    from commands import getpayoutrule
    from tests.test_payout_integration import call

    lm = ConsensusLifecycleManager(active_validators=[ADM_A])
    chain_state._lifecycle_manager = lm
    first = parse_payout_rule_set(rule_set())
    other = parse_payout_rule_set(rule_set(rule_index=3, due_at=ADM_HEIGHT + 9, due_retry=4))
    lm.payout_rules.install(first, ADM_HEIGHT - 1)
    lm.payout_rules.install(other, ADM_HEIGHT - 1)
    monkeypatch.setattr(getpayoutrule, "_tip",
                        lambda: ("head", ADM_HEIGHT + 1, lm.payout_rules))
    import types

    box = types.SimpleNamespace(db=db, chain_state=chain_state)
    data = call(getpayoutrule, f"getpayoutrule {ADM_A}", box)["data"]
    assert data["installed"] is True and data["rule"]["rule_id"] == first.rule_id.hex()
    assert [(r["rule_id"], r.get("rule_index"), r.get("due_retry")) for r in data["rules"]] == [
        (first.rule_id.hex(), None, None), (other.rule_id.hex(), 3, 4)]
    assert data["semantics"]["rules_per_account"] == MAX_RULES_PER_ACCOUNT
    lm.payout_rules.revoke(ADM_A)
    data = call(getpayoutrule, f"getpayoutrule {ADM_A}", box)["data"]
    assert data["installed"] is True and "rule" not in data and len(data["rules"]) == 1
