"""The optional terms of a payout rule and the two clocks it may read (#63).

    periods_from   the periods count from a signed point, not from the install
    due_at         the node runs the rule itself, once, at a signed point
    i48, i49       the clock of the install and of the last paid execution

Three things are pinned here, without an engine (the rule is scripted):

  * a rule that carries none of them is, byte for byte, the rule it was: same
    id, same book root, same stored row;
  * the book's own arithmetic: periods, the due queue, expiry, the round trip;
  * block apply: what a due run reads, pays, records and costs, through the
    real `apply_block` against an oracle of the full balance map.
"""
import copy

import pytest
from py_ecc.bls import G2Basic

import chain_state
import db
from consensus import sender_policy
from consensus.governance import ConsensusLifecycleManager
from consensus.payout import (
    MAX_PAYOUT_DUE_RUNS_PER_BLOCK,
    PayoutBook,
    PayoutShapeError,
    PayoutState,
    parse_payout_rule_set,
    parse_payout_spec,
    payout_rule_body,
    payout_spec_text,
    screen_payout_body,
    validate_terms_shape,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_signing import signing_message_bytes

from commands import createblock
from tests.bls_keys import pubkey_hex
from tests.test_miner_retractable_wake import (  # noqa: F401  (`node` is a fixture)
    RECIPIENT, SENDER, head_number, node,
)
from tests.test_payout_apply import _bal, _events, _executed, exec_tx, rid, set_tx
from tests.test_standing_apply import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _logs, _sign,
)

A, B, C = pubkey_hex(0x1A), pubkey_hex(0x2B), pubkey_hex(0x3C)
NOW, NOW_TS = 50, 1_767_225_600
RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
TWO = ("always ( (o30[t]:bv[24] = i40[t]:bv[24]) && "
       "(o31[t]:bv[24] = i41[t]:bv[24]) ).")

# What is left goes to slot 0 when nobody sent the execution; a sender gets
# what it asks for. Scripted below exactly so.
SWEEP = ("always ( (i13[t]:bv[384] = { 0 }:bv[384]) "
         "? (o30[t]:bv[24] = i2[t]:bv[24]) : (o30[t]:bv[24] = i40[t]:bv[24]) ).")
SWEEP_BODY = payout_rule_body(SWEEP)
# Pays what is asked once three ticks have passed since the last paid execution.
PACED = ("always ( (i5[t]:bv[64] >= (i49[t]:bv[64] + { 3 }:bv[64])) "
         "? (o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).")
PACED_BODY = payout_rule_body(PACED)
SINCE = ("always ( (i6[t]:bv[64] >= (i48[t]:bv[64] + { 3 }:bv[64])) "
         "? (o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).")
SINCE_BODY = payout_rule_body(SINCE)


def fields(**over):
    tx = {"tx_type": "payout_rule_set", "sender_pubkey": A, "sequence_number": 1,
          "expiration_time": 9_999_999_999, "expire_at_height": NOW + 5, "fee_limit": "10",
          "rule_text": RULE, "slots": [B], "cap_per_execution": 100, "cap_per_period": 300,
          "period_blocks": 10, "expires_at": NOW + 1000}
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def terms(**over):
    return parse_payout_rule_set(fields(**over))


def seconds(**over):
    return dict(period_blocks=None, period_seconds=60, expires_at=NOW_TS + 600, **over)


# --- a rule without them is the rule it was -----------------------------------------

def test_a_rule_without_the_optional_terms_keeps_its_id_its_root_and_its_row():
    """The three values below were computed by the code before the optional terms
    existed, from exactly these rules."""
    book = PayoutBook()
    one = terms()
    two = terms(sender_pubkey=C, slots=[B, ""], rule_text=TWO, **seconds())
    book.install(one, 49)
    book.record(A, 25, 53, NOW_TS)
    book.install(two, NOW_TS)
    assert one.rule_id.hex() == "2218f5e475a2058a961d5026ec07b25a830c2c06b85f53dff1457fafdcd4b55b"
    assert two.rule_id.hex() == "9d013fdbd39951dd67149af6c8af6ae3e5a33ae4ee2b4b718fdc7db34cd379aa"
    assert book.root().hex() == "da9d10218ec9683f95d1962b28d2f7c2312d5b3d0b945bbe70b2f01df4c6178a"
    assert [len(row) for row in book.store_rows()] == [16, 16]
    assert not one.extended and not two.extended
    assert book.state_of(A).last_clock == 0      # kept only for a rule that reads it


def test_each_optional_term_is_part_of_the_id():
    base = terms().rule_id
    ids = {terms(**over).rule_id for over in (
        {"periods_from": 60}, {"periods_from": 61}, {"due_at": 60}, {"due_at": 61},
        {"periods_from": 60, "due_at": 60}, {"periods_from": 60, "due_at": 61},
        {"periods_from": 0})}
    assert len(ids) == 7 and base not in ids


@pytest.mark.parametrize("field", ["periods_from", "due_at"])
@pytest.mark.parametrize("value", [None, -1, "60", 1.5, True, 2 ** 64])
def test_an_optional_term_is_a_number_or_left_out(field, value):
    tx = fields()
    tx[field] = value                # `null` too: one spelling per meaning
    with pytest.raises(PayoutShapeError, match="unsigned 64-bit"):
        parse_payout_rule_set(tx)


@pytest.mark.parametrize("field", ["periods_from", "due_at"])
def test_each_optional_term_is_signed(field):
    assert signing_message_bytes(fields(**{field: 60})) != signing_message_bytes(fields())
    assert signing_message_bytes(fields(**{field: 60})) != \
        signing_message_bytes(fields(**{field: 61}))


def test_the_spec_text_of_a_guarded_install_carries_them():
    tx = fields(periods_from=60, due_at=70)
    text = payout_spec_text(tx)
    assert '"due_at":70' in text and '"periods_from":60' in text
    assert parse_payout_spec(text, A, 1).rule_id == parse_payout_rule_set(tx).rule_id
    assert parse_payout_spec(text, A, 1).rule_id != terms().rule_id


# --- what may be installed -------------------------------------------------------------

@pytest.mark.parametrize("over, why", [
    ({"periods_from": NOW + 1000}, "periods_from must be before expires_at"),
    ({"due_at": NOW}, "due_at must be in the future"),
    ({"due_at": NOW + 1000}, "before expires_at"),
    ({"due_at": NOW + 5, "slots": [""]}, "needs a fixed slot"),
    ({"due_at": NOW + 5, "per_sale": True}, "per sale has no due point"),
])
def test_optional_terms_the_node_refuses(over, why):
    assert why in validate_terms_shape(terms(**over), NOW, NOW_TS)


@pytest.mark.parametrize("over", [
    {"periods_from": 0}, {"periods_from": NOW - 40}, {"periods_from": NOW + 999},
    {"due_at": NOW + 1}, {"due_at": NOW + 999}, {"due_at": NOW + 5, "slots": [B, ""], "rule_text": TWO},
    seconds(periods_from=NOW_TS + 86_400 - 86_400, due_at=NOW_TS + 1),
])
def test_optional_terms_the_node_accepts(over):
    assert validate_terms_shape(terms(**over), NOW, NOW_TS) is None


def test_the_two_clocks_are_part_of_the_abi_at_64_bits():
    assert screen_payout_body(PACED_BODY, 1) is None
    assert screen_payout_body(SINCE_BODY, 1) is None
    assert "must be bv[64]" in screen_payout_body(PACED_BODY.replace("i49[t]:bv[64]", "i49[t]:bv[24]"), 1)
    assert terms(rule_text=PACED).reads_clocks and terms(rule_text=SINCE).reads_clocks
    assert terms(rule_text=PACED).extended and not terms().reads_clocks
    # A mention inside a comment is not a read.
    commented = "always ( o30[t]:bv[24] = i40[t]:bv[24]   # not i49[t]:bv[64]\n )."
    assert not terms(rule_text=commented).reads_clocks
    assert terms(rule_text=commented).rule_id == terms().rule_id


# --- periods ---------------------------------------------------------------------------

def test_periods_count_from_the_signed_point_not_from_the_install():
    plain, dated = terms(), terms(periods_from=NOW + 25)
    state = PayoutState(anchor=NOW)
    assert [state.period_at(plain, NOW + n) for n in (0, 9, 10, 25, 34, 35)] == [0, 0, 1, 2, 3, 3]
    # Everything before the point belongs to the first period; then one period
    # every ten blocks from the point, wherever the install was.
    assert [state.period_at(dated, NOW + n) for n in (0, 10, 24, 25, 34, 35, 45)] == \
        [0, 0, 0, 0, 0, 1, 2]
    later = PayoutState(anchor=NOW + 7)
    assert [later.period_at(dated, NOW + n) for n in (25, 34, 35, 45)] == [0, 0, 1, 2]


def test_a_point_in_the_past_lines_the_periods_up_with_it():
    week, monday = 604_800, 1_766_966_400            # a Monday 00:00 UTC before NOW_TS
    dated = terms(**dict(seconds(), period_seconds=week, periods_from=monday,
                         expires_at=NOW_TS + 10 * week))
    state = PayoutState(anchor=NOW_TS)                # installed on a Thursday
    first_monday = monday + week
    assert state.period_at(dated, NOW_TS) == 0
    assert state.period_at(dated, first_monday - 1) == 0
    assert state.period_at(dated, first_monday) == 1


def test_the_cap_of_a_period_follows_the_signed_point():
    book = PayoutBook()
    dated = terms(periods_from=NOW + 25, cap_per_period=100)
    book.install(dated, NOW)
    state = book.record(A, 100, NOW + 30, NOW_TS)
    assert state.spent_at(dated, NOW + 34) == 100
    assert state.spent_at(dated, NOW + 35) == 0       # the point + one period
    # Counted from the install the cap would have come back at NOW + 40.
    plain_state = PayoutState(anchor=NOW, period_index=3, spent_in_period=100)
    assert plain_state.spent_at(terms(), NOW + 35) == 100


# --- the due queue ---------------------------------------------------------------------

def _keys(n):
    return [pubkey_hex(0x100 + k) for k in range(n)]


def test_due_points_run_earliest_first_and_at_most_sixteen_a_block():
    book, accounts = PayoutBook(), _keys(MAX_PAYOUT_DUE_RUNS_PER_BLOCK + 3)
    for k, account in enumerate(accounts):
        book.install(terms(sender_pubkey=account, due_at=NOW + 5 + (k % 3)), NOW)
    assert not book.has_due(NOW + 4, NOW_TS) and book.due(NOW + 4, NOW_TS) == []
    assert book.has_due(NOW + 5, NOW_TS)
    first = book.due(NOW + 5, NOW_TS)
    assert first == sorted(a for k, a in enumerate(accounts) if k % 3 == 0)
    turn = book.due(NOW + 7, NOW_TS)
    assert len(turn) == MAX_PAYOUT_DUE_RUNS_PER_BLOCK
    order = sorted((NOW + 5 + (k % 3), a) for k, a in enumerate(accounts))
    assert turn == [a for _, a in order[:MAX_PAYOUT_DUE_RUNS_PER_BLOCK]]
    for account in turn:
        book.due_ran(account)
    assert book.due(NOW + 8, NOW_TS) == [a for _, a in order[MAX_PAYOUT_DUE_RUNS_PER_BLOCK:]]
    for account in book.due(NOW + 8, NOW_TS):
        book.due_ran(account)
    assert not book.has_due(NOW + 10_000, NOW_TS + 10_000)
    with pytest.raises(KeyError):
        book.due_ran(accounts[0])                     # a due point runs once


def test_both_clocks_have_due_points_and_share_the_cap():
    book = PayoutBook()
    book.install(terms(due_at=NOW + 5), NOW)
    book.install(terms(sender_pubkey=C, **seconds(due_at=NOW_TS + 30)), NOW_TS)
    assert book.due(NOW + 5, NOW_TS + 29) == [A]
    assert book.due(NOW + 4, NOW_TS + 30) == [C]
    assert book.due(NOW + 5, NOW_TS + 30) == [A, C]
    assert book.due(NOW + 5, NOW_TS + 30, cap=1) == [A]


def test_the_run_the_node_makes_names_nobody():
    book = PayoutBook()
    dated = terms(due_at=NOW + 5)
    book.install(dated, NOW)
    got_terms, state, exe = book.due_execution(A)
    assert got_terms is dated and state.due_pending(dated)
    assert (exe.executor_pubkey, exe.account_pubkey, exe.rule_id) == ("", A, dated.rule_id)
    assert exe.recipients == () and exe.data == () and exe.sale_id is None
    book.install(terms(), NOW)                        # replaced by a rule without one
    assert not book.has_due(NOW + 5, NOW_TS)
    with pytest.raises(KeyError):
        book.due_execution(A)


def test_replacing_or_revoking_a_rule_takes_its_due_point_with_it():
    book = PayoutBook()
    book.install(terms(due_at=NOW + 5), NOW)
    book.install(terms(sender_pubkey=C, due_at=NOW + 6), NOW)
    book.install(terms(due_at=NOW + 9, sequence_number=2), NOW + 1)
    book.revoke(C)
    assert book.due(NOW + 8, NOW_TS) == [] and book.due(NOW + 9, NOW_TS) == [A]


def test_a_rule_whose_due_point_has_not_run_outlives_its_end():
    book = PayoutBook()
    book.install(terms(due_at=NOW + 5, expires_at=NOW + 6), NOW)
    book.install(terms(sender_pubkey=C, expires_at=NOW + 6), NOW)
    # The block clock jumped past both points before the node got to run it.
    assert [t.account_pubkey for t in book.expire(NOW + 6, NOW_TS)] == [C]
    assert book.get(A) is not None and book.has_expiring(NOW + 6, NOW_TS)
    assert book.expire(NOW + 7, NOW_TS) == []
    book.due_ran(A)
    assert [t.account_pubkey for t in book.expire(NOW + 7, NOW_TS)] == [A]
    assert book.count() == 0 and book.resolved_count == 2


def test_a_copy_of_the_book_has_its_own_due_queue():
    book = PayoutBook()
    book.install(terms(due_at=NOW + 5), NOW)
    root = book.root()
    clone = copy.deepcopy(book)
    clone.due_ran(A)
    assert book.due(NOW + 5, NOW_TS) == [A] and clone.due(NOW + 5, NOW_TS) == []
    assert book.root() == root != clone.root()


def test_the_book_root_holds_the_optional_terms_and_the_kept_clocks():
    def root(change):
        book = PayoutBook()
        book.install(terms(due_at=NOW + 5, rule_text=PACED), NOW)
        change(book)
        return book.root()

    plain = root(lambda book: None)
    ran = root(lambda book: book.due_ran(A))
    paid = root(lambda book: book.record(A, 5, NOW + 3, NOW_TS))
    paid_later = root(lambda book: book.record(A, 5, NOW + 4, NOW_TS))
    assert len({plain, ran, paid, paid_later}) == 4


# --- the round trip ------------------------------------------------------------------

def _rows_book():
    book = PayoutBook()
    book.install(terms(), NOW)
    book.install(terms(sender_pubkey=B, slots=[C], periods_from=NOW + 20, due_at=NOW + 30), NOW)
    book.install(terms(sender_pubkey=C, rule_text=PACED, **seconds()), NOW_TS)
    book.record(C, 7, NOW + 2, NOW_TS + 45)
    book.record(B, 9, NOW + 3, NOW_TS + 50)
    return book


def test_the_rows_carry_the_optional_terms_and_restore_them():
    book = _rows_book()
    rows = {row[1]: row for row in book.store_rows()}
    assert len(rows[A]) == 16
    assert rows[B][16:] == (None, (NOW + 20, NOW + 30, NOW + 3, False))
    assert rows[C][16:] == (None, (None, None, NOW_TS + 45, False))
    again = PayoutBook.restore(book.store_rows(), *book.resolved_state())
    assert again.root() == book.root() and again.store_rows() == book.store_rows()
    assert again._due == book._due and again._expiry == book._expiry
    assert again.state_of(C).last_clock == NOW_TS + 45
    book.due_ran(B)
    after = PayoutBook.restore(book.store_rows(), *book.resolved_state())
    assert after.state_of(B).due_done and not after.has_due(NOW + 10_000, NOW_TS)
    assert after.root() == book.root() != again.root()


@pytest.mark.parametrize("account, change, why", [
    (A, lambda row: row + (None, (None, None, 0, False)), "disagree"),
    (B, lambda row: row[:16], "does not match its terms"),
    (C, lambda row: row[:16], "disagree"),
    (B, lambda row: row[:17] + ((NOW + 21, NOW + 30, NOW + 3, False),), "does not match its terms"),
    (B, lambda row: row[:17] + ((NOW + 20, NOW + 30, -1, False),), "bad clocks"),
    (C, lambda row: row[:17] + ((None, None, 0, True),), "does not have"),
    (C, lambda row: row[:17] + ((None, None, 0),), "malformed optional terms"),
])
def test_a_row_that_does_not_fit_its_rule_refuses_to_load(account, change, why):
    book = _rows_book()
    rows = [change(row) if row[1] == account else row for row in book.store_rows()]
    with pytest.raises(ValueError, match=why):
        PayoutBook.restore(rows, *book.resolved_state())


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_database_round_trips_the_optional_terms(temp_database):
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.faucet_amount = chain_state._genesis_faucet_amount
    if chain_state._genesis_approval_slots_active:
        lm.activate_approval_slots()
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 500, B: 7})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    lm.payout_rules = _rows_book()
    lm.payout_rules.due_ran(B)
    lm.payout_rules.install(terms(sender_pubkey=pubkey_hex(0x4D), due_at=NOW + 40,
                                  per_sale=None), NOW)
    chain_state._lifecycle_manager = lm
    meta, book = lm.consensus_meta_hash(), lm.payout_rules
    chain_state.commit_state_to_db("head-hash", 60)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager.payout_rules
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded._due == book._due
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_miners_wake_hint_reads_the_persisted_due_points(temp_database):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    assert not db.has_due_payouts(NOW + 10_000, NOW_TS + 10_000)        # nothing stored yet
    lm.payout_rules.install(terms(due_at=NOW + 5), NOW)
    lm.payout_rules.install(terms(sender_pubkey=C, **seconds(due_at=NOW_TS + 30)), NOW_TS)
    lm.payout_rules.install(terms(sender_pubkey=B, slots=[C]), NOW)     # no due point
    chain_state.commit_state_to_db("head-hash", 40)
    assert not db.has_due_payouts(NOW + 4, NOW_TS + 29)
    assert db.has_due_payouts(NOW + 5, NOW_TS + 29)                     # the block clock
    assert db.has_due_payouts(NOW + 4, NOW_TS + 30)                     # the time clock
    lm.payout_rules.due_ran(A)
    lm.payout_rules.due_ran(C)
    chain_state.commit_state_to_db("head-hash-2", 41)
    assert not db.has_due_payouts(NOW + 10_000, NOW_TS + 10_000)        # each ran once


# --- block apply: the run the node makes ---------------------------------------------

def _sweep(inputs):
    if inputs.get("i13") == "0":
        return {"o30": inputs["i2"]}
    return {"o30": inputs.get("i40", "0")}


@pytest.fixture
def evs():
    out = {}
    for pool in ("apply", "payout_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    out["payout_apply"].set_outputs(SWEEP_BODY, _sweep)
    for body in (PACED_BODY, SINCE_BODY, payout_rule_body(RULE)):
        out["payout_apply"].set_outputs(body, lambda inputs: {"o30": inputs.get("i40", "0")})
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


def _dated(fee=0, **kw):
    kw.setdefault("rule", SWEEP)
    kw.setdefault("cap_exec", 1_000)
    kw.setdefault("cap_period", 1_000)
    kw.setdefault("due_at", HEIGHT + 5)
    ch, oracle = Chain(_bal(), fee=fee), Oracle(_bal())
    tx = set_tx(**{k: v for k, v in kw.items() if v is not None})
    ch.block([tx])
    oracle.create(tx, fee=fee)
    return ch, oracle, tx


def test_the_node_runs_the_rule_at_its_due_point_and_nobody_pays_a_fee(evs):
    ch, oracle, tx = _dated(fee=7)
    ch.block([], height=HEIGHT + 4, ts=TS + 4)
    assert _events(ch) == [] and evs["payout_apply"].output_calls == []
    oracle.check(ch)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    _executed(oracle, executor=PROPOSER, legs=[(BOB, 993)], ts=TS + 5)
    oracle.seq[PROPOSER] -= 1                     # nobody sent it: no sequence moves
    oracle.check(ch)
    assert _events(ch) == [{
        "account_pubkey": ALICE, "rule_id": rid(tx), "outcome": "executed",
        "due_at": HEIGHT + 5, "executor_pubkey": None, "total": 993,
        "legs": [{"slot": 0, "recipient_pubkey": BOB, "amount": 993}]}]
    state = ch.lm.payout_rules.state_of(ALICE)
    assert state.due_done and (state.executions, state.paid_total) == (1, 993)
    assert state.last_height == HEIGHT + 5 and state.last_clock == HEIGHT + 5
    (body, inputs), = evs["payout_apply"].output_calls
    assert body == SWEEP_BODY
    assert inputs["i13"] == "0" and inputs["i2"] == "993" and inputs["i30"] == "#x" + BOB
    assert inputs["i5"] == str(TS + 5) and inputs["i6"] == str(HEIGHT + 5)
    assert all(inputs[f"i{40 + k}"] == "0" for k in range(8))


def test_a_due_run_reads_the_balance_the_block_has_reached(evs):
    ch, oracle, tx = _dated()
    spend = exec_tx(rule_id=rid(tx), data={"0": 40})
    ch.block([spend], height=HEIGHT + 5, ts=TS + 5)
    _executed(oracle, legs=[(BOB, 40)], ts=TS + 5)
    _executed(oracle, executor=PROPOSER, legs=[(BOB, 960)], ts=TS + 5)
    oracle.seq[PROPOSER] -= 1
    oracle.check(ch)
    by_carol, by_node = evs["payout_apply"].output_calls
    assert by_carol[1]["i2"] == "1000"            # a sent execution: the parent block's
    assert by_node[1]["i2"] == "960" and by_node[1]["i26"] == "40"
    assert [e["total"] for e in _events(ch)] == [40, 960]
    assert ch.bal.get(ALICE, 0) == 0


def test_a_due_point_runs_once_whether_it_paid_or_not(evs):
    evs["payout_apply"].set_outputs(SWEEP_BODY, lambda inputs: {"o30": "0"})
    ch, oracle, tx = _dated()
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert _events(ch) == [{
        "account_pubkey": ALICE, "rule_id": rid(tx), "outcome": "due_not_paid",
        "due_at": HEIGHT + 5, "reason": "the rule pays nothing for these inputs"}]
    assert ch.lm.payout_rules.state_of(ALICE).due_done
    assert ch.lm.payout_rules.state_of(ALICE).executions == 0
    evs["payout_apply"].set_outputs(SWEEP_BODY, _sweep)
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    assert _events(ch) == [] and len(evs["payout_apply"].output_calls) == 1
    oracle.check(ch)


@pytest.mark.parametrize("kw, why", [
    (dict(cap_exec=500), "over the cap per execution 500"),
    (dict(cap_exec=100, cap_period=100, slots=[BOB, ""], rule=TWO.replace("i41", "i2")),
     "no recipient was named"),
])
def test_a_due_run_is_an_execution_like_any_other(evs, kw, why):
    evs["payout_apply"].set_outputs(
        payout_rule_body(TWO.replace("i41", "i2")), lambda inputs: {"o31": "5"})
    ch, oracle, tx = _dated(**kw)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    event, = _events(ch)
    assert event["outcome"] == "due_not_paid" and why in event["reason"]
    oracle.check(ch)                              # all or nothing: nothing moved


def test_a_due_run_keeps_the_cap_of_its_period(evs):
    ch, oracle, tx = _dated(cap_exec=600, cap_period=1_000)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 600})], height=HEIGHT + 2, ts=TS + 2)
    _executed(oracle, legs=[(BOB, 600)], ts=TS + 2)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    _executed(oracle, executor=PROPOSER, legs=[(BOB, 400)], ts=TS + 5)
    oracle.seq[PROPOSER] -= 1
    oracle.check(ch)
    assert ch.lm.payout_rules.state_of(ALICE).spent_in_period == 1_000


def test_a_block_that_reaches_the_due_point_and_the_end_runs_then_expires(evs):
    ch, oracle, tx = _dated(clock="period_seconds", period=3600, due_at=TS + 100,
                            expires_at=TS + 200)
    ch.block([], height=HEIGHT + 1, ts=TS + 500)
    _executed(oracle, executor=PROPOSER, legs=[(BOB, 1_000)], ts=TS + 500)
    oracle.seq[PROPOSER] -= 1
    oracle.check(ch)
    assert [e["outcome"] for e in _events(ch)] == ["executed", "expired"]
    assert ch.lm.payout_rules.get(ALICE) is None


def test_an_evaluator_refusal_at_the_due_point_moves_nothing(evs):
    ch, oracle, tx = _dated()
    evs["payout_apply"]._refused[SWEEP_BODY] = "step failed"
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    event, = _events(ch)
    assert event["outcome"] == "due_not_paid" and "cannot be evaluated" in event["reason"]
    assert ch.lm.payout_rules.state_of(ALICE).due_done
    oracle.check(ch)


def test_replay_without_an_evaluator_marks_the_due_point_and_moves_nothing(evs):
    ch, oracle, tx = _dated()
    sender_policy.set_evaluator("payout_apply", None)
    ch.block([], height=HEIGHT + 5, ts=TS + 5, replay=True)
    event, = _events(ch)
    assert event["outcome"] == "due_not_paid"
    state = ch.lm.payout_rules.state_of(ALICE)
    assert state.due_done and state.executions == 0
    oracle.check(ch)


def test_seventeen_rules_due_together_take_two_blocks(evs):
    sks = {G2Basic.SkToPk(9_000 + k).hex(): 9_000 + k
           for k in range(MAX_PAYOUT_DUE_RUNS_PER_BLOCK + 1)}
    bal = dict(_bal(), **{account: 10 for account in sks})
    ch = Chain(bal)
    txs = []
    for account, sk in sks.items():
        tx = {"tx_id": f"set-{account[:8]}", "tx_type": "payout_rule_set",
              "sender_pubkey": account, "sequence_number": 0, "expiration_time": 9_999_999_999,
              "expire_at_height": 1000, "fee_limit": "100", "rule_text": SWEEP,
              "slots": [BOB], "cap_per_execution": 10, "cap_per_period": 10,
              "period_blocks": 10, "expires_at": HEIGHT + 6, "due_at": HEIGHT + 5}
        txs.append(_sign(tx, sk))
    for k in range(0, len(txs), 8):               # the node's own cap on rule txs per block
        ch.block(txs[k:k + 8], height=HEIGHT + k // 8)
    assert ch.lm.payout_rules.count() == len(sks)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    first = [e["account_pubkey"] for e in _events(ch)]
    assert first == sorted(sks)[:MAX_PAYOUT_DUE_RUNS_PER_BLOCK]
    assert ch.bal[BOB] == 10 * MAX_PAYOUT_DUE_RUNS_PER_BLOCK
    # The seventeenth is past its end now, and still gets its run.
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    events = _events(ch)
    assert [(e["account_pubkey"], e["outcome"]) for e in events[:1]] == \
        [(sorted(sks)[-1], "executed")]
    assert sorted(e["outcome"] for e in events[1:]) == ["expired"] * len(sks)
    assert ch.bal[BOB] == 10 * len(sks) and ch.lm.payout_rules.count() == 0


def test_the_due_run_moves_the_state_hash_and_the_same_blocks_agree(evs):
    runs = []
    for _ in range(2):
        ch, _oracle, tx = _dated()
        ch.block([], height=HEIGHT + 4, ts=TS + 4)
        ch.block([], height=HEIGHT + 5, ts=TS + 5)
        ch.block([], height=HEIGHT + 6, ts=TS + 6)
        runs.append(list(ch.hashes))
    assert runs[0] == runs[1]
    installed, before, ran, after = runs[0]
    assert installed == before != ran == after


def test_a_block_does_not_touch_the_due_queue_of_its_parent(evs):
    ch, _oracle, tx = _dated()
    parent = ch.lm.payout_rules
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert parent.due(HEIGHT + 5, TS + 5) == [ALICE] and not parent.state_of(ALICE).due_done
    assert ch.lm.payout_rules.due(HEIGHT + 5, TS + 5) == []


# --- an idle chain -------------------------------------------------------------------

def test_an_idle_chain_seals_a_block_for_a_due_point(node, evs):
    """No transaction is waiting, and the due point still gets its block: the
    miner's hint reads the stored rows, the block builder asks the book."""
    lm = chain_state._lifecycle_manager
    lm.payout_rules.install(parse_payout_rule_set({
        "sender_pubkey": SENDER, "sequence_number": 0, "rule_text": SWEEP,
        "slots": [RECIPIENT], "cap_per_execution": 1_000, "cap_per_period": 1_000,
        "period_blocks": 10, "expires_at": 500, "due_at": 1}), 0)
    with db._db_lock, db._db_conn:
        db._write_payout_rows(chain_state._payout_state(lm))
    assert db.has_due_payouts(1, 0)
    refused = createblock.create_block_from_mempool()
    assert "block_hash" not in refused and head_number() == 0
    sealed = createblock.create_block_from_mempool(wake_if_due=True)
    assert "block_hash" in sealed and head_number() == 1
    assert chain_state._balances.get(SENDER, 0) == 0
    assert chain_state._balances[RECIPIENT] == 100
    assert chain_state._lifecycle_manager.payout_rules.state_of(SENDER).due_done
    assert not db.has_due_payouts(2, 0)
    again = createblock.create_block_from_mempool(wake_if_due=True)
    assert "block_hash" not in again and head_number() == 1          # nothing is due


# --- block apply: the two clocks ------------------------------------------------------

def test_a_rule_reads_when_it_was_installed_and_when_it_last_paid(evs):
    ch, oracle, tx = _dated(rule=PACED, due_at=None, clock="period_seconds", period=3600,
                            cap_exec=100, cap_period=1_000, expires_at=TS + 86_400)
    ch.block([exec_tx(seq=0, rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 1, ts=TS + 10)
    _executed(oracle, legs=[(BOB, 5)], ts=TS + 10)
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 6})], height=HEIGHT + 2, ts=TS + 20)
    _executed(oracle, legs=[(BOB, 6)], ts=TS + 20)
    oracle.check(ch)
    first, second = (call[1] for call in evs["payout_apply"].output_calls)
    assert (first["i48"], first["i49"]) == (str(TS), str(TS))           # no paid run yet
    assert (second["i48"], second["i49"]) == (str(TS), str(TS + 10))
    assert ch.lm.payout_rules.state_of(ALICE).last_clock == TS + 20


def test_a_refused_execution_does_not_move_the_last_paid_clock(evs):
    ch, oracle, tx = _dated(rule=SINCE, due_at=None, cap_exec=100)
    ch.block([exec_tx(seq=0, rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, legs=[(BOB, 5)], ts=TS + 3)
    refused = ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 0})], height=HEIGHT + 4)
    assert "pays nothing" in _logs(refused)
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 1})], height=HEIGHT + 6, ts=TS + 6)
    last = evs["payout_apply"].output_calls[-1][1]
    assert (last["i48"], last["i49"]) == (str(HEIGHT), str(HEIGHT + 3))   # block clock


def test_a_rule_that_reads_neither_clock_is_not_handed_them(evs):
    ch, _oracle, tx = _dated(rule=RULE, due_at=None, cap_exec=100)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 1, ts=TS + 1)
    inputs = evs["payout_apply"].output_calls[0][1]
    assert "i48" not in inputs and "i49" not in inputs
    assert ch.lm.payout_rules.state_of(ALICE).last_clock == 0


# --- admission: a rule with a due point is stepped once before it may be queued ------

from tests.test_payout_integration import (  # noqa: E402,F401  (fixtures)
    A as ADM_A, BODY as ADM_BODY, NEXT_HEIGHT as ADM_HEIGHT, book, evaluator, rule_set, tip_view,
)


def _due_set(**over):
    return rule_set(due_at=ADM_HEIGHT + 50, **over)


def test_admission_steps_a_rule_with_a_due_point_once_on_the_inputs_of_the_run(
        tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    result = validate_payout_rule_set_payload(_due_set(), tip_view)
    assert result.is_valid, result.error
    assert result.data["due_at"] == ADM_HEIGHT + 50
    (body, inputs), = evaluator.output_calls
    assert body == ADM_BODY
    assert inputs["i13"] == "0"                      # nobody executes it
    assert inputs["i6"] == str(ADM_HEIGHT + 50)      # the block clock at the due point
    assert inputs["i2"] == "1000"                    # what the account holds now
    assert inputs["i40"] == "0"                      # and no data


def test_admission_does_not_step_a_rule_without_a_due_point(tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    assert validate_payout_rule_set_payload(rule_set(), tip_view).is_valid
    assert validate_payout_rule_set_payload(
        rule_set(periods_from=ADM_HEIGHT - 5), tip_view).is_valid
    assert evaluator.output_calls == []


def test_admission_does_not_judge_what_the_trial_step_answers(tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    evaluator.fail_step(ADM_BODY, "no answer on these inputs")
    assert validate_payout_rule_set_payload(_due_set(), tip_view).is_valid
    assert len(evaluator.output_calls) == 1


def test_admission_stops_a_rule_whose_trial_step_runs_out_of_time(tip_view, evaluator):
    import tau_admission
    from consensus.admission import validate_payout_rule_set_payload
    from tau_speculation import WorkerLost, WorkerTimeout

    def slow(inputs):
        raise WorkerTimeout("slow")

    evaluator.set_outputs(ADM_BODY, slow)
    with pytest.raises(tau_admission.AdmissionTimeout):
        validate_payout_rule_set_payload(_due_set(), tip_view)

    def lost(inputs):
        raise WorkerLost("gone")

    evaluator.set_outputs(ADM_BODY, lost)
    with pytest.raises(tau_admission.AdmissionUnavailable):
        validate_payout_rule_set_payload(_due_set(), tip_view)


def test_admission_trial_for_a_rule_on_the_time_clock_uses_the_due_time(tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    now = tip_view.next_block_timestamp
    tx = rule_set(period_blocks=None, period_seconds=3600, expires_at=now + 90_000,
                  due_at=now + 7_200)
    assert validate_payout_rule_set_payload(tx, tip_view).is_valid, \
        validate_payout_rule_set_payload(tx, tip_view).error
    body, inputs = evaluator.output_calls[0]
    assert inputs["i5"] == str(now + 7_200) and inputs["i6"] == str(ADM_HEIGHT)
