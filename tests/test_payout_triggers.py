"""Payout rules, three ways a rule is started (#63).

A payout rule is stepped when someone sends an execution. Two more ways, both
signed with the rule and both generic: the clock (`due_at`, repeated by
`due_every` or `due_months`) and an arriving payment (`on_arrival` on a rule
that pays per sale). With them a standing payment and a share routed from each
incoming payment are payout rules like any other: the Tau rule decides the
amounts, the node only decides when it asks. `sealed` closes the account for
its own key until the rule ends, so money leaves by the rule and by nothing
else.

No engine here: block apply runs through the real `apply_block` with scripted
evaluators, as in tests/test_payout_options.py. The same rules run on the real
engine in tests/test_payout_triggers_native.py.
"""
import copy

import pytest

import chain_state
import db
from consensus import sender_policy
from consensus.approvals import ApprovalRequestLifecycleManager
from consensus.governance import ConsensusLifecycleManager
from consensus.payout import (
    MAX_DUE_MONTHS,
    MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK,
    MIN_DUE_EVERY_BLOCKS,
    MIN_DUE_EVERY_SECONDS,
    PayoutBook,
    PayoutShapeError,
    parse_payout_rule_set,
    parse_payout_spec,
    payout_rule_body,
    payout_spec_text,
    validate_terms_shape,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_signing import signing_message_bytes

from tests.bls_keys import pubkey_hex
from tests.test_payout_apply import _events, _reason, exec_tx, revoke_tx, rid, set_tx
from tests.test_payout_options import NOW, NOW_TS, PACED, fields, seconds, terms
from tests.test_payout_sales import _sale_id
from tests.test_standing_apply import (
    ALICE, BOB, CAROL, EVERY, HEIGHT, PROPOSER, SKS, TS, Chain, _sign, create_tx, spend_tx,
)

A, B, C, D = pubkey_hex(0x1A), pubkey_hex(0x2B), pubkey_hex(0x3C), pubkey_hex(0x4D)
DAY = 86_400
STEP = MIN_DUE_EVERY_BLOCKS

# A standing payment: 100 to slot 0 whenever the node itself runs the rule.
STANDING = ("always ( (i13[t]:bv[384] = { 0 }:bv[384]) "
            "? (o30[t]:bv[24] = { 100 }:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).")
STANDING_BODY = payout_rule_body(STANDING)
# A route: a fifth of every payment that arrives goes to slot 0.
ROUTE = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 5 }:bv[24] )."
ROUTE_BODY = payout_rule_body(ROUTE)
# The other half of a routed payment, for the account that gets the share.
HALF = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 2 }:bv[24] )."
HALF_BODY = payout_rule_body(HALF)


def repeating(**over):
    return terms(due_at=NOW + 5, due_every=STEP, **over)


def route(**over):
    return terms(rule_text=ROUTE, per_sale=True, on_arrival=True, **over)


# --- the rules from before are the rules they were -------------------------------------

def test_a_rule_without_the_new_terms_keeps_its_id_its_root_and_its_row():
    """The values below were computed by the code before these terms existed,
    from exactly these rules: one with both earlier optional terms, one that
    reads the kept clocks, one with a due point that has run."""
    book = PayoutBook()
    one = terms(periods_from=NOW + 20, due_at=NOW + 30)
    two = terms(sender_pubkey=C, rule_text=PACED, **seconds())
    three = terms(sender_pubkey=B, slots=[C], due_at=NOW + 7)
    book.install(one, NOW)
    book.install(two, NOW_TS)
    book.install(three, NOW)
    book.record(C, 7, NOW + 2, NOW_TS + 45)
    book.record(A, 9, NOW + 3, NOW_TS + 50)
    assert one.rule_id.hex() == "6f9ba84cd618aa3aeaf19f39f94e464b360c829917ee7cb56be63c3813a1fea4"
    assert two.rule_id.hex() == "fae3b8f1935e36e4eedf35b94553d19cdadf6607431bc875b7758e6200601cc6"
    assert three.rule_id.hex() == "0b7ca18e422f4783e6795435710caa19a722b105a9a252cb3fbe891b07a11452"
    assert book.root().hex() == "7a974948a30c387a035ebdbd526619020dceeddb310965e7d9dd0659b41e5bb4"
    book.due_ran(B, NOW + 7)
    assert book.root().hex() == "e447d213855e556148bba8aee45e4751b66f1822b61e758c79cb4e65af639b84"
    assert [row[16:] for row in book.store_rows()] == [
        (None, (NOW + 20, NOW + 30, NOW + 3, False)),
        (None, (None, NOW + 7, 0, True)),
        (None, (None, None, NOW_TS + 45, False))]


def test_each_new_term_is_part_of_the_id():
    base = terms(due_at=NOW + 5).rule_id
    ids = {terms(due_at=NOW + 5, **over).rule_id for over in (
        {"due_every": STEP}, {"due_every": STEP + 1}, {"sealed": True},
        {"due_every": STEP, "sealed": True})}
    ids |= {terms(**seconds(due_at=NOW_TS + 60, **over)).rule_id for over in (
        {}, {"due_months": 1}, {"due_months": 2}, {"due_every": MIN_DUE_EVERY_SECONDS})}
    ids |= {terms(rule_text=ROUTE, per_sale=True, **over).rule_id for over in (
        {}, {"on_arrival": True}, {"on_arrival": True, "sealed": True})}
    assert len(ids) == 11 and base not in ids


@pytest.mark.parametrize("field", ["on_arrival", "sealed"])
@pytest.mark.parametrize("value", [False, 1, 0, "true", "yes"])
def test_a_switch_is_true_or_left_out(field, value):
    tx = fields(rule_text=ROUTE, per_sale=True)
    tx[field] = value
    with pytest.raises(PayoutShapeError, match=f"{field} must be true or left out"):
        parse_payout_rule_set(tx)
    tx[field] = None                       # null is refused too: one spelling per meaning
    with pytest.raises(PayoutShapeError):
        parse_payout_rule_set(tx)


@pytest.mark.parametrize("field", ["due_every", "due_months"])
@pytest.mark.parametrize("value", [None, -1, "256", 1.5, True, 2 ** 64])
def test_a_repeat_is_a_number_or_left_out(field, value):
    tx = fields(due_at=NOW + 5)
    tx[field] = value
    with pytest.raises(PayoutShapeError):
        parse_payout_rule_set(tx)


@pytest.mark.parametrize("field, value, base", [
    ("due_every", STEP, {"due_at": NOW + 5}),
    ("due_months", 1, seconds(due_at=NOW_TS + 60)),
    ("on_arrival", True, {"rule_text": ROUTE, "per_sale": True}),
    ("sealed", True, {}),
])
def test_each_new_term_is_signed(field, value, base):
    with_it, without = fields(**base, **{field: value}), fields(**base)
    assert signing_message_bytes(with_it) != signing_message_bytes(without)
    if value is not True:
        other = dict(with_it, **{field: value + 1})
        assert signing_message_bytes(with_it) != signing_message_bytes(other)


def test_the_spec_text_of_a_guarded_install_carries_them():
    tx = fields(due_at=NOW + 5, due_every=STEP, sealed=True)
    text = payout_spec_text(tx)
    assert '"due_every":%d' % STEP in text and '"sealed":true' in text
    again = parse_payout_spec(text, A, sequence_number=1)
    assert again.rule_id == parse_payout_rule_set(tx).rule_id
    assert again.repeats and again.sealed and not again.on_arrival
    with pytest.raises(PayoutShapeError, match="canonical"):
        parse_payout_spec(text.replace('"sealed":true', '"sealed": true'), A, sequence_number=1)


@pytest.mark.parametrize("over, why", [
    ({"due_every": STEP}, "needs its first due point"),
    ({"due_at": NOW + 5, "due_every": STEP - 1}, "due_every must be in"),
    ({"due_at": NOW + 5, "due_every": 1_000_001}, "due_every must be in"),
    ({"due_at": NOW + 5, "due_months": 1}, "needs the time clock"),
    (seconds(due_at=NOW_TS + 60, due_every=MIN_DUE_EVERY_SECONDS - 1), "due_every must be in"),
    (seconds(due_at=NOW_TS + 60, due_months=0), "due_months must be in"),
    (seconds(due_at=NOW_TS + 60, due_months=MAX_DUE_MONTHS + 1), "due_months must be in"),
    (seconds(due_at=NOW_TS + 60, due_months=1, due_every=MIN_DUE_EVERY_SECONDS),
     "exclude each other"),
    ({"on_arrival": True}, "needs a rule that pays per sale"),
    ({"rule_text": ROUTE, "per_sale": True, "on_arrival": True, "slots": [""]},
     "needs a fixed slot"),
    ({"rule_text": ROUTE, "per_sale": True, "on_arrival": True, "due_at": NOW + 5},
     "has no due point"),
])
def test_terms_the_node_refuses(over, why):
    assert why in (validate_terms_shape(terms(**over), NOW, NOW_TS) or "")


@pytest.mark.parametrize("over", [
    {"due_at": NOW + 5, "due_every": STEP},
    {"due_at": NOW + 5, "due_every": 1_000_000, "expires_at": NOW + 5_000_000},
    seconds(due_at=NOW_TS + 60, due_every=MIN_DUE_EVERY_SECONDS),
    seconds(due_at=NOW_TS + 60, due_months=1),
    seconds(due_at=NOW_TS + 60, due_months=MAX_DUE_MONTHS),
    {"rule_text": ROUTE, "per_sale": True, "on_arrival": True},
    {"rule_text": ROUTE, "per_sale": True, "on_arrival": True, "slots": [B, ""]},
    {"sealed": True},
    {"due_at": NOW + 5, "due_every": STEP, "sealed": True, "periods_from": NOW + 2},
])
def test_terms_the_node_accepts(over):
    assert validate_terms_shape(terms(**over), NOW, NOW_TS) is None


def test_the_floor_of_a_repeat_lets_a_full_book_be_served():
    from consensus.payout import MAX_PAYOUT_DUE_RUNS_PER_BLOCK, MAX_PAYOUT_RULES_TOTAL

    assert MIN_DUE_EVERY_BLOCKS * MAX_PAYOUT_DUE_RUNS_PER_BLOCK >= MAX_PAYOUT_RULES_TOTAL


# --- the book: a due point that comes again ---------------------------------------------

def test_a_repeating_rule_is_run_at_every_due_point_each_once():
    book = PayoutBook()
    rule = repeating(expires_at=NOW + 5 + 3 * STEP)       # points 0, 1, 2 lie before the end
    book.install(rule, NOW)
    seen = []
    for clock in range(NOW, NOW + 5 + 4 * STEP):
        if book.has_due(clock, NOW_TS):
            assert book.due(clock, NOW_TS) == [A]
            seen.append((clock, book.state_of(A).due_index))
            book.due_ran(A, clock)
            assert not book.has_due(clock, NOW_TS)        # once
    assert seen == [(NOW + 5, 0), (NOW + 5 + STEP, 1), (NOW + 5 + 2 * STEP, 2)]
    state = book.state_of(A)
    assert state.due_done and state.due_index == 3 and state.next_due(rule) is None
    with pytest.raises(KeyError):
        book.due_ran(A, NOW + 5 + 3 * STEP)


def test_a_point_the_chain_passed_is_not_caught_up():
    book = PayoutBook()
    rule = repeating(expires_at=NOW + 5_000)
    book.install(rule, NOW)
    late = NOW + 5 + 3 * STEP + 40                        # points 1, 2 and 3 went by
    assert book.due(late, NOW_TS) == [A]
    book.due_ran(A, late)
    assert book.state_of(A).due_index == 4
    assert not book.has_due(NOW + 5 + 4 * STEP - 1, NOW_TS)
    assert book.has_due(NOW + 5 + 4 * STEP, NOW_TS)


def test_a_rule_waiting_for_its_last_due_point_outlives_its_end_and_then_goes():
    book = PayoutBook()
    rule = repeating(expires_at=NOW + 5 + STEP + 1)       # points 0 and 1
    book.install(rule, NOW)
    book.due_ran(A, NOW + 5)
    assert book.expire(NOW + 5 + STEP + 9, NOW_TS) == []  # point 1 has not run: kept
    book.due_ran(A, NOW + 5 + STEP + 9)
    assert book.state_of(A).due_done
    assert book.expire(NOW + 5 + STEP + 9, NOW_TS) == [rule]


def test_a_monthly_rule_signed_for_the_31st_runs_on_the_last_day_and_comes_back():
    jan31 = NOW_TS + 30 * DAY                             # NOW_TS is 2026-01-01T00:00:00Z
    rule = terms(**dict(seconds(due_at=jan31, due_months=1), expires_at=NOW_TS + 200 * DAY))
    assert validate_terms_shape(rule, NOW, NOW_TS) is None
    points = [rule.due_point(k) for k in range(5)]
    days = [(p - NOW_TS) // DAY for p in points]
    #        31 Jan, 28 Feb,      31 Mar,           30 Apr,                31 May
    assert days == [30, 31 + 27, 31 + 28 + 30, 31 + 28 + 31 + 29, 31 + 28 + 31 + 30 + 30]
    assert all(p % DAY == 0 for p in points)
    book = PayoutBook()
    book.install(rule, NOW_TS)
    book.due_ran(A, jan31)
    assert book.due(NOW, points[1] - 1) == [] and book.due(NOW, points[1]) == [A]
    book.due_ran(A, points[1])
    assert book.due(NOW, points[2] - 1) == [] and book.due(NOW, points[2]) == [A]


def test_a_copy_of_the_book_has_its_own_queues():
    book = PayoutBook()
    book.install(repeating(), NOW)
    book.install(route(sender_pubkey=C), NOW)
    book.note_sale(C, b"\x01" * 32, B, 50, NOW + 1, NOW_TS)
    clone = copy.deepcopy(book)
    clone.due_ran(A, NOW + 5)
    clone.drop_sale(C, b"\x01" * 32)
    assert book.state_of(A).due_index == 0 and book.due(NOW + 5, NOW_TS) == [A]
    assert book.arrivals() == [(C, b"\x01" * 32)] and clone.arrivals() == []
    assert clone.root() != book.root()


# --- the book: sales that arrive -----------------------------------------------------------

def test_arrivals_take_each_accounts_oldest_sale_first_and_sixteen_a_block():
    book = PayoutBook()
    book.install(route(), NOW)
    book.install(route(sender_pubkey=C, slots=[B]), NOW)
    sales = {A: [], C: []}
    for k in range(MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK + 4):
        account = C if k < MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK + 2 else A   # 18 for C, 2 for A
        sid = bytes([k + 1]) * 32
        assert book.note_sale(account, sid, B, 10 + k, NOW + 1 + k // 8,
                              NOW_TS) == "recorded"
        sales[account].append(sid)
    assert book.has_arrivals()
    turn = book.arrivals()
    # A's two sales came last and are not held up by the eighteen of C
    assert turn[:4] == [(C, sales[C][0]), (A, sales[A][0]), (C, sales[C][1]), (A, sales[A][1])]
    assert turn[4:] == [(C, sid) for sid in sales[C][2:MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK - 2]]
    assert len(turn) == MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK
    for account, sid in turn:
        book.drop_sale(account, sid)
    rest = book.arrivals()
    assert rest == [(C, sid) for sid in sales[C][MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK - 2:]]
    for account, sid in rest:
        _, _, exe = book.arrival_execution(account, sid)
        assert (exe.executor_pubkey, exe.recipients, exe.data, exe.sale_id) == ("", (), (), sid)
        book.record(account, 1, NOW + 9, NOW_TS, sid)     # a paid run closes it as well
    assert not book.has_arrivals() and book.arrivals() == []
    with pytest.raises(KeyError):
        book.drop_sale(A, b"\x01" * 32)


def test_no_sale_of_a_rule_the_node_runs_is_turned_away():
    from consensus.payout import MAX_OPEN_SALES

    book = PayoutBook()
    book.install(route(), NOW)
    book.install(terms(sender_pubkey=C, rule_text=ROUTE, per_sale=True), NOW)
    for k in range(MAX_OPEN_SALES + 6):
        sid = k.to_bytes(32, "big")
        assert book.note_sale(A, sid, B, 5, NOW + 1, NOW_TS) == "recorded"
        assert book.note_sale(C, sid, B, 5, NOW + 1, NOW_TS) == (
            "recorded" if k < MAX_OPEN_SALES else "missed")
    assert len(book.state_of(A).open_sales) == MAX_OPEN_SALES + 6
    assert (book.state_of(A).sales_missed, book.state_of(C).sales_missed) == (0, 6)
    again = PayoutBook.restore(book.store_rows(), *book.resolved_state())
    assert again.root() == book.root() and again._arrivals == {A}
    rows = [row if row[1] != C else row[:16] + ((0, book.state_of(A).open_sales),)
            for row in book.store_rows()]
    with pytest.raises(ValueError, match="impossible sales"):
        PayoutBook.restore(rows, *book.resolved_state())


def test_a_rule_someone_must_execute_has_no_arrivals():
    book = PayoutBook()
    book.install(terms(rule_text=ROUTE, per_sale=True), NOW)
    assert book.note_sale(A, b"\x07" * 32, C, 50, NOW + 1, NOW_TS) == "recorded"
    assert not book.has_arrivals() and book.arrivals() == []
    with pytest.raises(KeyError):
        book.arrival_execution(A, b"\x07" * 32)


def test_a_rule_with_a_sale_waiting_outlives_its_end_and_takes_no_new_sale():
    book = PayoutBook()
    rule = route(expires_at=NOW + 20)
    book.install(rule, NOW)
    assert book.note_sale(A, b"\x01" * 32, C, 50, NOW + 19, NOW_TS) == "recorded"
    assert book.note_sale(A, b"\x02" * 32, C, 50, NOW + 20, NOW_TS) is None     # the end
    assert book.expire(NOW + 20, NOW_TS) == []            # the node owes the first a run
    book.drop_sale(A, b"\x01" * 32)
    assert book.expire(NOW + 20, NOW_TS) == [rule]


def test_replacing_or_revoking_a_rule_takes_its_arrivals_with_it():
    book = PayoutBook()
    book.install(route(), NOW)
    book.note_sale(A, b"\x01" * 32, C, 50, NOW + 1, NOW_TS)
    book.install(terms(), NOW + 2)
    assert not book.has_arrivals()
    book.install(route(sequence_number=2), NOW + 3)
    book.note_sale(A, b"\x02" * 32, C, 50, NOW + 4, NOW_TS)
    book.revoke(A)
    assert not book.has_arrivals()


# --- the book: the seal ---------------------------------------------------------------------

def test_a_sealed_rule_cannot_be_replaced_or_revoked_until_it_ends():
    book = PayoutBook()
    sealed = terms(sealed=True, expires_at=NOW + 30)
    assert book.can_admit_set(sealed, NOW, NOW_TS) == (True, "")
    book.install(sealed, NOW)
    assert book.sealed(A) and not book.sealed(B) and not book.sealed(None)
    assert book.can_admit_set(terms(sequence_number=2), NOW + 1, NOW_TS) == (
        False, "the account's payout rule is sealed until it ends")
    assert book.can_admit_revoke(A) == (
        False, "the account's payout rule is sealed until it ends")
    assert book.expire(NOW + 30, NOW_TS) == [sealed]
    assert not book.sealed(A)
    assert book.can_admit_set(terms(sequence_number=2), NOW + 31, NOW_TS) == (True, "")


def test_a_rule_that_is_not_sealed_is_replaced_and_revoked_as_before():
    book = PayoutBook()
    book.install(repeating(), NOW)
    assert book.can_admit_set(terms(sequence_number=2), NOW + 1, NOW_TS) == (True, "")
    assert book.can_admit_revoke(A) == (True, "")


# --- the round trip -----------------------------------------------------------------------

def _rows_book():
    book = PayoutBook()
    book.install(terms(), NOW)
    book.install(repeating(sender_pubkey=B, slots=[C], sealed=True), NOW)
    book.install(route(sender_pubkey=C), NOW)
    book.install(terms(sender_pubkey=D, due_at=NOW + 900), NOW)
    book.due_ran(B, NOW + 5)
    book.record(B, 9, NOW + 5, NOW_TS + 50)
    book.note_sale(C, b"\x05" * 32, A, 77, NOW + 6, NOW_TS)
    return book


def test_the_rows_carry_the_new_terms_and_restore_them():
    book = _rows_book()
    rows = {row[1]: row for row in book.store_rows()}
    assert len(rows[A]) == 16
    assert rows[B][16:] == (None, (None, NOW + 5, NOW + 5, False, STEP, None, False, True, 1))
    assert rows[C][16:] == ((0, ((b"\x05" * 32, A, 77, NOW + 6),)),
                            (None, None, 0, False, None, None, True, False, 0))
    assert rows[D][16:] == (None, (None, NOW + 900, 0, False))     # as it was stored before
    again = PayoutBook.restore(book.store_rows(), *book.resolved_state())
    assert again.root() == book.root() and again.store_rows() == book.store_rows()
    assert again._due == book._due and again._expiry == book._expiry
    assert again._arrivals == book._arrivals == {C}
    assert again.sealed(B) and again.state_of(B).due_index == 1
    assert again.due(NOW + 5 + STEP, NOW_TS) == [B]


@pytest.mark.parametrize("account, change, why", [
    (B, lambda m: m[:4], "does not match its terms"),
    (D, lambda m: m + (None, None, False, False, 0), "disagree"),
    (D, lambda m: m + (None, None, False, False, 2), "disagree"),
    (B, lambda m: m[:8] + (-1,), "bad clocks"),
    (B, lambda m: m[:4] + ("x",) + m[5:], "bad optional term"),
    (B, lambda m: m[:7] + (2,) + m[8:], "bad switch"),
    (A, lambda m: (None, None, 0, False, None, None, False, False, 3), "disagree"),
    (C, lambda m: m + (0,), "malformed"),
])
def test_a_row_that_does_not_fit_its_rule_refuses_to_load(account, change, why):
    book = _rows_book()
    rows = []
    for row in book.store_rows():
        if row[1] == account:
            row = tuple(row) + (None,) * (18 - len(row))
            row = row[:17] + (change(row[17]),)
        rows.append(row)
    with pytest.raises(ValueError, match=why):
        PayoutBook.restore(rows, *book.resolved_state())


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_database_round_trips_the_new_terms_and_the_miner_reads_them(temp_database):
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
    chain_state._lifecycle_manager = lm
    meta, book = lm.consensus_meta_hash(), lm.payout_rules
    chain_state.commit_state_to_db("head-hash", 60)
    # the hint: a sale waits for its run, whatever the clocks say
    assert db.has_due_payouts(NOW, NOW_TS)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager.payout_rules
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded._due == book._due and reloaded._arrivals == book._arrivals
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta

    reloaded.drop_sale(C, b"\x05" * 32)
    chain_state.commit_state_to_db("head-hash-2", 61)
    assert not db.has_due_payouts(NOW + 5 + STEP - 1, NOW_TS)
    assert db.has_due_payouts(NOW + 5 + STEP, NOW_TS)       # the second due point, not the first


# --- block apply -----------------------------------------------------------------------------

@pytest.fixture
def evs():
    out = {}
    for pool in ("apply", "payout_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    pay = out["payout_apply"]
    pay.set_outputs(STANDING_BODY, lambda i: {"o30": "100" if i.get("i13") == "0" else "0"})
    pay.set_outputs(ROUTE_BODY, lambda i: {"o30": str(int(i.get("i27", "0")) // 5)})
    pay.set_outputs(HALF_BODY, lambda i: {"o30": str(int(i.get("i27", "0")) // 2)})
    pay.set_outputs(payout_rule_body("always ( o30[t]:bv[24] = i40[t]:bv[24] )."),
                    lambda i: {"o30": i.get("i40", "0")})
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


def _bal(**over):
    return dict({ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0}, **over)


def _standing(fee=0, balances=None, **kw):
    kw.setdefault("due_at", HEIGHT + 5)
    kw.setdefault("due_every", STEP)
    kw.setdefault("expires_at", HEIGHT + 5 + 10 * STEP)
    ch = Chain(balances or _bal(), fee=fee)
    tx = set_tx(rule=STANDING, cap_exec=100, cap_period=100, **kw)
    ch.block([tx])
    assert ch.lm.payout_rules.get(ALICE) is not None, _reason(ch.last, tx)
    return ch, tx


def _outcomes(ch):
    return [e["outcome"] for e in _events(ch)]


def test_a_standing_payment_as_a_rule_pays_once_at_each_due_point_and_nobody_pays_a_fee(evs):
    ch, tx = _standing(fee=7)
    assert (ch.bal[ALICE], ch.bal[PROPOSER]) == (993, 7)   # the one fee: the install's
    ch.block([], height=HEIGHT + 4, ts=TS + 4)
    assert _events(ch) == []
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert _events(ch) == [{
        "account_pubkey": ALICE, "rule_id": rid(tx), "due_at": HEIGHT + 5, "due_index": 0,
        "outcome": "executed", "executor_pubkey": None, "total": 100,
        "legs": [{"slot": 0, "recipient_pubkey": BOB, "amount": 100}]}]
    ch.block([], height=HEIGHT + 6, ts=TS + 6)
    assert _events(ch) == []                               # once in this period
    ch.block([], height=HEIGHT + 4 + STEP, ts=TS + 7)
    assert _events(ch) == []                               # not before the next point
    ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 8)
    assert [(e["due_at"], e["due_index"], e["total"]) for e in _events(ch)] == [
        (HEIGHT + 5 + STEP, 1, 100)]
    assert (ch.bal[ALICE], ch.bal[BOB], ch.bal[PROPOSER]) == (793, 200, 7)
    assert ch.seq == {ALICE: 1}                            # nobody signed for a run
    assert [i["i13"] for _, i in evs["payout_apply"].output_calls] == ["0", "0"]


def test_nobody_can_execute_the_standing_rule_for_more_or_at_another_time(evs):
    ch, tx = _standing()
    early = exec_tx(rule_id=rid(tx), data={"0": 100})
    ch.block([early], height=HEIGHT + 2, ts=TS + 2)
    assert _reason(ch.last, early) == "payout_not_executed"
    assert (ch.bal[ALICE], ch.bal[BOB]) == (1_000, 0)


def test_an_unfunded_due_point_pays_nothing_owes_nothing_and_the_next_one_pays(evs):
    ch, tx = _standing(balances=_bal(**{ALICE: 60}))
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    event, = _events(ch)
    assert event["outcome"] == "due_not_paid" and "holds 60" in event["reason"]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (60, 0)         # no part payment, no debt
    state = ch.lm.payout_rules.state_of(ALICE)
    assert (state.executions, state.paid_total, state.due_index) == (0, 0, 1)
    ch.block([spend_tx(CAROL, ALICE, 200, 0)], height=HEIGHT + 6, ts=TS + 6)
    assert _events(ch) == []                               # funded later: nothing is made up
    ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 7)
    assert _outcomes(ch) == ["executed"]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (160, 100)


def test_due_points_the_chain_slept_through_are_not_paid_later(evs):
    ch, tx = _standing()
    ch.block([], height=HEIGHT + 5 + 3 * STEP + 9, ts=TS + 5)
    assert [(e["due_index"], e["total"]) for e in _events(ch)] == [(0, 100)]
    ch.block([], height=HEIGHT + 5 + 3 * STEP + 10, ts=TS + 6)
    assert _events(ch) == []
    assert ch.lm.payout_rules.state_of(ALICE).due_index == 4
    ch.block([], height=HEIGHT + 5 + 4 * STEP, ts=TS + 7)
    assert [(e["due_index"], e["total"]) for e in _events(ch)] == [(4, 100)]
    assert ch.bal[BOB] == 200


def test_revoking_the_rule_stops_every_later_run_and_a_revoke_wins_in_its_block(evs):
    ch, tx = _standing()
    ch.block([revoke_tx()], height=HEIGHT + 5, ts=TS + 5)
    assert _outcomes(ch) == ["revoked"]
    ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 6)
    assert _events(ch) == [] and (ch.bal[ALICE], ch.bal[BOB]) == (1_000, 0)


def test_the_last_due_point_runs_and_then_the_rule_ends(evs):
    ch, tx = _standing(expires_at=HEIGHT + 5 + STEP + 1)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    ch.block([], height=HEIGHT + 5 + STEP + 3, ts=TS + 6)  # past the end, point 1 still owed
    assert _outcomes(ch) == ["executed", "expired"]
    assert ch.lm.payout_rules.get(ALICE) is None and ch.bal[BOB] == 200


def test_a_monthly_rule_on_the_31st_pays_on_the_last_day_of_february(evs):
    jan31 = TS + 30 * DAY
    ch = Chain(_bal())
    tx = set_tx(rule=STANDING, cap_exec=100, cap_period=100, clock="period_seconds",
                period=DAY, expires_at=TS + 200 * DAY, due_at=jan31, due_months=1)
    ch.block([tx])
    assert ch.lm.payout_rules.get(ALICE) is not None, _reason(ch.last, tx)
    paid = []
    for n, day in enumerate([29, 30, 31, 57, 58, 59, 88, 89, 118, 119]):
        ch.block([], height=HEIGHT + 1 + n, ts=TS + day * DAY)
        paid.append((day, sum(e.get("total", 0) for e in _events(ch))))
    #           31 Jan     28 Feb                31 Mar     30 Apr
    assert paid == [(29, 0), (30, 100), (31, 0), (57, 0), (58, 100), (59, 0),
                    (88, 0), (89, 100), (118, 0), (119, 100)]
    assert ch.bal[BOB] == 400


def test_replay_without_an_evaluator_marks_the_due_point_and_moves_nothing(evs):
    ch, tx = _standing()
    sender_policy.set_evaluator("payout_apply", None)
    ch.block([], height=HEIGHT + 5, ts=TS + 5, replay=True)
    assert _outcomes(ch) == ["due_not_paid"]
    assert ch.lm.payout_rules.state_of(ALICE).due_index == 1 and ch.bal[BOB] == 0


def test_the_same_blocks_give_the_same_state_and_a_run_moves_the_hash(evs):
    def run(with_rule):
        ch = Chain(_bal())
        ch.block([set_tx(rule=STANDING, cap_exec=100, cap_period=100, due_at=HEIGHT + 5,
                         due_every=STEP, expires_at=HEIGHT + 5 + 10 * STEP)]
                 if with_rule else [])
        ch.block([], height=HEIGHT + 5, ts=TS + 5)
        ch.block([], height=HEIGHT + 5 + STEP, ts=TS + 6)
        return ch.hashes

    one, two, none = run(True), run(True), run(False)
    assert one == two and len(set(one)) == 3 and one[1] != none[1]


# --- block apply: a payment arrives ------------------------------------------------------------

def _routed(fee=0, balances=None, **kw):
    ch = Chain(balances or _bal(), fee=fee)
    tx = set_tx(rule=ROUTE, per_sale=True, on_arrival=True, cap_exec=1_000,
                cap_period=10_000, **kw)
    ch.block([tx])
    assert ch.lm.payout_rules.get(ALICE) is not None, _reason(ch.last, tx)
    return ch, tx


def test_101_routed_at_a_fifth_gives_20_and_81_and_the_payer_pays_its_one_fee(evs):
    ch, tx = _routed(fee=3)
    assert (ch.bal[ALICE], ch.bal[PROPOSER]) == (997, 3)
    buy = spend_tx(CAROL, ALICE, 101, 0)
    ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
    assert _events(ch) == [{
        "account_pubkey": ALICE, "rule_id": rid(tx), "sale_id": _sale_id(buy),
        "sale_amount": 101, "payer_pubkey": CAROL,
        "outcome": "executed", "executor_pubkey": None, "total": 20,
        "legs": [{"slot": 0, "recipient_pubkey": BOB, "amount": 20}]}]
    assert ch.bal[BOB] == 20 and ch.bal[ALICE] == 997 + 81
    assert ch.bal[CAROL] == 500 - 101 - 3 and ch.bal[PROPOSER] == 6
    assert ch.seq == {ALICE: 1, CAROL: 1}                  # nobody signed for the run
    assert ch.lm.payout_rules.state_of(ALICE).open_sales == ()
    (body, inputs), = evs["payout_apply"].output_calls
    assert body == ROUTE_BODY and inputs["i13"] == "0"
    assert inputs["i27"] == "101" and inputs["i28"] == "#x" + CAROL


def test_each_payment_is_routed_on_its_own_and_once(evs):
    ch, tx = _routed()
    first, second = spend_tx(CAROL, ALICE, 101, 0), spend_tx(CAROL, ALICE, 9, 1)
    ch.block([first, second], height=HEIGHT + 1, ts=TS + 1)
    assert [e["total"] for e in _events(ch)] == [20, 1]    # 101 // 5 and 9 // 5, not 110 // 5
    assert ch.bal[BOB] == 21
    again = exec_tx(BOB, 0, rule_id=rid(tx))
    again["sale_id"] = _sale_id(first)
    again.pop("signature")
    ch.block([_sign(again, SKS[BOB])], height=HEIGHT + 2, ts=TS + 2)
    assert _reason(ch.last, again) == "payout_not_executed" and ch.bal[BOB] == 21


def test_a_routed_share_is_never_routed_again(evs):
    ch, tx = _routed()
    onward = set_tx(BOB, 0, rule=HALF, per_sale=True, on_arrival=True, slots=[CAROL],
                    cap_exec=1_000, cap_period=10_000)
    ch.block([onward], height=HEIGHT + 1, ts=TS + 1)
    assert ch.lm.payout_rules.get(BOB) is not None, _reason(ch.last, onward)
    ch.block([spend_tx(CAROL, ALICE, 101, 0)], height=HEIGHT + 2, ts=TS + 2)
    assert [(e["account_pubkey"], e["total"]) for e in _events(ch)] == [(ALICE, 20)]
    assert ch.bal[BOB] == 20                               # the share stays whole
    assert ch.lm.payout_rules.state_of(BOB).open_sales == ()
    # a payment someone signs to BOB is a sale of BOB's rule, and is shared
    ch.block([spend_tx(CAROL, BOB, 10, 1)], height=HEIGHT + 3, ts=TS + 3)
    assert [(e["account_pubkey"], e["total"]) for e in _events(ch)] == [(BOB, 5)]


def test_a_payment_too_small_to_share_is_closed_unpaid(evs):
    ch, tx = _routed()
    buy = spend_tx(CAROL, ALICE, 4, 0)
    ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
    event, = _events(ch)
    assert event["outcome"] == "arrival_not_paid" and event["sale_id"] == _sale_id(buy)
    assert "pays nothing" in event["reason"]
    assert (ch.bal[ALICE], ch.bal[BOB]) == (1_004, 0)
    assert ch.lm.payout_rules.state_of(ALICE).open_sales == ()


def test_seventeen_payments_in_one_block_take_two_blocks(evs):
    ch, tx = _routed()
    buys = [spend_tx(CAROL, ALICE, 10, k) for k in range(MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK + 1)]
    ch.block(buys, height=HEIGHT + 1, ts=TS + 1)
    assert [e["sale_id"] for e in _events(ch)] == [
        _sale_id(b) for b in buys[:MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK]]
    assert ch.bal[BOB] == 2 * MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK
    assert len(ch.lm.payout_rules.state_of(ALICE).open_sales) == 1
    ch.block([], height=HEIGHT + 2, ts=TS + 2)
    assert [e["sale_id"] for e in _events(ch)] == [_sale_id(buys[-1])]
    assert ch.bal[BOB] == 2 * (MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK + 1)
    assert not ch.lm.payout_rules.has_arrivals()


def test_a_payment_in_the_block_that_reaches_the_end_is_not_routed(evs):
    ch, tx = _routed(expires_at=HEIGHT + 3)
    ch.block([spend_tx(CAROL, ALICE, 50, 0)], height=HEIGHT + 2, ts=TS + 2)
    assert [e["total"] for e in _events(ch)] == [10]
    ch.block([spend_tx(CAROL, ALICE, 50, 1)], height=HEIGHT + 3, ts=TS + 3)
    assert _outcomes(ch) == ["expired"]
    assert ch.bal[BOB] == 10 and ch.lm.payout_rules.get(ALICE) is None


def test_the_owner_need_not_be_online_and_replay_gives_the_same_state(evs):
    def run():
        ch, tx = _routed()
        ch.block([spend_tx(CAROL, ALICE, 101, 0)], height=HEIGHT + 1, ts=TS + 1)
        ch.block([spend_tx(CAROL, ALICE, 55, 1)], height=HEIGHT + 2, ts=TS + 2)
        return ch

    one, two = run(), run()
    assert one.hashes == two.hashes and one.bal == two.bal and one.bal[BOB] == 31
    assert one.seq == {ALICE: 1, CAROL: 2}


# --- block apply: the seal -----------------------------------------------------------------

SPEND = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."


def _sealed(fee=0, **kw):
    kw.setdefault("expires_at", HEIGHT + 30)
    ch = Chain(_bal(), fee=fee)
    tx = set_tx(rule=SPEND, sealed=True, cap_exec=400, cap_period=400, **kw)
    ch.block([tx])
    assert ch.lm.payout_rules.sealed(ALICE), _reason(ch.last, tx)
    return ch, tx


def test_a_sealed_account_signs_nothing_and_pays_no_fee_for_trying(evs):
    ch, tx = _sealed(fee=5)
    before = dict(ch.bal)
    tries = [spend_tx(ALICE, CAROL, 900, 1), revoke_tx(ALICE, 1),
             set_tx(ALICE, 1, rule=SPEND, slots=[CAROL], cap_exec=1_000, cap_period=1_000),
             create_tx(ALICE, CAROL, 900, 1, first_due=HEIGHT + 3)]
    for n, attempt in enumerate(tries):
        result = ch.block([attempt], height=HEIGHT + 1 + n, ts=TS + 1 + n)
        assert _reason(result, attempt) == "account_sealed"
        assert _events(ch) == [] and ch.bal == before and ch.seq == {ALICE: 1}
    assert ch.lm.payout_rules.get(ALICE).rule_id.hex() == rid(tx)
    assert not ch.lm.standing_payments.terms


def test_money_leaves_a_sealed_account_by_its_rule_and_money_still_comes_in(evs):
    ch, tx = _sealed()
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 300})], height=HEIGHT + 1, ts=TS + 1)
    assert _outcomes(ch) == ["executed"] and (ch.bal[ALICE], ch.bal[BOB]) == (700, 300)
    ch.block([spend_tx(BOB, ALICE, 50, 0)], height=HEIGHT + 2, ts=TS + 2)
    assert (ch.bal[ALICE], ch.bal[BOB]) == (750, 250)


def test_the_seal_ends_with_the_rule_and_the_key_holds_the_account_again(evs):
    ch, tx = _sealed(expires_at=HEIGHT + 3)
    locked = spend_tx(ALICE, CAROL, 10, 1)
    result = ch.block([locked], height=HEIGHT + 2, ts=TS + 2)
    assert _reason(result, locked) == "account_sealed"
    ch.block([], height=HEIGHT + 3, ts=TS + 3)
    assert _outcomes(ch) == ["expired"] and not ch.lm.payout_rules.sealed(ALICE)
    ch.block([spend_tx(ALICE, CAROL, 10, 1)], height=HEIGHT + 4, ts=TS + 4)
    assert (ch.bal[ALICE], ch.bal[CAROL]) == (990, 510)


def test_a_seal_set_in_a_block_holds_for_the_rest_of_that_block(evs):
    ch = Chain(_bal())
    seal = set_tx(rule=SPEND, sealed=True, cap_exec=400, cap_period=400)
    after = spend_tx(ALICE, CAROL, 900, 1)
    result = ch.block([seal, after])
    assert ch.lm.payout_rules.sealed(ALICE) and _reason(result, after) == "account_sealed"
    assert ch.bal[ALICE] == 1_000 and ch.seq == {ALICE: 1}


def test_a_standing_payment_signed_before_the_seal_pays_nothing_while_it_holds(evs):
    ch = Chain(_bal())
    order = create_tx(ALICE, CAROL, 900, 0, first_due=HEIGHT + 5, interval=EVERY, periods=2)
    ch.block([order])
    assert ch.lm.standing_payments.terms
    seal = set_tx(ALICE, 1, rule=SPEND, sealed=True, cap_exec=400, cap_period=400,
                  expires_at=HEIGHT + 6)
    ch.block([seal], height=HEIGHT + 1, ts=TS + 1)
    assert ch.lm.payout_rules.sealed(ALICE), _reason(ch.last, seal)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert [o for o, _ in ch.outcomes()] == ["missed"]     # blocked, as a clause blocks one
    assert (ch.bal[ALICE], ch.bal[CAROL]) == (1_000, 500)
    ch.block([], height=HEIGHT + 6, ts=TS + 6)             # the seal ends with the rule
    assert not ch.lm.payout_rules.sealed(ALICE)
    ch.block([], height=HEIGHT + 5 + EVERY, ts=TS + 7)
    assert [o for o, _ in ch.outcomes()] == ["paid", "ended"]
    assert (ch.bal[ALICE], ch.bal[CAROL]) == (100, 1_400)


def test_sealing_ends_the_transfers_the_account_had_parked(evs, monkeypatch):
    ended = []
    real = ApprovalRequestLifecycleManager.resolve_all_for_sender

    def spy(self, pubkey, status):
        ended.append((pubkey, status))
        return real(self, pubkey, status)

    monkeypatch.setattr(ApprovalRequestLifecycleManager, "resolve_all_for_sender", spy)
    ch = Chain(_bal())
    ch.block([set_tx(rule=SPEND, cap_exec=400, cap_period=400)])
    assert ended == []                                     # a rule that is not sealed: nothing
    from consensus.approvals import STATUS_FAILED
    ch.block([set_tx(BOB, 0, rule=SPEND, sealed=True, slots=[CAROL], cap_exec=4,
                     cap_period=4)], height=HEIGHT + 1, ts=TS + 1)
    assert ended == [(BOB, STATUS_FAILED)]


def test_a_sealed_grant_pays_the_grantee_and_returns_the_rest_without_the_key(evs):
    """The money sits in an account of its own. Its rule pays what BOB asks for,
    up to the cap, and at the due point the node sends what is left to CAROL, who
    funded it. Between install and end the account's own key can do nothing."""
    grant = ("always ( (i13[t]:bv[384] = { 0 }:bv[384]) "
             "? ((o30[t]:bv[24] = { 0 }:bv[24]) && (o31[t]:bv[24] = i2[t]:bv[24])) "
             ": ((o30[t]:bv[24] = i40[t]:bv[24]) && (o31[t]:bv[24] = { 0 }:bv[24])) ).")

    def script(i):
        if i.get("i13") == "0":
            return {"o30": "0", "o31": i["i2"]}
        return {"o30": i.get("i40", "0"), "o31": "0"}

    evs["payout_apply"].set_outputs(payout_rule_body(grant), script)
    ch = Chain(_bal())
    tx = set_tx(rule=grant, slots=[BOB, CAROL], sealed=True, cap_exec=1_000, cap_period=1_000,
                due_at=HEIGHT + 10, expires_at=HEIGHT + 11)
    ch.block([tx])
    assert ch.lm.payout_rules.sealed(ALICE), _reason(ch.last, tx)
    ch.block([exec_tx(BOB, 0, rule_id=rid(tx), data={"0": 300})], height=HEIGHT + 2, ts=TS + 2)
    assert (ch.bal[ALICE], ch.bal[BOB]) == (700, 300)
    grab = spend_tx(ALICE, BOB, 700, 1)
    result = ch.block([grab], height=HEIGHT + 3, ts=TS + 3)
    assert _reason(result, grab) == "account_sealed" and ch.bal[ALICE] == 700
    ch.block([], height=HEIGHT + 10, ts=TS + 10)
    assert [(e["outcome"], e["total"]) for e in _events(ch)] == [("executed", 700)]
    assert (ch.bal[ALICE], ch.bal[BOB], ch.bal[CAROL]) == (0, 300, 1_200)
    ch.block([], height=HEIGHT + 11, ts=TS + 11)
    assert _outcomes(ch) == ["expired"] and not ch.lm.payout_rules.sealed(ALICE)


# --- admission -------------------------------------------------------------------------------

from tests.test_payout_integration import (  # noqa: E402,F401  (fixtures)
    A as ADM_A, NEXT_HEIGHT as ADM_HEIGHT, book, evaluator, revoke, rule_set, tip_view,
)


def test_admission_steps_a_rule_run_on_arrival_once_on_a_sale_of_the_cap(tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    evaluator.set_outputs(ROUTE_BODY, lambda i: {"o30": str(int(i["i27"]) // 5)})
    tx = rule_set(rule_text=ROUTE, per_sale=True, on_arrival=True)
    result = validate_payout_rule_set_payload(tx, tip_view)
    assert result.is_valid, result.error
    assert result.data["on_arrival"] is True and "sealed" not in result.data
    (body, inputs), = evaluator.output_calls
    assert body == ROUTE_BODY and inputs["i13"] == "0"
    assert inputs["i27"] == "100"                           # the cap per execution
    assert inputs["i6"] == str(ADM_HEIGHT)


def test_admission_does_not_step_a_per_sale_rule_someone_must_execute(tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    assert validate_payout_rule_set_payload(
        rule_set(rule_text=ROUTE, per_sale=True), tip_view).is_valid
    assert evaluator.output_calls == []


def test_admission_reports_the_repeat_and_the_seal(tip_view, evaluator):
    from consensus.admission import validate_payout_rule_set_payload

    result = validate_payout_rule_set_payload(
        rule_set(due_at=ADM_HEIGHT + 50, due_every=STEP, sealed=True), tip_view)
    assert result.is_valid, result.error
    assert (result.data["due_every"], result.data["sealed"]) == (STEP, True)
    assert "due_months" not in result.data and "on_arrival" not in result.data


@pytest.mark.parametrize("build", [
    lambda: revoke(),
    lambda: rule_set(sequence_number=2),
    lambda: {"tx_type": "user_tx", "sender_pubkey": ADM_A, "sequence_number": 2,
             "expiration_time": 9_999_999_999, "expire_at_height": ADM_HEIGHT + 5,
             "fee_limit": "10", "operations": {"1": [[ADM_A, B, 5]]}},
])
def test_admission_takes_nothing_a_sealed_account_signs(tip_view, book, build):
    from consensus.admission import validate_mempool_admission

    book.install(parse_payout_rule_set(rule_set(sealed=True)), ADM_HEIGHT - 1)
    result = validate_mempool_admission(build(), tip_view)
    assert not result.is_valid and "sealed" in result.error
    assert result.code == "ACCOUNT_SEALED"


def test_admission_takes_what_others_sign_for_a_sealed_account(tip_view, book, evaluator):
    from consensus.admission import validate_mempool_admission
    from tests.test_payout_integration import execute

    sealed = parse_payout_rule_set(rule_set(sealed=True))
    book.install(sealed, ADM_HEIGHT - 1)
    result = validate_mempool_admission(execute(sealed.rule_id.hex()), tip_view)
    assert result.is_valid, result.error
