"""Payout rules that pay per sale (#63): a royalty is owed once per sale, and the
sale's amount is the chain's record, never the claimant's word.

A rule installed with `per_sale: true` pays only against sales the chain
recorded itself: every signed transfer into the account while the rule is
installed. An execution names one open sale; the rule reads its amount (i27)
and payer (i28); a paid execution closes it, so the same sale is paid once.

Block apply runs through the real `apply_block` (scripted interpreter, mock
policy evaluators), against the same balance oracle as tests/test_payout_apply.py.
"""
import pytest

import chain_state
from block import compute_tx_hash
from consensus.payout import (
    MAX_OPEN_SALES,
    PayoutBook,
    PayoutRefused,
    PayoutShapeError,
    abi_width,
    parse_payout_execute,
    parse_payout_rule_set,
    payout_rule_body,
    payout_spec_text,
    parse_payout_spec,
    screen_payout_body,
)
from consensus.tx_signing import signing_message_bytes

from tests.test_payout_apply import _events, _executed, _reason, evs, exec_tx, set_tx  # noqa: F401
from tests.test_standing_apply import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _sign, spend_tx,
)
from tests import test_payout_integration as integ

# A 5% royalty on each sale, paid to the creator in slot 0.
# 5% is a twentieth; dividing only, the amount can never wrap at bv[24]
ROYALTY = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] )."
ROYALTY_BODY = payout_rule_body(ROYALTY)


def _royalty(inputs):
    return {"o30": str(int(inputs.get("i27", "0")) // 20)}


@pytest.fixture
def royalty(evs):
    evs["payout_apply"].set_outputs(ROYALTY_BODY, _royalty)
    return evs


def _bal():
    return {ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0}


def _store(**kw):
    """ALICE sells; BOB, the creator, is owed 5% of every sale."""
    ch, oracle = Chain(_bal()), Oracle(_bal())
    terms = dict(cap_exec=100, cap_period=1_000)
    terms.update(kw)
    tx = set_tx(rule=ROYALTY, per_sale=True, **terms)
    ch.block([tx])
    oracle.create(tx, fee=0)
    assert ch.lm.payout_rules.get(ALICE).per_sale, _reason(ch.last, tx)
    return ch, oracle, tx


def _sale_id(tx) -> str:
    return compute_tx_hash({k: v for k, v in tx.items() if k != "tx_id"})


def _sell(ch, oracle, amount=101, seq=0, height=HEIGHT + 1, buyer=CAROL):
    buy = spend_tx(buyer, ALICE, amount, seq)
    ch.block([buy], height=height, ts=TS + height - HEIGHT)
    oracle.spend(buyer, ALICE, amount, ts=TS + height - HEIGHT)
    return buy


def _pay(rule_tx, sale, seq=0, executor=BOB, **kw):
    tx = exec_tx(executor=executor, seq=seq, rule_id=parse_payout_rule_set(rule_tx).rule_id.hex(),
                 **kw)
    if sale is not None:
        tx = dict(tx, sale_id=sale)
        tx.pop("signature")
        tx = _sign(tx, SKS[executor])
    return tx


# --- block apply -------------------------------------------------------------------

def test_a_signed_transfer_into_the_account_is_recorded_as_a_sale(royalty):
    ch, oracle, _rule = _store()
    buy = _sell(ch, oracle)
    oracle.check(ch)
    state = ch.lm.payout_rules.state_of(ALICE)
    assert state.open_sales == ((bytes.fromhex(_sale_id(buy)), CAROL, 101, HEIGHT + 1),)
    assert any("Sale recorded" in line for o in ch.last.outcomes for line in o.receipt_logs)


def test_a_5_percent_royalty_on_101_pays_5_once(royalty):
    """gmikeyg's case on #34: a 5% royalty on 101 pays 5, once."""
    ch, oracle, rule = _store()
    sale = _sale_id(_sell(ch, oracle))

    first = _pay(rule, sale)
    ch.block([first], height=HEIGHT + 2, ts=TS + 2)
    _executed(oracle, executor=BOB, legs=[(BOB, 5)], ts=TS + 2)
    oracle.check(ch)
    event = _events(ch)[0]
    assert event["outcome"] == "executed" and event["total"] == 5
    assert event["sale_id"] == sale
    state = ch.lm.payout_rules.state_of(ALICE)
    assert state.open_sales == () and state.paid_total == 5

    # the same sale again: refused, not included, nothing moves
    again = _pay(rule, sale, seq=1)
    result = ch.block([again], height=HEIGHT + 3, ts=TS + 3)
    assert _reason(result, again) == "payout_not_executed"
    assert any("not an open sale" in line for o in result.outcomes for line in o.receipt_logs)
    oracle.check(ch)
    assert ch.lm.payout_rules.state_of(ALICE).paid_total == 5


def test_the_rule_reads_the_sale_amount_and_payer(royalty):
    ch, oracle, rule = _store()
    sale = _sale_id(_sell(ch, oracle, amount=240))
    ch.block([_pay(rule, sale)], height=HEIGHT + 2, ts=TS + 2)
    (_body, inputs), = royalty["payout_apply"].output_calls
    assert inputs["i27"] == "240" and inputs["i28"] == "#x" + CAROL
    _executed(oracle, executor=BOB, legs=[(BOB, 12)], ts=TS + 2)
    oracle.check(ch)


def test_each_sale_is_paid_on_its_own(royalty):
    ch, oracle, rule = _store()
    one = _sale_id(_sell(ch, oracle, amount=101, seq=0, height=HEIGHT + 1))
    two = _sale_id(_sell(ch, oracle, amount=300, seq=1, height=HEIGHT + 2))
    ch.block([_pay(rule, two), _pay(rule, one, seq=1)], height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, executor=BOB, legs=[(BOB, 15)], ts=TS + 3)
    _executed(oracle, executor=BOB, legs=[(BOB, 5)], ts=TS + 3)
    oracle.check(ch)
    assert ch.lm.payout_rules.state_of(ALICE).open_sales == ()


def test_two_legs_of_one_transaction_are_one_sale(royalty):
    ch, oracle, rule = _store()
    buy = _sign({"tx_id": "two-legs", "tx_type": "user_tx", "sender_pubkey": CAROL,
                 "sequence_number": 0, "expiration_time": 9_999_999_999,
                 "expire_at_height": 1000, "fee_limit": "100",
                 "operations": {"1": [[CAROL, ALICE, 60], [CAROL, ALICE, 41]]}}, SKS[CAROL])
    ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
    oracle.spend(CAROL, ALICE, 101, ts=TS + 1)
    oracle.check(ch)
    (sale,) = ch.lm.payout_rules.state_of(ALICE).open_sales
    assert sale[0].hex() == _sale_id(buy) and sale[2] == 101


def test_a_per_sale_rule_pays_only_a_recorded_sale(royalty):
    ch, oracle, rule = _store()
    _sell(ch, oracle)
    for sale, why in ((None, "name an open sale"), ("ab" * 32, "not an open sale")):
        tx = _pay(rule, sale)
        result = ch.block([tx], height=HEIGHT + 2, ts=TS + 2)
        assert _reason(result, tx) == "payout_not_executed"
        assert any(why in line for o in result.outcomes for line in o.receipt_logs), why
    oracle.check(ch)


def test_a_refused_execution_leaves_the_sale_open(royalty):
    ch, oracle, rule = _store(cap_exec=4, cap_period=4)
    sale = _sale_id(_sell(ch, oracle))
    tx = _pay(rule, sale)                    # 5 is over the cap per execution of 4
    result = ch.block([tx], height=HEIGHT + 2, ts=TS + 2)
    assert _reason(result, tx) == "payout_not_executed"
    assert ch.lm.payout_rules.state_of(ALICE).sale(bytes.fromhex(sale)) is not None
    oracle.check(ch)


def test_a_rule_without_per_sale_refuses_a_sale_id(evs):
    ch, oracle = Chain(_bal()), Oracle(_bal())
    rule = set_tx()
    ch.block([rule])
    oracle.create(rule, fee=0)
    buy = _sell(ch, oracle)
    assert ch.lm.payout_rules.state_of(ALICE).open_sales == ()     # no sale recorded
    tx = _pay(rule, _sale_id(buy), data={"0": 5})
    result = ch.block([tx], height=HEIGHT + 2, ts=TS + 2)
    assert _reason(result, tx) == "payout_not_executed"
    assert any("does not pay per sale" in line for o in result.outcomes
               for line in o.receipt_logs)
    oracle.check(ch)


def test_a_transfer_before_the_rule_or_from_the_account_itself_is_no_sale(royalty):
    ch, oracle = Chain(_bal()), Oracle(_bal())
    _sell(ch, oracle, height=HEIGHT)                      # before any rule
    rule = set_tx(rule=ROYALTY, per_sale=True, cap_exec=100, cap_period=1_000)
    ch.block([rule], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(rule, fee=0)
    assert ch.lm.payout_rules.state_of(ALICE).open_sales == ()


def test_sales_move_the_state_hash_and_the_same_blocks_agree(royalty):
    runs = []
    for _ in range(2):
        ch, oracle, rule = _store()
        before = ch.hashes[-1]
        buy = spend_tx(CAROL, ALICE, 101, 0)
        ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
        assert ch.hashes[-1] != before
        ch.block([_pay(rule, _sale_id(buy))], height=HEIGHT + 2, ts=TS + 2)
        runs.append([h for h in ch.hashes])
    assert runs[0] == runs[1]


def test_a_block_does_not_touch_its_parents_sales(royalty):
    ch, oracle, rule = _store()
    parent = ch.lm.payout_rules
    _sell(ch, oracle)
    assert parent.state_of(ALICE).open_sales == ()
    assert ch.lm.payout_rules.state_of(ALICE).open_sales != ()


# --- the book ------------------------------------------------------------------------

def _terms(per_sale=True, account=integ.A):
    return parse_payout_rule_set(integ.rule_set(
        sender_pubkey=account, rule_text=ROYALTY if per_sale else integ.RULE,
        **({"per_sale": True} if per_sale else {})))


def test_per_sale_gives_another_rule_id_and_only_true_is_accepted():
    with_sales, without = _terms(), parse_payout_rule_set(integ.rule_set())
    plain = parse_payout_rule_set(integ.rule_set(rule_text=ROYALTY))
    assert with_sales.per_sale and not plain.per_sale
    assert with_sales.rule_id != plain.rule_id and without.rule_id != plain.rule_id
    with pytest.raises(PayoutShapeError, match="per_sale"):
        parse_payout_rule_set(integ.rule_set(per_sale=False))
    with pytest.raises(PayoutShapeError, match="per_sale"):
        parse_payout_rule_set(integ.rule_set(per_sale=1))


def test_only_a_per_sale_rule_reads_the_sale():
    assert abi_width("i27") is None and abi_width("i28") is None
    assert abi_width("i27", per_sale=True) == 24 and abi_width("i28", per_sale=True) == 384
    assert "per_sale" in screen_payout_body(ROYALTY_BODY, 1)
    assert screen_payout_body(ROYALTY_BODY, 1, per_sale=True) is None


def test_per_sale_and_the_sale_are_signed():
    rule, plain = integ.rule_set(per_sale=True), integ.rule_set()
    assert signing_message_bytes(rule) != signing_message_bytes(plain)
    base = integ.execute("00" * 32)
    named = integ.execute("00" * 32, sale_id="ab" * 32)
    other = integ.execute("00" * 32, sale_id="cd" * 32)
    assert len({signing_message_bytes(t) for t in (base, named, other)}) == 3


def test_a_rule_change_request_carries_per_sale():
    fields = integ.rule_set(rule_text=ROYALTY, per_sale=True)
    text = payout_spec_text(fields, 4)
    assert parse_payout_spec(text, integ.A).per_sale


def test_malformed_sale_ids_are_refused():
    for bad in ("AB" * 32, "ab" * 31, 7, ""):
        with pytest.raises(PayoutShapeError, match="sale_id"):
            parse_payout_execute(integ.execute("00" * 32, sale_id=bad))
    assert parse_payout_execute(integ.execute("00" * 32, sale_id="ab" * 32)).sale_id == \
        bytes.fromhex("ab" * 32)


def test_open_sales_are_bounded_and_the_rest_are_counted_missed():
    book = PayoutBook()
    book.install(_terms(), 10)
    for n in range(MAX_OPEN_SALES):
        assert book.note_sale(integ.A, n.to_bytes(32, "big"), integ.C, 10, 11) == "recorded"
    assert book.note_sale(integ.A, b"\xff" * 32, integ.C, 10, 12) == "missed"
    state = book.state_of(integ.A)
    assert len(state.open_sales) == MAX_OPEN_SALES and state.sales_missed == 1
    # the same id twice, the account paying itself and an account without a
    # per-sale rule record nothing
    assert book.note_sale(integ.A, (0).to_bytes(32, "big"), integ.C, 10, 12) is None
    assert book.note_sale(integ.A, b"\x01" * 32, integ.A, 10, 12) is None
    assert book.note_sale(integ.B, b"\x01" * 32, integ.C, 10, 12) is None


def test_a_paid_sale_closes_and_the_root_follows_the_sales():
    book = PayoutBook()
    terms = _terms()
    book.install(terms, 10)
    empty = book.root()
    book.note_sale(integ.A, b"\x07" * 32, integ.C, 101, 11)
    recorded = book.root()
    assert recorded != empty
    exe = parse_payout_execute(integ.execute(terms.rule_id.hex(), sale_id="07" * 32))
    _, state = book.check_execution(exe, 12, 0)
    assert state.sale(b"\x07" * 32)[2] == 101
    book.record(integ.A, 5, 12, 0, b"\x07" * 32)
    assert book.state_of(integ.A).open_sales == ()
    with pytest.raises(PayoutRefused, match="not an open sale"):
        book.check_execution(exe, 13, 0)
    assert book.root() not in (empty, recorded)


def test_restore_refuses_impossible_sales():
    book = PayoutBook()
    book.install(_terms(), 10)
    book.note_sale(integ.A, b"\x07" * 32, integ.C, 101, 11)
    (row,) = book.store_rows()
    again = PayoutBook.restore([row], *book.resolved_state())
    assert again.root() == book.root()
    for sales in ((0, ((b"\x07" * 32, integ.C, 0, 11),)),            # nothing paid
                  (0, ((b"\x07" * 32, integ.C, 5, 11),) * 2),        # one sale twice
                  (-1, ()),                                          # negative misses
                  (0, ((b"\x07" * 31, integ.C, 5, 11),))):           # short id
        with pytest.raises(ValueError, match="sales"):
            PayoutBook.restore([row[:16] + (sales,)], *book.resolved_state())


@pytest.mark.usefixtures("isolated_chain_state")
def test_open_sales_survive_a_restart(temp_database):
    lm = integ._seed()
    book = lm.payout_rules
    book.install(_terms(account=integ.C), 50)
    book.note_sale(integ.C, b"\x09" * 32, integ.A, 333, 51)
    meta = lm.consensus_meta_hash()
    reloaded = integ._reload().payout_rules
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded.state_of(integ.C).open_sales == ((b"\x09" * 32, integ.A, 333, 51),)
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


# --- the command line ----------------------------------------------------------------

def test_the_cli_builds_a_per_sale_rule_and_an_execution_naming_a_sale():
    from tau_testnet_cli import tx as tx_mod
    from tau_testnet_cli.cli import build_parser

    built = tx_mod.build_payout_rule_set_tx(
        sender_pubkey=integ.A, sequence_number=1, expiration_time=integ.FAR,
        expire_at_height=integ.NEXT_HEIGHT + 5, rule_text=ROYALTY, slots=[integ.B],
        cap_per_execution=100, cap_per_period=300, period_blocks=10,
        expires_at=integ.NEXT_HEIGHT + 1000, per_sale=True)
    terms = parse_payout_rule_set(built)
    assert terms.per_sale and built["per_sale"] is True
    plain = tx_mod.build_payout_rule_set_tx(
        sender_pubkey=integ.A, sequence_number=1, expiration_time=integ.FAR,
        expire_at_height=integ.NEXT_HEIGHT + 5, rule_text=integ.RULE, slots=[integ.B],
        cap_per_execution=100, cap_per_period=300, period_blocks=10,
        expires_at=integ.NEXT_HEIGHT + 1000)
    assert "per_sale" not in plain
    exe = tx_mod.build_payout_execute_tx(
        sender_pubkey=integ.C, sequence_number=0, expiration_time=integ.FAR,
        expire_at_height=integ.NEXT_HEIGHT + 5, account_pubkey=integ.A,
        rule_id=terms.rule_id.hex(), sale_id="AB" * 32)
    assert parse_payout_execute(exe).sale_id == bytes.fromhex("ab" * 32)
    with pytest.raises(ValueError, match="sale_id"):
        tx_mod.build_payout_execute_tx(
            sender_pubkey=integ.C, sequence_number=0, expiration_time=integ.FAR,
            expire_at_height=integ.NEXT_HEIGHT + 5, account_pubkey=integ.A,
            rule_id=terms.rule_id.hex(), sale_id="ab")

    parser = build_parser()
    args = parser.parse_args(["payout", "set", "--key", "k", "--body", ROYALTY, "--slot", integ.B,
                              "--cap-per-execution", "5", "--cap-per-period", "9",
                              "--period-blocks", "10", "--ends-in", "100", "--per-sale"])
    assert args.per_sale is True
    args = parser.parse_args(["payout", "execute", "--key", "k", "--account", integ.A,
                              "--sale", "ab" * 32])
    assert args.sale == "ab" * 32


def test_admission_names_the_sale_it_would_pay(monkeypatch):
    from unittest.mock import MagicMock

    from consensus import sender_policy
    from consensus.admission import TipAdmissionView, validate_payout_execute_payload
    from consensus.policy_mock import MockPolicyEvaluator

    book = PayoutBook()
    terms = _terms()
    book.install(terms, integ.NEXT_HEIGHT - 1)
    book.note_sale(integ.A, b"\x05" * 32, integ.B, 101, integ.NEXT_HEIGHT - 1)
    mock = MockPolicyEvaluator(pool="payout_admission")
    mock.set_outputs(terms.body, _royalty)
    sender_policy.set_evaluator("payout_admission", mock)
    try:
        view = MagicMock(spec=TipAdmissionView)
        view.next_block_height = integ.NEXT_HEIGHT
        view.next_block_timestamp = integ.TIP_TS
        view.payout_book.return_value = book
        monkeypatch.setitem(chain_state._balances, integ.A, 1_000)
        ok = validate_payout_execute_payload(
            integ.execute(terms.rule_id.hex(), sale_id="05" * 32, data={}), view)
        assert ok.is_valid, ok.error
        assert ok.data["total"] == 5 and ok.data["sale_id"] == "05" * 32
        again = validate_payout_execute_payload(
            integ.execute(terms.rule_id.hex(), sale_id="06" * 32, data={}), view)
        assert again.code == "PAYOUT_REFUSED" and "not an open sale" in again.error
        assert mock.output_calls[0][1]["i27"] == "101"
    finally:
        sender_policy.set_evaluator("payout_admission", None)
