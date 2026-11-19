"""Rule-computed payouts (#63): caps, atomic legs, policy, persistence, RPC, CLI.

Block apply runs the payout rule through the `payout` policy pool; here that pool
is the in-process MockPolicyEvaluator, whose outputs are scripted per rule text
from the very inputs the engine feeds (i1 balance, i2 count, i3 period, i13+).
"""
import itertools
import json
import types
from datetime import datetime, timezone

import pytest

import chain_state
import db
from commands import getpayoutrules
from consensus import periods, sender_policy
from consensus.payouts import (
    PAYOUT_POLICY_POOL, PayoutBook, legs_from_outputs, load_payout_book,
    parse_payout_execute, parse_payout_install, tau_amount,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_signing import signing_message_bytes
from tau_testnet_cli import cli, tx as tx_mod
from tests.test_retractable_apply import (
    ALICE, BOB, CAROL, FAR, MALLORY, PROPOSER, SK_ALICE, SK_BOB, SK_CAROL,
    SK_MALLORY, Chain, _sign,
)

_SEQ = itertools.count()
KEYS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, MALLORY: SK_MALLORY}
T0 = int(datetime(2026, 11, 20, tzinfo=timezone.utc).timestamp())

# Royalty: 5% of the sale price (i13) to Bob, the rest of the price to Carol.
ROYALTY = ("(o1[t]:bv[24] = i13[t]:bv[24] / { 20 }:bv[24]) && "
           "(o2[t]:bv[24] = i13[t]:bv[24] - i13[t]:bv[24] / { 20 }:bv[24])")


def _royalty(inputs):
    price = int(inputs["i13"])
    return {"o1": price // 20, "o2": price - price // 20}


@pytest.fixture
def payout_pool():
    mock = MockPolicyEvaluator(pool=PAYOUT_POLICY_POOL)
    mock.set_outputs(ROYALTY, _royalty)
    sender_policy.set_evaluator(PAYOUT_POLICY_POOL, mock)
    yield mock
    sender_policy.set_evaluator(PAYOUT_POLICY_POOL, None)


def _base(tx_type, sender, seq, fee_limit=100):
    return {"tx_id": f"{tx_type}-{next(_SEQ)}", "tx_type": tx_type,
            "sender_pubkey": sender, "sequence_number": seq,
            "expiration_time": FAR, "expire_at_height": 1000, "fee_limit": str(fee_limit)}


def install_tx(seq=0, rule=ROYALTY, recipients=(BOB, CAROL), **over):
    tx = _base("payout_rule_install", ALICE, seq)
    tx.update({"rule_text": rule, "recipients": list(recipients),
               "max_per_execution": 2000, "max_per_period": 3000,
               "period_kind": periods.PERIOD_MONTH, "period_seconds": 0,
               "start_at": 0, "expires_at": 0})
    tx.update(over)
    return _sign(tx, SK_ALICE)


def exec_tx(rid, price, seq, sender=MALLORY):
    tx = _base("payout_execute", sender, seq)
    tx.update({"rule_id": rid, "inputs": {"13": str(price)}})
    return _sign(tx, KEYS[sender])


def rid_of(tx):
    return parse_payout_install(tx).rule_id.hex()


def setup(**kw):
    ch = Chain({ALICE: 10_000, MALLORY: 100}, **kw)
    t = install_tx()
    ch.block([t], ts=T0)
    assert not ch.last.invalid_tx_ids
    return ch, rid_of(t)


def test_rule_computes_legs_paid_atomically(payout_pool):
    ch, rid = setup()
    ch.block([exec_tx(rid, 1000, 0)], ts=T0 + 10)
    assert ch.bal[BOB] == 50 and ch.bal[CAROL] == 950 and ch.bal[ALICE] == 9_000
    # The engine fed the owner's balance and the executor's input.
    _, inputs = payout_pool.verdict_calls[-1]
    assert inputs["i1"] == "10000" and inputs["i13"] == "1000"


def test_caps_per_execution_and_per_period(payout_pool):
    ch, rid = setup()
    ch.block([exec_tx(rid, 2001, 0)], ts=T0 + 10)
    assert ch.last.invalid_tx_ids and ch.bal[ALICE] == 10_000
    ch.block([exec_tx(rid, 2000, 0)], ts=T0 + 20)
    ch.block([exec_tx(rid, 1001, 1)], ts=T0 + 30)  # 2000 + 1001 > 3000
    assert ch.last.invalid_tx_ids
    ch.block([exec_tx(rid, 1000, 1)], ts=T0 + 40)
    assert ch.bal[ALICE] == 7_000
    # New month: the period cap resets.
    ch.block([exec_tx(rid, 1000, 2)], ts=int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp()))
    assert ch.bal[ALICE] == 6_000


def test_insufficient_owner_balance_pays_no_leg(payout_pool):
    ch = Chain({ALICE: 500, MALLORY: 100})
    t = install_tx()
    ch.block([t], ts=T0)
    ch.block([exec_tx(rid_of(t), 1000, 0)], ts=T0 + 10)
    assert ch.last.invalid_tx_ids
    assert ch.bal.get(BOB, 0) == 0 and ch.bal.get(CAROL, 0) == 0


def test_owner_policy_block_stops_payout(payout_pool):
    ch, rid = setup()
    ch.block_o5 = True
    ch.block([exec_tx(rid, 1000, 0)], ts=T0 + 10)
    assert ch.last.invalid_tx_ids and ch.bal[ALICE] == 10_000


def test_rule_that_does_not_run_or_pays_nothing_is_rejected(payout_pool):
    ch, rid = setup()
    payout_pool.fail_step(ROYALTY)
    ch.block([exec_tx(rid, 1000, 0)], ts=T0 + 10)
    assert ch.last.invalid_tx_ids
    payout_pool._refused.clear()
    ch.block([exec_tx(rid, 0, 0)], ts=T0 + 20)
    assert ch.last.invalid_tx_ids and ch.bal[ALICE] == 10_000


def test_only_declared_recipients_can_be_paid(payout_pool):
    # A rule writing o3 has no slot 3: nothing is paid to anyone undeclared.
    terms = parse_payout_install(install_tx(rule="x", recipients=(BOB,)))
    assert legs_from_outputs(terms, {"o1": "7", "o3": "999"}) == [(BOB, 7)]


def test_executor_pays_fee_and_supply_conserved(payout_pool):
    ch, rid = setup(fee=2)
    supply = sum(ch.bal.values())
    ch.block([exec_tx(rid, 1000, 0)], ts=T0 + 10)
    # One fee step per leg, exactly as a multi-transfer user_tx is priced.
    assert ch.bal[MALLORY] == 100 - 2 * 2
    assert sum(ch.bal.values()) == supply


def test_remove_only_by_owner(payout_pool):
    ch, rid = setup()
    bad = _sign({**_base("payout_rule_remove", BOB, 0, 0), "rule_id": rid}, SK_BOB)
    ch.block([bad], ts=T0 + 10)
    assert ch.last.invalid_tx_ids
    ok = _sign({**_base("payout_rule_remove", ALICE, 1, 0), "rule_id": rid}, SK_ALICE)
    ch.block([ok], ts=T0 + 20)
    assert ch.lm.payout_rules.get(bytes.fromhex(rid)) is None


@pytest.mark.parametrize("over,needle", [
    ({"recipients": []}, "recipients"),
    ({"recipients": [BOB, BOB]}, "distinct"),
    ({"recipients": [ALICE]}, "owner"),
    ({"max_per_execution": 0}, "max_per_execution"),
    ({"max_per_period": 1}, "max_per_period"),
    ({"rule_text": "x" * 9000}, "longer"),
])
def test_invalid_install(over, needle):
    ok, reason = PayoutBook().can_admit_install(parse_payout_install(install_tx(**over)), T0)
    assert not ok and needle in reason


def test_executor_inputs_are_bounded():
    from consensus.payouts import PayoutShapeError

    for bad in ({"12": "1"}, {"21": "1"}, {"13": "1; drop"}, {"13": 5}):
        with pytest.raises(PayoutShapeError):
            parse_payout_execute({"sender_pubkey": BOB, "rule_id": "ab" * 32, "inputs": bad})
    ok = parse_payout_execute({"sender_pubkey": BOB, "rule_id": "ab" * 32,
                               "inputs": {"13": "{ #x0001f4 }:bv[24]", "20": "7"}})
    assert ok.inputs == ((13, "{ #x0001f4 }:bv[24]"), (20, "7"))


def test_tau_amount_parsing():
    assert tau_amount("#x0001f4") == 500 and tau_amount("{ #b101 }:bv[24]") == 5
    assert tau_amount("42") == 42 and tau_amount(None) == 0


def test_persistence_rpc_signing_cli(temp_database):
    book = PayoutBook()
    terms = parse_payout_install(install_tx())
    rid = book.install(terms)
    book.record(rid, 1000, T0)
    lm = types.SimpleNamespace(payout_rules=book)
    db.save_canonical_state_atomically("00" * 32, 1, {}, {}, "", "", "", [], [], [], [],
                                       payouts=chain_state._payouts_state(lm))
    assert load_payout_book(db.load_payouts_state()).root() == book.root()
    out = json.loads(getpayoutrules.execute(f"getpayoutrules {BOB} in", None))
    (row,) = out["data"]["payout_rules"]
    assert row["rule_id"] == rid.hex() and "i13..i20" in out["data"]["conventions"]

    state = db.load_payouts_state()
    state["rules"][0]["recipients"] = [MALLORY, CAROL]
    db.set_chain_state_value("payouts_v1", json.dumps(state))
    with pytest.raises(chain_state.DatabaseError):
        chain_state._restore_payouts(types.SimpleNamespace())

    base = tx_mod.build_payout_install_tx(
        sender_pubkey=ALICE, sequence_number=0, expiration_time=1, expire_at_height=1,
        rule_text=ROYALTY, recipients=[BOB], max_per_execution=1, max_per_period=1)
    ref = signing_message_bytes(base)
    for k, v in [("rule_text", "y"), ("recipients", [CAROL]), ("max_per_execution", 2),
                 ("max_per_period", 2), ("period_kind", 1), ("expires_at", 5)]:
        assert signing_message_bytes(dict(base, **{k: v})) != ref, k
    ex = tx_mod.build_payout_execute_tx(sender_pubkey=BOB, sequence_number=0,
                                        expiration_time=1, expire_at_height=1,
                                        rule_id="ab" * 32, inputs={"13": "5"})
    assert signing_message_bytes(dict(ex, inputs={"13": "6"})) != signing_message_bytes(ex)

    args = cli.build_parser().parse_args(["payout", "execute", "--key", "bob", "ab" * 32,
                                          "--input", "13=1000", "--input", "i14=2"])
    assert dict(args.input) == {"13": "1000", "14": "2"}
