"""Block-apply semantics for payout rules (#63).

Every scenario runs through the real `apply_block` with a scripted interpreter
and mock policy evaluators: o5 clauses and guards in the `apply` pool, payout
rules in `payout_apply`. Each compares the FULL balance map, sequences and
cooldown stamps against an oracle that knows only the documented rules:

  * installing costs one fee and moves no money; revoking is fee-free;
  * an execution costs its executor one fee; the rule is stepped once and pays
    every slot it writes or nothing;
  * 1 <= total <= cap per execution, period total <= cap per period, total <=
    the account's balance; an open slot pays only a recipient the executor named;
  * the payer's CURRENT o5 clause is re-checked at execution -- a frozen payer
    pays nothing, no debt, no completion event; the rule-change guard is
    (kinds 6 and 7).

`apply_block` itself raises on any supply drift, so every block is also a
conservation check.
"""
import json

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from consensus import sender_policy
from consensus.governance import build_mechanism_metadata
from consensus.payout import (
    MAX_PAYOUT_EXECUTIONS_PER_BLOCK,
    PayoutBook,
    parse_payout_rule_set,
    parse_payout_rule_update,
    payout_rule_body,
    payout_spec_text,
)
from consensus.policy_mock import MockPolicyEvaluator

from tests.chain_harness import (
    ALICE, BOB, CAROL, CLAUSE, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _logs, _sign,
)

RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
BODY = payout_rule_body(RULE)
TWO = ("always ( (o30[t]:bv[24] = i40[t]:bv[24]) && "
       "(o31[t]:bv[24] = i41[t]:bv[24]) ).")
TWO_BODY = payout_rule_body(TWO)
DAVE = G2Basic.SkToPk(77777).hex()

_N = iter(range(10**9))


def set_tx(sender=ALICE, seq=0, *, rule=RULE, slots=None, cap_exec=100, cap_period=250,
           period=10, clock="period_blocks", expires_at=HEIGHT + 500, fee_limit="100",
           **extra):
    tx = {"tx_id": f"set-{next(_N)}", "tx_type": "payout_rule_set", "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": FAR, "expire_at_height": 1000,
          "fee_limit": str(fee_limit), "rule_text": rule,
          "slots": [BOB] if slots is None else slots,
          "cap_per_execution": cap_exec, "cap_per_period": cap_period, clock: period,
          "expires_at": expires_at}
    tx.update(extra)
    return _sign(tx, SKS[sender])


def exec_tx(executor=CAROL, seq=0, *, account=ALICE, rule_id, data=None, recipients=None,
            fee_limit="100"):
    return _sign({"tx_id": f"exec-{next(_N)}", "tx_type": "payout_execute",
                  "sender_pubkey": executor, "sequence_number": seq,
                  "expiration_time": FAR, "expire_at_height": 1000,
                  "fee_limit": str(fee_limit), "account_pubkey": account,
                  "rule_id": rule_id, "recipients": recipients or {},
                  "data": data or {}}, SKS[executor])


def revoke_tx(sender=ALICE, seq=1, *, rule_id):
    return _sign({"tx_id": f"revoke-{next(_N)}", "tx_type": "payout_rule_revoke",
                  "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
                  "expire_at_height": 1000, "fee_limit": "0", "rule_id": rule_id},
                 SKS[sender])


def update_tx(old_rule_id, sender=ALICE, seq=2, **kw):
    """A payout_rule_update naming `old_rule_id`, with the rule fields of set_tx."""
    tx = set_tx(sender=sender, seq=seq, **kw)
    tx["tx_type"] = "payout_rule_update"
    tx["rule_id"] = old_rule_id
    tx["tx_id"] = f"update-{next(_N)}"
    tx.pop("signature")
    return _sign(tx, SKS[sender])


def rid(tx) -> str:
    return parse_payout_rule_set(tx).rule_id.hex()


def ridb(tx) -> bytes:
    """The rule id as bytes, for book.get / book.state_of."""
    return parse_payout_rule_set(tx).rule_id


def _data_rule(inputs):
    """The scripted payout rule: slot k gets i40+k."""
    return {f"o{30 + k}": inputs.get(f"i{40 + k}", "0") for k in range(8)}


@pytest.fixture
def evs():
    out = {}
    for pool in ("apply", "payout_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    out["payout_apply"].set_outputs(BODY, _data_rule)
    out["payout_apply"].set_outputs(TWO_BODY, _data_rule)
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


def _bal():
    return {ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0}


def _installed(fee=0, **kw):
    ch, oracle = Chain(_bal(), fee=fee), Oracle(_bal())
    tx = set_tx(**kw)
    ch.block([tx])
    oracle.create(tx, fee=fee)
    return ch, oracle, tx


def _events(ch):
    return ch.last.next_snapshot.metadata["payout_events"]


def _reason(result, tx):
    return next(o for o in result.outcomes if o.tx_id == tx["tx_id"]).reason


def _executed(oracle, *, executor=CAROL, fee=0, account=ALICE, legs, ts=TS):
    oracle.bal[executor] -= fee
    oracle.bal[PROPOSER] += fee
    oracle.seq[executor] += 1
    for who, amount in legs:
        oracle.bal[account] -= amount
        oracle.bal[who] += amount
    oracle.lts[account] = ts


# --- installing ------------------------------------------------------------------

def test_install_charges_one_fee_and_moves_no_money(evs):
    ch, oracle, tx = _installed(fee=7)
    oracle.check(ch)
    assert ch.lm.payout_rules.get(ALICE).rule_id.hex() == rid(tx)
    assert ch.lm.payout_rules.state_of(ALICE, ridb(tx)).anchor == HEIGHT
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                            "outcome": "installed", "tx_id": tx["tx_id"]}]
    # Built in the payout pool, never stepped at install, never in the o5 pool.
    assert evs["payout_apply"].validate_calls == [BODY]
    assert evs["payout_apply"].output_calls == []
    assert evs["apply"].validate_calls == []


@pytest.mark.parametrize("change, why", [
    (dict(rule="always ( o30[t]:bv[16] = i40[t]:bv[16] )."), "must be bv[24]"),
    (dict(rule="always ( o5[t]:bv[24] = i40[t]:bv[24] )."), "not part of the payout ABI"),
    (dict(rule="always ( o31[t]:bv[24] = i40[t]:bv[24] )."), "not part of the payout ABI"),
    (dict(rule="always ( o30[t-1]:bv[24] = i40[t]:bv[24] )."), ""),
    (dict(rule="always ( o30[t]:bv[24] = { #x000001 }:bv[24] )."), "read at least one input"),
    (dict(slots=[ALICE]), "pay the account itself"),
    (dict(slots=[BOB, BOB], rule=TWO), "one slot only"),
    (dict(cap_exec=0), "cap_per_execution"),
    (dict(cap_exec=300, cap_period=200), "cap_per_period"),
    (dict(period=0), "period"),
    (dict(expires_at=HEIGHT), "in the future"),
    (dict(expires_at=HEIGHT + 10_000_001), "ahead"),
])
def test_a_rule_outside_the_abi_or_limits_is_not_installed(evs, change, why):
    ch, oracle = Chain(_bal(), fee=7), Oracle(_bal())
    result = ch.block([set_tx(**change)])
    assert ch.lm.payout_rules.get(ALICE) is None
    assert ch.lm.payout_rules.is_empty()
    assert result.outcomes[0].reason == "payout_rule_not_set"
    assert why in _logs(result)
    oracle.check(ch)   # dropped: no fee, no sequence


def test_a_rule_that_does_not_build_is_not_installed(evs):
    evs["payout_apply"].fail_build(BODY, "type error")
    ch, oracle = Chain(_bal(), fee=7), Oracle(_bal())
    result = ch.block([set_tx()])
    assert ch.lm.payout_rules.get(ALICE) is None
    assert "does not build" in _logs(result)
    oracle.check(ch)


def test_a_second_rule_is_independent_and_an_update_supersedes_the_old_one(evs):
    ch, oracle, first = _installed()
    root_one = ch.lm.payout_rules.root()
    second = set_tx(seq=1, cap_exec=50)
    ch.block([second], height=HEIGHT + 1)
    oracle.create(second, fee=0)
    book = ch.lm.payout_rules
    # Installing again does NOT replace: the account now holds two rules.
    assert book.count_for(ALICE) == 2
    assert book.get(ALICE, ridb(first)) is not None
    assert book.get(ALICE, ridb(second)) is not None
    assert book.resolved_count == 0
    assert book.root() != root_one
    assert _events(ch)[0] == {"account_pubkey": ALICE, "rule_id": rid(second),
                              "outcome": "installed", "tx_id": second["tx_id"]}
    oracle.check(ch)
    # An update supersedes the old version: same lineage, version + 1, the old
    # id resolves to the new one and the removal is folded into the commitment.
    upd = update_tx(rid(first), seq=2, cap_exec=60)
    ch.block([upd], height=HEIGHT + 2)
    oracle.create(upd, fee=0)
    book = ch.lm.payout_rules   # the block replaced the lifecycle manager
    _, _, new_terms = parse_payout_rule_update(upd)
    from dataclasses import replace as _replace
    new_id = _replace(new_terms, version=2).rule_id
    assert book.get(ALICE, ridb(first)) is None
    assert book.get(ALICE, new_id) is not None
    assert book.get(ALICE, new_id).version == 2
    assert book.current_id(bytes.fromhex(rid(first))) == new_id
    assert book.count_for(ALICE) == 2
    assert book.resolved_count == 1
    # The event names the rule the book now holds (version 2, asserted
    # above) and the version it replaces.
    assert _events(ch)[0] == {"account_pubkey": ALICE, "rule_id": new_id.hex(),
                              "outcome": "updated", "tx_id": upd["tx_id"],
                              "replaces": rid(first)}
    assert book.root() != root_one
    oracle.check(ch)


def test_the_same_rule_twice_cannot_be_installed(evs):
    # The id carries the sequence number, so a second transaction is a new
    # rule; the same transaction again fails its sequence. The book refuses an
    # identical id as well, whatever path it came by.
    ch, _oracle, tx = _installed()
    result = ch.block([dict(tx)], height=HEIGHT + 1)
    assert "Invalid sequence number" in _logs(result)
    ok, why = ch.lm.payout_rules.can_admit_set(parse_payout_rule_set(tx), HEIGHT + 1, TS)
    assert not ok and "already installed" in why


# --- executing -------------------------------------------------------------------

def test_an_execution_pays_the_fixed_slot_and_the_executor_pays_the_fee(evs):
    ch, oracle, tx = _installed()
    ch.fee = 5
    exe = exec_tx(rule_id=rid(tx), data={"0": 40})
    ch.block([exe], height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, fee=5, legs=[(BOB, 40)], ts=TS + 3)
    oracle.check(ch)
    state = ch.lm.payout_rules.state_of(ALICE, ridb(tx))
    assert (state.executions, state.paid_total, state.spent_in_period) == (1, 40, 40)
    assert state.last_height == HEIGHT + 3
    event = _events(ch)[0]
    assert event["outcome"] == "executed" and event["executor_pubkey"] == CAROL
    assert event["legs"] == [{"slot": 0, "recipient_pubkey": BOB, "amount": 40}]
    assert event["tx_id"] == exe["tx_id"]


def test_the_rule_sees_the_payout_abi(evs):
    ch, _oracle, tx = _installed()
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 40, "3": 9})], height=HEIGHT + 3,
             ts=TS + 3)
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 4, ts=TS + 4)
    first, second = evs["payout_apply"].output_calls
    assert first[0] == BODY
    inputs = first[1]
    assert inputs["i2"] == "1000"                     # parent balance
    assert inputs["i5"] == str(TS + 3) and inputs["i6"] == str(HEIGHT + 3)
    assert inputs["i13"] == "#x" + CAROL
    assert inputs["i26"] == "0"
    assert inputs["i30"] == "#x" + BOB
    assert inputs["i40"] == "40" and inputs["i43"] == "9" and inputs["i47"] == "0"
    assert second[1]["i26"] == "40" and second[1]["i2"] == "960"


FREEZE = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def test_a_frozen_payer_executes_nothing(evs):
    ch, oracle, tx = _installed()
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = FREEZE
    evs["apply"].set_verdict(FREEZE, lambda inputs: 0)    # blocks every transfer
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 1, ts=TS + 1)
    assert result.outcomes[0].reason == "payout_not_executed"
    assert "o5" in _logs(result)
    assert ch.lm.payout_rules.state_of(ALICE, ridb(tx)).executions == 0
    oracle.check(ch)
    assert evs["apply"].verdict_calls  # the payer's o5 clause WAS consulted


def test_an_unfrozen_payer_executes_normally(evs):
    ch, oracle, tx = _installed()
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = CLAUSE
    evs["apply"].set_verdict(CLAUSE, lambda inputs: 1)    # allows every transfer
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(BOB, 30)], ts=TS + 1)
    oracle.check(ch)


def test_an_open_slot_pays_the_named_recipient(evs):
    ch, oracle, tx = _installed(slots=[""])
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 25}, recipients={"0": DAVE})],
             height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(DAVE, 25)], ts=TS + 1)
    oracle.check(ch)
    assert evs["payout_apply"].output_calls[0][1]["i30"] == "#x" + DAVE


def test_an_open_slot_nobody_named_reads_zero_and_paying_it_is_refused(evs):
    ch, oracle, tx = _installed(slots=[""])
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 25})], height=HEIGHT + 1)
    assert evs["payout_apply"].output_calls[0][1]["i30"] == "0"
    assert result.outcomes[0].reason == "payout_not_executed"
    assert "no recipient was named" in _logs(result)
    oracle.check(ch)


@pytest.mark.parametrize("recipients, why", [
    ({"0": DAVE}, "fixed recipient"),
    ({"3": DAVE}, "does not exist"),
])
def test_naming_a_fixed_or_missing_slot_is_refused(evs, recipients, why):
    ch, oracle, tx = _installed()
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 5}, recipients=recipients)],
                      height=HEIGHT + 1)
    assert why in _logs(result)
    oracle.check(ch)


def test_an_open_slot_may_not_pay_the_account_itself(evs):
    ch, oracle, tx = _installed(slots=[""])
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 5}, recipients={"0": ALICE})],
                      height=HEIGHT + 1)
    assert "account itself" in _logs(result)
    oracle.check(ch)


def test_the_executor_may_name_itself_and_nets_right(evs):
    ch, oracle, tx = _installed(slots=[""])
    ch.fee = 3
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 20}, recipients={"0": CAROL})],
             height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, fee=3, legs=[(CAROL, 20)], ts=TS + 1)
    oracle.check(ch)


def test_two_slots_are_paid_together(evs):
    ch, oracle, tx = _installed(rule=TWO, slots=[BOB, ""])
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 30, "1": 20}, recipients={"1": DAVE})],
             height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(BOB, 30), (DAVE, 20)], ts=TS + 1)
    oracle.check(ch)
    assert ch.lm.payout_rules.state_of(ALICE, ridb(tx)).spent_in_period == 50


@pytest.mark.parametrize("data, why", [
    ({"0": 0}, "pays nothing"),
    ({"0": 101}, "over the cap per execution"),
])
def test_nothing_or_too_much_is_refused(evs, data, why):
    ch, oracle, tx = _installed()
    result = ch.block([exec_tx(rule_id=rid(tx), data=data)], height=HEIGHT + 1)
    assert why in _logs(result)
    assert ch.lm.payout_rules.state_of(ALICE, ridb(tx)).executions == 0
    oracle.check(ch)


def test_all_or_nothing_over_the_balance(evs):
    bal = {ALICE: 60, BOB: 0, CAROL: 50, PROPOSER: 0}
    ch, oracle = Chain(bal), Oracle(bal)
    tx = set_tx(rule=TWO, slots=[BOB, CAROL])
    ch.block([tx])
    oracle.create(tx, fee=0)
    result = ch.block([exec_tx(executor=BOB if False else CAROL, rule_id=rid(tx),
                               data={"0": 40, "1": 30})], height=HEIGHT + 1)
    assert "the account holds 60" in _logs(result)
    oracle.check(ch)          # neither leg moved


def test_the_period_cap_spans_executions_and_resets_next_period(evs):
    ch, oracle, tx = _installed(cap_exec=100, cap_period=150, period=10)
    ch.block([exec_tx(seq=0, rule_id=rid(tx), data={"0": 100})], height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(BOB, 100)], ts=TS + 1)
    late = ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 60})], height=HEIGHT + 2)
    assert "over the cap per period 150" in _logs(late)
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 50})], height=HEIGHT + 3, ts=TS + 3)
    _executed(oracle, legs=[(BOB, 50)], ts=TS + 3)
    # The next period starts at anchor + period = HEIGHT + 10.
    early = ch.block([exec_tx(seq=2, rule_id=rid(tx), data={"0": 1})], height=HEIGHT + 9)
    assert "over the cap per period" in _logs(early)
    ch.block([exec_tx(seq=2, rule_id=rid(tx), data={"0": 100})], height=HEIGHT + 10,
             ts=TS + 10)
    _executed(oracle, legs=[(BOB, 100)], ts=TS + 10)
    oracle.check(ch)
    state = ch.lm.payout_rules.state_of(ALICE, ridb(tx))
    assert (state.period_index, state.spent_in_period, state.paid_total) == (1, 100, 250)


def test_two_executions_in_one_block_share_the_period_cap(evs):
    ch, oracle, tx = _installed(cap_exec=100, cap_period=150)
    result = ch.block([exec_tx(seq=0, rule_id=rid(tx), data={"0": 100}),
                       exec_tx(seq=1, rule_id=rid(tx), data={"0": 100})],
                      height=HEIGHT + 1, ts=TS + 1)
    _executed(oracle, legs=[(BOB, 100)], ts=TS + 1)
    assert [o.reason for o in result.outcomes][1] == "payout_not_executed"
    oracle.check(ch)


def test_a_seconds_period_counts_block_time(evs):
    ch, oracle, tx = _installed(clock="period_seconds", period=3600, cap_period=100,
                                expires_at=TS + 86_400)
    ch.block([exec_tx(seq=0, rule_id=rid(tx), data={"0": 100})], height=HEIGHT + 1,
             ts=TS + 10)
    _executed(oracle, legs=[(BOB, 100)], ts=TS + 10)
    refused = ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 1})],
                       height=HEIGHT + 50, ts=TS + 3599)
    assert "cap per period" in _logs(refused)
    ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 1})], height=HEIGHT + 51,
             ts=TS + 3600)
    _executed(oracle, legs=[(BOB, 1)], ts=TS + 3600)
    oracle.check(ch)


def test_an_execution_naming_a_superseded_rule_is_refused(evs):
    ch, oracle, first = _installed()
    upd = update_tx(rid(first), seq=1, cap_exec=50)
    ch.block([upd], height=HEIGHT + 1)
    oracle.create(upd, fee=0)
    result = ch.block([exec_tx(rule_id=rid(first), data={"0": 10})], height=HEIGHT + 2)
    assert "no payout rule with that id" in _logs(result)
    oracle.check(ch)


def test_at_most_sixteen_executions_per_block(evs):
    bal = {ALICE: 100_000, BOB: 0, CAROL: 50, PROPOSER: 0}
    ch, oracle = Chain(bal), Oracle(bal)
    tx = set_tx(cap_exec=10, cap_period=10_000)
    ch.block([tx])
    oracle.create(tx, fee=0)
    n = MAX_PAYOUT_EXECUTIONS_PER_BLOCK + 2
    result = ch.block([exec_tx(seq=s, rule_id=rid(tx), data={"0": 1}) for s in range(n)],
                      height=HEIGHT + 1, ts=TS + 1)
    reasons = [o.reason for o in result.outcomes]
    # The 17th is over the cap; the 18th then fails its sequence.
    assert reasons[:MAX_PAYOUT_EXECUTIONS_PER_BLOCK] == [None] * MAX_PAYOUT_EXECUTIONS_PER_BLOCK
    assert reasons[MAX_PAYOUT_EXECUTIONS_PER_BLOCK] == "payout_not_executed"
    assert "most payout executions" in _logs(result)
    for _ in range(MAX_PAYOUT_EXECUTIONS_PER_BLOCK):
        _executed(oracle, legs=[(BOB, 1)], ts=TS + 1)
    oracle.check(ch)


def test_an_evaluator_refusal_moves_nothing(evs):
    ch, oracle, tx = _installed()
    evs["payout_apply"]._refused[BODY] = "step failed"
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 1)
    assert "cannot be evaluated" in _logs(result)
    oracle.check(ch)


def test_replay_without_an_evaluator_moves_nothing(evs):
    ch, oracle, tx = _installed()
    sender_policy.set_evaluator("payout_apply", None)
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 1,
                      replay=True)
    assert result.outcomes[0].reason == "payout_not_executed"
    assert ch.lm.payout_rules.state_of(ALICE, ridb(tx)).executions == 0


# --- revoking and expiry -----------------------------------------------------------

def test_revoke_is_fee_free_and_stops_executions(evs):
    ch, oracle, tx = _installed(fee=4)
    ch.block([revoke_tx(rule_id=rid(tx))], height=HEIGHT + 1)
    oracle.cancel(ALICE)
    assert ch.lm.payout_rules.get(ALICE) is None
    assert _events(ch)[0]["outcome"] == "revoked"
    assert not ch.lm.payout_rules.is_empty()
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 2)
    assert "no payout rule" in _logs(result)
    oracle.check(ch)


def test_revoking_nothing_is_refused(evs):
    ch, oracle = Chain(_bal()), Oracle(_bal())
    result = ch.block([revoke_tx(seq=0, rule_id="00" * 32)])
    assert result.outcomes[0].reason == "payout_rule_not_revoked"
    oracle.check(ch)


def test_a_rule_expires_at_its_end_and_the_money_stays(evs):
    ch, oracle, tx = _installed(expires_at=HEIGHT + 5)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 4, ts=TS + 4)
    _executed(oracle, legs=[(BOB, 5)], ts=TS + 4)
    ch.block([], height=HEIGHT + 5)
    assert ch.lm.payout_rules.get(ALICE) is None
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                            "outcome": "expired"}]
    oracle.check(ch)


def test_an_execution_in_the_expiry_block_is_refused(evs):
    ch, oracle, tx = _installed(expires_at=HEIGHT + 5)
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 5)
    assert result.outcomes[0].reason == "payout_not_executed"
    oracle.check(ch)


# --- the guard -------------------------------------------------------------------

GUARD = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def test_a_guard_that_blocks_changes_blocks_install_and_revoke(evs):
    ch, oracle, tx = _installed()
    ch.lm.rule_offers.accepted_clauses[(ALICE, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD
    evs["apply"].set_verdict(GUARD, lambda inputs: 0)
    result = ch.block([set_tx(seq=1, cap_exec=50), revoke_tx(seq=1, rule_id=rid(tx)),
                       update_tx(rid(tx), seq=1, cap_exec=50)], height=HEIGHT + 1)
    assert [o.reason for o in result.outcomes] == ["payout_rule_not_set",
                                                   "payout_rule_not_revoked",
                                                   "payout_rule_not_updated"]
    assert "use a rule-change request" in _logs(result)
    kinds = [c[1]["i1"] for c in evs["apply"].verdict_calls]
    assert kinds == [str(tau_defs.RULE_CHANGE_KIND_SET_PAYOUT),
                     str(tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT),
                     str(tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT)]
    assert ch.lm.payout_rules.get(ALICE).rule_id.hex() == rid(tx)
    # Executions are not rule changes: the guard does not stop them.
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 2, ts=TS + 2)
    _executed(oracle, legs=[(BOB, 5)], ts=TS + 2)
    oracle.check(ch)


def test_a_guard_that_allows_lets_the_change_through(evs):
    ch = Chain(_bal())
    ch.lm.rule_offers.accepted_clauses[(ALICE, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD
    evs["apply"].set_verdict(GUARD, lambda inputs: 1)
    ch.block([set_tx()])
    assert ch.lm.payout_rules.get(ALICE) is not None


# --- the state commitment ----------------------------------------------------------

def test_an_empty_book_stays_out_of_the_metadata():
    assert "payout_rules_root" not in build_mechanism_metadata(
        [], "", 1, payout_rules_root="")


def test_the_state_hash_moves_with_the_book_and_not_before(evs):
    a, _o, tx = _installed()
    b = Chain(_bal())
    b.block([])
    # An empty block on an untouched book hashes as before the feature.
    c = Chain(_bal())
    c.lm.payout_rules = PayoutBook()
    c.block([])
    assert b.hashes[-1] == c.hashes[-1]
    assert a.hashes[-1] != b.hashes[-1]
    before = a.hashes[-1]
    a.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 1, ts=TS + 1)
    after_exec = a.hashes[-1]
    a.block([], height=HEIGHT + 2, ts=TS + 2)
    # The execution moved the commitment; an empty block leaves it where it is.
    assert before != after_exec == a.hashes[-1]
    a.block([revoke_tx(rule_id=rid(tx))], height=HEIGHT + 3, ts=TS + 3)
    assert a.hashes[-1] not in (before, after_exec, b.hashes[-1])


def test_the_same_blocks_give_the_same_hashes(evs):
    runs = []
    for _ in range(2):
        ch, _o, tx = _installed()
        ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 1, ts=TS + 1)
        ch.block([revoke_tx(rule_id=rid(tx))], height=HEIGHT + 2, ts=TS + 2)
        runs.append(list(ch.hashes))
    assert runs[0] == runs[1]


def test_a_block_does_not_touch_its_parents_book(evs):
    ch, _o, tx = _installed()
    parent_book = ch.lm.payout_rules
    snapshot = json.dumps([list(map(str, r)) for r in parent_book.store_rows()])
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 5})], height=HEIGHT + 1, ts=TS + 1)
    assert json.dumps([list(map(str, r)) for r in parent_book.store_rows()]) == snapshot
    assert ch.lm.payout_rules is not parent_book


def test_spec_text_is_canonical_and_carries_the_sequence():
    fields = {"rule_text": RULE, "slots": [BOB], "cap_per_execution": 1,
              "cap_per_period": 2, "period_blocks": 3, "expires_at": 4}
    text = payout_spec_text(fields, 9)
    assert json.loads(text)["sequence_number"] == 9
    assert " " not in text.replace(RULE, "")
