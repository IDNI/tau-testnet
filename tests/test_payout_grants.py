"""Conditional grants: escrow at install, draws out of it, refund at the deadline (#178).

A grant rule is a payout rule installed with `grant_amount` and
`grant_deadline` (gmikeyg's case 5 on #34: 5,000 granted, 1,200 drawn, 3,800
refunded at the deadline). Every scenario runs through the real `apply_block`
with a scripted interpreter and mock policy evaluators, and compares the FULL
balance map against an oracle that only knows the documented rules:

  * installing debits the grantor the grant amount (on top of the one fee)
    and holds it in the book: the grantor's balance falls, nobody is paid;
  * a draw pays its legs out of the held balance, never out of the account,
    and the rule reads the held balance as i2;
  * at the deadline the node refunds the remainder to the grantor and the
    rule ends, so no further draw is possible; revoking refunds the same way;
  * a grant rule is never updated, and installing one the grantor cannot fund
    is refused outright.

`apply_block` itself raises on any supply drift, so every block is also a
conservation check: the escrow counts toward the supply.
"""
import pytest
from py_ecc.bls import G2Basic

import tau_defs
from consensus import sender_policy
from consensus.approvals import STATUS_EXECUTED
from consensus.payout import (
    PayoutBook,
    parse_payout_rule_set,
    parse_payout_rule_update,
    payout_rule_body,
)
from consensus.policy_mock import MockPolicyEvaluator

from test_payout_guard import _parked as _guard_parked, spec as _guard_spec
from test_rule_change_release import _vote
from test_rule_change_requests import ALICE as GUARD_ALICE, GUARD_BODY
from tests.chain_harness import (
    ALICE, BOB, CAROL, CLAUSE, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _logs, _sign,
)

RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
BODY = payout_rule_body(RULE)
DUE_RULE = "always ( o30[t]:bv[24] = i2[t]:bv[24] - i2[t]:bv[24] + { 1200 }:bv[24] )."
DUE_BODY = payout_rule_body(DUE_RULE)
DAVE = G2Basic.SkToPk(77777).hex()
GRANT = 5_000
DEADLINE = HEIGHT + 100

_N = iter(range(10**9))


def set_tx(sender=ALICE, seq=0, *, rule=RULE, slots=None, cap_exec=5000,
           cap_period=5000, period=10, clock="period_blocks",
           expires_at=HEIGHT + 500, grant_amount=GRANT, grant_deadline=DEADLINE,
           fee_limit="100", **extra):
    tx = {"tx_id": f"set-{next(_N)}", "tx_type": "payout_rule_set", "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": FAR, "expire_at_height": 1000,
          "fee_limit": str(fee_limit), "rule_text": rule,
          "slots": [BOB] if slots is None else slots,
          "cap_per_execution": cap_exec, "cap_per_period": cap_period, clock: period,
          "expires_at": expires_at}
    if grant_amount is not None:
        tx["grant_amount"] = grant_amount
    if grant_deadline is not None:
        tx["grant_deadline"] = grant_deadline
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
    out["payout_apply"].set_outputs(DUE_BODY, lambda inputs: {"o30": "1200"})
    yield out
    for pool in ("apply", "payout_apply"):
        sender_policy.set_evaluator(pool, None)


@pytest.fixture
def guard_evs():
    """The guard allows a change only once slot i18 holds a pubkey."""
    evs = {}
    for pool in ("apply", "admission", "payout_apply", "payout_admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _bal():
    return {ALICE: 10_000, BOB: 0, CAROL: 50, PROPOSER: 0}


def _installed(fee=0, **kw):
    ch, oracle = Chain(_bal(), fee=fee), Oracle(_bal())
    tx = set_tx(**kw)
    ch.block([tx])
    oracle.create(tx, fee=fee)
    oracle.bal[ALICE] -= GRANT  # the grant leaves the grantor for the book
    return ch, oracle, tx


def _events(ch):
    return ch.last.next_snapshot.metadata["payout_events"]


def _drawn(oracle, *, executor=CAROL, fee=0, legs, ts=TS):
    """The oracle side of a grant draw: the executor pays the fee, the legs
    are paid, the grantor's balance does not move (it was debited at install)."""
    oracle.bal[executor] -= fee
    oracle.bal[PROPOSER] += fee
    oracle.seq[executor] += 1
    for who, amount in legs:
        oracle.bal[who] += amount
    oracle.lts[ALICE] = ts


def _state(ch, tx):
    return ch.lm.payout_rules.state_of(ALICE, ridb(tx))


# --- installing ------------------------------------------------------------------

def test_grant_install_escrows_the_amount(evs):
    ch, oracle, tx = _installed()
    oracle.check(ch)
    terms = ch.lm.payout_rules.get(ALICE)
    assert terms.is_grant and terms.grant_amount == GRANT
    assert terms.grant_deadline == DEADLINE
    state = _state(ch, tx)
    assert (state.held, state.drawn) == (GRANT, 0)
    assert ch.lm.payout_rules.escrow_total() == GRANT
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                            "outcome": "installed", "tx_id": tx["tx_id"],
                            "grant_amount": GRANT}]


def test_grant_install_with_a_fee_charges_the_fee_and_escrows(evs):
    ch, oracle, tx = _installed(fee=7)
    oracle.check(ch)
    assert ch.bal[ALICE] == 10_000 - 7 - GRANT
    assert _state(ch, tx).held == GRANT


def test_grant_install_is_refused_when_the_grantor_cannot_fund_it(evs):
    bal = {ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0}
    ch, oracle = Chain(bal), Oracle(bal)
    result = ch.block([set_tx()])
    assert ch.lm.payout_rules.get(ALICE) is None
    assert ch.lm.payout_rules.is_empty()
    assert result.outcomes[0].reason == "payout_rule_not_set"
    assert "less than the grant" in _logs(result)
    oracle.check(ch)  # nothing moved: no fee, no sequence


@pytest.mark.parametrize("change, why", [
    (dict(grant_deadline=None), "come together"),
    (dict(grant_amount=None), "come together"),
    (dict(grant_amount=0), "grant_amount must be in 1"),
    (dict(grant_deadline=HEIGHT), "in the future"),
    (dict(grant_deadline=HEIGHT + 501), "no later than expires_at"),
])
def test_a_grant_outside_its_shape_is_not_installed(evs, change, why):
    ch, oracle = Chain(_bal(), fee=7), Oracle(_bal())
    result = ch.block([set_tx(**change)])
    assert ch.lm.payout_rules.get(ALICE) is None
    assert result.outcomes[0].reason == "payout_rule_not_set"
    assert why in _logs(result)
    oracle.check(ch)


def test_a_grant_installs_through_a_rule_change_request(guard_evs):
    # NOTE: the guard harness has its own ALICE (test_rule_change_requests),
    # not the chain_harness one this file otherwise uses.
    chain, req = _guard_parked(
        tau_defs.RULE_CHANGE_KIND_SET_PAYOUT,
        _guard_spec(grant_amount=GRANT, grant_deadline=DEADLINE,
                    cap_per_execution=GRANT, cap_per_period=GRANT),
    )
    result = chain.block(_vote(req.request_id))
    assert chain.entry(req).status == STATUS_EXECUTED
    terms = chain.lm.payout_rules.get(GUARD_ALICE)
    assert terms is not None and terms.is_grant
    assert chain.lm.payout_rules.state_of(GUARD_ALICE, terms.rule_id).held == GRANT
    # GUARD_ALICE starts at 100_000 in this harness; the grant left for the book.
    assert chain.balances[GUARD_ALICE] == 100_000 - GRANT
    assert [e["outcome"] for e in result.next_snapshot.metadata["payout_events"]] == [
        "installed"]


# --- drawing ---------------------------------------------------------------------

def test_grant_draw_comes_out_of_the_escrow(evs):
    ch, oracle, tx = _installed()
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 1200})], height=HEIGHT + 1, ts=TS + 1)
    _drawn(oracle, legs=[(BOB, 1200)], ts=TS + 1)
    oracle.check(ch)
    state = _state(ch, tx)
    assert (state.executions, state.paid_total) == (1, 1200)
    assert (state.held, state.drawn) == (3800, 1200)
    assert ch.lm.payout_rules.escrow_total() == 3800
    # The rule judged the escrow, not the account: i2 was the held 5,000.
    assert evs["payout_apply"].output_calls[0][1]["i2"] == "5000"


def test_grant_draw_over_the_held_balance_is_refused(evs):
    ch, oracle, tx = _installed(cap_exec=10_000, cap_period=10_000)
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 6000})], height=HEIGHT + 1)
    assert result.outcomes[0].reason == "payout_not_executed"
    assert "the grant holds 5000" in _logs(result)
    assert _state(ch, tx).executions == 0
    oracle.check(ch)
    # A refused execution does not consume the executor's sequence: the same
    # sequence pays the whole grant out, then nothing is left to draw.
    ch.block([exec_tx(seq=0, rule_id=rid(tx), data={"0": 5000})], height=HEIGHT + 2,
             ts=TS + 2)
    _drawn(oracle, legs=[(BOB, 5000)], ts=TS + 2)
    assert _state(ch, tx).held == 0
    drained = ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 1})],
                       height=HEIGHT + 3)
    assert "the grant holds 0" in _logs(drained)
    oracle.check(ch)


def test_grant_frozen_payer_draw_is_refused(evs):
    FREEZE = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
    ch, oracle, tx = _installed()
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = FREEZE
    evs["apply"].set_verdict(FREEZE, lambda inputs: 0)    # blocks every transfer
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 1,
                      ts=TS + 1)
    assert result.outcomes[0].reason == "payout_not_executed"
    assert "o5" in _logs(result)
    assert _state(ch, tx).held == GRANT
    oracle.check(ch)
    assert evs["apply"].verdict_calls  # the payer's o5 clause WAS consulted
    # Unfrozen, the same draw pays out of the escrow: the refused execution
    # did not consume the executor's sequence.
    evs["apply"].set_verdict(FREEZE, lambda inputs: 1)
    ch.block([exec_tx(seq=0, rule_id=rid(tx), data={"0": 30})], height=HEIGHT + 2,
             ts=TS + 2)
    _drawn(oracle, legs=[(BOB, 30)], ts=TS + 2)
    assert _state(ch, tx).held == GRANT - 30
    oracle.check(ch)


# --- the deadline ----------------------------------------------------------------

def test_grant_deadline_refunds_the_remainder(evs):
    """gmikeyg's case 5: 5,000 granted, 1,200 drawn, 3,800 refunded."""
    ch, oracle, tx = _installed()
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 1200})], height=HEIGHT + 1, ts=TS + 1)
    _drawn(oracle, legs=[(BOB, 1200)], ts=TS + 1)
    ch.block([], height=DEADLINE)
    oracle.bal[ALICE] += 3800
    oracle.check(ch)
    assert ch.lm.payout_rules.get(ALICE) is None
    assert ch.lm.payout_rules.escrow_total() == 0
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                            "outcome": "refunded", "grant_amount": GRANT,
                            "drawn": 1200, "refunded": 3800}]
    # No further draw is possible: the rule is gone.
    result = ch.block([exec_tx(seq=1, rule_id=rid(tx), data={"0": 1})],
                      height=DEADLINE + 1)
    assert "no payout rule with that id" in _logs(result)
    oracle.check(ch)


def test_grant_draw_at_the_deadline_is_refused_then_the_remainder_refunds(evs):
    ch, oracle, tx = _installed()
    result = ch.block([exec_tx(rule_id=rid(tx), data={"0": 1})], height=DEADLINE)
    assert result.outcomes[0].reason == "payout_not_executed"
    assert "grant deadline has passed" in _logs(result)
    # The refund runs at the end of the same block: the draw was refused
    # because the deadline was reached, and the node refunds right after.
    oracle.bal[ALICE] += GRANT
    oracle.check(ch)
    assert _events(ch)[0]["outcome"] == "refunded"


def test_grant_deadline_equal_to_expiry_refunds_not_expires(evs):
    ch, oracle, tx = _installed(expires_at=HEIGHT + 5, grant_deadline=HEIGHT + 5)
    ch.block([], height=HEIGHT + 5)
    oracle.bal[ALICE] += GRANT
    oracle.check(ch)
    assert _events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                            "outcome": "refunded", "grant_amount": GRANT,
                            "drawn": 0, "refunded": GRANT}]


def test_grant_deadline_on_the_seconds_clock_refunds(evs):
    ch, oracle, tx = _installed(clock="period_seconds", period=3600,
                                expires_at=TS + 86_400, grant_deadline=TS + 3600)
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 1200})], height=HEIGHT + 1,
             ts=TS + 10)
    _drawn(oracle, legs=[(BOB, 1200)], ts=TS + 10)
    ch.block([], height=HEIGHT + 2, ts=TS + 3600)
    oracle.bal[ALICE] += 3800
    oracle.check(ch)
    assert _events(ch)[0]["outcome"] == "refunded"


def test_grant_due_run_draws_from_the_escrow(evs):
    ch, oracle, tx = _installed(rule=DUE_RULE, due_at=HEIGHT + 10)
    ch.block([], height=HEIGHT + 10)
    oracle.bal[BOB] += 1200
    oracle.lts[ALICE] = TS
    oracle.check(ch)
    assert _state(ch, tx).held == 3800
    assert _events(ch)[0]["outcome"] == "executed"
    ch.block([], height=DEADLINE)
    oracle.bal[ALICE] += 3800
    oracle.check(ch)
    assert _events(ch)[0]["outcome"] == "refunded"


# --- revoking and updating ----------------------------------------------------------

def test_grant_revoke_refunds_the_remainder(evs):
    ch, oracle, tx = _installed()
    ch.block([exec_tx(rule_id=rid(tx), data={"0": 1200})], height=HEIGHT + 1, ts=TS + 1)
    _drawn(oracle, legs=[(BOB, 1200)], ts=TS + 1)
    revoke = revoke_tx(rule_id=rid(tx))
    ch.block([revoke], height=HEIGHT + 2)
    oracle.cancel(ALICE)
    oracle.bal[ALICE] += 3800
    oracle.check(ch)
    assert ch.lm.payout_rules.get(ALICE) is None
    assert _events(ch)[0] == {"account_pubkey": ALICE, "rule_id": rid(tx),
                              "outcome": "revoked", "tx_id": revoke["tx_id"],
                              "refunded": 3800}


def test_grant_update_is_refused(evs):
    ch, oracle, tx = _installed()
    result = ch.block([update_tx(rid(tx), seq=1, cap_exec=4000)], height=HEIGHT + 1)
    assert result.outcomes[0].reason == "payout_rule_not_updated"
    assert "not updated" in _logs(result)
    assert _state(ch, tx).held == GRANT
    oracle.check(ch)
    # A plain rule cannot be updated into a grant either.
    plain = set_tx(seq=1, grant_amount=None, grant_deadline=None)
    ch.block([plain], height=HEIGHT + 2)
    oracle.create(plain, fee=0)
    oracle.check(ch)
    result = ch.block([update_tx(rid(plain), seq=2)], height=HEIGHT + 3)
    assert result.outcomes[0].reason == "payout_rule_not_updated"
    oracle.check(ch)


# --- the book ----------------------------------------------------------------------

def test_grant_rule_restores_with_its_escrow():
    tx = set_tx()
    terms = parse_payout_rule_set(tx)
    book = PayoutBook()
    book.install(terms, HEIGHT)
    book.record(ALICE, terms.rule_id, 1200, HEIGHT + 1, TS + 1)
    rows = book.store_rows()
    assert len(rows[0][18]) == 14  # `more` carries the grant pair
    restored = PayoutBook.restore(rows, *book.resolved_state())
    assert restored.root() == book.root()
    assert restored.escrow_total() == 3800
    state = restored.state_of(ALICE, terms.rule_id)
    assert (state.held, state.drawn) == (3800, 1200)
    assert restored.get(ALICE).grant_amount == GRANT


def test_grant_spec_text_carries_the_grant_fields():
    tx = set_tx()
    terms = parse_payout_rule_set(tx)
    assert terms.grant_amount == GRANT and terms.grant_deadline == DEADLINE
    # The same terms without the grant are a different rule.
    plain = set_tx(grant_amount=None, grant_deadline=None)
    assert parse_payout_rule_set(plain).rule_id != terms.rule_id
    # An update that only adds a grant is refused at the book, not the id.
    _, _, new_terms = parse_payout_rule_update(
        update_tx(rid(plain), grant_amount=GRANT, grant_deadline=DEADLINE))
    book = PayoutBook()
    book.install(parse_payout_rule_set(plain), HEIGHT)
    ok, why = book.can_admit_update(ALICE, parse_payout_rule_set(plain).rule_id,
                                    new_terms, HEIGHT + 1, TS + 1)
    assert not ok and "not updated" in why
