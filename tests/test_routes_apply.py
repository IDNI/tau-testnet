"""Receive routes (#35) through the real `apply_block`.

Every scenario runs with a scripted interpreter and mock policy evaluators:
o5 clauses in the `apply` pool, payout rules in `payout_apply`, receive
routes in `route_apply`. Each compares the FULL balance map, sequences and
cooldown stamps against an oracle that knows only the documented rules:

  * installing costs one fee and moves no money; revoking is fee-free;
  * a transfer into a routed account splits atomically: net to the account,
    routed to the destination, in the same staged writes;
  * a credit below min_amount, outside [active_from, expires_at), or from the
    account itself lands whole; a routed leg never re-routes (single hop);
  * a route that routes more than the gross is refused for this credit and the
    gross lands whole; the sender's transfer settles regardless.
"""
import itertools

import pytest

from consensus import sender_policy
from consensus.payout import payout_rule_body
from consensus.policy_mock import MockPolicyEvaluator
from consensus.routes import parse_route_set

from tests.test_payout_apply import exec_tx, set_tx  # noqa: F401
from tests.test_standing_apply import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _logs, _sign, spend_tx,
)

# The per-sale royalty from tests/test_payout_sales.py, inlined here so this
# module does not pull in the network stack (test_payout_integration).
ROYALTY = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] )."


def _royalty(inputs):
    return {"o30": str(int(inputs.get("i27", "0")) // 20)}

FULL = "always ( o30[t]:bv[24] = i27[t]:bv[24] )."
FIFTH = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] )."
OVER = "always ( o30[t]:bv[24] = i27[t]:bv[24] + { 1 }:bv[24] )."
FULL_BODY = payout_rule_body(FULL)
FIFTH_BODY = payout_rule_body(FIFTH)
OVER_BODY = payout_rule_body(OVER)

_N = iter(range(10 ** 9))


def route_tx(sender=ALICE, seq=0, *, rule=FIFTH, destination=BOB, min_amount=0,
             active_from=0, clock="expiry_blocks", expires_at=HEIGHT + 500,
             fee_limit="100", **extra):
    tx = {"tx_id": f"route-{next(_N)}", "tx_type": "route_set",
          "sender_pubkey": sender, "sequence_number": seq,
          "expiration_time": 9_999_999_999, "expire_at_height": 1000,
          "fee_limit": str(fee_limit), "rule_text": rule, "destination": destination,
          "min_amount": min_amount, "active_from": active_from, clock: expires_at}
    tx.update(extra)
    return _sign(tx, SKS[sender])


def route_revoke_tx(sender=ALICE, seq=1):
    return _sign({"tx_id": f"route-revoke-{next(_N)}", "tx_type": "route_revoke",
                  "sender_pubkey": sender, "sequence_number": seq,
                  "expiration_time": 9_999_999_999, "expire_at_height": 1000,
                  "fee_limit": "0"}, SKS[sender])


def rid(tx) -> str:
    return parse_route_set(tx).rule_id.hex()


def _fifth(inputs):
    return {"o30": str(int(inputs.get("i27", "0")) // 20)}


def _full(inputs):
    return {"o30": inputs.get("i27", "0")}


def _over(inputs):
    return {"o30": str(int(inputs.get("i27", "0")) + 1)}


@pytest.fixture
def revs():
    out = {}
    for pool in ("apply", "payout_apply", "route_apply"):
        out[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, out[pool])
    out["route_apply"].set_outputs(FIFTH_BODY, _fifth)
    out["route_apply"].set_outputs(FULL_BODY, _full)
    out["route_apply"].set_outputs(OVER_BODY, _over)
    out["payout_apply"].set_outputs(payout_rule_body(ROYALTY), _royalty)
    yield out
    for pool in ("apply", "payout_apply", "route_apply"):
        sender_policy.set_evaluator(pool, None)


def _bal():
    return {ALICE: 1_000, BOB: 0, CAROL: 500, PROPOSER: 0}


def _installed(fee=0, **kw):
    ch, oracle = Chain(_bal(), fee=fee), Oracle(_bal())
    tx = route_tx(**kw)
    ch.block([tx])
    oracle.create(tx, fee=fee)
    return ch, oracle, tx


def _route_events(ch):
    return ch.last.next_snapshot.metadata["route_events"]


def _reason(result, tx):
    return next(o for o in result.outcomes if o.tx_id == tx["tx_id"]).reason


def _routed_spend(oracle, sender, to, dest, amount, *, fee=0, ts, proposer=PROPOSER):
    """The oracle side of a routed transfer: the gross moves, then the split."""
    routed = amount // 20
    oracle.spend(sender, to, amount, fee=fee, ts=ts, proposer=proposer)
    oracle.bal[to] -= routed
    oracle.bal[dest] += routed
    return routed


# --- installing ------------------------------------------------------------------


def test_install_charges_one_fee_and_moves_no_money(revs):
    ch, oracle, tx = _installed(fee=7)
    oracle.check(ch)
    assert ch.lm.routes.get(ALICE).rule_id.hex() == rid(tx)
    assert ch.lm.routes.state_of(ALICE).anchor == HEIGHT
    assert _route_events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(tx),
                                  "outcome": "installed", "tx_id": tx["tx_id"]}]
    # Built in the route pool, never stepped at install, never in the o5 pool.
    assert revs["route_apply"].validate_calls == [FIFTH_BODY]
    assert revs["route_apply"].output_calls == []
    assert revs["apply"].validate_calls == []


def test_install_from_the_wrong_sender_and_bad_rules_stay_out(revs):
    ch, oracle, _tx = _installed()
    oracle.check(ch)
    # A route_set names its account from its sender, so BOB installing his
    # OWN route is legitimate -- and ALICE's route is untouched by it.
    other = route_tx(sender=BOB, seq=0, destination=CAROL)
    ch.block([other], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(other, fee=0)
    oracle.check(ch)
    assert ch.lm.routes.get(ALICE).rule_id.hex() == rid(_tx)
    assert ch.lm.routes.get(BOB) is not None
    assert ch.lm.routes.count() == 2

    for over, why in [
            ({"destination": ALICE}, "may not be the account itself"),
            ({"rule": "always ( o31[t]:bv[24] = i27[t]:bv[24] )."}, "not part of the payout ABI"),
            ({"rule": "always ( o30[t]:bv[24] = i13[t]:bv[384] )."}, "may not read i13"),
            ({"expires_at": HEIGHT}, "already ended"),
    ]:
        bad = route_tx(seq=1, **over)
        result = ch.block([bad], height=HEIGHT + 2, ts=TS + 2)
        assert _reason(result, bad) == "route_not_set"
        assert why in _logs(result)
    oracle.check(ch)
    assert ch.lm.routes.count() == 2


def test_install_of_an_unbuildable_rule_stays_out(revs):
    revs["route_apply"].fail_build(FIFTH_BODY, "boom")
    ch, oracle = Chain(_bal()), Oracle(_bal())
    tx = route_tx()
    result = ch.block([tx])
    assert _reason(result, tx) == "route_not_set"
    assert "does not build" in _logs(result)
    oracle.check(ch)
    assert ch.lm.routes.count() == 0


# --- splitting -------------------------------------------------------------------


def test_a_transfer_into_a_routed_account_splits_5_percent(revs):
    ch, oracle, _tx = _installed()
    buy = spend_tx(CAROL, ALICE, 101, 0)
    ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
    _routed_spend(oracle, CAROL, ALICE, BOB, 101, ts=TS + 1)
    oracle.check(ch)
    assert ch.bal[ALICE] == 1_000 + 96 and ch.bal[BOB] == 5
    # The route stepped once, with the arrival's own inputs.
    body, inputs = revs["route_apply"].output_calls[0]
    assert body == FIFTH_BODY
    assert inputs["i27"] == "101" and inputs["i28"] == "#x" + CAROL
    assert inputs["i2"] == "1000"  # the parent balance
    assert inputs["i5"] == str(TS + 1) and inputs["i6"] == str(HEIGHT + 1)


def test_a_full_route_moves_everything_to_the_destination(revs):
    ch, oracle, _tx = _installed(rule=FULL)
    buy = spend_tx(CAROL, ALICE, 101, 0)
    ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
    oracle.spend(CAROL, ALICE, 101, ts=TS + 1)
    oracle.bal[ALICE] -= 101
    oracle.bal[BOB] += 101
    oracle.check(ch)
    assert ch.bal[ALICE] == 1_000 and ch.bal[BOB] == 101


def test_below_the_minimum_and_outside_the_window_land_whole(revs):
    ch, oracle, _tx = _installed(min_amount=200, active_from=HEIGHT + 5)
    small = spend_tx(CAROL, ALICE, 101, 0)
    ch.block([small], height=HEIGHT + 1, ts=TS + 1)
    oracle.spend(CAROL, ALICE, 101, ts=TS + 1)
    oracle.check(ch)
    assert revs["route_apply"].output_calls == []  # never stepped

    big = spend_tx(CAROL, ALICE, 300, 1)
    ch.block([big], height=HEIGHT + 6, ts=TS + 6)
    _routed_spend(oracle, CAROL, ALICE, BOB, 300, ts=TS + 6)
    oracle.check(ch)
    assert ch.bal[BOB] == 15  # 5% of 300, once the window opens


def test_a_routed_leg_never_re_routes(revs):
    # ALICE routes 5% to BOB; BOB routes everything to CAROL. One transfer
    # into ALICE must split once: BOB's route does not fire on the routed leg.
    ch, oracle = Chain(_bal()), Oracle(_bal())
    tx_a = route_tx(sender=ALICE, seq=0)
    ch.block([tx_a])
    oracle.create(tx_a, fee=0)
    tx_b = route_tx(sender=BOB, seq=0, rule=FULL, destination=CAROL)
    ch.block([tx_b], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(tx_b, fee=0)
    buy = spend_tx(CAROL, ALICE, 100, 0)
    ch.block([buy], height=HEIGHT + 2, ts=TS + 2)
    _routed_spend(oracle, CAROL, ALICE, BOB, 100, ts=TS + 2)
    oracle.check(ch)
    assert ch.bal[ALICE] == 1_000 + 95 and ch.bal[BOB] == 5
    assert ch.bal[CAROL] == 500 - 100  # CAROL paid 100, got nothing back
    assert len(revs["route_apply"].output_calls) == 1  # stepped once, not twice


def test_a_rule_that_routes_more_than_the_gross_is_refused_for_this_credit(revs):
    ch, oracle, _tx = _installed(rule=OVER)
    buy = spend_tx(CAROL, ALICE, 101, 0)
    ch.block([buy], height=HEIGHT + 1, ts=TS + 1)
    oracle.spend(CAROL, ALICE, 101, ts=TS + 1)
    oracle.check(ch)
    assert ch.bal[ALICE] == 1_000 + 101 and ch.bal[BOB] == 0
    assert "over the gross credit" in _logs(ch.last)


# --- revoke and expiry -------------------------------------------------------------


def test_revoke_is_fee_free_and_later_transfers_land_whole(revs):
    ch, oracle, _tx = _installed()
    rev = route_revoke_tx()
    ch.block([rev], height=HEIGHT + 1, ts=TS + 1)
    oracle.cancel(ALICE)
    oracle.check(ch)
    assert ch.lm.routes.get(ALICE) is None
    assert _route_events(ch) == [{"account_pubkey": ALICE,
                                  "rule_id": rid(_tx), "outcome": "revoked",
                                  "tx_id": rev["tx_id"]}]
    buy = spend_tx(CAROL, ALICE, 100, 0)
    ch.block([buy], height=HEIGHT + 2, ts=TS + 2)
    oracle.spend(CAROL, ALICE, 100, ts=TS + 2)
    oracle.check(ch)
    assert revs["route_apply"].output_calls == []


def test_expiry_sweeps_the_route_and_later_transfers_land_whole(revs):
    ch, oracle, _tx = _installed(expires_at=HEIGHT + 2)
    buy = spend_tx(CAROL, ALICE, 100, 0)
    ch.block([buy], height=HEIGHT + 2, ts=TS + 2)
    oracle.spend(CAROL, ALICE, 100, ts=TS + 2)
    oracle.check(ch)
    assert ch.lm.routes.get(ALICE) is None
    assert _route_events(ch) == [{"account_pubkey": ALICE, "rule_id": rid(_tx),
                                  "outcome": "expired"}]
    assert revs["route_apply"].output_calls == []  # expired before the credit


def test_a_route_and_a_per_sale_royalty_coexist_on_one_sale(revs):
    ch, oracle = Chain(_bal()), Oracle(_bal())
    rule = set_tx(rule=ROYALTY, per_sale=True, cap_exec=100, cap_period=1_000)
    ch.block([rule])
    oracle.create(rule, fee=0)
    route = route_tx(seq=1)
    ch.block([route], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(route, fee=0)
    buy = spend_tx(CAROL, ALICE, 101, 0)
    ch.block([buy], height=HEIGHT + 2, ts=TS + 2)
    _routed_spend(oracle, CAROL, ALICE, BOB, 101, ts=TS + 2)
    oracle.check(ch)
    # The sale is recorded on the gross (101), the route splits the credit (5).
    state = ch.lm.payout_rules.state_of(ALICE)
    assert len(state.open_sales) == 1 and state.open_sales[0][2] == 101
    assert ch.bal[ALICE] == 1_000 + 96 and ch.bal[BOB] == 5
