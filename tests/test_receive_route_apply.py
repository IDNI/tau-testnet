"""Block-apply semantics for receive routes (#35).

Every scenario runs through the real `apply_block` with a scripted interpreter
and compares the FULL balance map, sequences and cooldown stamps against an
oracle that knows only the documented rules:

  * a route costs its owner one fee to set and moves no money; removing it and
    a destination's release are fee-free;
  * every payment credited to the owner splits: routed = floor(gross * bps /
    10000) to the destination (0 below min_amount), the rest to the owner;
  * the payer's debit, fee and cooldown stamp are what they are without a route;
  * routed: transfers, approved transfers, retractable releases, standing
    payments, payout legs. Not routed: retract refunds, faucet grants, fees,
    and money arriving through another route (one hop).

`apply_block` itself raises on any supply drift, so every block here is also a
conservation check.

The acceptance cases of the issue, by number:
  1 split and rounding ........ test_a_transfer_is_split_by_the_documented_rounding
  2 recipient online/offline .. test_the_owner_need_not_be_online
  3 no bypass ................. the credit-class section
  4 unsafe routes refused ..... test_unsafe_routes_are_refused, ..._back_to_the_owner
  5 protected admin ........... the guard and lock sections, test_receive_route_guard.py
  6 receipts and history ...... test_the_split_is_in_the_block_events (+ integration)
  7 replay and restore ........ test_replay_gives_the_same_state, integration round trip
  8 capability and check ...... test_receive_route_integration.py
"""
import json

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from consensus import sender_policy
from consensus.governance import build_mechanism_metadata
from consensus.policy_mock import MockPolicyEvaluator
from consensus.receive_route import (
    ReceiveRouteBook,
    RouteTerms,
    parse_receive_route_set,
)

from tests.test_standing_apply import (
    ALICE, BOB, CAROL, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, Oracle, _logs, _sign,
    create_tx, sid_of, spend_tx,
)
from tests.test_retractable_apply import park_tx, retract_tx, rid_of

DAVE = G2Basic.SkToPk(77777).hex()
NOT_A_KEY = "ab" * 48

_N = iter(range(10**9))


def route_tx(sender=BOB, seq=0, *, dest=DAVE, share=2000, fee_limit="100", **extra):
    tx = {"tx_id": f"route-{next(_N)}", "tx_type": "receive_route_set",
          "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
          "expire_at_height": 1000, "fee_limit": str(fee_limit),
          "destination_pubkey": dest, "share_bps": share}
    tx.update({k: v for k, v in extra.items() if v is not None})
    return _sign(tx, SKS[sender])


def remove_tx(sender=BOB, seq=1):
    return _sign({"tx_id": f"remove-{next(_N)}", "tx_type": "receive_route_remove",
                  "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
                  "expire_at_height": 1000, "fee_limit": "0"}, SKS[sender])


def release_tx(route_id, *, owner=BOB, signer=CAROL, seq=0):
    return _sign({"tx_id": f"release-{next(_N)}", "tx_type": "receive_route_release",
                  "sender_pubkey": signer, "sequence_number": seq, "expiration_time": FAR,
                  "expire_at_height": 1000, "fee_limit": "0", "owner_pubkey": owner,
                  "route_id": route_id}, SKS[signer])


def multi_spend(sender, legs, seq, fee_limit="100"):
    return _sign({"tx_id": f"multi-{next(_N)}", "tx_type": "user_tx",
                  "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
                  "expire_at_height": 1000, "fee_limit": str(fee_limit),
                  "operations": {"1": [[sender, to, amount] for to, amount in legs]}},
                 SKS[sender])


def route_id(tx) -> str:
    return parse_receive_route_set(tx).route_id.hex()


def _bal():
    return {ALICE: 10_000, BOB: 50, CAROL: 50, PROPOSER: 0}


def _routed(fee=0, **kw):
    """A chain where BOB routes a share of what it receives (20% to DAVE by default)."""
    ch, oracle = Chain(_bal(), fee=fee), Oracle(_bal())
    tx = route_tx(**kw)
    ch.block([tx])
    oracle.create(tx, fee=fee)
    return ch, oracle, tx


def _events(ch):
    return ch.last.next_snapshot.metadata["route_events"]


def _splits(ch):
    return [(e["credit_class"], e["gross"], e["routed"], e["net"])
            for e in _events(ch) if e["outcome"] == "routed"]


def _reason(result, tx):
    return next(o for o in result.outcomes if o.tx_id == tx["tx_id"]).reason


def _paid(oracle, payer, owner, gross, routed, *, dest=DAVE, fee=0, ts=TS):
    """A transfer payer -> owner that the route split."""
    oracle.bal[payer] -= gross + fee
    oracle.bal[PROPOSER] += fee
    oracle.bal[owner] += gross - routed
    oracle.bal[dest] += routed
    oracle.seq[payer] += 1
    oracle.lts[payer] = ts


# --- setting a route -----------------------------------------------------------

def test_set_charges_one_fee_and_moves_no_money():
    ch, oracle, tx = _routed(fee=7)
    oracle.check(ch)
    assert ch.lm.receive_routes.get(BOB).route_id.hex() == route_id(tx)
    assert _events(ch) == [{"outcome": "installed", "owner_pubkey": BOB,
                            "destination_pubkey": DAVE, "route_id": route_id(tx),
                            "tx_id": tx["tx_id"]}]


@pytest.mark.parametrize("over, why", [
    ({"dest": BOB}, "its own account"),
    ({"share": 9_001}, "share_bps must be in 1..9000"),
    ({"share": 0}, "share_bps must be in 1..9000"),
    ({"share": 10_001}, "share_bps must be an integer in 0..10000"),
    ({"share": True}, "share_bps must be an integer"),
    ({"locked": True}, "a locked route needs an end"),
    ({"locked": "yes"}, "locked must be true or false"),
    ({"expires_at": TS}, "expires_at must be in the future"),
    ({"active_from": TS + 100, "expires_at": TS + 100}, "end before it starts"),
    ({"active_from": TS + 31_622_401}, "active_from is more than"),
    ({"expires_at": TS + 4 * 31_622_400 + 1}, "expires_at is more than"),
    ({"locked": True, "expires_at": TS + 31_622_401}, "a locked route must end within"),
    ({"min_amount": tau_defs.MAX_TRANSFER_VALUE + 1}, "min_amount must be at most"),
])
def test_unsafe_routes_are_refused(over, why):
    ch, oracle = Chain(_bal(), fee=7), Oracle(_bal())
    tx = route_tx(**over)
    result = ch.block([tx])
    assert _reason(result, tx) == "receive_route_not_set"
    assert why in _logs(result)
    assert ch.lm.receive_routes.is_empty()
    oracle.check(ch)   # no fee, no sequence: the transaction did not land


def test_a_destination_that_is_not_a_key_is_refused():
    ch, oracle = Chain(_bal()), Oracle(_bal())
    tx = route_tx(dest=NOT_A_KEY)
    result = ch.block([tx])
    assert "destination_pubkey" in _logs(result)
    assert ch.lm.receive_routes.is_empty()
    oracle.check(ch)


def test_a_route_back_to_the_owner_is_refused():
    """A -> B while B -> A: the loop the issue rules out, refused at the second set."""
    ch, oracle = Chain(_bal()), Oracle(_bal())
    first = route_tx(sender=CAROL, dest=BOB)
    second = route_tx(sender=BOB, dest=CAROL)
    result = ch.block([first, second])
    oracle.create(first, fee=0)
    assert _reason(result, second) == "receive_route_not_set"
    assert "routes back to this account" in _logs(result)
    oracle.check(ch)


def test_a_new_route_replaces_the_old_one_and_the_root_remembers():
    ch, oracle, first = _routed()
    root = ch.lm.receive_routes.root()
    second = route_tx(seq=1, share=3000)
    ch.block([second], height=HEIGHT + 1)
    oracle.create(second, fee=0)
    oracle.check(ch)
    assert ch.lm.receive_routes.get(BOB).share_bps == 3000
    assert _events(ch)[0]["replaced"] == route_id(first)
    assert ch.lm.receive_routes.root() != root
    assert ch.lm.receive_routes.resolved_count == 1


# --- the split -------------------------------------------------------------------

def test_a_transfer_is_split_by_the_documented_rounding():
    ch, oracle, _ = _routed()
    pay = spend_tx(ALICE, BOB, 101, 0)
    ch.block([pay], height=HEIGHT + 1)
    _paid(oracle, ALICE, BOB, 101, 20)
    oracle.check(ch)
    assert ch.bal[BOB] == 50 + 81 and ch.bal[DAVE] == 20
    assert _splits(ch) == [("transfer", 101, 20, 81)]


def test_each_transfer_of_a_transaction_splits_on_its_own():
    ch, oracle, _ = _routed()
    pay = multi_spend(ALICE, [(BOB, 101), (BOB, 9), (CAROL, 50)], 0)
    ch.block([pay], height=HEIGHT + 1)
    oracle.bal[ALICE] -= 160
    oracle.bal[BOB] += 81 + 8
    oracle.bal[DAVE] += 20 + 1
    oracle.bal[CAROL] += 50
    oracle.seq[ALICE] += 1
    oracle.lts[ALICE] = TS
    oracle.check(ch)
    assert _splits(ch) == [("transfer", 101, 20, 81), ("transfer", 9, 1, 8)]


@pytest.mark.parametrize("gross, routed", [(4, 0), (5, 1), (99, 19), (100, 20)])
def test_small_credits_round_down(gross, routed):
    ch, oracle, _ = _routed()
    ch.block([spend_tx(ALICE, BOB, gross, 0)], height=HEIGHT + 1)
    _paid(oracle, ALICE, BOB, gross, routed)
    oracle.check(ch)
    assert len(_splits(ch)) == (1 if routed else 0)


def test_a_credit_below_the_minimum_is_not_routed():
    ch, oracle, _ = _routed(min_amount=100)
    ch.block([spend_tx(ALICE, BOB, 99, 0), spend_tx(ALICE, BOB, 100, 1)], height=HEIGHT + 1)
    _paid(oracle, ALICE, BOB, 99, 0)
    _paid(oracle, ALICE, BOB, 100, 20)
    oracle.check(ch)


def test_the_payer_pays_its_own_fee_and_nothing_more():
    ch, oracle, _ = _routed(fee=5)
    ch.block([spend_tx(ALICE, BOB, 1000, 0)], height=HEIGHT + 1)
    _paid(oracle, ALICE, BOB, 1000, 200, fee=5)
    oracle.check(ch)


def test_the_owner_need_not_be_online():
    """Acceptance 2: the owner signs nothing after the route; every block that
    pays it splits, whoever proposes it."""
    ch, oracle, _ = _routed()
    ch.block([spend_tx(ALICE, BOB, 500, 0)], height=HEIGHT + 1, proposer=CAROL)
    ch.block([spend_tx(CAROL, BOB, 50, 0)], height=HEIGHT + 2, proposer=PROPOSER)
    _paid(oracle, ALICE, BOB, 500, 100)
    _paid(oracle, CAROL, BOB, 50, 10)
    oracle.check(ch)


def test_a_route_counts_from_the_transaction_after_it():
    ch, oracle = Chain(_bal()), Oracle(_bal())
    before, route, after = (spend_tx(ALICE, BOB, 100, 0), route_tx(),
                            spend_tx(ALICE, BOB, 100, 1))
    ch.block([before, route, after])
    _paid(oracle, ALICE, BOB, 100, 0)
    oracle.create(route, fee=0)
    _paid(oracle, ALICE, BOB, 100, 20)
    oracle.check(ch)


def test_a_scheduled_route_waits_for_its_start():
    ch, oracle, _ = _routed(active_from=TS + 100)
    ch.block([spend_tx(ALICE, BOB, 100, 0)], height=HEIGHT + 1, ts=TS + 99)
    _paid(oracle, ALICE, BOB, 100, 0, ts=TS + 99)
    ch.block([spend_tx(ALICE, BOB, 100, 1)], height=HEIGHT + 2, ts=TS + 100)
    _paid(oracle, ALICE, BOB, 100, 20, ts=TS + 100)
    oracle.check(ch)


def test_a_route_ends_at_its_end_and_leaves_the_book():
    ch, oracle, tx = _routed(expires_at=TS + 50)
    ch.block([spend_tx(ALICE, BOB, 100, 0)], height=HEIGHT + 1, ts=TS + 49)
    _paid(oracle, ALICE, BOB, 100, 20, ts=TS + 49)
    ch.block([spend_tx(ALICE, BOB, 100, 1)], height=HEIGHT + 2, ts=TS + 50)
    _paid(oracle, ALICE, BOB, 100, 0, ts=TS + 50)
    oracle.check(ch)
    assert ch.lm.receive_routes.get(BOB) is None
    assert [e["outcome"] for e in _events(ch)] == ["expired"]


def test_a_rejected_transaction_splits_nothing():
    ch, oracle, _ = _routed()
    bad = multi_spend(ALICE, [(BOB, 100), (CAROL, 99_999)], 0)
    result = ch.block([bad], height=HEIGHT + 1)
    outcome = next(o for o in result.outcomes if o.tx_id == bad["tx_id"])
    assert outcome.status == "invalid" and _events(ch) == []
    assert "insufficient" in _logs(result)
    oracle.check(ch)


def test_the_split_is_in_the_block_events():
    ch, _o, route = _routed()
    pay = spend_tx(ALICE, BOB, 250, 0)
    ch.block([pay], height=HEIGHT + 1)
    assert _events(ch) == [{
        "outcome": "routed", "owner_pubkey": BOB, "destination_pubkey": DAVE,
        "route_id": route_id(route), "credit_class": "transfer", "gross": 250,
        "routed": 50, "net": 200, "payer_pubkey": ALICE, "tx_id": pay["tx_id"],
    }]


# --- credit classes: what is routed, what is not ---------------------------------

def test_a_retractable_release_is_routed():
    ch, oracle, _ = _routed()
    park = park_tx(amount=300, at_height=HEIGHT + 3)
    ch.block([park], height=HEIGHT + 1)
    oracle.bal[ALICE] -= 300
    oracle.seq[ALICE] += 1
    oracle.lts[ALICE] = TS
    ch.block([], height=HEIGHT + 3)
    oracle.bal[BOB] += 240
    oracle.bal[DAVE] += 60
    oracle.check(ch)
    event = _events(ch)[0]
    assert (event["credit_class"], event["routed"]) == ("retractable_release", 60)
    assert event["retractable_id"] == rid_of(park) and event["payer_pubkey"] == ALICE


def test_a_retract_refund_is_not_routed():
    """ALICE routes what she receives; her own money coming back is not received."""
    ch, oracle = Chain(_bal()), Oracle(_bal())
    route = route_tx(sender=ALICE, dest=DAVE, share=5000)
    park = park_tx(amount=300, seq=1, at_height=HEIGHT + 9)
    ch.block([route, park])
    ch.block([retract_tx(rid_of(park), seq=2)], height=HEIGHT + 1)
    oracle.seq[ALICE] += 3
    oracle.lts[ALICE] = TS
    oracle.check(ch)
    assert ch.bal.get(DAVE, 0) == 0


def test_a_standing_payment_is_routed():
    ch, oracle, _ = _routed()
    create = create_tx(amount=100, first_due=HEIGHT + 5, periods=1)
    ch.block([create], height=HEIGHT + 1)
    oracle.create(create, fee=0)
    ch.block([], height=HEIGHT + 5)
    oracle.pay(ALICE, BOB, 100, ts=TS)
    oracle.bal[BOB] -= 20
    oracle.bal[DAVE] += 20
    oracle.check(ch)
    event = _events(ch)[0]
    assert (event["credit_class"], event["standing_id"]) == ("standing_payment", sid_of(create))


def test_a_payout_leg_is_routed():
    from tests.test_payout_apply import BODY, _data_rule, exec_tx, rid, set_tx

    ev = MockPolicyEvaluator(pool="payout_apply")
    ev.set_outputs(BODY, _data_rule)
    sender_policy.set_evaluator("payout_apply", ev)
    try:
        ch, oracle, _ = _routed()
        rule = set_tx(sender=ALICE, slots=[BOB], expires_at=HEIGHT + 500)
        ch.block([rule], height=HEIGHT + 1)
        oracle.create(rule, fee=0)
        ch.block([exec_tx(executor=CAROL, rule_id=rid(rule), data={"0": 50})],
                 height=HEIGHT + 2)
        oracle.seq[CAROL] += 1
        oracle.bal[ALICE] -= 50
        oracle.bal[BOB] += 40
        oracle.bal[DAVE] += 10
        oracle.lts[ALICE] = TS
        oracle.check(ch)
        assert _splits(ch) == [("payout", 50, 10, 40)]
    finally:
        sender_policy.set_evaluator("payout_apply", None)


def test_an_approved_transfer_is_routed():
    from tests.test_approval_apply import ALICE as A, BOB as B, _apply, _balances, \
        _lm, _request, request_tx, vote_tx

    lm = _lm()
    lm.receive_routes.install(RouteTerms(B, 0, DAVE, 2500))
    req = _request(amount=5000)
    result, _post, _ = _apply([request_tx(req), vote_tx(req)], lm=lm)
    bal = _balances(result)
    assert (bal[B], bal[DAVE], bal[A]) == (3750, 1250, 100000 - 5000)
    event = result.next_snapshot.metadata["route_events"][0]
    assert (event["credit_class"], event["routed"]) == ("approved_transfer", 1250)


def test_a_fee_is_not_routed():
    ch, oracle = Chain(_bal(), fee=10), Oracle(_bal())
    ch.lm.receive_routes.install(RouteTerms(PROPOSER, 0, DAVE, 5000))
    ch.block([spend_tx(ALICE, BOB, 100, 0)])
    _paid(oracle, ALICE, BOB, 100, 0, fee=10)
    oracle.check(ch)


def test_a_faucet_grant_is_not_routed():
    """A new owner's grant is its own; the transfer that brought it is split.
    The destination, new too, gets its grant as any new recipient does."""
    grant = 500
    ch = Chain({ALICE: 10_000, PROPOSER: 0}, faucet=grant)
    ch.seq[ALICE] = 1
    ch.lm.receive_routes.install(RouteTerms(BOB, 0, DAVE, 2000))
    ch.block([spend_tx(ALICE, BOB, 100, 1)])
    assert (ch.bal[BOB], ch.bal[DAVE]) == (grant + 80, grant + 20)


def test_a_routed_share_is_never_routed_again():
    """DAVE routes everything it receives on to CAROL, but money that reaches
    DAVE through BOB's route stays with DAVE: one hop."""
    ch, oracle, _ = _routed()
    ch.lm.receive_routes.install(RouteTerms(DAVE, 0, CAROL, 9000))
    ch.block([spend_tx(ALICE, BOB, 100, 0)], height=HEIGHT + 1)
    _paid(oracle, ALICE, BOB, 100, 20)
    oracle.check(ch)
    assert len(_splits(ch)) == 1


def test_a_destination_may_pay_the_owner_and_be_paid_back():
    """CAROL pays BOB; BOB's route sends half straight back to CAROL. One hop,
    staged through one view: CAROL's fee reads her balance after the share."""
    ch, oracle = Chain(_bal(), fee=3), Oracle(_bal())
    ch.lm.receive_routes.install(RouteTerms(BOB, 0, CAROL, 5000))
    ch.block([spend_tx(CAROL, BOB, 40, 0)])
    _paid(oracle, CAROL, BOB, 40, 20, dest=CAROL, fee=3)
    oracle.check(ch)


# --- removing and locking --------------------------------------------------------

def test_remove_is_fee_free_and_stops_routing():
    ch, oracle, tx = _routed(fee=5)
    ch.block([remove_tx(), spend_tx(ALICE, BOB, 100, 0)], height=HEIGHT + 1)
    oracle.cancel(BOB)
    _paid(oracle, ALICE, BOB, 100, 0, fee=5)
    oracle.check(ch)
    assert ch.lm.receive_routes.get(BOB) is None
    assert _events(ch)[0]["outcome"] == "removed"


def test_removing_nothing_is_refused():
    ch, oracle = Chain(_bal()), Oracle(_bal())
    tx = remove_tx(seq=0)
    result = ch.block([tx])
    assert _reason(result, tx) == "receive_route_not_removed"
    oracle.check(ch)


LOCK_END = TS + 1000


def _locked(**kw):
    return _routed(dest=CAROL, locked=True, expires_at=LOCK_END, **kw)


def test_a_locked_route_cannot_be_removed_or_weakened_by_its_owner():
    ch, oracle, tx = _locked()
    weaker = [route_tx(seq=1, dest=CAROL, share=1000, locked=True, expires_at=LOCK_END),
              route_tx(seq=1, dest=DAVE, share=2000, locked=True, expires_at=LOCK_END),
              route_tx(seq=1, dest=CAROL, share=2000, locked=True, expires_at=LOCK_END - 1),
              route_tx(seq=1, dest=CAROL, share=2000, expires_at=LOCK_END),
              route_tx(seq=1, dest=CAROL, share=2000, locked=True, expires_at=LOCK_END,
                       min_amount=10),
              route_tx(seq=1, dest=CAROL, share=2000, locked=True, expires_at=LOCK_END,
                       active_from=TS + 10),
              remove_tx()]
    for i, bad in enumerate(weaker):
        result = ch.block([bad], height=HEIGHT + 1 + i, ts=TS + 1)
        assert "locked until" in _logs(result), bad
    assert ch.lm.receive_routes.get(BOB).route_id.hex() == route_id(tx)
    oracle.check(ch)


def test_a_locked_route_can_be_strengthened():
    ch, oracle, _ = _locked()
    stronger = route_tx(seq=1, dest=CAROL, share=2500, locked=True, expires_at=LOCK_END + 10)
    ch.block([stronger], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(stronger, fee=0)
    oracle.check(ch)
    assert ch.lm.receive_routes.get(BOB).share_bps == 2500


def test_only_the_destination_releases_a_locked_route():
    ch, oracle, tx = _locked()
    by_owner = release_tx(route_id(tx), signer=BOB, seq=1)
    stale = release_tx("00" * 32)
    ch.block([by_owner, stale], height=HEIGHT + 1, ts=TS + 1)
    assert ch.lm.receive_routes.get(BOB) is not None
    assert "only the route's destination" in _logs(ch.last)
    assert "not the one named" in _logs(ch.last)
    ok = release_tx(route_id(tx))
    ch.block([ok, spend_tx(ALICE, BOB, 100, 0)], height=HEIGHT + 2, ts=TS + 2)
    oracle.cancel(CAROL)
    _paid(oracle, ALICE, BOB, 100, 0, dest=CAROL, ts=TS + 2)
    oracle.check(ch)
    assert ch.lm.receive_routes.get(BOB) is None
    assert _events(ch)[0]["outcome"] == "released"


def test_a_locked_route_frees_its_owner_when_it_ends():
    ch, oracle, _ = _locked()
    ch.block([], height=HEIGHT + 1, ts=LOCK_END)
    assert ch.lm.receive_routes.get(BOB) is None
    again = route_tx(seq=1, dest=DAVE, share=1000)
    ch.block([again], height=HEIGHT + 2, ts=LOCK_END + 1)
    oracle.create(again, fee=0)
    oracle.check(ch)


# --- the guard -------------------------------------------------------------------

GUARD = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


@pytest.fixture
def guard_evaluator():
    ev = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", ev)
    yield ev
    sender_policy.set_evaluator("apply", None)


def test_a_guard_that_blocks_changes_blocks_set_and_remove(guard_evaluator):
    ch, oracle, tx = _routed(dest=CAROL)
    ch.lm.rule_offers.accepted_clauses[(BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD
    guard_evaluator.set_verdict(GUARD, lambda inputs: 0)
    result = ch.block([route_tx(seq=1, dest=DAVE), remove_tx(seq=1)], height=HEIGHT + 1)
    assert [o.reason for o in result.outcomes] == ["receive_route_not_set",
                                                   "receive_route_not_removed"]
    assert "use a rule-change request" in _logs(result)
    kinds = [c[1]["i1"] for c in guard_evaluator.verdict_calls]
    assert kinds == [str(tau_defs.RULE_CHANGE_KIND_SET_ROUTE),
                     str(tau_defs.RULE_CHANGE_KIND_REMOVE_ROUTE)]
    # The destination's release is not the owner's rule change.
    ch.block([release_tx(route_id(tx))], height=HEIGHT + 2)
    oracle.cancel(CAROL)
    oracle.check(ch)
    assert ch.lm.receive_routes.get(BOB) is None


def test_a_guard_that_allows_lets_the_change_through(guard_evaluator):
    ch = Chain(_bal())
    ch.lm.rule_offers.accepted_clauses[(BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD
    guard_evaluator.set_verdict(GUARD, lambda inputs: 1)
    ch.block([route_tx()])
    assert ch.lm.receive_routes.get(BOB) is not None


# --- the state commitment --------------------------------------------------------

def test_an_empty_book_stays_out_of_the_metadata():
    assert "receive_routes_root" not in build_mechanism_metadata(
        [], "", 1, receive_routes_root="")


def test_the_state_hash_moves_with_the_book_and_not_before():
    a, _o, _tx = _routed()
    b = Chain(_bal())
    b.block([])
    c = Chain(_bal())
    c.lm.receive_routes = ReceiveRouteBook()
    c.block([])
    assert b.hashes[-1] == c.hashes[-1]
    assert a.hashes[-1] != b.hashes[-1]
    before = a.hashes[-1]
    a.block([remove_tx()], height=HEIGHT + 1)
    assert a.hashes[-1] != before
    assert "receive_routes_root" in build_mechanism_metadata(
        [], "", 1, receive_routes_root=a.lm.receive_routes.root().hex())


def test_replay_gives_the_same_state():
    """Acceptance 7: the same blocks, mined and replayed, land in the same state."""
    runs = []
    for replay in (False, True):
        ch, _o, _tx = _routed()
        park = park_tx(amount=300, at_height=HEIGHT + 3)
        ch.block([spend_tx(ALICE, BOB, 101, 0), park], height=HEIGHT + 1, replay=replay)
        ch.block([], height=HEIGHT + 3, replay=replay)
        ch.block([remove_tx()], height=HEIGHT + 4, replay=replay)
        runs.append((list(ch.hashes), dict(ch.bal)))
    assert runs[0] == runs[1]


def test_a_block_does_not_touch_its_parents_book():
    ch, _o, _tx = _routed()
    parent_book = ch.lm.receive_routes
    rows = json.dumps([list(map(str, r)) for r in parent_book.store_rows()])
    ch.block([remove_tx()], height=HEIGHT + 1)
    assert json.dumps([list(map(str, r)) for r in parent_book.store_rows()]) == rows
    assert ch.lm.receive_routes is not parent_book


def test_a_standing_payment_paid_by_an_execute_is_routed_the_same_way():
    from tests.test_standing_execute_update import execute_tx

    ch, oracle, _ = _routed()
    create = create_tx(amount=100, first_due=HEIGHT + 5, periods=1)
    ch.block([create], height=HEIGHT + 1)
    oracle.create(create, fee=0)
    ch.block([execute_tx(sid_of(create), sender=CAROL, seq=0, fee_limit="0")],
             height=HEIGHT + 5)
    oracle.pay(ALICE, BOB, 100, ts=TS)
    oracle.create({"sender_pubkey": CAROL}, fee=0)
    oracle.bal[BOB] -= 20
    oracle.bal[DAVE] += 20
    oracle.check(ch)
    event = _events(ch)[0]
    assert (event["credit_class"], event["standing_id"]) == ("standing_payment", sid_of(create))
