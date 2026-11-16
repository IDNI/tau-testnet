"""Random block sequences: the node against a naive reference model (#34).

The model below knows nothing of the book's queue, lists or commitments. Each
block it recomputes, for every open authorization in id order, which period the
block falls in, and then applies the documented rules directly:

  * a period whose window closed unsettled is missed (several at once after a
    gap: no catch-up);
  * the current period is attempted once per block until it is settled:
    paid (funds, policy allows), missed (policy blocks), or retried (no funds);
  * when several are due, they go in the order they joined the line (the block
    they fell due, or the block after an unfunded try), then by id;
  * after the last period, or on cancel, the authorization is gone.

Hypothesis drives creates, cancels, top-ups, policy freezes and height gaps
through the REAL `apply_block` (signature checks stubbed, everything else real),
and after every block the node's balances, open set and per-entry counters must
equal the model's. Any divergence shrinks to a minimal program.
"""
import itertools
from unittest.mock import patch

from hypothesis import HealthCheck, given, settings, strategies as st

from consensus import sender_policy
from consensus.policy_mock import MockPolicyEvaluator
from consensus.standing import MIN_INTERVAL_BLOCKS, parse_standing_payment_create

from consensus.network_binding import BOUND_TX_TYPES, chain_genesis_hash
from tests.test_standing_apply import ALICE, BOB, CAROL, Chain, HEIGHT, TS, CLAUSE

PEOPLE = (ALICE, BOB, CAROL)
_IDS = itertools.count()


def _tx(sender, seq, height, tx_type, **fields):
    tx = {"tx_id": f"m-{next(_IDS)}", "tx_type": tx_type, "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": 9_999_999_999,
          "expire_at_height": height + 1, "fee_limit": "0", "signature": "00"}
    if tx_type in BOUND_TX_TYPES:
        tx["genesis_hash"] = chain_genesis_hash()
    tx.update(fields)
    return tx


class Model:
    def __init__(self, balances):
        self.bal = dict(balances)
        self.open = {}      # sid -> dict(terms, p, paid, missed)
        self.frozen = set()

    def create(self, terms):
        self.open[terms.standing_id] = {"t": terms, "p": 0, "paid": 0, "missed": 0,
                                        "joined": None, "retrying": False}

    def open_for(self, payer):
        return sum(e["t"].payer_pubkey == payer for e in self.open.values())

    def block(self, height):
        for e in self.open.values():
            t = e["t"]
            if e["joined"] is None and height >= t.first_due + e["p"] * t.interval:
                e["joined"] = height
        line = sorted((e["joined"], sid) for sid, e in self.open.items()
                      if e["joined"] is not None and e["joined"] <= height)
        for _, sid in line:
            e = self.open[sid]
            t = e["t"]
            current = min((height - t.first_due) // t.interval, t.periods)
            if current > e["p"]:
                e["missed"] += current - e["p"]
                e["p"], e["retrying"] = current, False
            if e["p"] >= t.periods:
                del self.open[sid]
                continue
            if self.bal.get(t.payer_pubkey, 0) < t.amount:
                e["joined"] = height + 1
                e["retrying"] = True
                continue
            e["joined"], e["retrying"] = None, False
            if t.payer_pubkey in self.frozen:
                e["missed"] += 1
            else:
                self.bal[t.payer_pubkey] -= t.amount
                self.bal[t.recipient_pubkey] = self.bal.get(t.recipient_pubkey, 0) + t.amount
                e["paid"] += 1
            e["p"] += 1
            if e["p"] >= t.periods:
                del self.open[sid]


step = st.fixed_dictionaries({
    "gap": st.sampled_from([1, 1, 1, 2, 7, MIN_INTERVAL_BLOCKS - 1, MIN_INTERVAL_BLOCKS,
                            MIN_INTERVAL_BLOCKS + 3, 3 * MIN_INTERVAL_BLOCKS + 1]),
    "creates": st.lists(st.tuples(
        st.sampled_from(PEOPLE), st.sampled_from(PEOPLE), st.integers(1, 400),
        st.sampled_from([MIN_INTERVAL_BLOCKS, MIN_INTERVAL_BLOCKS + 1, 2 * MIN_INTERVAL_BLOCKS]),
        st.integers(1, 2 * MIN_INTERVAL_BLOCKS), st.integers(1, 4),
    ), max_size=2),
    "cancel": st.booleans(),
    "topup": st.one_of(st.none(), st.tuples(st.sampled_from(PEOPLE), st.sampled_from(PEOPLE),
                                            st.integers(1, 500))),
    "freeze": st.one_of(st.none(), st.tuples(st.sampled_from(PEOPLE), st.booleans())),
    # Pay a payer whose due payment is waiting for money exactly what it lacks.
    "rescue": st.booleans(),
})


@settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(program=st.lists(step, min_size=1, max_size=14), cancel_pick=st.randoms())
def test_node_equals_the_reference_model(program, cancel_pick):
    start = {ALICE: 600, BOB: 300, CAROL: 0}
    ch, model = Chain(dict(start)), Model(dict(start))
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.set_verdict(CLAUSE, lambda inputs: 0)   # a registered clause blocks
    sender_policy.set_evaluator("apply", evaluator)
    seq = {p: 0 for p in PEOPLE}
    height = HEIGHT
    try:
        with patch("consensus.bls.verify", return_value=True):
            for s in program:
                height += s["gap"]
                txs = []
                if s["freeze"]:
                    who, on = s["freeze"]
                    key = (who, 5)
                    if on:
                        ch.lm.rule_offers.accepted_clauses[key] = CLAUSE
                        model.frozen.add(who)
                    else:
                        ch.lm.rule_offers.accepted_clauses.pop(key, None)
                        model.frozen.discard(who)
                transfers = [s["topup"]] if s["topup"] else []
                waiting = [e["t"] for e in model.open.values() if e["retrying"]]
                if s["rescue"] and waiting:
                    t = waiting[0]
                    short = t.amount - model.bal.get(t.payer_pubkey, 0)
                    donor = max((d for d in PEOPLE if d != t.payer_pubkey),
                                key=lambda d: model.bal.get(d, 0))
                    if short > 0:
                        transfers.append((donor, t.payer_pubkey, short))
                for frm, to, amount in transfers:
                    if frm != to and model.bal.get(frm, 0) >= amount and frm not in model.frozen:
                        txs.append(_tx(frm, seq[frm], height, "user_tx",
                                       operations={"1": [[frm, to, amount]]}))
                        seq[frm] += 1
                        model.bal[frm] -= amount
                        model.bal[to] = model.bal.get(to, 0) + amount
                created = []
                for payer, recipient, amount, interval, ahead, periods in s["creates"]:
                    pending = sum(c.payer_pubkey == payer for c in created)
                    if payer == recipient or model.open_for(payer) + pending >= 16:
                        continue
                    tx = _tx(payer, seq[payer], height, "standing_payment_create",
                             recipient_pubkey=recipient, amount=amount,
                             interval_blocks=interval, first_due=height + ahead,
                             periods=periods)
                    txs.append(tx)
                    seq[payer] += 1
                    created.append(parse_standing_payment_create(tx))
                if s["cancel"] and model.open:
                    sid = cancel_pick.choice(sorted(model.open))
                    payer = model.open[sid]["t"].payer_pubkey
                    txs.append(_tx(payer, seq[payer], height, "standing_payment_cancel",
                                   standing_id=sid.hex()))
                    seq[payer] += 1
                    del model.open[sid]
                for terms in created:
                    model.create(terms)

                ch.block(txs, height=height, ts=TS + height)
                model.block(height)

                assert {k: v for k, v in ch.bal.items() if v} == \
                    {k: v for k, v in model.bal.items() if v}
                book = ch.book
                assert set(book.terms) == set(model.open)
                for sid, e in model.open.items():
                    p = book.progress[sid]
                    assert (p.paid_count, p.missed_count) == (e["paid"], e["missed"]), sid.hex()
    finally:
        sender_policy.set_evaluator("apply", None)

