"""Random block sequences: the node against a naive reference model (spending limits).

The model knows nothing of the book's end lists, ids or commitments. It keeps
each open envelope as a plain dict and applies the documented rules directly:

  * a send needs a recipient other than the sender, an amount and every cap in
    1..MAX_TRANSFER_VALUE, a period in range, an end in the future and within
    the lifetime limit (all on the envelope's own clock), fewer than sixteen
    envelopes open from the sender, and funds for the amount and one fee; the
    amount then leaves the sender;
  * the period of a spend is (clock - anchor) // period, the anchor being the
    clock of the block that sent it; its cap is caps[n], then caps[-1] when
    recurring, else none; what was spent in an earlier period never counts;
  * only the recipient spends, before the end, at most what the envelope holds
    and what the period's cap leaves; the payee is credited first and the
    spender then pays one fee, so a spend to oneself can pay its own fee;
  * only the sender releases, fee-free: the rest goes to the recipient;
  * an envelope spent to zero closes; at the end of the block whose clock
    reaches its end, the rest goes to the recipient.

Hypothesis drives sends, spends (aimed at the edge of the period's room),
releases and plain payments through the REAL `apply_block` (signature checks
stubbed), with the clocks aimed at period starts and envelope ends. After every
block the balances, the open envelopes and the block's events must equal the
model's.

The second half proves the model has teeth: each mutant below breaks one rule
in the node, and the same search must catch it.
"""
import itertools
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, Phase, event, example, given, settings, strategies as st

import tau_defs
from consensus.envelope import (
    KIND_BLOCKS,
    MAX_LIFETIME_BLOCKS,
    MAX_LIFETIME_SECONDS,
    MAX_OPEN_ENVELOPES_PER_SENDER,
    MAX_PERIOD_BLOCKS,
    MAX_PERIOD_SECONDS,
    EnvelopeBook,
    EnvelopeState,
    EnvelopeTerms,
    parse_envelope_send,
)
from consensus.network_binding import BOUND_TX_TYPES, chain_genesis_hash

from tests.test_envelope_apply import DAVE
from tests.test_standing_apply import ALICE, BOB, CAROL, HEIGHT, PROPOSER, TS, Chain

KEYS = (ALICE, BOB, CAROL, DAVE)
FEE = 2
_IDS = itertools.count()


def _tx(sender, seq, height, tx_type, fee_limit="100", **fields):
    tx = {"tx_id": f"e-{next(_IDS)}", "tx_type": tx_type, "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": 9_999_999_999,
          "expire_at_height": height + 1, "fee_limit": fee_limit, "signature": "00"}
    if tx_type in BOUND_TX_TYPES:
        tx["genesis_hash"] = chain_genesis_hash()
    tx.update(fields)
    return tx


class Model:
    def __init__(self, balances):
        self.bal = dict(balances)
        self.open = {}            # eid -> envelope dict
        self.outcomes = []

    @staticmethod
    def clock(e, height, ts):
        return height if e["blocks"] else ts

    @staticmethod
    def cap(e, n):
        if n < len(e["caps"]):
            return e["caps"][n]
        return e["caps"][-1] if e["recurring"] else None

    def room(self, e, height, ts):
        """What one spend may take now, by the documented rule."""
        now = self.clock(e, height, ts)
        n = (now - e["anchor"]) // e["period"]
        spent = e["spent"] if e["index"] == n else 0
        cap = self.cap(e, n)
        if cap is None:
            return e["left"]
        return max(0, min(e["left"], cap - spent))

    def may_send(self, e, height, ts):
        now = self.clock(e, height, ts)
        top, life = ((MAX_PERIOD_BLOCKS, MAX_LIFETIME_BLOCKS) if e["blocks"]
                     else (MAX_PERIOD_SECONDS, MAX_LIFETIME_SECONDS))
        mx = tau_defs.MAX_TRANSFER_VALUE
        return (e["sender"] != e["recipient"] and 1 <= e["amount"] <= mx
                and all(1 <= c <= mx for c in e["caps"]) and 1 <= e["period"] <= top
                and now < e["end"] <= now + life
                and sum(1 for o in self.open.values() if o["sender"] == e["sender"])
                < MAX_OPEN_ENVELOPES_PER_SENDER
                and e["id"] not in self.open
                and self.bal.get(e["sender"], 0) >= e["amount"] + FEE)

    def fee(self, payer, proposer):
        self.bal[payer] = self.bal.get(payer, 0) - FEE
        self.bal[proposer] = self.bal.get(proposer, 0) + FEE

    def close(self, eid, outcome):
        e = self.open.pop(eid)
        if e["left"]:
            self.bal[e["recipient"]] = self.bal.get(e["recipient"], 0) + e["left"]
        self.outcomes.append((outcome, eid.hex(), e["left"] if outcome != "emptied" else 0))

    def end_of_block(self, height, ts):
        for eid in sorted(self.open, key=lambda k: (not self.open[k]["blocks"],
                                                    self.open[k]["end"], k)):
            e = self.open[eid]
            if self.clock(e, height, ts) >= e["end"]:
                self.close(eid, "ended")


# --- the program ---------------------------------------------------------------------

def _envelope(valid_only=False):
    rare = [] if valid_only else [0]
    return st.fixed_dictionaries({
        "blocks": st.booleans(),
        "amount": st.sampled_from(rare + [1, 40, 120, 120, 333, 333, 900, 6_000]),
        "caps": st.lists(st.sampled_from(rare + [1, 10, 25, 25, 60, 60, 150]),
                         min_size=1, max_size=3),
        "period": st.sampled_from(rare + [1, 2, 2, 3, 3, 5, 8]),
        "recurring": st.booleans(),
        "end": st.sampled_from(rare + [1, 4, 9, 17, 17, 30, 60, 60]),
    })


SPEND = st.tuples(st.just("spend"), st.integers(0, 7),
                  st.sampled_from(["recipient"] * 5 + ["sender", "other"]),
                  st.sampled_from(["self", "other", "other"]),
                  st.sampled_from(["room", "room", "room", "room+1", "one", "half", "all",
                                   "all+1"]))

ACTION = st.one_of(
    st.tuples(st.just("send"), st.sampled_from(KEYS), st.sampled_from(KEYS), _envelope()),
    SPEND, SPEND, SPEND,
    st.tuples(st.just("release"), st.integers(0, 7), st.sampled_from(["sender", "recipient"])),
    st.tuples(st.just("pay"), st.sampled_from(KEYS), st.sampled_from(KEYS),
              st.sampled_from([5, 50, 700])),
)

STEP = st.fixed_dictionaries({
    "gap": st.one_of(st.sampled_from([1, 2, 5]),
                     st.sampled_from(["reset", "reset", "reset-1", "end", "end-1"])),
    "proposer": st.sampled_from([PROPOSER, CAROL]),
    "actions": st.lists(ACTION, max_size=5),
})

# The first block always opens two well-formed envelopes, so most programs
# spend from something.
OPENING = st.fixed_dictionaries({
    "gap": st.just(1),
    "proposer": st.just(PROPOSER),
    "actions": st.tuples(
        st.tuples(st.just("send"), st.just(ALICE), st.just(BOB), _envelope(True)),
        st.tuples(st.just("send"), st.just(CAROL), st.just(DAVE), _envelope(True)),
    ).map(list),
})

PROGRAM = st.tuples(OPENING, st.lists(STEP, min_size=1, max_size=12)).map(
    lambda t: [t[0]] + t[1])

SECONDS_SCALE = 7          # a seconds envelope counts in multiples of 7 s


def _advance(gap, model, height, ts):
    """The next block's (height, ts): a plain step, or one aimed at (or just
    before) the next period start or end of an open envelope."""
    if isinstance(gap, int):
        return height + gap, ts + gap * 3
    targets = []
    for e in model.open.values():
        now = Model.clock(e, height, ts)
        if gap.startswith("end"):
            point = e["end"]
        else:
            n = (now - e["anchor"]) // e["period"]
            point = e["anchor"] + (n + 1) * e["period"]
        point -= 1 if gap.endswith("-1") else 0
        if point > now:
            targets.append((point - now, e["blocks"]))
    if not targets:
        return height + 1, ts + 3
    jump, blocks = min(targets)
    return (height + jump, ts + 1) if blocks else (height + 1, ts + jump)


def _fields(spec, height, ts):
    blocks = spec["blocks"]
    scale = 1 if blocks else SECONDS_SCALE
    now = height if blocks else ts
    out = {"amount": spec["amount"], "caps": list(spec["caps"]),
           ("period_blocks" if blocks else "period_seconds"): spec["period"] * scale,
           "expires_at": now + spec["end"] * scale}
    if spec["recurring"]:
        out["recurring"] = True
    return out


def check(program):
    start = {ALICE: 5_000, BOB: 3_000, CAROL: 2_000}
    ch = Chain(dict(start), fee=FEE)
    model = Model(start)
    seq = {k: 0 for k in KEYS}
    order = []                     # every envelope ever sent, by index
    height, ts = HEIGHT, TS
    with patch("consensus.bls.verify", return_value=True):
        for s in program:
            height, ts = _advance(s["gap"], model, height, ts)
            proposer = s["proposer"]
            model.outcomes = []
            txs = []

            def submit(sender, lands, tx_type, fee_limit="100", **fields):
                tx = _tx(sender, seq[sender], height, tx_type, fee_limit, **fields)
                tx["_lands"] = lands
                txs.append(tx)
                if lands:
                    seq[sender] += 1
                return tx

            for action in s["actions"]:
                kind = action[0]
                if kind == "send":
                    _, sender, recipient, spec = action
                    fields = _fields(spec, height, ts)
                    probe = _tx(sender, seq[sender], height, "envelope_send",
                                recipient_pubkey=recipient, **fields)
                    terms = parse_envelope_send(probe)
                    e = {"id": terms.envelope_id, "sender": sender, "recipient": recipient,
                         "amount": fields["amount"], "caps": fields["caps"],
                         "blocks": spec["blocks"], "recurring": spec["recurring"],
                         "period": terms.period, "end": terms.expires_at,
                         "left": fields["amount"], "index": 0, "spent": 0}
                    e["anchor"] = Model.clock(e, height, ts)
                    lands = model.may_send(e, height, ts)
                    submit(sender, lands, "envelope_send", recipient_pubkey=recipient,
                           **fields)
                    order.append(terms.envelope_id)
                    if lands:
                        model.fee(sender, proposer)
                        model.bal[sender] -= e["amount"]
                        model.open[e["id"]] = e
                elif kind == "spend":
                    _, k, who, payee, size = action
                    if not order:
                        continue
                    eid = order[k % len(order)]
                    e = model.open.get(eid)
                    if e is None:
                        continue
                    signer = {"recipient": e["recipient"], "sender": e["sender"]}.get(
                        who) or next(x for x in KEYS if x not in (e["sender"], e["recipient"]))
                    to = signer if payee == "self" else next(
                        x for x in KEYS if x != signer)
                    room = model.room(e, height, ts)
                    amount = {"room": room, "room+1": room + 1, "one": 1,
                              "half": max(1, room // 2), "all": e["left"],
                              "all+1": e["left"] + 1}[size]
                    if amount < 1:
                        amount = 1
                    ended = Model.clock(e, height, ts) >= e["end"]
                    lands = (signer == e["recipient"] and not ended and amount <= room
                             and model.bal.get(signer, 0) + (amount if to == signer else 0)
                             >= FEE)
                    submit(signer, lands, "envelope_spend", envelope_id=eid.hex(),
                           to_pubkey=to, amount=amount)
                    if lands:
                        now = Model.clock(e, height, ts)
                        n = (now - e["anchor"]) // e["period"]
                        e["spent"] = (e["spent"] if e["index"] == n else 0) + amount
                        e["index"] = n
                        e["left"] -= amount
                        model.bal[to] = model.bal.get(to, 0) + amount
                        model.fee(signer, proposer)
                        model.outcomes.append(("spend", eid.hex(), amount))
                        if e["left"] == 0:
                            model.close(eid, "emptied")
                elif kind == "release":
                    _, k, who = action
                    if not order:
                        continue
                    eid = order[k % len(order)]
                    e = model.open.get(eid)
                    if e is None:
                        continue
                    signer = e["sender"] if who == "sender" else e["recipient"]
                    lands = signer == e["sender"]
                    submit(signer, lands, "envelope_release", fee_limit="0",
                           envelope_id=eid.hex())
                    if lands:
                        model.close(eid, "released")
                else:                                              # pay
                    _, payer, to, amount = action
                    if payer == to or model.bal.get(payer, 0) < amount + FEE:
                        continue
                    submit(payer, True, "user_tx",
                           operations={"1": [[payer, to, str(amount)]]})
                    model.fee(payer, proposer)
                    model.bal[payer] -= amount
                    model.bal[to] = model.bal.get(to, 0) + amount
            model.end_of_block(height, ts)

            result = ch.block([{k: v for k, v in t.items() if k != "_lands"} for t in txs],
                              height=height, ts=ts, proposer=proposer)
            landed = set(result.accepted_tx_ids)
            for t in txs:
                assert (t["tx_id"] in landed) == t["_lands"], (t, result.outcomes)
                event(f'{t["tx_type"]} {"lands" if t["_lands"] else "refused"}')
            assert {k: v for k, v in ch.bal.items() if v} == \
                {k: v for k, v in model.bal.items() if v}
            book = ch.lm.envelopes
            assert {eid: st.remaining for eid, st in book.state.items()} == \
                {eid: e["left"] for eid, e in model.open.items()}
            events = result.next_snapshot.metadata.get("envelope_events", [])
            got = sorted((ev["outcome"], ev["envelope_id"],
                          ev.get("amount", ev.get("paid_out")))
                         for ev in events if ev["outcome"] != "sent")
            assert got == sorted(model.outcomes)
            for outcome, _, _ in model.outcomes:
                event(outcome)
            if any(e["caps"] and len(e["caps"]) > 1 for e in model.open.values()):
                event("a schedule of caps in force")


@settings(max_examples=1000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(program=PROGRAM)
def test_node_equals_the_reference_model(program):
    check(program)


# --- the model has teeth ----------------------------------------------------------

_check_spend = EnvelopeBook.check_spend
_can_release = EnvelopeBook.can_admit_release
_send = EnvelopeBook.send


def _sender_may_spend(self, spend, height, ts):
    terms = self.open.get(spend.envelope_id)
    if terms is not None and spend.spender_pubkey == terms.sender_pubkey:
        spend = type(spend)(terms.recipient_pubkey, spend.envelope_id, spend.to_pubkey,
                            spend.amount)
    return _check_spend(self, spend, height, ts)


def _anyone_releases(self, release):
    terms = self.open.get(release.envelope_id)
    if terms is not None:
        release = type(release)(terms.sender_pubkey, release.envelope_id)
    return _can_release(self, release)


def _end_included(self, spend, height, ts):
    """A spend in the block that reaches the end still lands (judged one tick earlier)."""
    terms = self.open.get(spend.envelope_id)
    if terms is not None and \
            terms.clock(height, ts) == self.state[spend.envelope_id].due_point(terms):
        if terms.kind == KIND_BLOCKS:
            height -= 1
        else:
            ts -= 1
    return _check_spend(self, spend, height, ts)


def _anchor_at_zero(self, terms, height, ts):
    return self._insert(terms, EnvelopeState(anchor=0, remaining=terms.amount))


def _no_reset(self, terms, clock):
    return self.spent_in_period


_left = EnvelopeState.left_at


def _one_more(self, terms, clock):
    return min(self.remaining, _left(self, terms, clock) + 1)


MUTANTS = {
    "the counter never resets": lambda mp: mp.setattr(EnvelopeState, "spent_at", _no_reset),
    "one more than the cap": lambda mp: mp.setattr(EnvelopeState, "left_at", _one_more),
    "recurring ignored": lambda mp: mp.setattr(
        EnvelopeTerms, "cap_for",
        lambda self, n: self.caps[n] if n < len(self.caps) else None),
    "the limit never lapses": lambda mp: mp.setattr(
        EnvelopeTerms, "cap_for", lambda self, n: self.caps[min(n, len(self.caps) - 1)]),
    "end included": lambda mp: mp.setattr(EnvelopeBook, "check_spend", _end_included),
    "envelopes never end": lambda mp: mp.setattr(EnvelopeBook, "end_due", lambda self, h, ts: []),
    "the sender may spend": lambda mp: mp.setattr(EnvelopeBook, "check_spend",
                                                  _sender_may_spend),
    "anyone may release": lambda mp: mp.setattr(EnvelopeBook, "can_admit_release",
                                                _anyone_releases),
    "periods count from genesis": lambda mp: mp.setattr(EnvelopeBook, "send", _anchor_at_zero),
}


# One program per planted bug that shows it, found by the search below and shrunk.
# Pinned, so catching each bug never depends on the path the search takes (that
# path can change when unrelated code changes).
WITNESSES = {
    "the counter never resets": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0}), ("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0})]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 40, "caps": [1, 1], "period": 2, "recurring": False, "end": 4}), ("spend", 4, "recipient", "self", "room"), ("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0})]},
        {"gap": 5, "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room"), ("spend", 0, "recipient", "self", "room"), ("spend", 4, "recipient", "self", "room")]},
    ],
    "one more than the cap": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0})]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0}), ("send", ALICE, BOB, {"blocks": False, "amount": 40, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0})]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0}), ("spend", 4, "recipient", "self", "room+1")]},
    ],
    "recurring ignored": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0})]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0}), ("send", ALICE, BOB, {"blocks": False, "amount": 40, "caps": [1], "period": 1, "recurring": True, "end": 4}), ("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0})]},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": [("spend", 4, "recipient", "self", "room+1")]},
    ],
    "the limit never lapses": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 40, "caps": [1], "period": 1, "recurring": False, "end": 4})]},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 2, "proposer": PROPOSER, "actions": [("spend", 1, "recipient", "self", "room")]},
    ],
    "end included": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0}), ("spend", 0, "recipient", "self", "room"), ("spend", 0, "recipient", "self", "room")]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0})]},
        {"gap": "reset", "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room"), ("spend", 3, "recipient", "self", "room")]},
    ],
    "envelopes never end": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": True, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
    ],
    "the sender may spend": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": []},
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [0], "period": 0, "recurring": False, "end": 0}), ("spend", 2, "sender", "self", "room")]},
    ],
    "anyone may release": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("release", 0, "recipient")]},
    ],
    "periods count from genesis": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [1], "period": 1, "recurring": False, "end": 1}), ("send", CAROL, DAVE, {"blocks": False, "amount": 40, "caps": [1], "period": 1, "recurring": False, "end": 1})]},
        {"gap": 1, "proposer": PROPOSER, "actions": [("spend", 1, "recipient", "self", "room+1")]},
    ],
}


@pytest.mark.parametrize("mutant", sorted(MUTANTS))
def test_the_model_catches_a_broken_node(mutant, monkeypatch):
    MUTANTS[mutant](monkeypatch)

    @settings(max_examples=400, deadline=None, database=None, derandomize=True,
              phases=[Phase.explicit, Phase.generate], suppress_health_check=list(HealthCheck))
    @example(program=WITNESSES[mutant])
    @given(program=PROGRAM)
    def search(program):
        check(program)

    with pytest.raises(AssertionError):
        search()
