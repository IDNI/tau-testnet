"""Random block sequences: the node against a naive reference model (time
conditions, with the spending limit).

The model knows nothing of the book's index, ids or commitments, and reads
weekdays and hours with Python's own `datetime` at the envelope's offset from
UTC, not with the node's arithmetic. It keeps each open envelope as a plain dict and applies the
documented rules directly:

  * a send needs what a spending-limit send needs (the limit now optional),
    at least one condition, windows only on the seconds clock and never every
    day or every hour, hold within the lifetime limit, an unlock before the end,
    and a second inside the windows between the unlock and the end (found by
    walking the quarter hours, since an offset may be one); an offset only with
    days or hours; the amount leaves the sender;
  * unlock = max(sent, not_before, sent + hold); the limit's periods start there;
  * a spend lands when the signer is the recipient, unlock <= clock < end,
    the block's weekday and hour at the envelope's offset are allowed, and the
    amount fits what the
    envelope holds and the period's cap; the payee is credited, the spender
    pays one fee;
  * at the end of the block whose clock reaches the end the rest goes to the
    recipient (ended).

Hypothesis drives sends, spends, releases and plain payments through the REAL
`apply_block` (signature checks stubbed), with the clocks aimed at unlocks,
ends, period starts and window edges (and one tick before each). After every
block the balances, the open envelopes and the block's events must equal the
model's.

The second half proves the model has teeth: each mutant breaks one rule of the
time conditions in the node, and the same search must catch it.
"""
import datetime as dt
import itertools
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, Phase, event, example, given, settings, strategies as st

import consensus.envelope as envelope_mod
import tau_defs
from consensus.envelope import (
    MAX_LIFETIME_BLOCKS,
    MAX_LIFETIME_SECONDS,
    MAX_OPEN_ENVELOPES_PER_SENDER,
    MAX_PERIOD_BLOCKS,
    MAX_PERIOD_SECONDS,
    OUTCOME_ENDED,
    EnvelopeBook,
    EnvelopeTerms,
    parse_envelope_send,
)
from consensus.network_binding import BOUND_TX_TYPES, chain_genesis_hash

from tests.test_envelope_apply import DAVE
from tests.test_standing_apply import ALICE, BOB, CAROL, HEIGHT, PROPOSER, TS, Chain

KEYS = (ALICE, BOB, CAROL, DAVE)
FEE = 2
HOUR, DAY = 3600, 86400
QUARTER = 900
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
_IDS = itertools.count()


def _tx(sender, seq, height, tx_type, fee_limit="100", **fields):
    tx = {"tx_id": f"c-{next(_IDS)}", "tx_type": tx_type, "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": 9_999_999_999,
          "expire_at_height": height + 1, "fee_limit": fee_limit, "signature": "00"}
    if tx_type in BOUND_TX_TYPES:
        tx["genesis_hash"] = chain_genesis_hash()
    tx.update({k: v for k, v in fields.items() if v is not None})
    return tx


class Model:
    def __init__(self, balances):
        self.bal = dict(balances)
        self.open = {}
        self.outcomes = []

    @staticmethod
    def clock(e, height, ts):
        return height if e["blocks"] else ts

    @staticmethod
    def allowed(e, ts):
        there = dt.timezone(dt.timedelta(minutes=15 * e.get("offset", 0)))
        when = dt.datetime.fromtimestamp(ts, tz=there)
        return ((not e["days"] or DAYS[when.weekday()] in e["days"])
                and (not e["hours"] or when.hour in e["hours"]))

    @staticmethod
    def due(e):
        """The clock at which the envelope closes on its own: its end."""
        return e["end"]

    def room(self, e, now):
        if not e["caps"]:
            return e["left"]
        n = max(0, now - e["unlock"]) // e["period"]
        cap = e["caps"][n] if n < len(e["caps"]) else (e["caps"][-1] if e["recurring"]
                                                       else None)
        if cap is None:
            return e["left"]
        spent = e["spent"] if e["index"] == n else 0
        return max(0, min(e["left"], cap - spent))

    def first_spend(self, e):
        """Walk from the unlock to the end, quarter hour by quarter hour."""
        due = self.due(e)
        if e["blocks"] or not (e["days"] or e["hours"]):
            return e["unlock"] if e["unlock"] < due else None
        t = e["unlock"]
        while t < due:
            if self.allowed(e, t):
                return t
            t = (t // QUARTER + 1) * QUARTER
        return None

    def may_send(self, e, height, ts):
        now = self.clock(e, height, ts)
        top, life = ((MAX_PERIOD_BLOCKS, MAX_LIFETIME_BLOCKS) if e["blocks"]
                     else (MAX_PERIOD_SECONDS, MAX_LIFETIME_SECONDS))
        mx = tau_defs.MAX_TRANSFER_VALUE
        has_condition = bool(e["caps"] or e["not_before"] is not None or e["hold"] is not None
                             or e["days"] or e["hours"])
        return (e["sender"] != e["recipient"] and 1 <= e["amount"] <= mx
                and all(1 <= c <= mx for c in e["caps"])
                and (not e["caps"] or 1 <= e["period"] <= top)
                and has_condition
                and not ((e["days"] or e["hours"]) and e["blocks"])
                and len(e["days"]) < 7 and len(e["hours"]) < 24
                and (not e.get("offset") or bool(e["days"] or e["hours"]))
                and (e["hold"] is None or 1 <= e["hold"] <= life)
                and now < e["end"] <= now + life
                and e["unlock"] < e["end"]
                and self.first_spend(e) is not None
                and sum(1 for o in self.open.values() if o["sender"] == e["sender"])
                < MAX_OPEN_ENVELOPES_PER_SENDER
                and e["id"] not in self.open
                and self.bal.get(e["sender"], 0) >= e["amount"] + FEE)

    def may_spend(self, e, signer, to, amount, height, ts):
        now = self.clock(e, height, ts)
        return (signer == e["recipient"] and e["unlock"] <= now < self.due(e)
                and (e["blocks"] or self.allowed(e, ts))
                and amount <= self.room(e, now)
                and self.bal.get(signer, 0) + (amount if to == signer else 0) >= FEE)

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
                                                    self.due(self.open[k]), k)):
            e = self.open[eid]
            if self.clock(e, height, ts) >= self.due(e):
                self.close(eid, "ended")


# --- the program ---------------------------------------------------------------------

def _envelope(valid_only=False):
    rare = [] if valid_only else [0]
    maybe = lambda *xs: st.one_of(st.none(), st.sampled_from(list(xs)))  # noqa: E731
    return st.fixed_dictionaries({
        "blocks": st.booleans(),
        "amount": st.sampled_from(rare + [1, 40, 120, 120, 333, 900]),
        "caps": st.one_of(st.just([]), st.just([]),
                          st.lists(st.sampled_from(rare + [10, 25, 60, 150]),
                                   min_size=1, max_size=2)),
        "period": st.sampled_from([1, 2, 3, 5, 24]),
        "recurring": st.booleans(),
        "end": st.sampled_from(rare + [2, 6, 12, 30, 30, 72, 170]),
        "not_before": maybe(0, 1, 4, 40),
        "hold": maybe(*(rare + [1, 2, 6, 30])),
        "days": st.sampled_from([(), (), ("sat", "sun"), ("mon", "tue", "wed", "thu", "fri"),
                                 ("thu",), ("fri", "sat"), DAYS]),
        "hours": st.sampled_from([(), (), (9, 10, 11, 12, 13, 14, 15, 16), (0, 1, 22, 23),
                                  (12,), tuple(range(24))]),
        # Quarter hours east of UTC: none, UTC+02:00, UTC-05:30, UTC+05:45 and both ends.
        "offset": st.sampled_from([0, 0, 0, 8, 8, -22, 23, 56, -48]),
    })


def _repair(spec):
    """Make a generated envelope one the node must accept (for the opening block)."""
    spec = dict(spec)
    if spec["blocks"] or len(spec["days"]) == 7:
        spec["days"] = ()
    if spec["blocks"] or len(spec["hours"]) == 24:
        spec["hours"] = ()
    if not (spec["days"] or spec["hours"]):
        spec["offset"] = 0
    if not (spec["caps"] or spec["not_before"] is not None or spec["hold"] is not None
            or spec["days"] or spec["hours"]):
        spec["hold"] = 1
    lock = max(spec["not_before"] or 0, spec["hold"] or 0)
    if spec["days"] or spec["hours"]:
        spec["end"] = max(spec["end"], 170)
    spec["end"] = max(spec["end"], lock + 6)
    return spec


def _valid_envelope():
    return _envelope(True).map(_repair)


SPEND = st.tuples(st.just("spend"), st.integers(0, 7),
                  st.sampled_from(["recipient"] * 6 + ["sender"]),
                  st.sampled_from(["self", "other", "other"]),
                  st.sampled_from(["room", "room", "room", "room+1", "one", "half", "all"]))

OTHER = st.one_of(
    st.tuples(st.just("release"), st.integers(0, 7), st.sampled_from(["sender", "recipient"])),
    st.tuples(st.just("pay"), st.sampled_from(KEYS), st.sampled_from(KEYS),
              st.sampled_from([5, 50, 700])),
    st.tuples(st.just("pay"), st.sampled_from(KEYS), st.sampled_from(KEYS),
              st.sampled_from([5, 50, 700])),
)

ACTION = st.one_of(
    st.tuples(st.just("send"), st.sampled_from(KEYS), st.sampled_from(KEYS),
              st.one_of(_envelope(), _valid_envelope())),
    SPEND, SPEND, SPEND, SPEND, SPEND, SPEND, SPEND, SPEND, OTHER,
)

# Where the next block lands: a plain step, or aimed at (or one tick before) one
# open envelope's unlock, end ("due"), period start or window edge, or halfway to
# its end.
AIMS = ["unlock", "unlock", "unlock-1", "due", "due", "due-1", "due-1", "due-1", "halfway",
        "halfway", "reset", "reset-1", "edge", "edge", "edge-1", "edge-1"]
STEP = st.fixed_dictionaries({
    "gap": st.one_of(st.tuples(st.just("plain"), st.sampled_from([1, 1, 2, 5]),
                               st.sampled_from([60, HOUR, 5 * HOUR, DAY, 3 * DAY])),
                     st.tuples(st.sampled_from(AIMS), st.integers(0, 3)),
                     st.tuples(st.sampled_from(AIMS), st.integers(0, 3))),
    "proposer": st.sampled_from([PROPOSER, CAROL]),
    "actions": st.lists(ACTION, min_size=1, max_size=5),
})

OPENING = st.fixed_dictionaries({
    "gap": st.just(("plain", 1, 60)),
    "proposer": st.just(PROPOSER),
    "actions": st.tuples(
        st.tuples(st.just("send"), st.just(ALICE), st.just(BOB), _valid_envelope()),
        st.tuples(st.just("send"), st.just(CAROL), st.just(DAVE), _valid_envelope()),
    ).map(list),
})

PROGRAM = st.tuples(OPENING, st.lists(STEP, min_size=1, max_size=12)).map(
    lambda t: [t[0]] + t[1])


def _points(e, now, ts, model):
    """Clock points worth landing on for one open envelope, by name."""
    out = {"unlock": [e["unlock"]], "due": [model.due(e)], "reset": [], "edge": []}
    if e["caps"]:
        n = max(0, now - e["unlock"]) // e["period"]
        out["reset"].append(e["unlock"] + (n + 1) * e["period"])
    if not e["blocks"] and (e["days"] or e["hours"]):
        t = (ts // QUARTER + 1) * QUARTER
        inside = model.allowed(e, ts)
        for _ in range(4 * 24 * 8):
            if model.allowed(e, t) != inside:      # the next window opens or closes
                out["edge"].append(t)
                break
            t += QUARTER
    start = max(now, e["unlock"])
    if model.due(e) - start > 1:                   # the middle of the spendable time
        out["halfway"] = [start + (model.due(e) - start) // 2]
    return out


def _advance(gap, model, height, ts):
    """The next block's (height, ts): a plain step, or aimed at a point of one
    open envelope (the k-th), or of any when that one has none ahead."""
    if gap[0] == "plain":
        return height + gap[1], ts + gap[2]
    aim, k = gap
    minus = aim.endswith("-1")
    aim = aim.removesuffix("-1")
    opened = sorted(model.open, key=lambda eid: model.open[eid]["seq"])
    choices = [model.open[opened[k % len(opened)]]] if opened else []
    for candidates in (choices, [model.open[eid] for eid in opened]):
        targets = []
        for e in candidates:
            now = Model.clock(e, height, ts)
            for point in _points(e, now, ts, model).get(aim, []):
                point -= 1 if minus else 0
                if point > now:
                    targets.append((point - now, e["blocks"]))
        if targets:
            jump, blocks = min(targets)
            return (height + jump, ts + 60) if blocks else (height + 1, ts + jump)
    return height + 1, ts + HOUR


def _fields(spec, height, ts):
    blocks = spec["blocks"]
    unit = 1 if blocks else HOUR
    now = height if blocks else ts
    out = {"amount": spec["amount"], "expires_at": now + spec["end"] * unit}
    if spec["caps"]:
        out["caps"] = list(spec["caps"])
        out["period_blocks" if blocks else "period_seconds"] = spec["period"] * unit
        if spec["recurring"]:
            out["recurring"] = True
    else:
        out["clock"] = "blocks" if blocks else "seconds"
    if spec["not_before"] is not None:
        out["not_before"] = now + spec["not_before"] * unit
    if spec["hold"] is not None:
        out["hold"] = spec["hold"] * unit
    if spec["days"]:
        out["days"] = [d for d in DAYS if d in spec["days"]]
    if spec["hours"]:
        out["hours"] = sorted(spec["hours"])
    if spec.get("offset"):
        out["utc_offset"] = spec["offset"]
    return out


def check(program):
    start = {ALICE: 5_000, BOB: 3_000, CAROL: 2_000}
    ch = Chain(dict(start), fee=FEE)
    model = Model(start)
    seq = {k: 0 for k in KEYS}
    order = []
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
                    terms = parse_envelope_send(_tx(sender, seq[sender], height,
                                                    "envelope_send",
                                                    recipient_pubkey=recipient, **fields))
                    sent = height if spec["blocks"] else ts
                    unlock = max([sent] + [v for v in (fields.get("not_before"),
                                                       sent + fields["hold"]
                                                       if "hold" in fields else None)
                                           if v is not None])
                    e = {"id": terms.envelope_id, "sender": sender, "recipient": recipient,
                         "amount": fields["amount"], "caps": fields.get("caps", []),
                         "blocks": spec["blocks"], "recurring": bool(fields.get("recurring")),
                         "period": terms.period, "end": terms.expires_at,
                         "not_before": fields.get("not_before"), "hold": fields.get("hold"),
                         "days": set(fields.get("days", ())),
                         "hours": set(fields.get("hours", ())),
                         "offset": fields.get("utc_offset", 0),
                         "unlock": unlock, "last": None, "seq": len(order),
                         "left": fields["amount"], "index": 0, "spent": 0}
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
                    opened = sorted(model.open, key=order.index)
                    if not opened:
                        continue
                    eid = opened[k % len(opened)]
                    e = model.open[eid]
                    signer = e["recipient"] if who == "recipient" else e["sender"]
                    to = signer if payee == "self" else next(x for x in KEYS if x != signer)
                    now = Model.clock(e, height, ts)
                    room = model.room(e, now)
                    amount = max(1, {"room": room, "room+1": room + 1, "one": 1,
                                     "half": room // 2, "all": e["left"]}[size])
                    lands = model.may_spend(e, signer, to, amount, height, ts)
                    submit(signer, lands, "envelope_spend", envelope_id=eid.hex(),
                           to_pubkey=to, amount=amount)
                    if lands:
                        n = max(0, now - e["unlock"]) // e["period"] if e["caps"] else 0
                        e["spent"] = (e["spent"] if e["index"] == n else 0) + amount
                        e["index"] = n
                        e["left"] -= amount
                        e["last"] = now
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
                else:
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
            for e in model.open.values():
                if Model.clock(e, height, ts) < e["unlock"]:
                    event("an envelope is still locked")
                if e["days"] or e["hours"]:
                    event("a window is in force")
                if e["offset"]:
                    event("a window is read at an offset from UTC")


@settings(max_examples=800, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(program=PROGRAM)
def test_node_equals_the_reference_model(program):
    check(program)


# --- the model has teeth ----------------------------------------------------------

_check_spend = EnvelopeBook.check_spend
_validate = envelope_mod.validate_send_shape
_unlock = EnvelopeTerms.unlock_at


def _no_hold(self, sent):
    return _unlock(type(self)(**{**self.__dict__, "hold": None}), sent)


def _no_not_before(self, sent):
    return _unlock(type(self)(**{**self.__dict__, "not_before": None}), sent)


def _lock_one_short(self, spend, height, ts):
    """The lock opens one tick early."""
    terms = self.open.get(spend.envelope_id)
    if terms is not None and terms.clock(height, ts) == self.state[spend.envelope_id].anchor - 1:
        height, ts = height + 1, ts + 1
    return _check_spend(self, spend, height, ts)


def _due_included(self, spend, height, ts):
    """A spend in the block that reaches the end still lands."""
    terms = self.open.get(spend.envelope_id)
    if terms is not None and \
            terms.clock(height, ts) == self.state[spend.envelope_id].due_point(terms):
        height, ts = height - 1, ts - 1
    return _check_spend(self, spend, height, ts)


def _no_window_check(terms, height, ts):
    reason = _validate(terms, height, ts)
    return None if reason and "never be spent" in reason else reason


MUTANTS = {
    "hold ignored": lambda mp: mp.setattr(EnvelopeTerms, "unlock_at", _no_hold),
    "not_before ignored": lambda mp: mp.setattr(EnvelopeTerms, "unlock_at", _no_not_before),
    "the lock opens a tick early": lambda mp: mp.setattr(EnvelopeBook, "check_spend",
                                                         _lock_one_short),
    "a spend lands on the end": lambda mp: mp.setattr(EnvelopeBook, "check_spend",
                                                      _due_included),
    "weeks start on Sunday": lambda mp: mp.setattr(
        envelope_mod, "weekday", lambda ts: (int(ts) // DAY + 4) % 7),
    "hours one off": lambda mp: mp.setattr(
        envelope_mod, "hour_of", lambda ts: (int(ts) % DAY) // HOUR + 1),
    "windows ignored": lambda mp: mp.setattr(EnvelopeTerms, "in_window", lambda self, ts: True),
    "the offset is ignored": lambda mp: mp.setattr(EnvelopeTerms, "local",
                                                   lambda self, ts: int(ts)),
    "the offset runs west": lambda mp: mp.setattr(
        EnvelopeTerms, "local", lambda self, ts: int(ts) - self.utc_offset * 900),
    "never-spendable sends accepted": lambda mp: mp.setattr(
        envelope_mod, "validate_send_shape", _no_window_check),
}


# One program per planted bug that shows it, found by the search below and shrunk.
# Pinned, so catching each bug never depends on the path the search takes (that
# path can change when unrelated code changes).
WITNESSES = {
    "hold ignored": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 7, "not_before": None, "hold": 1, "days": (), "hours": (), "offset": 0}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 7, "not_before": None, "hold": 1, "days": (), "hours": (), "offset": 0})]},
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, ALICE, {"blocks": False, "amount": 0, "caps": [], "period": 1, "recurring": False, "end": 0, "not_before": None, "hold": None, "days": (), "hours": (), "offset": 0}), ("spend", 0, "recipient", "self", "room")]},
    ],
    "not_before ignored": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 7, "not_before": None, "hold": 1, "days": (), "hours": (), "offset": 0}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 7, "not_before": None, "hold": 1, "days": (), "hours": (), "offset": 0})]},
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 2, "not_before": 4, "hold": None, "days": (), "hours": (), "offset": 0})]},
    ],
    "the lock opens a tick early": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": True, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 8, "not_before": None, "hold": 2, "days": (), "hours": ()}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 6, "not_before": None, "hold": None, "days": (), "hours": ()})]},
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
    "a spend lands on the end": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": True, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 7, "not_before": None, "hold": 1, "days": (), "hours": (), "offset": 0}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 7, "not_before": None, "hold": 1, "days": (), "hours": (), "offset": 0})]},
        {"gap": ("due-1", 0), "proposer": PROPOSER, "actions": [("pay", ALICE, ALICE, 5)]},
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
    "weeks start on Sunday": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 6, "not_before": None, "hold": None, "days": (), "hours": ()}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 170, "not_before": None, "hold": 30, "days": ("thu",), "hours": (9, 10, 11, 12, 13, 14, 15, 16)})]},
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
    "the offset is ignored": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 170, "not_before": None, "hold": None, "days": (), "hours": (12,), "offset": 8}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 6, "not_before": None, "hold": None, "days": (), "hours": (), "offset": 0})]},
        {"gap": ("edge", 0), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
    "the offset runs west": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 170, "not_before": None, "hold": None, "days": (), "hours": (12,), "offset": 23}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 6, "not_before": None, "hold": None, "days": (), "hours": (), "offset": 0})]},
        {"gap": ("edge", 0), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
    "hours one off": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 170, "not_before": None, "hold": None, "days": (), "hours": (12,)}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 6, "not_before": None, "hold": None, "days": (), "hours": ()})]},
        {"gap": ("edge", 0), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
    "windows ignored": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 6, "not_before": None, "hold": None, "days": (), "hours": ()}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 170, "not_before": None, "hold": 30, "days": ("thu",), "hours": (9, 10, 11, 12, 13, 14, 15, 16)})]},
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
    "never-spendable sends accepted": [
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("send", ALICE, BOB, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 6, "not_before": None, "hold": None, "days": (), "hours": ()}), ("send", CAROL, DAVE, {"blocks": False, "amount": 1, "caps": [], "period": 1, "recurring": False, "end": 170, "not_before": None, "hold": 30, "days": ("thu",), "hours": (9, 10, 11, 12, 13, 14, 15, 16)})]},
        {"gap": ("plain", 1, 60), "proposer": PROPOSER, "actions": [("spend", 0, "recipient", "self", "room")]},
    ],
}


@pytest.mark.parametrize("mutant", sorted(MUTANTS))
def test_the_model_catches_a_broken_node(mutant, monkeypatch):
    MUTANTS[mutant](monkeypatch)

    @settings(max_examples=1500, deadline=None, database=None, derandomize=True,
              phases=[Phase.explicit, Phase.generate], suppress_health_check=list(HealthCheck))
    @example(program=WITNESSES[mutant])
    @given(program=PROGRAM)
    def search(program):
        check(program)

    with pytest.raises(AssertionError):
        search()


def test_the_outcome_names_the_model_uses():
    assert OUTCOME_ENDED == 3
