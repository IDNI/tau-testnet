"""Random block sequences: the node against a naive reference model (#35).

The model knows nothing of the book's expiry list, ids or commitments. It keeps
one route per owner and applies the documented rules directly:

  * a route is in force from active_from (block timestamp) until expires_at,
    the end excluded; it leaves the book at the end of the block that reaches
    its end;
  * every credit of a routed class splits: routed = floor(gross * bps / 10000),
    nothing below min_amount, the rest to the owner; the routed share is a
    plain credit, never routed again;
  * fees are never routed, whoever proposes the block (one fee per Tau step:
    a transfer of n legs pays n);
  * credits that land at the end of a block (retractable releases) use the
    routes in force after the block's last transaction;
  * setting: not its own account, share 1..9000, start at most 366 days ahead,
    an end in the future and at most 4 x 366 days ahead and after the start; a
    locked route has an end at most 366 days ahead; refused when the
    destination routes straight back; while the current route is locked and has
    not ended, a replacement must keep the destination and the lock and give at
    least the same share, minimum, start and end;
  * removing: only an unlocked (or ended) route; releasing: only its
    destination, naming the route in force.

Hypothesis drives sets (fresh, or a variant of the route in force), removes,
releases, multi-leg payments and retractable payments through the REAL
`apply_block` (signature checks stubbed), with the block clock aimed at route
starts and ends. After every block the balances, the book and the block's
split events must equal the model's.

The second half proves the model has teeth: each mutant below breaks one rule
in the node, and the same search must catch it.
"""
import itertools
from unittest.mock import patch

import pytest
from hypothesis import HealthCheck, Phase, event, example, given, settings, strategies as st

from consensus import engine
from consensus.network_binding import BOUND_TX_TYPES, chain_genesis_hash
from consensus.receive_route import (
    BPS_DENOMINATOR,
    ReceiveRouteBook,
    RouteTerms,
    parse_receive_route_set,
)

from tests.test_receive_route_apply import DAVE
from tests.test_standing_apply import ALICE, BOB, CAROL, HEIGHT, PROPOSER, TS, Chain

OWNERS = (ALICE, BOB, CAROL)
KEYS = OWNERS + (DAVE,)
FEE = 2
DAY = 86_400
YEAR = 366 * DAY
_IDS = itertools.count()


def _tx(sender, seq, height, tx_type, fee_limit="100", **fields):
    tx = {"tx_id": f"m-{next(_IDS)}", "tx_type": tx_type, "sender_pubkey": sender,
          "sequence_number": seq, "expiration_time": 9_999_999_999,
          "expire_at_height": height + 1, "fee_limit": fee_limit, "signature": "00"}
    if tx_type in BOUND_TX_TYPES:
        tx["genesis_hash"] = chain_genesis_hash()
    tx.update(fields)
    return tx


def _route_fields(r):
    out = {"destination_pubkey": r["dest"], "share_bps": r["share"]}
    for key, value in (("min_amount", r["min"]), ("active_from", r["start"]),
                       ("expires_at", r["end"])):
        if value:
            out[key] = value
    if r["locked"]:
        out["locked"] = True
    return out


class Model:
    def __init__(self, balances):
        self.bal = dict(balances)
        self.routes = {}       # owner -> dict(dest, share, min, start, end, locked, id)
        self.parked = []       # (recipient, amount, release height, payer)
        self.splits = []       # this block: (owner, dest, class, gross, routed)

    # -- the rules ------------------------------------------------------------

    @staticmethod
    def ended(r, ts):
        return r["end"] != 0 and ts >= r["end"]

    def in_force(self, r, ts):
        return ts >= r["start"] and not self.ended(r, ts)

    def credit(self, who, gross, ts, credit_class):
        r = self.routes.get(who)
        routed = 0
        if r is not None and self.in_force(r, ts) and gross >= max(r["min"], 1):
            routed = gross * r["share"] // BPS_DENOMINATOR
        self.bal[who] = self.bal.get(who, 0) + gross - routed
        if routed:
            self.bal[r["dest"]] = self.bal.get(r["dest"], 0) + routed
            self.splits.append((who, r["dest"], credit_class, gross, routed))

    def fee(self, payer, proposer, steps=1):
        """One fee per Tau step: a transfer of n legs takes n steps."""
        self.bal[payer] -= FEE * steps
        self.bal[proposer] = self.bal.get(proposer, 0) + FEE * steps

    def may_set(self, owner, new, ts):
        if new["dest"] == owner or not 1 <= new["share"] <= 9000:
            return False
        if new["start"] > ts + YEAR:
            return False
        if new["end"] and not (ts < new["end"] <= ts + 4 * YEAR
                               and new["start"] < new["end"]):
            return False
        if new["locked"] and not (new["end"] and new["end"] <= ts + YEAR):
            return False
        back = self.routes.get(new["dest"])
        if back is not None and back["dest"] == owner:
            return False
        old = self.routes.get(owner)
        if old is not None and old["locked"] and not self.ended(old, ts):
            return (new["dest"] == old["dest"] and new["locked"]
                    and new["share"] >= old["share"] and new["min"] <= old["min"]
                    and new["start"] <= max(old["start"], ts) and new["end"] >= old["end"])
        return self.bal.get(owner, 0) >= FEE

    def may_remove(self, owner, ts):
        r = self.routes.get(owner)
        return r is not None and not (r["locked"] and not self.ended(r, ts))

    def end_of_block(self, height, ts):
        due = [p for p in self.parked if p[2] <= height]
        self.parked = [p for p in self.parked if p[2] > height]
        for who, amount, _, _ in due:
            self.credit(who, amount, ts, "retractable_release")
        gone = {o for o, r in self.routes.items() if r["end"] and ts >= r["end"]}
        for owner in gone:
            del self.routes[owner]
        return gone


# --- the program ------------------------------------------------------------------

AMOUNT = st.one_of(st.sampled_from([1, 4, 5, 9, 10, 11, 49, 50, 51, 99, 100, 101, 333]),
                   st.integers(1, 150))
START = st.sampled_from([0] * 5 + ["now", -10, 30, 600, 3_600, YEAR, YEAR + 1])
END = st.sampled_from([0] * 5 + [60, 3_600, 3_600, DAY, DAY, YEAR, YEAR + 1, 4 * YEAR + 1])
TO = st.sampled_from(OWNERS + OWNERS + (DAVE,))
FRESH = st.tuples(st.just("set"), st.sampled_from(OWNERS), st.sampled_from(KEYS),
                  st.sampled_from([1, 2000, 2000, 3333, 5000, 9000, 0, 9001]),
                  st.sampled_from([0, 0, 0, 10, 50]), START, END,
                  st.sampled_from([False, False, True]))
VARIANT = st.tuples(st.just("vary"), st.sampled_from(OWNERS), st.sampled_from(
    ["same", "share+1", "share-1", "min+1", "min-1", "start+1", "start-ts", "end+60",
     "end-1", "dest", "unlock"]))
PAY = st.tuples(st.just("pay"), st.sampled_from(OWNERS),
                st.lists(st.tuples(TO, AMOUNT), min_size=1, max_size=3))
ACTION = st.one_of(
    FRESH, FRESH, VARIANT, PAY, PAY, PAY,
    st.tuples(st.just("remove"), st.sampled_from(OWNERS)),
    st.tuples(st.just("release"), st.sampled_from(OWNERS),
              st.sampled_from(["dest", "dest", "other"]), st.booleans()),
)
STEP = st.fixed_dictionaries({
    "gap": st.one_of(st.sampled_from([1, 30, 600, 3_600, DAY]),
                     st.sampled_from(["start", "start-1", "end", "end-1"])),
    "proposer": st.sampled_from([PROPOSER, PROPOSER, ALICE, BOB]),
    "actions": st.lists(ACTION, max_size=6),
    "park": st.one_of(st.none(), st.tuples(st.sampled_from(OWNERS), TO,
                                           AMOUNT, st.integers(1, 3))),
})
# A first block that most often gives every owner a route, so later blocks
# have splits, locks, chains and ends to work on.
OPENING = st.lists(st.tuples(
    st.just("set"), st.sampled_from(OWNERS), TO, st.sampled_from([1, 2000, 3333, 5000, 9000]),
    st.sampled_from([0, 0, 10]), st.sampled_from([0, 0, "now", 30, 600]),
    st.sampled_from([0, 600, 3_600, DAY]), st.booleans(),
), min_size=0, max_size=4)
PROGRAM = st.builds(
    lambda opening, rest: [{"gap": 1, "proposer": PROPOSER, "actions": opening,
                            "park": None}] + rest,
    OPENING, st.lists(STEP, min_size=1, max_size=10))


def _gap(gap, model, ts):
    """A fixed gap, or one that lands on (or just before) a route's start or end."""
    if isinstance(gap, int):
        return gap
    edge = "start" if gap.startswith("start") else "end"
    targets = sorted(r[edge] for r in model.routes.values() if r[edge] > ts)
    if not targets:
        return 1
    return max(1, targets[0] - (1 if gap.endswith("-1") else 0) - ts)


def _variant(old, tweak, ts):
    new = dict(old)
    if tweak == "share+1":
        new["share"] += 1
    elif tweak == "share-1":
        new["share"] -= 1
    elif tweak == "min+1":
        new["min"] += 1
    elif tweak == "min-1":
        new["min"] = max(0, new["min"] - 1)
    elif tweak == "start+1":
        new["start"] = max(new["start"], ts) + 1
    elif tweak == "start-ts":
        new["start"] = ts
    elif tweak == "end+60":
        new["end"] = (new["end"] or ts) + 60
    elif tweak == "end-1":
        new["end"] = max(0, new["end"] - 1)
    elif tweak == "dest":
        new["dest"] = next(k for k in KEYS if k not in (old["dest"], old["owner"]))
    elif tweak == "unlock":
        new["locked"] = False
    return new


def check(program):
    start = {ALICE: 5_000, BOB: 3_000, CAROL: 2_000}
    ch = Chain(dict(start), fee=FEE)
    model = Model(start)
    seq = {k: 0 for k in KEYS}
    stale = {}
    height, ts = HEIGHT, TS
    with patch("consensus.bls.verify", return_value=True):
        for s in program:
            height += 1
            ts += _gap(s["gap"], model, ts)
            proposer = s["proposer"]
            model.splits = []
            txs = []

            def send(sender, lands, tx_type, fee_limit="100", **fields):
                tx = _tx(sender, seq[sender], height, tx_type, fee_limit, **fields)
                tx["_lands"] = lands
                txs.append(tx)
                if lands:
                    seq[sender] += 1
                return tx

            for action in s["actions"]:
                kind, owner = action[0], action[1]
                if kind in ("set", "vary"):
                    if kind == "set":
                        _, _, dest, share, mn, st_off, end_off, locked = action
                        new = {"owner": owner, "dest": dest, "share": share, "min": mn,
                               "start": ts if st_off == "now" else (ts + st_off if st_off
                                                                    else 0),
                               "end": ts + end_off if end_off else 0, "locked": locked}
                    else:
                        old = model.routes.get(owner)
                        if old is None:
                            continue
                        new = _variant(old, action[2], ts)
                    lands = model.may_set(owner, new, ts) and model.bal.get(owner, 0) >= FEE
                    tx = send(owner, lands, "receive_route_set", **_route_fields(new))
                    if lands:
                        model.fee(owner, proposer)
                        if owner in model.routes:
                            stale[owner] = model.routes[owner]["id"]
                        new["id"] = parse_receive_route_set(tx).route_id
                        model.routes[owner] = new
                elif kind == "remove":
                    lands = model.may_remove(owner, ts)
                    send(owner, lands, "receive_route_remove", fee_limit="0")
                    if lands:
                        stale[owner] = model.routes.pop(owner)["id"]
                elif kind == "release":
                    _, _, who, use_stale = action
                    r = model.routes.get(owner)
                    if r is None and owner not in stale:
                        continue
                    rid = stale.get(owner) if (use_stale or r is None) else r["id"]
                    if rid is None:
                        rid = r["id"]
                    dest = r["dest"] if r is not None else DAVE
                    signer = dest if who == "dest" else next(
                        k for k in KEYS if k not in (dest, owner))
                    lands = r is not None and rid == r["id"] and signer == r["dest"]
                    send(signer, lands, "receive_route_release", fee_limit="0",
                         owner_pubkey=owner, route_id=rid.hex())
                    if lands:
                        stale[owner] = model.routes.pop(owner)["id"]
                else:                                            # pay
                    legs = [(to, amount) for to, amount in action[2] if to != owner]
                    if not legs or model.bal.get(owner, 0) < \
                            sum(a for _, a in legs) + FEE * len(legs):
                        continue
                    send(owner, True, "user_tx",
                         operations={"1": [[owner, to, amount] for to, amount in legs]})
                    model.fee(owner, proposer, len(legs))
                    model.bal[owner] -= sum(a for _, a in legs)
                    for to, amount in legs:
                        model.credit(to, amount, ts, "transfer")
            if s["park"]:
                payer, to, amount, k = s["park"]
                if payer != to and model.bal.get(payer, 0) >= amount + FEE:
                    send(payer, True, "retractable_transfer", recipient_pubkey=to,
                         amount=amount, release_at_height=height + k)
                    model.fee(payer, proposer)
                    model.bal[payer] -= amount
                    model.parked.append((to, amount, height + k, payer))
            expired = model.end_of_block(height, ts)

            result = ch.block([{k: v for k, v in t.items() if k != "_lands"} for t in txs],
                              height=height, ts=ts, proposer=proposer)
            landed = set(result.accepted_tx_ids)
            for t in txs:
                assert (t["tx_id"] in landed) == t["_lands"], (t, result.outcomes)
            node = {k: v for k, v in ch.bal.items() if v}
            want = {k: v for k, v in model.bal.items() if v}
            assert node == want
            events = result.next_snapshot.metadata.get("route_events", [])
            got = sorted((e["owner_pubkey"], e["destination_pubkey"], e["credit_class"],
                          e["gross"], e["routed"]) for e in events if e["outcome"] == "routed")
            assert got == sorted(model.splits)
            assert {e["owner_pubkey"] for e in events if e["outcome"] == "expired"} == expired
            for what in {e[2] for e in model.splits} | ({"expired"} if expired else set()):
                event(what)
            for t in txs:
                event(f'{t["tx_type"]} {"lands" if t["_lands"] else "refused"}')
            if any(r["locked"] for r in model.routes.values()):
                event("a locked route in force")
            book = ch.lm.receive_routes
            assert {o: t.route_id for o, t in book.terms.items()} == \
                {o: r["id"] for o, r in model.routes.items()}


@settings(max_examples=1000, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(program=PROGRAM)
def test_node_equals_the_reference_model(program):
    check(program)


# --- the model has teeth ----------------------------------------------------------

def _ceil(self, gross):
    gross = int(gross)
    if gross <= 0 or gross < self.min_amount:
        return 0
    return -(-gross * self.share_bps // BPS_DENOMINATOR)


def _no_min(self, gross):
    return max(0, int(gross)) * self.share_bps // BPS_DENOMINATOR


def _multi_hop(lm, recipient, gross, timestamp, credit, credit_class, **source):
    book = engine._route_book(lm)
    route, routed = book.split(recipient, gross, int(timestamp or 0))
    credit(recipient, int(gross) - routed)
    if not routed:
        return None
    _multi_hop(lm, route.destination_pubkey, routed, timestamp, credit, credit_class)
    return engine.route_credit_event(route, gross, routed, credit_class, **source)


_admit = ReceiveRouteBook.can_admit_set


def _no_loop_check(self, terms, ts):
    ok, why = _admit(self, terms, ts)
    return (True, "") if "routes back" in why else (ok, why)


MUTANTS = {
    "ceil rounding": lambda mp: mp.setattr(RouteTerms, "share_of", _ceil),
    "no minimum": lambda mp: mp.setattr(RouteTerms, "share_of", _no_min),
    "end included": lambda mp: mp.setattr(
        RouteTerms, "ended", lambda self, ts: bool(self.expires_at) and ts > self.expires_at),
    "start excluded": lambda mp: mp.setattr(
        RouteTerms, "is_active", lambda self, ts: ts > self.active_from and not self.ended(ts)),
    "routes never leave": lambda mp: mp.setattr(ReceiveRouteBook, "expire", lambda self, ts: []),
    "lock ignored": lambda mp: mp.setattr(RouteTerms, "binding", lambda self, ts: False),
    "more than one hop": lambda mp: mp.setattr(engine, "_routed_credit", _multi_hop),
    "loops allowed": lambda mp: mp.setattr(ReceiveRouteBook, "can_admit_set", _no_loop_check),
}


# One program per planted bug that shows it, found by the search below and shrunk.
# Pinned, so catching each bug never depends on the path the search takes (that
# path can change when unrelated code changes).
WITNESSES = {
    "ceil rounding": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, BOB, 1, 0, 0, 0, False)], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("pay", BOB, [(ALICE, 1)])], "park": None},
    ],
    "no minimum": [
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, BOB, 2000, 10, 0, 0, False)], "park": (BOB, ALICE, 5, 1)},
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
    ],
    "end included": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", BOB, ALICE, 1, 0, 0, 600, True)], "park": None},
        {"gap": 600, "proposer": PROPOSER, "actions": [("set", BOB, ALICE, 1, 0, 0, 0, False)], "park": None},
    ],
    "start excluded": [
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", BOB, ALICE, 2000, 0, 0, 0, False), ("vary", BOB, "start-ts"), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("pay", ALICE, [(BOB, 5)])], "park": None},
    ],
    "routes never leave": [
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, BOB, 1, 0, 0, 60, False)], "park": None},
        {"gap": 600, "proposer": PROPOSER, "actions": [], "park": None},
    ],
    "lock ignored": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", BOB, ALICE, 1, 0, 0, 600, True), ("set", BOB, ALICE, 1, 0, 0, 0, False)], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
    ],
    "more than one hop": [
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", BOB, ALICE, 5000, 0, 0, 0, False)], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, CAROL, 5000, 0, 0, 0, False)], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, ALICE, 1, 0, 0, 0, False), ("pay", ALICE, [(BOB, 4)])], "park": None},
    ],
    "loops allowed": [
        {"gap": 1, "proposer": PROPOSER, "actions": [("set", ALICE, ALICE, 1, 0, 0, 0, False), ("set", ALICE, BOB, 1, 0, 0, 0, False), ("set", BOB, ALICE, 1, 0, 0, 0, False)], "park": None},
        {"gap": 1, "proposer": PROPOSER, "actions": [], "park": None},
    ],
}


@pytest.mark.parametrize("mutant", sorted(MUTANTS))
def test_the_model_catches_a_broken_node(mutant, monkeypatch):
    MUTANTS[mutant](monkeypatch)

    @settings(max_examples=600, deadline=None, database=None, derandomize=True,
              phases=[Phase.explicit, Phase.generate], suppress_health_check=list(HealthCheck))
    @example(program=WITNESSES[mutant])
    @given(program=PROGRAM)
    def search(program):
        check(program)

    with pytest.raises(AssertionError):
        search()
