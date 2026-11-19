#!/usr/bin/env python3
"""End-to-end programmable payments against REAL, disposable node processes.

The tests/test_{grant,standing,receive_routes,payout}_*.py suites mock the
engine; this drives live nodes with the NATIVE Tau engine, so it exercises what
only exists at runtime: the real fee rule, a payout rule compiled and stepped by
real Tau, block timestamps from the wall clock, the books surviving a restart,
and a second node reproducing the same state from the first node's blocks.

It reuses the isolation, provisioning and node harness of
scripts/e2e_retractable.py (same refusal rules: every node runs from its own
exported tree, database and ports).

USAGE
    python scripts/e2e_programmable_payments.py provision --dir .local/pp-e2e
    TAU_NATIVE_PATH=<dir with the tau module> \\
        python scripts/e2e_programmable_payments.py run --dir .local/pp-e2e

SCENARIOS
    g. conditional grant: time lock, per-period cap, expiry refund (the Alice/Bob demo, scaled to minutes)
    s. standing payment: due now, executed by the payee, second execution refused, cancel
    r. receive route: 20% of a 101 credit, floor rounding, single hop
    p. payout rule: a real Tau royalty rule, 5% / 95% split, cap refusal
    x. restart: every book survives; a follower node syncs to the same head

ASSERTION DISCIPLINE
    Balances are checked with an oracle of expected deltas per address. Fees are
    whatever the real fee rule charges: each fee is read as the miner's balance
    delta for that block (blocks are explicit, one transaction each, miner off)
    and charged to the transaction's sender in the oracle, so conservation is
    still checked exactly.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import e2e_retractable as h  # noqa: E402  (the shared harness)

h.NETWORK_ID = "tau-pp-e2e"
h.RPC_PORTS = {"node1": 64750, "node2": 64760}
h.P2P_PORTS = {"node1": 64770, "node2": 64780}
h.SCENARIOS = ("g", "s", "r", "p")
h.ROLES = ("sender", "recipient", "other")
h.ACTORS = ("miner",) + tuple(f"{s}_{r}" for s in h.SCENARIOS for r in h.ROLES) + ("pad1", "pad2")

say, check, ok, err_code, produce, wait_until = (
    h.say, h.check, h.ok, h.err_code, h.produce, h.wait_until)

FIXED_HOUR = 0  # periods.PERIOD_FIXED
DAY = 1

ROYALTY = ("(o1[t]:bv[24] = i13[t]:bv[24] / { 20 }:bv[24]) && "
           "(o2[t]:bv[24] = i13[t]:bv[24] - i13[t]:bv[24] / { 20 }:bv[24])")


class PP(h.Signer):
    """Builds, signs and submits the programmable-payment transactions."""

    def _env(self, node, name):
        seq, tip = self._envelope(node, name)
        chain_id = node.rpc("getchainid")["data"]["chain_id"]
        return dict(sender_pubkey=self.pk(name), sequence_number=seq,
                    expiration_time=int(time.time()) + 3600, expire_at_height=tip + 1000,
                    chain_id=chain_id)

    def send(self, node, name, payload):
        return self.submit(node, self.sign(name, payload))

    def grant_create(self, node, name, to, **terms):
        p = self.tx.build_grant_create_tx(**self._env(node, name), grantee_pubkey=self.pk(to),
                                          fee_limit="100000", **terms)
        from consensus.grants import parse_grant_create
        return self.send(node, name, p), parse_grant_create(p).grant_id.hex()

    def grant_draw(self, node, name, gid, to, amount):
        return self.send(node, name, self.tx.build_grant_draw_tx(
            **self._env(node, name), grant_id=gid, recipient_pubkey=self.pk(to),
            amount=amount, fee_limit="100000"))

    def standing_create(self, node, name, to, **terms):
        p = self.tx.build_standing_create_tx(**self._env(node, name),
                                             recipient_pubkey=self.pk(to),
                                             fee_limit="100000", **terms)
        from consensus.standing import parse_standing_create
        return self.send(node, name, p), parse_standing_create(p)

    def standing_execute(self, node, name, sid, period):
        return self.send(node, name, self.tx.build_standing_execute_tx(
            **self._env(node, name), standing_id=sid, period=period, fee_limit="100000"))

    def standing_cancel(self, node, name, sid):
        return self.send(node, name, self.tx.build_standing_cancel_tx(
            **self._env(node, name), standing_id=sid))

    def route_set(self, node, name, to, bps):
        return self.send(node, name, self.tx.build_route_set_tx(
            **self._env(node, name), destination_pubkey=self.pk(to), bps=bps,
            fee_limit="100000"))

    def payout_install(self, node, name, recipients, rule, **caps):
        p = self.tx.build_payout_install_tx(
            **self._env(node, name), rule_text=rule,
            recipients=[self.pk(r) for r in recipients], fee_limit="100000", **caps)
        from consensus.payouts import parse_payout_install
        return self.send(node, name, p), parse_payout_install(p).rule_id.hex()

    def payout_execute(self, node, name, rid, inputs):
        return self.send(node, name, self.tx.build_payout_execute_tx(
            **self._env(node, name), rule_id=rid, inputs=inputs, fee_limit="100000"))


def mine_one(node, orc, payer, label):
    """Mine one block and charge its fee (the miner's delta) to `payer` in the oracle."""
    miner = orc.signer.pk("miner")
    before = node.balance(miner)
    check(f"{label}: mined", produce(node, node.height() + 1))
    fee = node.balance(miner) - before
    orc.add(payer, -fee)
    orc.add("miner", fee)
    return fee


def admitted(res, label):
    return check(f"{label}: admitted", ok(res), json.dumps(res)[:300])


def refused(res, label, code=None):
    return check(f"{label}: refused at admission",
                 not ok(res) and (code is None or err_code(res) == code), json.dumps(res)[:300])


def scenario_g(node, sg):
    say("g. grant: time lock, per-period cap, expiry refund")
    s, r, o = "g_sender", "g_recipient", "g_other"
    orc = h.Oracle(node, sg, "g", (s, r, o))
    now = int(time.time())
    start, expires = now + 20, now + 150
    res, gid = sg.grant_create(node, s, r, amount=5000, start_at=start, expires_at=expires,
                               spend_cap=500, cap_period_kind=FIXED_HOUR,
                               cap_period_seconds=3600)
    admitted(res, "g: create")
    mine_one(node, orc, s, "g: create")
    orc.add(s, -5000)
    orc.verify("after create")
    refused(sg.grant_draw(node, r, gid, o, 100), "g: draw before start_at (time lock)")
    wait_until(lambda: time.time() > start + 2, "start_at", timeout=60)
    admitted(sg.grant_draw(node, r, gid, o, 300), "g: draw 300")
    mine_one(node, orc, r, "g: draw 300")
    orc.add(o, 300)
    admitted(sg.grant_draw(node, r, gid, o, 200), "g: draw 200")
    mine_one(node, orc, r, "g: draw 200")
    orc.add(o, 200)
    orc.verify("after draws")
    refused(sg.grant_draw(node, r, gid, o, 1), "g: draw past the cap", "GRANT_DRAW_REJECTED")
    rows = node.rpc(f"getgrants {sg.pk(r)} in")["data"]["grants"]
    check("g: getgrants shows remaining 4500 and nothing drawable", rows and
          rows[0]["remaining"] == 4500 and rows[0]["drawable_now"] == 0, rows)
    wait_until(lambda: time.time() > expires + 1, "expires_at", timeout=200)
    check("g: refund block mined", produce(node, node.height() + 1, allow_empty=True))
    orc.add(s, 4500)
    orc.verify("after expiry refund")
    check("g: grant gone", node.rpc(f"getgrants {sg.pk(r)} in")["data"]["grants"] == [])
    return gid


def scenario_s(node, sg):
    say("s. standing payment: executed by the payee, once per period, then cancelled")
    s, r, o = "s_sender", "s_recipient", "s_other"
    orc = h.Oracle(node, sg, "s", (s, r, o))
    now = int(time.time())
    offset = max(0, now % 86_400 - 120)
    res, terms = sg.standing_create(node, s, r, amount=1000, period_kind=DAY,
                                    start_at=now - (now % 86_400), due_offset_seconds=offset,
                                    window_seconds=3600, max_occurrences=3)
    admitted(res, "s: create")
    mine_one(node, orc, s, "s: create")
    sid = terms.standing_id.hex()
    rows = node.rpc(f"getstandingpayments {sg.pk(r)} in")["data"]["standing_payments"]
    check("s: due now and not yet paid", rows and rows[0]["due_period"] is not None
          and rows[0]["paid_this_period"] is False, rows)
    period = rows[0]["due_period"]
    admitted(sg.standing_execute(node, r, sid, period), "s: payee executes")
    fee = mine_one(node, orc, r, "s: execute")
    orc.add(s, -1000)
    orc.add(r, 1000)
    orc.verify("after execution")
    check("s: the payee paid the execution fee", fee >= 0, fee)
    refused(sg.standing_execute(node, o, sid, period), "s: second execution in the period",
            "STANDING_NOT_DUE")
    rows = node.rpc(f"getstandingpayments {sg.pk(s)} out")["data"]["standing_payments"]
    check("s: paid_this_period", rows and rows[0]["paid_this_period"] is True
          and rows[0]["executions"] == 1, rows)
    admitted(sg.standing_cancel(node, s, sid), "s: cancel")
    mine_one(node, orc, s, "s: cancel")
    orc.verify("after cancel")
    check("s: cancelled", node.rpc(f"getstandingpayments {sg.pk(s)}")["data"]["standing_payments"] == [])
    return sid


def scenario_r(node, sg):
    say("r. receive route: 20% of every credit, floor rounding")
    s, r, o = "r_sender", "r_recipient", "r_other"
    orc = h.Oracle(node, sg, "r", (s, r, o))
    admitted(sg.route_set(node, r, o, 2000), "r: route set")
    mine_one(node, orc, r, "r: route set")
    route = node.rpc(f"getreceiveroute {sg.pk(r)}")["data"]["route"]
    check("r: route active", route and route["active"] and route["bps"] == 2000, route)
    admitted(sg.transfer(node, s, r, 101), "r: send 101")
    mine_one(node, orc, s, "r: send")
    orc.add(s, -101)
    orc.add(r, 81)
    orc.add(o, 20)
    orc.verify("after routed credit")


def scenario_p(node, sg):
    say("p. payout rule compiled and stepped by real Tau")
    s, r, o = "p_sender", "p_recipient", "p_other"
    orc = h.Oracle(node, sg, "p", (s, r, o))
    res, rid = sg.payout_install(node, s, [r, o], ROYALTY, max_per_execution=2000,
                                 max_per_period=2500, period_kind=FIXED_HOUR,
                                 period_seconds=3600)
    admitted(res, "p: install (rule builds in the payout pool)")
    mine_one(node, orc, s, "p: install")
    admitted(sg.payout_execute(node, o, rid, {"13": "1000"}), "p: execute price 1000")
    mine_one(node, orc, o, "p: execute")
    orc.add(s, -1000)
    orc.add(r, 50)
    orc.add(o, 950)
    orc.verify("after royalty split")
    admitted(sg.payout_execute(node, o, rid, {"13": "1600"}), "p: execute over the period cap")
    before = node.balance(sg.pk(s))
    mine_one(node, orc, o, "p: over-cap execute")
    check("p: over-cap execution paid nothing", node.balance(sg.pk(s)) == before)
    orc.verify("after refused over-cap execution")
    return rid


def scenario_c(node, sg):
    say("c. cross-network replay: a tx signed for another chain id is refused")
    env = sg._env(node, "r_sender")
    env["chain_id"] = "9a" * 32
    p = sg.tx.build_route_remove_tx(**env)
    refused(sg.send(node, "r_sender", p), "c: other network's chain_id", "WRONG_CHAIN_ID")


def scenario_x(node1, node2, sg):
    say("x. restart and follower sync")
    snap = {
        "routes": node1.rpc(f"getreceiveroute {sg.pk('r_recipient')}")["data"]["route"],
        "payouts": node1.rpc(f"getpayoutrules {sg.pk('p_sender')} out")["data"]["payout_rules"],
    }
    node1.stop()
    node1.start()
    check("x: node1 restarted", node1.wait_ready())
    again = {
        "routes": node1.rpc(f"getreceiveroute {sg.pk('r_recipient')}")["data"]["route"],
        "payouts": node1.rpc(f"getpayoutrules {sg.pk('p_sender')} out")["data"]["payout_rules"],
    }
    for k in snap:
        for item in (snap[k] if isinstance(snap[k], list) else [snap[k]]):
            item and item.pop("as_of", None)
    check("x: books survive a restart", json.dumps(snap, sort_keys=True, default=str)[:4000]
          == json.dumps(again, sort_keys=True, default=str)[:4000])
    node1.peer_id = node1.peer_id or node1._peer_id()
    node2.bootstrap = [{"peer_id": node1.peer_id,
                        "addrs": [f"/ip4/127.0.0.1/tcp/{node1.p2p_port}"]}]
    node2.start()
    check("x: node2 ready", node2.wait_ready())
    target = node1.head()
    check("x: follower reaches the same head", wait_until(
        lambda: node2.head().get("block_hash") == target.get("block_hash"),
        "node2 head", timeout=300), (node2.head().get("block_hash"), target.get("block_hash")))


def run(base, log_dir, deadline):
    base = os.path.abspath(base)
    h.DEADLINE[0] = time.time() + deadline
    keys = json.load(open(os.path.join(base, "keys.json")))
    node1 = h.Node("node1", base, keys, os.path.join(log_dir, "pp-e2e-node1.log"), mining=False)
    node2 = h.Node("node2", base, keys, os.path.join(log_dir, "pp-e2e-node2.log"), mining=False)
    h.assert_isolated(base, node1.paths() + node2.paths())
    for node in (node1, node2):
        if os.path.exists(node.db_path):
            raise SystemExit(f"REFUSING: {node.db_path} already exists; re-provision for a clean run")
    import atexit
    atexit.register(h.stop_all)
    sg = PP(keys, node1.tree)
    try:
        node1.start()
        if not node1.wait_ready():
            say("node1 did not become ready")
            return 2
        scenario_r(node1, sg)
        scenario_s(node1, sg)
        scenario_p(node1, sg)
        scenario_g(node1, sg)
        scenario_c(node1, sg)
        scenario_x(node1, node2, sg)
    finally:
        h.stop_all()
    say("")
    if h.FAILED:
        say(f"{len(h.FAILED)} check(s) FAILED:")
        for name in h.FAILED:
            say(f"  - {name}")
        return 1
    say("All checks passed.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run"])
    parser.add_argument("--dir", default=os.path.join(h.REPO, ".local", "pp-e2e"))
    parser.add_argument("--log-dir", default=os.path.join(h.REPO, ".local"))
    parser.add_argument("--overlay-worktree", action="store_true")
    parser.add_argument("--deadline", type=int, default=3000)
    args = parser.parse_args(argv)
    os.makedirs(args.log_dir, exist_ok=True)
    if args.mode == "provision":
        return h.provision(args.dir, args.overlay_worktree)
    h.require_native()
    return run(args.dir, args.log_dir, args.deadline)


if __name__ == "__main__":
    raise SystemExit(main())
