#!/usr/bin/env python3
"""End-to-end envelopes with spending limits on REAL running nodes with the native Tau engine.

tests/test_envelope_*.py drive the real block apply in one process, and
tests/test_envelope_policy_native.py steps real o5 clauses; this drives two live
nodes (see scripts/e2e_rig.py): node A mines and is driven through its RPC port
and the `tau-testnet envelope` CLI; node B receives A's blocks only.

SCENARIOS (asserted on balances through an accounting oracle, fees to the miner
included, and on the envelope history every node records)
    1. A parent sends a child 1,000 with `envelope send`: at most 300 per
       10 blocks, every period. The amount leaves the parent when the send is
       mined.
    2. The child spends 200 to a shop, then 100 more; 150 in between is refused
       (ENVELOPE_LIMIT). In the next period two spends of 200 are queued
       together: the first lands, the second is refused when its block applies
       and is dropped, so it costs nothing. A spend `--to self`.
    3. o5 clauses on the real engine: the child's own clause judges its spends
       (61 refused, 60 lands); the parent's clause does not judge spends, but it
       does judge the parent's sends.
    4. Node A restarts: the envelope, its period and what it used survive.
    5. Receive routes: a spend splits by the payee's route (`envelope_spend`);
       the parent's `envelope release` (fee-free) sends the rest to the child,
       split by the child's route (`envelope_release`).
    6. An envelope nobody spends reaches its end: the rest goes to the child at
       the end of that block (`ended`).
    7. Node B replays A's blocks, restarts, and ends with the same state hash,
       the same balances and the same `getenvelope` / `getenvelopes` answers.

USAGE
    python scripts/e2e_envelope_limits.py provision --dir .local/e2e-envelope-limits
    python scripts/e2e_envelope_limits.py run --dir .local/e2e-envelope-limits

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import os

import e2e_rig as rig_mod
from e2e_rig import FEE_LIMIT, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-envelope-limits"
ACTORS = ("miner", "parent", "child", "shop", "tax", "piggy", "gran")

BLOCK_ALL = ("always ( i1[t]:bv[24] > { #x000000 }:bv[24] -> "
             "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")
ALLOW_ALL = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."


def spend_limit(limit):
    return ("always ( (i1[t]:bv[24] > { #x%06x }:bv[24]) ? "
            "( o5[t]:bv[24] = { #x000000 }:bv[24] ) : "
            "( o5[t]:bv[24] = { #x000001 }:bv[24] ) )." % limit)


# --- helpers shared by the envelope e2e scripts --------------------------------------

def envelope(rig, eid, node=None):
    return rig.read(f"getenvelope {eid}", node) or {}


def held(rig, eid):
    return int((envelope(rig, eid).get("envelope") or {}).get("remaining") or 0)


def closed(rig, eid):
    return envelope(rig, eid).get("closed")


def send(rig, who, to, *flags, expect_ok=True):
    """`envelope send`; returns (proc, envelope id or None)."""
    proc = rig.cli("envelope", "send", "--privkey", rig.privkey(who), "--to", rig.pk[to],
                   "--fee", FEE_LIMIT, *flags)
    eid = next((line.split()[-1] for line in (proc.stdout + proc.stderr).splitlines()
                if line.startswith("envelope id:")), None)
    if expect_ok:
        check(f"`envelope send` {who} -> {to} is admitted and prints the id",
              proc.returncode == 0 and eid, proc.stdout[-400:] + proc.stderr[-400:])
    return proc, eid


def spend(rig, who, eid, to, amount):
    """`envelope spend`; `to` is an actor or "self"."""
    target = "self" if to == "self" else rig.pk[to]
    return rig.cli("envelope", "spend", "--privkey", rig.privkey(who), eid, "--to", target,
                   "--amount", str(amount), "--fee", FEE_LIMIT)


def raw_spend(rig, who, eid, to, amount):
    from tau_testnet_cli import tx as cli_tx
    payload = cli_tx.build_envelope_spend_tx(
        **rig.common(who), envelope_id=eid, to_pubkey=rig.pk[to], amount=amount,
        fee_limit=FEE_LIMIT)
    return rig.submit(who, payload)


def code(res):
    return (res.get("error") or {}).get("code")


def o5(rig, who, clause):
    payload = rig.common(who)
    payload.update({"tx_type": "user_tx", "fee_limit": FEE_LIMIT, "operations": {"0": clause}})
    res = rig.submit(who, payload)
    check(f"{who}'s o5 clause is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)


def ok_proc(label, proc):
    return check(label, proc.returncode == 0, proc.stdout[-300:] + proc.stderr[-300:])


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_send(rig, st):
    say("1. The parent sends the child 1,000: at most 300 per 10 blocks")
    orc = Oracle(rig, "1", ("parent", "child"))
    _proc, eid = send(rig, "parent", "child", "--amount", "1000", "--cap", "300", "--recurring",
                      "--period-blocks", "10", "--ends-in-blocks", "200")
    st["main"] = eid
    rig.mine(empty=False)
    orc.fee("parent")
    orc.add("parent", -1000)
    orc.verify("the send (1,000 leaves the parent, the child gets nothing yet)")
    env = envelope(rig, eid).get("envelope") or {}
    check("the envelope holds 1,000, 300 spendable this period",
          env.get("remaining") == 1000 and env.get("left_this_period") == 300, env)


def scenario_spends(rig, st):
    say("2. The child spends within the cap; over it is refused")
    eid = st["main"]
    orc = Oracle(rig, "2", ("child", "shop"))
    ok_proc("a spend of 200 to the shop is admitted", spend(rig, "child", eid, "shop", 200))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 200)
    res = raw_spend(rig, "child", eid, "shop", 150)
    check("150 more (350 of 300) is refused ENVELOPE_LIMIT", code(res) == "ENVELOPE_LIMIT", res)
    ok_proc("100 more (300 of 300) is admitted", spend(rig, "child", eid, "shop", 100))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 100)
    orc.verify("the first period (300 spent, the child pays only fees)")
    check("the envelope holds 700", held(rig, eid) == 700, envelope(rig, eid).get("envelope"))

    env = envelope(rig, eid).get("envelope") or {}
    while (envelope(rig, eid).get("envelope") or {}).get("period_index") == env.get("period_index"):
        rig.mine()
    a = raw_spend(rig, "child", eid, "shop", 200)
    b = raw_spend(rig, "child", eid, "shop", 200)  # the next sequence: getsequence counts the queue
    check("two spends of 200 are both admitted against the tip", a.get("status") == "ok"
          and b.get("status") == "ok", (a, b))
    rig.mine(empty=False)
    rig.mine()
    orc.fee("child")
    orc.add("shop", 200)
    orc.verify("the two queued spends (the second refused in its block, no fee)")
    check("the envelope holds 500", held(rig, eid) == 500, envelope(rig, eid).get("envelope"))
    while (envelope(rig, eid).get("envelope") or {}).get("left_this_period") != 300:
        rig.mine()
    ok_proc("a spend `--to self` of 50 is admitted", spend(rig, "child", eid, "self", 50))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("child", 50)
    orc.verify("the spend to the child itself")


def scenario_o5(rig, st):
    say("3. o5 clauses on the real engine")
    eid = st["main"]
    orc = Oracle(rig, "3", ("child", "shop", "parent"))
    o5(rig, "child", spend_limit(60))
    orc.fee("child")
    res = raw_spend(rig, "child", eid, "shop", 61)
    check("the child's own clause refuses a spend of 61", res.get("status") != "ok", res)
    ok_proc("and lets 60 through", spend(rig, "child", eid, "shop", 60))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 60)
    o5(rig, "parent", BLOCK_ALL)
    orc.fee("parent")
    ok_proc("the parent's clause does not judge the child's spends",
            spend(rig, "child", eid, "shop", 40))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 40)
    proc, _eid = send(rig, "parent", "child", "--amount", "100", "--cap", "50",
                      "--period-blocks", "10", "--ends-in-blocks", "100", expect_ok=False)
    check("but it judges the parent's own sends", proc.returncode != 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    o5(rig, "parent", ALLOW_ALL)
    orc.fee("parent")
    o5(rig, "child", ALLOW_ALL)
    orc.fee("child")
    orc.verify("the clauses")


def scenario_restart(rig, st):
    say("4. Node A restarts")
    eid = st["main"]
    before = envelope(rig, eid).get("envelope")
    if not rig.restart_a():
        return
    after = envelope(rig, eid).get("envelope")
    check("the envelope, its period and what it used survive", after == before, (before, after))


def scenario_routes_and_release(rig, st):
    say("5. Routes split spends and releases; the parent releases the rest")
    eid = st["main"]
    orc = Oracle(rig, "5", ("parent", "child", "shop", "tax", "piggy"))
    ok_proc("the shop routes 10% to tax", rig.cli(
        "route", "set", "--privkey", rig.privkey("shop"), "--to", rig.pk["tax"],
        "--share", "10", "--fee", FEE_LIMIT))
    rig.mine(empty=False)
    orc.fee("shop")
    while (envelope(rig, eid).get("envelope") or {}).get("left_this_period", 0) < 100:
        rig.mine()
    ok_proc("a spend of 100 to the shop", spend(rig, "child", eid, "shop", 100))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 90)
    orc.add("tax", 10)
    ok_proc("the child routes 20% to its piggy bank", rig.cli(
        "route", "set", "--privkey", rig.privkey("child"), "--to", rig.pk["piggy"],
        "--share", "20", "--fee", FEE_LIMIT))
    rig.mine(empty=False)
    orc.fee("child")
    rest = held(rig, eid)
    ok_proc("the parent's `envelope release` is admitted", rig.cli(
        "envelope", "release", "--privkey", rig.privkey("parent"), eid))
    rig.mine(empty=False)
    orc.add("child", rest - rest * 2000 // 10000)
    orc.add("piggy", rest * 2000 // 10000)
    orc.verify(f"the spend (split by the shop's route) and the release of {rest} (fee-free, "
               "split by the child's route)")
    check("the envelope reads `released`", closed(rig, eid) == "released", envelope(rig, eid))
    route_hist = [(e.get("credit_class"), e.get("gross")) for e in
                  (rig.read(f"getreceiveroute {rig.pk['child']}") or {}).get("history") or []
                  if e.get("outcome") == "routed"]
    check("the split names the class `envelope_release`",
          ("envelope_release", rest) in route_hist, route_hist)


def scenario_end(rig, st):
    say("6. An envelope nobody spends reaches its end")
    orc = Oracle(rig, "6", ("gran", "child", "piggy"))
    _proc, eid = send(rig, "gran", "child", "--amount", "100", "--cap", "100",
                      "--period-blocks", "5", "--ends-in-blocks", "6")
    st["ended"] = eid
    rig.mine(empty=False)
    orc.fee("gran")
    orc.add("gran", -100)
    env = envelope(rig, eid).get("envelope") or {}
    end = int(env.get("due_at") or env.get("expires_at") or 0)
    rig.mine_to(end)
    check("it closed at the end: `ended`", closed(rig, eid) == "ended", envelope(rig, eid))
    orc.add("child", 80)
    orc.add("piggy", 20)
    orc.verify("the end (the rest to the child, through its route)")


def scenario_follower(rig, st):
    say("7. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getenvelope {eid}" for eid in st.values() if eid]
    reads += [f"getenvelopes {rig.pk[n]} all" for n in ("parent", "child", "gran")]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_send(rig, st)
            scenario_spends(rig, st)
            scenario_o5(rig, st)
            scenario_restart(rig, st)
            scenario_routes_and_release(rig, st)
            scenario_end(rig, st)
            scenario_follower(rig, st)
    except Exception:
        import traceback
        check("the run completed", False, traceback.format_exc()[-1500:])
    finally:
        rig.stop()
    return rig.finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run"])
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local",
                                                      "e2e-envelope-limits"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
