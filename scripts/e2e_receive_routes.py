#!/usr/bin/env python3
"""End-to-end receive routes (#35) on REAL running nodes with the native Tau engine.

tests/test_receive_route_*.py drive the real block apply in one process; this
drives two live nodes (see scripts/e2e_rig.py): node A mines and is driven
through its RPC port and the `tau-testnet route` CLI; node B receives A's blocks
only.

SCENARIOS (asserted on balances through an accounting oracle, fees to the miner
included, and on the split history every node records)
    1. The shop routes 20% of what it is paid to its tax account with `route set`.
    2. Alice pays the shop 101 (20 routed, 81 kept) and, in one transaction, two
       payments of 9 (each routes 1). Alice is charged exactly as without the
       route.
    3. Credits that land at the end of a block split too: a standing payment by
       the sweep, and a payout leg from a rule another account installed.
    4. The shop's own money coming back is not split: a retractable transfer it
       retracts returns whole.
    5. Node A restarts: the route still splits.
    6. One hop: the tax account routes half of its income to a treasury. A share
       arriving through the shop's route is not routed again; a payment to the
       tax account itself is. A route straight back is refused.
    7. A locked route: the owner cannot remove it or replace it with a weaker
       one; the destination lets go with `route release` (fee-free).
    8. The shop removes its route with `route remove` (fee-free); payments are
       no longer split.
    9. A route with an end in 15 seconds: it splits before, then a block past
       the end removes it (`expired`).
   10. Node B replays A's blocks, restarts, and ends with the same state hash,
       the same balances and the same `getreceiveroute` answers.

USAGE
    python scripts/e2e_receive_routes.py provision --dir .local/e2e-routes
    python scripts/e2e_receive_routes.py run --dir .local/e2e-routes

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import os
import time

import e2e_rig as rig_mod
from e2e_rig import FEE_LIMIT, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-routes"
ACTORS = ("miner", "shop", "tax", "treasury", "alice", "bob", "collab", "reviewer")
PASSTHROUGH = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."


def route(rig, who, node=None):
    return rig.read(f"getreceiveroute {rig.pk[who]}", node) or {}


def splits(rig, who):
    """The owner's `routed` events, oldest first, as (class, gross, routed)."""
    return [(e.get("credit_class"), e.get("gross"), e.get("routed"))
            for e in reversed(route(rig, who).get("history") or []) if e.get("outcome") == "routed"]


def last_outcome(rig, who):
    hist = route(rig, who).get("history") or []
    return hist[0].get("outcome") if hist else None


def set_route(rig, who, to, *flags, expect_ok=True):
    proc = rig.cli("route", "set", "--privkey", rig.privkey(who), "--to", rig.pk[to],
                   "--fee", FEE_LIMIT, *flags)
    if expect_ok:
        check(f"`route set` for {who} -> {to} is admitted", proc.returncode == 0,
              proc.stdout[-400:] + proc.stderr[-400:])
    return proc


def multi_transfer(rig, who, legs):
    payload = rig.common(who)
    payload.update({"tx_type": "user_tx", "fee_limit": FEE_LIMIT,
                    "operations": {"1": [[rig.pk[who], rig.pk[to], str(a)] for to, a in legs]}})
    return rig.submit(who, payload)


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_set_and_transfers(rig, st):
    say("1-2. The shop routes 20% to tax; Alice pays 101, then 9 + 9 in one transaction")
    orc = Oracle(rig, "2", ("shop", "tax", "alice"))
    set_route(rig, "shop", "tax", "--share", "20")
    rig.settle(lambda: route(rig, "shop").get("installed"), "the route to install")
    orc.fee("shop")
    orc.verify("the route set (one fee, no money moved)")
    check("the route reads active, 20%", (route(rig, "shop").get("route") or {}).get("status")
          == "active" and route(rig, "shop")["route"].get("share_bps") == 2000, route(rig, "shop"))
    res = rig.transfer("alice", "shop", 101)
    check("the payment of 101 is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "shop", 81)
    orc.move("alice", "tax", 20)
    orc.verify("101 to the shop (81 kept, 20 routed, Alice charged as without a route)")
    res = multi_transfer(rig, "alice", [("shop", 9), ("shop", 9)])
    check("two payments of 9 in one transaction are admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("alice", 2 * rig_mod.BASE_FEE)  # the fee step charges per transfer, route or not
    orc.move("alice", "shop", 16)
    orc.move("alice", "tax", 2)
    orc.verify("9 + 9 (each splits on its own: 1 + 1 routed, not 3)")
    orc2 = Oracle(rig, "2b", ("alice", "bob"))
    multi_transfer(rig, "alice", [("bob", 9), ("bob", 9)])
    rig.mine(empty=False)
    orc2.fee("alice", 2 * rig_mod.BASE_FEE)
    orc2.move("alice", "bob", 18)
    orc2.verify("the same 9 + 9 to an account with no route (the same fee)")
    check("the history names each split's class and amounts",
          splits(rig, "shop")[-3:] == [("transfer", 101, 20), ("transfer", 9, 1), ("transfer", 9, 1)],
          splits(rig, "shop"))


def scenario_end_of_block_credits(rig, st):
    say("3. A standing payment by the sweep and a payout leg split too")
    orc = Oracle(rig, "3", ("shop", "tax", "alice", "bob", "reviewer"))
    proc = rig.cli("standing", "create", "--privkey", rig.privkey("alice"), "--to", rig.pk["shop"],
                   "--amount", "500", "--periods", "1", "--every-blocks", "128",
                   "--first-due-in", "2", "--fee", FEE_LIMIT)
    check("Alice's standing payment to the shop is admitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("alice")
    rig.mine()
    rig.mine()
    rig.mine()
    orc.move("alice", "shop", 400)
    orc.move("alice", "tax", 100)
    orc.verify("the sweep's payment of 500 (400 kept, 100 routed)")

    proc = rig.cli("payout", "set", "--privkey", rig.privkey("bob"), "--body", PASSTHROUGH,
                   "--slot", rig.pk["shop"], "--cap-per-execution", "100",
                   "--cap-per-period", "100", "--period-blocks", "100", "--ends-in", "500",
                   "--fee", FEE_LIMIT)
    check("Bob's payout rule to the shop is admitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("bob")
    proc = rig.cli("payout", "execute", "--privkey", rig.privkey("reviewer"),
                   "--account", rig.pk["bob"], "--data", "0=50", "--fee", FEE_LIMIT)
    check("a stranger executes it for 50", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("reviewer")
    orc.move("bob", "shop", 40)
    orc.move("bob", "tax", 10)
    orc.verify("the payout leg of 50 (40 kept, 10 routed)")
    check("the splits name their classes",
          [c for c, _g, _r in splits(rig, "shop")[-2:]] == ["standing_payment", "payout"],
          splits(rig, "shop")[-2:])


def scenario_own_money_not_split(rig, st):
    say("4. The shop's own money coming back is not split")
    orc = Oracle(rig, "4", ("shop", "tax", "bob"))
    proc = rig.cli("retractable", "send", "--privkey", rig.privkey("shop"), "--to", rig.pk["bob"],
                   "--amount", "300", "--release-in", "50", "--fee", FEE_LIMIT)
    rid = next((line.split()[-1] for line in (proc.stdout + proc.stderr).splitlines()
                if line.startswith("retractable id:")), None)
    check("the shop parks 300 for Bob", proc.returncode == 0 and rid,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("shop")
    orc.add("shop", -300)
    proc = rig.cli("retractable", "retract", "--privkey", rig.privkey("shop"), rid)
    check("the shop retracts it", proc.returncode == 0, proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.add("shop", 300)
    orc.verify("the retract (300 back whole, nothing routed)")


def scenario_restart(rig, st):
    say("5. Node A restarts; the route still splits")
    orc = Oracle(rig, "5", ("shop", "tax", "alice"))
    before = route(rig, "shop").get("route")
    if not rig.restart_a():
        return
    check("the route survives the restart", route(rig, "shop").get("route") == before,
          (before, route(rig, "shop").get("route")))
    rig.transfer("alice", "shop", 1000)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "shop", 800)
    orc.move("alice", "tax", 200)
    orc.verify("1000 after the restart")


def scenario_one_hop(rig, st):
    say("6. One hop: tax routes half to the treasury; shares are not routed again")
    orc = Oracle(rig, "6", ("shop", "tax", "treasury", "alice"))
    set_route(rig, "tax", "treasury", "--share", "50")
    rig.mine(empty=False)
    orc.fee("tax")
    proc = set_route(rig, "treasury", "tax", "--share", "10", expect_ok=False)
    check("a route straight back (treasury -> tax while tax -> treasury) is refused",
          proc.returncode != 0, proc.stdout[-300:] + proc.stderr[-300:])
    rig.transfer("alice", "shop", 100)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "shop", 80)
    orc.move("alice", "tax", 20)
    orc.verify("100 to the shop (the 20 share reaches tax and stops there)")
    rig.transfer("alice", "tax", 100)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "tax", 50)
    orc.move("alice", "treasury", 50)
    orc.verify("100 to tax itself (split by tax's own route)")


def scenario_locked(rig, st):
    say("7. A locked route: the owner cannot undo it; the destination can let go")
    orc = Oracle(rig, "7", ("bob", "collab"))
    set_route(rig, "bob", "collab", "--share", "10", "--ends-in", "3600", "--locked")
    rig.mine(empty=False)
    orc.fee("bob")
    st["locked_id"] = (route(rig, "bob").get("route") or {}).get("route_id")
    proc = rig.cli("route", "remove", "--privkey", rig.privkey("bob"))
    check("the owner cannot remove a locked route", proc.returncode != 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    proc = set_route(rig, "bob", "collab", "--share", "5", "--ends-in", "3600", "--locked",
                     expect_ok=False)
    check("nor replace it with a smaller share", proc.returncode != 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    proc = rig.cli("route", "release", "--privkey", rig.privkey("collab"), "--owner", rig.pk["bob"])
    check("the destination's `route release` is admitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    check("the route is gone: `released`", not route(rig, "bob").get("installed")
          and last_outcome(rig, "bob") == "released", route(rig, "bob").get("history", [])[:2])
    orc.verify("the locked route and its release (fee-free)")


def scenario_remove(rig, st):
    say("8. The shop removes its route; payments are whole again")
    orc = Oracle(rig, "8", ("shop", "tax", "alice"))
    proc = rig.cli("route", "remove", "--privkey", rig.privkey("shop"))
    check("`route remove` is admitted", proc.returncode == 0, proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    check("the route is gone: `removed`", not route(rig, "shop").get("installed")
          and last_outcome(rig, "shop") == "removed", route(rig, "shop").get("history", [])[:2])
    rig.transfer("alice", "shop", 100)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "shop", 100)
    orc.verify("the remove (fee-free) and a whole payment after it")


def scenario_expiry(rig, st):
    say("9. A route that ends in 15 seconds")
    orc = Oracle(rig, "9", ("shop", "tax", "alice"))
    set_route(rig, "shop", "tax", "--share", "30", "--ends-in", "15")
    rig.mine(empty=False)
    orc.fee("shop")
    end = int((route(rig, "shop").get("route") or {}).get("expires_at") or 0)
    rig.transfer("alice", "shop", 100)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "shop", 70)
    orc.move("alice", "tax", 30)
    time.sleep(max(0.0, end - time.time() + 2))
    rig.mine()
    check("a block past the end removes it: `expired`", not route(rig, "shop").get("installed")
          and last_outcome(rig, "shop") == "expired", route(rig, "shop").get("history", [])[:2])
    rig.transfer("alice", "shop", 100)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "shop", 100)
    orc.verify("before and after the end")


def scenario_follower(rig, st):
    say("10. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getreceiveroute {rig.pk[n]}" for n in ("shop", "tax", "treasury", "bob", "collab")]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_set_and_transfers(rig, st)
            scenario_end_of_block_credits(rig, st)
            scenario_own_money_not_split(rig, st)
            scenario_restart(rig, st)
            scenario_one_hop(rig, st)
            scenario_locked(rig, st)
            scenario_remove(rig, st)
            scenario_expiry(rig, st)
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
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local", "e2e-routes"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
