#!/usr/bin/env python3
"""End-to-end: several payout rules per account, and a due point tried again,
on REAL running nodes with the native Tau engine.

    rule_index   Alice keeps three rules, each in its own place: a rent of 100
                 to Bob, a rent of 30 to Carol, and a rule anyone may execute
                 that pays Dave what is asked. A set or a revoke touches only
                 its own place; an execution names its rule by id.
    due_retry    Dave's rent finds his account short at the due point. The node
                 runs it again in later blocks, also after a restart, and it is
                 paid in the block that brings the money.

Two live nodes (see scripts/e2e_rig.py): node A mines and is driven through its
RPC port and the CLI; node B receives A's blocks only. The clock is the block
height.

SCENARIOS (balances through an accounting oracle, fees to the miner included)
    1. Alice installs the two rents in place 0 and place 1, due in the same
       block. That block has no transaction; Bob has 100 more and Carol 30.
    2. Alice installs a third rule in place 2. Carol executes it with
       `--rule-index 2` and Dave has 40; the rents are untouched.
    3. Alice replaces place 1 (a rent of 20 now) and revokes place 2: place 0
       is the rule it was, place 1 the new one, place 2 is empty.
    4. Dave installs a rent of 100 to Bob with `--due-retry`, holding less than
       100 at the due point: not paid, a retry is owed.
    5. Node A restarts: the places and the owed retry are still there.
    6. Carol pays Dave 150: in that block the retry pays Bob 100. Later blocks
       pay nothing more.
    7. Node B replays A's blocks, restarts, and ends with the same state hash.

USAGE
    python scripts/e2e_payout_places.py provision --dir .local/e2e-places
    python scripts/e2e_payout_places.py run --dir .local/e2e-places

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import os

import e2e_rig as rig_mod
from e2e_rig import BASE_FEE, FEE_LIMIT, FUNDS, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-places"
ACTORS = ("miner", "alice", "bob", "carol", "dave")


def c(n, w=24):
    return "{ %d }:bv[%d]" % (n, w)


NOBODY = "(i13[t]:bv[384] = { 0 }:bv[384])"


def rent(amount):
    """`amount` to slot 0 when the node itself runs the rule, nothing for anyone else."""
    return (f"always ( {NOBODY} ? (o30[t]:bv[24] = {c(amount)}) "
            f": (o30[t]:bv[24] = {c(0)}) ).")


ASKED = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."


def payout(rig, who, node=None):
    return rig.read(f"getpayoutrule {rig.pk[who]}", node) or {}


def places(rig, who):
    return {int(r.get("rule_index") or 0): r for r in payout(rig, who).get("rules") or []}


def history(rig, who):
    return payout(rig, who).get("history") or []


def install(rig, who, body, *flags):
    proc = rig.cli("payout", "set", "--privkey", rig.privkey(who), "--body", body,
                   "--fee", FEE_LIMIT, *flags)
    return proc.returncode == 0, proc.stdout[-400:] + proc.stderr[-400:]


def cli(rig, *args):
    proc = rig.cli(*args)
    return proc.returncode == 0, proc.stdout[-400:] + proc.stderr[-400:]


def pay(rig, orc, who, to, amount, label):
    res = rig.transfer(who, to, amount)
    ok = check(label, res.get("status") == "ok", res)
    if ok:
        orc.fee(who)
        orc.move(who, to, amount)
    return ok


def _rent_flags(rig, to, amount, due, *more):
    return ("--slot", rig.pk[to], "--cap-per-execution", str(amount),
            "--cap-per-period", str(amount), "--period-blocks", "10", "--ends-in", "2000",
            "--due-at", str(due), *more)


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_two_rents(rig, st):
    say("1. Two rules on one account, due in the same block")
    orc = Oracle(rig, "1", ("alice", "bob", "carol"))
    due = rig.a.height() + 5
    ok, out = install(rig, "alice", rent(100), *_rent_flags(rig, "bob", 100, due))
    check("the first rule (no --rule-index) is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("alice")
    ok, out = install(rig, "alice", rent(30), *_rent_flags(rig, "carol", 30, due),
                      "--rule-index", "1")
    check("the second rule (--rule-index 1) is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("alice")
    got = places(rig, "alice")
    check("both are installed, each in its own place, with their own ids",
          sorted(got) == [0, 1] and got[0]["rule_id"] != got[1]["rule_id"]
          and got[1].get("rule_index") == 1 and "rule_index" not in got[0], got)
    check("`rule` is still the first place's rule",
          payout(rig, "alice").get("rule", {}).get("rule_id") == got[0]["rule_id"],
          payout(rig, "alice").get("rule"))
    st["alice0"] = got[0]["rule_id"]
    rig.mine_to(due - 1)
    orc.verify("the blocks before the due point (two install fees)")
    rig.mine()
    orc.move("alice", "bob", 100)
    orc.move("alice", "carol", 30)
    orc.verify("the due block (100 to Bob and 30 to Carol, nobody paid a fee)")
    runs = [e for e in history(rig, "alice") if e.get("outcome") == "executed"]
    check("the history names both runs, the second with its place",
          {(e.get("rule_index") or 0, e.get("total")) for e in runs[:2]} == {(0, 100), (1, 30)},
          runs[:2])


def scenario_third_place(rig, st):
    say("2. A third rule in place 2, executed by anyone with --rule-index")
    orc = Oracle(rig, "2", ("alice", "carol", "dave"))
    ok, out = install(rig, "alice", ASKED, "--slot", rig.pk["dave"],
                      "--cap-per-execution", "50", "--cap-per-period", "500",
                      "--period-blocks", "10", "--ends-in", "2000", "--rule-index", "2")
    check("the rule in place 2 is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("alice")
    ok, out = cli(rig, "payout", "execute", "--privkey", rig.privkey("carol"),
                  "--account", rig.pk["alice"], "--rule-index", "2", "--data", "0=40",
                  "--fee", FEE_LIMIT)
    check("Carol's execution of place 2 is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("carol")
    orc.move("alice", "dave", 40)
    orc.verify("the execution (40 to Dave, Carol paid her fee)")
    got = places(rig, "alice")
    check("only place 2 counts the execution",
          got[2].get("executions") == 1 and got[0].get("executions") == 1
          and got[1].get("executions") == 1, got)


def scenario_replace_and_revoke(rig, st):
    say("3. A set replaces only its place; a revoke removes only its place")
    orc = Oracle(rig, "3", ("alice",))
    old1 = places(rig, "alice")[1]["rule_id"]
    due = rig.a.height() + 400
    ok, out = install(rig, "alice", rent(20), *_rent_flags(rig, "carol", 20, due),
                      "--rule-index", "1")
    check("a new rule for place 1 is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("alice")
    ok, out = cli(rig, "payout", "revoke", "--privkey", rig.privkey("alice"),
                  "--rule-index", "2")
    check("`payout revoke --rule-index 2` is admitted", ok, out)
    rig.mine(empty=False)
    orc.verify("replace and revoke (one install fee, the revoke is free)")
    got = places(rig, "alice")
    check("place 0 is the rule it was, place 1 the new one, place 2 is empty",
          sorted(got) == [0, 1] and got[0]["rule_id"] == st["alice0"]
          and got[1]["rule_id"] != old1 and got[1].get("cap_per_execution") == 20, got)
    replaced = [e for e in history(rig, "alice") if e.get("replaced") == old1]
    check("the history names the replaced rule", len(replaced) == 1, history(rig, "alice")[:3])


def scenario_short(rig, st):
    say("4. Dave's rent finds his account short: a retry is owed")
    orc = Oracle(rig, "4", ("dave", "bob"))
    st["dave_due"] = rig.a.height() + 4
    ok, out = install(rig, "dave", rent(100), *_rent_flags(rig, "bob", 100, st["dave_due"]),
                      "--due-retry", "200")
    check("`payout set --due-retry` is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("dave")
    st["dave_held"] = rig.balance("dave")
    check("Dave holds less than the rent", st["dave_held"] < 100, st["dave_held"])
    rig.mine_to(st["dave_due"])
    orc.verify("the due point (nothing moved)")
    first = next((e for e in history(rig, "dave") if e.get("outcome") == "due_not_paid"), {})
    check("the history says not paid, the account was short, and when it retries",
          f"holds {st['dave_held']}" in (first.get("reason") or "")
          and first.get("retry_at") == st["dave_due"] + 1, first)
    rig.mine()
    again = history(rig, "dave")[0]
    check("the next block tries again", again.get("retry") is True
          and again.get("outcome") == "due_not_paid", again)
    got = places(rig, "dave")[0]
    check("the wallet RPC shows the retry it owes",
          got.get("due_retry") == 200 and got.get("retry_until") == st["dave_due"] + 200
          and got.get("retry_at") == rig.a.height() + 1, got)


def scenario_restart(rig, st):
    say("5. Node A restarts: the places and the owed retry are still there")
    before = {who: places(rig, who) for who in ("alice", "dave")}
    if not rig.restart_a():
        return
    after = {who: places(rig, who) for who in before}
    check("every rule reads the same after the restart", after == before, (before, after))


def scenario_funded(rig, st):
    say("6. The money comes in: the retry pays in that block")
    orc = Oracle(rig, "6", ("dave", "bob", "carol"))
    pay(rig, orc, "carol", "dave", 150, "Carol pays Dave 150")
    rig.mine(empty=False)
    orc.move("dave", "bob", 100)
    orc.verify("the block with Carol's payment (Bob has the rent, nobody paid a fee for it)")
    paid = history(rig, "dave")[0]
    check("the history names the retry: executed, no executor, 100",
          paid.get("retry") is True and paid.get("outcome") == "executed"
          and paid.get("executor_pubkey") is None and paid.get("total") == 100, paid)
    rig.mine()
    rig.mine()
    orc.verify("the blocks after it (nothing more)")
    check("no retry is owed any more", "retry_at" not in places(rig, "dave")[0],
          places(rig, "dave")[0])


def scenario_follower(rig, st):
    say("7. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getpayoutrule {rig.pk[n]}" for n in ("alice", "dave")]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_two_rents(rig, st)
            scenario_third_place(rig, st)
            scenario_replace_and_revoke(rig, st)
            scenario_short(rig, st)
            scenario_restart(rig, st)
            scenario_funded(rig, st)
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
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local", "e2e-places"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        funded = {n: FUNDS for n in ("alice", "bob", "carol")}
        funded["dave"] = BASE_FEE + 20     # 60 once place 2 has paid him 40: short of the rent
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS, funded=funded,
                                 approval_slots=True)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
