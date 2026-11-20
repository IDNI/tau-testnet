#!/usr/bin/env python3
"""End-to-end standing payments (#34) on REAL running nodes with the native Tau engine.

tests/test_standing_*.py drive the real block apply in one process; this drives
two live nodes (see scripts/e2e_rig.py): node A mines and is driven through its
RPC port and the `tau-testnet standing` CLI; node B receives A's blocks only.

SCENARIOS (asserted on balances through an accounting oracle, fees to the miner
included, and on the payment history every node records)
    1. Alice signs once with `standing create` (every 128 blocks, the shortest
       interval, 2 periods). The sweep pays Bob at each due point and never in
       between; node A restarts after the first payment and the second still
       comes; the authorization ends by itself.
    2. Erin's payment finds too little: `unfunded`, retried in the next block of
       the window, paid as soon as money reaches her. The next period's window
       closes unfunded: `missed`, nothing owed.
    3. Two strangers execute the same due period in one block: one pays it and
       pays the fee, the other is refused and pays nothing; the sweep does not
       pay that period again.
    4. Alice replaces the terms with `standing update`: the old version ends
       `replaced`, the new one (version 2) pays the new amount.
    5. Alice cancels with `standing cancel`: fee-free, nothing is paid after it.
    6. One network: a create signed for another network is refused at
       admission (`WRONG_NETWORK`, naming this network's genesis hash) and costs
       nothing; one whose network was rewritten after signing is refused too;
       the same create signed for this network is admitted and lands.
    7. An idle node: node A runs its own miner, nobody sends anything, and the
       miner's due wake seals the due block and nothing else. (A seconds
       schedule needs at least an hour per period, so the wake is shown on the
       block clock; the seconds clock is covered by the apply tests.)
    8. Node B replays A's blocks, restarts, and ends with the same state hash,
       the same balances and the same answer to every standing payment read.

USAGE
    python scripts/e2e_standing_payments.py provision --dir .local/e2e-standing
    python scripts/e2e_standing_payments.py run --dir .local/e2e-standing

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import json
import os
import time

import e2e_rig as rig_mod
from e2e_rig import FEE_LIMIT, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-standing"
ACTORS = ("miner", "alice", "bob", "carol", "dave", "erin", "frank")
ERIN_FUNDS = 600


def standing(rig, sid, node=None):
    return rig.read(f"getstandingpayment {sid}", node) or {}


def outcomes(rig, sid):
    """The history, oldest first, as outcome names."""
    return [e.get("outcome") for e in reversed(standing(rig, sid).get("history") or [])]


def printed_id(proc):
    """The id the CLI prints: `standing payment id: [new version of <old>: ]<id>`."""
    return next((line.split()[-1] for line in (proc.stdout + proc.stderr).splitlines()
                 if line.startswith("standing payment id:")), None)


def create(rig, who, to, *terms):
    proc = rig.cli("standing", "create", "--privkey", rig.privkey(who), "--to", rig.pk[to],
                   "--fee", FEE_LIMIT, *terms)
    sid = printed_id(proc)
    check(f"`standing create` for {who} -> {to} prints the id", proc.returncode == 0 and sid,
          proc.stdout[-400:] + proc.stderr[-400:])
    return sid


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_sweep_and_restart(rig, ids):
    say("1. Alice signs once; the sweep pays Bob every 128 blocks; node A restarts midway")
    orc = Oracle(rig, "1", ("alice", "bob"))
    sid = create(rig, "alice", "bob", "--amount", "1000", "--periods", "2",
                 "--every-blocks", "128", "--first-due-in", "2")
    ids["sweep"] = sid
    rig.settle(lambda: standing(rig, sid).get("status") is not None, "the create to land")
    orc.fee("alice")
    orc.verify("the create (one fee, nothing paid yet)")
    row = standing(rig, sid)
    due = [int(row["first_due"]) + 128 * p for p in range(2)]
    say(f"   due at heights {due}, now at {rig.a.height()}")

    rig.mine_to(due[0] - 1)
    check("nothing is paid before the first due point", rig.balance("bob") == orc.before["bob"])
    rig.mine_to(due[0])
    orc.move("alice", "bob", 1000)
    orc.verify("the first due block")
    check("the sweep paid at the due height",
          standing(rig, sid).get("last_paid_height") == due[0], standing(rig, sid))

    if not rig.restart_a():
        return
    check("the book survives the restart", standing(rig, sid).get("paid_count") == 1,
          standing(rig, sid))
    rig.mine_to(due[1] - 1)
    orc.verify("the 127 blocks between due points (nothing more)")
    rig.mine_to(due[1])
    orc.move("alice", "bob", 1000)
    orc.verify("the second due block")
    row = standing(rig, sid)
    check("after its last period it ends by itself", row.get("status") == "ended", row)
    check("the history reads created, paid, paid, ended",
          outcomes(rig, sid) == ["created", "paid", "paid", "ended"], outcomes(rig, sid))
    rig.mine()
    orc.verify("a block after the end (nothing more)")


def scenario_unfunded(rig, ids):
    say("2. Erin's payment finds too little: unfunded, retried, paid; then missed")
    orc = Oracle(rig, "2", ("erin", "frank", "alice"))
    sid = create(rig, "erin", "frank", "--amount", "800", "--periods", "2",
                 "--every-blocks", "128", "--first-due-in", "2")
    ids["unfunded"] = sid
    rig.settle(lambda: standing(rig, sid).get("status") is not None, "the create to land")
    orc.fee("erin")
    first_due = int(standing(rig, sid)["first_due"])
    rig.mine_to(first_due)
    check("the first attempt finds too little and pays nothing",
          outcomes(rig, sid)[-1:] == ["unfunded"], outcomes(rig, sid))
    rig.mine()
    check("it is tried again in the next block of the window",
          outcomes(rig, sid)[-2:] == ["unfunded", "unfunded"], outcomes(rig, sid))
    orc.verify("two unfunded attempts (nothing moved)")
    res = rig.transfer("alice", "erin", 300)
    check("Alice's top-up is admitted", res.get("status") == "ok", res)
    rig.mine()
    orc.fee("alice")
    orc.move("alice", "erin", 300)
    orc.move("erin", "frank", 800)
    orc.verify("the top-up block (the retry pays in it)")
    check("the period is paid once money arrives", outcomes(rig, sid)[-1:] == ["paid"],
          outcomes(rig, sid))
    rig.mine_to(first_due + 128 + 128)
    hist = outcomes(rig, sid)  # the newest 50 events: the window's retries fill it
    check("the second period's window closes unfunded: missed, then the end",
          hist[-3:] == ["unfunded", "missed", "ended"], hist[-6:])
    orc.verify("the missed period (nothing owed)")


def scenario_execute_race(rig, ids):
    say("3. Two strangers execute the same due period in one block")
    orc = Oracle(rig, "3", ("alice", "bob", "carol", "dave"))
    sid = create(rig, "alice", "bob", "--amount", "500", "--periods", "3",
                 "--every-blocks", "128", "--first-due-in", "3")
    ids["execute"] = sid
    rig.settle(lambda: standing(rig, sid).get("status") is not None, "the create to land")
    orc.fee("alice")
    due = int(standing(rig, sid)["first_due"])
    rig.mine_to(due - 1)
    outs = {}
    for who in ("carol", "dave"):
        proc = rig.cli("standing", "execute", "--privkey", rig.privkey(who), sid,
                       "--fee", FEE_LIMIT)
        outs[who] = proc
        check(f"{who}'s execute is admitted for the period due in the next block",
              proc.returncode == 0, proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    hist = standing(rig, sid).get("history") or []
    paid = [e for e in hist if e.get("outcome") == "paid"]
    check("the period is paid exactly once", len(paid) == 1, hist)
    winner = rig.name_of.get((paid[0] if paid else {}).get("executor_pubkey"))
    check("the payment names the executor that paid it", winner in ("carol", "dave"), paid)
    if winner:
        orc.fee(winner)
    orc.move("alice", "bob", 500)
    orc.verify("the due block (one execute paid, the other paid nothing)")
    rig.mine()
    rig.mine()
    orc.verify("later blocks of the window (the sweep pays nothing more)")


def scenario_update(rig, ids):
    say("4. Alice replaces the terms with `standing update`")
    orc = Oracle(rig, "4", ("alice", "bob"))
    old = ids["execute"]
    row = standing(rig, old)
    next_due = int(row["period_due"])
    proc = rig.cli("standing", "update", old, "--privkey", rig.privkey("alice"),
                   "--to", rig.pk["bob"], "--amount", "700", "--periods", "2",
                   "--every-blocks", "128", "--first-due-height", str(next_due), "--fee", FEE_LIMIT)
    new = printed_id(proc)
    check("`standing update` prints the new version's id", proc.returncode == 0 and new,
          proc.stdout[-400:] + proc.stderr[-400:])
    ids["updated"] = new
    rig.mine(empty=False)
    orc.fee("alice")
    old_row = standing(rig, old)
    check("the old version ends `replaced` and names the new one",
          old_row.get("status") == "replaced" and old_row.get("replaced_by") == new, old_row)
    new_row = standing(rig, new)
    check("the new version is version 2 and names the one it replaces",
          new_row.get("version") == 2 and new_row.get("replaces") == old, new_row)
    rig.mine_to(next_due)
    orc.move("alice", "bob", 700)
    orc.verify("the next due block (the new amount)")


def scenario_cancel(rig, ids):
    say("5. Alice cancels the new version with `standing cancel`")
    orc = Oracle(rig, "5", ("alice", "bob"))
    sid = ids["updated"]
    next_due = int(standing(rig, sid)["period_due"])
    proc = rig.cli("standing", "cancel", "--privkey", rig.privkey("alice"), sid)
    check("the cancel is admitted", proc.returncode == 0, proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    check("the authorization reads `cancelled`", standing(rig, sid).get("status") == "cancelled",
          standing(rig, sid))
    rig.mine_to(next_due + 1)
    orc.verify("the cancel and the due point after it (fee-free, nothing paid)")


def scenario_one_network(rig, ids):
    say("6. One network: a create signed for another network is refused and costs nothing")
    orc = Oracle(rig, "6", ("carol", "dave"))
    here = rig.genesis_hash()
    check("the node reports its network with the sequence (64 hex, the same on B)",
          len(here) == 64 and here == rig.genesis_hash(rig.b), (here, rig.genesis_hash(rig.b)))
    elsewhere = "c3" * 32
    seq_before = rig.chain_values("carol")[0]

    def terms():
        tip = rig.a.height()
        payload = rig.common("carol")
        payload.update({"tx_type": "standing_payment_create", "fee_limit": FEE_LIMIT,
                        "recipient_pubkey": rig.pk["dave"], "amount": 40,
                        "interval_blocks": 128, "first_due": tip + 4, "periods": 1,
                        "expire_at_height": tip + 3})
        return payload

    res = rig.submit("carol", {**terms(), "genesis_hash": elsewhere})
    err = res.get("error") or {}
    check("signed for another network: refused with WRONG_NETWORK",
          res.get("status") == "error" and err.get("code") == "WRONG_NETWORK", res)
    check("the refusal names this network's genesis hash",
          (err.get("details") or {}).get("genesis_hash") == here, err)

    moved = rig.sign("carol", {**terms(), "genesis_hash": elsewhere})
    moved["genesis_hash"] = here
    res = rig.a.rpc("sendtx '" + json.dumps(moved, separators=(",", ":")) + "'")
    check("signed for another network, then rewritten to this one: refused",
          res.get("status") == "error", res)

    rig.mine()
    check("neither cost a fee nor used a sequence number",
          rig.chain_values("carol")[0] == seq_before, rig.chain_values("carol"))
    orc.verify("the two refusals (nothing moved)")

    res = rig.submit("carol", terms())
    check("the same create signed for this network is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("carol")
    mine = [r for r in (rig.read(f"getstandingpayments {rig.pk['carol']} out") or {}).get(
        "payments") or [] if r.get("recipient_pubkey") == rig.pk["dave"]]
    check("it lands and is open", len(mine) == 1, mine)
    if mine:
        ids["network"] = mine[0].get("standing_id")
        rig.mine_to(int(mine[0]["first_due"]))
        orc.move("carol", "dave", 40)
    orc.verify("its due block (paid like any other)")


def scenario_idle_wake(rig, ids):
    say("7. An idle node: the miner's due wake seals the due block, and only it")
    if not rig.restart_a(TAU_MINING_ENABLED="true"):
        return
    orc = Oracle(rig, "7", ("alice", "frank"))
    sid = create(rig, "alice", "frank", "--amount", "250", "--periods", "1",
                 "--every-blocks", "128", "--first-due-in", "4")
    ids["wake"] = sid
    rig.settle(lambda: standing(rig, sid).get("status") is not None, "the create to land", tries=3)
    orc.fee("alice")
    due = int(standing(rig, sid)["first_due"])
    rig.mine_to(due - 1)
    say(f"   idle at height {rig.a.height()}; due at {due}; no createblock, no traffic")
    done = rig.wait(lambda: standing(rig, sid).get("status") == "ended", "the payment",
                    timeout=60)
    check("the miner's wake sealed the payment with no transaction sent", done,
          standing(rig, sid))
    paid_at = [e["block_number"] for e in standing(rig, sid).get("history") or []
               if e.get("outcome") == "paid"]
    check("the due block is the one the wake made", rig.a.height() == due and paid_at == [due],
          (rig.a.height(), due, paid_at))
    time.sleep(8)
    check("nothing else is due, so the idle node makes no more blocks",
          rig.a.height() == due, rig.a.height())
    orc.move("alice", "frank", 250)
    orc.verify("the idle period")
    rig.restart_a()


def scenario_follower(rig, ids):
    say("8. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getstandingpayment {sid}" for sid in ids.values() if sid]
    reads += [f"getstandingpayments {rig.pk[n]} all" for n in ("alice", "erin", "bob", "carol")]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    ids: dict[str, str] = {}
    try:
        if rig.start():
            rig.mine()
            scenario_sweep_and_restart(rig, ids)
            scenario_unfunded(rig, ids)
            scenario_execute_race(rig, ids)
            scenario_update(rig, ids)
            scenario_cancel(rig, ids)
            scenario_one_network(rig, ids)
            scenario_idle_wake(rig, ids)
            scenario_follower(rig, ids)
    except Exception:
        import traceback
        check("the run completed", False, traceback.format_exc()[-1500:])
    finally:
        rig.stop()
    return rig.finish()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run"])
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local", "e2e-standing"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        funded = {n: rig_mod.FUNDS for n in ACTORS if n not in ("miner", "erin")}
        funded["erin"] = ERIN_FUNDS
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS, funded)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
