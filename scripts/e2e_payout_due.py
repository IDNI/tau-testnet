#!/usr/bin/env python3
"""End-to-end: the optional terms and the kept clocks of a payout rule, on REAL
running nodes with the native Tau engine.

The grant of scripts/e2e_payout_grant.py once more, with what that run still
needed a stranger and a lucky install block for:

    periods_from   the cap's periods count from the start Alice named, not from
                   the block that happened to install the rule
    due_at         at the deadline the node runs the rule itself: what Bob has
                   not spent goes back to Alice and nobody sends a transaction
    i48, i49       a second account pays a shop only some blocks after its rule
                   was installed, and then only every few blocks

Two live nodes (see scripts/e2e_rig.py): node A mines and is driven through its
RPC port and the CLI; node B receives A's blocks only. The clock is the block
height, so the run takes seconds.

SCENARIOS (balances through an accounting oracle, fees to the miner included)
    1. The grant account installs the same rule as before with two more signed
       numbers (`--periods-from`, `--due-at`) and `--policy-exempt`, its o5
       lock and its guard. Alice
       sends 5,000.
    2. Bob spends 500 at the start. Ten blocks after the INSTALL nothing has
       come back; ten blocks after the START the next 500 is paid.
    3. A drip account: its rule reads the block of its install (i48) and of its
       last paid execution (i49). Too early it pays nothing; then it pays, and
       pays again only three blocks later.
    4. Node A restarts: the due point, the periods and the last paid clock are
       all still there, and the drip pays on schedule after the restart.
    5. The deadline arrives in an EMPTY block. Nobody executes anything: the
       rest of the grant is back with Alice, no fee was paid, and the due point
       does not run a second time.
    6. Node B replays A's blocks, restarts, and ends with the same state hash.

USAGE
    python scripts/e2e_payout_due.py provision --dir .local/e2e-due
    python scripts/e2e_payout_due.py run --dir .local/e2e-due

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import os

import e2e_rig as rig_mod
from e2e_payout_grant import (
    AMOUNT, BLOCK_ALL, CAP, PERIOD, SETUP_FEES, conditions, execute, guard_text, payout,
    refused, rule, spend,
)
from e2e_rig import BASE_FEE, FEE_LIMIT, FUNDS, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-due"
ACTORS = ("miner", "alice", "grant", "bob", "shop", "carol", "drip")
OFFSET = 7                 # the start, in blocks after the install: not a period apart
WAIT, EVERY, DRIP = 4, 3, 25
DRIP_FUNDS = 10 * BASE_FEE + 10 * DRIP


def drip_rule():
    """Pays what is asked (i40) to the fixed slot once WAIT blocks have passed
    since the install (i48) and EVERY blocks since the last paid execution (i49)."""
    c = lambda n, w=64: "{ %d }:bv[%d]" % (n, w)                      # noqa: E731
    now, installed, last = "i6[t]:bv[64]", "i48[t]:bv[64]", "i49[t]:bv[64]"
    ready = f"(({now} >= ({installed} + {c(WAIT)})) && ({now} >= ({last} + {c(EVERY)})))"
    return (f"always ( {ready} ? (o30[t]:bv[24] = i40[t]:bv[24]) "
            f": (o30[t]:bv[24] = {c(0, 24)}) ).")


def drip(rig, node=None):
    return (rig.read(f"getpayoutrule {rig.pk['drip']}", node) or {}).get("rule") or {}


def drip_execute(rig, who="carol", ask=DRIP):
    from tau_testnet_cli import tx as cli_tx
    payload = cli_tx.build_payout_execute_tx(
        **rig.common(who), account_pubkey=rig.pk["drip"], rule_id=drip(rig).get("rule_id"),
        recipients={}, data={0: ask}, fee_limit=FEE_LIMIT)
    return rig.submit(who, payload)


def drip_pays(rig, orc, label):
    res = drip_execute(rig)
    ok = check(label, res.get("status") == "ok", res)
    rig.mine(empty=False)
    if ok:
        orc.fee("carol")
        orc.move("drip", "shop", DRIP)
    return ok


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_setup(rig, st):
    say("1. The grant account takes the same rule with a start for its periods and a due point")
    orc = Oracle(rig, "1", ("alice", "grant"))
    tip = rig.a.height()
    st["installed"] = tip + 1
    st["start"] = st["installed"] + OFFSET
    st["deadline"] = st["start"] + 2 * PERIOD + 6
    body = conditions(rig.pk["bob"], st["start"], st["deadline"])
    proc = rig.cli("payout", "set", "--privkey", rig.privkey("grant"), "--body", body,
                   "--fee", FEE_LIMIT, "--slot", "open", "--slot", rig.pk["alice"],
                   "--cap-per-execution", str(4 * AMOUNT), "--cap-per-period", str(8 * AMOUNT),
                   "--period-blocks", str(PERIOD), "--ends-in", "400",
                   "--periods-from", str(st["start"]), "--due-at", str(st["deadline"]),
                   "--policy-exempt")
    check("`payout set --periods-from --due-at` is admitted", proc.returncode == 0,
          proc.stdout[-400:] + proc.stderr[-400:])
    rig.mine(empty=False)
    got = rule(rig)
    check("the rule is installed and shows both signed points",
          rig.a.height() == st["installed"] and got.get("periods_from") == st["start"]
          and got.get("due_at") == st["deadline"] and got.get("due_done") is False,
          (rig.a.height(), got))
    orc.fee("grant")

    payload = rig.common("grant")
    payload.update({"tx_type": "user_tx", "fee_limit": FEE_LIMIT, "operations": {"0": BLOCK_ALL}})
    res = rig.submit("grant", payload)
    check("the o5 clause that blocks its transfers is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("grant")

    proc = rig.cli("policy", "guard", "set", "--privkey", rig.privkey("grant"),
                   "--body", guard_text(rig.pk["alice"], rig.pk["bob"]),
                   "--approver", f"18={rig.pk['alice']}", "--approver", f"19={rig.pk['bob']}")
    check("the guard request is submitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("grant")

    res = rig.transfer("alice", "grant", AMOUNT)
    check("Alice's payment of 5,000 is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "grant", AMOUNT)
    orc.verify("the setup and Alice's payment")
    check("the grant account holds exactly the 5,000", rig.balance("grant") == AMOUNT,
          rig.balance("grant"))


def scenario_periods(rig, st):
    say("2. The periods count from the start, not from the install")
    orc = Oracle(rig, "2", ("grant", "bob", "shop"))
    check("the next block is still before the start", rig.a.height() + 1 < st["start"],
          (rig.a.height(), st["start"]))
    res = execute(rig, "bob", 100, "shop")
    check("before the start Bob's spend is refused", refused(res), res)
    rig.mine_to(st["start"] - 1)
    spend(rig, orc, CAP, "at the start Bob spends the period's 500")
    rig.mine_to(st["installed"] + PERIOD - 1)
    check("the next block is ten blocks after the install, inside the first period "
          "from the start", st["start"] < rig.a.height() + 1 < st["start"] + PERIOD,
          (rig.a.height(), st))
    res = execute(rig, "bob", 1, "shop")
    check("ten blocks after the INSTALL nothing has come back: 1 more is refused",
          refused(res), res)
    rig.mine_to(st["start"] + PERIOD - 2)
    res = execute(rig, "bob", 1, "shop")
    check("one block before the second period: still refused", refused(res), res)
    rig.mine_to(st["start"] + PERIOD - 1)
    spend(rig, orc, CAP, "ten blocks after the START the next 500 is paid")
    check("the rule counts its second period", rule(rig).get("spent_this_period") == CAP,
          rule(rig))
    orc.verify("two periods counted from the start")


def scenario_drip(rig, st):
    say("3. A rule that reads the block of its install and of its last paid execution")
    orc = Oracle(rig, "3", ("drip", "carol", "shop"))
    proc = rig.cli("payout", "set", "--privkey", rig.privkey("drip"), "--body", drip_rule(),
                   "--fee", FEE_LIMIT, "--slot", rig.pk["shop"],
                   "--cap-per-execution", str(DRIP), "--cap-per-period", str(100 * DRIP),
                   "--period-blocks", "1000", "--ends-in", "400")
    check("the drip rule is admitted", proc.returncode == 0,
          proc.stdout[-400:] + proc.stderr[-400:])
    rig.mine(empty=False)
    orc.fee("drip")
    st["drip_installed"] = rig.a.height()
    check("it is installed", drip(rig).get("anchor") == st["drip_installed"], drip(rig))
    res = drip_execute(rig)
    check("one block after the install it pays nothing: refused", refused(res), res)
    rig.mine_to(st["drip_installed"] + WAIT - 2)
    res = drip_execute(rig)
    check(f"one block before install + {WAIT}: still refused", refused(res), res)
    rig.mine_to(st["drip_installed"] + WAIT - 1)
    drip_pays(rig, orc, f"at install + {WAIT} it pays the shop")
    st["drip_paid"] = rig.a.height()
    check("the node shows the clock of the last paid execution",
          drip(rig).get("last_paid_clock") == st["drip_paid"], drip(rig))
    res = drip_execute(rig)
    check("in the next block it pays nothing: refused", refused(res), res)
    orc.verify("the drip's first payment")


def scenario_restart(rig, st):
    say("4. Node A restarts: due point, periods and clocks are still there")
    orc = Oracle(rig, "4", ("drip", "carol", "shop", "grant"))
    before_grant, before_drip = rule(rig), drip(rig)
    if not rig.restart_a():
        return
    check("the grant rule with its due point survives the restart",
          rule(rig) == before_grant and rule(rig).get("due_done") is False,
          (before_grant, rule(rig)))
    check("the drip rule and its last paid clock survive the restart",
          drip(rig) == before_drip, (before_drip, drip(rig)))
    rig.mine_to(st["drip_paid"] + EVERY - 2)
    res = drip_execute(rig)
    check(f"one block before last paid + {EVERY}: refused", refused(res), res)
    rig.mine_to(st["drip_paid"] + EVERY - 1)
    drip_pays(rig, orc, f"at last paid + {EVERY} it pays again, after the restart")
    orc.verify("the drip's second payment")


def scenario_deadline(rig, st):
    say("5. The deadline arrives in an empty block and the node returns the rest itself")
    orc = Oracle(rig, "5", ("grant", "alice", "bob", "shop", "carol", "miner"))
    left = AMOUNT - 2 * CAP
    check("the grant account holds 4,000 before the deadline", rig.balance("grant") == left,
          rig.balance("grant"))
    check("the deadline is still ahead", rig.a.height() + 1 < st["deadline"],
          (rig.a.height(), st["deadline"]))
    rig.mine_to(st["deadline"] - 1)
    check("one block before the deadline nothing has moved",
          rig.balance("grant") == left and rule(rig).get("due_done") is False, rule(rig))
    sealed = rig.mine()                    # the deadline block: no transaction in it
    check("the deadline block is sealed with no transaction",
          rig.a.height() == st["deadline"], (rig.a.height(), sealed))
    orc.move("grant", "alice", left)
    orc.verify("the return (Alice gets the engine's 4,000; nobody paid a fee)")
    got = payout(rig)
    check("the grant account is empty and the due point is marked as run",
          rig.balance("grant") == 0 and (got.get("rule") or {}).get("due_done") is True, got)
    newest = (got.get("history") or [{}])[0]
    check("the history names the run: executed, no executor, 4,000 to Alice",
          newest.get("outcome") == "executed" and newest.get("executor_pubkey") is None
          and newest.get("due_at") == st["deadline"] and newest.get("total") == left
          and [leg.get("recipient_pubkey") for leg in newest.get("legs") or []]
          == [rig.pk["alice"]], newest)
    rig.mine()
    rig.mine()
    check("it does not run a second time", rule(rig).get("executions") == 3
          and rule(rig).get("paid_total") == AMOUNT, rule(rig))
    res = execute(rig, "bob", 100, "shop")
    check("Bob's spend after the deadline is refused: nothing is left", refused(res), res)
    orc.verify("the blocks after the deadline (nothing moved)")


def scenario_follower(rig, st):
    say("6. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getpayoutrule {rig.pk['grant']}", f"getpayoutrule {rig.pk['drip']}"]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_setup(rig, st)
            scenario_periods(rig, st)
            scenario_drip(rig, st)
            scenario_restart(rig, st)
            scenario_deadline(rig, st)
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
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local", "e2e-due"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        funded = {n: FUNDS for n in ("alice", "bob", "carol")}
        funded["grant"] = SETUP_FEES
        funded["drip"] = DRIP_FUNDS
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS, funded=funded,
                                 approval_slots=True)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
