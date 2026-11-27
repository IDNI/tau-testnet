#!/usr/bin/env python3
"""End-to-end: money with conditions as ONE payout rule, on REAL running nodes
with the native Tau engine.

Alice gives Bob 5,000 he may spend at most 500 per period, not before a start,
and what he has not spent by a deadline goes back to her. None of these
conditions is node code: they are lines of one Tau rule on a grant account that
holds nothing but that money (tests/test_payout_conditions_native.py has the
same rule on the block's time, against a model). The node code in play is the
payout path, the o5 policy and the rule-change guard, as they are.

Two live nodes (see scripts/e2e_rig.py): node A mines and is driven through its
RPC port and the CLI; node B receives A's blocks only. Periods are 10 blocks so
the run takes seconds; the clock the rule reads is the block height (i6).

SCENARIOS (balances through an accounting oracle, fees to the miner included)
    1. The grant account installs the rule (signed with `policy_exempt`, so
       the clause that follows does not stop its payments), an o5 clause that
       blocks every transfer it could sign, and a guard that needs Alice's and
       Bob's co-signature for any rule change. Alice sends it 5,000.
    2. Before the start Bob's spend is refused.
    3. From the start: Bob spends 300 to a shop, then 201 is refused, 200 is
       paid, 1 more is refused. A stranger's and Alice's executions pay nothing.
    4. The grant account's own key can neither transfer the money (o5) nor
       remove the rule (guard).
    5. Alice sends a second payment of 1,000 to the same account: the cap is
       shared, Bob still gets nothing more this period.
    6. Node A restarts; the next period pays 500 again, and no more.
    7. At the deadline a stranger sends the execution: everything left goes to
       Alice, and nothing can be paid after it.
    8. Node B replays A's blocks, restarts, and ends with the same state hash.

USAGE
    python scripts/e2e_payout_grant.py provision --dir .local/e2e-grant
    python scripts/e2e_payout_grant.py run --dir .local/e2e-grant

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import os

import e2e_rig as rig_mod
from e2e_rig import BASE_FEE, FEE_LIMIT, FUNDS, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-grant"
ACTORS = ("miner", "alice", "grant", "bob", "shop", "carol")
SETUP_FEES = 3 * BASE_FEE                 # the rule, the o5 clause, the guard
AMOUNT, CAP, PERIOD, TOP_UP = 5_000, 500, 10, 1_000

BLOCK_ALL = ("always ( i1[t]:bv[24] > { #x000000 }:bv[24] -> "
             "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")


def conditions(bob, start, deadline, cap=CAP):
    """Bob spends what he asks (i40) to the payee he names (slot 0) while what the
    rule paid this period (i26) plus the ask stays inside the cap, from `start`
    until `deadline` (block heights, i6); from the deadline on, whoever executes,
    the account's whole balance (i2) goes to Alice (slot 1)."""
    c = lambda n, w=24: "{ %d }:bv[%d]" % (n, w)                      # noqa: E731
    now, holds, paid, asked = ("i6[t]:bv[64]", "i2[t]:bv[24]", "i26[t]:bv[24]",
                               "i40[t]:bv[24]")
    pays = lambda payee, back: (                                       # noqa: E731
        f"((o30[t]:bv[24] = {payee}) && (o31[t]:bv[24] = {back}))")
    spend = (f"((i13[t]:bv[384] = {{ #x{bob} }}:bv[384]) && ({now} >= {c(start, 64)}) && "
             f"({now} < {c(deadline, 64)}) && ({asked} <= {c(cap)}) && ({paid} <= {c(cap)}) && "
             f"({asked} <= ({c(cap)} - {paid})))")
    over = f"({now} >= {c(deadline, 64)})"
    return (f"always ( {spend} ? {pays(asked, c(0))} : "
            f"( {over} ? {pays(c(0), holds)} : {pays(c(0), c(0))} ) ).")


def guard_text(first, second):
    return ("always ( ((i18[t]:bv[384] = { #x%s }:bv[384]) && "
            "(i19[t]:bv[384] = { #x%s }:bv[384])) ? "
            "(o5[t]:bv[24] = { #x000001 }:bv[24]) : "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) )." % (first, second))


def payout(rig, node=None):
    return rig.read(f"getpayoutrule {rig.pk['grant']}", node) or {}


def rule(rig):
    return payout(rig).get("rule") or {}


def execute(rig, who, ask=0, payee=None):
    from tau_testnet_cli import tx as cli_tx
    payload = cli_tx.build_payout_execute_tx(
        **rig.common(who), account_pubkey=rig.pk["grant"], rule_id=rule(rig).get("rule_id"),
        recipients={0: rig.pk[payee]} if payee else {}, data={0: ask} if ask else {},
        fee_limit=FEE_LIMIT)
    return rig.submit(who, payload)


def refused(res):
    return res.get("status") != "ok"


def spend(rig, orc, amount, label):
    res = execute(rig, "bob", amount, "shop")
    ok = check(label, res.get("status") == "ok", res)
    rig.mine(empty=False)
    if ok:
        orc.fee("bob")
        orc.move("grant", "shop", amount)
    return ok


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_setup(rig, st):
    say("1. The grant account takes its rule, its o5 lock and its guard; Alice sends 5,000")
    orc = Oracle(rig, "1", ("alice", "grant"))
    tip = rig.a.height()
    st["start"], st["deadline"] = tip + 1 + PERIOD, tip + 1 + PERIOD + 25
    body = conditions(rig.pk["bob"], st["start"], st["deadline"])
    proc = rig.cli("payout", "set", "--privkey", rig.privkey("grant"), "--body", body,
                   "--fee", FEE_LIMIT, "--slot", "open", "--slot", rig.pk["alice"],
                   "--cap-per-execution", str(4 * AMOUNT), "--cap-per-period", str(8 * AMOUNT),
                   "--period-blocks", str(PERIOD), "--ends-in", "400", "--policy-exempt")
    check("`payout set --policy-exempt` with the conditions is admitted", proc.returncode == 0,
          proc.stdout[-400:] + proc.stderr[-400:])
    rig.mine(empty=False)
    check("the rule is installed in the next block, so its periods start there",
          payout(rig).get("installed") and rig.a.height() == tip + 1,
          (rig.a.height(), tip, payout(rig)))
    check("the rule shows that the account's o5 clause is not asked for it",
          rule(rig).get("policy_exempt") is True, rule(rig))
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
    guard = (rig.read(f"getruleoffers {rig.pk['grant']} all") or {}).get("rule_change_guard") or ""
    check("the guard is in force and names Alice and Bob",
          rig.pk["alice"] in guard and rig.pk["bob"] in guard, guard[:200])
    orc.fee("grant")
    orc.verify("the three setup transactions (one fee each)")
    check("the grant account has spent its fee money and holds nothing",
          rig.balance("grant") == 0, rig.balance("grant"))

    res = rig.transfer("alice", "grant", AMOUNT)
    check("Alice's payment of 5,000 is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "grant", AMOUNT)
    orc.verify("Alice's payment")
    check("the grant account holds exactly the 5,000", rig.balance("grant") == AMOUNT,
          rig.balance("grant"))


def scenario_before_the_start(rig, st):
    say("2. Before the start Bob gets nothing")
    check("the next block is still before the start", rig.a.height() + 1 < st["start"],
          (rig.a.height(), st["start"]))
    res = execute(rig, "bob", 100, "shop")
    check("Bob's spend before the start is refused at admission", refused(res), res)


def scenario_spends(rig, st):
    say("3. From the start: 300, then 201 refused, 200 paid, 1 refused")
    orc = Oracle(rig, "3", ("grant", "bob", "shop", "alice", "carol"))
    rig.mine_to(st["start"] - 1)
    spend(rig, orc, 300, "at the start Bob spends 300 to the shop")
    res = execute(rig, "bob", 201, "shop")
    check("201 more would make 501 of 500: refused", refused(res), res)
    spend(rig, orc, 200, "200 more is paid (500 of 500)")
    res = execute(rig, "bob", 1, "shop")
    check("1 more is refused: the period's cap is spent", refused(res), res)
    res = execute(rig, "carol", 100, "carol")
    check("a stranger's execution pays nothing: refused", refused(res), res)
    res = execute(rig, "alice", 100, "alice")
    check("Alice's execution before the deadline pays nothing: refused", refused(res), res)
    orc.verify("the spends of the first period (the shop got the engine's 500)")


def scenario_locked(rig, st):
    say("4. The grant account's own key can neither move the money nor remove the rule")
    orc = Oracle(rig, "4", ("grant", "carol"))
    res = rig.transfer("grant", "carol", 50)
    check("a transfer signed by the grant account is refused by its o5", refused(res), res)
    before = rule(rig).get("rule_id")
    proc = rig.cli("payout", "revoke", "--privkey", rig.privkey("grant"))
    rig.mine()
    check("a direct `payout revoke` does not remove the rule (the guard blocks it)",
          payout(rig).get("installed") and rule(rig).get("rule_id") == before,
          proc.stdout[-300:] + proc.stderr[-300:])
    orc.verify("the locked account (nothing moved)")


def scenario_second_payment(rig, st):
    say("5. A second payment of Alice to the same account shares the cap")
    orc = Oracle(rig, "5", ("alice", "grant", "bob", "shop"))
    res = rig.transfer("alice", "grant", TOP_UP)
    check("Alice's second payment of 1,000 is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.move("alice", "grant", TOP_UP)
    check("the account now holds 5,500", rig.balance("grant") == AMOUNT + TOP_UP - CAP,
          rig.balance("grant"))
    check("the period has not ended yet", rig.a.height() + 1 < st["start"] + PERIOD,
          (rig.a.height(), st["start"]))
    res = execute(rig, "bob", 1, "shop")
    check("Bob still gets nothing more this period: one cap for both payments",
          refused(res), res)
    orc.verify("the second payment")


def scenario_restart_and_next_period(rig, st):
    say("6. Node A restarts; the next period pays 500 again, and no more")
    orc = Oracle(rig, "6", ("grant", "bob", "shop"))
    before = rule(rig)
    if not rig.restart_a():
        return
    check("the rule and its count survive the restart", rule(rig) == before, (before, rule(rig)))
    rig.mine_to(st["start"] + PERIOD - 1)
    spend(rig, orc, 500, "in the next period Bob spends 500")
    res = execute(rig, "bob", 1, "shop")
    check("1 more is refused", refused(res), res)
    orc.verify("the second period")


def scenario_deadline(rig, st):
    say("7. At the deadline everything left goes back to Alice, whoever asks")
    orc = Oracle(rig, "7", ("grant", "alice", "bob", "shop", "carol"))
    left = AMOUNT + TOP_UP - 2 * CAP
    check("the account holds 5,000 of the 6,000 Alice sent", rig.balance("grant") == left,
          rig.balance("grant"))
    res = execute(rig, "carol", 0, None)
    check("an execution before the deadline returns nothing: refused", refused(res), res)
    rig.mine_to(st["deadline"] - 1)
    res = execute(rig, "carol", 4_000, "carol")
    check("a stranger's execution at the deadline is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("carol")
    orc.move("grant", "alice", left)
    orc.verify("the return (Alice gets the engine's 5,000, the stranger nothing)")
    check("the grant account is empty", rig.balance("grant") == 0, rig.balance("grant"))
    res = execute(rig, "bob", 100, "shop")
    check("Bob's spend after the deadline is refused: nothing is left", refused(res), res)
    paid = rule(rig).get("paid_total")
    check("the rule's history adds up: 1,000 spent and 5,000 returned", paid == 6_000, rule(rig))


def scenario_follower(rig, st):
    say("8. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getpayoutrule {rig.pk['grant']}"]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_setup(rig, st)
            scenario_before_the_start(rig, st)
            scenario_spends(rig, st)
            scenario_locked(rig, st)
            scenario_second_payment(rig, st)
            scenario_restart_and_next_period(rig, st)
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
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local", "e2e-grant"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        funded = {n: FUNDS for n in ("alice", "bob", "carol")}
        funded["grant"] = SETUP_FEES
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS, funded=funded,
                                 approval_slots=True)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
