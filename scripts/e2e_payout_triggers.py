#!/usr/bin/env python3
"""End-to-end: three ways a payout rule is started, on REAL running nodes with
the native Tau engine.

A payout rule is stepped when someone sends an execution. Here the node also
steps it by the clock, again and again, and when a payment arrives. With that a
standing payment and a share routed from every incoming payment are payout
rules like any other, and a sealed account holds money its own key cannot move.

    due_at + due_every   Alice's account pays Bob 100 at a block she signed and
                         again every 256 blocks; nobody sends a transaction
    on_arrival           a fifth of every payment the shop receives goes to the
                         creator, in the block that carries the payment; the
                         payer pays its own fee and nothing more
    sealed               a vault holds Carol's money for Bob: until the rule
                         ends the vault's own key can neither spend nor change
                         the rule; what Bob has not taken goes back to Carol at
                         the due point

Two live nodes (see scripts/e2e_rig.py): node A mines and is driven through its
RPC port and the CLI; node B receives A's blocks only. The clock is the block
height, so the run takes minutes.

SCENARIOS (balances through an accounting oracle, fees to the miner included)
    1. Alice installs the standing rule. At the signed block Bob has 100 more,
       in a block with no transaction. The blocks after it pay nothing.
    2. The shop installs the route. Carol pays 101: the creator has 20, the
       shop 81, Carol paid 101 and her one fee. 4 is too small to share. Two
       payments in one block are each split on their own.
    3. The creator shares what it is paid with Alice the same way. A share that
       came from the shop's rule stays whole; a payment someone signs to the
       creator is shared.
    4. The vault installs a sealed rule and Carol funds it. The vault's key
       tries a transfer, a revoke and a new rule: all refused, no fee, no
       sequence number. Bob takes 300 by the rule.
    5. Node A restarts: the next due point, the route and the seal are still
       there.
    6. The vault's due point arrives in an empty block: the 700 left are back
       with Carol. The rule ends and the vault's key works again.
    7. 256 blocks after the first, Alice's second payment to Bob.
    8. Node B replays A's blocks, restarts, and ends with the same state hash.

USAGE
    python scripts/e2e_payout_triggers.py provision --dir .local/e2e-triggers
    python scripts/e2e_payout_triggers.py run --dir .local/e2e-triggers

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import os

import e2e_rig as rig_mod
from e2e_rig import BASE_FEE, FEE_LIMIT, FUNDS, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-triggers"
ACTORS = ("miner", "alice", "bob", "carol", "shop", "creator", "vault")
EVERY = 256
RENT, GRANT, TAKE = 100, 1_000, 300


def c(n, w=24):
    return "{ %d }:bv[%d]" % (n, w)


NOBODY = "(i13[t]:bv[384] = { 0 }:bv[384])"
RENT_RULE = (f"always ( {NOBODY} ? (o30[t]:bv[24] = {c(RENT)}) "
             f": (o30[t]:bv[24] = {c(0)}) ).")
ROUTE_RULE = f"always ( o30[t]:bv[24] = i27[t]:bv[24] / {c(5)} )."
HALF_RULE = f"always ( o30[t]:bv[24] = i27[t]:bv[24] / {c(2)} )."


def vault_rule(bob):
    """Bob takes what he asks for (slot 0 is Bob). When the node itself runs the
    rule, everything left goes to slot 1. Anyone else gets nothing."""
    pays = lambda a, b: f"((o30[t]:bv[24] = {a}) && (o31[t]:bv[24] = {b}))"   # noqa: E731
    is_bob = f"(i13[t]:bv[384] = {{ #x{bob} }}:bv[384])"
    return (f"always ( {is_bob} ? {pays('i40[t]:bv[24]', c(0))} : "
            f"( {NOBODY} ? {pays(c(0), 'i2[t]:bv[24]')} : {pays(c(0), c(0))} ) ).")


def payout(rig, who, node=None):
    return rig.read(f"getpayoutrule {rig.pk[who]}", node) or {}


def rule(rig, who):
    return payout(rig, who).get("rule") or {}


def newest(rig, who):
    return (payout(rig, who).get("history") or [{}])[0]


def refused(res):
    return res.get("status") != "ok"


def install(rig, who, body, *flags):
    proc = rig.cli("payout", "set", "--privkey", rig.privkey(who), "--body", body,
                   "--fee", FEE_LIMIT, *flags)
    return proc.returncode == 0, proc.stdout[-400:] + proc.stderr[-400:]


def execute(rig, who, account, ask=0):
    from tau_testnet_cli import tx as cli_tx
    payload = cli_tx.build_payout_execute_tx(
        **rig.common(who), account_pubkey=rig.pk[account],
        rule_id=rule(rig, account).get("rule_id"), recipients={},
        data={0: ask} if ask else {}, fee_limit=FEE_LIMIT)
    return rig.submit(who, payload)


def pay(rig, orc, who, to, amount, label):
    res = rig.transfer(who, to, amount)
    ok = check(label, res.get("status") == "ok", res)
    if ok:
        orc.fee(who)
        orc.move(who, to, amount)
    return ok


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_standing(rig, st):
    say("1. A standing payment as a rule: the clock starts it, again and again")
    orc = Oracle(rig, "1", ("alice", "bob"))
    st["rent_due"] = rig.a.height() + 5
    ok, out = install(rig, "alice", RENT_RULE, "--slot", rig.pk["bob"],
                      "--cap-per-execution", str(RENT), "--cap-per-period", str(RENT),
                      "--period-blocks", "10", "--ends-in", "5000",
                      "--due-at", str(st["rent_due"]), "--due-every", str(EVERY))
    check("`payout set --due-at --due-every` is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("alice")
    got = rule(rig, "alice")
    check("the rule is installed and shows its repeat and its next due point",
          got.get("due_every") == EVERY and got.get("next_due") == st["rent_due"]
          and got.get("due_done") is False, got)
    res = execute(rig, "carol", "alice")
    check("nobody can execute it for anything: refused", refused(res), res)
    rig.mine_to(st["rent_due"] - 1)
    orc.verify("the blocks before the due point (only the install fee)")
    rig.mine()                                 # the due block: no transaction in it
    check("the due block is sealed with no transaction", rig.a.height() == st["rent_due"],
          rig.a.height())
    orc.move("alice", "bob", RENT)
    orc.verify("the first due point (Bob has 100, nobody paid a fee)")
    event = newest(rig, "alice")
    check("the history names the run: executed, no executor, due point 0",
          event.get("outcome") == "executed" and event.get("executor_pubkey") is None
          and event.get("due_at") == st["rent_due"] and event.get("due_index") == 0
          and event.get("total") == RENT, event)
    rig.mine()
    rig.mine()
    got = rule(rig, "alice")
    check("the next due point is 256 blocks after the first",
          got.get("next_due") == st["rent_due"] + EVERY and got.get("executions") == 1, got)
    orc.verify("the blocks after it (nothing more)")


def scenario_route(rig, st):
    say("2. A route as a rule: a payment that arrives starts it")
    orc = Oracle(rig, "2", ("shop", "creator", "carol", "bob"))
    ok, out = install(rig, "shop", ROUTE_RULE, "--slot", rig.pk["creator"], "--per-sale",
                      "--on-arrival", "--cap-per-execution", "100000",
                      "--cap-per-period", "1000000", "--period-blocks", "1000",
                      "--ends-in", "5000")
    check("`payout set --per-sale --on-arrival` is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("shop")
    check("the rule is installed and shows on_arrival",
          rule(rig, "shop").get("on_arrival") is True, rule(rig, "shop"))

    pay(rig, orc, "carol", "shop", 101, "Carol's payment of 101 is admitted")
    rig.mine(empty=False)
    orc.move("shop", "creator", 20)
    orc.verify("101 routed at a fifth (20 and 81, Carol paid 101 and one fee)")
    event = newest(rig, "shop")
    check("the history names the run: executed, no executor, the sale, 20",
          event.get("outcome") == "executed" and event.get("executor_pubkey") is None
          and len(event.get("sale_id") or "") == 64 and event.get("total") == 20
          and event.get("sale_amount") == 101
          and event.get("payer_pubkey") == rig.pk["carol"], event)
    check("no sale is left open", not (rule(rig, "shop").get("open_sales") or []),
          rule(rig, "shop"))

    pay(rig, orc, "carol", "shop", 4, "a payment of 4 is admitted")
    rig.mine(empty=False)
    orc.verify("4 is too small to share (all of it stays with the shop)")
    check("the history says so and the sale is closed",
          newest(rig, "shop").get("outcome") == "arrival_not_paid"
          and not (rule(rig, "shop").get("open_sales") or []), newest(rig, "shop"))

    pay(rig, orc, "carol", "shop", 55, "Carol pays 55")
    pay(rig, orc, "bob", "shop", 10, "and Bob pays 10, for the same block")
    rig.mine(empty=False)
    orc.move("shop", "creator", 11 + 2)
    orc.verify("two payments in one block, each split on its own (11 and 2)")


def scenario_no_second_hop(rig, st):
    say("3. A routed share is not routed again")
    orc = Oracle(rig, "3", ("shop", "creator", "carol", "alice"))
    ok, out = install(rig, "creator", HALF_RULE, "--slot", rig.pk["alice"], "--per-sale",
                      "--on-arrival", "--cap-per-execution", "100000",
                      "--cap-per-period", "1000000", "--period-blocks", "1000",
                      "--ends-in", "5000")
    check("the creator's own route (half to Alice) is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("creator")
    before = rule(rig, "creator").get("executions")
    pay(rig, orc, "carol", "shop", 100, "Carol pays the shop 100")
    rig.mine(empty=False)
    orc.move("shop", "creator", 20)
    event = newest(rig, "shop")
    check("the shop's rule ran for Carol's 100 and paid 20",
          event.get("outcome") == "executed" and event.get("total") == 20
          and event.get("sale_amount") == 100, event)
    orc.verify("the creator's share of 20 stays whole")
    check("the creator's rule did not run for it",
          rule(rig, "creator").get("executions") == before
          and not (rule(rig, "creator").get("open_sales") or []), rule(rig, "creator"))
    pay(rig, orc, "carol", "creator", 10, "Carol pays the creator 10 herself")
    rig.mine(empty=False)
    orc.move("creator", "alice", 5)
    orc.verify("a payment someone signs to the creator is shared (5 to Alice)")


def scenario_seal(rig, st):
    say("4. A sealed account: its own key can neither spend nor change the rule")
    orc = Oracle(rig, "4", ("vault", "carol", "bob"))
    st["vault_due"] = rig.a.height() + 16
    ok, out = install(rig, "vault", vault_rule(rig.pk["bob"]), "--slot", rig.pk["bob"],
                      "--slot", rig.pk["carol"], "--sealed",
                      "--cap-per-execution", str(4 * GRANT), "--cap-per-period", str(8 * GRANT),
                      "--period-blocks", "1000", "--due-at", str(st["vault_due"]),
                      "--ends-at", str(st["vault_due"] + 2))
    check("`payout set --sealed --due-at` is admitted", ok, out)
    rig.mine(empty=False)
    orc.fee("vault")
    check("the rule is installed and shows the seal", rule(rig, "vault").get("sealed") is True,
          rule(rig, "vault"))
    pay(rig, orc, "carol", "vault", GRANT, "Carol's payment of 1,000 is admitted")
    rig.mine(empty=False)
    held, seq = rig.balance("vault"), rig.chain_values("vault")[0]

    res = rig.transfer("vault", "bob", 500)
    check("the vault's key signs a transfer: refused, the account is sealed",
          refused(res) and (res.get("error") or {}).get("code") == "ACCOUNT_SEALED", res)
    proc = rig.cli("payout", "revoke", "--privkey", rig.privkey("vault"))
    check("it tries to remove the rule: refused", proc.returncode != 0
          and "sealed" in (proc.stdout + proc.stderr), proc.stdout[-300:] + proc.stderr[-300:])
    ok, out = install(rig, "vault", ROUTE_RULE.replace("i27", "i40"), "--slot",
                      rig.pk["bob"], "--cap-per-execution", "100000",
                      "--cap-per-period", "100000", "--period-blocks", "10", "--ends-in", "50")
    check("it tries to install another rule: refused", not ok and "sealed" in out, out)
    rig.mine()
    check("nothing moved, no fee was paid and no sequence number was used",
          rig.balance("vault") == held and rig.chain_values("vault")[0] == seq,
          (rig.balance("vault"), held, rig.chain_values("vault")[0], seq))

    res = execute(rig, "carol", "vault", 200)
    check("Carol asks the rule for 200: refused, the rule pays only Bob", refused(res), res)
    res = execute(rig, "bob", "vault", TAKE)
    check("Bob asks the rule for 300: admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("bob")
    orc.move("vault", "bob", TAKE)
    orc.verify("the sealed vault (only the rule moved money: 300 to Bob)")


def scenario_restart(rig, st):
    say("5. Node A restarts: the next due point, the route and the seal are still there")
    before = {who: rule(rig, who) for who in ("alice", "shop", "creator", "vault")}
    if not rig.restart_a():
        return
    after = {who: rule(rig, who) for who in before}
    check("every rule reads the same after the restart", after == before, (before, after))
    res = rig.transfer("vault", "bob", 1)
    check("the vault is still sealed", refused(res)
          and (res.get("error") or {}).get("code") == "ACCOUNT_SEALED", res)
    orc = Oracle(rig, "5", ("shop", "creator", "carol"))
    pay(rig, orc, "carol", "shop", 25, "Carol pays the shop 25 after the restart")
    rig.mine(empty=False)
    orc.move("shop", "creator", 5)
    orc.verify("the route after the restart (5 of 25)")


def scenario_return(rig, st):
    say("6. The vault's due point returns the rest, the rule ends, the key works again")
    orc = Oracle(rig, "6", ("vault", "carol", "bob"))
    left = rig.balance("vault")
    check("the due point is still ahead", rig.a.height() + 1 < st["vault_due"],
          (rig.a.height(), st["vault_due"]))
    rig.mine_to(st["vault_due"] - 1)
    check("one block before it nothing has moved", rig.balance("vault") == left,
          rig.balance("vault"))
    rig.mine()
    orc.move("vault", "carol", left)
    orc.verify("the due point (what was left is back with Carol, nobody paid a fee)")
    event = newest(rig, "vault")
    check("the history names the run: executed, no executor, all to Carol",
          event.get("outcome") == "executed" and event.get("executor_pubkey") is None
          and [leg.get("recipient_pubkey") for leg in event.get("legs") or []]
          == [rig.pk["carol"]] and event.get("total") == left, event)
    rig.mine_to(st["vault_due"] + 2)
    check("the rule has ended", payout(rig, "vault").get("installed") is False,
          payout(rig, "vault").get("rule"))
    pay(rig, orc, "carol", "vault", BASE_FEE + 10, "Carol sends the vault a fee and 10")
    rig.mine(empty=False)
    pay(rig, orc, "vault", "bob", 10, "the vault's key signs a transfer again: admitted")
    rig.mine(empty=False)
    orc.verify("the vault after its rule ended")


def scenario_second_period(rig, st):
    say("7. 256 blocks after the first, Alice's second payment to Bob")
    orc = Oracle(rig, "7", ("alice", "bob"))
    second = st["rent_due"] + EVERY
    check("the second due point is still ahead", rig.a.height() + 1 < second,
          (rig.a.height(), second))
    rig.mine_to(second - 1)
    orc.verify("the blocks before the second due point (nothing)")
    rig.mine()
    orc.move("alice", "bob", RENT)
    orc.verify("the second due point (another 100, nobody paid a fee)")
    event, got = newest(rig, "alice"), rule(rig, "alice")
    check("the history names due point 1 and the rule waits for the third",
          event.get("due_index") == 1 and event.get("due_at") == second
          and got.get("next_due") == second + EVERY and got.get("executions") == 2,
          (event, got))


def scenario_follower(rig, st):
    say("8. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getpayoutrule {rig.pk[n]}" for n in ("alice", "shop", "creator", "vault")]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_standing(rig, st)
            scenario_route(rig, st)
            scenario_no_second_hop(rig, st)
            scenario_seal(rig, st)
            scenario_restart(rig, st)
            scenario_return(rig, st)
            scenario_second_period(rig, st)
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
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local", "e2e-triggers"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        funded = {n: FUNDS for n in ("alice", "bob", "carol")}
        funded["shop"] = BASE_FEE
        funded["creator"] = BASE_FEE
        funded["vault"] = BASE_FEE
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS, funded=funded,
                                 approval_slots=True)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
