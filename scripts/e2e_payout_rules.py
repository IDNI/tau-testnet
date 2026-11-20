#!/usr/bin/env python3
"""End-to-end payout rules (#63) on REAL running nodes with the native Tau engine.

tests/test_payout_*.py drive the real block apply in one process, and
tests/test_payout_native.py builds the documented rules on the engine; this
drives two live nodes (see scripts/e2e_rig.py), so every amount below is the one
the real engine computed inside a running node's payout pool. Node A mines and
is driven through its RPC port and the `tau-testnet payout` CLI; node B receives
A's blocks only.

SCENARIOS (asserted on balances through an accounting oracle, fees to the miner
included, and on the rule's history every node records)
    1. The treasury installs "only the reviewer releases money" with
       `payout set` (fixed slot: Bob; 500 per execution, 800 per 20-block period).
    2. A stranger's execution is refused at admission: the rule gives it 0.
    3. The reviewer releases 300 with `payout execute`: Bob gets exactly 300.
       Over the per-execution cap: refused. Up to the period cap: paid; one
       more: refused; in the next period: paid again.
    4. Node A restarts: the rule and its period count survive.
    5. A signed transfer is blocked by the treasury's own o5 clause, yet the
       payout rule still pays: it is the account's second authorization.
    6. The treasury replaces its rule (a fixed and an open slot, both the asked
       amount): an execution pinned to the old rule id is refused; a stranger
       names Dave for the open slot and both slots are paid together.
    7. The replaced rule reaches its end: `expired`, and executions are refused.
    8. A third rule is installed and revoked with `payout revoke` (fee-free).
    9. A royalty paid once per sale: the treasury installs `payout set
       --per-sale` (5% to Bob). Carol pays the treasury 101; the node records
       that transfer as an open sale named by its transaction hash. Bob runs
       `payout execute --sale <hash>`: the engine reads 101 and Bob gets 5. The
       same sale again is refused; a sale nobody paid is refused.
   10. Node B replays A's blocks, restarts, and ends with the same state hash,
       the same balances and the same `getpayoutrule` answer.

USAGE
    python scripts/e2e_payout_rules.py provision --dir .local/e2e-payout
    python scripts/e2e_payout_rules.py run --dir .local/e2e-payout

The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
import os

import e2e_rig as rig_mod
from e2e_rig import FEE_LIMIT, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-payout"
ACTORS = ("miner", "treasury", "reviewer", "bob", "carol", "dave")

PASSTHROUGH = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
TWO_SLOTS = "always ( (o30[t]:bv[24] = i40[t]:bv[24]) && (o31[t]:bv[24] = i40[t]:bv[24]) )."
BLOCK_ALL = ("always ( i1[t]:bv[24] > { #x000000 }:bv[24] -> "
             "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")


ROYALTY = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] )."


def reviewer_only(pk):
    return ("always ( (i13[t]:bv[384] = { #x%s }:bv[384]) ? "
            "(o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { #x000000 }:bv[24]) )." % pk)


def payout(rig, node=None):
    return rig.read(f"getpayoutrule {rig.pk['treasury']}", node) or {}


def rule_id(rig):
    return (payout(rig).get("rule") or {}).get("rule_id")


def history(rig):
    return [e.get("outcome") for e in reversed(payout(rig).get("history") or [])]


def install(rig, body, *flags):
    proc = rig.cli("payout", "set", "--privkey", rig.privkey("treasury"), "--body", body,
                   "--fee", FEE_LIMIT, *flags)
    check("`payout set` is admitted", proc.returncode == 0, proc.stdout[-400:] + proc.stderr[-400:])
    return proc


def execute(rig, who, *flags):
    return rig.cli("payout", "execute", "--privkey", rig.privkey(who),
                   "--account", rig.pk["treasury"], "--fee", FEE_LIMIT, *flags)


def raw_execute(rig, who, rid, data, recipients=None, sale_id=None):
    from tau_testnet_cli import tx as cli_tx
    payload = cli_tx.build_payout_execute_tx(
        **rig.common(who), account_pubkey=rig.pk["treasury"], rule_id=rid,
        recipients=recipients or {}, data=data, sale_id=sale_id, fee_limit=FEE_LIMIT)
    return rig.submit(who, payload)


def refused(res):
    return res.get("status") != "ok"


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_install(rig, st):
    say("1. The treasury installs 'only the reviewer releases money'")
    orc = Oracle(rig, "1", ("treasury",))
    install(rig, reviewer_only(rig.pk["reviewer"]), "--slot", rig.pk["bob"],
            "--cap-per-execution", "500", "--cap-per-period", "800",
            "--period-blocks", "20", "--ends-in", "400")
    rig.settle(lambda: payout(rig).get("installed"), "the rule to install")
    orc.fee("treasury")
    orc.verify("the install (one fee)")
    st["rule1"] = rule_id(rig)
    check("the rule is installed with an id", bool(st["rule1"]), payout(rig))
    check("the history records `installed`", history(rig)[-1:] == ["installed"], history(rig))


def scenario_executions(rig, st):
    say("2-3. Executions: a stranger gets nothing; the reviewer releases within the caps")
    orc = Oracle(rig, "3", ("treasury", "reviewer", "bob", "carol"))
    res = raw_execute(rig, "carol", st["rule1"], {0: 300})
    check("a stranger's execution is refused at admission (the rule gives it 0)",
          refused(res), res)
    proc = execute(rig, "reviewer", "--data", "0=300")
    check("the reviewer's `payout execute` is admitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("reviewer")
    orc.move("treasury", "bob", 300)
    orc.verify("the reviewer's execution (Bob gets the engine's 300)")

    res = raw_execute(rig, "reviewer", st["rule1"], {0: 600})
    check("600 is over the per-execution cap: refused", refused(res), res)
    proc = execute(rig, "reviewer", "--data", "0=400")
    check("400 more fits the period cap (700 of 800)", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("reviewer")
    orc.move("treasury", "bob", 400)
    res = raw_execute(rig, "reviewer", st["rule1"], {0: 200})
    check("200 more would make 900 of 800: refused", refused(res), res)
    orc.verify("the period cap")
    rule = payout(rig).get("rule") or {}
    check("the rule reads 700 spent and 100 left this period",
          rule.get("spent_this_period") == 700 and rule.get("left_this_period") == 100, rule)
    st["period_closes"] = rule.get("period_ends") or rule.get("period_end")


def scenario_restart_and_next_period(rig, st):
    say("4. Node A restarts; the next period pays again")
    orc = Oracle(rig, "4", ("treasury", "reviewer", "bob"))
    before = payout(rig).get("rule")
    if not rig.restart_a():
        return
    check("the rule and its period count survive the restart", payout(rig).get("rule") == before,
          (before, payout(rig).get("rule")))
    for _ in range(25):
        rule = payout(rig).get("rule") or {}
        if rule.get("spent_this_period") == 0:
            break
        rig.mine()
    proc = execute(rig, "reviewer", "--data", "0=200")
    check("in the next period 200 is paid again", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("reviewer")
    orc.move("treasury", "bob", 200)
    orc.verify("the next period")


def scenario_o5_does_not_apply(rig, st):
    say("5. The treasury's own o5 blocks its signed transfers; the payout rule still pays")
    orc = Oracle(rig, "5", ("treasury", "reviewer", "bob", "carol"))
    payload = rig.common("treasury")
    payload.update({"tx_type": "user_tx", "fee_limit": FEE_LIMIT, "operations": {"0": BLOCK_ALL}})
    res = rig.submit("treasury", payload)
    check("the blocking o5 clause is admitted", res.get("status") == "ok", res)
    rig.mine(empty=False)
    orc.fee("treasury")
    res = rig.transfer("treasury", "carol", 50)
    check("a signed transfer from the treasury is refused by its o5", refused(res), res)
    proc = execute(rig, "reviewer", "--data", "0=100")
    check("the reviewer's execution is admitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("reviewer")
    orc.move("treasury", "bob", 100)
    orc.verify("o5 blocks transfers, the payout rule pays")


def scenario_replace(rig, st):
    say("6. The treasury replaces its rule: two slots, one of them open")
    orc = Oracle(rig, "6", ("treasury", "bob", "carol", "dave"))
    install(rig, TWO_SLOTS, "--slot", rig.pk["bob"], "--slot", "open",
            "--cap-per-execution", "300", "--cap-per-period", "1000",
            "--period-blocks", "100", "--ends-in", "12")
    rig.settle(lambda: rule_id(rig) not in (None, st["rule1"]), "the new rule to install")
    orc.fee("treasury")
    st["rule2"] = rule_id(rig)
    check("the history records the replacement", "replaced" in history(rig)
          or any((e.get("replaced") or e.get("replaces")) for e in payout(rig).get("history") or []),
          payout(rig).get("history"))
    res = raw_execute(rig, "carol", st["rule1"], {0: 100}, {1: rig.pk["dave"]})
    check("an execution pinned to the old rule id is refused", refused(res), res)
    proc = execute(rig, "carol", "--recipient", f"1={rig.pk['dave']}", "--data", "0=100")
    check("a stranger names Dave for the open slot", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("carol")
    orc.move("treasury", "bob", 100)
    orc.move("treasury", "dave", 100)
    orc.verify("both slots paid together")


def scenario_expire_and_revoke(rig, st):
    say("7-8. The rule reaches its end; a third rule is installed and revoked")
    orc = Oracle(rig, "7", ("treasury", "carol", "bob", "dave"))
    end = int((payout(rig).get("rule") or {}).get("expires_at") or 0)
    rig.mine_to(end + 1)
    check("the rule ends by itself: `expired`", not payout(rig).get("installed")
          and history(rig)[-1:] == ["expired"], history(rig)[-3:])
    res = raw_execute(rig, "carol", st["rule2"], {0: 50}, {1: rig.pk["dave"]})
    check("an execution after the end is refused", refused(res), res)
    install(rig, PASSTHROUGH, "--slot", rig.pk["bob"], "--cap-per-execution", "10",
            "--cap-per-period", "10", "--period-blocks", "10", "--ends-in", "100")
    rig.settle(lambda: payout(rig).get("installed"), "the third rule to install")
    orc.fee("treasury")
    st["rule3"] = rule_id(rig)
    proc = rig.cli("payout", "revoke", "--privkey", rig.privkey("treasury"))
    check("`payout revoke` is admitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    check("the rule is gone: `revoked`", not payout(rig).get("installed")
          and history(rig)[-1:] == ["revoked"], history(rig)[-3:])
    res = raw_execute(rig, "carol", st["rule3"], {0: 5})
    check("an execution after the revoke is refused", refused(res), res)
    orc.verify("the end and the revoke (fee-free)")


def scenario_per_sale(rig, st):
    say("9. A royalty paid once per sale: 5% of a sale of 101 is 5, once")
    orc = Oracle(rig, "9", ("treasury", "carol", "bob"))
    install(rig, ROYALTY, "--slot", rig.pk["bob"], "--cap-per-execution", "100",
            "--cap-per-period", "1000", "--period-blocks", "20", "--ends-in", "400",
            "--per-sale")
    rig.settle(lambda: payout(rig).get("installed"), "the royalty rule to install")
    orc.fee("treasury")
    rule = payout(rig).get("rule") or {}
    check("the rule is installed to pay per sale, with no open sale yet",
          rule.get("per_sale") is True and rule.get("open_sales") == [], rule)
    st["rule4"] = rule.get("rule_id")

    res = rig.transfer("carol", "treasury", 101)
    sale = (res.get("data") or {}).get("tx_hash")
    check("Carol's payment of 101 to the treasury is admitted", bool(sale), res)
    rig.mine(empty=False)
    orc.fee("carol")
    orc.move("carol", "treasury", 101)
    opened = (payout(rig).get("rule") or {}).get("open_sales") or []
    check("the node records it as an open sale named by its transaction hash",
          [(s.get("sale_id"), s.get("payer_pubkey"), s.get("amount")) for s in opened]
          == [(sale, rig.pk["carol"], 101)], opened)

    res = raw_execute(rig, "bob", st["rule4"], {}, sale_id="ab" * 32)
    check("a sale nobody paid is refused at admission", refused(res), res)
    proc = execute(rig, "bob", "--sale", sale)
    check("Bob's `payout execute --sale` is admitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.mine(empty=False)
    orc.fee("bob")
    orc.move("treasury", "bob", 5)
    orc.verify("the royalty (Bob gets the engine's 5 of 101)")
    rule = payout(rig).get("rule") or {}
    check("the sale is closed", rule.get("open_sales") == [] and rule.get("paid_total") == 5,
          rule)
    executed = (payout(rig).get("history") or [{}])[0]
    check("the history names the sale it paid",
          executed.get("outcome") == "executed" and executed.get("sale_id") == sale, executed)

    res = raw_execute(rig, "bob", st["rule4"], {}, sale_id=sale)
    check("the same sale again is refused at admission", refused(res), res)
    orc.verify("nothing more is paid for that sale")


def scenario_follower(rig, st):
    say("10. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getpayoutrule {rig.pk['treasury']}"]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_install(rig, st)
            scenario_executions(rig, st)
            scenario_restart_and_next_period(rig, st)
            scenario_o5_does_not_apply(rig, st)
            scenario_replace(rig, st)
            scenario_expire_and_revoke(rig, st)
            scenario_per_sale(rig, st)
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
    parser.add_argument("--dir", default=os.path.join(rig_mod.REPO, ".local", "e2e-payout"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
