#!/usr/bin/env python3
"""End-to-end combined envelope conditions on REAL running nodes with the native Tau engine.

tests/test_envelope_combined.py proves the readings by exhaustive search and
tests/test_envelope_tau_form.py checks the conditions against the real Tau
engine; this drives two live nodes (see scripts/e2e_rig.py and
scripts/e2e_envelope_limits.py): node A mines and is driven through its RPC port
and the `tau-testnet envelope` CLI; node B receives A's blocks only.

SCENARIOS
    1. `envelope check` reads the guide's example offline (Alice sends Bob 5,000:
       500 a week from the first of a month, working days, back if unused for
       two weeks or left four weeks later): plain words, the info note, exit 0.
    2. A send that could never be spent: `envelope check` names the clash and
       exits 1; `envelope send` refuses it before signing; a raw send is refused
       by the node (ENVELOPE_NEVER_SPENDABLE) with the clash in words.
    3. The example sent for real: the node's answer carries `plan`, `notes` and
       `text`, `getenvelope` reads the same text, and a spend now is refused
       ENVELOPE_LOCKED until the example's first day.
    4. One envelope with a limit, a hold, an idle refund and `at_end refund` on
       the block clock: the refusals come in the documented order (locked
       before more than it holds before over the cap), a spend inside every
       condition lands, and the idle point returns the rest.
    5. The grant with exactly three conditions (5,000, at most 500 a week, only
       from a first day, the rest back to the sender at the deadline): read
       offline and sent with its real dates, a spend now refused ENVELOPE_LOCKED;
       then the same three conditions on the block clock, so that it finishes
       while you watch: locked before the first block, 500 in the first period,
       one more refused ENVELOPE_LIMIT, 500 again in the next period, and at the
       deadline the remaining 4,000 back with the sender with no transaction.
    6. A condition that never decides is named in the node's preview
       (`HOLD_COVERED`), and the envelope behaves exactly as without it.
    7. Node B replays A's blocks, restarts, and ends with the same state hash,
       the same balances and the same `getenvelope` answers.

USAGE
    python scripts/e2e_envelope_combined.py provision --dir .local/e2e-envelope-combined
    python scripts/e2e_envelope_combined.py run --dir .local/e2e-envelope-combined

The native binding comes from $TAU_NATIVE_PATH. The example's dates are taken from
today (the first day of the month after next, and four weeks later), so the run
reads the same on any day.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os

import e2e_rig as rig_mod
from e2e_envelope_limits import closed, code, envelope, ok_proc, raw_spend, send, spend
from e2e_rig import FEE_LIMIT, Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-envelope-combined"
ACTORS = ("miner", "alice", "bob", "shop")


def example_dates(today=None):
    """(first day, end) of the guide's example, always ahead of `today`: the first
    day of the month after next, and four weeks later, as UTC dates."""
    today = today or datetime.datetime.now(datetime.timezone.utc).date()
    first = (today.replace(day=1) + datetime.timedelta(days=62)).replace(day=1)
    return first.isoformat(), (first + datetime.timedelta(days=28)).isoformat()


FIRST_DAY, END_DAY = example_dates()
EXAMPLE = ("--amount", "5000", "--cap", "500", "--recurring", "--period", "7d",
           "--not-before", FIRST_DAY, "--days", "mon-fri", "--refund-idle", "14d",
           "--ends-at", END_DAY, "--at-end", "refund")
GRANT = ("--amount", "5000", "--cap", "500", "--recurring", "--period", "7d",
         "--not-before", FIRST_DAY, "--ends-at", END_DAY, "--at-end", "refund")


def offline(rig, *args):
    """`envelope check`: no key, no node."""
    env = dict(os.environ)
    env["PYTHONPATH"] = rig_mod.base.NATIVE + os.pathsep + rig.tree_a
    import subprocess
    return subprocess.run([rig_mod.base.PYTHON, "-m", "tau_testnet_cli", "--port", "1",
                           "envelope", "check", *args],
                          cwd=rig.tree_a, env=env, capture_output=True, text=True, timeout=120)


def raw_send(rig, who, to, **terms):
    from tau_testnet_cli import tx as cli_tx
    payload = cli_tx.build_envelope_send_tx(**rig.common(who), recipient_pubkey=rig.pk[to],
                                            fee_limit=FEE_LIMIT, **terms)
    return rig.submit(who, payload)


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_check_offline(rig, st):
    say("1. `envelope check` reads the guide's example offline")
    proc = offline(rig, "--to", rig.pk["bob"], *EXAMPLE)
    out = proc.stdout
    check("it exits 0 and reads the conditions in words", proc.returncode == 0
          and "500 per week" in out and "Mon-Fri" in out, out[-600:] + proc.stderr[-300:])
    check("the info note: at most 2,000 of the 5,000 before the end",
          "info:" in out and "2,000 of the 5,000" in out, out[-600:])


def scenario_never_spendable(rig, st):
    say("2. A send that could never be spent")
    flags = ("--amount", "100", "--hold-blocks", "10", "--ends-in-blocks", "5")
    proc = offline(rig, "--to", rig.pk["bob"], "--at-height", "100", *flags)
    check("`envelope check` exits 1 and names the clash", proc.returncode == 1
          and "refused:" in proc.stdout and "could never be spent" in proc.stdout,
          proc.stdout[-400:] + proc.stderr[-300:])
    proc, _eid = send(rig, "alice", "bob", *flags, expect_ok=False)
    check("`envelope send` refuses it before signing", proc.returncode != 0
          and "never be spent" in (proc.stdout + proc.stderr), proc.stdout[-300:] + proc.stderr[-300:])
    tip = rig.a.height()
    res = raw_send(rig, "alice", "bob", amount=100, clock="blocks", hold=10,
                   expires_at=tip + 6)
    msg = (res.get("error") or {}).get("message", "")
    check("the node refuses a raw send ENVELOPE_NEVER_SPENDABLE, naming the unlock and the end",
          code(res) == "ENVELOPE_NEVER_SPENDABLE" and "would unlock at" in msg
          and "before its end" in msg, res)


def scenario_example_for_real(rig, st):
    say("3. The example sent for real")
    orc = Oracle(rig, "3", ("alice", "bob"))
    proc = rig.cli("--json", "envelope", "send", "--privkey", rig.privkey("alice"),
                   "--to", rig.pk["bob"], "--fee", FEE_LIMIT, *EXAMPLE)
    try:
        answer = json.loads(proc.stdout)
    except ValueError:
        answer = {}
    eid = next((line.split()[-1] for line in proc.stderr.splitlines()
                if line.startswith("envelope id:")), None)
    st["example"] = eid
    preview = ((answer.get("response") or {}).get("data") or {}).get("envelope") or {}
    check("the node's answer carries plan, notes and text",
          proc.returncode == 0 and preview.get("plan") and preview.get("text")
          and isinstance(preview.get("notes"), list), proc.stdout[-500:] + proc.stderr[-300:])
    codes = [n.get("code") for n in preview.get("notes") or []]
    check("the notes include LIMIT_LEAVES_REST", "LIMIT_LEAVES_REST" in codes, codes)
    rig.mine(empty=False)
    orc.fee("alice")
    orc.add("alice", -5000)
    env = envelope(rig, eid).get("envelope") or {}
    check("`getenvelope` reads the same text", env.get("text") == preview.get("text"),
          (env.get("text"), preview.get("text")))
    res = raw_spend(rig, "bob", eid, "shop", 100)
    check("a spend now is refused ENVELOPE_LOCKED, naming the example's first day",
          code(res) == "ENVELOPE_LOCKED" and FIRST_DAY in (res.get("error") or {}).get("message", ""),
          res)
    orc.verify("the example sent")


def scenario_check_order(rig, st):
    say("4. Limit + hold + idle refund + at_end refund on the block clock")
    orc = Oracle(rig, "4", ("alice", "bob", "shop"))
    _p, eid = send(rig, "alice", "bob", "--amount", "120", "--cap", "50", "--recurring",
                   "--period-blocks", "5", "--hold-blocks", "3", "--refund-idle-blocks", "8",
                   "--ends-in-blocks", "40", "--at-end", "refund")
    st["combined"] = eid
    rig.mine(empty=False)
    orc.fee("alice")
    orc.add("alice", -120)
    res = raw_spend(rig, "bob", eid, "shop", 1000)
    check("before the unlock, too much and over the cap: ENVELOPE_LOCKED comes first",
          code(res) == "ENVELOPE_LOCKED", res)
    unlock = int((envelope(rig, eid).get("envelope") or {}).get("unlocks_at") or 0)
    rig.mine_to(unlock - 1)
    res = raw_spend(rig, "bob", eid, "shop", 1000)
    check("unlocked, 1,000 of 120: ENVELOPE_INSUFFICIENT before the cap",
          code(res) == "ENVELOPE_INSUFFICIENT", res)
    res = raw_spend(rig, "bob", eid, "shop", 60)
    check("60 of a cap of 50: ENVELOPE_LIMIT", code(res) == "ENVELOPE_LIMIT", res)
    ok_proc("50 inside every condition is admitted", spend(rig, "bob", eid, "shop", 50))
    rig.mine(empty=False)
    orc.fee("bob")
    orc.add("shop", 50)
    idle = int((envelope(rig, eid).get("envelope") or {}).get("idle_refund_at") or 0)
    rig.mine_to(idle)
    check("with no spend for 8 blocks it closes `refunded_idle`",
          closed(rig, eid) == "refunded_idle", envelope(rig, eid).get("history", [])[:1])
    orc.add("alice", 70)
    orc.verify("the combined envelope")


def scenario_grant(rig, st):
    say("5. The grant: 5,000, at most 500 a week from a first day, the rest back at the deadline")
    proc = offline(rig, "--to", rig.pk["bob"], *GRANT)
    out = proc.stdout
    check("`envelope check` reads the three conditions in words", proc.returncode == 0
          and "500 per week" in out and FIRST_DAY in out and END_DAY in out
          and "goes back to the sender" in out, out[-600:] + proc.stderr[-300:])
    check("and says how much can be spent before the deadline at most",
          "2,000 of the 5,000" in out, out[-600:])
    orc = Oracle(rig, "5", ("alice", "bob", "shop"))
    _p, dated = send(rig, "alice", "bob", *GRANT)
    st["grant_dated"] = dated
    rig.mine(empty=False)
    orc.fee("alice")
    orc.add("alice", -5000)
    res = raw_spend(rig, "bob", dated, "shop", 500)
    check("with its real dates a spend now is refused ENVELOPE_LOCKED, naming the first day",
          code(res) == "ENVELOPE_LOCKED" and FIRST_DAY in (res.get("error") or {}).get("message", ""),
          res)

    # The same three conditions on the block clock: a period of 4 blocks.
    first = rig.a.height() + 4
    _p, eid = send(rig, "alice", "bob", "--amount", "5000", "--cap", "500", "--recurring",
                   "--period-blocks", "4", "--not-before-height", str(first),
                   "--ends-in-blocks", "16", "--at-end", "refund")
    st["grant"] = eid
    rig.mine(empty=False)
    orc.fee("alice")
    orc.add("alice", -5000)
    env = envelope(rig, eid).get("envelope") or {}
    unlock, due = int(env.get("unlocks_at") or 0), int(env.get("due_at") or 0)
    check("it unlocks at the first block and is due back at its end",
          unlock == first and due > unlock + 8 and env.get("due_outcome") == "refunded", env)
    res = raw_spend(rig, "bob", eid, "shop", 500)
    check("before the first block a spend is refused ENVELOPE_LOCKED",
          code(res) == "ENVELOPE_LOCKED", res)
    rig.mine_to(unlock - 1)
    ok_proc("500 in the first period is admitted", spend(rig, "bob", eid, "shop", 500))
    rig.mine(empty=False)
    orc.fee("bob")
    orc.add("shop", 500)
    res = raw_spend(rig, "bob", eid, "shop", 1)
    check("one more in the same period is refused ENVELOPE_LIMIT",
          code(res) == "ENVELOPE_LIMIT", res)
    rig.mine_to(unlock + 3)
    ok_proc("the next period allows 500 again", spend(rig, "bob", eid, "shop", 500))
    rig.mine(empty=False)
    orc.fee("bob")
    orc.add("shop", 500)
    rig.mine_to(due)
    check("at the deadline it closes `refunded`, with no transaction",
          closed(rig, eid) == "refunded", envelope(rig, eid).get("history", [])[:1])
    orc.add("alice", 4000)
    orc.verify("the grant (1,000 spent, 4,000 back with the sender)")


def scenario_never_decides(rig, st):
    say("6. A condition that never decides is named, and changes nothing")
    tip = rig.a.height()
    proc = rig.cli("--json", "envelope", "send", "--privkey", rig.privkey("alice"),
                   "--to", rig.pk["bob"], "--fee", FEE_LIMIT, "--amount", "40",
                   "--hold-blocks", "6", "--not-before-height", str(tip + 3),
                   "--ends-in-blocks", "30")
    try:
        answer = json.loads(proc.stdout)
    except ValueError:
        answer = {}
    eid = next((line.split()[-1] for line in proc.stderr.splitlines()
                if line.startswith("envelope id:")), None)
    st["covered"] = eid
    notes = (((answer.get("response") or {}).get("data") or {}).get("envelope") or {}).get("notes") or []
    covered = [n for n in notes if n.get("code") == "NOT_BEFORE_COVERED"]
    check("the preview names `not_before` as covered by the hold, level never_decides",
          covered and covered[0].get("level") == "never_decides", notes)
    rig.mine(empty=False)
    env = envelope(rig, eid).get("envelope") or {}
    check("it unlocks by the hold alone", env.get("unlocked_by") in ("hold", None)
          and int(env.get("unlocks_at") or 0) == rig.a.height() + 6, env)


def scenario_follower(rig, st):
    say("7. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getenvelope {eid}" for eid in st.values() if eid]
    reads += [f"getenvelopes {rig.pk[n]} all" for n in ("alice", "bob")]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_check_offline(rig, st)
            scenario_never_spendable(rig, st)
            scenario_example_for_real(rig, st)
            scenario_check_order(rig, st)
            scenario_grant(rig, st)
            scenario_never_decides(rig, st)
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
                                                      "e2e-envelope-combined"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
