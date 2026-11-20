#!/usr/bin/env python3
"""End-to-end envelope time conditions and refunds on REAL running nodes with the native Tau engine.

tests/test_envelope_time*.py and tests/test_envelope_refund*.py drive the real
block apply in one process; this drives two live nodes (see scripts/e2e_rig.py
and scripts/e2e_envelope_limits.py): node A mines and is driven through its RPC
port and the `tau-testnet envelope` CLI; node B receives A's blocks only.

SCENARIOS (asserted on balances through an accounting oracle, fees to the miner
included, and on the envelope history every node records)
    1. Locks on the block clock: `--hold-blocks` and `--not-before-height`. A
       spend before the unlock is refused (ENVELOPE_LOCKED); at the unlock it
       lands.
    2. Windows on the block time: an envelope open on today's UTC weekday and
       this hour is spent; one whose days or hours leave out now is refused
       (ENVELOPE_OUTSIDE_WINDOW) and says when its next window opens. The same
       with `--utc-offset +05:45`: the hours open there are spent, the UTC hours
       read there are shut.
    3. An idle refund on the block clock: a spend moves the idle point; with no
       spend after it, the rest goes back to the sender at the idle point
       (`refunded_idle`), fee-free and past the sender's receive route
       untouched. A spend for the due block itself is refused (ENVELOPE_ENDED).
    4. `--at-end refund`: what is left at the end goes back to the sender
       (`refunded`).
    5. An idle refund on the seconds clock on an idle node: node A runs its own
       miner, nobody sends anything, and the miner's due wake makes the one
       block that refunds it.
    6. Node B replays A's blocks, restarts, and ends with the same state hash,
       the same balances and the same `getenvelope` answers.

USAGE
    python scripts/e2e_envelope_time_refunds.py provision --dir .local/e2e-envelope-time
    python scripts/e2e_envelope_time_refunds.py run --dir .local/e2e-envelope-time

The native binding comes from $TAU_NATIVE_PATH. Scenario 2 reads the node's
own clock; a run that crosses a UTC hour while it is in scenario 2 may report a
window check falsely, so it is rerun once on such a failure.
"""
from __future__ import annotations

import argparse
import datetime
import os
import time

import e2e_rig as rig_mod
from e2e_envelope_limits import closed, code, envelope, held, ok_proc, raw_spend, send, spend
from e2e_rig import Oracle, Rig, check, say

NETWORK_ID = "tau-e2e-envelope-time"
ACTORS = ("miner", "gran", "child", "shop", "piggy")
DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def env_field(rig, eid, name):
    return (envelope(rig, eid).get("envelope") or {}).get(name)


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_locks(rig, st):
    say("1. Locks on the block clock")
    orc = Oracle(rig, "1", ("gran", "child", "shop"))
    _p, hold = send(rig, "gran", "child", "--amount", "300", "--hold-blocks", "4",
                    "--ends-in-blocks", "60")
    st["hold"] = hold
    rig.mine(empty=False)
    orc.fee("gran")
    orc.add("gran", -300)
    unlock = int(env_field(rig, hold, "unlocks_at") or 0)
    res = raw_spend(rig, "child", hold, "shop", 100)
    check("a spend before the hold ends is refused ENVELOPE_LOCKED",
          code(res) == "ENVELOPE_LOCKED", res)
    rig.mine_to(unlock - 1)
    ok_proc("a spend for the unlock block is admitted", spend(rig, "child", hold, "shop", 100))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 100)

    nb = rig.a.height() + 6
    _p, later = send(rig, "gran", "child", "--amount", "200", "--not-before-height", str(nb),
                     "--ends-in-blocks", "60")
    st["not_before"] = later
    rig.mine(empty=False)
    orc.fee("gran")
    orc.add("gran", -200)
    res = raw_spend(rig, "child", later, "shop", 50)
    check("a spend before `not_before` is refused ENVELOPE_LOCKED",
          code(res) == "ENVELOPE_LOCKED", res)
    rig.mine_to(nb - 1)
    ok_proc("at `not_before` it lands", spend(rig, "child", later, "shop", 50))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 50)
    orc.verify("the locks")


def scenario_windows(rig, st, retry=True):
    say("2. Windows on the block time")
    orc = Oracle(rig, "2", ("gran", "child", "shop"))
    now = datetime.datetime.now(datetime.timezone.utc)
    if now.minute == 59 and now.second > 30:
        time.sleep(40)
        now = datetime.datetime.now(datetime.timezone.utc)
    today, hour = DAYS[now.weekday()], now.hour
    others = [d for d in DAYS if d != today]
    hours_now = f"{hour},{(hour + 1) % 24}" if hour < 23 else "0,23"
    hours_not = ",".join(str(h) for h in range(24) if h not in (hour, (hour + 1) % 24))
    _p, open_now = send(rig, "gran", "child", "--amount", "100", "--days", today,
                        "--hours", hours_now, "--ends-in", "3d")
    _p, not_today = send(rig, "gran", "child", "--amount", "100", "--days", ",".join(others),
                         "--ends-in", "3d")
    _p, not_now = send(rig, "gran", "child", "--amount", "100", "--hours", hours_not,
                       "--ends-in", "3d")
    # The same hours read somewhere else: at UTC+05:45 the wall clock shows another
    # hour, so "this hour and the next" is open there and the UTC hours are shut.
    there = now + datetime.timedelta(hours=5, minutes=45)
    hours_there = (f"{there.hour},{(there.hour + 1) % 24}" if there.hour < 23 else "0,23")
    _p, open_there = send(rig, "gran", "child", "--amount", "100", "--hours", hours_there,
                          "--utc-offset", "+05:45", "--ends-in", "3d")
    _p, shut_there = send(rig, "gran", "child", "--amount", "100", "--hours", hours_now,
                          "--utc-offset", "+05:45", "--ends-in", "3d")
    st.update(window_open=open_now, window_day=not_today, window_hour=not_now,
              window_open_there=open_there, window_shut_there=shut_there)
    rig.mine(empty=False)
    for _ in range(5):
        orc.fee("gran")
        orc.add("gran", -100)
    ok_proc(f"a spend inside {today} {hours_now}h UTC is admitted",
            spend(rig, "child", open_now, "shop", 30))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 30)
    ok_proc(f"a spend inside hours {hours_there} read at UTC+05:45 is admitted",
            spend(rig, "child", open_there, "shop", 30))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 30)
    for label, eid in (("weekday", not_today), ("hour", not_now)):
        res = raw_spend(rig, "child", eid, "shop", 30)
        msg = (res.get("error") or {}).get("message", "")
        ok = check(f"outside its {label}s: refused ENVELOPE_OUTSIDE_WINDOW, naming the next window",
                   code(res) == "ENVELOPE_OUTSIDE_WINDOW" and "UTC" in msg, res)
        if not ok and retry and datetime.datetime.now(datetime.timezone.utc).hour != hour:
            say("  (the UTC hour changed during the check; rerunning the window scenario)")
            rig_mod.FAILED.pop()
            return scenario_windows(rig, st, retry=False)
    window = env_field(rig, not_today, "next_window")
    check("`getenvelope` shows the next window and that the next block is outside it",
          bool(window) and env_field(rig, not_today, "in_window") is False,
          envelope(rig, not_today).get("envelope"))
    res = raw_spend(rig, "child", shut_there, "shop", 30)
    msg = (res.get("error") or {}).get("message", "")
    check(f"hours {hours_now} read at UTC+05:45 are shut now: refused, naming the offset",
          code(res) == "ENVELOPE_OUTSIDE_WINDOW" and "UTC+05:45" in msg, res)
    check("`getenvelope` shows where an envelope's windows are read",
          env_field(rig, shut_there, "windows_read_at") == "UTC+05:45"
          and env_field(rig, shut_there, "utc_offset") == 23
          and env_field(rig, not_now, "windows_read_at") == "UTC",
          envelope(rig, shut_there).get("envelope"))
    orc.verify("the windows")


def scenario_idle_refund(rig, st):
    say("3. An idle refund on the block clock, past the sender's route")
    orc = Oracle(rig, "3", ("gran", "child", "shop", "piggy"))
    ok_proc("gran routes 50% of her income to the piggy bank", rig.cli(
        "route", "set", "--privkey", rig.privkey("gran"), "--to", rig.pk["piggy"],
        "--share", "50", "--fee", rig_mod.FEE_LIMIT))
    rig.mine(empty=False)
    orc.fee("gran")
    _p, eid = send(rig, "gran", "child", "--amount", "500", "--refund-idle-blocks", "5",
                   "--ends-in-blocks", "100")
    st["idle"] = eid
    rig.mine(empty=False)
    orc.fee("gran")
    orc.add("gran", -500)
    first = int(env_field(rig, eid, "idle_refund_at") or 0)
    rig.mine_to(first - 2)
    ok_proc("a spend before the idle point", spend(rig, "child", eid, "shop", 100))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 100)
    moved = int(env_field(rig, eid, "idle_refund_at") or 0)
    check("the spend moves the idle point", moved == rig.a.height() + 5, (first, moved))
    rig.mine_to(moved - 1)
    res = raw_spend(rig, "child", eid, "shop", 10)
    check("a spend for the due block is refused ENVELOPE_ENDED", code(res) == "ENVELOPE_ENDED", res)
    rig.mine()
    check("at the idle point it closes `refunded_idle`", closed(rig, eid) == "refunded_idle",
          envelope(rig, eid).get("history", [])[:1])
    orc.add("gran", 400)
    orc.verify("the idle refund (400 back to gran whole, fee-free, not routed)")


def scenario_end_refund(rig, st):
    say("4. `--at-end refund`")
    orc = Oracle(rig, "4", ("gran", "child", "shop", "piggy"))
    _p, eid = send(rig, "gran", "child", "--amount", "80", "--ends-in-blocks", "4",
                   "--at-end", "refund")
    st["end_refund"] = eid
    rig.mine(empty=False)
    orc.fee("gran")
    orc.add("gran", -80)
    ok_proc("a spend of 30", spend(rig, "child", eid, "shop", 30))
    rig.mine(empty=False)
    orc.fee("child")
    orc.add("shop", 30)
    end = int(env_field(rig, eid, "due_at") or 0)
    rig.mine_to(end)
    check("at the end it closes `refunded`", closed(rig, eid) == "refunded",
          envelope(rig, eid).get("history", [])[:1])
    orc.add("gran", 50)
    orc.verify("the end refund (50 back to gran)")


def scenario_idle_wake(rig, st):
    say("5. A seconds-clock idle refund on an idle node: the miner's wake")
    if not rig.restart_a(TAU_MINING_ENABLED="true"):
        return
    check("the open envelopes survive the restart",
          held(rig, st["hold"]) == 200 and held(rig, st["window_open"]) == 70,
          (held(rig, st["hold"]), held(rig, st["window_open"])))
    orc = Oracle(rig, "5", ("gran", "child"))
    _p, eid = send(rig, "gran", "child", "--amount", "60", "--refund-idle", "15s",
                   "--ends-in", "1h")
    st["wake"] = eid
    rig.settle(lambda: envelope(rig, eid).get("open"), "the send to land", tries=3)
    orc.fee("gran")
    orc.add("gran", -60)
    due = int(env_field(rig, eid, "idle_refund_at") or 0)
    height = rig.a.height()
    say(f"   idle at height {height}; refund due at {due} (now {int(time.time())})")
    done = rig.wait(lambda: closed(rig, eid) == "refunded_idle", "the refund",
                    timeout=max(60.0, due - time.time() + 40))
    check("the miner's wake refunded it with no transaction sent", done,
          envelope(rig, eid).get("history", [])[:1])
    check("the wake made exactly one block", rig.a.height() == height + 1,
          (height, rig.a.height()))
    orc.add("gran", 60)
    orc.verify("the idle period")
    rig.restart_a()


def scenario_follower(rig, st):
    say("6. Node B replays A's blocks, restarts, and agrees")
    rig.mine()
    reads = [f"getenvelope {eid}" for eid in st.values() if eid]
    reads += [f"getenvelopes {rig.pk[n]} all" for n in ("gran", "child")]
    reads += [f"getbalance {rig.pk[n]}" for n in ACTORS]
    rig.follower_agrees(reads)


def run(root: str) -> int:
    rig = Rig(root)
    st: dict = {}
    try:
        if rig.start():
            rig.mine()
            scenario_locks(rig, st)
            scenario_windows(rig, st)
            scenario_idle_refund(rig, st)
            scenario_end_refund(rig, st)
            scenario_idle_wake(rig, st)
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
                                                      "e2e-envelope-time"))
    args = parser.parse_args(argv)
    if args.mode == "provision":
        return rig_mod.provision(args.dir, NETWORK_ID, ACTORS)
    return run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
