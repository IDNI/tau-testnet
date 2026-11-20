#!/usr/bin/env python3
"""End-to-end recipient controls against REAL, disposable node processes.

tests/test_recipient_policy_*.py mock the engine or the chain; this drives live
nodes with the NATIVE engine through what only exists at runtime: the feature
switched on by a governance update on a RUNNING chain (no regenesis), the real
policy workers judging real clauses at admission and at block apply, a second
node reproducing every block from the first node's chain, and the flag
surviving a restart.

It reuses the process harness of scripts/e2e_retractable.py (isolated trees
exported from `git archive HEAD`, own keys, genesis, databases and ports).

USAGE
    python scripts/e2e_recipient_controls.py provision --dir .local/recipient-e2e
    python scripts/e2e_recipient_controls.py run --dir .local/recipient-e2e

SCENARIOS
    0  before activation: the node reports the feature off, refuses a receive
       rule at deploy, and pays everyone
    1  activation by governance update on the running chain
    2  inbound allow-list (#47): listed sender paid, stranger refused, a batch
       with one refusing recipient fails as one transaction
    3  one policy unit: outbound whitelist and inbound allow-list both enforce
    4  maximum hold time (#76): cap 0, cap 600 s, no cap, retract and release
    5  a refusal at block apply costs nothing (a rule that lands in the same
       block as a payment admitted before it)
    6  second node syncs from block 0 and agrees; the flag survives a restart
"""
from __future__ import annotations

import argparse
import atexit
import json
import os
import signal
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import e2e_retractable as rig  # noqa: E402

rig.NETWORK_ID = "tau-recipient-e2e"
rig.RPC_PORTS = {"node1": 64750, "node2": 64760}
rig.P2P_PORTS = {"node1": 64775, "node2": 64785}
rig.ACTORS = ("miner", "alice", "bob", "carol", "shop", "dave", "erin", "frank",
              "gina", "hugo", "ivan", "judy")

say, check, ok, err_code = rig.say, rig.check, rig.ok, rig.err_code
produce, wait_until, tx_ok = rig.produce, rig.wait_until, rig.tx_ok
BASE_FEE = rig.BASE_FEE

ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
MINE = "(i17[t]:bv[64] = { 0 }:bv[64])"


def _is(stream, pk):
    return "(%s[t]:bv[384] = { #x%s }:bv[384])" % (stream, pk)


def allow_list(*pks):
    listed = " || ".join(_is("i3", pk) for pk in pks)
    return "always ( ( %s || %s ) ? %s : %s )." % (MINE, listed, ALLOW, BLOCK)


def max_hold(seconds):
    return "always ( (i17[t]:bv[64] > { %d }:bv[64]) ? %s : %s )." % (seconds + 1, BLOCK, ALLOW)


BLOCKS = 10 ** 18      # where the hold lengths in blocks start on i17


def max_hold_either(seconds, blocks):
    return ("always ( ( ( (i17[t]:bv[64] > { %d }:bv[64]) && (i17[t]:bv[64] < { %d }:bv[64]) )"
            " || (i17[t]:bv[64] > { %d }:bv[64]) ) ? %s : %s )." % (
                seconds + 1, BLOCKS, BLOCKS + blocks, BLOCK, ALLOW))


def one_unit(pay_only, accept_only_from, seconds):
    return "always ( ( ( %s && !%s ) || ( !%s && !%s ) || (i17[t]:bv[64] > { %d }:bv[64]) ) ? %s : %s )." % (
        MINE, _is("i4", pay_only), MINE, _is("i3", accept_only_from), seconds + 1, BLOCK, ALLOW)


class Signer(rig.Signer):
    def rule(self, node, name, rule_text):
        seq, tip = self._envelope(node, name)
        payload = {"tx_type": "user_tx", "sender_pubkey": self.pk(name), "sequence_number": seq,
                   "expiration_time": int(time.time()) + 3600, "expire_at_height": tip + 1000,
                   "fee_limit": "10000", "operations": {"0": rule_text}}
        return self.sign(name, payload)

    def transfer_payload(self, node, name, legs, extra_operations=None):
        seq, tip = self._envelope(node, name)
        operations = {"1": [[self.pk(name), self.pk(to), str(amount)] for to, amount in legs]}
        operations.update(extra_operations or {})
        return self.sign(name, {
            "tx_type": "user_tx", "sender_pubkey": self.pk(name), "sequence_number": seq,
            "expiration_time": int(time.time()) + 3600, "expire_at_height": tip + 1000,
            "fee_limit": "10000", "operations": operations})

    def transfer_at(self, node, name, to, amount, seq):
        _own, tip = self._envelope(node, name)
        return self.submit(node, self.sign(name, {
            "tx_type": "user_tx", "sender_pubkey": self.pk(name), "sequence_number": seq,
            "expiration_time": int(time.time()) + 3600, "expire_at_height": tip + 1000,
            "fee_limit": "10000",
            "operations": {"1": [[self.pk(name), self.pk(to), str(amount)]]}}))

    def batch(self, node, name, legs):
        return self.submit(node, self.transfer_payload(node, name, legs))

    def governance(self, node, patch):
        gov = node.rpc("getgovernance")["data"]
        activate_at = int(gov["next_block_height"]) + int(gov["active_validator_count"]) + 2
        seq, tip = self._envelope(node, "miner")
        update = self.tx.build_consensus_rule_update_tx(
            sender_pubkey=self.pk("miner"), sequence_number=seq,
            expiration_time=int(time.time()) + 3600, expire_at_height=tip + 1000,
            # An update carries the consensus rules in force; only the patch is new.
            rule_revisions=[gov["consensus_rules"]], activate_at_height=activate_at,
            host_contract_patch=patch)
        from consensus.serialization import compute_update_id
        update_id = compute_update_id(update["rule_revisions"], activate_at, patch).hex()
        res = self.submit(node, self.sign("miner", update))
        return res, update_id, activate_at

    def vote(self, node, update_id):
        seq, tip = self._envelope(node, "miner")
        vote = self.tx.build_consensus_rule_vote_tx(
            sender_pubkey=self.pk("miner"), sequence_number=seq,
            expiration_time=int(time.time()) + 3600, expire_at_height=tip + 1000,
            update_id=update_id)
        return self.submit(node, self.sign("miner", vote))


def policy(node, pk, sender=None, amount=None):
    cmd = f"getrecipientpolicy {pk}" + (f" {sender} {amount}" if sender else "")
    for _ in range(20):                      # an expensive command: back off when limited
        res = node.rpc(cmd)
        if ok(res):
            return res["data"]
        if err_code(res) not in ("RATE_LIMITED", "BUSY", "TOO_MANY_REQUESTS"):
            return {"error": res}
        time.sleep(2.5)
    return {"error": res}


def flag(node):
    return node.rpc("getgovernance")["data"].get("recipient_policy_active")


def mined(node, label, blocks=1):
    return check(label, produce(node, node.height() + blocks))


def deploy(node, sg, name, rule_text, label):
    res = sg.submit(node, sg.rule(node, name, rule_text))
    tx_ok(res, f"{label}: rule admitted")
    mined(node, f"{label}: rule mined")
    return check(f"{label}: the node reports the address judges incoming payments",
                 wait_until(lambda: policy(node, sg.pk(name)).get("judges_incoming") is True,
                            "judges_incoming", 120))


def refused(res, code, label, **details):
    got = (res.get("error") or {})
    fine = (not ok(res)) and got.get("code") == code and all(
        (got.get("details") or {}).get(k) == v for k, v in details.items())
    return check(label, fine, json.dumps(res)[:300])


# --------------------------------------------------------------------------- #

def scenario_0(node, sg):
    say("0. before activation")
    check("0: getgovernance reports the feature off", flag(node) is False, flag(node))
    report = policy(node, sg.pk("bob"))
    check("0: getrecipientpolicy reports it off",
          report.get("active") is False and report.get("judges_incoming") is False, report)
    res = sg.submit(node, sg.rule(node, "bob", allow_list(sg.pk("alice"))))
    refused(res, "RECIPIENT_POLICY_INACTIVE", "0: an allow-list is refused at deploy with a clear reason")
    blob = json.dumps(sg.rule(node, "bob", allow_list(sg.pk("alice"))), separators=(",", ":"))
    refused(node.rpc("checktx '" + blob + "'"), "RECIPIENT_POLICY_INACTIVE",
            "0: checktx refuses it the same way")
    refused(node.rpc("checktx estimate '" + blob + "'"), "RECIPIENT_POLICY_INACTIVE",
            "0: and so does checktx estimate")
    res = sg.submit(node, sg.rule(node, "bob", max_hold(600)))
    refused(res, "RECIPIENT_POLICY_INACTIVE", "0: a hold cap is refused at deploy too")
    orc = rig.Oracle(node, sg, "0", ("bob", "carol"))
    tx_ok(sg.transfer(node, "carol", "bob", 11), "0: anyone pays bob")
    mined(node, "0: transfer mined")
    orc.add("carol", -(11 + BASE_FEE)); orc.add("bob", 11); orc.add("miner", BASE_FEE)
    orc.verify("after transfer")


def scenario_1(node, sg):
    say("1. activation by governance update on the running chain")
    res, update_id, activate_at = sg.governance(node, {"recipient_policy_active": True})
    tx_ok(res, "1: update proposed")
    mined(node, "1: proposal mined")
    tx_ok(sg.vote(node, update_id), "1: vote admitted")
    mined(node, "1: vote mined")
    check("1: still off before the activation height", flag(node) is False, flag(node))
    check("1: chain reaches the activation height",
          produce(node, activate_at, allow_empty=True))
    check("1: getgovernance reports the feature on",
          wait_until(lambda: flag(node) is True, "flag on", 120), flag(node))
    report = policy(node, sg.pk("bob"))
    check("1: getrecipientpolicy reports it on, nobody judging yet",
          report.get("active") is True and report.get("judges_incoming") is False, report)
    tx_ok(sg.transfer(node, "carol", "bob", 1), "1: transfers still flow after activation")
    mined(node, "1: transfer mined")
    res = sg.submit(node, sg.transfer_payload(node, "carol", [("bob", 1)], {"17": "0"}))
    check("1: only the node writes the receive stream", not ok(res), json.dumps(res)[:200])


def scenario_2(node, sg):
    say("2. inbound allow-list (#47)")
    deploy(node, sg, "bob", allow_list(sg.pk("alice")), "2")
    orc = rig.Oracle(node, sg, "2", ("alice", "bob", "carol", "shop"))

    tx_ok(sg.transfer(node, "alice", "bob", 40), "2: the listed sender is admitted")
    mined(node, "2: listed transfer mined")
    orc.add("alice", -(40 + BASE_FEE)); orc.add("bob", 40); orc.add("miner", BASE_FEE)
    orc.verify("listed sender paid")

    res = sg.transfer(node, "carol", "bob", 40)
    refused(res, "RECIPIENT_POLICY", "2: a stranger is refused with the recipient reason",
            transfer_index=1, recipient=sg.pk("bob"))
    check("2: the refusal names the recipient policy",
          "rejected by recipient policy (o5)" in json.dumps(res), json.dumps(res)[:200])
    dry = node.rpc("checktx estimate '" + json.dumps(
        sg.transfer_payload(node, "carol", [("bob", 40)]), separators=(",", ":")) + "'")
    refused(dry, "RECIPIENT_POLICY", "2: checktx gives the same refusal")

    res = sg.batch(node, "carol", [("shop", 5), ("bob", 5)])
    refused(res, "RECIPIENT_POLICY", "2: one refusing recipient fails the whole batch",
            transfer_index=2)
    tx_ok(sg.batch(node, "alice", [("shop", 5), ("bob", 5)]), "2: a batch both recipients accept")
    mined(node, "2: batch mined")
    # one fee step per transfer, so a batch of two pays twice
    orc.add("alice", -(10 + 2 * BASE_FEE)); orc.add("shop", 5); orc.add("bob", 5)
    orc.add("miner", 2 * BASE_FEE)

    tx_ok(sg.transfer(node, "carol", "shop", 3), "2: the stranger's other payments are untouched")
    tx_ok(sg.transfer(node, "bob", "carol", 7), "2: bob still pays anyone")
    mined(node, "2: both mined")
    orc.add("carol", -(3 + BASE_FEE) + 7); orc.add("shop", 3)
    orc.add("bob", -(7 + BASE_FEE)); orc.add("miner", 2 * BASE_FEE)
    orc.verify("end")

    probe = policy(node, sg.pk("bob"), sg.pk("alice"), 40).get("probe") or {}
    check("2: the probe accepts the listed sender", probe.get("accepts_payment") is True, probe)
    probe = policy(node, sg.pk("bob"), sg.pk("carol"), 40).get("probe") or {}
    check("2: the probe refuses the stranger", probe.get("accepts_payment") is False, probe)


def scenario_3(node, sg):
    say("3. one policy unit: outbound whitelist + inbound allow-list")
    deploy(node, sg, "dave", one_unit(sg.pk("shop"), sg.pk("alice"), 7_776_000), "3")
    orc = rig.Oracle(node, sg, "3", ("alice", "dave", "shop", "carol"))
    tx_ok(sg.transfer(node, "dave", "shop", 9), "3: dave pays the shop")
    tx_ok(sg.transfer(node, "alice", "dave", 9), "3: alice pays dave")
    mined(node, "3: both mined")
    orc.add("dave", -(9 + BASE_FEE) + 9); orc.add("shop", 9)
    orc.add("alice", -(9 + BASE_FEE)); orc.add("miner", 2 * BASE_FEE)
    res = sg.transfer(node, "dave", "carol", 9)
    check("3: dave may not pay anyone else (his own outbound rule)",
          (not ok(res)) and err_code(res) == "TX_REJECTED"
          and "sender's own policy clause" in json.dumps(res), json.dumps(res)[:200])
    res = sg.transfer(node, "carol", "dave", 9)
    refused(res, "RECIPIENT_POLICY", "3: nobody else may pay dave (his inbound rule)")
    orc.verify("end")


def scenario_4(node, sg):
    say("4. maximum hold time (#76)")
    deploy(node, sg, "erin", max_hold(0), "4a")
    orc = rig.Oracle(node, sg, "4", ("alice", "erin", "frank", "gina"))

    tx_ok(sg.transfer(node, "alice", "erin", 20), "4a: instant-only still takes a plain transfer")
    mined(node, "4a: transfer mined")
    orc.add("alice", -(20 + BASE_FEE)); orc.add("erin", 20); orc.add("miner", BASE_FEE)
    for label, kw in (("in 5 minutes", dict(at_time=int(time.time()) + 300)),
                      ("in a day", dict(at_time=int(time.time()) + 86_400)),
                      ("at a height", dict(at_height=node.height() + 50))):
        res, _rid = sg.park(node, "alice", "erin", 20, **kw)
        refused(res, "RECIPIENT_MAX_HOLD", f"4a: a park releasing {label} is refused, carrying the cap",
                max_hold_seconds=0)
        check(f"4a: the message carries the cap ({label})",
              "max_hold_seconds=0" in json.dumps(res), json.dumps(res)[:240])
    probe = policy(node, sg.pk("erin"), sg.pk("alice"), 20).get("probe") or {}
    check("4a: a wallet can read the cap before sending",
          probe.get("accepts_payment") is True and probe.get("max_hold_seconds") == 0, probe)

    deploy(node, sg, "frank", max_hold(600), "4b")
    res, short = sg.park(node, "alice", "frank", 30, at_time=int(time.time()) + 600)
    tx_ok(res, "4b: a park releasing in 10 minutes is admitted under the 600 s cap")
    mined(node, "4b: park mined")
    check("4b: the park is open", (node.retractable(short) or {}).get("status") == "open",
          node.retractable(short))
    orc.add("alice", -(30 + BASE_FEE)); orc.add("miner", BASE_FEE)
    res, _rid = sg.park(node, "alice", "frank", 30, at_time=int(time.time()) + 3_600)
    refused(res, "RECIPIENT_MAX_HOLD", "4b: a park releasing in an hour is refused, carrying the cap",
            max_hold_seconds=600)
    check("4b: the refusal reports the hold it was asked for",
          3_500 <= ((res.get("error") or {}).get("details") or {}).get("hold_seconds", 0) <= 3_600,
          json.dumps(res)[:240])
    res, _rid = sg.park(node, "alice", "frank", 30, at_height=node.height() + 3)
    refused(res, "RECIPIENT_MAX_HOLD", "4b: a cap in seconds alone takes no height release",
            max_hold_seconds=600, max_hold_blocks=0)
    probe = policy(node, sg.pk("frank"), sg.pk("alice"), 30).get("probe") or {}
    check("4b: the probe reports 600", probe.get("max_hold_seconds") == 600
          and probe.get("accepts_height_release") is False, probe)

    res, long_rid = sg.park(node, "alice", "gina", 10, at_time=int(time.time()) + 80 * 86_400)
    tx_ok(res, "4c: with no cap deployed, an 80-day park is admitted")
    res2, by_height = sg.park(node, "carol", "gina", 10, at_height=node.height() + 40)
    tx_ok(res2, "4c: and so is a height release")
    mined(node, "4c: parks mined")
    orc.add("alice", -(10 + BASE_FEE)); orc.add("miner", 2 * BASE_FEE)

    say("   frank tightens his cap to instant-only while alice's park to him is open")
    deploy(node, sg, "frank", max_hold(0), "4d")
    tx_ok(sg.retract(node, "alice", long_rid), "4d: a retract is admitted (gina, no cap)")
    res = sg.retract(node, "alice", short)
    tx_ok(res, "4d: a retract is admitted whatever the recipient's cap (frank, cap 0)")
    mined(node, "4d: retracts mined")
    check("4d: both entries retracted",
          (node.retractable(short) or {}).get("status") == "retracted"
          and (node.retractable(long_rid) or {}).get("status") == "retracted")
    orc.add("alice", 30 + 10)
    orc.add("frank", -2 * BASE_FEE); orc.add("miner", 2 * BASE_FEE)     # his two rules

    say("   erin now takes a hold of 600 seconds, or a height release at most 20 blocks ahead")
    deploy(node, sg, "erin", max_hold_either(600, 20), "4e")
    orc.add("erin", -BASE_FEE); orc.add("miner", BASE_FEE)
    res, near = sg.park(node, "alice", "erin", 15, at_height=node.height() + 10)
    tx_ok(res, "4e: a height release 10 blocks ahead is admitted under the 20-block cap")
    mined(node, "4e: park mined")
    check("4e: the park is open", (node.retractable(near) or {}).get("status") == "open",
          node.retractable(near))
    orc.add("alice", -(15 + BASE_FEE)); orc.add("miner", BASE_FEE)
    res, _rid = sg.park(node, "alice", "erin", 15, at_height=node.height() + 60)
    refused(res, "RECIPIENT_MAX_HOLD", "4e: one 60 blocks ahead is refused, carrying the cap in blocks",
            max_hold_blocks=20)
    details = (res.get("error") or {}).get("details") or {}
    check("4e: the refusal reports the hold in blocks, and no seconds",
          55 <= details.get("hold_blocks", 0) <= 60 and "max_hold_seconds" not in details,
          json.dumps(res)[:240])
    check("4e: the message carries the cap in blocks",
          "max_hold_blocks=20" in json.dumps(res), json.dumps(res)[:240])
    res, _rid = sg.park(node, "alice", "erin", 15, at_time=int(time.time()) + 3_600)
    refused(res, "RECIPIENT_MAX_HOLD", "4e: the same rule caps a timed park in seconds",
            max_hold_seconds=600)
    probe = policy(node, sg.pk("erin"), sg.pk("alice"), 15).get("probe") or {}
    check("4e: the probe reports both caps",
          probe.get("max_hold_seconds") == 600 and probe.get("max_hold_blocks") == 20
          and probe.get("accepts_height_release") is True, probe)
    tx_ok(sg.retract(node, "alice", near), "4e: alice takes the park back")
    mined(node, "4e: retract mined")
    check("4e: the park is retracted",
          (node.retractable(near) or {}).get("status") == "retracted", node.retractable(near))
    orc.add("alice", 15)
    orc.verify("end")
    return by_height


SPEND_CAP = ("always ( (i1[t]:bv[24] > { #x0f4240 }:bv[24]) ? %s : %s )." % (BLOCK, ALLOW))


def scenario_5(node, sg):
    say("5. a refusal at block apply costs nothing")
    # Admission judges against the tip, so a payment can be admitted while the
    # recipient's rule is still in the mempool. A block puts transfers ahead of
    # rule transactions, except that one sender's transactions keep their
    # sequence order: Ivan's payment follows his own rule transaction, which
    # lands behind Judy's. So her allow-list is in force when his payment is
    # applied, in the same block.
    orc = rig.Oracle(node, sg, "5", ("ivan", "judy", "hugo"))
    seq0 = node.sequence(sg.pk("ivan"))
    tx_ok(sg.submit(node, sg.rule(node, "judy", allow_list(sg.pk("hugo")))),
          "5: judy's allow-list admitted")
    time.sleep(0.2)
    tx_ok(sg.submit(node, sg.rule(node, "ivan", SPEND_CAP)), "5: a rule of ivan's own admitted")
    res = sg.transfer_at(node, "ivan", "judy", 15, seq0 + 1)
    tx_ok(res, "5: ivan's payment admitted while her rule is not yet in a block")
    tx_hash = rig.ids_of(res)
    mined(node, "5: block mined")
    check("5: judy's rule is in force",
          wait_until(lambda: policy(node, sg.pk("judy")).get("judges_incoming") is True,
                     "judges_incoming", 120))
    status = node.txstatus(tx_hash)
    check("5: the refused payment is in no block", status.get("status") != "confirmed", status)
    check("5: ivan's sequence number moved for his rule only",
          node.sequence(sg.pk("ivan")) == seq0 + 1, (node.sequence(sg.pk("ivan")), seq0))
    orc.add("judy", -BASE_FEE); orc.add("ivan", -BASE_FEE); orc.add("miner", 2 * BASE_FEE)
    orc.verify("only the two rule fees moved")
    check("5: the mempool does not keep the refused payment", node.mempool_len() == 0,
          node.mempool_len())
    tx_ok(sg.transfer(node, "hugo", "judy", 15), "5: the listed sender is paid")
    tx_ok(sg.transfer(node, "ivan", "hugo", 15), "5: ivan's next payment reuses the sequence number")
    mined(node, "5: both mined")
    orc.add("hugo", -(15 + BASE_FEE) + 15); orc.add("judy", 15)
    orc.add("ivan", -(15 + BASE_FEE)); orc.add("miner", 2 * BASE_FEE)
    orc.verify("end")


def scenario_6(node1, node2, sg, by_height):
    say("6. second node syncs from block 0 and agrees; restart keeps the flag")
    check("6: node1 passes the open height release", produce(node1, node1.height() + 2, allow_empty=True))
    target = rig.head_fingerprint(node1)
    check("6: node2 reaches node1's head",
          wait_until(lambda: rig.head_fingerprint(node2) == target, "head agreement", 600, 3.0),
          f"node1={target} node2={rig.head_fingerprint(node2)}")
    check("6: head state hash agrees", rig.head_fingerprint(node2)[1] == target[1])
    check("6: node2 reports the feature on", flag(node2) is True, flag(node2))
    pks = [sg.pk(n) for n in rig.ACTORS]
    check("6: all balances agree", all(node1.balance(p) == node2.balance(p) for p in pks))
    check("6: all sequences agree", all(node1.sequence(p) == node2.sequence(p) for p in pks))
    for name in ("bob", "dave", "erin", "frank", "judy"):
        a, b = policy(node1, sg.pk(name)), policy(node2, sg.pk(name))
        check(f"6: {name}'s receive rule agrees on both nodes",
              a == b and a.get("judges_incoming") is True, f"node1={a} node2={b}")
    res = sg.transfer(node2, "carol", "bob", 4)
    refused(res, "RECIPIENT_POLICY", "6: node2 refuses the stranger too")
    check("6: the height release to gina is still tracked on both",
          node1.retractable(by_height) == node2.retractable(by_height),
          (node1.retractable(by_height), node2.retractable(by_height)))


# --------------------------------------------------------------------------- #

def run(base, log_dir, deadline):
    base = os.path.abspath(base)
    rig.DEADLINE[0] = time.time() + deadline
    keys = json.load(open(os.path.join(base, "keys.json")))
    node1 = rig.Node("node1", base, keys, os.path.join(log_dir, "recipient-e2e-node1-run.log"),
                     mining=False)
    node2 = rig.Node("node2", base, keys, os.path.join(log_dir, "recipient-e2e-node2-run.log"),
                     mining=False)
    rig.assert_isolated(base, node1.paths() + node2.paths())
    for node in (node1, node2):
        if os.path.exists(node.db_path):
            raise SystemExit(f"REFUSING: {node.db_path} already exists; re-provision for a clean run")
    footprint = rig.main_footprint()
    atexit.register(rig.stop_all)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: sys.exit(130))

    sg = Signer(keys, node1.tree)
    try:
        node1.start()
        if not node1.wait_ready():
            say("node1 did not become ready")
            return 2
        scenario_0(node1, sg)
        scenario_1(node1, sg)
        scenario_2(node1, sg)
        scenario_3(node1, sg)
        by_height = scenario_4(node1, sg)
        scenario_5(node1, sg)

        say("restarting node1: the flag and the rules must survive")
        node1.stop()
        node1.start()
        if not node1.wait_ready():
            say("node1 did not become ready after the restart")
            return 2
        check("restart: the feature is still on", flag(node1) is True, flag(node1))
        res = sg.transfer(node1, "carol", "bob", 4)
        refused(res, "RECIPIENT_POLICY", "restart: bob's allow-list still refuses the stranger")
        tx_ok(sg.transfer(node1, "alice", "bob", 4), "restart: and still admits the listed sender")
        mined(node1, "restart: transfer mined")

        node1.peer_id = node1.peer_id or node1._peer_id()
        node2.bootstrap = [{"peer_id": node1.peer_id,
                            "addrs": [f"/ip4/127.0.0.1/tcp/{node1.p2p_port}"]}]
        node2.start()
        if not node2.wait_ready():
            say("node2 did not become ready")
            return 2
        scenario_6(node1, node2, sg, by_height)
    finally:
        rig.stop_all()

    check("main repository data/ and node.db untouched", rig.main_footprint() == footprint)
    say("")
    if rig.FAILED:
        say(f"{len(rig.FAILED)} check(s) FAILED:")
        for name in rig.FAILED:
            say(f"  - {name}")
        return 1
    say("All checks passed.")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run"])
    parser.add_argument("--dir", default=os.path.join(rig.REPO, ".local", "recipient-e2e"))
    parser.add_argument("--log-dir", default=os.path.join(rig.REPO, ".local"))
    parser.add_argument("--overlay-worktree", action="store_true",
                        help="provision: also copy uncommitted tracked edits over the exported HEAD")
    parser.add_argument("--deadline", type=int, default=3000, help="overall seconds")
    args = parser.parse_args(argv)
    os.makedirs(args.log_dir, exist_ok=True)
    if args.mode == "provision":
        return rig.provision(args.dir, args.overlay_worktree)
    rig.require_native()
    return run(args.dir, args.log_dir, args.deadline)


if __name__ == "__main__":
    raise SystemExit(main())
