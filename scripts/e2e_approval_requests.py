#!/usr/bin/env python3
"""End-to-end co-signature approvals against a REAL running node.

tests/test_approval_apply.py mocks the engine; this drives a live node with the
NATIVE one, so it exercises what only exists at runtime: real clause
compilation, the derived composite in the live interpreter, the restore plan
after a restart, and a parked transfer actually being released.

WHAT IT ASSERTS THAT A UNIT TEST CANNOT
    Inbox scoping in BOTH directions. A 2,000-coin transfer must reach the auth
    bot AND leave the scanner's and the partner's inboxes EMPTY. Checking only
    that the right approver was notified would pass just as happily if everyone
    saw everything, which is the failure mode that matters here: an approver
    being asked to sign things that are none of their business.

USAGE
    # 1. Provision an isolated node directory (own data/, keys, genesis with
    #    approval slots active from block 0)
    python scripts/e2e_approval_requests.py provision --dir /tmp/tau-appr

    # 2. Start the node from that directory, e.g.
    #      cd /tmp/tau-appr && TAU_ENV=production TAU_FORCE_TEST=0 \
    #        TAU_MINER_PRIVKEY=$(cat miner.sk) TAU_MINER_PUBKEY=$(cat miner.pk) \
    #        TAU_MINING_ENABLED=true TAU_PORT=65501 python server.py
    #
    #    TAU_MINER_PUBKEY is required and is NOT derived from the private key;
    #    without it the proposer gate refuses to build blocks.

    # 3. Run the scenarios
    python scripts/e2e_approval_requests.py run --dir /tmp/tau-appr --port 65501

ASSERTION DISCIPLINE
    Assert on the admission verdict or the request's terminal status, never on a
    net balance: an incoming transfer in the same block silently confounds a
    balance comparison. That mistake was made three times while writing the
    rule-sharing e2e.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

ACTORS = ("miner", "alice", "bob", "authbot", "scanbot", "partner")

# The tiers the e2e policy encodes.
TIER_1, TIER_2, TIER_3 = 1000, 10000, 100000

FAILED: list[str] = []


def say(msg):
    print(f"[e2e] {msg}", flush=True)


def check(label, condition, detail=""):
    if condition:
        say(f"  PASS  {label}")
    else:
        FAILED.append(label)
        say(f"  FAIL  {label} {detail}")
    return condition


# --------------------------------------------------------------------------- #
# provisioning
# --------------------------------------------------------------------------- #

def provision(target: str) -> int:
    from py_ecc.bls import G2Basic as bls

    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.makedirs(target, exist_ok=True)
    say(f"Exporting the working tree into {target}")
    subprocess.run(
        f"git -C {repo} archive HEAD | tar -x -C {target}", shell=True, check=True
    )
    os.makedirs(os.path.join(target, "data"), exist_ok=True)

    keys = {}
    for name in ACTORS:
        sk = bls.KeyGen(f"appr-e2e-{name}".encode())
        keys[name] = {"sk": format(sk, "064x"), "pk": bls.SkToPk(sk).hex()}
        open(os.path.join(target, f"{name}.sk"), "w").write(keys[name]["sk"])
        open(os.path.join(target, f"{name}.pk"), "w").write(keys[name]["pk"])
    json.dump(keys, open(os.path.join(target, "keys.json"), "w"), indent=2)

    cmd = [
        sys.executable, "scripts/gen_genesis.py",
        "--validator-privkey", keys["miner"]["sk"],
        "--base-fee", "10", "--network-id", "tau-appr-e2e",
        # Fresh chain, so the slots are reserved from block 0: nothing to audit,
        # nothing that can halt, no legacy o5 writers to reason about.
        "--approval-slots",
        "--out", "data/genesis.json",
    ]
    for name in ("alice", "bob", "authbot", "scanbot", "partner"):
        cmd += ["--account", f"{keys[name]['pk']}:1000000"]
    subprocess.run(cmd, cwd=target, check=True)

    say("Provisioned with approval slots active from genesis.")
    say("Start the node from that directory (see the module docstring), then run"
        " this script with `run`.")
    return 0


# --------------------------------------------------------------------------- #
# node client
# --------------------------------------------------------------------------- #

class Node:
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.keys = json.load(open(os.path.join(target, "keys.json")))
        sys.path.insert(0, target)
        from consensus.tx_signing import signing_message_bytes
        from py_ecc.bls import G2Basic as bls

        self._sign_bytes = signing_message_bytes
        self._bls = bls

    def rpc(self, cmd, timeout=180.0):
        sock = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            sock.sendall((cmd + "\r\n").encode())
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                buf = sock.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
            return json.loads(b"".join(chunks).decode(errors="replace").strip())
        finally:
            sock.close()

    def pk(self, name):
        return self.keys[name]["pk"]

    def submit(self, name, payload, expect_ok=True):
        payload["sender_pubkey"] = self.pk(name)
        payload["sequence_number"] = self.rpc(
            f"getsequence {self.pk(name)}")["data"]["sequence_number"]
        payload["expiration_time"] = int(time.time()) + 3600
        payload.setdefault("fee_limit", "10000")
        digest = hashlib.sha256(self._sign_bytes(payload)).digest()
        payload["signature"] = self._bls.Sign(
            int(self.keys[name]["sk"], 16), digest).hex()
        res = self.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
        if expect_ok and res.get("status") != "ok":
            raise RuntimeError(json.dumps(res)[:400])
        return res

    def mine(self):
        return self.rpc("createblock")

    def height(self):
        blocks = self.rpc("getblocks")["data"].get("blocks") or []
        return max((int(b["header"]["block_number"]) for b in blocks), default=0)

    def inbox(self, name):
        data = self.rpc(f"getapprovalrequests {self.pk(name)} in")["data"]
        return data.get("incoming") or []

    def request_row(self, request_id):
        res = self.rpc(f"getapprovalrequest {request_id}")
        return res["data"] if res.get("status") == "ok" else None

    def clauses(self):
        return self.rpc(f"getapprovalslots {self.pk('alice')}")["data"]

    # -- the policy ---------------------------------------------------------

    def tier_clause(self):
        """Alice's policy, in the flat disjunction form the node composes."""
        def bv24(n):
            return "{ #x%s }:bv[24]" % format(n, "06x")

        def bv384(h):
            return "{ #x%s }:bv[384]" % h

        return (
            "always ( ( (i1[t]:bv[24] > %s && !(i20[t]:bv[384] = %s))"
            " || (i1[t]:bv[24] > %s && !(i19[t]:bv[384] = %s))"
            " || (i1[t]:bv[24] > %s && !(i18[t]:bv[384] = %s)) )"
            " ? (o5[t]:bv[24] = { #x000000 }:bv[24])"
            " : (o5[t]:bv[24] = { #x000001 }:bv[24]) )." % (
                bv24(TIER_3), bv384(self.pk("partner")),
                bv24(TIER_2), bv384(self.pk("scanbot")),
                bv24(TIER_1), bv384(self.pk("authbot")),
            )
        )

    def deploy_policy(self):
        return self.submit("alice", {"tx_type": "user_tx",
                                     "operations": {"0": self.tier_clause()}})

    def request(self, amount, approvers, expire_in=500, customs=None):
        payload = {
            "tx_type": "approval_request",
            "recipient_pubkey": self.pk("bob"),
            "amount": amount,
            "expire_at_height": self.height() + expire_in,
            "approvers": {str(k): v for k, v in approvers.items()},
            "custom_inputs": customs or {},
        }
        res = self.submit("alice", payload)
        return res, payload

    def vote(self, name, request_id, approve=True, reason=""):
        payload = {"tx_type": "transfer_vote", "request_id": request_id,
                   "approve": approve}
        if reason:
            payload["reason"] = reason
        return self.submit(name, payload)

    def transfer(self, amount, expect_ok=False):
        """A PLAIN transfer, to prove the policy gates it without votes."""
        return self.submit("alice", {
            "tx_type": "user_tx",
            "operations": {"1": [[self.pk("alice"), self.pk("bob"), str(amount)]]},
        }, expect_ok=expect_ok)


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_policy(node):
    say("Deploying Alice's tiered policy")
    node.deploy_policy()
    node.mine()
    slots = node.clauses()
    check("policy registered as a clause", slots.get("has_clause") is True, slots)
    check("slots readable: 18=auth 19=scan 20=partner",
          slots.get("slots", {}).get("18") == node.pk("authbot")
          and slots.get("slots", {}).get("19") == node.pk("scanbot")
          and slots.get("slots", {}).get("20") == node.pk("partner"), slots)


def scenario_below_tier_one(node):
    say(f"A transfer of {TIER_1 - 500} needs nobody")
    res = node.transfer(TIER_1 - 500, expect_ok=True)
    check("below tier 1 is admitted as an ordinary transfer",
          res.get("status") == "ok", json.dumps(res)[:200])
    node.mine()
    for who in ("authbot", "scanbot", "partner"):
        check(f"{who} inbox empty", node.inbox(who) == [])


def scenario_tier_one(node):
    amount = TIER_1 + 1000
    say(f"A transfer of {amount} needs the auth bot only")

    blocked = node.transfer(amount, expect_ok=False)
    check("a plain transfer over tier 1 is refused by the sender's own policy",
          blocked.get("status") == "error", json.dumps(blocked)[:200])

    _res, payload = node.request(amount, {18: node.pk("authbot")})
    node.mine()
    rid = node.rpc("getrequestid '" + json.dumps({
        "sender_pubkey": node.pk("alice"),
        "recipient_pubkey": payload["recipient_pubkey"],
        "amount": payload["amount"],
        "sequence_number": payload["sequence_number"],
        "expire_at_height": payload["expire_at_height"],
        "approvers": payload["approvers"],
        "custom_inputs": payload["custom_inputs"],
    }) + "'")["data"]["request_id"]

    check("auth bot is notified", len(node.inbox("authbot")) == 1)
    # The point of the whole tier-scoping design.
    check("scanner is NOT notified", node.inbox("scanbot") == [])
    check("partner is NOT notified", node.inbox("partner") == [])

    node.vote("authbot", rid, approve=True)
    node.mine()
    row = node.request_row(rid)
    check("released by the auth bot alone",
          (row or {}).get("status") == "executed", json.dumps(row)[:200])


def scenario_tier_two(node):
    amount = TIER_2 + 1000
    say(f"A transfer of {amount} needs auth AND scanner")
    _res, payload = node.request(
        amount, {18: node.pk("authbot"), 19: node.pk("scanbot")})
    node.mine()
    rid = _request_id(node, payload)

    check("auth bot notified", len(node.inbox("authbot")) == 1)
    check("scanner notified", len(node.inbox("scanbot")) == 1)
    check("partner still NOT notified", node.inbox("partner") == [])

    node.vote("authbot", rid, approve=True)
    node.mine()
    row = node.request_row(rid)
    check("one signature is not enough at tier 2",
          (row or {}).get("status") == "open", json.dumps(row)[:200])

    node.vote("scanbot", rid, approve=True)
    node.mine()
    row = node.request_row(rid)
    check("released once the scanner signs too",
          (row or {}).get("status") == "executed", json.dumps(row)[:200])


def scenario_tier_three_and_decline(node):
    amount = TIER_3 + 1000
    say(f"A transfer of {amount} needs all three; the partner declines")
    _res, payload = node.request(amount, {
        18: node.pk("authbot"), 19: node.pk("scanbot"), 20: node.pk("partner")})
    node.mine()
    rid = _request_id(node, payload)
    for who in ("authbot", "scanbot", "partner"):
        check(f"{who} notified at tier 3", len(node.inbox(who)) == 1)

    node.vote("authbot", rid, approve=True)
    node.vote("scanbot", rid, approve=True)
    node.mine()
    node.vote("partner", rid, approve=False, reason="not this quarter")
    node.mine()
    row = node.request_row(rid)
    check("a needed approver's decline leaves it unreleased",
          (row or {}).get("status") == "failed", json.dumps(row)[:200])


def scenario_over_declared_approver_cannot_veto(node):
    amount = TIER_1 + 1000
    say("An over-declared approver declines; the transfer should still go")
    _res, payload = node.request(amount, {
        18: node.pk("authbot"), 19: node.pk("scanbot")})
    node.mine()
    rid = _request_id(node, payload)

    node.vote("scanbot", rid, approve=False, reason="not my business")
    node.mine()
    row = node.request_row(rid)
    check("a decline from an unneeded approver does not resolve it",
          (row or {}).get("status") == "open", json.dumps(row)[:200])

    node.vote("authbot", rid, approve=True)
    node.mine()
    row = node.request_row(rid)
    check("the needed approver still releases it",
          (row or {}).get("status") == "executed", json.dumps(row)[:200])


def scenario_custom_input_reaches_the_approver(node):
    say("The sender's comment reaches the partner")
    _res, payload = node.request(
        TIER_1 + 1, {18: node.pk("authbot")}, customs={26: "rent for Q3"})
    node.mine()
    inbox = node.inbox("authbot")
    check("comment visible to the approver",
          any((r.get("custom_inputs") or {}).get("26") == "rent for Q3"
              for r in inbox), json.dumps(inbox)[:200])


def scenario_preview(node):
    say("The advisory preview picks the minimal approver set")
    for amount, expected in ((TIER_1 - 500, []), (TIER_1 + 1, ["18"]),
                             (TIER_2 + 1, ["18", "19"])):
        draft = json.dumps({
            "sender_pubkey": node.pk("alice"),
            "recipient_pubkey": node.pk("bob"),
            "amount": amount,
            "approvers": {"18": node.pk("authbot"), "19": node.pk("scanbot"),
                          "20": node.pk("partner")},
        })
        res = node.rpc("getapprovalpreview '" + draft + "'")
        data = res.get("data") or {}
        got = sorted(str(s) for s in (data.get("required_slots") or []))
        check(f"preview for {amount} -> {expected}", got == expected,
              json.dumps(data)[:200])


def _request_id(node, payload):
    return node.rpc("getrequestid '" + json.dumps({
        "sender_pubkey": node.pk("alice"),
        "recipient_pubkey": payload["recipient_pubkey"],
        "amount": payload["amount"],
        "sequence_number": payload["sequence_number"],
        "expire_at_height": payload["expire_at_height"],
        "approvers": payload["approvers"],
        "custom_inputs": payload["custom_inputs"],
    }) + "'")["data"]["request_id"]


def snapshot(node, path):
    state = {
        "height": node.height(),
        "slots": node.clauses(),
        "alice_out": node.rpc(
            f"getapprovalrequests {node.pk('alice')} out")["data"].get("outgoing"),
        "spec_units": node.rpc("gettaustate")["data"].get("rules", "").count("always"),
    }
    json.dump(state, open(path, "w"), indent=2)
    say(f"Snapshot written to {path}; restart the node, then run `after-restart`.")
    return 0


def scenario_after_restart(node, path):
    before = json.load(open(path))
    say("Comparing state after the restart")
    check("policy clause survived", node.clauses() == before["slots"])
    check("spec unit count unchanged",
          node.rpc("gettaustate")["data"].get("rules", "").count("always")
          == before["spec_units"])
    after_out = node.rpc(
        f"getapprovalrequests {node.pk('alice')} out")["data"].get("outgoing")
    check("request history survived", after_out == before["alice_out"])
    return 0


# --------------------------------------------------------------------------- #

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run", "before-restart",
                                         "after-restart"])
    parser.add_argument("--dir", default="/tmp/tau-appr")
    parser.add_argument("--port", type=int, default=65501)
    parser.add_argument("--snapshot", default="/tmp/tau_appr_snapshot.json")
    args = parser.parse_args(argv)

    if args.mode == "provision":
        return provision(args.dir)

    node = Node(args.dir, args.port)

    if args.mode == "before-restart":
        return snapshot(node, args.snapshot)
    if args.mode == "after-restart":
        rc = scenario_after_restart(node, args.snapshot)
        return 1 if FAILED else rc

    scenario_policy(node)
    scenario_below_tier_one(node)
    scenario_tier_one(node)
    scenario_tier_two(node)
    scenario_tier_three_and_decline(node)
    scenario_over_declared_approver_cannot_veto(node)
    scenario_custom_input_reaches_the_approver(node)
    scenario_preview(node)

    say("")
    if FAILED:
        say(f"{len(FAILED)} check(s) FAILED:")
        for name in FAILED:
            say(f"  - {name}")
        return 1
    say("All checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
