#!/usr/bin/env python3
"""End-to-end rule-sharing check against a REAL running node.

Unlike tests/test_rule_sharing_e2e.py (which mocks the Tau engine), this drives
a live node over its TCP RPC with the NATIVE engine, so it exercises the parts
that only exist at runtime: real rule compilation, the live interpreter, the
restore plan on restart, and actual transfer admission under an accepted policy.

It found the accumulation bug that the mocked test could not see: composites
were appended to the application-rules spec instead of being derived from the
clause registry, so the spec grew one composite per acceptance and the net
policy depended on replay order.

USAGE
    # 1. Provision an isolated node directory (its own data/, keys, genesis)
    python scripts/e2e_rule_sharing.py provision --dir /tmp/tau-e2e

    # 2. Start the node yourself, pointing at that directory, e.g.
    #      cd /tmp/tau-e2e && TAU_ENV=production TAU_FORCE_TEST=0 \
    #        TAU_MINER_PRIVKEY=$(cat miner.sk) TAU_MINER_PUBKEY=$(cat miner.pk) \
    #        TAU_MINING_ENABLED=true TAU_PORT=65500 python server.py
    #
    #    TAU_MINER_PUBKEY is required: it is NOT derived from the private key,
    #    and without it the proposer gate refuses to build blocks.

    # 3. Run the scenarios, restarting the node when prompted
    python scripts/e2e_rule_sharing.py run --dir /tmp/tau-e2e --port 65500

NATIVE ENGINE NOTE
    The node needs `tau.cpython-3XX-*.so` on PYTHONPATH matching the
    interpreter running it. If ../tau-lang was built against a different Python
    than your venv, the module is simply unimportable and the node silently
    falls back to a non-native path. Only two translation units depend on the
    Python version, so rebuilding just those against your venv is enough --
    libTAU.a can be reused.
"""
import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time

BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
ALLOW_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
ACTORS = ("miner", "alice", "bob", "carol")

FAILED = []


def say(msg):
    print(msg, flush=True)


def check(label, cond, detail=""):
    say(f"  [{'PASS' if cond else 'FAIL'}] {label}" + (f" -- {detail}" if detail else ""))
    if not cond:
        FAILED.append(label)
    return cond


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
        sk = bls.KeyGen(f"e2e-{name}".encode())
        keys[name] = {"sk": format(sk, "064x"), "pk": bls.SkToPk(sk).hex()}
        open(os.path.join(target, f"{name}.sk"), "w").write(keys[name]["sk"])
        open(os.path.join(target, f"{name}.pk"), "w").write(keys[name]["pk"])
    json.dump(keys, open(os.path.join(target, "keys.json"), "w"), indent=2)

    cmd = [
        sys.executable, "scripts/gen_genesis.py",
        "--validator-privkey", keys["miner"]["sk"],
        "--base-fee", "10", "--network-id", "tau-e2e",
        "--out", "data/genesis.json",
    ]
    for name in ("alice", "bob", "carol"):
        cmd += ["--account", f"{keys[name]['pk']}:100000"]
    subprocess.run(cmd, cwd=target, check=True)

    say("Provisioned. Start the node from that directory (see the module docstring),")
    say("then re-run this script with `run`.")
    return 0


# --------------------------------------------------------------------------- #
# rpc + tx helpers
# --------------------------------------------------------------------------- #

class Node:
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.keys = json.load(open(os.path.join(target, "keys.json")))
        sys.path.insert(0, target)
        from commands.sendtx import _get_signing_message_bytes
        from py_ecc.bls import G2Basic as bls
        self._sign_bytes = _get_signing_message_bytes
        self._bls = bls

    def rpc(self, cmd, timeout=180.0):
        s = socket.create_connection(("127.0.0.1", self.port), timeout=timeout)
        try:
            s.sendall((cmd + "\r\n").encode())
            s.shutdown(socket.SHUT_WR)
            out = []
            while True:
                b = s.recv(65536)
                if not b:
                    break
                out.append(b)
            return json.loads(b"".join(out).decode(errors="replace").strip())
        finally:
            s.close()

    def pk(self, name):
        return self.keys[name]["pk"]

    def submit(self, name, payload, expect_ok=True):
        payload["sender_pubkey"] = self.pk(name)
        seq_data = self.rpc(f"getsequence {self.pk(name)}")["data"]
        payload["sequence_number"] = seq_data["sequence_number"]
        payload["expiration_time"] = int(time.time()) + 3600
        # Height deadline, counted from the tip that came back with the
        # sequence. A request or offer that sets its own keeps it.
        payload.setdefault("expire_at_height",
                           int(seq_data.get("tip_height") or 0) + 1000)
        payload.setdefault("fee_limit", "1000")
        digest = hashlib.sha256(self._sign_bytes(payload)).digest()
        payload["signature"] = self._bls.Sign(int(self.keys[name]["sk"], 16), digest).hex()
        res = self.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
        if expect_ok and res.get("status") != "ok":
            raise RuntimeError(json.dumps(res)[:300])
        return res

    def mine(self):
        return self.rpc("createblock")

    def height(self):
        blocks = self.rpc("getblocks")["data"]["blocks"]
        return max(int(b["header"]["block_number"]) for b in blocks)

    def bal(self, name):
        return int(self.rpc(f"getbalance {self.pk(name)}")["data"]["balance"])

    def clauses(self, name):
        return self.rpc(f"getruleoffers {self.pk(name)}")["data"]["accepted_clauses"]

    def spec_units(self):
        spec = self.rpc("gettaustate")["data"]["rules_state"]
        return [u for u in spec.split("\n") if u.strip()]

    def offer_id(self, frm, to, rule, expire):
        return self.rpc("getofferid '" + json.dumps({
            "sender_pubkey": self.pk(frm), "recipient_pubkey": self.pk(to),
            "rule_text": rule, "expire_at_height": expire,
        }, separators=(",", ":")) + "'")["data"]["offer_id"]

    def offer(self, frm, to, rule, expire):
        return self.submit(frm, {
            "tx_type": "rule_offer", "recipient_pubkey": self.pk(to),
            "rule_text": rule, "expire_at_height": expire})

    def decide(self, actor, offer_id, accept, rule=None):
        p = {"tx_type": "rule_offer_accept" if accept else "rule_offer_reject",
             "offer_id": offer_id}
        if accept:
            p["rule_text"] = rule
        return self.submit(actor, p)

    def transfer(self, frm, to, amount, expect_ok=True):
        return self.submit(frm, {
            "tx_type": "user_tx",
            "operations": {"1": [[self.pk(frm), self.pk(to), str(amount)]]},
        }, expect_ok=expect_ok)

    def verdict(self, name, to="alice", amount=5):
        """'allowed' / 'blocked' by user policy.

        Asserts on the admission verdict, not a net balance: an INCOMING
        transfer in the same block silently confounds a balance comparison.
        """
        res = self.transfer(name, to, amount, expect_ok=False)
        if res.get("status") == "ok":
            return "allowed"
        return "blocked" if "user policy" in str(res.get("error", {})) else "error"

    def offer_and_accept(self, frm, to, rule):
        expire = self.height() + 1000
        oid = self.offer_id(frm, to, rule, expire)
        self.offer(frm, to, rule, expire)
        self.mine()
        self.decide(to, oid, True, rule)
        self.mine()
        return oid


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_offer_accept_isolation(n: Node):
    say("== baseline: everyone can transfer ==")
    b0, c0 = n.bal("bob"), n.bal("carol")
    n.transfer("bob", "alice", 5)
    n.transfer("carol", "alice", 7)
    n.mine()
    check("bob transfer applied", n.bal("bob") < b0)
    check("carol transfer applied", n.bal("carol") < c0)

    say("== alice offers bob a rule that blocks bob's transfers ==")
    expire = n.height() + 1000
    oid = n.offer_id("alice", "bob", BLOCK_RULE, expire)
    n.offer("alice", "bob", BLOCK_RULE, expire)
    n.mine()
    inbox = n.rpc(f"getruleoffers {n.pk('bob')} in")["data"]
    check("offer in bob's inbox", inbox["pending_incoming"] == 1)
    check("offer id matches the client-side derivation",
          inbox["incoming"][0]["offer_id"] == oid)
    detail = n.rpc(f"getruleoffer {oid}")["data"]
    check("full rule text returned", detail["rule_text"] == BLOCK_RULE)

    say("== conflict report (real engine compile) ==")
    rep = n.rpc(f"getruleconflict {oid}")["data"]
    layers = {l["layer"]: l for l in rep["layers"]}
    check("advisory", rep["advisory"] is True)
    check("compile layer ran", layers["compile"]["status"] == "ok",
          str(layers["compile"].get("detail"))[:100])
    check("satisfiability reported unavailable",
          layers["unrealizable"]["status"] == "unavailable")

    say("== bob accepts ==")
    n.decide("bob", oid, True, BLOCK_RULE)
    n.mine()
    check("bob has one clause", len(n.clauses("bob")) == 1)
    # The composite is derived from the registry, never appended.
    check("accumulation carries no composite",
          not any("i12" in u for u in n.spec_units()),
          f"{len(n.spec_units())} units")

    say("== isolation: only the acceptor is affected ==")
    vb, vc = n.verdict("bob"), n.verdict("carol")
    n.mine()
    check("bob is blocked by his accepted policy", vb == "blocked", vb)
    check("carol is unaffected", vc == "allowed", vc)


def scenario_second_acceptor(n: Node):
    say("== a second acceptor must not disturb the first ==")
    n.offer_and_accept("alice", "carol", BLOCK_RULE)
    check("accumulation still carries no composite",
          not any("i12" in u for u in n.spec_units()), f"{len(n.spec_units())} units")
    check("bob has one clause", len(n.clauses("bob")) == 1)
    check("carol has one clause", len(n.clauses("carol")) == 1)
    vb, vc, va = n.verdict("bob"), n.verdict("carol"), n.verdict("alice", to="bob")
    n.mine()
    check("bob still blocked (first acceptor preserved)", vb == "blocked", vb)
    check("carol now blocked (second acceptor applied)", vc == "blocked", vc)
    check("alice unaffected (no clause)", va == "allowed", va)

    say("== reject leaves the recipient's clause alone ==")
    expire = n.height() + 1000
    oid = n.offer_id("alice", "bob", ALLOW_RULE, expire)
    n.offer("alice", "bob", ALLOW_RULE, expire)
    n.mine()
    n.decide("bob", oid, False)
    n.mine()
    check("offer status is rejected",
          n.rpc(f"getruleoffer {oid}")["data"]["status"] == "rejected")
    body = n.clauses("bob")[0]["clause_body"]
    check("bob's clause unchanged by the rejection", "#x000000" in body, body)

    say("== accepting again replaces the acceptor's own clause ==")
    n.offer_and_accept("alice", "bob", ALLOW_RULE)
    clauses = n.clauses("bob")
    check("still exactly one clause", len(clauses) == 1)
    check("clause replaced with ALLOW", "#x000001" in clauses[0]["clause_body"])
    vb, vc = n.verdict("bob"), n.verdict("carol")
    n.mine()
    check("bob can transfer again", vb == "allowed", vb)
    check("carol still blocked (untouched)", vc == "blocked", vc)


def snapshot(n: Node, path):
    blocks = n.rpc("getblocks")["data"]["blocks"]
    tip = max(blocks, key=lambda b: int(b["header"]["block_number"]))
    snap = {
        "height": int(tip["header"]["block_number"]),
        "state_hash": tip["header"].get("state_hash"),
        "bob": n.clauses("bob"), "carol": n.clauses("carol"),
        "spec_units": len(n.spec_units()),
        "bob_bal": n.bal("bob"), "carol_bal": n.bal("carol"),
    }
    json.dump(snap, open(path, "w"))
    say(f"  snapshot: height={snap['height']} units={snap['spec_units']}")


def scenario_after_restart(n: Node, path):
    say("== after restart: the composite must be rebuilt from the registry ==")
    snap = json.load(open(path))
    blocks = n.rpc("getblocks")["data"]["blocks"]
    tip = max(blocks, key=lambda b: int(b["header"]["block_number"]))
    check("height unchanged", int(tip["header"]["block_number"]) == snap["height"])
    check("state hash unchanged", tip["header"].get("state_hash") == snap["state_hash"])
    check("balances unchanged",
          n.bal("bob") == snap["bob_bal"] and n.bal("carol") == snap["carol_bal"])
    check("bob's clause restored", n.clauses("bob") == snap["bob"])
    check("carol's clause restored", n.clauses("carol") == snap["carol"])
    check("spec did not grow across restart", len(n.spec_units()) == snap["spec_units"],
          f"{snap['spec_units']} -> {len(n.spec_units())}")
    vb, vc = n.verdict("bob"), n.verdict("carol")
    n.mine()
    check("bob's policy still enforced", vb == "allowed", vb)
    check("carol's policy still enforced", vc == "blocked", vc)


def scenario_rejections(n: Node):
    say("== malformed / unauthorized offers refused at admission ==")
    expire = n.height() + 1000
    guarded = ("always ( (i12[t]:bv[384] = { #x" + n.pk("bob")
               + " }:bv[384]) && o5[t]:bv[24] = { #x000001 }:bv[24] ).")
    cases = [
        ("writes reserved o9", "alice", "bob", "always ( o9[t]:bv[24] = { #x000001 }:bv[24] ).", expire),
        ("reads mocked i2", "alice", "bob", "always ( o5[t]:bv[24] = i2[t]:bv[24] ).", expire),
        ("two rule units", "alice", "bob", "always ( o5[t] = 1 ). always ( o5[t] = 0 ).", expire),
        ("self offer", "alice", "alice", ALLOW_RULE, expire),
        ("references i12", "alice", "bob", guarded, expire),
        ("expired window", "alice", "bob", ALLOW_RULE, 1),
    ]
    for label, frm, to, rule, exp in cases:
        try:
            n.offer(frm, to, rule, exp)
            check(f"refused: {label}", False, "was ACCEPTED")
        except RuntimeError as exc:
            check(f"refused: {label}", True, str(exc)[:60])

    say("== only the recipient may decide, and the text must match ==")
    expire = n.height() + 1000
    oid = n.offer_id("alice", "bob", ALLOW_RULE, expire)
    n.offer("alice", "bob", ALLOW_RULE, expire)
    n.mine()
    for label, actor, rule, needle in (
        ("non-recipient accept refused", "carol", ALLOW_RULE, "recipient"),
        ("altered accept text refused", "bob", BLOCK_RULE, "digest"),
    ):
        try:
            n.decide(actor, oid, True, rule)
            check(label, False, "was ACCEPTED")
        except RuntimeError as exc:
            check(label, needle in str(exc), str(exc)[:70])


def scenario_lanes(n: Node):
    say("== lanes: a transfer is not stuck behind rule work ==")
    start = n.height()
    n.offer("alice", "carol", ALLOW_RULE, n.height() + 1000)
    n.transfer("bob", "alice", 3)
    check("both queued", n.rpc("getmempool")["data"]["count"] == 2)
    # The node's own miner may claim them first, so drain rather than relying on
    # a single createblock response.
    for _ in range(40):
        if n.rpc("getmempool")["data"]["count"] == 0:
            break
        n.mine()
        time.sleep(0.5)
    per_block = {}
    for b in n.rpc("getblocks")["data"]["blocks"]:
        num = int(b["header"]["block_number"])
        if num <= start:
            continue
        for tx in (b.get("transactions") or []):
            if isinstance(tx, dict):
                per_block.setdefault(num, []).append(tx.get("tx_type", "user_tx"))
    kinds = [k for v in per_block.values() for k in v]
    check("mempool drained", n.rpc("getmempool")["data"]["count"] == 0)
    check("a rule offer and a transfer were both mined",
          "rule_offer" in kinds and "user_tx" in kinds, str(per_block))
    shared = [v for v in per_block.values() if "rule_offer" in v and "user_tx" in v]
    if shared:
        # Different senders, so lane order is observable: with one sender,
        # per-sender sequence order outranks it.
        check("transfer ordered before rule work", shared[0][0] == "user_tx", str(shared[0]))
    else:
        say(f"  [skip] landed in separate blocks: {per_block}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["provision", "run", "before-restart", "after-restart"])
    ap.add_argument("--dir", required=True, help="isolated node directory")
    ap.add_argument("--port", type=int, default=65500)
    ap.add_argument("--snapshot", default="/tmp/tau_e2e_snapshot.json")
    args = ap.parse_args()

    if args.mode == "provision":
        return provision(args.dir)

    node = Node(args.dir, args.port)
    if args.mode == "before-restart":
        snapshot(node, args.snapshot)
        return 0
    if args.mode == "after-restart":
        scenario_after_restart(node, args.snapshot)
    else:
        scenario_offer_accept_isolation(node)
        scenario_second_acceptor(node)
        scenario_rejections(node)
        scenario_lanes(node)

    say("")
    if FAILED:
        say(f"{len(FAILED)} CHECK(S) FAILED")
        for f in FAILED:
            say(f"  - {f}")
        return 1
    say("ALL CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
