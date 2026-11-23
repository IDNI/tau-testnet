#!/usr/bin/env python3
"""End-to-end recipient policy (#47, #76) against a REAL running node.

tests/test_recipient_policy.py mocks the evaluator; this drives a live node with
the NATIVE engine, so it exercises what only exists at runtime: the governance
activation itself, real clause compilation of rules that read i17, and the
admission and block-apply gates on a chain that is actually mining.

USAGE
    # 1. Provision an isolated node directory (own data/, keys, genesis)
    python scripts/e2e_recipient_policy.py provision --dir /tmp/tau-recv

    # 2. Start the node from that directory, e.g.
    #      cd /tmp/tau-recv && TAU_ENV=production TAU_FORCE_TEST=0 \
    #        TAU_MINER_PRIVKEY=$(cat miner.sk) TAU_MINER_PUBKEY=$(cat miner.pk) \
    #        TAU_MINING_ENABLED=true TAU_PORT=65511 python server.py

    # 3. Run the scenarios
    python scripts/e2e_recipient_policy.py run --dir /tmp/tau-recv --port 65511

    # 4. Start a second node from the same genesis, sync it from the miner over
    #    libp2p, and check both agree (head, state hash, balances, sequences,
    #    the activation flag)
    python scripts/e2e_recipient_policy.py follow --dir /tmp/tau-recv --port 65511 \
        --miner-identity <miner data dir>/identity.key --miner-p2p /ip4/127.0.0.1/tcp/4001

WHAT IT CHECKS
    0. getgovernance reports recipient_policy {supported: true, active: false}.
    1. Before activation a clause reading i17 is refused at deploy
       (RECIPIENT_POLICY_INACTIVE), not admitted as a rule that never runs.
    2. A governance update carrying {"recipient_policy_active": true} activates
       it; getgovernance then reports active: true.
    3. #47: bob accepts only alice. alice -> bob lands; carol -> bob is refused
       at admission with RECIPIENT_POLICY; an account with no policy is paid.
    4. #47: a batch carol -> {dave, bob} is refused whole; dave is not paid.
    5. #47: bob's one clause also restricts what bob sends (outbound + inbound).
    6. #76: erin accepts holds of at most 600 seconds. A park held 600 s lands;
       one held an hour is refused with RECIPIENT_MAX_HOLD carrying 600; a
       plain transfer to erin lands; alice may retract her open park to erin.
    (A payment admitted before its recipient's rule and refused at apply depends
    on the proposer's ordering within a block; it is pinned deterministically by
    test_a_rule_earlier_in_the_block_refuses_a_payment_admitted_before_it.)

ASSERTION DISCIPLINE
    Assert on the admission verdict or on whether a tx reached the chain, never
    on a net balance alone: the node's own miner races every explicit mine.
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

ACTORS = ("miner", "alice", "bob", "carol", "dave", "erin")
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
        sk = bls.KeyGen(f"recv-e2e-{name}".encode())
        keys[name] = {"sk": format(sk, "064x"), "pk": bls.SkToPk(sk).hex()}
        open(os.path.join(target, f"{name}.sk"), "w").write(keys[name]["sk"])
        open(os.path.join(target, f"{name}.pk"), "w").write(keys[name]["pk"])
    json.dump(keys, open(os.path.join(target, "keys.json"), "w"), indent=2)

    cmd = [
        sys.executable, "scripts/gen_genesis.py",
        "--validator-privkey", keys["miner"]["sk"],
        "--base-fee", "10", "--network-id", "tau-recv-e2e",
        "--out", "data/genesis.json",
    ]
    for name in ACTORS[1:]:
        cmd += ["--account", f"{keys[name]['pk']}:1000000"]
    subprocess.run(cmd, cwd=target, check=True)
    say("Provisioned. Recipient policy starts INACTIVE; the run activates it "
        "by governance.")
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
        from consensus.serialization import compute_update_id
        from py_ecc.bls import G2Basic as bls

        self._sign_bytes = signing_message_bytes
        self._update_id = compute_update_id
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

    def submit(self, name, payload):
        payload["sender_pubkey"] = self.pk(name)
        seq_data = self.rpc(f"getsequence {self.pk(name)}")["data"]
        payload["sequence_number"] = seq_data["sequence_number"]
        payload.setdefault("expiration_time", int(time.time()) + 3600)
        payload.setdefault("expire_at_height", int(seq_data.get("tip_height") or 0) + 1000)
        payload.setdefault("fee_limit", "10000")
        digest = hashlib.sha256(self._sign_bytes(payload)).digest()
        payload["signature"] = self._bls.Sign(int(self.keys[name]["sk"], 16), digest).hex()
        return self.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")

    def mine(self, tries=8):
        last = None
        for _ in range(tries):
            last = self.rpc("createblock")
            err = (last.get("error") or {})
            msg = str(err.get("code", "")) + str(err.get("message", "")) + str(last.get("message", ""))
            if "BUSY" not in msg.upper():
                return last
            time.sleep(3)
        return last

    def wait_for(self, predicate, what, tries=25, delay=3.0):
        for _ in range(tries):
            if predicate():
                return True
            self.mine()
            time.sleep(delay)
        say(f"  (timed out waiting for {what})")
        return predicate()

    def governance(self):
        return self.rpc("getgovernance")["data"]

    def balance(self, name):
        return int(self.rpc(f"getbalance {self.pk(name)}")["data"]["balance"])

    def tx_landed(self, res):
        tx_hash = (res.get("data") or {}).get("tx_hash")
        if not tx_hash:
            return False

        def _done():
            st = self.rpc(f"gettxstatus {tx_hash}").get("data") or {}
            return st.get("status") in ("confirmed", "included", "accepted")
        return self.wait_for(_done, f"tx {tx_hash[:12]} to land")

    # -- rules ------------------------------------------------------------------

    @staticmethod
    def _key(pk):
        return "{ #x" + pk + " }:bv[384]"

    def allow_only(self, payer):
        """Accept incoming money only from <payer>; outbound unaffected."""
        return (
            "always ( ((i17[t]:bv[64] > { #x0000000000000000 }:bv[64]) && "
            f"!(i3[t]:bv[384] = {self._key(self.pk(payer))})) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
        )

    def both_ways(self, payer, payee):
        """Receive only from <payer>, send only to <payee>, in one clause."""
        return (
            "always ( (((i17[t]:bv[64] = { #x0000000000000000 }:bv[64]) && "
            f"!(i4[t]:bv[384] = {self._key(self.pk(payee))})) || "
            "((i17[t]:bv[64] > { #x0000000000000000 }:bv[64]) && "
            f"!(i3[t]:bv[384] = {self._key(self.pk(payer))}))) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
        )

    @staticmethod
    def hold_cap(seconds):
        return (
            f"always ( (i17[t]:bv[64] > {{ #x{format(1 + seconds, '016x')} }}:bv[64]) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
        )

    def deploy(self, name, rule):
        return self.submit(name, {"tx_type": "user_tx", "operations": {"0": rule}})

    def pay(self, name, *to_amounts):
        ops = [[self.pk(name), self.pk(to), str(amount)] for to, amount in to_amounts]
        return self.submit(name, {"tx_type": "user_tx", "operations": {"1": ops}})

    def park(self, name, to, amount, hold_seconds):
        release = int(time.time()) + hold_seconds
        return self.submit(name, {
            "tx_type": "retractable_transfer",
            "recipient_pubkey": self.pk(to),
            "amount": amount,
            "release_at_time": release,
            "expiration_time": int(time.time()) + min(300, hold_seconds - 30),
        })

    # -- governance -------------------------------------------------------------

    def activate(self):
        gov = self.governance()
        rules = [gov["consensus_rules"]]
        # Leave room for the update and the vote to land before the activation
        # height; an update whose height passes without a quorum is archived.
        activate_at = int(gov["next_block_height"]) + int(gov["active_validator_count"]) + 15
        patch = {"recipient_policy_active": True}
        uid = self._update_id(rules, activate_at, patch).hex()
        upd = self.submit("miner", {
            "tx_type": "consensus_rule_update", "fee_limit": "0",
            "rule_revisions": rules, "activate_at_height": activate_at,
            "host_contract_patch": patch,
        })
        check("governance update with recipient_policy_active admitted",
              upd.get("status") == "ok", json.dumps(upd)[:300])
        self.wait_for(lambda: uid in [u.get("update_id") for u in self.governance()["pending_updates"]],
                      "the update to land")
        # getgovernance can list the update a moment before vote admission
        # knows it; retry the vote while it reports the id as unknown.
        vote = {}
        for _ in range(10):
            vote = self.submit("miner", {
                "tx_type": "consensus_rule_vote", "fee_limit": "0",
                "update_id": uid, "approve": True,
            })
            if vote.get("status") == "ok" or "unknown update_id" not in json.dumps(vote):
                break
            self.mine()
            time.sleep(3)
        check("validator vote admitted", vote.get("status") == "ok", json.dumps(vote)[:300])
        # The node mines only when the mempool has work, so drive the height to
        # the activation block with small transfers between accounts that have
        # no policy.
        def _active():
            if self.governance()["recipient_policy"]["active"] is True:
                return True
            self.pay("dave", ("carol", 1))
            return False
        return self.wait_for(_active, "recipient policy to activate", tries=60)


def _code(res):
    err = res.get("error") or {}
    return err.get("code") or res.get("code") or ""


def _text(res):
    return json.dumps(res)


def run(target, port) -> int:
    n = Node(target, port)

    say("0. capability report")
    rp = n.governance().get("recipient_policy") or {}
    check("node reports recipient policy supported", rp.get("supported") is True, rp)
    check("node reports recipient policy inactive at genesis", rp.get("active") is False, rp)

    say("1. an inbound rule before activation")
    res = n.deploy("bob", n.allow_only("alice"))
    check("clause reading i17 refused at deploy while inactive",
          _code(res) == "RECIPIENT_POLICY_INACTIVE", _text(res)[:300])

    say("2. activation by governance")
    check("recipient policy active after the governance update", n.activate())

    say("3. #47 inbound allow-list")
    check("bob deploys 'accept only alice'", n.deploy("bob", n.allow_only("alice")).get("status") == "ok")
    n.wait_for(lambda: not (n.rpc("getmempool")["data"].get("transactions") or []), "the rule to land")
    ok = n.pay("alice", ("bob", 25))
    check("alice -> bob admitted", ok.get("status") == "ok", _text(ok)[:300])
    check("alice -> bob reaches the chain", n.tx_landed(ok))
    bad = n.pay("carol", ("bob", 25))
    check("carol -> bob refused with RECIPIENT_POLICY",
          _code(bad) == "RECIPIENT_POLICY", _text(bad)[:300])
    free = n.pay("carol", ("dave", 25))
    check("carol -> dave (no policy) admitted", free.get("status") == "ok", _text(free)[:300])
    check("carol -> dave reaches the chain", n.tx_landed(free))

    say("4. #47 batch atomicity")
    batch = n.pay("carol", ("dave", 5), ("bob", 5))
    check("carol -> {dave, bob} refused as one transaction",
          _code(batch) == "RECIPIENT_POLICY" and "#2" in _text(batch), _text(batch)[:300])

    say("5. #47 one clause, both directions")
    check("bob deploys 'receive only from alice, send only to dave'",
          n.deploy("bob", n.both_ways("alice", "dave")).get("status") == "ok")
    n.wait_for(lambda: not (n.rpc("getmempool")["data"].get("transactions") or []), "the rule to land")
    out_ok = n.pay("bob", ("dave", 3))
    check("bob -> dave admitted (outbound rule allows)", out_ok.get("status") == "ok", _text(out_ok)[:300])
    n.tx_landed(out_ok)
    out_bad = n.pay("bob", ("carol", 3))
    check("bob -> carol refused by bob's own outbound rule",
          out_bad.get("status") != "ok" and _code(out_bad) != "RECIPIENT_POLICY", _text(out_bad)[:300])
    in_bad = n.pay("carol", ("bob", 3))
    check("carol -> bob still refused by the inbound rule",
          _code(in_bad) == "RECIPIENT_POLICY", _text(in_bad)[:300])

    say("6. #76 hold cap of 600 seconds")
    check("erin deploys 'holds of at most 600 seconds'", n.deploy("erin", n.hold_cap(600)).get("status") == "ok")
    n.wait_for(lambda: not (n.rpc("getmempool")["data"].get("transactions") or []), "the rule to land")
    plain = n.pay("alice", ("erin", 10))
    check("plain transfer to erin admitted", plain.get("status") == "ok", _text(plain)[:300])
    n.tx_landed(plain)
    short = n.park("alice", "erin", 10, 590)
    check("park held ~10 minutes admitted", short.get("status") == "ok", _text(short)[:300])
    long_ = n.park("alice", "erin", 10, 3600)
    check("park held an hour refused with RECIPIENT_MAX_HOLD",
          _code(long_) == "RECIPIENT_MAX_HOLD", _text(long_)[:300])
    check("the refusal carries erin's cap (600)",
          "600" in _text(long_) and "at most 600 seconds" in _text(long_), _text(long_)[:300])
    if short.get("status") == "ok":
        n.tx_landed(short)
        rid = (short.get("data") or {}).get("retractable_id") or ""
        if rid:
            retract = n.submit("alice", {"tx_type": "retract_transfer", "retractable_id": rid})
            check("alice's retract of the open park is admitted",
                  retract.get("status") == "ok", _text(retract)[:300])

    say("")
    if FAILED:
        say(f"{len(FAILED)} check(s) FAILED: {FAILED}")
        return 1
    say("ALL CHECKS PASSED")
    return 0


def follow(target, port, miner_identity, miner_p2p, follower_port=65521,
           follower_p2p="/ip4/127.0.0.1/tcp/4012") -> int:
    from network.libp2p_compat import keypair_from_seed
    from libp2p.peer.id import ID

    n = Node(target, port)
    peer = str(ID.from_pubkey(keypair_from_seed(open(miner_identity, "rb").read()).public_key))
    data = os.path.join(target, "follower")
    os.makedirs(data, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "TAU_ENV": "production", "TAU_FORCE_TEST": "0", "TAU_MINING_ENABLED": "false",
        "TAU_PORT": str(follower_port), "TAU_HOST": "127.0.0.1",
        "TAU_DATA_DIR": data, "TAU_DB_PATH": os.path.join(data, "node.db"),
        "TAU_IDENTITY_KEY_PATH": os.path.join(data, "identity.key"),
        "TAU_PEERSTORE_PATH": os.path.join(data, "peerstore"),
        "TAU_NETWORK_LISTEN": follower_p2p,
        "TAU_BOOTSTRAP_PEERS": json.dumps([{"peer_id": peer, "addrs": [miner_p2p]}]),
        "TAU_DHT_BOOTSTRAP": "[]",
    })
    env.pop("TAU_MINER_PRIVKEY", None)
    log = open(os.path.join(data, "follower.log"), "w")
    proc = subprocess.Popen([sys.executable, "server.py"], cwd=target, env=env,
                            stdout=log, stderr=log)
    f = Node(target, follower_port)

    def head(node):
        blocks = node.rpc("getblocks")["data"].get("blocks") or []
        top = max(blocks, key=lambda b: int(b["header"]["block_number"]))
        return (int(top["header"]["block_number"]), top["block_hash"],
                top["header"].get("state_hash"))

    try:
        target_head = head(n)
        say(f"miner head {target_head}")
        synced = False
        for _ in range(120):
            time.sleep(5)
            try:
                if head(f) == target_head:
                    synced = True
                    break
            except Exception:
                continue
        check("follower reaches the miner's head (height, hash, state hash)", synced)
        for name in ACTORS:
            pk = n.pk(name)
            a = (n.rpc(f"getbalance {pk}")["data"]["balance"],
                 n.rpc(f"getsequence {pk}")["data"]["sequence_number"])
            b = (f.rpc(f"getbalance {pk}")["data"]["balance"],
                 f.rpc(f"getsequence {pk}")["data"]["sequence_number"])
            check(f"{name}: balance and sequence agree", a == b, f"miner={a} follower={b}")
        check("recipient policy active on both nodes",
              n.governance()["recipient_policy"]["active"] is True
              and f.governance()["recipient_policy"]["active"] is True)
    finally:
        proc.terminate()
    if FAILED:
        say(f"{len(FAILED)} check(s) FAILED: {FAILED}")
        return 1
    say("BOTH NODES AGREE")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("provision")
    p.add_argument("--dir", required=True)
    r = sub.add_parser("run")
    r.add_argument("--dir", required=True)
    r.add_argument("--port", type=int, default=65511)
    fo = sub.add_parser("follow")
    fo.add_argument("--dir", required=True)
    fo.add_argument("--port", type=int, default=65511)
    fo.add_argument("--miner-identity", required=True)
    fo.add_argument("--miner-p2p", default="/ip4/127.0.0.1/tcp/4001")
    args = ap.parse_args()
    if args.cmd == "provision":
        return provision(args.dir)
    if args.cmd == "follow":
        return follow(args.dir, args.port, args.miner_identity, args.miner_p2p)
    return run(args.dir, args.port)


if __name__ == "__main__":
    sys.exit(main())
