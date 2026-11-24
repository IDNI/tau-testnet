#!/usr/bin/env python3
"""End-to-end recipient controls (#47 + #76) on REAL running nodes with the
native Tau engine.

tests/test_recipient_controls.py mocks the engine; this drives two live
nodes. Node A mines and is driven through its RPC port; node B runs the
same validator key and receives A's blocks, so it replays every gate
decision on its own. A third mining role is played by B itself in the
cap-tightening scenario (B mines the rule change while the park sits in
A's mempool, so A's next block refuses the park AT APPLY).

Actors: miner (validator), alice (sender A), bob (recipient R), carol
(sender B). Bob's single clause does everything at once: inbound
allow-list (alice only) + time cap 600s + height cap 10 blocks.

SCENARIOS (asserted on live admission verdicts, receipts, escrow and
state hashes)
  1. Capability reporting: getgovernance shows recipient_policy_active
     and capabilities.recipient_controls; getrecipientpolicy judges.
  2. Allow-list live: carol -> bob refused recipient_policy_block;
     alice -> bob admitted; carol -> alice (no clause) admitted.
  3. Memorable moment: alice 600s park admitted and escrowed on both
     nodes; alice 600-block park refused RECIPIENT_MAX_HOLD with
     max_hold_blocks=10; alice 10-block park admitted; alice 3600s park
     refused with max_hold_seconds=600.
  4. Guarded mode live: alice -> bob plain transfer is admitted by the
     clause (getrecipientpolicy says not blocked) but refused by the
     guarded unit in the genesis application rules (i12+i4+i16 == bob,
     final) — while the same transfer to carol passes and the 600s park
     to bob passes the guarded step.
  5. Apply-time receipt live (cap tightening): bob's cap is 600 when
     alice's 300s park is admitted to A's mempool; the park's gossip to B
     is contained by dropping it from B's mempool DB (the miner reads that
     table); bob tightens the cap to 60, B mines the change, A follows, A
     mines the park's block — the park is refused AT APPLY, and
     gettxstatus shows reason=recipient_max_hold with the receipt log
     line carrying max_hold_seconds=60; A's node log carries the same line.
  6. Follower parity: B ends with the same head hash, escrow and
     balances as A.

USAGE
    python scripts/e2e_recipient_controls.py provision --dir .local/e2e-recipient-controls
    python scripts/e2e_recipient_controls.py run --dir .local/e2e-recipient-controls

The native binding comes from $TAU_NATIVE_PATH; the nodes run under
$TAU_E2E_PYTHON (the repo venv python).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)

import e2e_authority as base  # noqa: E402

base.NETWORK_ID = "tau-e2e-recipient-controls"
ACTORS = ("miner", "alice", "bob", "carol")
FAILED: list[str] = []

AMOUNT = 100
SECONDS_CAP = 600
BLOCKS_CAP = 10
TIGHTENED_CAP = 60


def say(msg=""):
    print(f"[e2e] {msg}", flush=True)


def check(label, cond, detail=""):
    if cond:
        say(f"  PASS  {label}" + (f"  [{detail}]" if detail != "" else ""))
    else:
        FAILED.append(label)
        say(f"  FAIL  {label}  [{detail}]")
    return bool(cond)


def _hex64(value: int) -> str:
    return f"{value:016x}"


def cap_clause(allowed_pk: str, seconds_cap: int, blocks_cap: int) -> str:
    """Inbound allow-list (allowed only) + time cap + height cap, one unit."""
    return (
        "always ( (((i16[t]:bv[64] = { #x" + _hex64(1) + " }:bv[64]) || "
        "(i16[t]:bv[64] = { #x" + _hex64(2) + " }:bv[64]) || "
        "(i16[t]:bv[64] = { #x" + _hex64(3) + " }:bv[64])) && "
        "!(i3[t]:bv[384] = { #x" + allowed_pk.lower() + " }:bv[384])) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(((i16[t]:bv[64] = { #x" + _hex64(2) + " }:bv[64]) && "
        "(i17[t]:bv[64] > { #x" + _hex64(seconds_cap) + " }:bv[64])) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(((i16[t]:bv[64] = { #x" + _hex64(3) + " }:bv[64]) && "
        "(i17[t]:bv[64] > { #x" + _hex64(blocks_cap) + " }:bv[64])) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]))))."
    )


def guarded_unit(recipient_pk: str) -> str:
    """A guarded unit for the genesis application rules: vetoes a FINAL
    payment exactly when the step runs 'as' the recipient (i12 and i4
    both the recipient, context incoming-final). In the main step i12 is
    the sender, so it can only fire there for a self-transfer (already
    refused upstream); the guarded step sets i12 to the recipient, so
    this is the guarded veto. Parks (i16 2/3) never match."""
    return (
        "always ( ((i12[t]:bv[384] = { #x" + recipient_pk.lower() + " }:bv[384]) && "
        "(i4[t]:bv[384] = { #x" + recipient_pk.lower() + " }:bv[384]) && "
        "(i16[t]:bv[64] = { #x" + _hex64(1) + " }:bv[64])) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )


def provision(root: str) -> int:
    root = os.path.abspath(root)
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    base.ACTORS = ACTORS
    keys = base.make_keys()
    with open(os.path.join(root, "keys.json"), "w") as fh:
        json.dump({n: {"sk": format(k["sk"], "064x"), "pk": k["pk"]}
                   for n, k in keys.items()}, fh, indent=2)

    tree_a, tree_b = os.path.join(root, "nodeA"), os.path.join(root, "nodeB")
    say(f"Exporting the working tree into {tree_a} and {tree_b}")
    base.export_worktree(REPO, tree_a)
    base.export_worktree(REPO, tree_b)
    os.makedirs(os.path.join(tree_a, "data"), exist_ok=True)
    os.makedirs(os.path.join(tree_b, "data"), exist_ok=True)

    # Genesis application rules: the stock genesis.tau plus the guarded
    # unit for bob. The gate itself activates at genesis.
    genesis_rules = os.path.join(root, "genesis_rules.tau")
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        stock = fh.read()
    with open(genesis_rules, "w") as fh:
        fh.write(stock)
        if not stock.endswith("\n"):
            fh.write("\n")
        fh.write(guarded_unit(keys["bob"]["pk"]) + "\n")

    cmd = [base.PYTHON, "scripts/gen_genesis.py", "--base-fee", str(base.BASE_FEE),
           "--network-id", base.NETWORK_ID, "--recipient-policy-active",
           "--genesis-rules-path", genesis_rules,
           "--validator-privkey", format(keys["miner"]["sk"], "064x"),
           "--out", "data/genesis.json"]
    for name in ("alice", "bob", "carol"):
        cmd += ["--account", f"{keys[name]['pk']}:1000000"]
    subprocess.run(cmd, cwd=tree_a, check=True, capture_output=True)
    shutil.copy2(os.path.join(tree_a, "data", "genesis.json"),
                 os.path.join(tree_b, "data", "genesis.json"))
    say("Provisioned: recipient controls active from genesis, one validator.")
    return 0


class Rig:
    def __init__(self, root):
        self.root = root
        raw = json.load(open(os.path.join(root, "keys.json")))
        self.keys = {n: {"sk": int(k["sk"], 16), "pk": k["pk"]} for n, k in raw.items()}
        self.pk = {n: k["pk"] for n, k in self.keys.items()}
        self.tree_a = os.path.join(root, "nodeA")
        self.tree_b = os.path.join(root, "nodeB")
        ports = [base.free_port() for _ in range(2)]
        self.a = base.Node("A", self.tree_a, self.keys, "miner", wrapper=True,
                           rpc_port=ports[0], p2p_port=ports[0] + 8)
        self.b = base.Node("B", self.tree_b, self.keys, "miner", wrapper=True,
                           rpc_port=ports[1], p2p_port=ports[1] + 8)
        # B follows A; A also follows B (the cap-tightening scenario has B
        # mine a block A must follow).
        self.a.bootstrap = []
        self.chain = base.Chain(self.keys)

    def start_nodes(self):
        self.a.start()
        say(f"node A pid={self.a.proc.pid} rpc={self.a.rpc_port} p2p={self.a.p2p_port}")
        if not self.a.wait_ready(timeout=420):
            raise RuntimeError("node A never became ready: " + self.a.log()[-2000:])
        # A must know B's peer id to bootstrap, and vice versa; the wrapper
        # nodes discover each other via the DHT bootstrap list, so B starts
        # with A as its bootstrap peer once A is up.
        self.b.bootstrap = ([{"peer_id": self.a.peer_id,
                               "addrs": [f"/ip4/127.0.0.1/tcp/{self.a.p2p_port}"]}]
                            if self.a.peer_id else [])
        self.b.start()
        say(f"node B pid={self.b.proc.pid} rpc={self.b.rpc_port} p2p={self.b.p2p_port}")
        if not self.b.wait_ready(timeout=420):
            raise RuntimeError("node B never became ready: " + self.b.log()[-2000:])

    def drop_from_mempool(self, node, tx_hash):
        """Delete one tx from a node's mempool DB. Harness-only: the miner
        reads the mempool table, so this is how the e2e keeps a tx out of a
        block without touching consensus code."""
        import sqlite3
        db_path = os.path.join(node.tree, "data", "node.db")
        con = sqlite3.connect(db_path, timeout=10)
        try:
            cur = con.execute("DELETE FROM mempool WHERE tx_hash = ?",
                              (tx_hash,))
            con.commit()
            return cur.rowcount
        finally:
            con.close()

    def mine(self, node=None):
        node = node or self.a
        out = node.mine()
        self.chain.mined()
        return out

    def settle(self, predicate, what, tries=10):
        for _ in range(tries):
            self.mine()
            if predicate():
                return True
        say(f"  (timed out waiting for {what})")
        return predicate()

    def wait_height(self, node, height, timeout=120):
        end = time.time() + timeout
        while time.time() < end:
            try:
                if node.height() >= height:
                    return True
            except Exception:
                pass
            time.sleep(1.0)
        return node.height() >= height

    # -- reads ----------------------------------------------------------------

    def has_policy(self, who, node=None):
        res = (node or self.a).rpc(f"getruleoffers {self.pk[who]} all")
        if res.get("status") != "ok":
            return False
        return any(str(c["target_stream"]) == "5"
                   for c in res["data"].get("accepted_clauses", []))

    def clause(self, who, node=None):
        res = (node or self.a).rpc(f"getruleoffers {self.pk[who]} all")
        for c in res.get("data", {}).get("accepted_clauses", []):
            if str(c["target_stream"]) == "5":
                return c.get("clause_body") or c.get("rule_text") or ""
        return ""

    def escrow_in(self, who, node=None):
        d = (node or self.a).rpc(f"getaccountstate {self.pk[who]}")["data"]
        return int(d["escrowed_in"])

    def tx_status(self, tx_hash, node=None):
        res = (node or self.a).rpc(f"gettxstatus {tx_hash}")
        return res.get("data", {}) if res.get("status") == "ok" else {}

    # -- transactions ---------------------------------------------------------

    def send(self, node, who, ops, **kw):
        return self.chain.send(node, who, ops, **kw)

    def transfer(self, node, who, to, amount, **kw):
        return self.chain.transfer(node, who, self.pk[to], amount, **kw)

    def park(self, node, who, to, amount, *, release_at_time=None,
             release_at_height=None, fee_limit="5000"):
        from consensus.tx_signing import signing_message_bytes
        import hashlib
        extra = {"recipient_pubkey": self.pk[to], "amount": amount}
        if release_at_time is not None:
            extra["release_at_time"] = release_at_time
        if release_at_height is not None:
            extra["release_at_height"] = release_at_height
        payload = self.chain.signed(node, who, None, fee_limit=fee_limit,
                                    tx_type="retractable_transfer", **extra)
        # The park deadline must precede the release (DEADLINE_AFTER_RELEASE
        # otherwise): pull the expiry inside the release point and re-sign.
        if release_at_time is not None:
            payload["expiration_time"] = release_at_time - 60
        if release_at_height is not None:
            payload["expire_at_height"] = release_at_height
        digest = hashlib.sha256(signing_message_bytes(payload)).digest()
        payload["signature"] = base._bls().Sign(self.keys[who]["sk"], digest).hex()
        res = node.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
        if res.get("status") == "ok":
            self.chain.pending[who] = self.chain.pending.get(who, 0) + 1
        return res

    def register_clause(self, node, who, body, fee_limit="10000"):
        from tau_testnet_cli import tx as cli_tx
        seq_data = node.rpc(f"getsequence {self.pk[who]}")["data"]
        seq = int(seq_data["sequence_number"]) + self.chain.pending.get(who, 0)
        tip = int(seq_data.get("tip_height") or 0)
        payload = cli_tx.build_rule_change_request_tx(
            sender_pubkey=self.pk[who], sequence_number=seq,
            expiration_time=int(time.time()) + 3600,
            expire_at_height=tip + 2 * 1000, kind=1, rule_text=body,
            approvers={}, fee_limit=fee_limit)
        # build_rule_change_request_tx leaves signing to the caller: sign
        # with the owner's key over the canonical bytes.
        from consensus.tx_signing import signing_message_bytes
        import hashlib
        digest = hashlib.sha256(signing_message_bytes(payload)).digest()
        payload["signature"] = base._bls().Sign(self.keys[who]["sk"], digest).hex()
        res = node.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
        if res.get("status") == "ok":
            self.chain.pending[who] = self.chain.pending.get(who, 0) + 1
        return res

# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------

def _err_code(res):
    return ((res.get("error") or {}).get("code")
            or (res.get("details") or {}).get("code"))


def _recipient_policy(res):
    return ((res.get("error") or {}).get("details") or {}).get("recipient_policy") or {}


def scenario_capabilities(rig):
    say("1. Capability reporting on the live node")
    gov = rig.a.rpc("getgovernance")
    check("getgovernance is ok", gov.get("status") == "ok", gov)
    data = gov.get("data", {})
    check("recipient_policy_active at genesis",
          data.get("recipient_policy_active") is True, data)
    caps = data.get("capabilities", {}).get("recipient_controls", {})
    check("capabilities report the streams",
          caps.get("active") is True and caps.get("hold_stream") == 17
          and caps.get("context_stream") == 16, caps)
    pre = rig.a.rpc(f"getrecipientpolicy {rig.pk['bob']}")
    check("getrecipientpolicy reports neutral default before any clause",
          pre.get("data", {}).get("neutral_default") is True, pre)


def scenario_register_clause(rig):
    say("2. Bob registers one clause: allow alice only, cap 600s / 10 blocks")
    body = cap_clause(rig.pk["alice"], SECONDS_CAP, BLOCKS_CAP)
    res = rig.register_clause(rig.a, "bob", body)
    check("the rule-change request is admitted", base.ok(res), res)
    ok = rig.settle(lambda: rig.has_policy("bob"), "bob's clause to register")
    check("bob's clause is registered", ok and rig.has_policy("bob"))
    check("the registered body is the cap clause",
          "i17" in rig.clause("bob") and "i16" in rig.clause("bob"),
          rig.clause("bob")[:120])
    check("node B has the same clause",
          rig.wait_height(rig.b, rig.a.height()) and rig.has_policy("bob", rig.b))


def scenario_allowlist(rig):
    say("3. Allow-list live: carol refused, alice admitted")
    res = rig.transfer(rig.a, "carol", "bob", AMOUNT)
    check("carol -> bob refused", not base.ok(res), res)
    check("refusal is recipient_policy_block",
          _recipient_policy(res).get("reason") == "recipient_policy_block", res)
    res = rig.transfer(rig.a, "alice", "bob", AMOUNT)
    check("alice -> bob is refused only by the guarded unit (see scenario 4)",
          not base.ok(res), res)
    check("that refusal is the guarded veto",
          _recipient_policy(res).get("mode") == "guarded", res)
    res = rig.transfer(rig.a, "carol", "alice", AMOUNT)
    check("carol -> alice (no clause) admitted", base.ok(res), res)
    rig.mine()
    check("carol -> alice landed",
          rig.a.balance("alice") == 1_000_000 + AMOUNT,
          rig.a.balance("alice"))


def scenario_memorable_moment(rig):
    say("4. Memorable moment: seconds park passes, height park refused with cap")
    now = int(time.time())
    res = rig.park(rig.a, "alice", "bob", AMOUNT, release_at_time=now + SECONDS_CAP)
    check("alice 600s park admitted", base.ok(res), res)
    rig.mine()
    check("the 600s park is escrowed to bob on A",
          rig.escrow_in("bob", rig.a) == AMOUNT, rig.escrow_in("bob", rig.a))
    check("the 600s park is escrowed to bob on B",
          rig.wait_height(rig.b, rig.a.height())
          and rig.escrow_in("bob", rig.b) == AMOUNT,
          rig.escrow_in("bob", rig.b))

    height = rig.a.height()
    res = rig.park(rig.a, "alice", "bob", AMOUNT,
                   release_at_height=height + 600)
    check("alice 600-block park refused", not base.ok(res), res)
    check("refusal code is RECIPIENT_MAX_HOLD",
          _err_code(res) == "RECIPIENT_MAX_HOLD", res)
    rp = _recipient_policy(res)
    check("refusal carries max_hold_blocks=10",
          rp.get("max_hold_blocks") == BLOCKS_CAP
          and rp.get("unit") == "blocks", rp)
    res = rig.park(rig.a, "alice", "bob", AMOUNT,
                   release_at_height=height + BLOCKS_CAP)
    check("alice 10-block park admitted", base.ok(res), res)
    rig.mine()
    check("escrowed_in(bob) is now 2 parks on A",
          rig.escrow_in("bob", rig.a) == 2 * AMOUNT)
    res = rig.park(rig.a, "alice", "bob", AMOUNT, release_at_time=now + 3600)
    check("alice 3600s park refused", not base.ok(res), res)
    rp = _recipient_policy(res)
    check("refusal carries max_hold_seconds=600",
          rp.get("max_hold_seconds") == SECONDS_CAP
          and rp.get("unit") == "seconds", rp)


def scenario_guarded(rig):
    say("5. Guarded mode live: clause admits, guarded unit vetoes")
    pre = rig.a.rpc(
        f"getrecipientpolicy {rig.pk['bob']} {rig.pk['alice']} 0 seconds")
    check("clause mode alone admits alice -> bob plain",
          pre.get("data", {}).get("judged", {}).get("blocked") is False, pre)
    res = rig.transfer(rig.a, "alice", "bob", AMOUNT)
    check("alice -> bob plain refused live", not base.ok(res), res)
    check("the live refusal is the guarded veto",
          _recipient_policy(res).get("mode") == "guarded", res)
    res = rig.transfer(rig.a, "alice", "carol", AMOUNT)
    check("alice -> carol (no guarded unit) admitted", base.ok(res), res)
    rig.mine()
    check("alice -> carol landed",
          rig.a.balance("carol") == 1_000_000 - AMOUNT - base.BASE_FEE + AMOUNT,
          rig.a.balance("carol"))


def scenario_apply_receipt(rig):
    say("6. Apply-time receipt live: cap tightens between admission and apply")
    # Bob's cap is 600; alice's 300s park is admitted to A's mempool.
    now = int(time.time())
    import block as _block
    from consensus.tx_signing import signing_message_bytes
    import hashlib
    payload = rig.chain.signed(
        rig.a, "alice", None, fee_limit="5000",
        tx_type="retractable_transfer",
        recipient_pubkey=rig.pk["bob"], amount=AMOUNT,
        release_at_time=now + 300)
    payload["expiration_time"] = now + 300 - 60
    digest = hashlib.sha256(signing_message_bytes(payload)).digest()
    payload["signature"] = base._bls().Sign(rig.keys["alice"]["sk"], digest).hex()
    tx_hash = _block.compute_tx_hash(payload)
    res = rig.a.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
    check("alice 300s park admitted under cap 600", base.ok(res), res)
    if base.ok(res):
        rig.chain.pending["alice"] = rig.chain.pending.get("alice", 0) + 1
    check("the park is queued on A",
          rig.tx_status(tx_hash, rig.a).get("status") == "queued",
          rig.tx_status(tx_hash, rig.a))
    # The park gossips to B, and B's miner would take it first (fast lane)
    # and admit it under the old cap. Contain the gossip: wait until B has
    # it queued, then drop it from B's mempool DB (the miner reads that
    # table), so B's next block carries ONLY the rule change.
    end = time.time() + 60
    while time.time() < end and \
            rig.tx_status(tx_hash, rig.b).get("status") != "queued":
        time.sleep(1.0)
    check("the park gossiped to B",
          rig.tx_status(tx_hash, rig.b).get("status") == "queued",
          rig.tx_status(tx_hash, rig.b))
    dropped = rig.drop_from_mempool(rig.b, tx_hash)
    check("the park is dropped from B's mempool", dropped == 1, dropped)
    check("B no longer knows the park",
          rig.tx_status(tx_hash, rig.b).get("status") == "unknown",
          rig.tx_status(tx_hash, rig.b))
    # Bob tightens the cap to 60 — submitted to B, mined BY B, so A's
    # mempool never sees a competing block; A follows B's block.
    tight = cap_clause(rig.pk["alice"], TIGHTENED_CAP, BLOCKS_CAP)
    res = rig.register_clause(rig.b, "bob", tight)
    check("the tightening request is admitted on B", base.ok(res), res)
    rig.mine(rig.b)
    # Poll B's clause WITHOUT mining on A: A still holds the park in its
    # mempool, and an A-mine now could land the park under the old cap.
    end = time.time() + 120
    while time.time() < end and "000000000000003c" not in rig.clause("bob", rig.b):
        time.sleep(1.0)
        rig.mine(rig.b)
    check("B has the tightened cap (60s)",
          "000000000000003c" in rig.clause("bob", rig.b),
          rig.clause("bob", rig.b)[:160])
    check("A follows B to the new height",
          rig.wait_height(rig.a, rig.b.height()), (rig.a.height(), rig.b.height()))
    check("A has the tightened cap too",
          "000000000000003c" in rig.clause("bob", rig.a),
          rig.clause("bob", rig.a)[:160])
    queued = rig.tx_status(tx_hash, rig.a).get("status")
    check("the park is STILL queued on A after following (not re-admitted)",
          queued == "queued", rig.tx_status(tx_hash, rig.a))
    # A mines the park's block: apply refuses it under the tightened cap.
    mark = rig.a.log_mark()
    rig.mine(rig.a)
    status = rig.tx_status(tx_hash, rig.a)
    check("the park is rejected at apply", status.get("status") == "rejected", status)
    check("the live receipt reason is recipient_max_hold",
          status.get("reason") == "recipient_max_hold", status)
    check("the live receipt detail carries max_hold_seconds=60",
          "max_hold_seconds=60" in str(status.get("detail", "")), status)
    check("A's node log carries the apply-time line",
          "max_hold_seconds=60" in rig.a.log_since(mark), "")


def scenario_follower(rig):
    say("7. Follower parity")
    check("B reaches A's height",
          rig.wait_height(rig.b, rig.a.height()), (rig.a.height(), rig.b.height()))
    check("head hashes match",
          rig.a.head()["block_hash"] == rig.b.head()["block_hash"],
          (rig.a.head()["block_hash"], rig.b.head()["block_hash"]))
    check("escrow matches on both nodes",
          rig.escrow_in("bob", rig.a) == rig.escrow_in("bob", rig.b),
          (rig.escrow_in("bob", rig.a), rig.escrow_in("bob", rig.b)))
    check("alice balances match",
          rig.a.balance("alice") == rig.b.balance("alice"),
          (rig.a.balance("alice"), rig.b.balance("alice")))


def run(root: str) -> int:
    root = os.path.abspath(root)
    rig = Rig(root)
    t0 = time.time()
    try:
        rig.start_nodes()
        rig.mine()
        scenario_capabilities(rig)
        scenario_register_clause(rig)
        scenario_allowlist(rig)
        scenario_memorable_moment(rig)
        scenario_guarded(rig)
        scenario_apply_receipt(rig)
        scenario_follower(rig)
    except Exception:
        import traceback
        check("the run completed", False, traceback.format_exc()[-1500:])
    finally:
        for node in (rig.a, rig.b):
            try:
                code = node.stop()
                say(f"stopped node {node.name} (exit {code})")
            except Exception as exc:
                say(f"could not stop node {node.name}: {exc!r}")
    say("")
    say(f"{len(FAILED)} check(s) failed in {time.time() - t0:.0f}s" if FAILED
        else f"All checks passed in {time.time() - t0:.0f}s.")
    for name in FAILED:
        say(f"  - {name}")
    return 1 if FAILED else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run"])
    parser.add_argument("--dir", default=os.path.join(REPO, ".local", "e2e-recipient-controls"))
    args = parser.parse_args(argv)
    return provision(args.dir) if args.mode == "provision" else run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
