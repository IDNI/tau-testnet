#!/usr/bin/env python3
"""Step 6: the worker-backed authority on real, disposable nodes.

Everything runs against processes this script starts and owns: two nodes (A and
B, both validators of a genesis made here), each in its own exported tree with
its own data/, database, identity, ports and logs. Nothing reads or writes any
other node's state, and cleanup stops exactly the processes started here.

    python scripts/e2e_authority.py run --dir <scratch>/e2e
    python scripts/e2e_authority.py unpatched --dir <scratch>/e2e-main --ref main

`run` drives the fifteen-step acceptance sequence; `unpatched` reproduces the
original incident on a tree without the fix, for the before/after record. Both
write `report.json` in --dir. Node A runs through scripts/e2e_authority_node.py
-- the production server with failures injectable from outside.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import threading
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

NATIVE = os.environ.get(
    "TAU_NATIVE_PATH",
    "/Users/ak/idni/tau-lang/build-Release/bindings/python/nanobind")
PYTHON = os.environ.get("TAU_E2E_PYTHON", sys.executable)
NETWORK_ID = "tau-e2e-authority"
ACTORS = ("minerA", "minerB", "alice", "bob", "carol", "dave", "erin", "inf")

RESULTS = []
EVIDENCE = {}


def say(msg=""):
    print(msg, flush=True)


def check(step, label, cond, detail=""):
    RESULTS.append({"step": step, "check": label, "ok": bool(cond),
                    "detail": detail if isinstance(detail, (str, int, float, bool, type(None)))
                    else json.dumps(detail, default=str)[:800]})
    say(f"  [{'PASS' if cond else 'FAIL'}] ({step}) {label}"
        + (f" -- {str(detail)[:300]}" if detail not in ("", None) else ""))
    return bool(cond)


# --- keys, rules, transactions ---------------------------------------------------

def _bls():
    from py_ecc.bls import G2Basic
    return G2Basic


def make_keys():
    bls = _bls()
    keys = {}
    for name in ACTORS:
        sk = bls.KeyGen(hashlib.sha256(f"e2e-authority-{name}".encode()).digest())
        keys[name] = {"sk": sk, "pk": bls.SkToPk(sk).hex()}
    return keys


def pin_rule(pk):
    """Total form on o5 for everyone, mentioning i12 with a literal -- the shape
    that pinned i12 narrow in the incident's process."""
    return ("always ( (i12[t]:bv[384] = { #x%s }:bv[384]) ? "
            "( o5[t]:bv[24] = { #x000001 }:bv[24] ) : "
            "( o5[t]:bv[24] = { #x000001 }:bv[24] ) )." % pk)


def incident_rule(pk):
    """The original shape: an UNPARENTHESIZED implication on an i12 comparison.
    Satisfiable, and it means one thing: `pk` is blocked."""
    return ("always ( i12[t]:bv[384] = { #x%s }:bv[384] -> "
            "( o5[t]:bv[24] = { #x000000 }:bv[24] ) )." % pk)


def history_policy_total(pk, previous="00005a"):
    """`pk` is blocked right after a step whose amount was 90 (0x5a); everyone
    else is allowed. TOTAL on every branch: the only o5 rule on its chain."""
    return ("always ( (i12[t]:bv[384] = { #x%s }:bv[384]) ? "
            "((i1[t-1]:bv[24] = { #x%s }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24])) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )." % (pk, previous))


def history_fee(dave, carol):
    """dave pays the previous step's amount as a custom fee; carol pays its low
    six bits; nobody else pays one. o8 is on no other rule, so this composes
    with the incident's o5 rules (checked by replay before it was used here)."""
    return ("always ( (i12[t]:bv[384] = { #x%s }:bv[384]) ? (o8[t]:bv[24] = i1[t-1]:bv[24]) : "
            "((i12[t]:bv[384] = { #x%s }:bv[384]) ? "
            "(o8[t]:bv[24] = (i1[t-1]:bv[24] & { #x00003f }:bv[24])) : "
            "(o8[t]:bv[24] = { #x000000 }:bv[24])) )." % (dave, carol))


def fresh_address(tag):
    bls = _bls()
    return bls.SkToPk(bls.KeyGen(hashlib.sha256(f"e2e-addr-{tag}".encode()).digest())).hex()


# --- trees ------------------------------------------------------------------------

def export_worktree(src, dst):
    """Tracked and untracked-not-ignored files: exactly the working tree."""
    out = subprocess.run(["git", "-C", src, "ls-files", "-co", "--exclude-standard", "-z"],
                         check=True, capture_output=True).stdout.decode()
    for rel in filter(None, out.split("\0")):
        s = os.path.join(src, rel)
        if not os.path.isfile(s):
            continue
        d = os.path.join(dst, rel)
        os.makedirs(os.path.dirname(d), exist_ok=True)
        shutil.copy2(s, d)


def export_ref(ref, dst):
    os.makedirs(dst, exist_ok=True)
    subprocess.run(f"git -C {REPO} archive {ref} | tar -x -C {dst}", shell=True, check=True)


def make_genesis(tree, keys, *, validators, accounts):
    cmd = [PYTHON, "scripts/gen_genesis.py", "--base-fee", "10",
           "--network-id", NETWORK_ID, "--out", "data/genesis.json"]
    for name in validators:
        cmd += ["--validator-privkey", format(keys[name]["sk"], "064x")]
    for name, balance in accounts.items():
        cmd += ["--account", f"{keys[name]['pk']}:{balance}"]
    os.makedirs(os.path.join(tree, "data"), exist_ok=True)
    subprocess.run(cmd, cwd=tree, check=True, capture_output=True)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --- a node this script owns ------------------------------------------------------

class Node:
    def __init__(self, name, tree, keys, miner, *, wrapper, bootstrap=None,
                 rpc_port=None, p2p_port=None):
        self.name, self.tree, self.keys, self.miner = name, tree, keys, miner
        self.wrapper = wrapper
        self.bootstrap = bootstrap or []
        self.rpc_port = rpc_port or free_port()
        self.p2p_port = p2p_port or free_port()
        self.control = os.path.join(tree, "e2e-control")
        os.makedirs(self.control, exist_ok=True)
        self.proc = None
        self.log_path = os.path.join(tree, "node.log")
        self.peer_id = None
        self._rid = 0
        self.extra_env = {}

    # process -----------------------------------------------------------------

    def env(self):
        env = dict(os.environ)
        env.update({
            "TAU_ENV": "production", "TAU_FORCE_TEST": "0",
            "TAU_MINER_PRIVKEY": format(self.keys[self.miner]["sk"], "064x"),
            "TAU_MINER_PUBKEY": self.keys[self.miner]["pk"],
            "TAU_MINING_ENABLED": "false",
            "TAU_NETWORK_ID": NETWORK_ID,
            "TAU_NETWORK_LISTEN": f"/ip4/127.0.0.1/tcp/{self.p2p_port}",
            "TAU_BOOTSTRAP_PEERS": json.dumps(self.bootstrap),
            "TAU_DHT_BOOTSTRAP": "[]",
            "TAU_PORT": str(self.rpc_port),
            "TAU_DB_PATH": os.path.join(self.tree, "data", "node.db"),
            "TAU_LOG_LEVEL": "INFO",
            "TAU_E2E_CONTROL": self.control,
            "PYTHONPATH": NATIVE,
            "PYTHONUNBUFFERED": "1",
        })
        env.pop("TAU_REBUILD_JOURNAL", None)
        env.update(self.extra_env)
        return env

    def start(self, **extra_env):
        self.extra_env = dict(extra_env)
        entry = (["scripts/e2e_authority_node.py"] if self.wrapper else ["server.py"])
        self._log = open(self.log_path, "a")
        self._log.write(f"\n===== start {time.strftime('%H:%M:%S')} env={extra_env} =====\n")
        self._log.flush()
        self.proc = subprocess.Popen([PYTHON] + entry, cwd=self.tree, env=self.env(),
                                     stdout=self._log, stderr=subprocess.STDOUT,
                                     start_new_session=True)
        return self

    def stop(self, timeout=30):
        if self.proc is None:
            return None
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # our own process group only: the node and the workers it spawned
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=10)
        code = self.proc.returncode
        self.proc = None
        self._log.close()
        return code

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait_ready(self, timeout=420):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.alive():
                return False
            try:
                if self.rpc("gettimestamp", timeout=5).get("status") == "ok":
                    self.peer_id = self._peer_id()
                    return True
            except Exception:
                pass
            time.sleep(1.0)
        return False

    def wait_exit(self, timeout=420):
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def _peer_id(self):
        for line in reversed(self.log().splitlines()):
            if "Network identity ready peer_id=" in line:
                return line.split("peer_id=")[1].split()[0]
        return None

    def log(self):
        try:
            return open(self.log_path, errors="replace").read()
        except FileNotFoundError:
            return ""

    def log_since(self, mark):
        return self.log()[mark:]

    def log_mark(self):
        return len(self.log())

    def crash_dumps(self):
        d = os.path.join(self.tree, "logs")
        return sorted(f for f in os.listdir(d) if f.startswith("tau_crash_")) \
            if os.path.isdir(d) else []

    # rpc ---------------------------------------------------------------------

    def rpc(self, cmd, timeout=180):
        s = socket.create_connection(("127.0.0.1", self.rpc_port), timeout=timeout)
        try:
            s.sendall((cmd + "\r\n").encode())
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                b = s.recv(65536)
                if not b:
                    break
                chunks.append(b)
            return json.loads(b"".join(chunks).decode(errors="replace").strip())
        finally:
            s.close()

    def head(self):
        """The CANONICAL head -- not the newest stored block, which after a
        received fork or a refused block is a different thing."""
        with self.db() as c:
            row = c.execute("SELECT value FROM chain_state WHERE key = "
                            "'canonical_head_hash'").fetchone()
            data = c.execute("SELECT block_data FROM blocks WHERE block_hash = ?",
                             (row[0],)).fetchone() if row else None
        return json.loads(data[0]) if data else {"block_hash": None, "header": {}}

    def height(self):
        return int(self.head()["header"]["block_number"])

    def balance(self, who):
        return int(self.rpc(f"getbalance {self.keys[who]['pk']}")["data"]["balance"])

    def balance_of(self, pk):
        return int(self.rpc(f"getbalance {pk}")["data"]["balance"])

    def mine(self, attempts=20):
        for _ in range(attempts):
            res = self.rpc("createblock")
            if res.get("status") == "ok":
                return res["data"]
            code = (res.get("error") or {}).get("code")
            if code != "MINING_BUSY":
                return res
            time.sleep(1.0)
        return res

    # probes --------------------------------------------------------------------

    def arm(self, marker):
        open(os.path.join(self.control, marker), "w").close()

    def probe(self, name, timeout=120, **args):
        self._rid += 1
        rid = f"{int(time.time()*1000)}-{self._rid}"
        tmp = os.path.join(self.control, f".cmd-{rid}")
        with open(tmp, "w") as fh:
            json.dump({"probe": name, "args": args}, fh)
        os.replace(tmp, os.path.join(self.control, f"cmd-{rid}.json"))
        res = os.path.join(self.control, f"res-{rid}.json")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(res):
                with open(res) as fh:
                    out = json.load(fh)
                os.remove(res)
                if not out.get("ok"):
                    raise RuntimeError(out.get("trace") or out.get("error"))
                return out["result"]
            time.sleep(0.2)
        raise TimeoutError(f"probe {name} on {self.name} timed out")

    # durable state, read-only ----------------------------------------------------

    def db(self):
        path = os.path.join(self.tree, "data", "node.db")
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=10)

    def journal(self):
        with self.db() as c:
            return c.execute("SELECT seq, kind, rule_text, inputs, target, outcome, "
                             "result_fp, link FROM tau_journal_v1 ORDER BY seq").fetchall()

    def commits(self):
        with self.db() as c:
            return c.execute("SELECT execution_id, tip, journal_head, plan_json "
                             "FROM block_commits_v1 ORDER BY rowid").fetchall()


class Chain:
    """Signing and submission, with sequence numbers tracked per sender."""

    def __init__(self, keys):
        self.keys = keys
        from consensus.tx_signing import signing_message_bytes
        self._msg = signing_message_bytes
        self.pending = {}

    def signed(self, node, who, ops, fee_limit="5000", seq=None, tx_type="user_tx", **extra):
        pk = self.keys[who]["pk"]
        seq_data = node.rpc(f"getsequence {pk}")["data"]
        if seq is None:
            seq = int(seq_data["sequence_number"]) + self.pending.get(who, 0)
        payload = {"tx_type": tx_type, "sender_pubkey": pk, "sequence_number": seq,
                   "expiration_time": int(time.time()) + 3600,
                   "expire_at_height": int(seq_data.get("tip_height") or 0) + 1000,
                   "fee_limit": fee_limit, **extra}
        if ops is not None:
            payload["operations"] = ops
        digest = hashlib.sha256(self._msg(payload)).digest()
        payload["signature"] = _bls().Sign(self.keys[who]["sk"], digest).hex()
        return payload

    def send(self, node, who, ops, **kw):
        payload = self.signed(node, who, ops, **kw)
        res = node.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")
        if res.get("status") == "ok":
            self.pending[who] = self.pending.get(who, 0) + 1
        return res

    def mined(self):
        self.pending.clear()

    def transfer(self, node, who, to_pk, amount, **kw):
        return self.send(node, who, {"1": [[self.keys[who]["pk"], to_pk, str(amount)]]}, **kw)


def ok(res):
    return res.get("status") == "ok"


def err(res):
    return (res.get("error") or {})


def tx_hash(res):
    return (res.get("data") or {}).get("tx_hash")


def block_txs(node):
    """The transactions of the canonical head block."""
    return node.head().get("tx_ids") or []


def semantic_journal(rows):
    """What an execution MEANT: independent of links and runtime identities."""
    return [(kind, rule, inputs, target, outcome, fp)
            for (_seq, kind, rule, inputs, target, outcome, fp, _link) in rows]


def canonical_chain(node):
    """The source node's canonical blocks, genesis excluded, oldest first --
    read from its database, the way its sync server would serve them."""
    with node.db() as c:
        row = c.execute("SELECT value FROM chain_state WHERE key = 'canonical_head_hash'").fetchone()
        blocks = {h: json.loads(d) for h, d in
                  c.execute("SELECT block_hash, block_data FROM blocks").fetchall()}
    chain, cur = [], row[0] if row else None
    while cur in blocks and int(blocks[cur]["header"]["block_number"]) > 0:
        chain.append(blocks[cur])
        cur = blocks[cur]["header"]["previous_hash"]
    return list(reversed(chain))


def relay(src, dst):
    """Deliver src's blocks that dst lacks, through dst's own network ingestion.

    The libp2p transport between two local node processes does not complete a
    security handshake on this host (pre-existing: local main does the same), so
    the harness carries the blocks -- and hands them to exactly the function the
    node's sync path calls with them, NetworkService._ingest_blocks.
    """
    have = {b["block_hash"] for b in canonical_chain(dst)}
    missing = [b for b in canonical_chain(src) if b["block_hash"] not in have]
    if not missing:
        return {"ingested": 0, "seconds": 0.0}
    return dst.probe("ingest", blocks=missing, peer=f"relay-{src.name}", timeout=600)


def fee_probe(chain, node, who, to_pk):
    """The fee admission quotes `who` for a 1-unit transfer: FEE_LIMIT_TOO_LOW
    carries it. With dave's history fee this reads the committed history."""
    res = chain.transfer(node, who, to_pk, 1, fee_limit="1")
    return int((err(res).get("details") or {}).get("required_fee", -1))


# --- the run ------------------------------------------------------------------------

def run(args):
    root = os.path.abspath(args.dir)
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    keys = make_keys()
    chain = Chain(keys)
    nodes = []
    t0 = time.time()
    try:
        _run(root, keys, chain, nodes, args)
    except Exception as exc:
        import traceback
        check("harness", "the run completed", False, traceback.format_exc()[-1500:])
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
        summary = {
            "passed": sum(1 for r in RESULTS if r["ok"]),
            "failed": [r for r in RESULTS if not r["ok"]],
            "checks": RESULTS, "evidence": EVIDENCE,
            "seconds": round(time.time() - t0, 1),
        }
        with open(os.path.join(root, "report.json"), "w") as fh:
            json.dump(summary, fh, indent=2, default=str)
        say(f"\n{summary['passed']} passed, {len(summary['failed'])} failed "
            f"in {summary['seconds']}s -> {os.path.join(root, 'report.json')}")
    return 0 if not [r for r in RESULTS if not r["ok"]] else 1


def _mine(chain, node):
    out = node.mine()
    chain.mined()
    return out


def _run(root, keys, chain, nodes, args):
    pk = {n: keys[n]["pk"] for n in keys}
    accounts = {"alice": 100000, "bob": 100000, "carol": 100000, "dave": 100000,
                "erin": 100000, "inf": 1}

    # ---------------------------------------------------------------- 1, 2
    say("== 1-2: fresh nodes, native Tau, no journal; genesis initializes it ==")
    tree_a, tree_b = os.path.join(root, "nodeA"), os.path.join(root, "nodeB")
    export_worktree(REPO, tree_a)
    # ONE validator. B runs the same validator key: a second instance of it,
    # eligible whenever A is -- which is what lets a competing block for the
    # same height arrive from the network while A's own candidate is pending.
    make_genesis(tree_a, keys, validators=("minerA",), accounts=accounts)
    export_worktree(REPO, tree_b)
    os.makedirs(os.path.join(tree_b, "data"), exist_ok=True)
    shutil.copy2(os.path.join(tree_a, "data", "genesis.json"),
                 os.path.join(tree_b, "data", "genesis.json"))
    check(1, "node A starts with no database at all",
          not os.path.exists(os.path.join(tree_a, "data", "node.db")))
    a = Node("A", tree_a, keys, "minerA", wrapper=True)
    nodes.append(a)
    a.start()
    check(1, "node A becomes ready", a.wait_ready(), a.log()[-800:] if not a.alive() else "")
    check(1, "the worker-backed authority is serving (native: mock cannot mine)",
          "Authoritative evaluator ready (ACTIVE)" in a.log())
    journal, commits = a.journal(), a.commits()
    check(2, "genesis committed its rules as the first journal entries", len(journal) > 0,
          f"{len(journal)} entries")
    check(2, "one commit record, for genesis",
          len(commits) == 1 and str(commits[0][0]).startswith("genesis:"),
          commits[0][0] if commits else None)
    check(2, "the record names the journal's head", bool(commits) and commits[0][2] == journal[-1][7])
    EVIDENCE["genesis"] = {"journal_entries": len(journal), "record": commits[0][:3] if commits else None}

    b = Node("B", tree_b, keys, "minerA", wrapper=True)
    nodes.append(b)
    b.start()
    check(1, "node B (a second instance of the validator) becomes ready", b.wait_ready())
    dumps_a0, dumps_b0 = a.crash_dumps(), b.crash_dumps()

    def follow(label):
        r = relay(a, b)
        EVIDENCE.setdefault("relay", []).append({label: r})
        ok_ = b.head()["block_hash"] == a.head()["block_hash"] and \
            b.head()["header"]["state_hash"] == a.head()["header"]["state_hash"]
        check(11, f"B committed A's blocks through ingestion, no local artifact ({label})",
              ok_, r)
        return ok_

    # ---------------------------------------------------------------- 3, 4
    say("== 3-4: the original unparenthesized implication, end to end ==")
    r = chain.send(a, "alice", {"0": pin_rule(pk["alice"])})
    check(3, "i12-pinning rule admitted", ok(r), r)
    _mine(chain, a)
    check(3, "and included", tx_hash(r) in block_txs(a))
    rule = incident_rule(pk["bob"])
    EVIDENCE["incident_rule"] = rule
    r = chain.send(a, "bob", {"0": rule})
    check(4, "incident rule: sendtx accepted", ok(r), r)
    height0 = a.height()
    _mine(chain, a)
    check(4, "incident rule: included in a durable block",
          tx_hash(r) in block_txs(a) and a.height() == height0 + 1)
    check(4, "the block has a commit record naming it", a.commits()[-1][1] == a.head()["block_hash"])
    check(4, "the rule is present in canonical state",
          rule in a.rpc("gettaustate")["data"]["rules_state"])
    r_bob = chain.transfer(a, "bob", pk["alice"], 5)
    check(4, "policy verdict: bob is blocked",
          not ok(r_bob) and "user policy" in err(r_bob).get("message", ""), r_bob)
    r_carol = chain.transfer(a, "carol", pk["alice"], 5)
    check(4, "policy verdict: carol is allowed", ok(r_carol), r_carol)
    _mine(chain, a)
    check(4, "the node keeps mining: carol's transfer lands", tx_hash(r_carol) in block_txs(a))
    check(4, "no crash artifact from the incident sequence", a.crash_dumps() == dumps_a0,
          a.crash_dumps())
    follow("after the incident")

    # ---------------------------------------------------------------- 5, 6, 7
    say("== 5-7: A/B/C/D -- B steps the evaluator and allocates, then is rejected ==")
    r = chain.send(a, "carol", {"0": history_fee(pk["dave"], pk["carol"])})
    check(5, "history fee rule admitted", ok(r), r)
    _mine(chain, a)
    check(5, "and included", tx_hash(r) in block_txs(a))
    new_addr, x_addr = fresh_address("abcd-new"), fresh_address("abcd-x")
    carol0, dave0 = a.balance("carol"), a.balance("dave")
    ta = chain.transfer(a, "alice", x_addr, 90, fee_limit="60")
    tb = chain.transfer(a, "dave", new_addr, 5, fee_limit="60")
    tc_ = chain.transfer(a, "carol", new_addr, 3, fee_limit="60")
    td = chain.transfer(a, "erin", pk["alice"], 1, fee_limit="60")
    check(5, "A, B, C, D all admitted at the committed head",
          all(ok(x) for x in (ta, tb, tc_, td)), [ta, tb, tc_, td])
    _mine(chain, a)
    txs = block_txs(a)
    check(5, "the block carries A, C, D -- and not B",
          txs == [tx_hash(ta), tx_hash(tc_), tx_hash(td)],
          {"block": txs, "A": tx_hash(ta), "B": tx_hash(tb), "C": tx_hash(tc_), "D": tx_hash(td)})
    status_b = a.rpc(f"gettxstatus {tx_hash(tb)}")["data"]
    check(5, "B was rejected at apply (its fee after A is 10 + 90 > 60)",
          status_b.get("status") == "rejected", status_b)
    check(6, "B left nothing: dave paid no fee and moved nothing", a.balance("dave") == dave0)
    paid = carol0 - a.balance("carol")
    check(6, "C saw A and not B: carol's fee reads A's 90 (26), not B's 5",
          paid == 3 + 10 + (90 & 63), {"paid": paid, "if_B_leaked": 3 + 10 + 5})
    check(6, "the new address holds C's transfer only", a.balance_of(new_addr) == 3,
          a.balance_of(new_addr))
    with a.db() as c:
        bound = [k for (k,) in c.execute("SELECT key FROM tau_shrink_ids").fetchall()
                 if new_addr in k]
    check(6, "the allocator published the new address exactly once", len(bound) == 1, bound)
    check(7, "no crash artifact for the deterministic rejection", a.crash_dumps() == dumps_a0)
    # A RULE the engine refuses outright: i1 is typed bv[24] by the builtin
    # rules, this one types it bv[16]. It is refused where apply would refuse
    # it -- in an evaluator carrying the committed type history -- and nothing
    # on the node treats that as a crash.
    clash = chain.send(a, "erin", {"0": "always ( o13[t]:bv[16] = i1[t]:bv[16] )."})
    check(7, "a rule the engine refuses is rejected at admission, with its reason",
          not ok(clash) and err(clash).get("code") == "TX_REJECTED"
          and "i1" in err(clash).get("message", ""), clash)
    check(7, "and leaves no crash artifact", a.crash_dumps() == dumps_a0, a.crash_dumps())
    follow("after A/B/C/D")

    # ---------------------------------------------------------------- 8
    say("== 8: restart; the evaluator continues where it was ==")
    before = fee_probe(chain, a, "dave", pk["alice"])
    check(8, "admission reads the committed history: dave's quote is 10 + D's 1",
          before == 11, before)
    a.stop()
    a.start()
    check(8, "A restarts", a.wait_ready())
    check(8, "the authority was rebuilt from the committed journal",
          "authoritative evaluator reconstructed from" in a.log().split("===== start")[-1])
    check(8, "the same quote after restart", fee_probe(chain, a, "dave", pk["alice"]) == before)
    dave0 = a.balance("dave")
    chain.transfer(a, "dave", pk["alice"], 2)
    mark = a.log_mark()
    _mine(chain, a)
    check(8, "the reconstructed authority continues the history: dave pays 10 + 1",
          dave0 - a.balance("dave") == 2 + 11, dave0 - a.balance("dave"))
    r_bob = chain.transfer(a, "bob", pk["alice"], 5)
    check(8, "the incident policy survives restart: bob still blocked",
          not ok(r_bob) and "user policy" in err(r_bob).get("message", ""), r_bob)

    # ---------------------------------------------------------------- 9
    say("== 9: the promoted worker is reused, not replayed ==")
    since = a.log_since(mark)
    check(9, "the first block after restart ran on the lent authority",
          "runs on the authoritative worker (lent)" in since)
    check(9, "and committed its own evaluation", "reuses its own evaluation" in since)
    mark = a.log_mark()
    for _ in range(2):
        chain.transfer(a, "erin", pk["alice"], 1)
        _mine(chain, a)
    since = a.log_since(mark)
    check(9, "two more blocks: two loans, no reconstruction",
          since.count("runs on the authoritative worker (lent)") == 2
          and "authoritative evaluator reconstructed" not in since,
          {"lent": since.count("runs on the authoritative worker (lent)")})
    follow("after the restart")

    # ---------------------------------------------------------------- 10
    say("== 10: promotion fails after the durable commit ==")
    a.arm("fail_promotion")
    height0 = a.height()
    r = chain.transfer(a, "erin", pk["alice"], 7)
    mark = a.log_mark()
    _mine(chain, a)
    check(10, "the block is committed anyway",
          a.height() == height0 + 1 and tx_hash(r) in block_txs(a))
    check(10, "the injected failure is what happened",
          "injected promotion failure" in a.log_since(mark))
    snap = a.probe("snapshot")
    check(10, "and nothing is served", snap["state"] == "UNAVAILABLE", snap["state"])
    check(10, "admission still answers from the committed journal: 10 + 7",
          fee_probe(chain, a, "dave", pk["alice"]) == 17)
    dave0 = a.balance("dave")
    chain.transfer(a, "dave", pk["alice"], 1)
    mark = a.log_mark()
    _mine(chain, a)
    since = a.log_since(mark)
    check(10, "the next block is built from the journal, not the lost worker",
          "runs on the authoritative worker (lent)" not in since and a.height() == height0 + 2)
    check(10, "and continues the same history: dave pays 10 + 7",
          dave0 - a.balance("dave") == 1 + 17, dave0 - a.balance("dave"))
    a.stop()
    a.start()
    check(10, "restart after the failure", a.wait_ready())
    check(10, "the same continuation after restart: quote 10 + 1",
          fee_probe(chain, a, "dave", pk["alice"]) == 11)
    plan = json.loads(a.commits()[-1][3] or "{}")
    EVIDENCE["plan_after_recovery"] = plan
    rule2 = incident_rule(pk["erin"])
    r = chain.send(a, "erin", {"0": rule2})
    check(3, "the incident shape again, after the recovery replanned "
             f"(i12 {'interned' if 12 in plan.get('interned', []) else 'plain'}): admitted",
          ok(r), {"plan": plan, "res": r})
    _mine(chain, a)
    check(3, "included", tx_hash(r) in block_txs(a))
    r_erin = chain.transfer(a, "erin", pk["alice"], 1)
    r_alice = chain.transfer(a, "alice", pk["erin"], 1)
    check(3, "and it means what it says: erin blocked, alice allowed",
          not ok(r_erin) and "user policy" in err(r_erin).get("message", "") and ok(r_alice),
          [r_erin, r_alice])
    _mine(chain, a)
    check(3, "no crash artifact at any point", a.crash_dumps() == dumps_a0, a.crash_dumps())
    follow("after the promotion failure")

    # ---------------------------------------------------------------- 11, 12 + lending
    say("== 11-12: a competing block arrives while the authority is lent ==")
    follow("before the competing block")
    parent = a.head()["block_hash"]
    a.arm("hold_next_block")
    chain.transfer(a, "alice", pk["carol"], 2)
    a.rpc("createblock")
    held = json.load(open(os.path.join(a.control, "held.json")))
    check("lend", "candidate X was built and held", held.get("block") is not None, held)
    snap = a.probe("snapshot")
    check("lend", "X's artifact is pending on the LENT authority",
          snap["state"] == "LENT" and snap["pending_key"] == held.get("key"), snap)
    requests_before = snap["pending_worker_requests"]
    chain.mined()
    ry = chain.transfer(b, "carol", pk["alice"], 3)     # erin is blocked by now
    check(11, "a transaction submitted to B", ok(ry), ry)
    y = _mine(chain, b)
    check(11, "B builds Y on the same parent",
          y.get("block_hash") is not None and b.head()["header"]["previous_hash"] == parent, y)
    got = relay(b, a)
    EVIDENCE["relay_Y"] = got
    check(11, "A commits Y -- received, no local artifact, authority lent elsewhere",
          a.head()["block_hash"] == y.get("block_hash"), got)
    since = a.log()
    snap = a.probe("snapshot")
    check("lend", "the lent worker was never touched while Y was processed",
          snap["pending_worker_requests"] == requests_before, snap)
    check("lend", "A is served by Y's own worker, not the lent one",
          snap["state"] == "ACTIVE" and snap["serving_worker"] != snap["pending_worker"], snap)
    check("lend", "X's artifact is still pending, bound to X", snap["pending_key"] == held.get("key"))
    ver = a.probe("verify_held")
    EVIDENCE["stale_artifact"] = ver
    check(12, "X's artifact is refused against the moved parent",
          ver.get("claimed") and ver.get("refusal"), ver)
    check(12, "returning it leaves the authority serving", ver.get("state_after") == "ACTIVE", ver)
    check(12, "and its worker is gone", ver.get("worker_alive_after_dispose") is False, ver)
    _mine(chain, a)
    follow("after the competing block")

    # ---------------------------------------------------------------- 13
    say("== 13: reprocessing a committed block ==")
    for node in (a, b):
        rep = node.probe("reprocess_head")
        EVIDENCE[f"reprocess_{node.name}"] = rep
        check(13, f"{node.name}: re-delivered head changes nothing, directly or via ingestion",
              rep["unchanged"], rep)

    # ---------------------------------------------------------------- 14 + migration
    say("== 14: rebuild the journal explicitly from the stored blocks ==")
    b.stop()
    head_a, journal_a = a.head(), a.journal()
    quote_a = fee_probe(chain, a, "dave", pk["alice"])
    tree_r = os.path.join(root, "nodeR")
    shutil.copytree(tree_b, tree_r, ignore=shutil.ignore_patterns("e2e-control", "node.log", "logs"))
    db_r = os.path.join(tree_r, "data", "node.db")
    with sqlite3.connect(db_r) as c:
        c.execute("DELETE FROM tau_journal_v1")
        c.execute("DELETE FROM block_commits_v1")
    rn = Node("R", tree_r, keys, "minerA", wrapper=True)
    nodes.append(rn)
    rn.start()
    code = rn.wait_exit(timeout=300)
    rn.proc = None
    check("migration", "a chain without a journal refuses to start without the flag",
          code not in (None, 0) and "TAU_REBUILD_JOURNAL=1" in rn.log(), code)
    started = time.time()
    rn.start(TAU_REBUILD_JOURNAL="1")
    check(14, "with TAU_REBUILD_JOURNAL=1 it rebuilds and starts", rn.wait_ready(timeout=900))
    EVIDENCE["rebuild_seconds"] = round(time.time() - started, 1)
    head_r = rn.head()
    check(14, "same head, same state hash",
          head_r["block_hash"] == head_a["block_hash"]
          and head_r["header"]["state_hash"] == head_a["header"]["state_hash"])
    journal_r = rn.journal()
    check(14, "the rebuilt journal means what A's means, entry for entry",
          semantic_journal(journal_r) == semantic_journal(journal_a),
          {"A": len(journal_a), "rebuilt": len(journal_r)})
    EVIDENCE["rebuild_links_identical"] = [x[7] for x in journal_r] == [x[7] for x in journal_a]
    check(14, "the rebuilt evaluator continues identically (dave's quote)",
          fee_probe(chain, rn, "dave", pk["alice"]) == quote_a, quote_a)
    rn.stop()
    before = rn.journal()
    rn.start(TAU_REBUILD_JOURNAL="1")
    check("migration", "restart with =1 on a complete journal", rn.wait_ready())
    check("migration", "does nothing destructive",
          rn.journal() == before and "nothing to rebuild" in rn.log().split("===== start")[-1])
    rn.stop()
    with sqlite3.connect(db_r) as c:
        c.execute("DELETE FROM block_commits_v1")
    before = rn.journal()
    rn.start(TAU_REBUILD_JOURNAL="1")
    code = rn.wait_exit(timeout=300)
    rn.proc = None
    check("migration", "a journal no record describes: refused even with =1",
          code not in (None, 0) and "TAU_REBUILD_JOURNAL=discard" in rn.log().split("===== start")[-1],
          code)
    check("migration", "and left exactly as it was", rn.journal() == before)
    rn.start(TAU_REBUILD_JOURNAL="discard")
    check("migration", "=discard replaces it", rn.wait_ready(timeout=900))
    check("migration", "with the same history", semantic_journal(rn.journal())
          == semantic_journal(journal_a) and rn.head()["block_hash"] == head_a["block_hash"])
    rn.stop()
    a.stop()
    check(7, "no crash artifact on any node",
          a.crash_dumps() == dumps_a0 and b.crash_dumps() == dumps_b0 and not rn.crash_dumps(),
          [a.crash_dumps(), b.crash_dumps(), rn.crash_dumps()])

    # ---------------------------------------------------------------- 15
    step15(root, keys, chain, nodes, patched=True)


def step15(root, keys, chain, nodes, *, patched):
    """Repeated admission requests around a `[t-1]` o5 policy, on a chain of its
    own: the policy is the only o5 rule there, so nothing else composes with it."""
    say("== 15: admission requests cannot influence one another ==")
    pk = {n: keys[n]["pk"] for n in keys}
    tag = "15" if patched else "15-unpatched"
    tree = os.path.join(root, "nodeC" if patched else "nodeC-unpatched")
    if patched:
        export_worktree(REPO, tree)
    else:
        export_ref("main", tree)
    make_genesis(tree, keys, validators=("minerA",),
                 accounts={"dave": 100000, "erin": 100000, "alice": 100000, "inf": 1})
    node = Node("C", tree, keys, "minerA", wrapper=patched)
    nodes.append(node)
    node.start()
    check(tag, "a fresh node for the policy", node.wait_ready())
    chain.pending.clear()
    r = chain.send(node, "dave", {"0": history_policy_total(pk["dave"])})
    check(tag, "dave's [t-1] policy admitted", ok(r), r)
    _mine(chain, node)
    check(tag, "and included", tx_hash(r) in block_txs(node))
    chain.transfer(node, "erin", pk["alice"], 1)
    _mine(chain, node)                                  # history now ends at 1
    for _ in range(3):
        rinf = chain.transfer(node, "inf", fresh_address("elsewhere"), 90)
    check(tag, "influencers reach the Tau step (amount 90) and are refused after it",
          err(rinf).get("code") == "INSUFFICIENT_FUNDS", rinf)
    rd = chain.transfer(node, "dave", fresh_address("dave-target"), 5)
    if patched:
        check(tag, "dave is admitted: committed history ends at 1, not the influencers' 90",
              ok(rd), rd)
        _mine(chain, node)
        check(tag, "and included: admission and inclusion agree", tx_hash(rd) in block_txs(node))
        chain.transfer(node, "alice", fresh_address("x90"), 90)
        _mine(chain, node)                              # history now ends at 90
        for _ in range(3):
            chain.transfer(node, "inf", fresh_address("elsewhere"), 5)
        rd = chain.transfer(node, "dave", fresh_address("dave-target"), 5)
        check(tag, "the other direction: history ends at 90, influencers feed 5 -- dave refused",
              not ok(rd) and "user policy" in err(rd).get("message", ""), rd)
        verdicts, threads, lock = [], [], threading.Lock()

        def _one(who, amount):
            out = chain.transfer(node, who, fresh_address(f"c-{who}"), amount)
            with lock:
                verdicts.append((who, "admitted" if ok(out) else err(out).get("code"),
                                 err(out).get("message", "")[:60]))

        for i in range(8):
            threads.append(threading.Thread(
                target=_one, args=(("dave", 5) if i % 2 else ("inf", 5))))
        for t in threads:
            t.start()
        for t in threads:
            t.join(180)
        EVIDENCE["concurrent_admission"] = verdicts
        daves = [v for v in verdicts if v[0] == "dave"]
        answered = [v for v in daves if v[1] not in ("ADMISSION_UNAVAILABLE", "ADMISSION_TIMEOUT")]
        check(tag, "eight concurrent requests: no dave request got a verdict from anyone "
                   "else's history", answered and all(v[1] == "TX_REJECTED" and
                                                      "user policy" in v[2] for v in answered),
              verdicts)
        check(tag, "no crash artifact", not node.crash_dumps())
    else:
        EVIDENCE["unpatched_step15"] = rd
        check(tag, "UNPATCHED: dave is falsely refused -- the influencers' 90 became his [t-1]",
              not ok(rd) and "user policy" in err(rd).get("message", ""), rd)
    node.stop()


def unpatched(args):
    """The incident on a tree without the fix: the before of the before/after."""
    root = os.path.abspath(args.dir)
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    keys = make_keys()
    chain = Chain(keys)
    nodes = []
    tree = os.path.join(root, "node")
    export_ref(args.ref, tree)
    make_genesis(tree, keys, validators=("minerA",),
                 accounts={"alice": 100000, "bob": 100000, "carol": 100000})
    node = Node("U", tree, keys, "minerA", wrapper=False)
    nodes.append(node)
    t0 = time.time()
    try:
        node.start()
        check("u", "unpatched node becomes ready", node.wait_ready())
        dumps0 = node.crash_dumps()
        r = chain.send(node, "alice", {"0": pin_rule(keys["alice"]["pk"])})
        check("u", "pin rule admitted", ok(r), r)
        _mine(chain, node)
        check("u", "pin rule included", tx_hash(r) in block_txs(node))
        r = chain.send(node, "bob", {"0": incident_rule(keys["bob"]["pk"])})
        check("u", "incident rule: sendtx says ok", ok(r), r)
        mark = node.log_mark()
        _mine(chain, node)
        time.sleep(1.0)
        check("u", "incident rule NOT included", tx_hash(r) not in block_txs(node),
              block_txs(node))
        since = node.log_since(mark)
        EVIDENCE["unpatched_apply_log"] = [l for l in since.splitlines()
                                           if "REJECT" in l.upper() or "Incompatible" in l][:5]
        check("u", "rejected during apply", "REJECTED" in since.upper(),
              EVIDENCE["unpatched_apply_log"])
        check("u", "a crash artifact appeared", len(node.crash_dumps()) > len(dumps0),
              node.crash_dumps())
        r_bob = chain.transfer(node, "bob", keys["alice"]["pk"], 5)
        check("u", "and bob is NOT blocked: the policy never took effect", ok(r_bob), r_bob)
        node.stop()
        step15(root, keys, chain, nodes, patched=False)
    except Exception:
        import traceback
        check("harness", "the run completed", False, traceback.format_exc()[-1500:])
    finally:
        for n in nodes:
            try:
                n.stop()
            except Exception:
                pass
        summary = {"passed": sum(1 for r in RESULTS if r["ok"]),
                   "failed": [r for r in RESULTS if not r["ok"]], "checks": RESULTS,
                   "evidence": EVIDENCE, "seconds": round(time.time() - t0, 1)}
        with open(os.path.join(root, "report.json"), "w") as fh:
            json.dump(summary, fh, indent=2, default=str)
        say(f"\n{summary['passed']} passed, {len(summary['failed'])} failed")
    return 0 if not summary["failed"] else 1


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--dir", required=True)
    u = sub.add_parser("unpatched")
    u.add_argument("--dir", required=True)
    u.add_argument("--ref", default="main")
    args = p.parse_args()
    return run(args) if args.cmd == "run" else unpatched(args)


if __name__ == "__main__":
    sys.exit(main())
