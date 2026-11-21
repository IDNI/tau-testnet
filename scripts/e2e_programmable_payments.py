#!/usr/bin/env python3
"""End-to-end programmable payments against REAL, disposable node processes.

tests/test_*_native.py mine signed txs through the in-process chain; this
drives live nodes with the NATIVE engine, so it exercises what only exists
at runtime: the real fee rule, the miner sealing blocks, the books
surviving a restart, and a second node reproducing the same state from
the first node's blocks. One flow per stage: (a) credits, (b) grants,
(c) standing payments, (d) receive routes, (e) payout rules, (f) restart
+ follower agreement.

Every node runs from its own tree under --dir (exported from `git archive HEAD`,
so it tests committed code) with its own keys, genesis, database and ports. The
harness refuses to start when any node data path resolves outside its own tree
or inside the main repository's data/ or root.

USAGE
    python scripts/e2e_programmable_payments.py provision --dir .local/payments-e2e
    python scripts/e2e_programmable_payments.py run --dir .local/payments-e2e

`run` starts node1 (miner off), drives scenarios a, b, d, e, restarts node1
with its miner enabled, drives scenario c, then starts node2 (follower)
for scenario f, and stops exactly the processes it started.

BLOCKER (2026-11-21): `run` requires the native tau binding
(`require_native` below). The tau-lang build is blocked on this machine
by an execution-risk check, so `run` cannot execute here until a built
tau module is available. `provision` is still validated; do NOT claim
e2e coverage that has not run.

ASSERTION DISCIPLINE
    Each scenario asserts an accounting oracle -- expected balance deltas
    aggregated per address, escrow totals, book rows via the getgrants /
    getstandingpayments / getreceiveroute / getpayoutrule RPC getters, and
    sequence numbers -- never one createblock response: the node's own
    miner races every explicit mine, so the chain is awaited, not the
    call. Fees are assumed BASE_FEE per fee-bearing tx, as in e2e_retractable.py.
Exceptions, all by design: `grant_draw` is fee-exempt (only
`grant_create` bears a fee); a standing-payment sweep charges the
payer one extra BASE_FEE (`max_fee_per_execution`) per execution;
a rejected tx (e.g. a cap-skipped second payout execute) pays no fee.
"""
from __future__ import annotations

import argparse
import atexit
import hashlib
import json
import os
import signal
import socket
import sqlite3
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYTHON = os.environ.get("TAU_E2E_PYTHON", sys.executable)
NATIVE = os.environ.get("TAU_NATIVE_PATH") or os.environ.get("PYTHONPATH", "")
NETWORK_ID = "tau-payments-e2e"
BASE_FEE = 10
FUNDS = 1_000_000
# Ports above 65535 are invalid, so the block sits at 648xx. The WS server scans RPC+1..+9, so RPC ports are spaced and p2p ports sit
# outside every scan range.
RPC_PORTS = {"node1": 64810, "node2": 64820}
P2P_PORTS = {"node1": 64830, "node2": 64840}
PORT_MIN, PORT_MAX = 64810, 64890
SCENARIOS = ("a", "b", "c", "d", "e", "f")
ROLES = ("sender", "recipient", "other")
ACTORS = ("miner",) + tuple(f"{s}_{r}" for s in SCENARIOS for r in ROLES) + ("pad1", "pad2")
DAY = 86400
WEEK = 7 * DAY
# Valid payout-clause shape (Stage 5): a ternary over an input guard.
# Bare decimals (`o1[t] = 300`) and comma-separated assignments do not parse,
# and a constant-only clause cannot be stepped at all (it reads no input
# stream), so the clause must read an input -- here i1, the payer balance.
# Caveat: the i1[t]:bv[24] guard caps at 16,777,215; fine for the balances
# in this e2e (1,000,000), but a payer holding more would need a wider guard.
CLAUSE = (
    "always ((i1[t]:bv[24] > { #x000000 }:bv[24])"
    " ? (o1[t]:bv[24] = { 300 }:bv[24] && o2[t]:bv[24] = { 700 }:bv[24])"
    " : (o1[t]:bv[24] = { 0 }:bv[24] && o2[t]:bv[24] = { 0 }:bv[24]))."
)

FAILED: list[str] = []
STARTED: list["Node"] = []
DEADLINE = [time.time() + 3000]


def say(msg=""):
    print(msg, flush=True)


def check(label, cond, detail=""):
    if cond:
        say(f"  PASS  {label}" + (f"  [{detail}]" if detail != "" else ""))
    else:
        FAILED.append(label)
        say(f"  FAIL  {label}  [{detail}]")
    return bool(cond)


def over_deadline():
    return time.time() > DEADLINE[0]


# --------------------------------------------------------------------------- #
# isolation
# --------------------------------------------------------------------------- #

def main_repo_root():
    common = subprocess.run(
        ["git", "-C", REPO, "rev-parse", "--git-common-dir"],
        check=True, capture_output=True, text=True).stdout.strip()
    common = os.path.realpath(os.path.join(REPO, common))
    return os.path.dirname(common)


def assert_isolated(base, paths):
    """Refuse any path outside `base`, inside the main repo's data/, or directly in its root."""
    main = os.path.realpath(main_repo_root())
    base = os.path.realpath(base)
    for label, path in paths:
        rp = os.path.realpath(path)
        say(f"[isolation] {label}: {rp}")
        in_main_data = rp == os.path.join(main, "data") or rp.startswith(os.path.join(main, "data") + os.sep)
        in_main_root = os.path.dirname(rp) == main
        outside = not (rp == base or rp.startswith(base + os.sep))
        if in_main_data or in_main_root or outside:
            raise SystemExit(f"REFUSING: {label} resolves to {rp} "
                             f"(main-data={in_main_data} main-root={in_main_root} outside-harness-dir={outside})")


def main_footprint():
    main = main_repo_root()
    out = {}
    for rel in ("node.db", "data"):
        p = os.path.join(main, rel)
        if os.path.isdir(p):
            for name in sorted(os.listdir(p)):
                q = os.path.join(p, name)
                out[f"{rel}/{name}"] = (os.stat(q).st_mtime_ns, os.stat(q).st_size)
        elif os.path.exists(p):
            out[rel] = (os.stat(p).st_mtime_ns, os.stat(p).st_size)
    return out


# --------------------------------------------------------------------------- #
# provisioning
# --------------------------------------------------------------------------- #

def _bls():
    from py_ecc.bls import G2Basic
    return G2Basic


def make_keys():
    bls = _bls()
    keys = {}
    for name in ACTORS:
        sk = bls.KeyGen(hashlib.sha256(f"payments-e2e-{name}".encode()).digest())
        keys[name] = {"sk": format(sk, "064x"), "pk": bls.SkToPk(sk).hex()}
    return keys


def tree_of(base, node):
    return os.path.join(base, node)


def overlay_worktree(tree):
    """Copy tracked files modified (uncommitted) in the working tree over the exported HEAD."""
    out = subprocess.run(["git", "-C", REPO, "diff", "--name-only", "-z", "HEAD"],
                         check=True, capture_output=True).stdout.decode()
    names = [n for n in out.split("\0") if n]
    for rel in names:
        src = os.path.join(REPO, rel)
        if os.path.isfile(src):
            os.makedirs(os.path.dirname(os.path.join(tree, rel)), exist_ok=True)
            subprocess.run(["cp", src, os.path.join(tree, rel)], check=True)
    return names


def provision(base, overlay=False):
    base = os.path.abspath(base)
    os.makedirs(base, exist_ok=True)
    keys = make_keys()
    json.dump(keys, open(os.path.join(base, "keys.json"), "w"), indent=2)
    for node in ("node1", "node2"):
        tree = tree_of(base, node)
        os.makedirs(tree, exist_ok=True)
        say(f"Exporting HEAD into {tree}")
        subprocess.run(f"git -C {REPO} archive HEAD | tar -x -C {tree}", shell=True, check=True)
        if overlay:
            say(f"  overlaid uncommitted files: {overlay_worktree(tree)}")
        os.makedirs(os.path.join(tree, "data"), exist_ok=True)
        for stale in ("node.db", "data/node.db", "data/identity.key"):
            if os.path.exists(os.path.join(tree, stale)):
                os.remove(os.path.join(tree, stale))

    cmd = [PYTHON, "scripts/gen_genesis.py", "--validator-privkey", keys["miner"]["sk"],
           "--base-fee", str(BASE_FEE), "--network-id", NETWORK_ID, "--out", "data/genesis.json"]
    for name, k in keys.items():
        if name != "miner":
            cmd += ["--account", f"{k['pk']}:{FUNDS}"]
    subprocess.run(cmd, cwd=tree_of(base, "node1"), check=True)
    subprocess.run(["cp", os.path.join(tree_of(base, "node1"), "data", "genesis.json"),
                    os.path.join(tree_of(base, "node2"), "data", "genesis.json")], check=True)
    say(f"Provisioned {base}")
    return 0

# --------------------------------------------------------------------------- #
# node process + client
# --------------------------------------------------------------------------- #

class Node:
    def __init__(self, name, base, keys, log_path, *, mining, bootstrap=None):
        self.name = name
        self.tree = tree_of(base, name)
        self.keys = keys
        self.log_path = log_path
        self.mining = mining
        self.bootstrap = bootstrap or []
        self.rpc_port = RPC_PORTS[name]
        self.p2p_port = P2P_PORTS[name]
        self.db_path = os.path.join(self.tree, "data", "node.db")
        self.proc = None
        self.peer_id = None
        self._log = None

    def paths(self):
        return [(f"{self.name} tree", self.tree), (f"{self.name} db", self.db_path),
                (f"{self.name} genesis", os.path.join(self.tree, "data", "genesis.json")),
                (f"{self.name} identity", os.path.join(self.tree, "data", "identity.key"))]

    def env(self):
        env = dict(os.environ)
        env.update({
            "TAU_ENV": "production", "TAU_FORCE_TEST": "0",
            "TAU_MINING_ENABLED": "true" if self.mining else "false",
            "TAU_NETWORK_ID": NETWORK_ID,
            "TAU_NETWORK_LISTEN": f"/ip4/127.0.0.1/tcp/{self.p2p_port}",
            "TAU_BOOTSTRAP_PEERS": json.dumps(self.bootstrap),
            "TAU_DHT_BOOTSTRAP": "[]",
            "TAU_PORT": str(self.rpc_port),
            "TAU_DB_PATH": self.db_path,
            "TAU_PEERSTORE_PATH": os.path.join(self.tree, "data", "peerstore"),
            "TAU_IDENTITY_KEY_PATH": os.path.join(self.tree, "data", "identity.key"),
            "TAU_LOG_LEVEL": "INFO",
            "PYTHONPATH": NATIVE,
            "PYTHONUNBUFFERED": "1",
        })
        # The key is needed for explicit createblock even when the background
        # miner is off; only the follower runs without it.
        env["TAU_MINER_PUBKEY"] = self.keys["miner"]["pk"]
        if self.name == "node1":
            env["TAU_MINER_PRIVKEY"] = self.keys["miner"]["sk"]
        else:
            env.pop("TAU_MINER_PRIVKEY", None)
        env.pop("TAU_REBUILD_JOURNAL", None)
        return env

    def start(self):
        for port in (self.rpc_port, self.p2p_port):
            assert PORT_MIN <= port <= PORT_MAX, port
        self._log = open(self.log_path, "a")
        self._log.write(f"\n===== start {time.strftime('%H:%M:%S')} =====\n")
        self._log.flush()
        self.proc = subprocess.Popen([PYTHON, "server.py"], cwd=self.tree, env=self.env(),
                                     stdout=self._log, stderr=subprocess.STDOUT,
                                     start_new_session=True)
        if self not in STARTED:
            STARTED.append(self)
        say(f"[{self.name}] started pid={self.proc.pid} rpc={self.rpc_port} p2p={self.p2p_port} log={self.log_path}")

    def stop(self, timeout=40):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                os.killpg(self.proc.pid, signal.SIGKILL)
                self.proc.wait(timeout=15)
        self.proc = None
        if self._log:
            self._log.close()
            self._log = None

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait_ready(self, timeout=420):
        end = time.time() + timeout
        while time.time() < end:
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

    def _peer_id(self):
        try:
            text = open(self.log_path, errors="replace").read()
        except FileNotFoundError:
            return None
        for line in reversed(text.splitlines()):
            if "Network identity ready peer_id=" in line:
                return line.split("peer_id=")[1].split()[0]
        return None

    def rpc(self, cmd, timeout=240.0):
        s = socket.create_connection(("127.0.0.1", self.rpc_port), timeout=timeout)
        try:
            s.sendall((cmd + "\r\n").encode())
            s.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                buf = s.recv(65536)
                if not buf:
                    break
                chunks.append(buf)
            return json.loads(b"".join(chunks).decode(errors="replace").strip())
        finally:
            s.close()

    # -- durable state, read-only -----------------------------------------

    def head(self):
        con = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=10)
        try:
            row = con.execute("SELECT value FROM chain_state WHERE key = 'canonical_head_hash'").fetchone()
            data = con.execute("SELECT block_data FROM blocks WHERE block_hash = ?",
                               (row[0],)).fetchone() if row else None
        finally:
            con.close()
        return json.loads(data[0]) if data else {"block_hash": None, "header": {"block_number": -1}}

    def height(self):
        try:
            return int(self.head()["header"]["block_number"])
        except Exception:
            return -1

    # -- chain reads ---------------------------------------------------------

    def chain_id(self):
        return self.rpc("getchainid")["data"]["chain_id"]

    def balance(self, pk):
        return int(self.rpc(f"getbalance {pk}")["data"]["balance"])

    def acct(self, pk):
        d = self.rpc(f"getaccountstate {pk}")["data"]
        return int(d["escrowed_out"]), int(d["escrowed_in"])

    def sequence(self, pk):
        return int(self.rpc(f"getsequence {pk}")["data"]["sequence_number"])

    def grants(self, pk=None):
        cmd = "getgrants" + (f" {pk}" if pk else "")
        return self.rpc(cmd)["data"]["grants"]

    def standing(self, pk=None):
        cmd = "getstandingpayments" + (f" {pk}" if pk else "")
        return self.rpc(cmd)["data"]["standing_payments"]

    def route(self, pk):
        return self.rpc(f"getreceiveroute {pk}")["data"]["route"]

    def payout(self, pid):
        return self.rpc(f"getpayoutrule {pid}")["data"]["payout_rule"]

    def mempool_len(self):
        return len(self.rpc("getmempool")["data"].get("transactions") or [])

    def txstatus(self, tx_hash):
        return self.rpc(f"gettxstatus {tx_hash}").get("data") or {}


class Signer:
    def __init__(self, keys, tree, chain_id):
        sys.path.insert(0, tree)
        from consensus.tx_signing import signing_message_bytes
        from tau_testnet_cli import tx as cli_tx
        self.keys = keys
        self._msg = signing_message_bytes
        self.tx = cli_tx
        self.chain_id = chain_id

    def pk(self, name):
        return self.keys[name]["pk"]

    def sign(self, name, payload):
        digest = hashlib.sha256(self._msg(payload)).digest()
        payload["signature"] = _bls().Sign(int(self.keys[name]["sk"], 16), digest).hex()
        return payload

    def submit(self, node, payload):
        return node.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")

    def _envelope(self, node, name):
        d = node.rpc(f"getsequence {self.pk(name)}")["data"]
        return int(d["sequence_number"]), int(d["tip_height"])

    def _base(self, node, name, tx_type):
        seq, tip = self._envelope(node, name)
        return {
            "tx_type": tx_type,
            "sender_pubkey": self.pk(name),
            "sequence_number": seq,
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": tip + 1000,
            "fee_limit": "10000",
            "chain_id": self.chain_id,
        }

    def transfer(self, node, name, to, amount):
        payload = self._base(node, name, "user_tx")
        payload["operations"] = {"1": [[self.pk(name), self.pk(to), str(amount)]]}
        return self.submit(node, self.sign(name, payload))

    def grant_create(self, node, name, to, amount=5000, spend_cap=500,
                     per_payment_cap=500):
        payload = self._base(node, name, "grant_create")
        now = int(time.time())
        payload.update({
            "grantee_pubkey": self.pk(to),
            "refund_to": self.pk(name),
            "amount": amount,
            "period_kind": 2,  # PERIOD_WEEK (consensus/periods.py)
            "period_anchor": 0,
            "spend_cap": spend_cap,
            "per_payment_cap": per_payment_cap,
            "start_at": now,
            "expires_at": now + 28 * DAY,
        })
        return self.submit(node, self.sign(name, payload))

    def grant_draw(self, node, name, grant_id, amount):
        payload = self._base(node, name, "grant_draw")
        payload.update({"grant_id": grant_id, "amount": amount})
        return self.submit(node, self.sign(name, payload))

    def standing_create(self, node, name, to, amount=100):
        payload = self._base(node, name, "standing_payment")
        now = int(time.time())
        payload.update({
            "payee_pubkey": self.pk(to),
            "amount": amount,
            "period_kind": 1,  # PERIOD_DAY (consensus/periods.py)
            "period_anchor": 0,
            "max_fee_per_execution": 10,
            "start_at": now,
        })
        return self.submit(node, self.sign(name, payload))

    def route_set(self, node, name, to, bps=2500, min_incoming=0):
        payload = self._base(node, name, "route_set")
        now = int(time.time())
        payload.update({
            "destination_pubkey": self.pk(to),
            "bps": bps,
            "min_incoming": min_incoming,
            "activate_at": now,
            "expires_at": now + 30 * DAY,
            "locked_until": None,
        })
        return self.submit(node, self.sign(name, payload))

    def payout_create(self, node, name, recipients, clause=CLAUSE,
                      max_per_execution=1000, max_per_period=1000):
        payload = self._base(node, name, "payout_create")
        now = int(time.time())
        payload.update({
            "recipients": [self.pk(r) for r in recipients],
            "clause": clause,
            "max_per_execution": max_per_execution,
            "max_per_period": max_per_period,
            "period_kind": 2,  # PERIOD_WEEK (consensus/periods.py)
            "period_length": None,
            "period_anchor": 0,
            "start_at": now,
            "expires_at": now + 30 * DAY,
            "locked_until": None,
        })
        return self.submit(node, self.sign(name, payload))

    def payout_execute(self, node, name, payout_id):
        payload = self._base(node, name, "payout_execute")
        payload.update({"payout_id": payout_id})
        return self.submit(node, self.sign(name, payload))


def ok(res):
    return res.get("status") == "ok"


def err_code(res):
    return (res.get("error") or {}).get("code")


# --------------------------------------------------------------------------- #
# chain driving and the accounting oracle
# --------------------------------------------------------------------------- #

def produce(node, target_height, *, allow_empty=False, deadline=300):
    """Mine until the canonical head reaches `target_height`; the node's own miner may help."""
    end = time.time() + deadline
    cmd = "createblock allow-empty" if allow_empty else "createblock"
    while time.time() < end and not over_deadline():
        if node.height() >= target_height:
            return True
        try:
            node.rpc(cmd, timeout=300)
        except Exception as exc:
            say(f"  (createblock raised {exc!r})")
        time.sleep(1.0)
    return node.height() >= target_height


def wait_until(pred, what, timeout=180, delay=2.0):
    end = time.time() + timeout
    while time.time() < end and not over_deadline():
        try:
            if pred():
                return True
        except Exception:
            pass
        time.sleep(delay)
    say(f"  (timed out waiting for {what})")
    return False


class Oracle:
    """Expected balance deltas aggregated by address, checked for every address involved."""

    def __init__(self, node, signer, label, addrs):
        self.node, self.signer, self.label = node, signer, label
        self.names = {signer.pk(n): n for n in addrs}
        self.names[signer.pk("miner")] = "miner"
        self.addrs = list(self.names)
        self.before = {a: node.balance(a) for a in self.addrs}
        self.expected = {a: 0 for a in self.addrs}

    def add(self, name, delta):
        self.expected[self.signer.pk(name)] += delta

    def verify(self, step):
        after = {a: self.node.balance(a) for a in self.addrs}
        observed = {self.names[a]: after[a] - self.before[a] for a in self.addrs}
        wanted = {self.names[a]: self.expected[a] for a in self.addrs}
        check(f"{self.label}/{step}: balance deltas by address", observed == wanted,
              f"observed={observed} expected={wanted}")


def ids_of(res):
    return (res.get("data") or {}).get("tx_hash")


def tx_ok(res, label):
    return check(label, ok(res), json.dumps(res)[:200] if not ok(res) else "")


def head_fingerprint(node):
    h = node.head()
    return h["block_hash"], h["header"].get("state_hash"), int(h["header"]["block_number"])


def fresh(prefix):
    return f"{prefix}_sender", f"{prefix}_recipient", f"{prefix}_other"

# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_a(node, sg):
    say("a. credits: plain transfer moves funds, sequence advances")
    s, r, o = fresh("a")
    orc = Oracle(node, sg, "a", (s, r, o))
    seq0 = node.sequence(sg.pk(s))
    amount = 700
    res = sg.transfer(node, s, r, amount)
    tx_ok(res, "a: transfer admitted")
    tx_hash = ids_of(res)
    check("a: transfer mined", produce(node, node.height() + 1))
    orc.add(s, -(amount + BASE_FEE)); orc.add(r, amount); orc.add("miner", BASE_FEE)
    orc.verify("after transfer")
    check("a: sender sequence advanced by the transfer",
          node.sequence(sg.pk(s)) == seq0 + 1, node.sequence(sg.pk(s)))
    st = node.txstatus(tx_hash)
    check("a: gettxstatus reports the transfer confirmed",
          st.get("status") == "confirmed", st)


def scenario_b(node, sg):
    say("b. grants: create escrows, draw pays the grantee")
    g, r, o = fresh("b")
    orc = Oracle(node, sg, "b", (g, r, o))
    seq0 = node.sequence(sg.pk(g))
    amount = 5000
    res = sg.grant_create(node, g, r, amount=amount)
    tx_ok(res, "b: grant_create admitted")
    check("b: grant_create mined", produce(node, node.height() + 1))
    check("b: getgrants lists the open grant",
          wait_until(lambda: len(node.grants(sg.pk(g))) == 1, "grant visible", 180))
    row = node.grants(sg.pk(g))[0]
    check("b: grant row carries the agreed terms",
          row["amount"] == amount and row["grantee_pubkey"] == sg.pk(r)
          and row["granter_pubkey"] == sg.pk(g), row)
    gid = row["grant_id"]
    orc.add(g, -(amount + BASE_FEE)); orc.add("miner", BASE_FEE)
    orc.verify("after create")
    out, inn = node.acct(sg.pk(g)); _, r_in = node.acct(sg.pk(r))
    check("b: granter escrowed_out == amount", out == amount, out)
    check("b: grantee escrowed_in == amount", r_in == amount, r_in)
    check("b: granter sequence advanced by the create",
          node.sequence(sg.pk(g)) == seq0 + 1, node.sequence(sg.pk(g)))

    draw = 500
    res = sg.grant_draw(node, r, gid, draw)
    tx_ok(res, "b: grant_draw admitted")
    check("b: grant_draw mined", produce(node, node.height() + 1))
    # grant_draw is fee-exempt by design (only grant_create bears a fee),
    # so the grantee receives the full draw and the miner gains nothing.
    orc.add(r, draw)
    orc.verify("after draw")
    out, _ = node.acct(sg.pk(g)); _, r_in = node.acct(sg.pk(r))
    check("b: escrow drops to the remainder after the draw",
          out == amount - draw and r_in == amount - draw, (out, r_in))
    row = node.grants(sg.pk(g))[0]
    check("b: grant still open after a partial draw",
          row["grant_id"] == gid, row)
    return gid


def scenario_c(node, sg):
    say("c. standing payments: create sweeps the current period once")
    p, r, o = fresh("c")
    orc = Oracle(node, sg, "c", (p, r, o))
    seq0 = node.sequence(sg.pk(p))
    amount = 100
    res = sg.standing_create(node, p, r, amount=amount)
    tx_ok(res, "c: standing_payment admitted")
    check("c: standing_payment mined", produce(node, node.height() + 1))
    check("c: getstandingpayments lists the open schedule",
          wait_until(lambda: len(node.standing(sg.pk(p))) == 1, "standing visible", 180))
    row = node.standing(sg.pk(p))[0]
    check("c: standing row carries the agreed terms",
          row["amount"] == amount and row["payee_pubkey"] == sg.pk(r)
          and row["payer_pubkey"] == sg.pk(p), row)
    # The sweep executes the current period at create: the payee is paid
    # once immediately. The payer bears two fees: the create fee (BASE_FEE)
    # plus the sweep execution's fee (max_fee_per_execution = BASE_FEE here),
    # charged by design; the miner receives both.
    orc.add(p, -(amount + 2 * BASE_FEE)); orc.add(r, amount); orc.add("miner", 2 * BASE_FEE)
    orc.verify("after create (first-period sweep)")
    check("c: schedule executed exactly once in its first period",
          int(row.get("executions", 0)) == 1, row)
    check("c: payer sequence advanced by the create",
          node.sequence(sg.pk(p)) == seq0 + 1, node.sequence(sg.pk(p)))

    say("   mining on: no second execution inside the same period")
    check("c: chain advances without a second sweep",
          produce(node, node.height() + 3, allow_empty=True))
    orc.verify("after more blocks (still one execution)")
    row = node.standing(sg.pk(p))[0]
    check("c: executions still 1 after more blocks in the period",
          int(row.get("executions", 0)) == 1, row)
    return row["standing_id"]


def scenario_d(node, sg):
    say("d. receive routes: an incoming credit splits to the destination")
    a, r, o = fresh("d")
    orc = Oracle(node, sg, "d", (a, r, o))
    seq0 = node.sequence(sg.pk(a))
    res = sg.route_set(node, a, r, bps=2500)
    tx_ok(res, "d: route_set admitted")
    check("d: route_set mined", produce(node, node.height() + 1))
    check("d: getreceiveroute shows the route",
          wait_until(lambda: node.route(sg.pk(a)) is not None, "route visible", 180))
    row = node.route(sg.pk(a))
    check("d: route row carries the agreed terms",
          row["destination_pubkey"] == sg.pk(r) and int(row["bps"]) == 2500, row)
    orc.add(a, -BASE_FEE); orc.add("miner", BASE_FEE)
    orc.verify("after route_set")
    check("d: account sequence advanced by the route_set",
          node.sequence(sg.pk(a)) == seq0 + 1, node.sequence(sg.pk(a)))

    # A third party pays the routed account 1000: 750 stays, 250 routes on.
    orc2 = Oracle(node, sg, "d", (o, a, r))
    res = sg.transfer(node, o, a, 1000)
    tx_ok(res, "d: transfer to the routed account admitted")
    check("d: transfer mined", produce(node, node.height() + 1))
    orc2.add(o, -(1000 + BASE_FEE)); orc2.add(a, 750); orc2.add(r, 250)
    orc2.add("miner", BASE_FEE)
    orc2.verify("after split transfer")
    row = node.route(sg.pk(a))
    check("d: route unchanged by the split transfer",
          row["destination_pubkey"] == sg.pk(r) and int(row["bps"]) == 2500, row)


def scenario_e(node, sg):
    say("e. payout rules: create + clause execute splits 300/700, cap blocks a repeat")
    p, r1, r2 = "e_sender", "e_recipient", "e_other"
    orc = Oracle(node, sg, "e", (p, r1, r2))
    seq0 = node.sequence(sg.pk(p))
    res = sg.payout_create(node, p, (r1, r2))
    tx_ok(res, "e: payout_create admitted")
    check("e: payout_create mined", produce(node, node.height() + 1))
    check("e: getpayoutrule lists the open rule",
          wait_until(lambda: len(node.rpc("getpayoutrule")["data"]["payout_rules"]) >= 1,
                     "payout rule visible", 180))
    rows = node.rpc("getpayoutrule")["data"]["payout_rules"]
    row = [x for x in rows if x["payer_pubkey"] == sg.pk(p)][0]
    pid = row["payout_id"]
    check("e: payout row carries the agreed recipients",
          list(row["recipients"]) == [sg.pk(r1), sg.pk(r2)], row)
    orc.add(p, -BASE_FEE); orc.add("miner", BASE_FEE)
    orc.verify("after create (a rule holds no escrow)")
    check("e: payer sequence advanced by the create",
          node.sequence(sg.pk(p)) == seq0 + 1, node.sequence(sg.pk(p)))

    res = sg.payout_execute(node, p, pid)
    tx_ok(res, "e: payout_execute admitted")
    check("e: payout_execute mined", produce(node, node.height() + 1))
    orc.add(p, -(1000 + BASE_FEE)); orc.add(r1, 300); orc.add(r2, 700)
    orc.add("miner", BASE_FEE)
    orc.verify("after execute (300/700)")
    row = node.payout(pid)
    check("e: rule still open after execution within its period cap",
          row is not None and row["payout_id"] == pid, row)

    say("   executing again in the same period: the cap must pay nothing")
    res = sg.payout_execute(node, p, pid)
    tx_ok(res, "e: second payout_execute admitted")
    check("e: second payout_execute mined", produce(node, node.height() + 1))
    # The cap-skipped second execute is rejected, and rejected txs pay no
    # fee -- so neither the payer nor the miner moves on this execute.
    orc.verify("after second execute (cap-skipped: no payout, no fee)")
    return pid


def scenario_f(node1, node2, sg, ids):
    say("f. restart + second node: books survive, follower agrees")
    gid, sid, pid = ids
    # node1 was already restarted with its miner enabled before scenario c;
    # the books must still be there after that restart.
    check("f: grant survives the node1 restart",
          any(r["grant_id"] == gid for r in node1.grants()))
    check("f: standing schedule survives the node1 restart",
          any(r["standing_id"] == sid for r in node1.standing()))
    check("f: payout rule survives the node1 restart",
          node1.payout(pid) is not None)

    # Live traffic while node2 is connected: a credit to a routed account
    # must gossip and split identically on both nodes.
    s, r, o = fresh("f")
    res = sg.transfer(node1, s, r, 500)
    tx_ok(res, "f: transfer admitted on node1")
    check("f: transfer mined on node1", produce(node1, node1.height() + 1))

    target = head_fingerprint(node1)
    check("f: node2 reaches node1's head",
          wait_until(lambda: head_fingerprint(node2) == target, "head agreement", 420, 3.0),
          f"node1={target} node2={head_fingerprint(node2)}")
    check("f: head state hash agrees", head_fingerprint(node2)[1] == target[1])
    pks = [sg.pk(n) for n in ACTORS]
    check("f: all balances agree",
          all(node1.balance(p) == node2.balance(p) for p in pks))
    check("f: all escrow totals agree", all(node1.acct(p) == node2.acct(p) for p in pks))
    check("f: all sequences agree", all(node1.sequence(p) == node2.sequence(p) for p in pks))
    check("f: grants agree",
          node1.grants() == node2.grants(),
          f"node1={node1.grants()} node2={node2.grants()}")
    check("f: standing payments agree",
          node1.standing() == node2.standing())
    check("f: receive routes agree",
          all(node1.route(p) == node2.route(p) for p in pks))
    check("f: payout rules agree",
          node1.rpc("getpayoutrule")["data"]["payout_rules"]
          == node2.rpc("getpayoutrule")["data"]["payout_rules"])


# --------------------------------------------------------------------------- #

def stop_all():
    for node in STARTED:
        try:
            node.stop()
        except Exception as exc:
            say(f"[{node.name}] stop failed: {exc!r}")


def run(base, log_dir, deadline):
    base = os.path.abspath(base)
    DEADLINE[0] = time.time() + deadline
    keys = json.load(open(os.path.join(base, "keys.json")))
    log1 = os.path.join(log_dir, "payments-e2e-node1-run.log")
    log2 = os.path.join(log_dir, "payments-e2e-node2-run.log")
    node1 = Node("node1", base, keys, log1, mining=False)
    node2 = Node("node2", base, keys, log2, mining=False)

    assert_isolated(base, node1.paths() + node2.paths())
    for node in (node1, node2):
        if os.path.exists(node.db_path):
            raise SystemExit(f"REFUSING: {node.db_path} already exists; re-provision for a clean run")
    footprint = main_footprint()
    atexit.register(stop_all)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: sys.exit(130))

    sg = Signer(keys, node1.tree, None)
    try:
        node1.start()
        if not node1.wait_ready():
            say("node1 did not become ready")
            return 2
        check("node1 database is the isolated one", os.path.exists(node1.db_path), node1.db_path)
        sg.chain_id = node1.chain_id()
        say(f"chain_id (genesis hash): {sg.chain_id[:16]}...")
        # Blocks are explicit while the miner is off, so each flow is
        # observable step by step.
        scenario_a(node1, sg)
        gid = scenario_b(node1, sg)
        scenario_d(node1, sg)
        pid = scenario_e(node1, sg)

        say("restarting node1 with its own miner enabled")
        node1.stop()
        node1.mining = True
        node1.start()
        if not node1.wait_ready():
            say("node1 did not become ready with mining enabled")
            return 2
        sid = scenario_c(node1, sg)

        node1.peer_id = node1.peer_id or node1._peer_id()
        node2.bootstrap = [{"peer_id": node1.peer_id,
                            "addrs": [f"/ip4/127.0.0.1/tcp/{node1.p2p_port}"]}]
        say(f"node2 bootstrap: {node2.bootstrap}")
        node2.start()
        if not node2.wait_ready():
            say("node2 did not become ready")
            return 2
        check("node2 database is the isolated one", os.path.exists(node2.db_path), node2.db_path)
        scenario_f(node1, node2, sg, (gid, sid, pid))
    finally:
        stop_all()

    check("main repository data/ and node.db untouched", main_footprint() == footprint)
    say("")
    if FAILED:
        say(f"{len(FAILED)} check(s) FAILED:")
        for name in FAILED:
            say(f"  - {name}")
        return 1
    say("All checks passed.")
    return 0


def require_native():
    probe = subprocess.run(
        [PYTHON, "-c", "import tau_native; assert tau_native.load_tau_module() is not None"],
        cwd=REPO, env=dict(os.environ, PYTHONPATH=os.pathsep.join([REPO, NATIVE])),
        capture_output=True, text=True)
    if probe.returncode != 0:
        raise SystemExit("native tau binding not importable: set TAU_NATIVE_PATH (or PYTHONPATH) "
                         "to the directory holding the built tau module\n" + probe.stderr[-400:])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["provision", "run"])
    parser.add_argument("--dir", default=os.path.join(REPO, ".local", "payments-e2e"))
    parser.add_argument("--log-dir", default=os.path.join(REPO, ".local"))
    parser.add_argument("--overlay-worktree", action="store_true",
                        help="provision: also copy uncommitted tracked edits over the exported HEAD")
    parser.add_argument("--deadline", type=int, default=3000, help="overall seconds")
    args = parser.parse_args(argv)
    os.makedirs(args.log_dir, exist_ok=True)
    if args.mode == "provision":
        return provision(args.dir, args.overlay_worktree)
    require_native()
    return run(args.dir, args.log_dir, args.deadline)


if __name__ == "__main__":
    raise SystemExit(main())
