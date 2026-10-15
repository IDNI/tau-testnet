#!/usr/bin/env python3
"""End-to-end retractable transfers against REAL, disposable node processes.

tests/test_retractable_*.py mock the engine; this drives live nodes with the
NATIVE one, so it exercises what only exists at runtime: the real fee rule, the
miner's idle wake sealing a timed release, the book surviving a restart and a
second node reproducing the same state from the first node's blocks.

Every node runs from its own tree under --dir (exported from `git archive HEAD`,
so it tests committed code) with its own keys, genesis, database and ports. The
harness refuses to start when any node data path resolves outside its own tree
or inside the main repository's data/ or root.

USAGE
    python scripts/e2e_retractable.py provision --dir .local/retract-e2e
    python scripts/e2e_retractable.py run --dir .local/retract-e2e

`run` starts node1 (miner), drives scenarios a-e, then starts node2 (follower)
for scenario f, and stops exactly the processes it started.

ASSERTION DISCIPLINE
    Each scenario asserts an accounting oracle -- expected balance deltas
    aggregated per address, escrow totals, terminal status and sequence numbers
    -- never one createblock response: the node's own miner races every
    explicit mine, so the chain is awaited, not the call.
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
NETWORK_ID = "tau-retract-e2e"
BASE_FEE = 10
FUNDS = 1_000_000
# Ports above 65535 are invalid, so the block sits at 647xx. The WS server scans RPC+1..+9, so RPC ports are spaced and p2p ports sit
# outside every scan range.
RPC_PORTS = {"node1": 64710, "node2": 64720}
P2P_PORTS = {"node1": 64730, "node2": 64740}
PORT_MIN, PORT_MAX = 64710, 64790
SCENARIOS = ("a", "b", "c", "d", "e", "f")
ROLES = ("sender", "recipient", "other")
ACTORS = ("miner",) + tuple(f"{s}_{r}" for s in SCENARIOS for r in ROLES) + ("pad1", "pad2")

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
        sk = bls.KeyGen(hashlib.sha256(f"retract-e2e-{name}".encode()).digest())
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
            "TAU_AUTO_FAUCET": "false",
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

    def balance(self, pk):
        return int(self.rpc(f"getbalance {pk}")["data"]["balance"])

    def acct(self, pk):
        d = self.rpc(f"getaccountstate {pk}")["data"]
        return int(d["escrowed_out"]), int(d["escrowed_in"])

    def sequence(self, pk):
        return int(self.rpc(f"getsequence {pk}")["data"]["sequence_number"])

    def retractable(self, rid):
        r = self.rpc(f"getretractable {rid}")
        return r.get("data") if r.get("status") == "ok" else None

    def open_ids(self, pk, role="all"):
        d = self.rpc(f"getretractables {pk} {role}")["data"]
        return sorted(r["retractable_id"] for r in d["retractables"])

    def mempool_len(self):
        return len(self.rpc("getmempool")["data"].get("transactions") or [])

    def txstatus(self, tx_hash):
        return self.rpc(f"gettxstatus {tx_hash}").get("data") or {}


class Signer:
    def __init__(self, keys, tree):
        sys.path.insert(0, tree)
        from consensus.tx_signing import signing_message_bytes
        from tau_testnet_cli import tx as cli_tx
        self.keys = keys
        self._msg = signing_message_bytes
        self.tx = cli_tx

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

    def park(self, node, name, to, amount, *, at_height=None, at_time=None):
        seq, tip = self._envelope(node, name)
        payload = self.tx.build_retractable_transfer_tx(
            sender_pubkey=self.pk(name), sequence_number=seq,
            expiration_time=int(time.time()) + 3600, expire_at_height=tip + 1000,
            recipient_pubkey=self.pk(to), amount=amount,
            release_at_height=at_height, release_at_time=at_time, fee_limit="10000")
        rid = node.rpc("getretractableid '" + json.dumps(payload) + "'")["data"]["retractable_id"]
        res = self.submit(node, self.sign(name, payload))
        return res, rid

    def retract(self, node, name, rid):
        seq, tip = self._envelope(node, name)
        payload = self.tx.build_retract_transfer_tx(
            sender_pubkey=self.pk(name), sequence_number=seq,
            expiration_time=int(time.time()) + 3600, expire_at_height=tip + 1000,
            retractable_id=rid, fee_limit="0")
        return self.submit(node, self.sign(name, payload))

    def transfer(self, node, name, to, amount):
        seq, tip = self._envelope(node, name)
        payload = {"tx_type": "user_tx", "sender_pubkey": self.pk(name), "sequence_number": seq,
                   "expiration_time": int(time.time()) + 3600, "expire_at_height": tip + 1000,
                   "fee_limit": "10000",
                   "operations": {"1": [[self.pk(name), self.pk(to), str(amount)]]}}
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


def confirm_status(node, rid, status, timeout=180):
    return wait_until(lambda: (node.retractable(rid) or {}).get("status") == status,
                      f"{rid[:12]} -> {status}", timeout)


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def fresh(prefix):
    return f"{prefix}_sender", f"{prefix}_recipient", f"{prefix}_other"


def scenario_a(node, sg):
    say("a. height park -> retract before release -> refund")
    s, r, o = fresh("a")
    orc = Oracle(node, sg, "a", (s, r, o))
    seq0 = node.sequence(sg.pk(s))
    amount = 700
    release = node.height() + 6
    res, rid = sg.park(node, s, r, amount, at_height=release)
    tx_ok(res, "a: park admitted")
    park_hash = ids_of(res)
    check("a: park admitted into the mempool as an escrow, not yet spent", node.mempool_len() == 1)
    park_height = node.height() + 1
    check("a: park mined", produce(node, park_height))
    confirm_status(node, rid, "open")
    orc.add(s, -(amount + BASE_FEE)); orc.add("miner", BASE_FEE)
    orc.verify("after park")
    out, inn = node.acct(sg.pk(s)); _, r_in = node.acct(sg.pk(r))
    check("a: sender escrowed_out == amount", out == amount, out)
    check("a: recipient escrowed_in == amount", r_in == amount, r_in)
    check("a: open set lists the entry", node.open_ids(sg.pk(s), "out") == [rid]
          and node.open_ids(sg.pk(r), "in") == [rid])
    row = node.retractable(rid)
    check("a: getretractable open at the release height",
          row and row["status"] == "open" and row.get("release_at_height") == release, row)
    st = node.txstatus(park_hash)
    check("a: gettxstatus reports the park open", (st.get("retractable") or {}) == {"id": rid, "status": "open"}, st)
    check("a: sender sequence advanced by the park", node.sequence(sg.pk(s)) == seq0 + 1,
          node.sequence(sg.pk(s)))

    res = sg.retract(node, s, rid)
    tx_ok(res, "a: retract admitted")
    retract_hash = ids_of(res)
    check("a: retract mined", produce(node, node.height() + 1))
    confirm_status(node, rid, "retracted")
    orc.add(s, amount)
    orc.verify("after retract")
    out, _ = node.acct(sg.pk(s)); _, r_in = node.acct(sg.pk(r))
    check("a: escrow back to zero on both ends", out == 0 and r_in == 0, (out, r_in))
    row = node.retractable(rid)
    check("a: terminal status retracted", row and row["status"] == "retracted", row)
    check("a: gettxstatus park -> retracted",
          (node.txstatus(park_hash).get("retractable") or {}).get("status") == "retracted")
    check("a: gettxstatus retract names its target",
          node.txstatus(retract_hash).get("retracts") == rid, node.txstatus(retract_hash))
    check("a: sender sequence advanced by park and retract", node.sequence(sg.pk(s)) == seq0 + 2,
          node.sequence(sg.pk(s)))

    say("   advancing past the release point: a retracted entry must never release")
    check("a: chain passes R", produce(node, release + 1, allow_empty=True))
    orc.verify("after R")
    check("a: still retracted", (node.retractable(rid) or {}).get("status") == "retracted")
    return rid


def scenario_b(node, sg):
    say("b. height park -> chain advances -> released at the first block >= R")
    s, r, o = fresh("b")
    orc = Oracle(node, sg, "b", (s, r, o, "pad1", "pad2"))
    seq0 = node.sequence(sg.pk(s))
    amount = 900
    tip = node.height()
    release = tip + 4
    res, rid = sg.park(node, s, r, amount, at_height=release)
    tx_ok(res, "b: park admitted")
    check("b: park mined", produce(node, tip + 1))
    orc.add(s, -(amount + BASE_FEE)); orc.add("miner", BASE_FEE)
    confirm_status(node, rid, "open")
    orc.verify("after park")

    fee_txs = 0
    for k, h in enumerate((tip + 2, tip + 3)):
        res = sg.transfer(node, "pad1", "pad2", 5)
        tx_ok(res, f"b: unrelated transfer {k + 1} admitted")
        check(f"b: block {h} mined", produce(node, h))
        orc.add("pad1", -(5 + BASE_FEE)); orc.add("pad2", 5); orc.add("miner", BASE_FEE)
        row = node.retractable(rid)
        check(f"b: still open at height {h} < R={release}", row and row["status"] == "open", row)
        orc.verify(f"at height {h}")
        check(f"b: recipient not yet paid at height {h}", node.balance(sg.pk(r)) == orc.before[sg.pk(r)])

    res = sg.transfer(node, "pad1", "pad2", 5)
    tx_ok(res, "b: third unrelated transfer admitted")
    check("b: release block mined", produce(node, release))
    check("b: head is exactly R", node.height() == release, node.height())
    orc.add("pad1", -(5 + BASE_FEE)); orc.add("pad2", 5); orc.add("miner", BASE_FEE)
    orc.add(r, amount)
    confirm_status(node, rid, "released")
    orc.verify("after release")
    row = node.retractable(rid)
    check("b: released at the first block >= R", row and row.get("resolved_at_height") == release, row)
    out, _ = node.acct(sg.pk(s)); _, r_in = node.acct(sg.pk(r))
    check("b: escrow drained", out == 0 and r_in == 0, (out, r_in))
    check("b: sender sequence advanced once", node.sequence(sg.pk(s)) == seq0 + 1)
    check("b: pad1 sequence advanced three times", node.sequence(sg.pk("pad1")) >= 3)
    return rid


def scenario_c(node, sg):
    say("c. time park on an idle node -> the miner wake seals the release")
    s, r, o = fresh("c")
    orc = Oracle(node, sg, "c", (s, r, o))
    seq0 = node.sequence(sg.pk(s))
    amount = 1100
    release = int(time.time()) + 60
    res, rid = sg.park(node, s, r, amount, at_time=release)
    tx_ok(res, "c: park admitted")
    park_height = node.height() + 1
    check("c: park mined", produce(node, park_height))
    confirm_status(node, rid, "open")
    orc.add(s, -(amount + BASE_FEE)); orc.add("miner", BASE_FEE)
    orc.verify("after park")
    check("c: mempool empty (idle node)", node.mempool_len() == 0)
    say(f"   idle until {release} (no createblock, no traffic); wake must seal the release")
    t0 = time.time()
    done = wait_until(lambda: (node.retractable(rid) or {}).get("status") == "released",
                      "the wake to seal the release", timeout=240, delay=2.0)
    check("c: released with no other traffic", done, f"after {time.time() - t0:.0f}s")
    time.sleep(8)
    head = node.head()
    check("c: exactly one block sealed after the park", node.height() == park_height + 1, node.height())
    check("c: the wake block is empty", (head.get("transactions") or []) == []
          and (head.get("tx_ids") or []) == [], head.get("tx_ids"))
    ts = int(head["header"]["timestamp"])
    check("c: release block timestamp >= release time", ts >= release, f"ts={ts} release={release}")
    orc.add(r, amount)
    orc.verify("after wake release")
    out, _ = node.acct(sg.pk(s)); _, r_in = node.acct(sg.pk(r))
    check("c: escrow drained", out == 0 and r_in == 0, (out, r_in))
    row = node.retractable(rid)
    check("c: terminal status released", row and row["status"] == "released", row)
    check("c: sender sequence advanced once", node.sequence(sg.pk(s)) == seq0 + 1)
    return rid


def scenario_d(node, sg):
    say("d. retract after the release point is refused; funds stay with the recipient")
    s, r, o = fresh("d")
    orc = Oracle(node, sg, "d", (s, r, o))
    seq0 = node.sequence(sg.pk(s))
    amount = 1300
    tip = node.height()
    release = tip + 3
    res, rid = sg.park(node, s, r, amount, at_height=release)
    tx_ok(res, "d: park admitted")
    check("d: park mined", produce(node, tip + 1))
    orc.add(s, -(amount + BASE_FEE)); orc.add("miner", BASE_FEE)
    check("d: block before R mined", produce(node, tip + 2, allow_empty=True))
    check("d: next block is R, entry still open", node.height() + 1 == release
          and (node.retractable(rid) or {}).get("status") == "open")
    res = sg.retract(node, s, rid)
    check("d: retract refused with RETRACT_TOO_LATE", not ok(res) and err_code(res) == "RETRACT_TOO_LATE",
          json.dumps(res)[:240])
    orc.verify("after refused retract")
    check("d: escrow untouched by the refusal", node.acct(sg.pk(s))[0] == amount)

    check("d: release block mined", produce(node, release, allow_empty=True))
    confirm_status(node, rid, "released")
    orc.add(r, amount)
    orc.verify("after release")
    res = sg.retract(node, s, rid)
    check("d: retract after release refused (entry resolved)", not ok(res)
          and err_code(res) == "UNKNOWN_RETRACTABLE", json.dumps(res)[:240])
    orc.verify("after post-release retract attempt")
    out, _ = node.acct(sg.pk(s)); _, r_in = node.acct(sg.pk(r))
    check("d: escrow drained", out == 0 and r_in == 0, (out, r_in))
    check("d: sender sequence advanced once (refusals consume none)",
          node.sequence(sg.pk(s)) == seq0 + 1, node.sequence(sg.pk(s)))
    return rid


def scenario_e(node, sg):
    say("e. restart the node mid-escrow -> book reloads, release still happens")
    s, r, o = fresh("e")
    orc = Oracle(node, sg, "e", (s, r, o))
    seq0 = node.sequence(sg.pk(s))
    amount = 1500
    tip = node.height()
    release = tip + 5
    res, rid = sg.park(node, s, r, amount, at_height=release)
    tx_ok(res, "e: park admitted")
    check("e: park mined", produce(node, tip + 1))
    confirm_status(node, rid, "open")
    orc.add(s, -(amount + BASE_FEE)); orc.add("miner", BASE_FEE)
    orc.verify("before restart")

    snap = {
        "open_out": node.open_ids(sg.pk(s), "out"),
        "open_in": node.open_ids(sg.pk(r), "in"),
        "esc_s": node.acct(sg.pk(s)), "esc_r": node.acct(sg.pk(r)),
        "row": node.retractable(rid),
        "seq": node.sequence(sg.pk(s)),
        "head": node.head()["block_hash"],
        "head_state": node.head()["header"].get("state_hash"),
        "bal": {n: node.balance(sg.pk(n)) for n in (s, r, "miner")},
    }
    say("   stopping node1")
    node.stop()
    node.start()
    check("e: node1 ready after restart", node.wait_ready(), "")
    check("e: same canonical head after restart", node.head()["block_hash"] == snap["head"])
    check("e: head state hash unchanged", node.head()["header"].get("state_hash") == snap["head_state"])
    check("e: open set reloaded (sender out, recipient in)",
          node.open_ids(sg.pk(s), "out") == snap["open_out"] == [rid]
          and node.open_ids(sg.pk(r), "in") == snap["open_in"] == [rid])
    check("e: escrow totals reloaded", node.acct(sg.pk(s)) == snap["esc_s"]
          and node.acct(sg.pk(r)) == snap["esc_r"], (node.acct(sg.pk(s)), node.acct(sg.pk(r))))
    check("e: entry row reloaded identically", node.retractable(rid) == snap["row"], node.retractable(rid))
    check("e: sequence reloaded", node.sequence(sg.pk(s)) == snap["seq"])
    check("e: balances reloaded", {n: node.balance(sg.pk(n)) for n in (s, r, "miner")} == snap["bal"])
    orc.verify("after restart")

    check("e: chain advances to R", produce(node, release, allow_empty=True))
    confirm_status(node, rid, "released")
    orc.add(r, amount)
    orc.verify("after release")
    out, _ = node.acct(sg.pk(s)); _, r_in = node.acct(sg.pk(r))
    check("e: escrow drained", out == 0 and r_in == 0, (out, r_in))
    row = node.retractable(rid)
    check("e: released at R", row and row.get("resolved_at_height") == release, row)
    check("e: sender sequence advanced once", node.sequence(sg.pk(s)) == seq0 + 1)
    return rid


def head_fingerprint(node):
    h = node.head()
    return h["block_hash"], h["header"].get("state_hash"), int(h["header"]["block_number"])


def scenario_f(node1, node2, sg, rids):
    say("f. second node syncs through park + release and agrees")
    s, r, o = fresh("f")
    # live traffic while node2 is connected: park and release gossip
    amount = 1700
    tip = node1.height()
    release = tip + 3
    res, rid = sg.park(node1, s, r, amount, at_height=release)
    tx_ok(res, "f: park admitted on node1")
    check("f: park mined on node1", produce(node1, tip + 1))
    confirm_status(node1, rid, "open")
    check("f: node2 sees the open entry (gossip/sync)",
          wait_until(lambda: (node2.retractable(rid) or {}).get("status") == "open", "node2 open", 240))
    check("f: node1 reaches R", produce(node1, release, allow_empty=True))
    confirm_status(node1, rid, "released")
    rids = list(rids) + [rid]

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
    for i, x in enumerate(rids):
        a, b = node1.retractable(x), node2.retractable(x)
        check(f"f: entry {x[:10]} status agrees", a == b, f"node1={a} node2={b}")
    check("f: no open entries remain on either node",
          all(node1.acct(p)[0] == 0 and node2.acct(p)[0] == 0 for p in pks))


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
    log1 = os.path.join(log_dir, "retract-e2e-node1-run.log")
    log2 = os.path.join(log_dir, "retract-e2e-node2-run.log")
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

    sg = Signer(keys, node1.tree)
    try:
        node1.start()
        if not node1.wait_ready():
            say("node1 did not become ready")
            return 2
        check("node1 database is the isolated one", os.path.exists(node1.db_path), node1.db_path)
        # Blocks are explicit while the miner is off, so the window before a
        # release point is observable; the miner's own wake would seal it first.
        rids = [scenario_a(node1, sg), scenario_b(node1, sg),
                scenario_d(node1, sg), scenario_e(node1, sg)]

        say("restarting node1 with its own miner enabled")
        node1.stop()
        node1.mining = True
        node1.start()
        if not node1.wait_ready():
            say("node1 did not become ready with mining enabled")
            return 2
        rids.append(scenario_c(node1, sg))

        node1.peer_id = node1.peer_id or node1._peer_id()
        node2.bootstrap = [{"peer_id": node1.peer_id,
                            "addrs": [f"/ip4/127.0.0.1/tcp/{node1.p2p_port}"]}]
        say(f"node2 bootstrap: {node2.bootstrap}")
        node2.start()
        if not node2.wait_ready():
            say("node2 did not become ready")
            return 2
        check("node2 database is the isolated one", os.path.exists(node2.db_path), node2.db_path)
        scenario_f(node1, node2, sg, rids)
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
    parser.add_argument("--dir", default=os.path.join(REPO, ".local", "retract-e2e"))
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
