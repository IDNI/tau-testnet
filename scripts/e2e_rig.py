#!/usr/bin/env python3
"""Two live nodes for end-to-end scripts that need a miner and a follower.

Used by the e2e scripts of the payment features and of rules in force. It builds on
scripts/e2e_authority.py the way scripts/e2e_rule_changes.py does (node
processes, signing, the block relay through NetworkService._ingest_blocks) and
adds what those scenarios need:

- an accounting oracle: expected balance deltas per address, fees to the miner
  included, checked against the node after each step;
- empty blocks on request (`createblock allow-empty`), so a due point is reached
  without traffic;
- the miner's own idle wake (node A restarted with mining enabled);
- a restart of node A, and node B replaying A's blocks, restarting, and ending
  with the same state hash and the same answers to every read the script names.

Node A mines and is driven through its RPC port and the `tau-testnet` CLI; node
B runs the same validator key with mining off and only ever receives A's blocks.
Every node runs from its own tree exported from the working tree, with its own
genesis, database and ports. The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
sys.path.insert(0, HERE)
os.environ.setdefault(
    "TAU_NATIVE_PATH", "/Users/ak/idni/tau-lang/build/release/bindings/python/nanobind")

import e2e_authority as base  # noqa: E402

FAILED: list[str] = []
BASE_FEE = base.BASE_FEE
FUNDS = 1_000_000
FEE_LIMIT = "1000"

# Fields a read carries that depend on when it is asked, not on the chain.
VOLATILE = {"tip_height", "now", "server_time", "as_of_time", "elapsed_ms", "queued",
            "mempool", "pending", "in_mempool"}


def say(msg=""):
    print(f"[e2e] {msg}", flush=True)


def check(label, condition, detail=""):
    if condition:
        say(f"  PASS  {label}")
    else:
        FAILED.append(label)
        say(f"  FAIL  {label} {str(detail)[:600]}")
    return bool(condition)


def stable(value):
    """A read with the fields that depend on the moment of asking removed."""
    if isinstance(value, dict):
        return {k: stable(v) for k, v in value.items() if k not in VOLATILE}
    if isinstance(value, list):
        return [stable(v) for v in value]
    return value


# --------------------------------------------------------------------------- #
# provisioning
# --------------------------------------------------------------------------- #

def _export_env():
    """Keep the export from recursing into .local/ when --dir lives there."""
    exclude = os.path.join(tempfile.mkdtemp(prefix="e2e-excl-"), "excludes")
    with open(exclude, "w") as fh:
        fh.write(".local/\n")
    os.environ.update({
        "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "core.excludesFile",
        "GIT_CONFIG_VALUE_0": exclude,
    })


def provision(root: str, network_id: str, actors: tuple, funded: dict | None = None,
              approval_slots: bool = False) -> int:
    """Two trees (nodeA, nodeB), keys.json and one genesis with `miner` as the
    only validator. `funded` maps actor -> genesis balance (default: every
    actor but the miner gets FUNDS). `approval_slots` activates approval slots
    from block 0 (needed for rule-change guards and votes)."""
    root = os.path.abspath(root)
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    _export_env()
    base.ACTORS = actors
    base.NETWORK_ID = network_id
    keys = base.make_keys()
    with open(os.path.join(root, "keys.json"), "w") as fh:
        json.dump({"network_id": network_id,
                   "keys": {n: {"sk": format(k["sk"], "064x"), "pk": k["pk"]}
                            for n, k in keys.items()}}, fh, indent=2)
    tree_a, tree_b = os.path.join(root, "nodeA"), os.path.join(root, "nodeB")
    say(f"Exporting the working tree into {tree_a} and {tree_b}")
    base.export_worktree(REPO, tree_a)
    base.export_worktree(REPO, tree_b)
    if funded is None:
        funded = {n: FUNDS for n in actors if n != "miner"}
    if approval_slots:
        cmd = [base.PYTHON, "scripts/gen_genesis.py", "--base-fee", str(BASE_FEE),
               "--network-id", network_id, "--approval-slots",
               "--validator-privkey", format(keys["miner"]["sk"], "064x"),
               "--out", "data/genesis.json"]
        for name, balance in funded.items():
            cmd += ["--account", f"{keys[name]['pk']}:{balance}"]
        os.makedirs(os.path.join(tree_a, "data"), exist_ok=True)
        subprocess.run(cmd, cwd=tree_a, check=True, capture_output=True)
    else:
        base.make_genesis(tree_a, keys, validators=("miner",), accounts=funded)
    os.makedirs(os.path.join(tree_b, "data"), exist_ok=True)
    shutil.copy2(os.path.join(tree_a, "data", "genesis.json"),
                 os.path.join(tree_b, "data", "genesis.json"))
    say(f"Provisioned: one validator, {len(funded)} funded accounts.")
    return 0


# --------------------------------------------------------------------------- #
# the rig
# --------------------------------------------------------------------------- #

_TAKEN: list[int] = []


def _port_block():
    import socket
    while True:
        start = base.free_port()
        if start + 16 > 65535 or any(abs(start - t) < 32 for t in _TAKEN):
            continue
        ok = True
        for port in range(start, start + 16):
            with socket.socket() as sock:
                try:
                    sock.bind(("127.0.0.1", port))
                except OSError:
                    ok = False
                    break
        if ok:
            _TAKEN.append(start)
            return start


class Oracle:
    """Expected balance deltas by address, from the moment it is made."""

    def __init__(self, rig, label, names):
        self.rig, self.label = rig, label
        self.names = tuple(dict.fromkeys(tuple(names) + ("miner",)))
        self.before = {n: rig.balance(n) for n in self.names}
        self.expected = {n: 0 for n in self.names}

    def add(self, name, delta):
        self.expected[name] += delta

    def fee(self, payer, fee=BASE_FEE):
        self.add(payer, -fee)
        self.add("miner", fee)

    def move(self, src, dst, amount):
        self.add(src, -amount)
        self.add(dst, amount)

    def verify(self, step):
        seen = {n: self.rig.balance(n) - self.before[n] for n in self.names}
        return check(f"{self.label}: balances after {step}", seen == self.expected,
                     f"seen={seen} expected={self.expected}")


class Rig:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        raw = json.load(open(os.path.join(self.root, "keys.json")))
        base.NETWORK_ID = raw["network_id"]
        self.keys = {n: {"sk": int(k["sk"], 16), "pk": k["pk"]} for n, k in raw["keys"].items()}
        self.pk = {n: k["pk"] for n, k in self.keys.items()}
        self.name_of = {k["pk"]: n for n, k in self.keys.items()}
        self.tree_a = os.path.join(self.root, "nodeA")
        self.tree_b = os.path.join(self.root, "nodeB")
        # A node's websocket server probes upward from its RPC port, so each
        # node's ports sit in their own block of 16.
        ports = [_port_block() for _ in range(2)]
        self.a = base.Node("A", self.tree_a, self.keys, "miner", wrapper=True,
                           rpc_port=ports[0], p2p_port=ports[0] + 8)
        self.b = base.Node("B", self.tree_b, self.keys, "miner", wrapper=True,
                           rpc_port=ports[1], p2p_port=ports[1] + 8)
        self.t0 = time.time()

    # -- lifecycle ------------------------------------------------------------

    def start(self):
        for node in (self.a, self.b):
            node.start()
            say(f"node {node.name} pid={node.proc.pid} rpc={node.rpc_port}")
            if not check(f"node {node.name} becomes ready", node.wait_ready(timeout=420),
                         node.log()[-600:]):
                return False
        return True

    def restart_a(self, **env):
        code = self.a.stop()
        say(f"  node A stopped (exit {code}); starting again {env or ''}")
        self.a.start(**env)
        return check("node A is ready again", self.a.wait_ready(timeout=420),
                     self.a.log()[-600:])

    def stop(self):
        for node in (self.a, self.b):
            try:
                code = node.stop()
                say(f"stopped node {node.name} (exit {code})")
            except Exception as exc:  # pragma: no cover - cleanup
                say(f"could not stop node {node.name}: {exc!r}")

    def finish(self):
        say("")
        took = time.time() - self.t0
        say(f"{len(FAILED)} check(s) failed in {took:.0f}s" if FAILED
            else f"All checks passed in {took:.0f}s.")
        for name in FAILED:
            say(f"  - {name}")
        return 1 if FAILED else 0

    # -- transactions ---------------------------------------------------------

    def chain_values(self, who):
        data = self.a.rpc(f"getsequence {self.pk[who]}")["data"]
        return int(data["sequence_number"]), int(data.get("tip_height") or 0)

    def common(self, who, *, expire_in=1000):
        seq, tip = self.chain_values(who)
        return {"sender_pubkey": self.pk[who], "sequence_number": seq,
                "expiration_time": int(time.time()) + 3600,
                "expire_at_height": tip + expire_in}

    def sign(self, who, payload):
        import hashlib
        from consensus.tx_signing import signing_message_bytes
        payload = dict(payload)
        payload.pop("signature", None)
        digest = hashlib.sha256(signing_message_bytes(payload)).digest()
        payload["signature"] = base._bls().Sign(self.keys[who]["sk"], digest).hex()
        return payload

    def submit(self, who, payload):
        """Sign `payload` as `who` and send it to node A."""
        signed = self.sign(who, payload)
        res = self.a.rpc("sendtx '" + json.dumps(signed, separators=(",", ":")) + "'")
        return res

    def transfer(self, who, to, amount, fee_limit=FEE_LIMIT):
        payload = self.common(who)
        payload.update({"tx_type": "user_tx", "fee_limit": str(fee_limit),
                        "operations": {"1": [[self.pk[who], self.pk[to], str(amount)]]}})
        return self.submit(who, payload)

    def cli(self, *args, timeout=300):
        env = dict(os.environ)
        env["PYTHONPATH"] = base.NATIVE + os.pathsep + self.tree_a
        return subprocess.run(
            [base.PYTHON, "-m", "tau_testnet_cli", "--port", str(self.a.rpc_port),
             "--timeout", "120", *args],
            cwd=self.tree_a, env=env, capture_output=True, text=True, timeout=timeout)

    def privkey(self, who):
        return format(self.keys[who]["sk"], "064x")

    # -- blocks ---------------------------------------------------------------

    def mine(self, empty=True):
        """One block on node A. With `empty`, a block is sealed even when the
        mempool is empty, so a due point can be reached without traffic."""
        cmd = "createblock allow-empty" if empty else "createblock"
        for _ in range(20):
            res = self.a.rpc(cmd)
            if res.get("status") == "ok":
                return res.get("data")
            if (res.get("error") or {}).get("code") != "MINING_BUSY":
                return res
            time.sleep(1.0)
        return res

    def mine_to(self, height):
        while self.a.height() < height:
            self.mine()
        return self.a.height()

    def settle(self, predicate, what, tries=6):
        for _ in range(tries):
            self.mine()
            if predicate():
                return True
        say(f"  (timed out waiting for {what})")
        return predicate()

    def wait(self, predicate, what, timeout=120.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.5)
        say(f"  (timed out waiting for {what})")
        return predicate()

    # -- reads ----------------------------------------------------------------

    def balance(self, who, node=None):
        return int((node or self.a).rpc(f"getbalance {self.pk[who]}")["data"]["balance"])

    def read(self, cmd, node=None):
        res = (node or self.a).rpc(cmd)
        return res.get("data") if res.get("status") == "ok" else None

    def tx_status(self, tx_hash, node=None):
        return self.read(f"gettxstatus {tx_hash}", node) or {}

    def in_head(self, tx_hash):
        return tx_hash in (self.a.head().get("tx_ids") or [])

    # -- the follower -----------------------------------------------------------

    def follower_agrees(self, reads, label="B"):
        """Relay A's blocks to B, then restart B, and compare after each."""
        moved = base.relay(self.a, self.b)
        ok = check(f"{label} ingests A's blocks",
                   self.b.head()["block_hash"] == self.a.head()["block_hash"], moved)
        ok &= self._same(reads, f"{label} after replay")
        code = self.b.stop()
        say(f"  node B stopped (exit {code}); starting again")
        self.b.start()
        ok &= check(f"{label} is ready after a restart", self.b.wait_ready(timeout=420),
                    self.b.log()[-600:])
        ok &= self._same(reads, f"{label} after its restart")
        return ok

    def _same(self, reads, label):
        ha, hb = self.a.head(), self.b.head()
        ok = check(f"{label}: same head and state hash",
                   ha["block_hash"] == hb["block_hash"]
                   and ha["header"]["state_hash"] == hb["header"]["state_hash"],
                   (ha["header"].get("block_number"), hb["header"].get("block_number")))
        for cmd in reads:
            ra, rb = stable(self.read(cmd, self.a)), stable(self.read(cmd, self.b))
            ok &= check(f"{label}: same `{cmd.split()[0]}` {cmd.split()[1][:12] if ' ' in cmd else ''}",
                        ra == rb and ra is not None, {"A": ra, "B": rb})
        return ok
