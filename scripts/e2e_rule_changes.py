#!/usr/bin/env python3
"""End-to-end rule-change guard on REAL running nodes with the native Tau engine.

tests/test_rule_change_*.py mock the engine; this drives two live nodes. Node A
mines and is driven through its RPC port and the `tau-testnet policy` CLI; node B
runs the same validator key (as in scripts/e2e_authority.py) and receives A's
blocks through NetworkService._ingest_blocks, so it replays every guard, park,
vote, release and cancel on its own.

SCENARIOS (asserted on admission verdicts and request terminal statuses, never
on net balances)
    1. The owner installs "any change needs co-signer X" as a guard with
       `policy guard set` (no guard yet, so it executes in its own block).
    2. A thief holding the same key submits the neutral o5 revoke and a
       permissive op-0 o5 rule directly: both refused RULE_CHANGE_NEEDS_APPROVAL.
    3. The thief requests a policy revoke: it parks. X approves through the real
       TOTP bot (a valid code for that request, delivered to the bot in-process,
       then a poll casts the vote): the request executes and the o5 clause is gone.
    4. The thief requests a permissive policy and the owner cancels it with
       rule_change_cancel: CANCELLED, and a later approval cannot execute it.
    5. Node B ends with the same clause registry, request statuses, roots and
       state hash as node A.
The 1000-block time escape is covered by the mock tests and not mined here.

USAGE
    python scripts/e2e_rule_changes.py provision --dir .local/e2e-rule-changes
    python scripts/e2e_rule_changes.py run --dir .local/e2e-rule-changes

`provision` exports the working tree twice (nodeA, nodeB), writes keys.json and a
genesis with approval slots active from block 0. `run` starts both nodes on free
local ports, drives the scenarios, and stops exactly the processes it started.
The native binding comes from $TAU_NATIVE_PATH.
"""
from __future__ import annotations

import argparse
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

base.NETWORK_ID = "tau-e2e-rule-changes"
ACTORS = ("miner", "alice", "xavier")
FAILED: list[str] = []

SPEND_LIMIT = ("always ( (i1[t]:bv[24] > { #x001388 }:bv[24]) ? "
               "( o5[t]:bv[24] = { #x000000 }:bv[24] ) : "
               "( o5[t]:bv[24] = { #x000001 }:bv[24] ) ).")
NEUTRAL = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
PERMISSIVE = ("always ( (i1[t]:bv[24] > { #x7fffff }:bv[24]) ? "
              "( o5[t]:bv[24] = { #x000000 }:bv[24] ) : "
              "( o5[t]:bv[24] = { #x000001 }:bv[24] ) ).")
OWN_POLICY_INDEX = "5"


def say(msg=""):
    print(f"[e2e] {msg}", flush=True)


def check(label, condition, detail=""):
    if condition:
        say(f"  PASS  {label}")
    else:
        FAILED.append(label)
        say(f"  FAIL  {label} {str(detail)[:400]}")
    return bool(condition)


def guard_text(cosigner_pk):
    return ("always ( (i18[t]:bv[384] = { #x%s }:bv[384]) ? "
            "(o5[t]:bv[24] = { #x000001 }:bv[24]) : "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) )." % cosigner_pk)


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


def provision(root: str) -> int:
    root = os.path.abspath(root)
    if os.path.exists(root):
        shutil.rmtree(root)
    os.makedirs(root)
    _export_env()
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
    cmd = [base.PYTHON, "scripts/gen_genesis.py", "--base-fee", str(base.BASE_FEE),
           "--network-id", base.NETWORK_ID, "--approval-slots",
           "--validator-privkey", format(keys["miner"]["sk"], "064x"),
           "--out", "data/genesis.json"]
    for name in ("alice", "xavier"):
        cmd += ["--account", f"{keys[name]['pk']}:1000000"]
    subprocess.run(cmd, cwd=tree_a, check=True, capture_output=True)
    shutil.copy2(os.path.join(tree_a, "data", "genesis.json"),
                 os.path.join(tree_b, "data", "genesis.json"))
    say("Provisioned: approval slots active from genesis, one validator.")
    return 0


# --------------------------------------------------------------------------- #
# driving
# --------------------------------------------------------------------------- #

_TAKEN: list[int] = []


def _port_block():
    import socket
    while True:
        start = base.free_port()
        if any(abs(start - t) < 32 for t in _TAKEN):
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


class Rig:
    def __init__(self, root):
        self.root = root
        raw = json.load(open(os.path.join(root, "keys.json")))
        self.keys = {n: {"sk": int(k["sk"], 16), "pk": k["pk"]} for n, k in raw.items()}
        self.pk = {n: k["pk"] for n, k in self.keys.items()}
        self.tree_a = os.path.join(root, "nodeA")
        self.tree_b = os.path.join(root, "nodeB")
        # A node's websocket server probes upward from its RPC port, so each
        # node's ports sit in their own block of 16.
        ports = [_port_block() for _ in range(2)]
        self.a = base.Node("A", self.tree_a, self.keys, "miner", wrapper=True,
                           rpc_port=ports[0], p2p_port=ports[0] + 8)
        self.b = base.Node("B", self.tree_b, self.keys, "miner", wrapper=True,
                           rpc_port=ports[1], p2p_port=ports[1] + 8)
        self.chain = base.Chain(self.keys)
        self.rids: dict[str, str] = {}

    # -- transactions ---------------------------------------------------------

    def send(self, who, payload, fee_limit="10000"):
        seq = int(self.a.rpc(f"getsequence {self.pk[who]}")["data"]["sequence_number"])
        tip = int(self.a.rpc(f"getsequence {self.pk[who]}")["data"].get("tip_height") or 0)
        payload.update({
            "sender_pubkey": self.pk[who], "sequence_number": seq,
            "expiration_time": int(time.time()) + 3600,
            "fee_limit": fee_limit,
        })
        payload.setdefault("expire_at_height", tip + 1000)
        from consensus.tx_signing import signing_message_bytes
        import hashlib
        digest = hashlib.sha256(signing_message_bytes(payload)).digest()
        payload["signature"] = base._bls().Sign(self.keys[who]["sk"], digest).hex()
        return self.a.rpc("sendtx '" + json.dumps(payload, separators=(",", ":")) + "'")

    def mine(self):
        out = self.a.mine()
        self.chain.mined()
        return out

    def settle(self, predicate, what, tries=6):
        """Mine until `predicate()` holds: bounded, and asserts on chain state."""
        for _ in range(tries):
            self.mine()
            if predicate():
                return True
        say(f"  (timed out waiting for {what})")
        return predicate()

    # -- reads ----------------------------------------------------------------

    def request(self, rid, node=None):
        res = (node or self.a).rpc(f"getapprovalrequest {rid}")
        return res["data"] if res.get("status") == "ok" else None

    def status(self, rid, node=None):
        return (self.request(rid, node) or {}).get("status")

    def offers(self, who, node=None):
        return (node or self.a).rpc(f"getruleoffers {self.pk[who]} all")["data"]

    def has_policy(self, who, node=None):
        return any(str(c["target_stream"]) == OWN_POLICY_INDEX
                   for c in self.offers(who, node)["accepted_clauses"])

    def guard(self, who, node=None):
        return self.offers(who, node).get("rule_change_guard")

    def rule_change_id(self, payload):
        from consensus.approvals import parse_rule_change_request
        return parse_rule_change_request(payload).request_id.hex()

    def request_payload(self, kind, text="", approvers=None):
        from tau_testnet_cli import tx as cli_tx
        tip = int(self.a.rpc(f"getsequence {self.pk['alice']}")["data"]["tip_height"])
        return cli_tx.build_rule_change_request_tx(
            sender_pubkey=self.pk["alice"], sequence_number=0,
            expiration_time=int(time.time()) + 3600,
            expire_at_height=tip + 2 * 1000, kind=kind, rule_text=text,
            approvers=approvers or {})

    def cli(self, *args):
        env = dict(os.environ)
        env["PYTHONPATH"] = base.NATIVE + os.pathsep + self.tree_a
        proc = subprocess.run(
            [base.PYTHON, "-m", "tau_testnet_cli", "--port", str(self.a.rpc_port),
             "--timeout", "120", *args],
            cwd=self.tree_a, env=env, capture_output=True, text=True, timeout=300)
        return proc


# --------------------------------------------------------------------------- #
# scenarios
# --------------------------------------------------------------------------- #

def scenario_setup(rig):
    say("Alice installs an ordinary o5 policy directly (no guard yet)")
    res = rig.send("alice", {"tx_type": "user_tx", "operations": {"0": SPEND_LIMIT}})
    check("an op-0 o5 policy is admitted while no guard exists", base.ok(res), res)
    rig.settle(lambda: rig.has_policy("alice"), "the policy to register")
    check("the policy is registered as alice's own clause", rig.has_policy("alice"))


def scenario_set_guard(rig):
    say("1. Alice sets the guard 'any change needs X' with `policy guard set`")
    proc = rig.cli(
        "policy", "guard", "set", "--privkey", format(rig.keys["alice"]["sk"], "064x"),
        "--body", guard_text(rig.pk["xavier"]), "--approver", f"18={rig.pk['xavier']}")
    check("the CLI submits the guard request", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rid = next((line.split(":", 1)[1].strip() for line in proc.stdout.splitlines()
                if line.startswith("request id:")), None)
    check("the CLI prints the request id", bool(rid), proc.stdout)
    rig.rids["guard"] = rid
    rig.settle(lambda: rig.status(rid) == "executed", "the guard request to execute")
    check("a guard set with no guard yet executes in its own block",
          rig.status(rid) == "executed", rig.request(rid))
    guard = rig.guard("alice") or ""
    check("the guard is registered and names X", rig.pk["xavier"] in guard, rig.offers("alice"))
    check("alice's own policy is untouched", rig.has_policy("alice"))
    shown = rig.cli("policy", "guard", "show", "--privkey",
                    format(rig.keys["alice"]["sk"], "064x"))
    check("`policy guard show` prints the guard", "i18" in shown.stdout, shown.stdout)


def scenario_direct_doors(rig):
    say("2. The thief tries both direct doors")
    before = rig.offers("alice")["accepted_clauses"]
    revoke = rig.send("alice", {"tx_type": "user_tx", "operations": {"0": NEUTRAL}})
    check("the neutral o5 revoke is refused RULE_CHANGE_NEEDS_APPROVAL",
          base.err(revoke).get("code") == "RULE_CHANGE_NEEDS_APPROVAL", revoke)
    permissive = rig.send("alice", {"tx_type": "user_tx", "operations": {"0": PERMISSIVE}})
    check("a permissive op-0 o5 rule is refused RULE_CHANGE_NEEDS_APPROVAL",
          base.err(permissive).get("code") == "RULE_CHANGE_NEEDS_APPROVAL", permissive)
    rig.mine()
    check("alice's policy is unchanged", rig.offers("alice")["accepted_clauses"] == before)


def scenario_revoke_with_cosigner(rig, totp_dir):
    say("3. The thief requests a revoke; X approves through the TOTP bot")
    approvers = {"18": rig.pk["xavier"]}
    payload = rig.request_payload(2, approvers=approvers)
    res = rig.send("alice", payload)
    rid = rig.rule_change_id(payload)
    check("the kind-2 request is admitted", base.ok(res), res)
    rig.rids["revoke"] = rid
    rig.settle(lambda: rig.request(rid) is not None, "the request to be mined")
    row = rig.request(rid) or {}
    check("the request parks: open, not ready",
          row.get("status") == "open" and row.get("ready") is False, row)
    check("the request reads as a policy revoke",
          row.get("request_type") == "rule_change" and row.get("kind") == 2, row)
    check("the policy is still there while it parks", rig.has_policy("alice"))

    from approval_bot_common import NodeClient, Signer
    from approval_bot_totp import EnrollmentStore, TotpBot, totp_at

    store = EnrollmentStore(totp_dir)
    secret = store.enroll(rig.pk["alice"])
    bot = TotpBot(NodeClient("127.0.0.1", rig.a.rpc_port), Signer(
        format(rig.keys["xavier"]["sk"], "064x")), poll_seconds=0.1, store=store)
    check("the bot sees the request and, with no code, casts no vote", bot.tick() == 0)
    ok_wrong, _ = bot.submit_code(rid, "000000" if totp_at(secret, time.time()) != "000000"
                                  else "000001")
    check("a wrong code is refused by the bot", ok_wrong is False)
    check("still no vote after a wrong code", bot.tick() == 0)
    accepted, detail = bot.submit_code(rid, totp_at(secret, int(time.time())))
    check("a valid code for this request is accepted", accepted, detail)
    check("the next poll casts the vote", bot.tick() == 1)
    rig.settle(lambda: rig.status(rid) == "executed", "the revoke to execute")
    check("the revoke executes after X's vote", rig.status(rid) == "executed",
          rig.request(rid))
    check("the o5 clause is gone", not rig.has_policy("alice"))
    check("the guard is still in force", bool(rig.guard("alice")))


def scenario_cancel(rig):
    say("4. The thief requests a permissive policy; the owner cancels it")
    payload = rig.request_payload(1, PERMISSIVE, {"18": rig.pk["xavier"]})
    res = rig.send("alice", payload)
    rid = rig.rule_change_id(payload)
    check("the kind-1 request is admitted", base.ok(res), res)
    rig.rids["permissive"] = rid
    rig.settle(lambda: rig.request(rid) is not None, "the request to be mined")
    check("the permissive request parks", rig.status(rid) == "open", rig.request(rid))

    proc = rig.cli("policy", "change", "cancel",
                   "--privkey", format(rig.keys["alice"]["sk"], "064x"),
                   "--request-id", rid)
    check("the owner's cancel is submitted", proc.returncode == 0,
          proc.stdout[-300:] + proc.stderr[-300:])
    rig.settle(lambda: rig.status(rid) == "cancelled", "the cancel to land")
    check("the request ends CANCELLED", rig.status(rid) == "cancelled", rig.request(rid))

    from tau_testnet_cli import tx as cli_tx
    vote = cli_tx.build_transfer_vote_tx(
        sender_pubkey=rig.pk["xavier"], sequence_number=0,
        expiration_time=int(time.time()) + 3600, expire_at_height=rig.a.height() + 500,
        request_id=rid, approve=True)
    rig.send("xavier", vote, fee_limit="0")
    for _ in range(2):
        rig.mine()
    check("a later approval does not execute it", rig.status(rid) == "cancelled",
          rig.request(rid))
    check("the permissive policy never lands", not rig.has_policy("alice"))


def scenario_follower(rig):
    say("5. Node B replays A's blocks and agrees")
    rig.mine()
    moved = base.relay(rig.a, rig.b)
    check("B ingests A's blocks", rig.b.head()["block_hash"] == rig.a.head()["block_hash"],
          moved)
    check("same state hash at the head",
          rig.a.head()["header"]["state_hash"] == rig.b.head()["header"]["state_hash"])
    check("same height", rig.a.height() == rig.b.height() and rig.a.height() > 0)
    check("same accepted clauses",
          rig.offers("alice", rig.a)["accepted_clauses"]
          == rig.offers("alice", rig.b)["accepted_clauses"])
    check("same guard", rig.guard("alice", rig.a) == rig.guard("alice", rig.b)
          and bool(rig.guard("alice", rig.b)))
    for name, rid in sorted(rig.rids.items()):
        check(f"same status for the {name} request",
              rig.status(rid, rig.a) == rig.status(rid, rig.b) is not None,
              (rig.status(rid, rig.a), rig.status(rid, rig.b)))
    ra, rb = rig.a.probe("registry"), rig.b.probe("registry")
    check("same approval_requests_root", ra["approval_requests_root"]
          == rb["approval_requests_root"] and bool(ra["approval_requests_root"]), (ra, rb))
    check("same rule_clauses_root", ra["rule_clauses_root"] == rb["rule_clauses_root"])
    say(f"  statuses: { {n: rig.status(r) for n, r in rig.rids.items()} }")
    say(f"  approval_requests_root: {ra['approval_requests_root']}")


def run(root: str) -> int:
    root = os.path.abspath(root)
    rig = Rig(root)
    nodes = [rig.a, rig.b]
    totp_dir = os.path.join(root, "totp")
    t0 = time.time()
    try:
        rig.a.start()
        say(f"node A pid={rig.a.proc.pid} rpc={rig.a.rpc_port} p2p={rig.a.p2p_port}")
        if not check("node A becomes ready", rig.a.wait_ready(timeout=420),
                     rig.a.log()[-600:]):
            return 1
        rig.b.start()
        say(f"node B pid={rig.b.proc.pid} rpc={rig.b.rpc_port} p2p={rig.b.p2p_port}")
        if not check("node B becomes ready", rig.b.wait_ready(timeout=420),
                     rig.b.log()[-600:]):
            return 1
        rig.mine()
        scenario_setup(rig)
        scenario_set_guard(rig)
        scenario_direct_doors(rig)
        scenario_revoke_with_cosigner(rig, totp_dir)
        scenario_cancel(rig)
        scenario_follower(rig)
    except Exception:
        import traceback
        check("the run completed", False, traceback.format_exc()[-1500:])
    finally:
        for node in nodes:
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
    parser.add_argument("--dir", default=os.path.join(REPO, ".local", "e2e-rule-changes"))
    args = parser.parse_args(argv)
    return provision(args.dir) if args.mode == "provision" else run(args.dir)


if __name__ == "__main__":
    raise SystemExit(main())
