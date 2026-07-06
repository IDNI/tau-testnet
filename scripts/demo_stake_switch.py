#!/usr/bin/env python3
"""Stake-switch demo driver for the 4-node docker network (scenes 1-8).

Reuses the governance helpers from scripts/demo_governance.py; blocks are
produced only via the `createblock` RPC (background mining is off on every
node). Node RPC ports are fixed 65441..65444 -> node1..node4.

    venv/bin/python scripts/demo_stake_switch.py e2e            # scenes 1-7
    venv/bin/python scripts/demo_stake_switch.py --scene 8      # encore
"""
import argparse
import json
import os
import sys
import time

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from commands.sendtx import _get_signing_message_bytes  # noqa: E402
from scripts.demo_governance import (  # noqa: E402
    rpc_command,
    rpc_json_command,
    get_governance_state,
    submit_rule_update,
    submit_vote,
    compute_target_activation,
    assert_lifecycle,
    get_seq,
    _pk_from_sk,
    _parse_privkey,
    sign,
)

DEMO = os.path.join(_ROOT, "demo")
NODE_PORTS = {1: 65441, 2: 65442, 3: 65443, 4: 65444}
REVISION_FILE = os.path.join(DEMO, "stake_consensus_revision.tau")


def _fail(msg):
    print(f"\n[FATAL] {msg}")
    sys.exit(1)


def _banner(title):
    print("\n" + "=" * 72)
    print(f"  {title}")
    print("=" * 72)


def _key(name, kind):
    with open(os.path.join(DEMO, "keys", f"{name}.{kind}")) as f:
        return f.read().strip()


def createblock(host, port):
    resp = rpc_command("createblock\r\n", host, port)
    print(f"  [node:{port}] createblock -> {resp.strip()}")
    return resp


def get_balance(host, port, pubkey):
    data = rpc_json_command(f"getbalance {pubkey}\r\n", host, port)
    return int(data.get("balance", 0)) if isinstance(data, dict) else 0


def latest_block(host, port):
    data = rpc_json_command("getblocks\r\n", host, port)
    blocks = data.get("blocks", []) if isinstance(data, dict) else []
    return blocks[-1] if blocks else None


def submit_transfer(host, port, privkey_hex, to_pubkey, amount):
    sk_bytes = _parse_privkey(privkey_hex)
    sk_int = int.from_bytes(sk_bytes, "big")
    pk = _pk_from_sk(sk_bytes)
    seq = get_seq(pk, host, port)
    payload = {
        "tx_type": "user_tx",
        "sender_pubkey": pk,
        "sequence_number": seq,
        "expiration_time": int(time.time()) + 3600,
        "fee_limit": "0",
        "operations": {"1": [[pk, to_pubkey, str(amount)]]},
    }
    payload["signature"] = sign(_get_signing_message_bytes(payload), sk_int)
    blob = json.dumps(payload, separators=(",", ":"))
    resp = rpc_command(f"sendtx '{blob}'\r\n", host, port)
    print(f"  [node:{port}] transfer {amount} -> {to_pubkey[:12]}...: {resp.strip()}")
    return resp


def _all_ports():
    return sorted(NODE_PORTS.values())


# --------------------------------------------------------------------------- #
# Scenes
# --------------------------------------------------------------------------- #

def scene1_status(host):
    _banner("Scene 1 — status: 4 nodes agree, validator_set mode, 3 validators")
    heads = {}
    for port in _all_ports():
        gov = get_governance_state(host, port)
        heads[port] = gov.get("head_hash")
        mode = gov.get("eligibility_mode")
        vals = gov.get("active_validators", [])
        print(f"  node:{port} head={str(gov.get('head_hash'))[:16]} "
              f"height={gov.get('head_number')} mode={mode} validators={len(vals)}")
        if port == NODE_PORTS[1]:
            if len(vals) != 3:
                _fail(f"expected 3 active validators, got {len(vals)}")
            if mode != "validator_set":
                _fail(f"expected validator_set mode, got {mode}")
    if len(set(heads.values())) != 1:
        _fail(f"nodes disagree on head hash: {heads}")
    print("  OK: all nodes share head, node1 shows 3 validators in validator_set mode")


def scene2_outsider_blocked(host):
    _banner("Scene 2 — outsider-blocked: node4 cannot propose in validator_set mode")
    resp = createblock(host, NODE_PORTS[4])
    if "not in the active validator set" not in resp:
        _fail(f"expected membership rejection, got: {resp.strip()}")
    print("  OK: node4 refused (not in the active validator set)")


def scene3_fund(host):
    _banner("Scene 3 — fund: treasury -> node4, 150000, mined by node1, synced to all")
    treasury_priv = _key("treasury", "priv")
    node4_pub = _key("node4", "pub")
    submit_transfer(host, NODE_PORTS[1], treasury_priv, node4_pub, 150000)
    createblock(host, NODE_PORTS[1])
    time.sleep(2)  # let the block gossip to peers
    for port in _all_ports():
        bal = get_balance(host, port, node4_pub)
        print(f"  node:{port} node4 balance = {bal}")
        if bal != 150000:
            _fail(f"node:{port} expected node4 balance 150000, got {bal}")
    print("  OK: node4 funded 150000 on all four nodes")


def scene4_propose(host):
    _banner("Scene 4 — propose: submit stake revision + eligibility_mode=stake patch")
    with open(REVISION_FILE, encoding="utf-8") as f:
        revision = f.read().strip()
    node1_priv = _key("node1", "priv")
    gov = get_governance_state(host, NODE_PORTS[1])
    target, min_h = compute_target_activation(gov)
    print(f"  activation height H = {target} (min {min_h})")
    uid = submit_rule_update(
        host, NODE_PORTS[1], node1_priv, target, [revision],
        patch={"eligibility_mode": "stake"},
    )
    createblock(host, NODE_PORTS[1])
    time.sleep(2)
    for port in _all_ports():
        gov = get_governance_state(host, port)
        assert_lifecycle(gov, uid, "pending", f"node:{port} propose")
    print(f"  OK: update {uid[:16]}... pending on all nodes; H={target}")
    return uid, target


def scene5_vote(host, uid, *, checkpoint=False):
    _banner("Scene 5 — vote: node2 + node3 approve (2/3 supermajority)")
    for name in ("node2", "node3"):
        submit_vote(host, NODE_PORTS[1], _key(name, "priv"), uid, approve=True)
    createblock(host, NODE_PORTS[1])
    time.sleep(2)
    for port in _all_ports():
        gov = get_governance_state(host, port)
        assert_lifecycle(gov, uid, "approved-and-scheduled", f"node:{port} vote")
    print(f"  OK: update {uid[:16]}... approved-and-scheduled on all nodes")
    if checkpoint:
        os.system(f"bash {os.path.join(DEMO, 'checkpoint.sh')} snapshot")


def scene6_activate(host, uid, target):
    _banner("Scene 6 — activate: mine empty blocks until height H, mode flips to stake")
    with open(REVISION_FILE, encoding="utf-8") as f:
        revision = f.read().strip()
    for _ in range(target + 5):
        gov = get_governance_state(host, NODE_PORTS[1])
        if int(gov.get("head_number", -1)) >= target:
            break
        createblock(host, NODE_PORTS[1])
        time.sleep(1)
    time.sleep(2)
    for port in _all_ports():
        gov = get_governance_state(host, port)
        assert_lifecycle(gov, uid, "activated", f"node:{port} activate")
        if gov.get("eligibility_mode") != "stake":
            _fail(f"node:{port} eligibility_mode still {gov.get('eligibility_mode')}")
        if (gov.get("consensus_rules") or "").strip() != revision:
            _fail(f"node:{port} consensus_rules != revision text")
    print(f"  OK: patch applied during block H={target}; mode=stake on all nodes")
    print(f"  NOTE: first stake-verified block is H+1 = {target + 1}")


def scene7_outsider_mines(host):
    _banner("Scene 7 — outsider-mines: node4 (stake 150000) proposes and it STICKS")
    resp = createblock(host, NODE_PORTS[4])
    if "block_hash" not in resp:
        _fail(f"node4 failed to mine in stake mode: {resp.strip()}")
    time.sleep(2)
    node4_pub = _key("node4", "pub")
    heads = {}
    for port in _all_ports():
        blk = latest_block(host, port)
        proposer = (blk or {}).get("header", {}).get("proposer_pubkey")
        heads[port] = (blk or {}).get("block_hash")
        print(f"  node:{port} head={str(heads[port])[:16]} proposer={str(proposer)[:12]}...")
        if proposer != node4_pub:
            _fail(f"node:{port} latest block proposer {proposer} != node4 {node4_pub}")
    if len(set(heads.values())) != 1:
        _fail(f"nodes disagree on head after node4 block: {heads}")
    print("\n  " + "*" * 60)
    print("  *  THE MONEY SHOT: a non-validator with stake just produced   *")
    print("  *  a block that ALL FOUR nodes accepted as canonical.         *")
    print("  " + "*" * 60)


def scene8_poor_proposer_rejected(host):
    _banner("Scene 8 — encore: a validator with 0 stake is NOT eligible (o7=0)")
    resp = createblock(host, NODE_PORTS[1])
    if "Not our turn" not in resp:
        _fail(f"expected 'Not our turn' (o7=0 for zero-stake proposer), got: {resp.strip()}")
    print("  OK: node1 (0 stake) refused by Tau o7 dry-run in stake mode")


def run_e2e(host):
    scene1_status(host)
    scene2_outsider_blocked(host)
    scene3_fund(host)
    uid, target = scene4_propose(host)
    scene5_vote(host, uid, checkpoint=True)
    scene6_activate(host, uid, target)
    scene7_outsider_mines(host)
    print("\n[e2e] scenes 1-7 all green.")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", nargs="?", default="e2e", choices=["e2e"],
                   help="run the full scenes 1-7 pipeline")
    p.add_argument("--scene", type=int, choices=range(1, 9),
                   help="run a single scene (1-8); scenes 4-6 need prior state")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--threshold", type=int, default=100000,
                   help="informational; the revision file is rendered by setup.sh")
    a = p.parse_args()

    if a.scene is None:
        run_e2e(a.host)
        return

    # Single-scene entry points (for restart checks / the encore). Scenes that
    # depend on a specific update id re-derive it from live governance state.
    if a.scene == 1:
        scene1_status(a.host)
    elif a.scene == 2:
        scene2_outsider_blocked(a.host)
    elif a.scene == 3:
        scene3_fund(a.host)
    elif a.scene == 7:
        scene7_outsider_mines(a.host)
    elif a.scene == 8:
        scene8_poor_proposer_rejected(a.host)
    else:
        _fail(f"scene {a.scene} is part of the e2e sequence; run `e2e` to reach it")


if __name__ == "__main__":
    main()
