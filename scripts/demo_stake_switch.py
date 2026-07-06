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


def createblock(host, port, *, retries=6):
    """Trigger block production. A node still reconstructing state after a
    restart can transiently return an empty body; retry until it answers."""
    resp = ""
    for _ in range(retries):
        resp = rpc_command("createblock\r\n", host, port)
        if resp.strip():
            break
        time.sleep(1)
    print(f"  [node:{port}] createblock -> {resp.strip()}")
    return resp


def get_balance(host, port, pubkey):
    # Tolerant of a transient empty body; returns -1 so convergence predicates
    # simply keep polling instead of raising SystemExit inside _wait.
    for _ in range(20):
        try:
            resp = rpc_command(f"getbalance {pubkey}\r\n", host, port)
            env = json.loads(resp.strip())
            if env.get("status") == "ok":
                return int((env.get("data") or {}).get("balance", 0))
        except Exception:
            pass
        time.sleep(1.0)
    return -1


def latest_block(host, port):
    for _ in range(20):
        try:
            resp = rpc_command("getblocks\r\n", host, port)
            env = json.loads(resp.strip())
            if env.get("status") == "ok":
                blocks = (env.get("data") or {}).get("blocks", [])
                return blocks[-1] if blocks else None
        except Exception:
            pass
        time.sleep(1.0)
    return None


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


def _gov(host, port, *, retries=20):
    """Resilient getgovernance read: a busy node (mid tau-step / mining) can
    transiently return an empty RPC body; retry rather than aborting the demo."""
    for i in range(retries):
        try:
            resp = rpc_command("getgovernance\r\n", host, port)
            env = json.loads(resp.strip())
            if env.get("status") == "ok":
                return env.get("data") or {}
        except Exception:
            pass
        time.sleep(1.0)
    _fail(f"getgovernance on node:{port} kept returning an unusable response")


def _node_ready(host, port):
    """True once a node answers getgovernance with a parseable head number."""
    try:
        resp = rpc_command("getgovernance\r\n", host, port)
        env = json.loads(resp.strip())
        return env.get("status") == "ok" and "head_number" in (env.get("data") or {})
    except Exception:
        return False


def _wait_all_ready(host, *, timeout=90):
    return _wait(lambda: all(_node_ready(host, p) for p in _all_ports()),
                 timeout=timeout, what="nodes ready")


def _wait(predicate, *, timeout=90, interval=1.0, what="condition"):
    """Poll `predicate()` until truthy or timeout. Blocks/gossip are async, so
    cross-node assertions must wait for convergence rather than a fixed sleep."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if predicate():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def _sync_head(host, miner_port, *, timeout=45):
    """Wait until every node's head reaches the miner's head. Paces mining to the
    follower sync rate: block propagation is pull-on-announce, so a miner left to
    run freely (esp. node4 as the sole stake-mode proposer) outruns the mesh."""
    target = int(_gov(host, miner_port).get("head_number", 0))
    return _wait(lambda: all(int(_gov(host, p).get("head_number", -1)) >= target
                             for p in _all_ports()), timeout=timeout)


def _mine_until(host, miner_port, predicate, *, rounds=25, settle=3):
    """Mine on `miner_port` until `predicate()` holds on all nodes.

    Block propagation is pull-on-announce with no periodic catch-up: a node that
    was not yet peered when a block was announced only catches up on the NEXT
    announcement. Re-mining re-announces the head; header-sync then pulls the
    whole missing range. After each block we wait for the mesh to catch up before
    mining again, so the miner never runs away from the followers. Extra blocks
    are empty and harmless.
    """
    for _ in range(rounds):
        if _wait(predicate, timeout=settle, interval=1.0):
            return True
        createblock(host, miner_port)
        _sync_head(host, miner_port)
    return _wait(predicate, timeout=settle)


# --------------------------------------------------------------------------- #
# Scenes
# --------------------------------------------------------------------------- #

def scene1_status(host):
    _banner("Scene 1 — status: 4 nodes agree, validator_set mode, 3 validators")
    heads = {}
    for port in _all_ports():
        gov = _gov(host, port)
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
    if not _mine_until(host, NODE_PORTS[1],
                       lambda: all(get_balance(host, p, node4_pub) == 150000 for p in _all_ports())):
        for port in _all_ports():
            print(f"  node:{port} node4 balance = {get_balance(host, port, node4_pub)}")
        _fail("node4 balance did not reach 150000 on all nodes")
    for port in _all_ports():
        print(f"  node:{port} node4 balance = {get_balance(host, port, node4_pub)}")
    print("  OK: node4 funded 150000 on all four nodes")


def scene4_propose(host):
    _banner("Scene 4 — propose: submit stake revision + eligibility_mode=stake patch")
    with open(REVISION_FILE, encoding="utf-8") as f:
        revision = f.read().strip()
    node1_priv = _key("node1", "priv")
    gov = _gov(host, NODE_PORTS[1])
    target, min_h = compute_target_activation(gov)
    print(f"  activation height H = {target} (min {min_h})")
    uid = submit_rule_update(
        host, NODE_PORTS[1], node1_priv, target, [revision],
        patch={"eligibility_mode": "stake"},
    )
    def _lifecycle_all(status):
        return all(
            _gov(host, p).get("lifecycle", {}).get(uid) == status
            for p in _all_ports()
        )
    if not _mine_until(host, NODE_PORTS[1], lambda: _lifecycle_all("pending")):
        for port in _all_ports():
            assert_lifecycle(_gov(host, port), uid, "pending", f"node:{port} propose")
    print(f"  OK: update {uid[:16]}... pending on all nodes; H={target}")
    return uid, target


def scene5_vote(host, uid):
    _banner("Scene 5 — vote: node2 + node3 approve (2/3 supermajority)")
    for name in ("node2", "node3"):
        submit_vote(host, NODE_PORTS[1], _key(name, "priv"), uid, approve=True)

    def _sched_all():
        return all(
            _gov(host, p).get("lifecycle", {}).get(uid) == "approved-and-scheduled"
            for p in _all_ports()
        )
    if not _mine_until(host, NODE_PORTS[1], _sched_all):
        for port in _all_ports():
            assert_lifecycle(_gov(host, port), uid,
                             "approved-and-scheduled", f"node:{port} vote")
    print(f"  OK: update {uid[:16]}... approved-and-scheduled on all nodes")


def take_checkpoint(host):
    """Snapshot the activated chain state as a rollback point. Taken AFTER
    activation: a consistent snapshot requires stopping the nodes, and only the
    ACTIVATED consensus params (mode + rule) are durably persisted — a snapshot
    taken while an update is merely scheduled would not survive the restart
    (scheduled-update payloads are not persisted; see docs/demo_stake_switch.md)."""
    _banner("Checkpoint — snapshot the activated (stake-mode) chain state")
    os.system(f"bash {os.path.join(DEMO, 'checkpoint.sh')} snapshot")
    if not _wait_all_ready(host):
        _fail("nodes did not come back ready after checkpoint snapshot")
    print("  OK: checkpoint saved; all nodes ready")


def scene6_activate(host, uid, target):
    _banner("Scene 6 — activate: mine empty blocks until height H, mode flips to stake")
    with open(REVISION_FILE, encoding="utf-8") as f:
        revision = f.read().strip()
    # Mine node1 up to H, PACED: node1 is the last eligible proposer (in stake
    # mode after H it holds 0 stake and cannot mine), so if a follower misses the
    # activation block there is no later announcement to catch it. Wait for the
    # mesh to converge after each block so all nodes reach H together.
    def _node1_height():
        if not _node_ready(host, NODE_PORTS[1]):
            return -1
        return int(_gov(host, NODE_PORTS[1]).get("head_number", -1))

    for _ in range(target + 15):
        if _node1_height() >= target:
            break
        createblock(host, NODE_PORTS[1])
        _sync_head(host, NODE_PORTS[1])

    # Functional activation: on EVERY node the eligibility mode is now "stake"
    # and the active consensus rule is the stake revision. (The getgovernance
    # `lifecycle` label reads "activated" on the proposer and "archived" on
    # followers because it is derived from active_consensus_id, which is
    # miner-local provenance, not hashed consensus state — so we assert the
    # functional outcome, and only that the update is no longer pending.)
    def _switched_all():
        for p in _all_ports():
            gov = _gov(host, p)
            if gov.get("eligibility_mode") != "stake":
                return False
            if (gov.get("consensus_rules") or "").strip() != revision:
                return False
            if gov.get("lifecycle", {}).get(uid) not in ("activated", "archived"):
                return False
        return True
    if not _wait(_switched_all, timeout=60, what="stake-mode activation sync"):
        for port in _all_ports():
            gov = _gov(host, port)
            if gov.get("eligibility_mode") != "stake":
                _fail(f"node:{port} eligibility_mode still {gov.get('eligibility_mode')}")
            if (gov.get("consensus_rules") or "").strip() != revision:
                _fail(f"node:{port} consensus_rules != revision text")
            if gov.get("lifecycle", {}).get(uid) not in ("activated", "archived"):
                _fail(f"node:{port} update {uid[:16]} still {gov.get('lifecycle', {}).get(uid)}")
    print(f"  OK: mode=stake and stake rule active on all four nodes (H={target})")
    print(f"  NOTE: first stake-verified block is H+1 = {target + 1}")


def scene7_outsider_mines(host):
    _banner("Scene 7 — outsider-mines: node4 (stake 150000) proposes and it STICKS")
    resp = createblock(host, NODE_PORTS[4])
    if "block_hash" not in resp:
        _fail(f"node4 failed to mine in stake mode: {resp.strip()}")
    node4_pub = _key("node4", "pub")

    def _all_on_node4_block():
        # The money shot: every node's canonical tip was produced by node4, the
        # non-validator. node4 is the ONLY eligible proposer post-switch, so a
        # node4-proposed tip on every node proves the outsider's blocks are
        # canonical network-wide. We do not require an identical hash instant —
        # node4 keeps mining (re-announcing) to pull laggards forward, so a node
        # trailing by one block still has a node4-proposed head.
        for port in _all_ports():
            blk = latest_block(host, port)
            if (blk or {}).get("header", {}).get("proposer_pubkey") != node4_pub:
                return False
        return True
    # node4 re-announces its head each round; wait generously between rounds so a
    # slow follower can pull up to a stable head rather than chase a moving one.
    if not _mine_until(host, NODE_PORTS[4], _all_on_node4_block, rounds=12, settle=15):
        for port in _all_ports():
            blk = latest_block(host, port)
            proposer = (blk or {}).get("header", {}).get("proposer_pubkey")
            print(f"  node:{port} head={str((blk or {}).get('block_hash'))[:16]} "
                  f"proposer={str(proposer)[:12]}...")
        _fail("not all nodes accepted node4's block as canonical head")
    for port in _all_ports():
        blk = latest_block(host, port)
        proposer = (blk or {}).get("header", {}).get("proposer_pubkey")
        print(f"  node:{port} head={str((blk or {}).get('block_hash'))[:16]} "
              f"proposer={str(proposer)[:12]}...")
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


# --------------------------------------------------------------------------- #
# Phase 7 — abort / rollback / encore
# --------------------------------------------------------------------------- #

def _flatten_rule(path):
    """Rule text as a single line with `#` comment lines removed (an i0 rule
    value is fed raw; tau_native does not strip comments from it)."""
    with open(path, encoding="utf-8") as f:
        lines = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]
    return " ".join(lines)


def _eligible_miner(host):
    """The node that may propose under the CURRENT mode: node4 (funded) in stake
    mode, else node1 (a validator)."""
    return NODE_PORTS[4] if _gov(host, NODE_PORTS[1]).get("eligibility_mode") == "stake" else NODE_PORTS[1]


def _find_update(host, port, want_mode):
    """Return (uid, activate_at_height) of a pending/scheduled update whose
    host_contract_patch sets eligibility_mode == want_mode, else (None, None)."""
    gov = _gov(host, port)
    sched_heights = {uid: h for h, uid in
                     [(e[0], e[1]) if isinstance(e, (list, tuple)) else (None, None)
                      for e in gov.get("scheduled_updates", [])]}
    for u in gov.get("pending_updates", []):
        patch = u.get("host_contract_patch") or {}
        if patch.get("eligibility_mode") == want_mode:
            return u.get("update_id"), int(u.get("activate_at_height"))
    # Fall back to lifecycle+scheduled if the payload already left the pending list.
    for uid, status in gov.get("lifecycle", {}).items():
        if status in ("pending", "approved-and-scheduled"):
            return uid, sched_heights.get(uid)
    return None, None


def scene_propose_spare(host):
    """Late-activation spare: re-propose the stake switch with a far-future
    activation height (current + 20), for when a vote misses the window."""
    _banner("Spare — propose stake switch with activation height current + 20")
    revision = _flatten_rule(REVISION_FILE)
    gov = _gov(host, NODE_PORTS[1])
    target = int(gov["next_block_height"]) + 20
    print(f"  activation height H = {target}")
    uid = submit_rule_update(host, NODE_PORTS[1], _key("node1", "priv"), target,
                             [revision], patch={"eligibility_mode": "stake"})
    if not _mine_until(host, _eligible_miner(host),
                       lambda: all(_gov(host, p).get("lifecycle", {}).get(uid) == "pending"
                                   for p in _all_ports())):
        _fail("spare proposal did not reach pending on all nodes")
    print(f"  OK: spare update {uid[:16]}... pending on all nodes; H={target}")


REVERSE_MODE = "validator_set"


def scene_propose_reverse(host):
    """Encore / regret: propose reverting to PoA (mode-guarded genesis rule as a
    full restatement + eligibility_mode=validator_set patch)."""
    _banner("Reverse — propose switch BACK to validator_set (PoA)")
    revision = _flatten_rule(os.path.join(DEMO, "genesis_consensus_demo.tau"))
    gov = _gov(host, NODE_PORTS[1])
    # Generous runway: propose + vote each need a few blocks to converge across
    # the mesh (re-announce = mine), and mining must not overshoot H (a pending
    # update whose activate_at passes auto-expires to archival). activate-reverse
    # mines the remaining blocks up to H.
    target = int(gov["next_block_height"]) + int(gov["active_validator_count"]) + 15
    print(f"  activation height H = {target}")
    miner = _eligible_miner(host)
    uid = submit_rule_update(host, miner, _key("node1", "priv"), target,
                             [revision], patch={"eligibility_mode": REVERSE_MODE})
    if not _mine_until(host, miner,
                       lambda: all(_gov(host, p).get("lifecycle", {}).get(uid) == "pending"
                                   for p in _all_ports())):
        _fail("reverse proposal did not reach pending on all nodes")
    print(f"  OK: reverse update {uid[:16]}... pending on all nodes; H={target}")


def scene_vote_reverse(host):
    _banner("Reverse — node2 + node3 approve the revert")
    uid, _ = _find_update(host, NODE_PORTS[1], REVERSE_MODE)
    if not uid:
        _fail("no pending reverse update found to vote on")
    miner = _eligible_miner(host)
    for name in ("node2", "node3"):
        submit_vote(host, miner, _key(name, "priv"), uid, approve=True)
    if not _mine_until(host, miner,
                       lambda: all(_gov(host, p).get("lifecycle", {}).get(uid) == "approved-and-scheduled"
                                   for p in _all_ports())):
        _fail("reverse update not approved-and-scheduled on all nodes")
    print(f"  OK: reverse update {uid[:16]}... approved-and-scheduled on all nodes")


def scene_activate_reverse(host):
    _banner("Reverse — mine to H; mode returns to validator_set, outsider blocked again")
    uid, target = _find_update(host, NODE_PORTS[1], REVERSE_MODE)
    if not target:
        # already activated or scheduled height unknown: derive from head+margin
        target = int(_gov(host, NODE_PORTS[1])["head_number"]) + 1
    miner = _eligible_miner(host)  # still stake mode -> node4 mines up to H

    def _reverted_all():
        return all(_gov(host, p).get("eligibility_mode") == "validator_set" for p in _all_ports())
    if not _mine_until(host, miner, _reverted_all, rounds=30):
        for p in _all_ports():
            print(f"  node:{p} mode={_gov(host, p).get('eligibility_mode')}")
        _fail("reverse activation did not restore validator_set on all nodes")
    print("  OK: all nodes back in validator_set mode")
    # node4 (outsider) must be refused again -> proves the door swings both ways.
    resp = createblock(host, NODE_PORTS[4])
    if "not in the active validator set" not in resp:
        _fail(f"expected node4 refused post-revert, got: {resp.strip()}")
    print("  OK: node4 refused again (PoA restored) — the switch is not a one-way door")


def scene_checkpoint(host):
    _banner("Checkpoint — snapshot current chain state")
    os.system(f"bash {os.path.join(DEMO, 'checkpoint.sh')} snapshot")
    if not _wait_all_ready(host):
        _fail("nodes did not come back ready after checkpoint")
    print("  OK: checkpoint saved")


def scene_restore(host):
    _banner("Restore — roll back to the last checkpoint")
    os.system(f"bash {os.path.join(DEMO, 'checkpoint.sh')} restore")
    if not _wait_all_ready(host):
        _fail("nodes did not come back ready after restore")
    print("  OK: restored from checkpoint")


def scene_drill_abort(host):
    """Rehearsed worst case: run to a scheduled update, checkpoint, then RESTORE
    instead of activating, and prove the network is back at the scheduled state
    (still validator_set) — muscle memory for the live abort path."""
    scene1_status(host)
    scene3_fund(host)
    uid, target = scene4_propose(host)
    scene5_vote(host, uid)
    head_before = _gov(host, NODE_PORTS[1])["head_hash"]
    scene_checkpoint(host)
    scene_restore(host)
    _banner("Drill — verify state after restore")
    for p in _all_ports():
        gov = _gov(host, p)
        if gov.get("eligibility_mode") != "validator_set":
            _fail(f"node:{p} not validator_set after restore: {gov.get('eligibility_mode')}")
        if gov.get("lifecycle", {}).get(uid) != "approved-and-scheduled":
            _fail(f"node:{p} update not approved-and-scheduled after restore")
        if gov.get("head_hash") != head_before:
            _fail(f"node:{p} head {gov.get('head_hash')[:12]} != checkpoint head {head_before[:12]}")
    print("  OK: restore returned all nodes to the scheduled/validator_set state")


def scene_drill_node_restart(host):
    """Restart one node and prove it reproduces the others' head + governance
    state from persisted data (restart determinism on the live network)."""
    _banner("Drill — restart node3, verify it reconverges")
    os.system(f"docker compose -f {os.path.join(DEMO, 'docker-compose.yml')} restart node3")
    if not _wait_all_ready(host):
        _fail("nodes not ready after node3 restart")
    ref = _gov(host, NODE_PORTS[1])
    n3 = _gov(host, NODE_PORTS[3])
    for field in ("head_hash", "eligibility_mode", "consensus_rules"):
        if n3.get(field) != ref.get(field):
            _fail(f"node3 {field} diverged from node1 after restart")
    print(f"  OK: node3 reconverged (head={str(n3.get('head_hash'))[:12]}, "
          f"mode={n3.get('eligibility_mode')})")


def run_e2e(host):
    scene1_status(host)
    scene2_outsider_blocked(host)
    scene3_fund(host)
    uid, target = scene4_propose(host)
    scene5_vote(host, uid)
    scene6_activate(host, uid, target)
    take_checkpoint(host)          # rollback point on the activated (stake) state
    scene7_outsider_mines(host)
    print("\n[e2e] scenes 1-7 all green.")


# Standalone scenes: name -> callable(host). Scenes 4-6 need prior state built
# up within a run, so they are reachable only through `e2e`.
_SCENES = {
    "1": scene1_status,
    "2": scene2_outsider_blocked,
    "3": scene3_fund,
    "7": scene7_outsider_mines,
    "8": scene8_poor_proposer_rejected,
    "propose-spare": scene_propose_spare,
    "propose-reverse": scene_propose_reverse,
    "vote-reverse": scene_vote_reverse,
    "activate-reverse": scene_activate_reverse,
    "checkpoint": scene_checkpoint,
    "restore": scene_restore,
    "drill-abort": scene_drill_abort,
    "drill-node-restart": scene_drill_node_restart,
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("mode", nargs="?", default="e2e", choices=["e2e"],
                   help="run the full scenes 1-7 pipeline")
    p.add_argument("--scene", choices=list(_SCENES),
                   help="run a single scene / drill (see choices)")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--threshold", type=int, default=100000,
                   help="informational; the revision file is rendered by setup.sh")
    a = p.parse_args()

    if a.scene is None:
        run_e2e(a.host)
        return
    _SCENES[a.scene](a.host)


if __name__ == "__main__":
    main()
