"""Run a wallet's inbound rule in native admission and block policy workers."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

import chain_state
import tau_native
import tau_policy
from commands import checktx
from consensus import sender_policy
from test_checktx_estimate import node  # noqa: F401 -- worker-backed admission fixture
from test_recipient_controls import (
    A, B, C, HEIGHT, deploy, install, new_chain, park, publish_tip, transfer,
)


@pytest.mark.parametrize("guarded", [False, True], ids=["unguarded", "owner-guarded"])
def test_native_inbound_verdicts_at_admission_and_apply(node, monkeypatch, guarded):
    try:
        tau_native.load_tau_module()
    except ImportError:
        pytest.skip("native tau module not built")
    repo = str(Path(__file__).resolve().parents[1])
    env = dict(os.environ, PYTHONPATH=repo + os.pathsep + os.environ.get("PYTHONPATH", ""))
    workers = {}
    try:
        for pool in ("recipient-admission", "recipient-apply"):
            workers[pool] = tau_policy.PolicyEvaluator(pool=pool, cwd=repo, env=env, timeout=120)
            sender_policy.set_evaluator(pool, workers[pool])
        now = int(time.time())
        chain = new_chain()
        # One rule reads the complete BLS key and the host-supplied clock interval.
        # For A, a plain transfer or a park of exactly 60 seconds is admissible.
        permitted = f"(i3[t]:bv[384] = {{ #x{A} }}:bv[384] && i17[t]:bv[64] <= {{ 60 }}:bv[64])"
        allow = "(o5[t]:bv[24] = { 1 }:bv[24])"
        block = "(o5[t]:bv[24] = { 0 }:bv[24])"
        verdict = f"({permitted} ? {allow} : {block})"
        if guarded:
            owner = f"(i12[t]:bv[384] = {{ #x{B} }}:bv[384])"
            verdict = f"({owner} ? {verdict} : {allow})"
        install(chain, deploy(inbound=f"always ( {verdict} )."))
        publish_tip(chain, monkeypatch, now)
        chain_state.get_sequence_number.side_effect = lambda key: chain.seq.get(key, 0)
        monkeypatch.setitem(chain_state._balances, C, chain.bal[C])
        cases = [
            (transfer(C, 0, (B, 10)), False),
            (park(A, 0, now, seconds=61), False),
            (park(A, 0, now, seconds=60), True),
            (transfer(A, 1, (B, 10)), True),
        ]
        for tx, allowed in cases:
            result = json.loads(checktx.execute("checktx estimate " + json.dumps(tx), None))
            verdict = chain.block([tx], HEIGHT, now)
            assert (result["status"] == "ok") is allowed, result
            assert (tx["tx_id"] in verdict.accepted_tx_ids) is allowed, verdict.outcomes
            if not allowed:
                assert result["error"]["code"] == "RECIPIENT_POLICY_BLOCKED"
                assert verdict.outcomes[0].reason == "RECIPIENT_POLICY_BLOCKED"
        assert all(worker.stats()["steps"] >= len(cases) for worker in workers.values())
    finally:
        for pool, worker in workers.items():
            sender_policy.set_evaluator(pool, None)
            worker.close()


def test_mined_recipient_controls_on_local_native_chain(tmp_path):
    try:
        tau_native.load_tau_module()
    except ImportError:
        pytest.skip("native tau module not built")
    source = Path(__file__).resolve()
    repo = source.parents[1]
    paths = [str(repo), str(source.parent), os.environ.get("PYTHONPATH", "")]
    for mode in ("mine", "import"):
        data_dir = tmp_path / mode
        data_dir.mkdir()
        env = dict(os.environ, TAU_FORCE_TEST="0", TAU_ENV="test", TAU_MINING_ENABLED="false",
                   PYTHONPATH=os.pathsep.join(paths), TAU_DATA_DIR=str(data_dir),
                   TAU_DB_PATH=str(data_dir / "node.sqlite"))
        run = subprocess.run([sys.executable, str(source), mode, str(tmp_path)],
                             cwd=repo, env=env, text=True, capture_output=True, timeout=180)
        assert run.returncode == 0, run.stdout[-1500:] + run.stderr[-3000:]


def _boot(genesis, validator):
    import config
    import db
    import tau_manager

    config.MINER_PUBKEYS = [validator]
    db.init_db()
    chain_state.load_genesis(str(genesis))
    tau_manager.tau_direct_interface = tau_native.TauInterface(config.TAU_PROGRAM_FILE)
    tau_manager.tau_test_mode = False
    tau_manager.tau_process_ready.set()
    plan = chain_state.get_tau_restore_plan(use_persisted_state=False)
    chain_state.replay_tau_restore_plan(plan, source_prefix="startup")
    tau_manager.tau_ready.set()


def _account_and_policy_state(keys):
    import db
    import tau_defs
    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    head = db.get_canonical_head_block()
    assert tip.recipient_controls_active
    record = json.loads(tip.clause_for(keys["b"], tau_defs.RECIPIENT_POLICY_INDEX))
    return {
        "balances": {owner: chain_state.get_balance(pk) for owner, pk in keys.items()},
        "sequences": {owner: chain_state.get_sequence_number(pk) for owner, pk in keys.items()},
        "rule": record,
        "state_hash": head["header"]["state_hash"],
        "head": head["block_hash"],
    }


def _import_chain(work):
    from block import Block

    saved = json.loads((work / "signed-chain.json").read_text())
    keys = saved["public_keys"]
    _boot(work / "genesis.json", keys["miner"])
    # A fresh node verifies and reapplies every signed block from genesis.
    for raw in saved["blocks"]:
        block = Block.from_dict(raw)
        assert chain_state.process_new_block(block), block.header.block_number
    assert _account_and_policy_state(keys) == saved["final_state"]


def _mine_local_chain(work):
    """Fresh ephemeral accounts; exercise admission, canonical mining and reload."""
    import config
    import db
    from bls_keys import pubkey_hex, sign_payload
    from commands import createblock, sendtx
    from py_ecc.bls import G2Basic

    secrets = {name: G2Basic.KeyGen(os.urandom(32)) for name in ("miner", "a", "b", "c")}
    keys = {name: pubkey_hex(secret) for name, secret in secrets.items()}
    genesis = work / "genesis.json"
    cmd = [sys.executable, "scripts/gen_genesis.py", "--validator-key", keys["miner"],
           "--base-fee", "10", "--recipient-controls", "--network-id", "local-recipient-test",
           "--out", str(genesis)]
    for owner in ("a", "b", "c"):
        cmd.extend(["--account", keys[owner] + ":10000"])
    subprocess.run(cmd, check=True)

    config.MINER_PRIVKEY = format(secrets["miner"], "064x")
    config.MINER_PUBKEY = keys["miner"]
    _boot(genesis, keys["miner"])

    def height():
        return db.get_canonical_head_block()["header"]["block_number"]

    def seal():
        block = createblock.create_block_from_mempool(allow_empty=True)
        assert "block_hash" in block, block

    def submit(owner, tx_type="user_tx", **fields):
        pk = keys[owner]
        tx = {
            "tx_type": tx_type, "sender_pubkey": pk,
            "sequence_number": chain_state.get_sequence_number(pk),
            "expiration_time": int(time.time()) + 3600, "expire_at_height": height() + 15,
            "fee_limit": "100", **fields,
        }
        return sendtx.queue_transaction(json.dumps(sign_payload(tx, secrets[owner])), propagate=False)

    def pay(owner):
        return submit(owner, operations={"1": [[keys[owner], keys["b"], "55"]]})

    def policy(cap):
        inbound = (
            f"always ( (i3[t]:bv[384] = {{ #x{keys['a']} }}:bv[384]) "
            "? (o5[t]:bv[24] = { 1 }:bv[24]) : (o5[t]:bv[24] = { 0 }:bv[24]) )."
        )
        unit = "recipient_v1 o5[t] " + json.dumps({"inbound": inbound, "max_hold_blocks": cap})
        return submit("b", operations={"0": unit})

    def escrow(release):
        return submit("a", "retractable_transfer", recipient_pubkey=keys["b"], amount=40,
                      release_at_height=release, expire_at_height=height() + 2)

    seal()
    assert policy(4)["ok"]
    seal()
    assert pay("c")["code"] == "RECIPIENT_POLICY_BLOCKED"
    assert pay("a")["ok"]
    seal()
    assert chain_state.get_balance(keys["b"]) == 10_045

    refused = escrow(height() + 6)
    assert refused["code"] == "RECIPIENT_MAX_HOLD" and refused["details"]["max_hold_blocks"] == 4
    release = height() + 4
    assert escrow(release)["ok"]
    seal()
    assert chain_state.get_balance(keys["b"]) == 10_045
    assert policy(0)["ok"]
    seal()
    while height() < release:
        seal()

    assert chain_state.load_state_from_db()
    assert height() == 7
    state = _account_and_policy_state(keys)
    assert state["balances"] == {"a": 9885, "b": 10075, "c": 10000, "miner": 40}
    assert state["rule"]["max_hold_blocks"] == 0
    blocks = db.get_canonical_blocks_at_or_after_height(1)
    assert len(blocks) == 7
    (work / "signed-chain.json").write_text(json.dumps({
        "blocks": blocks, "public_keys": keys, "final_state": state,
    }))


if __name__ == "__main__":
    mode, directory = sys.argv[1:]
    {"mine": _mine_local_chain, "import": _import_chain}[mode](Path(directory))
