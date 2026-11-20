"""Bounty 03, issues #47 + #76: recipient controls across TWO nodes on the
native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this file
beside tests/test_recipient_controls_native.py. The single-node native suite
proves the gate on one node; this file proves the same verdicts on two.

What "two nodes" means here, precisely: two child processes, each a full
node state instance with its OWN sqlite database, booted from the same
genesis artifact and miner identity exactly as the single-node native suite
boots (this is the repo's own native-subprocess pattern —
tests/test_replay_determinism_native.py, modelled on the stake-switch e2e
tests). The proposer produces blocks through the real sendtx + createblock
path; blocks cross to the follower as serialized dicts (Block.to_dict(),
the codebase's block wire format; Block.from_dict() re-verifies hash and
body on import), and the follower ingests each one through
chain_state.process_new_block — the standard network/import ingestion path
(commands/createblock.py: "The node runs standard process_new_block
ingestion as if we imported it over network"). No live sockets are opened;
everything else — admission, apply, fee accounting, escrow, the recipient
gate's clause verdicts from the real PolicyEvaluator — is the production
code path on both sides.

Scenario, asserted at checkpoints on BOTH nodes:
  (a) an allowlisted inbound transfer settles identically (balances,
      sequences, head hash and header state hash agree at the same height);
  (b) a refused inbound transfer costs no fee on both nodes — refused at
      admission on the proposer, and refused at apply on both: the block
      candidate carrying it is dry-run through the real engine on each node
      (the verdict is invalid / recipient_policy_block) and then ingested
      through process_new_block, leaving every balance and sequence
      untouched;
  (c) mid-flight tightening: with a 600-second park cap in force a 540s
      park settles into escrow on both nodes; the recipient's clause is
      then tightened to a 300-second cap on both nodes (installed through
      the same registry surfaces a real accepted offer lands on, at the
      same height — the governance outcome both nodes adopt), and a fresh
      540s park is refused at admission on the proposer (RECIPIENT_MAX_HOLD
      carrying the verified 300) and at apply on both nodes;
  (d) final parity: both nodes report the same recipient-policy view
      (getrecipientpolicy, cap 300) and the same head at the final height.

Apply-refusal mechanics, honestly: createblock drops invalid transactions
from the block it commits, so a recipient-blocked transaction never appears
in a committed block. The refusal candidates here are therefore built the
way the real miner computes a header — a dry-run of engine.apply_block
(with the interpreter save/restore createblock itself performs), the
resulting state hash embedded in the header — and the identical block
bytes are then ingested on both nodes. Each node computes its own apply
verdict before ingesting; the parent test compares them.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, pubkey_hex


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built")

_REPO = pathlib.Path(__file__).resolve().parent.parent

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
STRANGER = pubkey_hex(SK_MALLORY)

# The single-node native suite's canonical clause bodies, evaluated here by
# the real engine on both nodes: the allow-list admits only SENDER inbound;
# the cap body caps time parks and height parks, each in the park's own
# unit. TIGHT_CAP_BODY is the same body with the time cap tightened
# 600s (0x0258) -> 300s (0x012c).
ALLOWLIST_BODY = (
    "(i16[t]:bv[64] = { #x0000 }:bv[64] || "
    "i3[t]:bv[384] = { #x" + SENDER + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
)

CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0258 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

TIGHT_CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x012c }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

# --- Child harness ------------------------------------------------------------
# One script, two roles (env TWONODE_ROLE=proposer|follower). Each child
# boots a complete node on its own database, then either produces the op
# stream (proposer) or replays it (follower). Both record checkpoints,
# apply verdicts, admission outcomes and ingestion results as JSON; the
# parent compares the two records. The child os._exit()s after writing its
# record — the native engine segfaults on interpreter teardown (the
# replay-determinism harness's documented reason).
_CHILD_SRC = r'''
import hashlib
import json
import os
import sys
import time
import traceback
from unittest.mock import patch

os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"

ROLE = os.environ["TWONODE_ROLE"]
REPO = os.environ["TWONODE_REPO"]
WORKDIR = os.environ["TWONODE_WORKDIR"]
DB_PATH = os.path.join(WORKDIR, ROLE + ".sqlite")
EVENTS_PATH = os.path.join(WORKDIR, "twonode_events.json")
OUT_PATH = os.path.join(WORKDIR, "twonode_" + ROLE + ".json")

SENDER = %(SENDER)r
RECIPIENT = %(RECIPIENT)r
STRANGER = %(STRANGER)r
ALLOWLIST_BODY = %(ALLOWLIST_BODY)r
CAP_BODY = %(CAP_BODY)r
TIGHT_CAP_BODY = %(TIGHT_CAP_BODY)r

GENESIS_TAU = os.path.join(REPO, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(REPO, "rules", "04_handle_valid_transfer.tau")

result = {"role": ROLE, "checkpoints": {}, "verdicts": {}, "admissions": {},
          "ingest": {}, "produced": {}, "notes": []}


def note(msg):
    result["notes"].append(str(msg))
    print("NOTE " + str(msg))
    sys.stdout.flush()


def finish(code=0):
    with open(OUT_PATH, "w") as fh:
        json.dump(result, fh, indent=1, sort_keys=True, default=str)
    sys.stdout.flush()
    os._exit(code)


def main():
    import config
    import chain_state
    import db
    import tau_manager
    import tau_native
    from bls_keys import SK_ALICE, SK_MALLORY, sign_payload
    from block import Block
    import block as block_mod
    from commands import createblock, getrecipientpolicy, sendtx
    from tau_testnet_cli import tx as cli_tx

    # --- Boot: the single-node native suite's setUp, on this child's own DB.
    iface = tau_native.TauInterface(GENESIS_TAU)
    config.set_database_path(DB_PATH)
    if not config.MINER_PRIVKEY:
        # Miner identity via config's own loaders, assigned AFTER
        # set_database_path (whose legacy-export re-sync would wipe an
        # earlier assignment). Skip only if the identity genuinely does
        # not exist — the only skip this harness has.
        _priv = config._load_miner_privkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.key"))
        _pub = config._load_miner_pubkey_from_path(
            os.path.join(config.DATA_LOCAL_DIR, "test_miner.pub"))
        if not _priv or not _pub:
            result["skip"] = (
                "data_local/test_miner.key absent; local miner identity "
                "required for real PoA mining (see config.DATA_LOCAL_DIR)")
            finish(0)
        config.MINER_PRIVKEY = _priv
        config.MINER_PUBKEY = _pub
    if db._db_conn:
        db._db_conn.close()
    db._db_conn = None
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    db.init_db()
    chain_state.load_genesis("data/genesis.json")
    db.clear_mempool()
    chain_state._balances[SENDER] = 100000
    chain_state._balances[STRANGER] = 100000
    chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
    chain_state._lifecycle_manager.recompute_approval_threshold()
    chain_state._lifecycle_manager.activate_recipient_policy()
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_ready.set()

    def seed_rule(rule_text, label):
        out = tau_manager.communicate_with_tau(
            rule_text=rule_text, target_output_stream_index=0,
            apply_rules_update=False, source="seed-" + label)
        if "error" in str(out).lower():
            raise RuntimeError("seeding " + label + " failed: " + str(out))

    seed_rule(open(TRANSFER_RULE_PATH).read(), "transfer-rule")
    seed_rule(
        chain_state._preprocess_tau_spec_text(
            json.load(open("data/genesis.json"))["consensus_rules"]),
        "genesis-consensus")
    patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
    patch("commands.createblock._BLS_AVAILABLE", True).start()
    patch("block.bls_signing_available", return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.verify_block_header",
          return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.query_eligibility",
          return_value=True).start()

    # --- Shared helpers.
    def install_clause(body):
        lm = chain_state._lifecycle_manager
        lm.rule_offers.accepted_clauses[(RECIPIENT.lower(), 5)] = body
        with db._db_lock:
            db._insert_clause_rows([{
                "acceptor_pubkey": RECIPIENT.lower(),
                "target_stream": 5,
                "clause_body": body,
            }])
            db._db_conn.commit()

    def head_dict():
        return db.get_canonical_head_block()

    def checkpoint(label):
        head = head_dict()
        view = json.loads(getrecipientpolicy.execute(
            "getrecipientpolicy " + RECIPIENT + " " + SENDER
            + " 100 3600 seconds", None))
        result["checkpoints"][label] = {
            "height": int(head["header"]["block_number"]),
            "head_hash": head["block_hash"],
            "state_hash": head["header"]["state_hash"],
            "balances": {a: chain_state._balances.get(a, 0)
                         for a in (SENDER, RECIPIENT, STRANGER)},
            "sequences": {a: chain_state.get_sequence_number(a)
                          for a in (SENDER, RECIPIENT, STRANGER)},
            "escrow": chain_state._lifecycle_manager
                .retractable_transfers.escrow_total(),
            "policy_view": view.get("data"),
        }

    def dry_run(candidate):
        """engine.apply_block on a candidate, with the interpreter
        save/restore createblock itself performs around its simulation."""
        from consensus.engine import TauConsensusEngine
        from consensus.state import TauStateSnapshot, compute_consensus_state_hash
        engine = TauConsensusEngine()
        app_rules = (chain_state._application_rules_state or "").encode("utf-8")
        cons_rules = (chain_state._consensus_rules_state or "").encode("utf-8")
        acc_hash = chain_state.compute_accounts_hash(
            chain_state._balances, chain_state._sequence_numbers)
        meta_hash = chain_state._lifecycle_manager.consensus_meta_hash()
        parent_snapshot = TauStateSnapshot(
            state_hash=compute_consensus_state_hash(
                cons_rules, app_rules, acc_hash, meta_hash),
            tau_bytes=app_rules,
            metadata={
                "source": "chain_state",
                "balances": chain_state._balances,
                "sequence_numbers": chain_state._sequence_numbers,
                "last_transfer_ts": chain_state._last_transfer_ts,
                "lifecycle_manager": chain_state._lifecycle_manager,
                "active_consensus_id": chain_state._active_consensus_id,
                "consensus_rules_state": chain_state._consensus_rules_state,
            })
        active_view = engine.derive_active_consensus(
            parent_snapshot, candidate.header.block_number)
        saved_app_rules = chain_state.get_application_rules_state()
        try:
            saved_db_full_spec = db.get_chain_state_value("full_tau_spec", "")
        except Exception:
            saved_db_full_spec = None
        saved_full_spec = None
        try:
            _iface = tau_manager.tau_direct_interface
            if _iface is not None and hasattr(_iface, "get_current_spec"):
                saved_full_spec = _iface.get_current_spec()
        except Exception:
            saved_full_spec = None
        if saved_full_spec is None:
            saved_full_spec = tau_manager.last_known_tau_spec
        try:
            saved_shrunk = tau_manager.get_runtime_shrunk_streams()
        except Exception:
            saved_shrunk = None
        try:
            return engine.apply_block(active_view, candidate, parent_snapshot)
        finally:
            if saved_full_spec is not None:
                try:
                    tau_manager.restore_full_tau_spec(
                        saved_full_spec, runtime_shrunk_streams=saved_shrunk)
                except Exception:
                    pass
            chain_state.save_application_rules_state(saved_app_rules)
            if saved_db_full_spec is not None:
                try:
                    db.set_chain_state_value("full_tau_spec", saved_db_full_spec)
                except Exception:
                    pass

    def verdict_of(res, tx_id):
        return {
            "accepted": sorted(res.accepted_tx_ids),
            "invalid": sorted(res.invalid_tx_ids),
            "reasons": {o.tx_id: o.reason for o in (res.outcomes or [])},
            "next_state_hash": res.next_snapshot.state_hash,
        }

    def ingest_refusal(block_dict, label):
        """Follower/proposer-shared: dry-run the imported candidate on THIS
        node's state (its own apply verdict), then ingest the identical
        bytes through the standard ingestion path."""
        candidate = Block.from_dict(block_dict)
        res = dry_run(candidate)
        result["verdicts"][label] = verdict_of(res, None)
        result["ingest"][label] = bool(chain_state.process_new_block(candidate))

    # --- Proposer-only production helpers.
    def queue_transfer(sender, to, amount, sk):
        tx = json.dumps(sign_payload({
            "sender_pubkey": sender,
            "sequence_number": chain_state.get_sequence_number(sender),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[sender, to, str(amount)]]},
            "fee_limit": "50",
        }, sk))
        return sendtx.queue_transaction(tx, propagate=False)

    def mine_transfer(label, sender, to, amount, sk):
        res = queue_transfer(sender, to, amount, sk)
        if not res.get("ok"):
            raise RuntimeError(label + ": transfer refused: " + str(res))
        block_res = createblock.create_block_from_mempool()
        result["produced"][label] = {
            "n_tx": len(block_res.get("transactions", [])),
            "raw": str(block_res)[:200],
        }
        if len(block_res.get("transactions", [])) != 1:
            raise RuntimeError(label + ": block did not carry exactly the "
                               "one transfer: " + str(block_res))

    def park_payload(sender, amount, release_at_time, tx_id=None):
        head = head_dict()
        payload = cli_tx.build_retractable_transfer_tx(
            sender_pubkey=sender,
            sequence_number=chain_state.get_sequence_number(sender),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=int(head["header"]["block_number"]) + 50,
            recipient_pubkey=RECIPIENT, amount=amount, fee_limit="1000",
            release_at_time=release_at_time)
        if tx_id is not None:
            payload["tx_id"] = tx_id
        return payload

    def build_refusal_candidate(tx, label):
        """Dry-run the candidate on this node's state, embed the resulting
        state hash (the real miner's header computation), sign the proof
        with the miner key as createblock does."""
        head = head_dict()
        height = int(head["header"]["block_number"]) + 1
        ts = int(head["header"]["timestamp"]) + 10
        candidate = Block.create(
            block_number=height, previous_hash=head["block_hash"],
            transactions=[tx], proposer_pubkey=config.MINER_PUBKEY,
            timestamp=ts)
        res = dry_run(candidate)
        result["verdicts"][label] = verdict_of(res, None)
        candidate.header.state_hash = res.next_snapshot.state_hash
        candidate.header.state_locator = (
            config.STATE_LOCATOR_NAMESPACE + ":" + res.next_snapshot.state_hash)
        candidate.block_hash = block_mod.sha256_hex(
            candidate.header.canonical_bytes())
        from py_ecc.bls import G2Basic
        msg_hash = hashlib.sha256(candidate.header.canonical_bytes()).digest()
        sig = G2Basic.Sign(int(config.MINER_PRIVKEY, 16), msg_hash)
        candidate.consensus_proof = sig.hex()
        return candidate

    install_clause(ALLOWLIST_BODY)

    if ROLE == "proposer":
        events = []

        def emit(ev):
            events.append(ev)

        # Warm-up + case (a): allowlisted transfers settle.
        mine_transfer("warmup", SENDER, RECIPIENT, 1, SK_ALICE)
        emit({"op": "block", "label": "warmup", "block": head_dict()})
        checkpoint("warmup")
        mine_transfer("a_settled", SENDER, RECIPIENT, 101, SK_ALICE)
        emit({"op": "block", "label": "a_settled", "block": head_dict()})
        checkpoint("a_settled")

        # Case (b), admission half: the unlisted payer is refused by
        # sendtx — nothing queued, nothing moved.
        res = queue_transfer(STRANGER, RECIPIENT, 100, SK_MALLORY)
        result["admissions"]["b_admission"] = {
            "ok": bool(res.get("ok")), "text": str(res)[:400],
            "mempool": len(db.get_mempool_txs())}
        emit({"op": "admission", "label": "b_admission"})
        checkpoint("b_admission")

        # Case (b), apply half: a block candidate carrying the same
        # transfer is refused by the engine and ingested as a dead
        # transaction — no fee, no sequence, no movement.
        tx = sign_payload({
            "tx_id": "twonode-unlisted",
            "sender_pubkey": STRANGER,
            "sequence_number": chain_state.get_sequence_number(STRANGER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[STRANGER, RECIPIENT, "100"]]},
            "fee_limit": "50",
        }, SK_MALLORY)
        candidate = build_refusal_candidate(tx, "b_apply")
        result["ingest"]["b_apply"] = bool(
            chain_state.process_new_block(candidate))
        emit({"op": "refusal", "label": "b_apply",
              "tx_id": "twonode-unlisted", "block": candidate.to_dict()})
        checkpoint("b_apply")

        # Case (c): the 600s cap clause replaces the allow-list on this
        # node; a 540s park settles into escrow.
        install_clause(CAP_BODY)
        emit({"op": "clause", "label": "cap_installed", "which": "cap"})
        checkpoint("cap_installed")
        res = sendtx.queue_transaction(json.dumps(sign_payload(
            park_payload(SENDER, 100, int(time.time()) + 540), SK_ALICE)),
            propagate=False)
        if not res.get("ok"):
            raise RuntimeError("c_park: in-cap park refused: " + str(res))
        block_res = createblock.create_block_from_mempool()
        result["produced"]["c_park"] = {
            "n_tx": len(block_res.get("transactions", [])),
            "raw": str(block_res)[:200]}
        if len(block_res.get("transactions", [])) != 1:
            raise RuntimeError("c_park: block did not carry the park: "
                               + str(block_res))
        emit({"op": "block", "label": "c_park", "block": head_dict()})
        checkpoint("c_park")

        # Tightening: the 300s cap replaces the 600s cap at this height.
        install_clause(TIGHT_CAP_BODY)
        emit({"op": "clause", "label": "c_tightened", "which": "tight"})
        checkpoint("c_tightened")

        # Case (c), admission half: a fresh 540s park is now refused,
        # carrying the verified tightened cap.
        res = sendtx.queue_transaction(json.dumps(sign_payload(
            park_payload(SENDER, 100, int(time.time()) + 540), SK_ALICE)),
            propagate=False)
        details = res.get("details") or {}
        policy = details.get("recipient_policy") or {}
        result["admissions"]["c_admission"] = {
            "ok": bool(res.get("ok")), "text": str(res)[:600],
            "max_hold_seconds": policy.get("max_hold_seconds"),
            "mempool": len(db.get_mempool_txs())}
        emit({"op": "admission", "label": "c_admission"})
        checkpoint("c_admission")

        # Case (c), apply half: the same park, carried in a block
        # candidate, is refused by the engine under the tightened cap.
        head = head_dict()
        tx = sign_payload(park_payload(
            SENDER, 100, int(head["header"]["timestamp"]) + 10 + 540,
            tx_id="twonode-tightened-park"), SK_ALICE)
        candidate = build_refusal_candidate(tx, "c_apply")
        result["ingest"]["c_apply"] = bool(
            chain_state.process_new_block(candidate))
        emit({"op": "refusal", "label": "c_apply",
              "tx_id": "twonode-tightened-park",
              "block": candidate.to_dict()})
        checkpoint("c_apply")

        # Case (d): one last plain transfer (context "final" — the cap
        # body leaves it alone), then final parity is the parent's
        # checkpoint comparison.
        mine_transfer("d_final", SENDER, RECIPIENT, 7, SK_ALICE)
        emit({"op": "block", "label": "d_final", "block": head_dict()})
        checkpoint("d_final")

        with open(EVENTS_PATH, "w") as fh:
            json.dump({"events": events}, fh, indent=1, sort_keys=True,
                      default=str)
    else:
        with open(EVENTS_PATH) as fh:
            events = json.load(fh)["events"]
        for ev in events:
            op, label = ev["op"], ev["label"]
            if op == "block":
                blk = Block.from_dict(ev["block"])
                result["ingest"][label] = bool(
                    chain_state.process_new_block(blk))
            elif op == "refusal":
                ingest_refusal(ev["block"], label)
            elif op == "clause":
                install_clause(CAP_BODY if ev["which"] == "cap"
                               else TIGHT_CAP_BODY)
            elif op == "admission":
                pass  # admission is proposer-side; the checkpoint records
                      # this node's untouched state at the same point.
            else:
                raise RuntimeError("unknown op " + op)
            checkpoint(label)
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


def _child_src() -> str:
    return _CHILD_SRC % {
        "SENDER": SENDER, "RECIPIENT": RECIPIENT, "STRANGER": STRANGER,
        "ALLOWLIST_BODY": ALLOWLIST_BODY, "CAP_BODY": CAP_BODY,
        "TIGHT_CAP_BODY": TIGHT_CAP_BODY,
    }


def _run_child(tmp_path, role):
    script = tmp_path / f"twonode_child_{role}.py"
    script.write_text(_child_src())
    env = dict(os.environ)
    env["TWONODE_ROLE"] = role
    env["TWONODE_REPO"] = str(_REPO)
    env["TWONODE_WORKDIR"] = str(tmp_path)
    env["TAU_FORCE_TEST"] = "0"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(_REPO), str(_REPO / "tests"), env.get("PYTHONPATH", "")])
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, cwd=str(_REPO), timeout=600,
    )
    out_file = tmp_path / f"twonode_{role}.json"
    assert out_file.exists(), (
        f"{role} child wrote no record (rc={proc.returncode})\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    record = json.loads(out_file.read_text())
    return proc, record


def _assert_child_ok(proc, record, role):
    if record.get("skip"):
        pytest.skip(f"{role} child skipped: {record['skip']}")
    assert "error" not in record, (
        f"{role} child failed:\n{record.get('error')}\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


def test_recipient_controls_two_node_parity(tmp_path):
    """Two nodes, one chain: the recipient gate's verdicts — settle,
    refuse, tighten, refuse again — are identical on the proposer that
    produced the blocks and the follower that ingested them, at every
    checkpoint, on the real engine."""
    proc_p, prop = _run_child(tmp_path, "proposer")
    _assert_child_ok(proc_p, prop, "proposer")
    proc_f, foll = _run_child(tmp_path, "follower")
    _assert_child_ok(proc_f, foll, "follower")

    # Every produced block and both refusal candidates ingested cleanly on
    # both nodes (the proposer's own ingestion is the createblock path's
    # process_new_block call for mined blocks; refusals are ingested
    # explicitly on both sides).
    for label, ok in sorted(foll["ingest"].items()):
        assert ok, f"follower failed to ingest {label}"
    for label, ok in sorted(prop["ingest"].items()):
        assert ok, f"proposer failed to ingest {label}"
    for label, produced in sorted(prop["produced"].items()):
        assert produced["n_tx"] == 1, f"proposer's {label} block: {produced}"

    # The checkpoint streams are identical: same height, same head hash,
    # same state hash, same balances, sequences, escrow and policy view at
    # every point of the scenario.
    assert prop["checkpoints"].keys() == foll["checkpoints"].keys()
    for label in prop["checkpoints"]:
        assert prop["checkpoints"][label] == foll["checkpoints"][label], (
            f"checkpoint {label} diverges:\nproposer={prop['checkpoints'][label]}"
            f"\nfollower={foll['checkpoints'][label]}")

    cp = prop["checkpoints"]

    # (a) The allowlisted 101 settled: the recipient's balance moved by
    # exactly 101 across the measured block, on both nodes (the streams
    # are equal, so the follower's delta is the same number).
    delta = (cp["a_settled"]["balances"][RECIPIENT]
             - cp["warmup"]["balances"][RECIPIENT])
    assert delta == 101, f"allowlisted transfer settled {delta}, not 101"
    # The pre-flight view agrees the listed payer is admitted.
    assert cp["a_settled"]["policy_view"]["evaluation"]["admitted"] is True

    # (b) Admission refusal on the proposer: not ok, names the recipient
    # policy, nothing queued.
    adm_b = prop["admissions"]["b_admission"]
    assert adm_b["ok"] is False, adm_b
    assert "recipient" in adm_b["text"].lower(), adm_b
    assert adm_b["mempool"] == 0, adm_b
    # Apply refusal on BOTH nodes: identical verdicts, the recipient
    # reason, and the state afterwards is the state before — no fee, no
    # sequence consumed, nothing moved (the dead block still commits, so
    # the height advances by exactly one and the head hash moves with it).
    for record in (prop, foll):
        verdict = record["verdicts"]["b_apply"]
        assert verdict["invalid"] == ["twonode-unlisted"], verdict
        assert verdict["reasons"] == {
            "twonode-unlisted": "recipient_policy_block"}, verdict
    assert prop["verdicts"]["b_apply"] == foll["verdicts"]["b_apply"]
    for before, after in (("b_admission", "b_apply"),):
        assert cp[after]["balances"] == cp[before]["balances"]
        assert cp[after]["sequences"] == cp[before]["sequences"]
        assert cp[after]["escrow"] == cp[before]["escrow"]
        assert cp[after]["height"] == cp[before]["height"] + 1

    # (c) The 540s park settled under the 600s cap: escrow up exactly 100
    # on both nodes, and the pre-flight view at that point reports the
    # verified 600 cap.
    assert cp["c_park"]["escrow"] - cp["cap_installed"]["escrow"] == 100
    assert cp["cap_installed"]["policy_view"]["evaluation"][
        "max_hold_seconds"] == 600
    # After tightening, the view reports the verified 300 cap.
    assert cp["c_tightened"]["policy_view"]["evaluation"][
        "max_hold_seconds"] == 300
    # Admission refusal of a fresh 540s park, carrying the tightened cap.
    adm_c = prop["admissions"]["c_admission"]
    assert adm_c["ok"] is False, adm_c
    assert "RECIPIENT_MAX_HOLD" in adm_c["text"], adm_c
    assert adm_c["max_hold_seconds"] == 300, adm_c
    assert adm_c["mempool"] == 0, adm_c
    # Apply refusal on BOTH nodes under the tightened cap: identical
    # verdicts, escrow and balances untouched.
    for record in (prop, foll):
        verdict = record["verdicts"]["c_apply"]
        assert verdict["invalid"] == ["twonode-tightened-park"], verdict
        assert verdict["reasons"].get("twonode-tightened-park"), verdict
    assert prop["verdicts"]["c_apply"] == foll["verdicts"]["c_apply"]
    assert cp["c_apply"]["balances"] == cp["c_admission"]["balances"]
    assert cp["c_apply"]["sequences"] == cp["c_admission"]["sequences"]
    assert cp["c_apply"]["escrow"] == cp["c_admission"]["escrow"]
    assert cp["c_apply"]["height"] == cp["c_admission"]["height"] + 1

    # (d) Final parity is the checkpoint equality asserted above; pin the
    # final height (genesis + warmup + settled + dead refusal + park +
    # dead refusal + final = 6) and the final policy view's cap.
    assert cp["d_final"]["height"] == 6, cp["d_final"]
    assert cp["d_final"]["policy_view"]["evaluation"][
        "max_hold_seconds"] == 300
