"""Bounty 01, stage 5: the 5,000 grant (named case 5) across TWO nodes on
the native tau-lang engine — the two-node demo for the refunds PR.

Kept in its own file so the real-Tau CI job can register exactly this file
beside tests/test_grants_native.py. The book, engine and single-node native
suites already prove named case 5 on one node; this file proves the same
case end-to-end on two: the refund path settles identically on a node that
only ever INGESTS the blocks.

What "two nodes" means here, precisely: two child processes, each a full
node state instance with its OWN sqlite database, booted from the same
genesis artifact and miner identity exactly as the single-node native
suite boots (the repo's own native-subprocess pattern —
tests/test_replay_determinism_native.py, and the recipient-controls
two-node suite). The proposer produces blocks; blocks cross to the
follower as serialized dicts (Block.to_dict(), the codebase's block wire
format; Block.from_dict() re-verifies hash and body on import), and the
follower ingests each one through chain_state.process_new_block — the
standard network/import ingestion path. No live sockets are opened;
everything else — admission, apply, the release schedule, the expiry
sweep — is the production code path on both sides.

The scenario is the maintainer's named case 5 with the official numbers,
in the exact shape the mock suites pin
(test_grants_engine_bounty01.py::test_named_case_5_end_to_end): a funder
stocks a 5,000 grant releasing 500/week; the beneficiary draws 500 in
each of weeks 1, 2 and 3 (1,500 total, each draw submitted by a third
party through the real sendtx admission); at the deadline an empty block
settles the sweep refund — exactly 3,500 back to the funder, fee-free.
Both nodes checkpoint after every step (height, head hash, state hash,
balances, sequences, grant accounting) and the parent asserts the two
streams are identical, plus the case's numbers on the stream itself.

Calendar, honestly: the grant's December is anchored at the parent's
spawn time (anchor = wall clock minus one hour, passed to both children
identically through the environment, so both sign and seal the same
fields), and the eight weeks to the deadline are compressed into block
timestamps — the chain clock advances by block headers, which is the
only clock grant semantics ever read (consensus/grants.py: conditions
are evaluated against the block timestamp, never a wall clock). Two
consequences, both deliberate:

- Blocks are hand-built after the timeline leaves the wall clock, using
  the miner's own header computation (a dry-run of engine.apply_block
  with createblock's interpreter save/restore, the resulting state hash
  embedded, the proof signed with the miner key) — createblock stamps
  wall time, which would regress against the advanced tip. Each node
  dry-runs every block itself before ingesting the identical bytes, so
  each records its own apply verdict.
- Ingestion bounds a block's future drift against the wall clock
  (chain_state._validate_block_timestamp; default 120s — an anti-spam
  guard, not grant semantics). The children widen it through the
  codebase's own configuration knob (the TAU_MAX_BLOCK_FUTURE_DRIFT
  environment variable config.py reads) so the follower can ingest the
  schedule-advancing blocks. Both children run the identical setting.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex


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

FUNDER = pubkey_hex(SK_ALICE)
BENEFICIARY = pubkey_hex(SK_BOB)
SUBMITTER = pubkey_hex(SK_CAROL)

WEEK = 604_800

# --- Child harness ------------------------------------------------------------
# One script, two roles (env TWONODE_ROLE=proposer|follower). Each child
# boots a complete node on its own database, then either produces the op
# stream (proposer) or replays it (follower). Both record checkpoints,
# apply verdicts, admissions and ingestion results as JSON; the parent
# compares the two records. The child os._exit()s after writing its
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
# The scenario's blocks run up to eight weeks ahead of the wall clock;
# widen the ingestion future-drift bound through config's own env knob
# BEFORE config is imported anywhere in this process.
os.environ["TAU_MAX_BLOCK_FUTURE_DRIFT"] = "6048000"

ROLE = os.environ["TWONODE_ROLE"]
REPO = os.environ["TWONODE_REPO"]
WORKDIR = os.environ["TWONODE_WORKDIR"]
T0 = int(os.environ["TWONODE_T0"])
DB_PATH = os.path.join(WORKDIR, ROLE + ".sqlite")
EVENTS_PATH = os.path.join(WORKDIR, "twonode_events.json")
OUT_PATH = os.path.join(WORKDIR, "twonode_" + ROLE + ".json")

FUNDER = %(FUNDER)r
BENEFICIARY = %(BENEFICIARY)r
SUBMITTER = %(SUBMITTER)r

WEEK = 604800
DAY = 86400
DEADLINE = T0 + 8 * WEEK
TX_EXPIRY = T0 + 60 * DAY

GENESIS_TAU = os.path.join(REPO, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(REPO, "rules", "04_handle_valid_transfer.tau")

result = {"role": ROLE, "checkpoints": {}, "verdicts": {}, "admissions": {},
          "ingest": {}, "notes": []}


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
    from bls_keys import SK_ALICE, SK_CAROL, sign_payload
    from block import Block
    import block as block_mod
    from commands import createblock, sendtx
    from consensus.grants import GrantEntry
    from consensus.standing_payments import SCHEDULE_WEEKLY

    GRANT_ID = GrantEntry(
        funder_pubkey=FUNDER, beneficiary_pubkey=BENEFICIARY,
        total_amount=5000, release_per_period=500,
        schedule_kind=SCHEDULE_WEEKLY, signed_day=0,
        start_ts=T0, deadline_ts=DEADLINE,
        locked_until_ts=0, window_start_ts=0, window_end_ts=0,
        inactivity_seconds=0, version=1,
    ).grant_id

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
    chain_state._balances[FUNDER] = 100000
    chain_state._balances[SUBMITTER] = 1000
    chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
    chain_state._lifecycle_manager.recompute_approval_threshold()
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
    def head_dict():
        return db.get_canonical_head_block()

    def grant_view():
        book = chain_state._lifecycle_manager.grants
        if book.grant_count() == 0:
            return None
        head = head_dict()
        return {
            "accounting": book.accounting(GRANT_ID),
            "status": book.status(GRANT_ID, int(head["header"]["timestamp"])),
            "held_total": book.held_total(),
        }

    def checkpoint(label):
        head = head_dict()
        result["checkpoints"][label] = {
            "height": int(head["header"]["block_number"]),
            "head_hash": head["block_hash"],
            "state_hash": head["header"]["state_hash"],
            "balances": {a: chain_state._balances.get(a, 0)
                         for a in (FUNDER, BENEFICIARY, SUBMITTER)},
            "sequences": {a: chain_state.get_sequence_number(a)
                          for a in (FUNDER, SUBMITTER)},
            "grant": grant_view(),
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

    def record_verdict(label, res):
        events = []
        md = res.next_snapshot.metadata or {}
        for e in (md.get("grant_events") or []):
            events.append({
                "action": e.get("action"), "amount": e.get("amount"),
                "funder": e.get("funder_pubkey"),
                "grant_id": e.get("grant_id")})
        result["verdicts"][label] = {
            "accepted": sorted(res.accepted_tx_ids),
            "invalid": sorted(res.invalid_tx_ids),
            "reasons": {o.tx_id: o.reason for o in (res.outcomes or [])},
            "next_state_hash": res.next_snapshot.state_hash,
            "grant_events": events,
        }

    def build_block(txs, ts, label):
        """Dry-run the candidate on this node's state, embed the
        resulting state hash (the real miner's header computation), sign
        the proof with the miner key as createblock does."""
        head = head_dict()
        height = int(head["header"]["block_number"]) + 1
        candidate = Block.create(
            block_number=height, previous_hash=head["block_hash"],
            transactions=txs, proposer_pubkey=config.MINER_PUBKEY,
            timestamp=ts)
        res = dry_run(candidate)
        record_verdict(label, res)
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

    def ingest(block_dict, label):
        """Follower path (and the proposer's own check for non-mined
        blocks): dry-run the imported candidate on THIS node's state,
        then ingest the identical bytes through the standard ingestion
        path."""
        candidate = Block.from_dict(block_dict)
        res = dry_run(candidate)
        record_verdict(label, res)
        result["ingest"][label] = bool(chain_state.process_new_block(candidate))

    # --- Proposer-only production helpers.
    def queue_and_fetch(payload, label):
        res = sendtx.queue_transaction(json.dumps(payload), propagate=False)
        result["admissions"][label] = {
            "ok": bool(res.get("ok")), "text": str(res)[:400]}
        if not res.get("ok"):
            raise RuntimeError(label + ": refused at admission: " + str(res))
        tx_id = payload["tx_id"]
        for raw in db.get_mempool_txs():
            tx = json.loads(raw)
            if tx.get("tx_id") == tx_id:
                return tx
        raise RuntimeError(label + ": admitted tx not found in mempool")

    def produce(label, txs, ts):
        candidate = build_block(txs, ts, label)
        result["ingest"][label] = bool(chain_state.process_new_block(candidate))
        db.clear_mempool()
        return candidate

    def create_tx():
        return sign_payload({
            "tx_id": "pr5-case5-create",
            "tx_type": "create_grant",
            "sender_pubkey": FUNDER,
            "sequence_number": chain_state.get_sequence_number(FUNDER),
            "expiration_time": TX_EXPIRY,
            "expire_at_height": 5000,
            "fee_limit": "1000",
            "grant_beneficiary_pubkey": BENEFICIARY,
            "grant_total_amount": 5000,
            "grant_release_per_period": 500,
            "grant_schedule": "weekly",
            "grant_signed_day": 0,
            "grant_start_ts": T0,
            "grant_deadline_ts": DEADLINE,
            "grant_locked_until_ts": 0,
            "grant_window_start_ts": 0,
            "grant_window_end_ts": 0,
            "grant_inactivity_seconds": 0,
            "grant_version": 1,
        }, SK_ALICE)

    def draw_tx(n):
        return sign_payload({
            "tx_id": "pr5-case5-draw-" + str(n),
            "tx_type": "draw_grant",
            "sender_pubkey": SUBMITTER,
            "sequence_number": chain_state.get_sequence_number(SUBMITTER),
            "expiration_time": TX_EXPIRY,
            "expire_at_height": 5000,
            "fee_limit": "50",
            "grant_id": GRANT_ID.hex(),
            "grant_draw_amount": 500,
        }, SK_CAROL)

    if ROLE == "proposer":
        events = []

        def emit(label, candidate):
            events.append({"op": "block", "label": label,
                           "block": candidate.to_dict()})

        checkpoint("boot")

        # The grant opens at the anchor: the funder's create is admitted
        # through the real sendtx path and custodies 5,000 via the seam.
        tx = queue_and_fetch(create_tx(), "create")
        candidate = produce("create", [tx], T0)
        emit("create", candidate)
        checkpoint("create")

        # Weeks 1-3: one 500 draw each. Draw 1 is admitted against the
        # wall-clock-side tip; draws 2 and 3 first advance the chain
        # clock with an empty schedule block, because admission reads
        # the tip (max of tip timestamp and wall clock).
        tx = queue_and_fetch(draw_tx(1), "draw1")
        candidate = produce("draw1", [tx], T0 + 10)
        emit("draw1", candidate)
        checkpoint("draw1")

        candidate = produce("advance2", [], T0 + WEEK + 10)
        emit("advance2", candidate)
        checkpoint("advance2")

        tx = queue_and_fetch(draw_tx(2), "draw2")
        candidate = produce("draw2", [tx], T0 + WEEK + 10)
        emit("draw2", candidate)
        checkpoint("draw2")

        candidate = produce("advance3", [], T0 + 2 * WEEK + 10)
        emit("advance3", candidate)
        checkpoint("advance3")

        tx = queue_and_fetch(draw_tx(3), "draw3")
        candidate = produce("draw3", [tx], T0 + 2 * WEEK + 10)
        emit("draw3", candidate)
        checkpoint("draw3")

        # The deadline block carries no transaction at all: the sweep
        # refunds the unspent remainder to the funder.
        candidate = produce("refund", [], DEADLINE)
        emit("refund", candidate)
        checkpoint("refund")

        with open(EVENTS_PATH, "w") as fh:
            json.dump({"events": events}, fh, indent=1, sort_keys=True,
                      default=str)
    else:
        with open(EVENTS_PATH) as fh:
            events = json.load(fh)["events"]
        checkpoint("boot")
        for ev in events:
            if ev["op"] != "block":
                raise RuntimeError("unknown op " + ev["op"])
            ingest(ev["block"], ev["label"])
            checkpoint(ev["label"])
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


def _child_src() -> str:
    return _CHILD_SRC % {
        "FUNDER": FUNDER, "BENEFICIARY": BENEFICIARY,
        "SUBMITTER": SUBMITTER,
    }


def _run_child(tmp_path, role, t0):
    script = tmp_path / f"grants_twonode_child_{role}.py"
    script.write_text(_child_src())
    env = dict(os.environ)
    env["TWONODE_ROLE"] = role
    env["TWONODE_REPO"] = str(_REPO)
    env["TWONODE_WORKDIR"] = str(tmp_path)
    env["TWONODE_T0"] = str(t0)
    env["TAU_FORCE_TEST"] = "0"
    env["TAU_MAX_BLOCK_FUTURE_DRIFT"] = "6048000"
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


def test_grant_case5_two_node_refund_parity(tmp_path):
    """Named case 5 on two nodes: a 5,000 grant releasing 500/week is
    drawn 500 in each of weeks 1-3 (1,500 total) and the deadline block's
    sweep refunds exactly 3,500 to the funder — identically on the
    proposer that produced the blocks and the follower that only
    ingested them, at every checkpoint, on the real engine."""
    import time
    t0 = int(time.time()) - 3600
    proc_p, prop = _run_child(tmp_path, "proposer", t0)
    _assert_child_ok(proc_p, prop, "proposer")
    proc_f, foll = _run_child(tmp_path, "follower", t0)
    _assert_child_ok(proc_f, foll, "follower")

    # Every block ingested cleanly on both nodes.
    for label, ok in sorted(foll["ingest"].items()):
        assert ok, f"follower failed to ingest {label}"
    for label, ok in sorted(prop["ingest"].items()):
        assert ok, f"proposer failed to ingest {label}"

    # Admission on the proposer accepted the create and all three draws
    # through the real sendtx path.
    for label in ("create", "draw1", "draw2", "draw3"):
        assert prop["admissions"][label]["ok"] is True, (
            f"{label} admission: {prop['admissions'][label]}")

    # Both nodes' own apply verdicts agree on every block, and the grant
    # transactions were accepted — never invalid — on both.
    assert prop["verdicts"].keys() == foll["verdicts"].keys()
    for label in prop["verdicts"]:
        assert prop["verdicts"][label] == foll["verdicts"][label], (
            f"verdict {label} diverges:\nproposer={prop['verdicts'][label]}"
            f"\nfollower={foll['verdicts'][label]}")
    for label, tx_id in (("create", "pr5-case5-create"),
                         ("draw1", "pr5-case5-draw-1"),
                         ("draw2", "pr5-case5-draw-2"),
                         ("draw3", "pr5-case5-draw-3")):
        verdict = prop["verdicts"][label]
        assert tx_id in verdict["accepted"], (label, verdict)
        assert verdict["invalid"] == [], (label, verdict)

    # The checkpoint streams are identical at every point of the
    # scenario: same height, head hash, state hash, balances, sequences
    # and grant accounting on both nodes.
    assert prop["checkpoints"].keys() == foll["checkpoints"].keys()
    for label in prop["checkpoints"]:
        assert prop["checkpoints"][label] == foll["checkpoints"][label], (
            f"checkpoint {label} diverges:\nproposer={prop['checkpoints'][label]}"
            f"\nfollower={foll['checkpoints'][label]}")

    cp = prop["checkpoints"]

    # Creation custodied the full 5,000 in the book; the funder is down
    # by the total plus exactly the create's fee, the beneficiary
    # untouched.
    assert cp["create"]["grant"] == {
        "accounting": {"principal": 5000, "drawn": 0, "held": 5000,
                       "refunded": 0},
        "status": "active", "held_total": 5000}, cp["create"]["grant"]
    create_cost = (cp["boot"]["balances"][FUNDER]
                   - cp["create"]["balances"][FUNDER])
    assert create_cost > 5000, f"create cost {create_cost} (custody + fee)"
    assert (cp["create"]["balances"][BENEFICIARY]
            == cp["boot"]["balances"][BENEFICIARY])

    # Each draw moved exactly 500 to the beneficiary; the schedule
    # blocks moved nothing.
    prev = "create"
    for label in ("draw1", "draw2", "draw3"):
        delta = (cp[label]["balances"][BENEFICIARY]
                 - cp[prev]["balances"][BENEFICIARY])
        assert delta == 500, f"{label}: beneficiary moved {delta}, not 500"
        prev = label
        if label == "draw1":
            assert cp["advance2"]["balances"] == cp["draw1"]["balances"]
        if label == "draw2":
            assert cp["advance3"]["balances"] == cp["draw2"]["balances"]
    assert (cp["draw3"]["balances"][BENEFICIARY]
            - cp["boot"]["balances"][BENEFICIARY]) == 1500
    assert cp["draw3"]["grant"]["accounting"] == {
        "principal": 5000, "drawn": 1500, "held": 3500, "refunded": 0}

    # The deadline block: the sweep refunded exactly 3,500 to the
    # funder — the delta is the remainder itself, to the unit, on both
    # nodes (the streams are equal, so the follower's delta is the same
    # number) — and both nodes' apply of that block recorded the refund
    # event.
    refund_delta = (cp["refund"]["balances"][FUNDER]
                    - cp["draw3"]["balances"][FUNDER])
    assert refund_delta == 3500, f"refund moved {refund_delta}, not 3500"
    for record in (prop, foll):
        events = record["verdicts"]["refund"]["grant_events"]
        assert len(events) == 1, events
        assert events[0]["action"] == "refunded", events
        assert events[0]["amount"] == 3500, events
        assert events[0]["funder"] == FUNDER, events

    # Final state: the grant is fully settled — nothing held, nothing
    # left to draw — at height 7 (genesis + create + 3 draws + 2
    # schedule blocks + the deadline block).
    assert cp["refund"]["grant"] == {
        "accounting": {"principal": 5000, "drawn": 1500, "held": 0,
                       "refunded": 3500},
        "status": "refunded", "held_total": 0}, cp["refund"]["grant"]
    assert cp["refund"]["height"] == 7, cp["refund"]
