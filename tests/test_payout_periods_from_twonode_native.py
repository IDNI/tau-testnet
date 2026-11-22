"""Bounty 01, FIX-1A: named case 5 in the Tau-clause form, with a signed
periods_from anchor, across TWO nodes on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this
file beside tests/test_payout_tau_rule_native.py. The single-node
native suite proves the grant example as a Tau payout rule and the
periods_from grid at book level; this file proves the two together,
end to end, on two nodes: the same settlement stream lands identically
on a node that only ever INGESTS the blocks, with the period grid
counted from the signed anchor — never from the install day.

What "two nodes" means here is exactly what the grants two-node suite
(test_grants_twonode_native.py) established: two child processes, each
a full node state instance with its OWN sqlite database, booted from
the same genesis artifact and miner identity; the proposer produces
blocks; blocks cross to the follower as serialized dicts
(Block.to_dict() / Block.from_dict()) and the follower ingests each
through chain_state.process_new_block. Blocks after the timeline
leaves the wall clock are hand-built with the miner's own header
computation (a dry-run of engine.apply_block, the resulting state hash
embedded, the proof signed with the miner key), and the ingestion
future-drift bound is widened through config's own env knob
(TAU_MAX_BLOCK_FUTURE_DRIFT) — both children run the identical setting.

The scenario, with the official numbers: a grant account holds 5,000.
Its owner's Tau clause is the grant's terms — before the deadline it
pays Bob what the current period still owes of 500 (500 minus the
period's paid total at i26, which the node feeds from the book); at or
after the deadline it pays the funder the account's whole remaining
balance (read at i2). The rule's periods are WEEKS counted from the
signed periods_from anchor (the "1 December" of the case), and the
install lands two weeks and three days after that anchor — mid-week-2
of the anchored grid, at a moment the install-anchored grid would call
week 0. The draws then discriminate the two grids in the money path
itself, not just in bookkeeping:

- draw 1, in anchored week 2: settles 500, recorded under anchored
  period 2 — the install grid would have recorded period 0;
- a second execution in the same anchored week settles nothing (the
  clause reads i26 = 500 for that week and computes no leg), on both
  nodes;
- draw 2, at anchor + 3 weeks + 10s: PAYS 500. The anchored grid calls
  this week 3 (i26 reads 0); the install grid — whose week 0 runs to
  install + 7 days, three days later — would still call it week 0 and
  read i26 = 500, refusing the draw. The grids give different answers
  here and the chain follows the anchored one;
- draw 3, in anchored week 4: settles 500 (1,500 drawn in total);
- after the deadline, one more execution (base 1 — the amount comes
  from the clause's state inputs) refunds exactly 3,500 to the funder.

The declared caps (3,500 per execution, 3,500 per period) never bind
in this scenario: the weekly discipline is the clause's, computed over
the anchored i26 feed — which is precisely the quantity periods_from
re-anchors. Both nodes checkpoint after every step (height, head hash,
state hash, balances, sequences, the payout book's period totals and
settlement list) and the parent asserts the two streams are identical,
plus the case's numbers on the stream itself.

Installation is the one deliberate shortcut, stated plainly: both
children install the identical entry with the book's own install call
at boot — the single-node native suite's idiom for this book — rather
than through an install transaction (that path is covered by the
admission and mock suites). The case's numbers require it: an install
transaction charges the grant account its own install fee (measured
10 in this suite's first CI run), after which the account holds 4,990
and the remainder is 3,490, not the case's exact 3,500. With the book
install the account holds exactly 5,000, and every number below is
the official one, to the unit.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex


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
BOB = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
OWNER = pubkey_hex(SK_MALLORY)

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
# The scenario's blocks run up to five weeks ahead of the wall clock;
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
BOB = %(BOB)r
EXECUTOR = %(EXECUTOR)r
OWNER = %(OWNER)r

WEEK = 604800
DAY = 86400
INSTALL_TS = T0 + 2 * WEEK + 3 * DAY
DEADLINE = T0 + 5 * WEEK
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


def grant_clause(bob_idx, funder_idx):
    """The grant's terms as a Tau clause body (sender_policy wraps it).

    Before the deadline: pay Bob what the current anchored period
    still owes of the weekly 500 (500 - i26). At/after the deadline:
    pay the funder the account's remaining balance (i2). Every branch
    assigns all three leg outputs, and the clause reads i26/i5/i2 — a
    clause that reads no input stream cannot be stepped by the policy
    worker at all.
    """
    def no_legs():
        return ("((o30[t]:bv[64] = { 0 }:bv[64]) "
                "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
                "&& (o32[t]:bv[64] = { 0 }:bv[64]))")

    def one_leg(idx, amount_expr):
        return ("((o30[t]:bv[64] = { 1 }:bv[64]) "
                "&& (o31[t]:bv[64] = { " + str(idx) + " }:bv[64]) "
                "&& (o32[t]:bv[64] = " + amount_expr + "))")

    draw = ("((i26[t]:bv[64] < { 500 }:bv[64]) "
            "? " + one_leg(bob_idx, "({ 500 }:bv[64] - i26[t]:bv[64])")
            + " : " + no_legs() + ")")
    refund = ("((i2[t]:bv[64] < { 1 }:bv[64]) "
              "? " + no_legs()
              + " : " + one_leg(funder_idx, "i2[t]:bv[64]") + ")")
    return ("((i5[t]:bv[64] < { " + str(DEADLINE) + " }:bv[64]) "
            "? " + draw + " : " + refund + ")")


def main():
    import config
    import chain_state
    import db
    import tau_manager
    import tau_native
    from bls_keys import SK_CAROL, sign_payload
    from block import Block
    import block as block_mod
    from commands import createblock, sendtx
    from consensus.payout_rules import FORM_TAU_RULE, PayoutRuleEntry

    RECIPIENTS = sorted([BOB, FUNDER])
    CLAUSE = grant_clause(RECIPIENTS.index(BOB), RECIPIENTS.index(FUNDER))

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
    chain_state._balances[OWNER] = 5000  # stocked by the funder
    chain_state._balances[EXECUTOR] = 100000
    chain_state._balances[FUNDER] = 0
    chain_state._balances[BOB] = 0
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

    def payout_view():
        book = chain_state._lifecycle_manager.payout_rules
        entry = book.get(OWNER)
        if entry is None:
            return None
        return {
            "rule_id": entry.rule_id.hex(),
            "period_totals": {
                str(i): book.period_total(entry.rule_id, i)
                for i in range(7)},
            "settled": sorted(
                s.settlement_id.hex()
                for s in book.settlements_for(entry.rule_id)),
        }

    def checkpoint(label):
        head = head_dict()
        result["checkpoints"][label] = {
            "height": int(head["header"]["block_number"]),
            "head_hash": head["block_hash"],
            "state_hash": head["header"]["state_hash"],
            "balances": {a: chain_state._balances.get(a, 0)
                         for a in (OWNER, BOB, FUNDER, EXECUTOR)},
            "sequences": {a: chain_state.get_sequence_number(a)
                          for a in (OWNER, EXECUTOR)},
            "payout": payout_view(),
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
        result["verdicts"][label] = {
            "accepted": sorted(res.accepted_tx_ids),
            "invalid": sorted(res.invalid_tx_ids),
            "reasons": {o.tx_id: o.reason for o in (res.outcomes or [])},
            "next_state_hash": res.next_snapshot.state_hash,
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

    def rule_id_hex():
        entry = chain_state._lifecycle_manager.payout_rules.get(OWNER)
        return entry.rule_id.hex()

    def execute_tx(tx_id, sid_hex, base):
        return sign_payload({
            "tx_id": tx_id,
            "tx_type": "execute_payout_rule",
            "sender_pubkey": EXECUTOR,
            "sequence_number": chain_state.get_sequence_number(EXECUTOR),
            "expiration_time": TX_EXPIRY,
            "expire_at_height": 5000,
            "fee_limit": "50",
            "payout_rule_id": rule_id_hex(),
            "payout_settlement_id": sid_hex,
            "payout_base_amount": base,
        }, SK_CAROL)

    # --- Shared: the identical entry, installed with the book's own
    # install call on BOTH children (see the module docstring for why
    # not an install transaction: the case's exact numbers). The
    # install's recorded moment is anchor + 2 weeks + 3 days —
    # mid-week-2 of the anchored grid, week 0 of the install grid.
    checkpoint("boot")
    entry = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=tuple(RECIPIENTS), legs=(),
        max_per_execution=3500, max_per_period=3500,
        period_seconds=WEEK, period_anchor_ts=INSTALL_TS, version=1,
        form=FORM_TAU_RULE, clause_text=CLAUSE, periods_from_ts=T0,
    )
    chain_state._lifecycle_manager.payout_rules.install(entry, INSTALL_TS)
    checkpoint("install")

    if ROLE == "proposer":
        events = []

        def emit(label, candidate):
            events.append({"op": "block", "label": label,
                           "block": candidate.to_dict()})

        # Draw 1 in anchored week 2.
        tx = queue_and_fetch(execute_tx("fix1a-draw-1", "11" * 32, 500), "draw1")
        candidate = produce("draw1", [tx], INSTALL_TS + 10)
        emit("draw1", candidate)
        checkpoint("draw1")

        # A second execution in the same anchored week, force-included
        # with admission bypassed: the clause computes no leg (i26
        # already reads 500 for this week), so it settles nothing.
        tx = execute_tx("fix1a-draw-1b", "22" * 32, 500)
        candidate = produce("draw1b", [tx], INSTALL_TS + 20)
        emit("draw1b", candidate)
        checkpoint("draw1b")

        # Advance the chain clock into anchored week 3, then draw 2 —
        # a timestamp the install grid would still call week 0.
        candidate = produce("advance3", [], T0 + 3 * WEEK + 5)
        emit("advance3", candidate)
        checkpoint("advance3")

        tx = queue_and_fetch(execute_tx("fix1a-draw-2", "33" * 32, 500), "draw2")
        candidate = produce("draw2", [tx], T0 + 3 * WEEK + 10)
        emit("draw2", candidate)
        checkpoint("draw2")

        candidate = produce("advance4", [], T0 + 4 * WEEK + 5)
        emit("advance4", candidate)
        checkpoint("advance4")

        tx = queue_and_fetch(execute_tx("fix1a-draw-3", "44" * 32, 500), "draw3")
        candidate = produce("draw3", [tx], T0 + 4 * WEEK + 10)
        emit("draw3", candidate)
        checkpoint("draw3")

        # Past the deadline the clause's refund leg is selected: one
        # execution with base 1 returns the whole remainder.
        candidate = produce("advance5", [], T0 + 5 * WEEK + 5)
        emit("advance5", candidate)
        checkpoint("advance5")

        tx = queue_and_fetch(execute_tx("fix1a-refund", "55" * 32, 1), "refund")
        candidate = produce("refund", [tx], T0 + 5 * WEEK + 10)
        emit("refund", candidate)
        checkpoint("refund")

        with open(EVENTS_PATH, "w") as fh:
            json.dump({"events": events}, fh, indent=1, sort_keys=True,
                      default=str)
    else:
        with open(EVENTS_PATH) as fh:
            events = json.load(fh)["events"]
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
        "FUNDER": FUNDER, "BOB": BOB, "EXECUTOR": EXECUTOR, "OWNER": OWNER,
    }


def _run_child(tmp_path, role, t0):
    script = tmp_path / f"payout_twonode_child_{role}.py"
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
        capture_output=True, text=True, env=env, cwd=str(_REPO), timeout=900,
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


def test_case5_tau_form_periods_from_two_node_parity(tmp_path):
    """Named case 5, Tau-clause form, periods_from set, on two nodes:
    a 5,000 grant whose clause pays 500 per anchored week is installed
    two weeks and three days after its signed anchor; three weekly
    draws settle (1,500), a same-week repeat settles nothing, and the
    post-deadline execution refunds exactly 3,500 — identically on the
    proposer that produced the blocks and the follower that only
    ingested them, at every checkpoint, on the real engine."""
    import time
    t0 = int(time.time()) - 3600
    proc_p, prop = _run_child(tmp_path, "proposer", t0)
    _assert_child_ok(proc_p, prop, "proposer")
    proc_f, foll = _run_child(tmp_path, "follower", t0)
    _assert_child_ok(proc_f, foll, "follower")

    # Every block ingested cleanly on both nodes. The one stated
    # exception is the same-week repeat's block: whether a block
    # carrying a settles-nothing execution is ingested or refused is
    # the engine's business — parity requires only that BOTH nodes did
    # the same thing with it, which is asserted instead.
    assert prop["ingest"].keys() == foll["ingest"].keys()
    for label in prop["ingest"]:
        assert prop["ingest"][label] == foll["ingest"][label], (
            f"ingest {label} diverges: proposer={prop['ingest'][label]}"
            f" follower={foll['ingest'][label]}")
        if label != "draw1b":
            assert prop["ingest"][label], f"block {label} not ingested"

    # Admission on the proposer accepted all three draws and the
    # refund through the real sendtx path.
    for label in ("draw1", "draw2", "draw3", "refund"):
        assert prop["admissions"][label]["ok"] is True, (
            f"{label} admission: {prop['admissions'][label]}")

    # Both nodes' own apply verdicts agree on every block; the admitted
    # transactions were accepted — never invalid — on both.
    assert prop["verdicts"].keys() == foll["verdicts"].keys()
    for label in prop["verdicts"]:
        assert prop["verdicts"][label] == foll["verdicts"][label], (
            f"verdict {label} diverges:\nproposer={prop['verdicts'][label]}"
            f"\nfollower={foll['verdicts'][label]}")
    for label, tx_id in (("draw1", "fix1a-draw-1"),
                         ("draw2", "fix1a-draw-2"),
                         ("draw3", "fix1a-draw-3"),
                         ("refund", "fix1a-refund")):
        verdict = prop["verdicts"][label]
        assert tx_id in verdict["accepted"], (label, verdict)
        assert verdict["invalid"] == [], (label, verdict)

    # The checkpoint streams are identical at every point of the
    # scenario: same height, head hash, state hash, balances, sequences
    # and payout accounting on both nodes.
    assert prop["checkpoints"].keys() == foll["checkpoints"].keys()
    for label in prop["checkpoints"]:
        assert prop["checkpoints"][label] == foll["checkpoints"][label], (
            f"checkpoint {label} diverges:\nproposer={prop['checkpoints'][label]}"
            f"\nfollower={foll['checkpoints'][label]}")

    cp = prop["checkpoints"]

    # The install recorded the rule; nothing paid yet.
    assert cp["install"]["payout"]["period_totals"] == {
        str(i): 0 for i in range(7)}, cp["install"]["payout"]
    assert cp["install"]["payout"]["settled"] == []

    # Draw 1 settles 500 to Bob, recorded under ANCHORED period 2 —
    # the install grid would have called this period 0.
    totals = cp["draw1"]["payout"]["period_totals"]
    assert totals["2"] == 500, totals
    assert totals["0"] == 0, totals
    assert (cp["draw1"]["balances"][BOB] - cp["install"]["balances"][BOB]) == 500
    assert (cp["install"]["balances"][OWNER]
            - cp["draw1"]["balances"][OWNER]) == 500

    # The same-week repeat settles nothing: Bob, the grant account and
    # the funder are exactly where draw 1 left them, and the period
    # totals and settlement list do not move (the executor's own fee
    # handling, whatever it is, is identical on both nodes — the
    # streams above are equal).
    for acct in (BOB, OWNER, FUNDER):
        assert (cp["draw1b"]["balances"][acct]
                == cp["draw1"]["balances"][acct]), acct
    assert cp["draw1b"]["payout"]["period_totals"] == totals
    assert cp["draw1b"]["payout"]["settled"] == cp["draw1"]["payout"]["settled"]

    # The schedule blocks move nothing.
    assert cp["advance3"]["balances"] == cp["draw1b"]["balances"]
    assert cp["advance4"]["balances"] == cp["draw2"]["balances"]
    assert cp["advance5"]["balances"] == cp["draw3"]["balances"]

    # Draws 2 and 3 settle 500 each, under anchored periods 3 and 4.
    totals = cp["draw3"]["payout"]["period_totals"]
    assert totals["2"] == 500 and totals["3"] == 500 and totals["4"] == 500, totals
    assert totals["0"] == 0 and totals["1"] == 0, totals
    assert (cp["draw3"]["balances"][BOB] - cp["boot"]["balances"][BOB]) == 1500
    assert cp["draw3"]["balances"][OWNER] == 3500

    # The refund execution returns exactly 3,500 to the funder — the
    # delta is the remainder itself, to the unit — recorded under
    # anchored period 5, and the grant account ends empty.
    refund_delta = (cp["refund"]["balances"][FUNDER]
                    - cp["draw3"]["balances"][FUNDER])
    assert refund_delta == 3500, f"refund moved {refund_delta}, not 3500"
    assert cp["refund"]["balances"][OWNER] == 0
    assert cp["refund"]["payout"]["period_totals"]["5"] == 3500
    assert cp["refund"]["payout"]["settled"] == sorted(
        ["11" * 32, "33" * 32, "44" * 32, "55" * 32])

    # The refund block closes the stream two heights after draw 3
    # (the deadline-advance block, then the refund block itself) —
    # stated relatively so the assertion does not depend on whether
    # the same-week repeat's block was ingested or refused identically
    # on both nodes (the streams above pin that it was the SAME on
    # both, which is the parity this file exists to prove).
    assert cp["refund"]["height"] == cp["draw3"]["height"] + 2, cp["refund"]
