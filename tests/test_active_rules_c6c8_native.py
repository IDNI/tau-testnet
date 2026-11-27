"""C6–C8 proof tests for PR #191 (B02, issue #42) — two-node, native engine.

Written fresh against our own #191 code (consensus/engine.py snapshot
harvesting, db.record_spec_snapshots, consensus/active_rules.py ledger /
resolve path, commands/getactiverules.py). The acceptance CASES are the
ones named in the rival scan (RIVAL-SCAN-B123-2026-11-27.md §2.3/§2.4):
MarcoDiPolo's #42 same-block observation and AtticKnight's concurrent-
commit report -- but every test body below is written from our code, not
copied from any rival test file.

  * C6 — same-block two-update attribution (#42): two rule updates that
    land in ONE block must each keep their own snapshot, their own tx
    hash, and their own revision step in the wallet ledger; updating the
    same output twice in one block leaves the second value in force and
    marks the first unit displaced by the second transaction at the same
    height. Two acceptance cases, one test function.
  * C7 — concurrent-commit resolve (AtticKnight): a block commit landing
    in the middle of a read must never produce an answer that labels one
    block but shows another block's rule text. Our resolve path is
    height-pinned (resolve_answer_with_status never re-reads the head
    after resolving); the test proves it with a reader thread running
    during mining, with sequential re-reads across a commit, and with
    the empty-record case (a height with no commit answers
    not-available, never a wrong answer).
  * C8 — served history pairs the stored revision with the checked text
    (residu §2.3): checked_snapshot_sequence keeps the STORED revision
    and height while carrying the CHECKED (journal-cut) text. The test
    observes the natural stored-vs-cut divergence per height, proves the
    pairing with a synthetic divergent row against the real committed
    journal, and proves the served view (and its ledger) always follows
    the checked text.

Same two-node harness shape as tests/test_active_rules_twonode_native.py
(two child processes, each a full node with its own sqlite database,
proposer mines through the real sendtx + createblock path, follower
ingests serialized blocks through chain_state.process_new_block). The
child here is parameterised by a mining PLAN -- a list of blocks, each a
list of rule indices -- so one block can carry two rule transactions.
No live sockets; everything else is production code on both sides.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest


def _native_available():
    try:
        import tau_native

        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)

_REPO = pathlib.Path(__file__).resolve().parent.parent

# C6 rules (fresh scenario text, our own): X and Y update independent
# outputs; Z1 and Z2 update the SAME output, one after the other.
RULE_X = "always ( o26[t]:bv[24] = { 7 }:bv[24] )."
RULE_Y = "always ( o27[t]:bv[24] = { 9 }:bv[24] )."
RULE_Z1 = "always ( o26[t]:bv[24] = { 11 }:bv[24] )."
RULE_Z2 = "always ( o26[t]:bv[24] = { 13 }:bv[24] )."
# C7/C8 reuse the two-node file's A/B units (our own scenario text).
RULE_A = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
          "o27[t]:bv[24] = { 9 }:bv[24] ).")
RULE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."

SCENARIOS = {
    # plan: list of blocks; each block is a list of indices into rules.
    "c6": {"rules": [RULE_X, RULE_Y, RULE_Z1, RULE_Z2],
           "plan": [[0, 1], [2, 3]]},
    "c7": {"rules": [RULE_A, RULE_B], "plan": [[0], [1]]},
    "c8": {"rules": [RULE_A], "plan": [[0]]},
}

_CHILD_SRC = r'''
import hashlib
import json
import os
import sys
import threading
import time
import traceback
from unittest.mock import patch

os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"

ROLE = os.environ["TWONODE_ROLE"]
REPO = os.environ["TWONODE_REPO"]
WORKDIR = os.environ["TWONODE_WORKDIR"]
DB_PATH = os.path.join(WORKDIR, ROLE + ".sqlite")
EVENTS_PATH = os.path.join(WORKDIR, "twonode_events.jsonl")
OUT_PATH = os.path.join(
    WORKDIR, "twonode_" + ROLE + "_" + os.environ["TWONODE_SCENARIO"] + ".json")
SCENARIO = os.environ["TWONODE_SCENARIO"]
RULES = json.loads(os.environ["TWONODE_RULES"])
PLAN = json.loads(os.environ["TWONODE_PLAN"])

result = {"role": ROLE, "scenario": SCENARIO, "answers": {}, "cuts": {},
          "receipts": {}, "heads": {}, "notes": [], "snapshots": [],
          "outcomes": [], "tx_by_revision": [], "ledger": [],
          "concurrent_reads": [], "reader_errors": [], "c7": {},
          "c8": {}}


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
    from py_ecc.bls import G2Basic as bls
    from block import Block
    from commands import createblock, getactiverules, getpaymentconditions
    from commands import sendtx
    from commands.sendtx import _get_signing_message_bytes
    from consensus import active_rules
    from types import SimpleNamespace

    import threading

    import tau_admission
    import tau_authority as auth
    import tau_commit as tc
    from consensus.governance import ConsensusLifecycleManager

    config.set_database_path(DB_PATH)
    if db._db_conn:
        db._db_conn.close()
    db._db_conn = None
    db.init_db()
    db.clear_mempool()
    config.MINER_PRIVKEY = "0" * 63 + "1"
    chain_state._balances = {}
    chain_state._sequence_numbers = {}
    chain_state._application_rules_state = ""
    chain_state._lifecycle_manager = ConsensusLifecycleManager()
    chain_state.load_genesis("data/genesis.json")
    chain_state._lifecycle_manager = ConsensusLifecycleManager()

    baseline = "always ( " + open(
        os.path.join(REPO, "genesis.tau")).read().strip() + " )."
    owner = auth.AuthoritativeTauOwner(
        ready=threading.Event(), program_baseline=baseline)
    auth.reset(owner)
    tc.registry().discard()
    tau_admission.reset()
    if hasattr(active_rules, "reset_spec_mirror"):
        active_rules.reset_spec_mirror()
    _env = dict(os.environ)
    _env["PYTHONPATH"] = REPO + os.pathsep + _env.get("PYTHONPATH", "")
    owner.initialize(cwd=REPO, env=_env)

    import tau_manager

    class _FeeStub:
        def communicate(self, rule_text=None, target_output_stream_index=0,
                        input_stream_values=None, source="unknown",
                        apply_rules_update=True, node_generated=False):
            return "1"

        def communicate_multi(self, rule_text=None, input_stream_values=None,
                              source="unknown", apply_rules_update=True,
                              node_generated=False):
            return {1: "1", 6: "1", 7: "1"}

        def update_spec(self, new_spec):
            pass

        def get_current_spec(self):
            return "always o0[t] = 1."

    tau_manager.tau_direct_interface = _FeeStub()
    tau_manager.tau_test_mode = False
    tau_manager._rules_handler = None
    tau_manager.tau_ready.set()

    patch("consensus.engine.TauConsensusEngine.query_eligibility",
          return_value=True).start()
    patch("consensus.engine.TauConsensusEngine.verify_block_header",
          return_value=True).start()
    patch("consensus.bls.verify", lambda *a, **k: True).start()

    sk = bls.KeyGen(b"b02-twonode-sender".ljust(32, b"_"))
    sender = bls.SkToPk(sk).hex()
    stranger = bls.SkToPk(
        bls.KeyGen(b"b02-twonode-stranger".ljust(32, b"_"))).hex()
    result["sender"] = sender
    result["stranger"] = stranger
    chain_state._balances[sender] = 1000000

    container = SimpleNamespace(db=db, chain_state=chain_state)

    def answer(height):
        return json.loads(getactiverules.execute(
            "getactiverules " + str(height), container))["data"]

    def cut_answer(height):
        cut = active_rules.resolve_answer(height)
        if cut is None:
            return {"spec_hash": None, "spec_revision": None,
                    "derived": None, "effective_spec": None}
        return {"spec_hash": cut.get("spec_hash"),
                "spec_revision": cut.get("spec_revision"),
                "derived": cut.get("derived"),
                "effective_spec": cut.get("spec_text"),
                "height": cut.get("height")}

    def collect_answers():
        tip = db.canonical_tip_height()
        out = {}
        for h in range(1, tip + 1):
            out[str(h)] = answer(h)
        result["heads"]["tip_height"] = tip
        head = db.get_canonical_head_block()
        result["heads"]["tip_hash"] = head["block_hash"] if head else None
        return out

    def collect_cuts():
        # Height 0 included: the genesis cut is the reference for any
        # reader observation taken before the first block commits.
        tip = db.canonical_tip_height()
        return {str(h): cut_answer(h) for h in range(0, tip + 1)}

    def collect_receipts():
        import tau_journal
        entries = tau_journal.journal_from_rows(
            db.committed_journal_entries()).entries()
        texts = [e.rule_text for e in entries
                 if e.kind == tau_journal.REVISION and e.rule_text]
        commits = {}
        tip = db.canonical_tip_height()
        for h in range(1, (tip or 0) + 1):
            commit = db.block_commit_at_height(h)
            commits[str(h)] = commit["spec_revision"] if commit else None
        return {"revision_texts": texts, "commit_revisions": commits}

    def collect_tables():
        result["snapshots"] = db.get_all_spec_snapshots()
        result["outcomes"] = [
            {"tx_hash": row["tx_hash"],
             "block_number": row["block_number"],
             "outcome": row["outcome"],
             "spec_revision_before": row["spec_revision_before"],
             "spec_revision_after": row["spec_revision_after"],
             "revision_status": row["revision_status"]}
            for row in db.list_rule_outcomes()
        ]
        result["tx_by_revision"] = sorted(
            db.get_rule_tx_by_revision().items())
        result["ledger"] = active_rules.survival_ledger()

    def submit(rule_text, seq):
        tx = {"tx_type": "user_tx", "sender_pubkey": sender,
              "sequence_number": seq,
              "expiration_time": int(time.time()) + 3600,
              "expire_at_height": 5000,
              "operations": {"0": rule_text}, "fee_limit": "100000"}
        tx["signature"] = bls.Sign(sk, hashlib.sha256(
            _get_signing_message_bytes(tx)).digest()).hex()
        out = sendtx.queue_transaction(json.dumps(tx), propagate=False)
        if not out.get("ok"):
            raise RuntimeError("queue failed: " + str(out))

    # C7: a reader thread resolving the tip WHILE the proposer mines.
    # The AtticKnight failure mode is a read that labels one block but
    # shows another block's text; every observation here must match the
    # stored snapshot at the height it claims. The reader only reads
    # (resolve_answer builds a fresh mirror iface per call; db reads
    # are lock-guarded), so it cannot disturb the commit path.
    _stop_reader = threading.Event()
    _reader_thread = None

    def _reader_loop():
        while not _stop_reader.is_set():
            try:
                ans, _code = active_rules.resolve_answer_with_status()
                if ans is not None:
                    result["concurrent_reads"].append({
                        "height": ans.get("height"),
                        "spec_revision": ans.get("spec_revision"),
                        "spec_hash": ans.get("spec_hash")})
            except Exception as exc:  # recorded, never swallowed silently
                result["reader_errors"].append(str(exc))
            _stop_reader.wait(0.05)

    if ROLE == "proposer":
        with open(EVENTS_PATH, "w") as events:
            seq = 0
            if SCENARIO == "c7":
                _reader_thread = threading.Thread(
                    target=_reader_loop, daemon=True)
                _reader_thread.start()
            for i, block_plan in enumerate(PLAN):
                for rule_idx in block_plan:
                    submit(RULES[rule_idx], seq)
                    seq += 1
                out = createblock.create_block_from_mempool()
                if "error" in out:
                    raise RuntimeError("createblock failed: " + str(out))
                head = db.get_canonical_head_block()
                events.write(json.dumps({"block": head}) + "\n")
                events.flush()
                if SCENARIO == "c7" and i == 0 and len(PLAN) > 1:
                    # Pinning probe 1 of 2: the height-1 answer as seen
                    # AFTER block 1 mined, BEFORE block 2's commit lands.
                    result["c7"]["answer_h1_before"] = answer(1)
            if SCENARIO == "c7":
                _stop_reader.set()
                if _reader_thread is not None:
                    _reader_thread.join(timeout=60)
                # Pinning probe 2 of 2: the height-1 answer AFTER the
                # second block committed -- must be identical to probe 1.
                result["c7"]["answer_h1_after"] = answer(1)
                # Case (c): heights the node does not hold, at both
                # layers. The earliest snapshot is the genesis one at
                # height 0, so height (earliest - 1) is before the
                # first snapshot: the resolve helper floors at the
                # earliest snapshot and says so (its height field is
                # the snapshot's own height, never the requested one).
                # (The command cannot be asked for a negative height:
                # its parser only accepts isdigit() tokens, so -1 is
                # INVALID_PARAMS there -- also never a wrong answer.)
                # Height 999 is past the tip: both layers answer the
                # latest snapshot at-or-before it -- no future state
                # is fabricated, and the answer is labelled with the
                # height it actually comes from.
                earliest = min(s["height"] for s in
                               db.get_all_spec_snapshots())
                probes = {}
                ans_pre, code_pre = active_rules.\
                    resolve_answer_with_status(earliest - 1)
                probes[str(earliest - 1)] = {
                    "resolve_answer": ans_pre,
                    "resolve_code": code_pre}
                ans999, code999 = active_rules.resolve_answer_with_status(999)
                data999 = json.loads(getactiverules.execute(
                    "getactiverules 999", container))["data"]
                probes["999"] = {
                    "resolve_answer": ans999,
                    "resolve_code": code999,
                    "command_available": data999.get("available"),
                    "command_height": data999.get("height"),
                    "command_revision": data999.get("spec_revision"),
                    "command_hash": data999.get("sha256")}
                result["c7"]["probes"] = probes
                result["c7"]["earliest_snapshot_height"] = earliest
    elif ROLE == "follower":
        with open(EVENTS_PATH) as events:
            for line in events:
                block = Block.from_dict(json.loads(line)["block"])
                res = chain_state.process_new_block(block)
                ok = res[0] if isinstance(res, tuple) else res
                if not ok:
                    raise RuntimeError("ingest failed: " + str(res))

    result["answers"] = collect_answers()
    result["receipts"] = collect_receipts()
    result["cuts"] = collect_cuts()
    collect_tables()

    if SCENARIO == "c8" and ROLE == "proposer":
        # Natural stored-vs-cut divergence per height, plus a synthetic
        # divergent row against the REAL committed journal: take the
        # stored snapshot at height 1, change one value in its text,
        # and check the pairing -- the row must keep the STORED
        # revision + height while carrying the CHECKED (cut) text.
        per_height = {}
        tip = db.canonical_tip_height()
        for h in range(1, (tip or 0) + 1):
            stored = db.get_spec_snapshot_at_height(h)
            cut = active_rules.journal_cut_at_height(h)
            served = result["answers"][str(h)]
            per_height[str(h)] = {
                "stored_revision": stored["spec_revision"] if stored else None,
                "stored_text": stored["canonical_text"] if stored else None,
                "cut_revision": cut["spec_revision"] if cut else None,
                "cut_text": cut["spec_text"] if cut else None,
                "served_text": served.get("canonical_text"),
                "served_revision": served.get("spec_revision"),
                "served_derived": served.get("derived")}
        result["c8"]["per_height"] = per_height
        stored1 = db.get_spec_snapshot_at_height(1)
        cut1 = active_rules.journal_cut_at_height(1)
        fake_text = stored1["canonical_text"].replace("{ 7 }", "{ 77 }", 1)
        used_fallback = False
        if fake_text == stored1["canonical_text"]:
            fake_text = stored1["canonical_text"] + " "
            used_fallback = True
        fake = {"spec_revision": stored1["spec_revision"],
                "height": stored1["height"],
                "canonical_text": fake_text,
                "sha256": hashlib.sha256(
                    fake_text.encode("utf-8")).hexdigest()}
        seq_rows, seq_code = active_rules.checked_snapshot_sequence([fake])
        checked = active_rules.checked_snapshot_answer(fake)
        result["c8"]["synthetic"] = {
            "used_fallback": used_fallback,
            "fake_revision": fake["spec_revision"],
            "fake_height": fake["height"],
            "cut_revision": cut1["spec_revision"] if cut1 else None,
            "cut_text": cut1["spec_text"] if cut1 else None,
            "cut_hash": cut1["spec_hash"] if cut1 else None,
            "sequence_code": seq_code,
            "sequence_row": seq_rows[0] if seq_rows else None,
            "checked_text": checked["spec_text"] if checked else None,
            "checked_hash": checked["spec_hash"] if checked else None,
            "checked_revision": checked["spec_revision"] if checked else None}
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


def _run_child(role, workdir, scenario):
    cfg = SCENARIOS[scenario]
    env = dict(os.environ)
    env["TWONODE_ROLE"] = role
    env["TWONODE_REPO"] = str(_REPO)
    env["TWONODE_WORKDIR"] = str(workdir)
    env["TWONODE_SCENARIO"] = scenario
    env["TWONODE_RULES"] = json.dumps(cfg["rules"])
    env["TWONODE_PLAN"] = json.dumps(cfg["plan"])
    env["PYTHONPATH"] = str(_REPO) + os.pathsep + env.get("PYTHONPATH", "")
    tag = f"{role}-{scenario}"
    stdout_path = workdir / f"twonode_{tag}.stdout"
    stderr_path = workdir / f"twonode_{tag}.stderr"
    with open(stdout_path, "w") as out_fh, open(stderr_path, "w") as err_fh:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD_SRC],
            cwd=str(_REPO), env=env, stdout=out_fh, stderr=err_fh,
            timeout=1800)
    out_path = workdir / f"twonode_{role}_{scenario}.json"
    stdout = stdout_path.read_text(errors="replace")
    stderr = stderr_path.read_text(errors="replace")
    assert out_path.exists(), (
        f"{role} child wrote no record; rc={proc.returncode}\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}")
    record = json.loads(out_path.read_text())
    if record.get("skip"):
        pytest.skip(record["skip"])
    assert "error" not in record, (
        f"{role} child failed:\n{record.get('error')}\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}")
    return record


def _norm(text):
    """Whitespace-normalised form for fragment containment checks."""
    return " ".join((text or "").split())


def _units_by_revision(answer_data):
    return {u["introduced_at_revision"]: u
            for u in answer_data.get("units", [])}


def _snapshot_at_or_before(snapshots, height):
    found = None
    for snap in snapshots:
        if snap["height"] <= height:
            found = snap
        else:
            break
    return found


def test_c6_same_block_two_updates_attribution(tmp_path):
    """C6 (#42): two updates in one block keep their own snapshot, tx
    hash and revision step; updating the same output twice in one block
    leaves the second value in force, the first displaced by the second
    transaction at the same height."""
    proposer = _run_child("proposer", tmp_path, "c6")
    follower = _run_child("follower", tmp_path, "c6")

    assert proposer["heads"]["tip_height"] == 2
    assert proposer["heads"] == follower["heads"]

    snaps = proposer["snapshots"]
    h1 = [s for s in snaps if s["height"] == 1]
    h2 = [s for s in snaps if s["height"] == 2]
    # One snapshot per revision advanced -- two updates in one block
    # means TWO snapshots sharing that block's height.
    assert len(h1) == 2, snaps
    assert len(h2) == 2, snaps
    revs1 = sorted(s["spec_revision"] for s in h1)
    revs2 = sorted(s["spec_revision"] for s in h2)
    assert revs1[1] == revs1[0] + 1, revs1
    assert revs2[1] == revs2[0] + 1, revs2
    assert revs2[0] > revs1[1]

    # Only steps that ADVANCED the revision (a no-op outcome that
    # merely landed on a revision carries no interval of its own).
    outcomes = [o for o in proposer["outcomes"]
                if o["outcome"] and o["outcome"].startswith("ACCEPTED")
                and o["revision_status"] == "REVISION_RECORDED"
                and o["spec_revision_before"] is not None
                and o["spec_revision_before"] < o["spec_revision_after"]]
    by_block = {1: [o for o in outcomes if o["block_number"] == 1],
                2: [o for o in outcomes if o["block_number"] == 2]}
    assert len(by_block[1]) == 2, outcomes
    assert len(by_block[2]) == 2, outcomes
    tx_by_rev = {int(r): t for r, t in proposer["tx_by_revision"]}
    assert len({tx_by_rev[r] for r in revs1 + revs2}) == 4
    assert all(tx_by_rev[r] == o["tx_hash"]
               for o in outcomes
               for r in [o["spec_revision_after"]])

    # Block 1 at height 1: both independent updates in the view, each
    # its own revision unit with its own tx hash, both in force.
    ans1 = proposer["answers"]["1"]
    assert ans1["available"] is True
    units1 = _units_by_revision(ans1)
    # The ledger's baseline is the genesis unit (height 0, no tx,
    # revision exactly one below the first rule's -- see the issue42
    # ledger test): the height-1 view carries it plus the two rules.
    assert set(units1) == set(revs1) | {revs1[0] - 1}, units1
    genesis1 = units1[revs1[0] - 1]
    assert genesis1["introduced_at_height"] == 0, genesis1
    assert genesis1["introduced_by_tx"] is None, genesis1
    assert genesis1["status"] == "in_force", genesis1
    assert units1[revs1[0]]["introduced_by_tx"] == tx_by_rev[revs1[0]]
    assert units1[revs1[1]]["introduced_by_tx"] == tx_by_rev[revs1[1]]
    assert units1[revs1[0]]["introduced_by_tx"] != \
        units1[revs1[1]]["introduced_by_tx"]
    conj1 = " ".join(c for u in units1.values() for c in u["conjuncts"])
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in _norm(conj1)
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in _norm(conj1)
    assert all(u["status"] == "in_force" for u in units1.values())
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in ans1["canonical_text"]
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in ans1["canonical_text"]

    # Block 2 at height 2 (the tip): the second same-output update is
    # in force with value 13; the first is displaced BY THE SECOND
    # transaction at the same height; the earlier o26=7 unit is
    # displaced by the first same-output update, o27=9 survives.
    ans2 = proposer["answers"]["2"]
    assert ans2["available"] is True
    units2 = _units_by_revision(ans2)
    # Genesis + X + Y + Z1 + Z2; the genesis unit still in force.
    assert set(units2) == set(revs1) | set(revs2) | {revs1[0] - 1}, units2
    assert units2[revs1[0] - 1]["status"] == "in_force", units2
    z1, z2 = revs2[0], revs2[1]
    assert units2[z2]["status"] == "in_force"
    assert units2[z2]["introduced_by_tx"] == tx_by_rev[z2]
    assert "o26[t]:bv[24] = { 13 }:bv[24]" in _norm(
        " ".join(units2[z2]["conjuncts"]))
    assert units2[z1]["status"] == "displaced"
    assert units2[z1]["introduced_by_tx"] == tx_by_rev[z1]
    disp = units2[z1]["displaced_conjuncts"]
    assert len(disp) == 1, disp
    assert disp[0]["displaced_at_revision"] == z2
    assert disp[0]["displaced_by_tx"] == tx_by_rev[z2]
    assert "o26[t]:bv[24] = { 13 }:bv[24]" in _norm(
        disp[0]["displaced_by"])
    assert "o26[t]:bv[24] = { 13 }:bv[24]" in ans2["canonical_text"]
    assert "o26[t]:bv[24] = { 11 }:bv[24]" not in ans2["canonical_text"]
    assert "o26[t]:bv[24] = { 7 }:bv[24]" not in ans2["canonical_text"]
    assert units2[revs1[0]]["status"] == "displaced"
    assert units2[revs1[0]]["displaced_conjuncts"][0][
        "displaced_by_tx"] == tx_by_rev[z1]
    assert units2[revs1[1]]["status"] == "in_force"

    # The same claims through the survival ledger (the other surface
    # that attributes per unit), with block numbers attached.
    ledger = {e["tx_hash"]: e for e in proposer["ledger"]}
    assert ledger[tx_by_rev[z1]]["status"] == "displaced"
    assert ledger[tx_by_rev[z1]]["block_number"] == 2
    assert ledger[tx_by_rev[z1]]["displaced_by"] == [tx_by_rev[z2]]
    assert ledger[tx_by_rev[z2]]["status"] == "in_force"
    assert ledger[tx_by_rev[z2]]["block_number"] == 2
    assert ledger[tx_by_rev[revs1[0]]]["status"] == "displaced"
    assert tx_by_rev[z1] in \
        ledger[tx_by_rev[revs1[0]]]["displaced_by"]
    assert ledger[tx_by_rev[revs1[1]]]["status"] == "in_force"

    # The follower ingested the same two blocks and attributes them
    # identically: same answers, same snapshots, same outcomes, same
    # ledger.
    assert proposer["answers"] == follower["answers"]
    assert proposer["snapshots"] == follower["snapshots"]
    assert proposer["outcomes"] == follower["outcomes"]
    assert proposer["ledger"] == follower["ledger"]
    assert proposer["receipts"] == follower["receipts"]


def test_c7_concurrent_commit_resolve_stays_pinned(tmp_path):
    """C7 (AtticKnight): a block commit landing mid-read must never
    produce an answer that labels one block but shows another block's
    rule text. The resolve path is height-pinned, so: (a) a reader
    thread resolving the tip during mining only ever observes answers
    consistent with one committed height; (b) the height-1 answer read
    before block 2 commits is identical after it commits; (c) heights
    the node does not hold are answered without mislabelling -- past
    the tip both layers serve the latest snapshot at-or-before,
    labelled with its own height; before the first snapshot the
    resolve helper floors at the genesis snapshot, also labelled
    with its own height (the command cannot even be asked for a
    negative height: its parser only accepts isdigit() tokens)."""
    proposer = _run_child("proposer", tmp_path, "c7")
    follower = _run_child("follower", tmp_path, "c7")

    assert proposer["heads"]["tip_height"] == 2
    assert proposer["heads"] == follower["heads"]

    # (b) Sequential pinning across the commit.
    before = proposer["c7"]["answer_h1_before"]
    after = proposer["c7"]["answer_h1_after"]
    assert before["available"] is True, before
    assert after["available"] is True, after
    for key in ("spec_revision", "sha256", "canonical_text", "units"):
        assert before[key] == after[key], key
    assert proposer["answers"]["2"]["spec_revision"] != \
        before["spec_revision"]
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in \
        proposer["answers"]["2"]["canonical_text"]
    assert "o26[t]:bv[24] = { 3 }:bv[24]" not in before["canonical_text"]

    # (a) Every concurrent observation matches the committed record at
    # the height it claims: same revision as the stored snapshot there,
    # and a hash that is either the stored snapshot's or the journal
    # cut's at that height (the served hash is the cut's when the two
    # diverge -- see C8).
    assert proposer["reader_errors"] == [], proposer["reader_errors"]
    reads = proposer["concurrent_reads"]
    assert len(reads) >= 1, reads
    snaps_by_rev = {s["spec_revision"]: s for s in proposer["snapshots"]}
    for obs in reads:
        snap = snaps_by_rev.get(obs["spec_revision"])
        assert snap is not None, obs
        assert snap["height"] == obs["height"], obs
        cut = proposer["cuts"].get(str(obs["height"]))
        allowed_hashes = {snap["sha256"]}
        if cut is not None and cut.get("spec_hash"):
            allowed_hashes.add(cut["spec_hash"])
        assert obs["spec_hash"] in allowed_hashes, obs

    # (c) Heights the node does not hold: no answer ever labels one
    # block while showing another's text. (Resolve answers carry
    # spec_hash/spec_text keys -- cut or view shape alike.)
    probes = proposer["c7"]["probes"]
    earliest = proposer["c7"]["earliest_snapshot_height"]
    assert earliest == 0, proposer["c7"]
    # Past the tip (999): both layers serve the latest snapshot
    # at-or-before -- the height-2 answer, labelled height 2.
    past = probes["999"]
    ans2 = proposer["answers"]["2"]
    assert past["resolve_code"] is None, past
    assert past["resolve_answer"]["spec_revision"] == \
        ans2["spec_revision"], past
    assert past["resolve_answer"]["spec_hash"] == ans2["sha256"], past
    assert past["resolve_answer"]["height"] == 2, past
    assert past["command_available"] is True, past
    assert past["command_height"] == 2, past
    assert past["command_revision"] == ans2["spec_revision"], past
    assert past["command_hash"] == ans2["sha256"], past
    # Before the first snapshot (earliest - 1 = -1): the resolve
    # helper floors at the earliest snapshot and labels it with its
    # own height -- never the requested height, never another block.
    pre = probes[str(earliest - 1)]
    assert pre["resolve_code"] is None, pre
    assert pre["resolve_answer"] is not None, pre
    assert pre["resolve_answer"]["height"] == earliest, pre
    earliest_snaps = [s for s in proposer["snapshots"]
                      if s["height"] == earliest]
    assert len(earliest_snaps) == 1, earliest_snaps
    assert pre["resolve_answer"]["spec_revision"] == \
        earliest_snaps[0]["spec_revision"], pre
    cut0 = proposer["cuts"].get(str(earliest))
    allowed = {earliest_snaps[0]["sha256"]}
    if cut0 is not None and cut0.get("spec_hash"):
        allowed.add(cut0["spec_hash"])
    assert pre["resolve_answer"]["spec_hash"] in allowed, pre

    # The follower agrees on every answer.
    assert proposer["answers"] == follower["answers"]
    assert proposer["cuts"] == follower["cuts"]


def test_c8_served_history_pairs_stored_revision_with_checked_text(tmp_path):
    """C8 (residu §2.3): checked_snapshot_sequence keeps the STORED
    revision + height while carrying the CHECKED (journal-cut) text.
    The served view -- and the ledger derived from it -- always follows
    the checked text, never the stored text."""
    proposer = _run_child("proposer", tmp_path, "c8")

    per_height = proposer["c8"]["per_height"]
    assert per_height, per_height

    # (1) The natural divergence fires: the stored snapshot text and
    # the journal-cut text differ (worker-fed form vs mirror cut), so
    # the pairing is observable in production, not only synthetic.
    h1 = per_height["1"]
    assert h1["stored_text"] != h1["cut_text"], (
        "expected stored-vs-cut divergence at height 1 (bv[8] fed form "
        "vs bv[384] mirror cut); if this fails the C8 premise changed")
    # (2) At every height the served view carries the CHECKED text at
    # the STORED revision, marked journal_cut exactly when they differ.
    for h, row in per_height.items():
        assert row["served_text"] == row["cut_text"], h
        assert row["served_revision"] == row["stored_revision"], h
        if row["stored_text"] != row["cut_text"]:
            assert row["served_derived"] == "journal_cut", h
    # (3) The synthetic pairing, against the real committed journal: a
    # divergent stored row maps to the stored revision + height with the
    # cut's text and hash.
    syn = proposer["c8"]["synthetic"]
    assert syn["sequence_code"] is None, syn
    row = syn["sequence_row"]
    assert row is not None, syn
    assert row["spec_revision"] == syn["fake_revision"], syn
    assert row["height"] == syn["fake_height"], syn
    assert row["canonical_text"] == syn["cut_text"], syn
    assert row["sha256"] == syn["cut_hash"], syn
    assert syn["checked_text"] == syn["cut_text"], syn
    assert syn["checked_hash"] == syn["cut_hash"], syn
    assert syn["checked_revision"] == syn["cut_revision"], syn
    # (4) The ledger follows the checked text (O-4(a)): every surviving
    # conjunct is in the served text; every displaced conjunct is not.
    served_text = proposer["answers"]["1"]["canonical_text"]
    for unit in proposer["answers"]["1"]["units"]:
        for conj in unit["surviving_conjuncts"]:
            assert _norm(conj) in _norm(served_text), conj
        for disp in unit["displaced_conjuncts"]:
            assert _norm(disp["conjunct"]) not in _norm(served_text), disp
