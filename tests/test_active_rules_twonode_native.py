"""Issue #42 (B02-4, ported to the #151 line; B02-6): the rules-in-force
view across TWO nodes, on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this
file beside tests/test_active_rules_issue42_native.py, in the form the
Bounty 03 two-node suite established: two child processes, each a full
node with its OWN sqlite database, booted from the same genesis
artifact and miner identity. The proposer mines through the real
sendtx + createblock path; blocks cross as serialized dicts
(Block.to_dict / Block.from_dict -- the codebase's block wire format)
and the follower ingests them through chain_state.process_new_block,
the standard import path. No live sockets are opened; everything else
-- admission, apply, the journal, the commits -- is production code on
both sides.

Scenario: the named resend case plus one unrelated unit -- A
(o26 = {7} && o27 = {9}), B (o26 = {3}), A again, then a constant
rule over o28 -- one block each. Asserted on BOTH nodes, per height:

  * the getactiverules answer (spec hash + revision) from the stored
    snapshots agrees;
  * after the snapshots are wiped on the proposer, the journal-cut
    answer agrees too, carries `derived: "journal_cut"`, and at
    block 3 runs the first unit's terms (o26 = 7, o27 = 9) -- while
    the snapshot-only command itself answers not-available; the
    follower keeps its snapshots, so its command still answers and
    its cuts serve the kept snapshot;
  * the committed journal record (revision texts in order, and each
    block commit's spec_revision) agrees;
  * getpaymentconditions for a clause-free pair agrees: same block,
    same spec, both sides neutral, allowed.

Then the follower is RESTARTED as a new process on the same database
(chain_state.load_state_from_db, the production restart path). Its
snapshots were NOT wiped before the restart -- the restart mirrors
production, where the snapshot table is durable and fast-load reads
it -- so the restarted node must answer every height identically,
proving the view survives a production restart on the committed
record, not on any process's memory. (Opsi B, bedah B02 §4: the
rebuild path is NOT called here -- extending the fee stub so a
rebuild could run would fake a green, and is rejected.)

PORT NOTE: the #134-line original read cut answers through its
`getactiverules`; on this line the command serves snapshots only, so
the children read cuts through `consensus.active_rules.resolve_answer`
(the surface `getpaymentconditions` resolves through) and assert the
command's own post-wipe answer is an explicit not-available.
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
    not _native_available(), reason="native tau module not built")

_REPO = pathlib.Path(__file__).resolve().parent.parent

RULE_A = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
          "o27[t]:bv[24] = { 9 }:bv[24] ).")
RULE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
# A fourth unit over an unrelated stream, so the scenario also crosses
# a block the A/B/A assertions do not read. (An o5-only unit cannot be
# the fourth: admission routes a rule that only defines o5 as a clause
# declaration and refuses it for reading no input stream.)
RULE_D = "always ( o28[t]:bv[24] = { 42 }:bv[24] )."
RULES = [RULE_A, RULE_B, RULE_A, RULE_D]

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
RESTART = os.environ.get("TWONODE_RESTART") == "1"
REPO = os.environ["TWONODE_REPO"]
WORKDIR = os.environ["TWONODE_WORKDIR"]
DB_PATH = os.path.join(WORKDIR, ROLE + ".sqlite")
EVENTS_PATH = os.path.join(WORKDIR, "twonode_events.jsonl")
OUT_PATH = os.path.join(
    WORKDIR, "twonode_" + ROLE + ("-restart" if RESTART else "") + ".json")

RULES = %(RULES)r

result = {"role": ROLE, "restart": RESTART, "answers": {}, "cuts": {},
          "receipts": {}, "heads": {}, "notes": []}


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

    # --- Boot: the single-node native suite's boot (conftest node_state
    # + the authority fixture of test_active_rules_issue42_native.py),
    # on this child's own DB. Production nodes run the authoritative
    # worker, and it matters here: direct-mode admission probes an op-0
    # rule as if it were a policy clause and refuses it ("clause cannot
    # be evaluated: it reads no input stream"), so the children run
    # authority mode exactly like the single-node authority harness.
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
    if RESTART:
        if not chain_state.load_state_from_db():
            raise RuntimeError("load_state_from_db failed on restart")
    else:
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

    # conftest's fake_engine, mirrored: tau_manager's advisory paths
    # (the fee gate in createblock waits on tau_ready; fee quotes read
    # the direct interface) get the harness's canned answers, while the
    # authoritative worker above does the real rule work.
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
    if not RESTART:
        chain_state._balances[sender] = 1000000

    container = SimpleNamespace(db=db, chain_state=chain_state)

    def answer(height):
        data = json.loads(getactiverules.execute(
            "getactiverules " + str(height), container))["data"]
        return {"available": data.get("available"),
                "spec_hash": data.get("sha256"),
                "spec_revision": data.get("spec_revision")}

    def cut_answer(height):
        cut = active_rules.resolve_answer(height)
        if cut is None:
            return {"spec_hash": None, "spec_revision": None,
                    "derived": None, "effective_spec": None}
        return {"spec_hash": cut.get("spec_hash"),
                "spec_revision": cut.get("spec_revision"),
                "derived": cut.get("derived"),
                "effective_spec": cut.get("spec_text")}

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
        tip = db.canonical_tip_height()
        return {str(h): cut_answer(h) for h in range(1, tip + 1)}

    def collect_receipts():
        # The journal is the record both nodes must agree on: every
        # REVISION text in order (genesis units first, then the
        # scenario's), plus each block commit's spec_revision.
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

    def payment_probe():
        data = json.loads(getpaymentconditions.execute(
            "getpaymentconditions " + sender + " " + stranger + " 100",
            container))["data"]
        return {"allowed": data["allowed"],
                "block_height": data["block"]["height"],
                "spec_hash": data["spec"]["spec_hash"],
                "sender_has_clause": data["sender_side"]["has_clause"],
                "recipient_has_clause": data["recipient_side"]["has_clause"]}

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

    if ROLE == "proposer" and not RESTART:
        with open(EVENTS_PATH, "w") as events:
            for i, rule in enumerate(RULES):
                submit(rule, i)
                out = createblock.create_block_from_mempool()
                if "error" in out:
                    raise RuntimeError("createblock failed: " + str(out))
                head = db.get_canonical_head_block()
                events.write(json.dumps({"block": head}) + "\n")
                events.flush()
    elif ROLE == "follower" and not RESTART:
        with open(EVENTS_PATH) as events:
            for line in events:
                block = Block.from_dict(json.loads(line)["block"])
                res = chain_state.process_new_block(block)
                ok = res[0] if isinstance(res, tuple) else res
                if not ok:
                    raise RuntimeError("ingest failed: " + str(res))

    result["answers"] = collect_answers()
    result["receipts"] = collect_receipts()
    result["payment"] = payment_probe()
    result["snapshots_present"] = db.get_latest_spec_snapshot() is not None
    if not RESTART and ROLE == "proposer":
        # Opsi B (bedah B02 §4): only the proposer wipes. The follower
        # keeps its snapshots so its restart mirrors production, where
        # the snapshot table is durable and fast-load reads it.
        with db._db_lock:
            db._db_conn.execute("DELETE FROM spec_snapshots")
            db._db_conn.commit()
        # This line's command serves snapshots only: wiped means an
        # explicit not-available, recorded here so the parent can pin
        # it; the cut collection below is the journal's answer.
        result["answers_after_wipe"] = collect_answers()
    result["cuts"] = collect_cuts()
    finish(0)


try:
    main()
except Exception:
    result["error"] = traceback.format_exc()
    finish(3)
'''


def _run_child(role, workdir, restart=False):
    env = dict(os.environ)
    env["TWONODE_ROLE"] = role
    env["TWONODE_REPO"] = str(_REPO)
    env["TWONODE_WORKDIR"] = str(workdir)
    if restart:
        env["TWONODE_RESTART"] = "1"
    env["PYTHONPATH"] = str(_REPO) + os.pathsep + env.get("PYTHONPATH", "")
    # Child output goes to files, not pipes: if a child has to be killed
    # at the timeout, worker grandchildren holding a pipe open must not
    # be able to keep the parent blocked on pipe EOF.
    tag = f"{role}{'-restart' if restart else ''}"
    stdout_path = workdir / f"twonode_{tag}.stdout"
    stderr_path = workdir / f"twonode_{tag}.stderr"
    with open(stdout_path, "w") as out_fh, open(stderr_path, "w") as err_fh:
        proc = subprocess.run(
            [sys.executable, "-c", _CHILD_SRC % {"RULES": RULES}],
            cwd=str(_REPO), env=env, stdout=out_fh, stderr=err_fh,
            timeout=1800)
    out_name = f"twonode_{role}{'-restart' if restart else ''}.json"
    out_path = workdir / out_name
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


def test_rules_view_agrees_across_two_nodes(tmp_path):
    proposer = _run_child("proposer", tmp_path)
    follower = _run_child("follower", tmp_path)
    restarted = _run_child("follower", tmp_path, restart=True)

    heights = [str(h) for h in range(1, len(RULES) + 1)]
    # Same head, same snapshot answers, same journal on all three
    # processes (proposer, follower, restarted follower).
    assert proposer["heads"] == follower["heads"]
    for h in heights:
        for key in ("spec_hash", "spec_revision"):
            assert proposer["answers"][h][key] == follower["answers"][h][key]
            assert restarted["answers"][h][key] == \
                proposer["answers"][h][key]
    assert proposer["receipts"] == follower["receipts"] == \
        restarted["receipts"]
    # The scenario's four units were recorded as revisions, in order
    # (the resend of A included -- no deduplication), and the commits'
    # spec_revision advanced by exactly one per block (genesis commits
    # its own rules first, so the absolute values start above 4).
    texts = proposer["receipts"]["revision_texts"]
    stream = iter(texts)
    assert all(any(t == want for t in stream) for want in RULES), texts
    revs = [proposer["receipts"]["commit_revisions"][str(h)]
            for h in range(1, len(RULES) + 1)]
    assert all(r is not None for r in revs), revs
    assert all(b == a + 1 for a, b in zip(revs, revs[1:])), revs

    # After the proposer's wipe, its command answers not-available and
    # its journal cuts agree with the snapshot answers they replaced;
    # the follower kept its snapshots (Opsi B), so its command still
    # answers from the durable table and its cuts serve the kept
    # snapshot. The restarted follower answers identically from the
    # same table (its resolve_answer may serve the kept snapshot --
    # the hash and revision are the claim, not the source marker).
    # Proposer: wiped -> its command answers not-available, and its
    # journal cuts agree with the snapshot answers they replaced.
    assert proposer["snapshots_present"] is True
    for h in heights:
        assert proposer["answers_after_wipe"][h]["available"] is False
        cut = proposer["cuts"][h]
        assert cut["derived"] == "journal_cut"
        assert cut["spec_hash"] == proposer["answers"][h]["spec_hash"]
        assert cut["spec_revision"] == \
            proposer["answers"][h]["spec_revision"]
    # Follower: snapshots KEPT (Opsi B) -> its command still answers
    # from the durable table, and its served answers agree with the
    # journal cuts (same hash and revision). NOTE (F1b): a cut always
    # carries derived="journal_cut" (a cut IS a journal cut) -- the
    # earlier assert cut["derived"] is None was wrong by
    # construction and was never reached while the follower was
    # wiped. The claim is the hash/revision agreement, not the
    # source marker: the served answers may themselves carry
    # derived="journal_cut" when the Step 7 stopgap fires (here the
    # genesis b02 is shrunk to bv[8] in the worker's fed form,
    # bv[384] in the mirror cut -- O-4).
    assert follower["snapshots_present"] is True
    assert "answers_after_wipe" not in follower
    for h in heights:
        assert follower["answers"][h]["available"] is True
        cut = follower["cuts"][h]
        assert cut["derived"] == "journal_cut"
        assert cut["spec_hash"] == follower["answers"][h]["spec_hash"]
        assert cut["spec_revision"] == \
            follower["answers"][h]["spec_revision"]
        assert cut["spec_hash"] == proposer["answers"][h]["spec_hash"]
        assert cut["spec_revision"] == \
            proposer["answers"][h]["spec_revision"]
    assert restarted["snapshots_present"] is True
    for h in heights:
        cut = restarted["cuts"][h]
        assert cut["spec_hash"] == proposer["answers"][h]["spec_hash"]
        assert cut["spec_revision"] == proposer["answers"][h]["spec_revision"]
    at3 = proposer["cuts"]["3"]["effective_spec"]
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in at3
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in at3
    assert "{ 3 }" not in at3
    at2 = proposer["cuts"]["2"]["effective_spec"]
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in at2

    # Two-sided payment conditions agree on all three processes.
    assert proposer["payment"] == follower["payment"] == \
        restarted["payment"]
    assert proposer["payment"]["allowed"] is True
    assert proposer["payment"]["sender_has_clause"] is False
    assert proposer["payment"]["recipient_has_clause"] is False
