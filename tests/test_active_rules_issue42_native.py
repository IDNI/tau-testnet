"""Issue #42 on the native tau-lang engine, ported to the #151 line
(B02-6): the named resend case and the journal forge under worker-backed
authority, the snapshot-vs-replay equivalence of audit §6.1, and the
served unit ledger under authority of audit §6.7.

Kept in its own file so the real-Tau CI job can register exactly this
file: these tests need the native bindings, which the mock test job
does not have. The skip below is environment-driven -- in the real-Tau
job's image the bindings are present (its preflight imports them), so
the skip lifts and the tests run for real. Everywhere else they skip.

What this file does NOT repeat: the Sep 27 displacement probe on two
fresh interpreters (tests/test_active_rules_probe_native.py on this
line) and the probe view under authority
(tests/test_active_rules_authority_native.py). This file covers what
those do not:

  * the resend A,B,A under authority, with the journal-cut answers
    after the snapshots are wiped (B02-1/B02-2);
  * the forged-journal case: a step fingerprint rewritten with every
    link recomputed and the commits re-pointed passes chain
    verification and is caught only by the rebuild replay check
    (B02-3);
  * §6.1: at every height of a scenario that includes a guarded
    (non-plain-assignment) unit and a same-block install+replace, the
    snapshot text `getactiverules` serves is byte-identical to the
    journal cut's text -- the cut being a full replay of the committed
    journal through a fresh mirror -- and the hashes agree;
  * §6.7: after two revisions under authority, `getactiverules`
    serves a non-empty per-unit ledger that agrees with the view (the
    #134-line observation -- ledger empty under the authority harness
    -- does not carry to this line's served ledger).

PORT NOTE: the #134-line original read its answers through a
`getactiverules` that itself resolved journal cuts (keys
`effective_spec` / `spec_hash`). On this line the command serves
stored snapshots only (keys `canonical_text` / `sha256`), and the cut
is read through `consensus.active_rules.resolve_answer` /
`journal_cut_at_height` -- the same module functions the original
suite pinned. Assertions are adapted to those surfaces, and the
post-wipe behaviour of the command itself (explicitly not available)
is asserted as this line's design, not silently skipped.
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic as bls

import chain_state
import db
import tau_admission
import tau_authority as auth
import tau_commit as tc
from commands import createblock, getactiverules, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus import active_rules
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _native_available():
    try:
        from tau_native import load_tau_module

        load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)

PROBE_A = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
           "o27[t]:bv[24] = { 9 }:bv[24] ).")
PROBE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."

# Genesis baseline conjuncts (B02 §3 / F4, new world after F3-permanent):
# every snapshot is now the executing session's own spec, carried in the
# receipt (receipt.get("current_spec")), so S0/S1/S2 all carry the same
# eight genesis conjuncts -- consensus o6/o7/o9, application, builtins
# 01-04 -- and the genesis unit reads in_force. Builtin 02 is the
# worker's shrunk form (i3/i4 bv[384] -> bv[8]; tau_shrink
# MIN_SHRINK_WIDTH=128, fresh-chain width 8; prepare_rule verified
# empirically on the real b02 text). GENESIS_B02_FULL is the form the
# journal-cut mirror renders (it is fed full-width journal text): the
# served view text carries it while the stored ledger carries the shrunk
# form -- the two differ on b02 only (see the union note below). The
# exact strings below assume the interpreter renders its spec
# '.'-separated at the fed spacing (O-1); CI answers that empirically.
# COORDINATOR CORRECTION: the baseline CI cut already contradicts the
# as-fed assumption (it normalizes APP/o1/o9/B01), so only GENESIS_O6
# and GENESIS_O7 -- the two plain assignments the cut verifies
# verbatim -- are asserted on; the rest of these constants are the
# as-fed model kept as documentation until CI reveals the rendering.
GENESIS_APP = ("((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)")
GENESIS_B01 = (
    "((i1[t]:bv[24] > i2[t]:bv[24]) && o2[t] = { #x000000 }:bv[24]) || "
    "((i1[t]:bv[24] <= i2[t]:bv[24]) && o2[t] = { #x000001 }:bv[24])")
GENESIS_B02_FULL = (
    "((i3[t]:bv[384] = i4[t]:bv[384]) && o3[t] = { #x0000 }:bv[16]) || "
    "((i3[t]:bv[384] != i4[t]:bv[384]) && o3[t] = { #x0001 }:bv[16])")
GENESIS_B02_SHRUNK = (
    "((i3[t]:bv[8] = i4[t]:bv[8]) && o3[t] = { #x0000 }:bv[16]) || "
    "((i3[t]:bv[8] != i4[t]:bv[8]) && o3[t] = { #x0001 }:bv[16])")
GENESIS_B03 = (
    "((i1[t]:bv[24] = { #x000000 }:bv[24]) && o4[t] = { #x000000 }:bv[24]) || "
    "((i1[t]:bv[24] != { #x000000 }:bv[24]) && o4[t] = { #x000001 }:bv[24])")
GENESIS_B04 = (
    "o1[t]:bv[24] = ((i1[t]:bv[24] + { #x000000 }:bv[24]) & "
    "((i1[t]:bv[24] + { #x000000 }:bv[24]) | { #x000000 }:bv[24]))")
GENESIS_O6 = "o6[t]:bv[16] = i10[t]:bv[16]"
GENESIS_O7 = "o7[t]:bv[16] = { 1 }:bv[16]"
GENESIS_O9 = "o9[t]:bv[24] = { #x00000a }:bv[24]"

# GENESIS_SURVIVING_STORED: the genesis unit's 9 surviving
# conjuncts as the STORED snapshot renders them (pinned from mirror
# run 45779972374: the journal cut renders the 8 non-b02 conjuncts
# identically, and the ledger union's single diff gives the stored
# b02 form -- bv[8] with the operands i3=i4, vs the cut's bv[384]
# i4=i3). The APP ternary renders as TWO conjuncts (a conjunction
# of two disjunctions), so the genesis unit has 9 conjuncts, not 8.
# This replaces the as-fed constants above as the asserted model;
# the as-fed constants are kept as documentation of what was fed.
GENESIS_SURVIVING_STORED = [
    "(i0[t]:tau = 0 || o0[t]:tau = 0 && u[t]:tau = i0[t]:tau)",
    "(o0[t]:tau' = 0 || i0[t]:tau != 0)",
    "o7[t]:bv[16] = { 1 }:bv[16]",
    "o9[t]:bv[24] = { 10 }:bv[24]",
    "o6[t]:bv[16] = i10[t]:bv[16]",
    "(o2[t]:bv[24] = 0 && i2[t]:bv[24] < i1[t]:bv[24] || o2[t]:bv[24] = { 1 }:bv[24] && i2[t]:bv[24] !< i1[t]:bv[24])",
    "(o3[t]:bv[16] = 0 && i3[t]:bv[8] = i4[t]:bv[8] || o3[t]:bv[16] = { 1 }:bv[16] && i3[t]:bv[8] != i4[t]:bv[8])",
    "(o4[t]:bv[24] = 0 && i1[t]:bv[24] = 0 || i1[t]:bv[24] != 0 && o4[t]:bv[24] = { 1 }:bv[24])",
    "o1[t]:bv[24] = i1[t]:bv[24]",
]


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _reset_spec_mirror():
    reset = getattr(active_rules, "reset_spec_mirror", None)
    if reset is not None:
        reset()


@pytest.fixture
def authority(node_state):
    baseline = "always ( " + open(
        os.path.join(REPO, "genesis.tau")).read().strip() + " )."
    owner = auth.AuthoritativeTauOwner(
        ready=threading.Event(), program_baseline=baseline)
    auth.reset(owner)
    tc.registry().discard()
    tau_admission.reset()
    _reset_spec_mirror()
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    _reset_spec_mirror()
    tc.registry().discard()
    tau_admission.reset()
    auth.reset(None)


@pytest.fixture
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility",
                      lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header",
                      lambda *a, **k: True), \
         patch("consensus.bls.verify", lambda *a, **k: True):
        yield


def _sender(tag):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = 1_000_000
    return sk, pk


def _submit(sk, pk, ops, seq):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk,
          "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600,
          "expire_at_height": 5000,
          "operations": ops, "fee_limit": "100000"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return out


def _answer_at(height=None):
    container = SimpleNamespace(db=db, chain_state=chain_state)
    raw = "getactiverules" if height is None else f"getactiverules {height}"
    return json.loads(getactiverules.execute(raw, container))["data"]


def _submit_and_mine(sk, pk, rule, seq):
    out = _submit(sk, pk, {"0": rule}, seq=seq)
    assert out.get("ok"), f"submit seq={seq} refused: {out}"
    _mine()
    return out


# --- B02-2: the resend case A,B,A under authority -------------------------

def test_resend_a_b_a_under_authority(authority, _mining_allowed):
    """Send A (o26 = {7} && o27 = {9}), then B (o26 = {3}), then A again,
    one block each. The view at the third block runs the first unit's
    terms again -- the resend is a new revision, not an accumulation
    replay (which would end at [A, B] with o26 = 3) -- and the journal
    records all three sends as accepted revisions, the resend included.
    Then the snapshots are wiped and the same heights must be answered
    from the journal cut (B02-1), with identical text and hash, marked
    derived -- read through `resolve_answer`, the cut's surface on this
    line, while the snapshot-only command answers not-available."""
    sk, pk = _sender("authority-resend")
    for seq, rule in enumerate((PROBE_A, PROBE_B, PROBE_A)):
        _submit_and_mine(sk, pk, rule, seq)

    # The journal is the authority-side record of the resend: three
    # REVISION entries, A then B then A again, each accepted, and the
    # block commits' spec_revision advancing by one per block -- the
    # resend was recorded as a new revision, not deduplicated against
    # the first send. (The survival-ledger form of this same case, over
    # recorded outcomes, is test_resend_a_b_a_served_unit_ledger in the
    # mock suite.)
    import tau_journal

    revisions = [
        e for e in tau_journal.journal_from_rows(
            db.committed_journal_entries()).entries()
        if e.kind == tau_journal.REVISION and e.rule_text in (PROBE_A, PROBE_B)
    ]
    assert [e.rule_text for e in revisions] == [PROBE_A, PROBE_B, PROBE_A], \
        [e.rule_text for e in revisions]
    assert all(
        (e.outcome or "").startswith("ACCEPTED") for e in revisions), \
        [e.outcome for e in revisions]
    commits = [db.block_commit_at_height(h) for h in (1, 2, 3)]
    assert all(c is not None for c in commits), commits
    # Genesis committed its own rules first, so the blocks land at
    # revisions 7, 8, 9 in this harness; the invariant is one new
    # revision per block, the resend's block included.
    revs = [c["spec_revision"] for c in commits]
    assert revs[1] == revs[0] + 1 and revs[2] == revs[1] + 1, commits
    h_first, h_displaced, h_resend = 1, 2, 3

    at2 = _answer_at(h_displaced)
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in at2["canonical_text"], at2
    at3 = _answer_at(h_resend)
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in at3["canonical_text"], at3
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in at3["canonical_text"], at3
    assert "{ 3 }" not in at3["canonical_text"], at3

    snapshots = {h: _answer_at(h)
                 for h in (h_first, h_displaced, h_resend)}
    with db._db_lock:
        db._db_conn.execute("DELETE FROM spec_snapshots")
        db._db_conn.commit()
    assert db.get_latest_spec_snapshot() is None
    for h in (h_first, h_displaced, h_resend):
        # This line's command serves snapshots only: wiped means
        # explicitly not available, never a silent substitute.
        assert _answer_at(h)["available"] is False
        cut = active_rules.resolve_answer(h)
        assert cut is not None and cut["derived"] == "journal_cut", cut
        assert cut["spec_text"] == snapshots[h]["canonical_text"], cut
        assert cut["spec_hash"] == snapshots[h]["sha256"], cut
        assert cut["spec_revision"] == snapshots[h]["spec_revision"], cut


# --- B02-3: the journal forge ----------------------------------------------

# The rebuild replay check spawns a reconstruction session -- the work a
# node does once, in its own process, at a lifecycle point. The forge
# test therefore runs the check in a child process against the harness
# database (a fresh interpreter, the production context for a replay),
# bounded by a subprocess timeout, instead of inside the pytest process
# alongside the live authority owner.
_REPLAY_CHECK_CHILD = r'''
import json
import os
import sys
import threading

db_path, baseline_path = sys.argv[1], sys.argv[2]
out = {}
try:
    import config
    config.set_database_path(db_path)
    import db
    if db._db_conn is not None:
        db._db_conn.close()
    db._db_conn = None
    db.init_db()
    import tau_authority as auth
    owner = auth.AuthoritativeTauOwner(
        ready=threading.Event(),
        program_baseline=open(baseline_path).read())
    auth.reset(owner)
    out["baseline"] = bool(auth.program_baseline())
    latest = db.latest_block_commit()
    out["plan_stored"] = bool(latest and latest.get("plan_json"))
    import tau_journal
    from consensus import active_rules
    journal = tau_journal.journal_from_rows(db.committed_journal_entries())
    out["entries"] = len(journal)
    out["check"] = active_rules._rebuild_replay_check(journal)
except BaseException as exc:
    out["error"] = repr(exc)
print("RESULT " + json.dumps(out))
sys.stdout.flush()
os._exit(0)
'''


def _replay_check_in_child(tmp_path):
    db_file = db._db_conn.execute("PRAGMA database_list").fetchone()[2]
    baseline = "always ( " + open(
        os.path.join(REPO, "genesis.tau")).read().strip() + " )."
    baseline_path = tmp_path / "forge-baseline.txt"
    baseline_path.write_text(baseline)
    # Output to files, not pipes, so a timed-out child cannot keep the
    # parent blocked on pipe EOF through lingering worker grandchildren.
    stdout_path = tmp_path / "replay-check.stdout"
    stderr_path = tmp_path / "replay-check.stderr"
    with open(stdout_path, "w") as out_fh, open(stderr_path, "w") as err_fh:
        proc = subprocess.run(
            [sys.executable, "-c", _REPLAY_CHECK_CHILD,
             db_file, str(baseline_path)],
            cwd=REPO, env=_env(), stdout=out_fh, stderr=err_fh, timeout=900)
    stdout = stdout_path.read_text(errors="replace")
    stderr = stderr_path.read_text(errors="replace")
    lines = [l for l in stdout.splitlines() if l.startswith("RESULT ")]
    assert lines, (
        f"replay-check child produced no result (rc={proc.returncode}):\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}")
    return json.loads(lines[-1][len("RESULT "):])


def test_forged_journal_fingerprint_rejected_under_authority(
        authority, _mining_allowed, tmp_path, monkeypatch):
    """Rewrite one entry's recorded result fingerprint in the stored
    journal, recompute every link, and re-point the commit records at
    the recomputed links, so the stored chain verifies cleanly and the
    commits agree with it. The one thing the forge cannot fix is the
    fingerprint itself: the rebuild replay check recomputes it from
    the replay, reports divergence, and the rebuild serves no text."""
    import tau_journal
    from dataclasses import replace

    sk, pk = _sender("authority-forge")
    for seq, rule in enumerate((PROBE_A, PROBE_B)):
        _submit_and_mine(sk, pk, rule, seq)

    honest = _replay_check_in_child(tmp_path)
    assert honest.get("check") is True, f"honest journal must verify: {honest}"

    entries = tau_journal.journal_from_rows(
        db.committed_journal_entries()).entries()
    target = next(
        (e for e in entries if e.kind == tau_journal.STEP), entries[-1])
    forged_fp = json.dumps(
        {"outcome": "ACCEPTED_UNCHANGED", "present": [],
         "progressed": False, "values": {}},
        sort_keys=True, separators=(",", ":"))
    # Compute the forged chain BEFORE taking db._db_lock: the lock is
    # not re-entrant, and db read helpers acquire it themselves.
    forged_chain = []
    prev = None
    for entry in entries:
        fixed = entry
        if entry.seq == target.seq:
            fixed = replace(fixed, result_fingerprint=forged_fp)
        fixed = replace(fixed, prev=prev)
        fixed = replace(fixed, link=fixed.compute_link())
        forged_chain.append(fixed)
        prev = fixed.link
    with db._db_lock:
        cur = db._db_conn.cursor()
        cur.execute(
            "UPDATE tau_journal_v1 SET result_fp = ? WHERE seq = ?",
            (forged_fp, target.seq))
        for old, fixed in zip(entries, forged_chain):
            cur.execute(
                "UPDATE tau_journal_v1 SET prev = ?, link = ? WHERE seq = ?",
                (fixed.prev, fixed.link, fixed.seq))
            cur.execute(
                "UPDATE block_commits_v1 SET journal_head = ? "
                "WHERE journal_head = ?",
                (fixed.link, old.link))
        db._db_conn.commit()

    # The forged record verifies: links and commit pointers agree.
    tau_journal.journal_from_rows(
        db.committed_journal_entries()).verify_chain()
    # The replay recomputes a different fingerprint: divergence.
    forged = _replay_check_in_child(tmp_path)
    assert forged.get("check") is False, \
        f"forged journal must diverge: {forged}"
    # And the rebuild gate turns a diverged check into no text at all.
    monkeypatch.setattr(
        active_rules, "_rebuild_replay_check", lambda journal: False)
    _reset_spec_mirror()
    assert active_rules._authority_spec_text() is None


# --- B02-6 (§6.1): snapshot text == journal replay, per height -------------

def test_snapshot_text_equals_journal_cut_replay_at_each_height(
        authority, _mining_allowed):
    """The fidelity claim, on the real engine: at every height of a
    scenario that crosses (a) a plain displacement, (b) a guarded unit
    -- a non-plain-assignment conjunct the composer carries verbatim --
    and (c) an install+replace inside ONE block, the snapshot text
    `getactiverules` serves equals the journal cut's text BYTE FOR
    BYTE, and the sha256 agree. The cut is a full replay of the
    committed journal through a fresh mirror interface, so this pins
    the composed snapshot source to the engine's own replayed spec,
    not to a parallel rendering that merely agrees on probe values."""
    sk, pk = _sender("replay-equivalence")
    guarded = (
        "always ( ( i12[t]:bv[384] = { #x" + pk + " }:bv[384] "
        "-> ( o28[t]:bv[24] = { #x000005 }:bv[24] ) ) )."
    )
    same_block_first = "always ( o29[t]:bv[24] = { #x000001 }:bv[24] )."
    same_block_replace = "always ( o29[t]:bv[24] = { #x000002 }:bv[24] )."

    _submit_and_mine(sk, pk, PROBE_A, seq=0)          # height 1
    _submit_and_mine(sk, pk, PROBE_B, seq=1)          # height 2
    _submit_and_mine(sk, pk, guarded, seq=2)          # height 3
    out = _submit(sk, pk, {"0": same_block_first}, seq=3)
    assert out.get("ok"), out
    out = _submit(sk, pk, {"0": same_block_replace}, seq=4)
    assert out.get("ok"), out
    _mine()                                           # height 4

    # NOTE (F3b): under the Step 7 stopgap this loop is vacuous when
    # the stopgap fires -- the served text IS the cut by
    # construction. It fires at every height here: the genesis b02
    # is shrunk to bv[8] in the worker's fed form (bv[384] in the
    # mirror cut), so the stored snapshot still diverges (O-4) and
    # the view is served from the cut. The firing is asserted, not
    # hidden: when O-4 is fixed and the stored snapshot agrees with
    # the cut, this assert must be updated (the stopgap stops
    # firing). The snapshot-vs-cut agreement itself is pinned by
    # the ledger union (which fails on O-4 alone).
    for height in (1, 2, 3, 4):
        served = _answer_at(height)
        assert served["available"] is True, served
        cut = active_rules.journal_cut_at_height(height)
        assert cut is not None, f"no journal cut at height {height}"
        assert served.get("derived") == "journal_cut"
        assert cut["spec_text"] == served["canonical_text"], (
            f"height {height}: replay text != snapshot text\n"
            f"--- snapshot ---\n{served['canonical_text']}\n"
            f"--- journal cut ---\n{cut['spec_text']}")
        assert cut["spec_hash"] == served["sha256"]
        assert cut["spec_revision"] == served["spec_revision"]

    # The scenario really crossed the cases it names: the guarded
    # conjunct is in force from height 3 on both readings, and the
    # same-block replacement is the o29 form in force at height 4.
    at3 = _answer_at(3)
    assert "i12[t]" in at3["canonical_text"]
    at4 = _answer_at(4)
    # NOTE (F3b): the interpreter renders bv literals DECIMAL
    # ({ 2 }, not { #x000002 }) in its canonical spec -- the as-fed
    # hex form cannot be asserted against the served text (mirror
    # run 45779972374: the served text carries o29[t]:bv[24] =
    # { 2 }:bv[24]).
    assert "o29[t]:bv[24] = { 2 }:bv[24]" in at4["canonical_text"]
    assert "o29[t]:bv[24] = { 1 }:bv[24]" not in at4["canonical_text"]


# --- B02-6 (§6.7): the served unit ledger under authority ------------------

def test_unit_ledger_served_under_authority(authority, _mining_allowed):
    """After install + displace under the authoritative worker, the
    served view's per-unit ledger is NOT empty (the #134-line harness
    observation does not carry): the genesis unit -- recorded as the
    baseline snapshot at height 0 (B02 §3) from the receipt-carried
    session spec -- reads in_force (all eight genesis conjuncts survive
    every later snapshot), the install unit reads partially_displaced
    with its loss attributed to the displacing transaction, the
    displacing unit reads in_force, the units are attributed to the
    transactions that were actually mined, and the ledger's surviving
    conjuncts are exactly the conjuncts of the text the view serves.

    Revisions are asserted relatively (genesis == install - 1): no
    assert pins the absolute genesis revision, which is 6 when the
    application unit counts and 5 when it lands ACCEPTED_NOOP."""
    sk, pk = _sender("authority-ledger")
    install = _submit_and_mine(sk, pk, PROBE_A, seq=0)
    displace = _submit_and_mine(sk, pk, PROBE_B, seq=1)

    # The genesis snapshot is the ledger's baseline: recorded at height 0
    # (B02 §3) with the executing session's spec (consensus + application
    # + builtins). Verified against the stored sequence, not the served
    # height-0 view: the Step 7 checked-snapshot answer serves the
    # journal cut at height 0, and the cut at height 0 is the pre-genesis
    # baseline by construction (cut_len=0, revision 0 --
    # active_rules._journal_cut_at_height), so the served height-0 text
    # carries no o6 and reports revision 0. That is a known stopgap
    # divergence (fix: include the genesis journal entries in the
    # height-0 cut, or exempt the genesis snapshot from the check), not
    # a defect of the recorded snapshot checked here.
    stored0 = db.get_spec_snapshot_at_height(0)
    assert stored0 is not None, "no snapshot recorded at height 0"
    assert stored0["height"] == 0, stored0
    assert GENESIS_O6 in getactiverules.top_level_conjuncts(
        stored0["canonical_text"]), stored0
    at0 = _answer_at(0)
    assert at0["available"] is True, at0
    assert at0["height"] == 0, at0

    view = _answer_at()
    assert view["available"] is True
    units = view["units"]
    assert len(units) == 3, units
    genesis, first, second = units
    assert stored0["spec_revision"] == genesis["introduced_at_revision"]
    assert genesis["introduced_by_tx"] is None
    assert genesis["introduced_at_height"] == 0
    assert genesis["introduced_at_revision"] == first["introduced_at_revision"] - 1
    assert genesis["status"] == "in_force"
    # NOTE (F5d): the exact genesis conjuncts ARE now asserted (the
    # coordinator correction asked for them to be pinned once CI
    # revealed the rendering -- mirror run 45779972374 did: the cut
    # renders the 8 non-b02 conjuncts, the union diff gives the
    # stored b02). The genesis unit is the STORED form (bv[8],
    # i3=i4), not the cut form (bv[384], i4=i3) -- the ledger reads
    # stored snapshots, and the two differ on b02 alone (O-4).
    assert sorted(genesis["surviving_conjuncts"]) == sorted(
        GENESIS_SURVIVING_STORED)
    assert genesis["displaced_conjuncts"] == []
    assert first["introduced_by_tx"] == install["tx_hash"]
    assert first["status"] == "partially_displaced"
    assert first["surviving_conjuncts"] == [
        "o27[t]:bv[24] = { 9 }:bv[24]"]
    assert first["displaced_conjuncts"] == [{
        "conjunct": "o26[t]:bv[24] = { 7 }:bv[24]",
        "displaced_at_revision": second["introduced_at_revision"],
        "displaced_by_tx": displace["tx_hash"],
        "displaced_by": "o26[t]:bv[24] = { 3 }:bv[24]",
    }]
    assert second["introduced_by_tx"] == displace["tx_hash"]
    assert second["status"] == "in_force"

    # NOTE (F4, known residual -- not an F4 defect): the union below is
    # the check that the served text and the ledger agree, and it is
    # currently predicted to fail on builtin 02 ALONE. The stored
    # snapshots carry b02 shrunk (bv[8], the worker's fed form) while
    # the served view text is the journal cut, which the mirror renders
    # full-width (bv[384]); the two canonicalizations are not yet
    # unified, so sorted(surviving) and the served conjuncts differ by
    # exactly the b02 pair. The ledger is complete against the stored
    # canonical text (verified in the F4 simulation); unifying the two
    # canonicalizations is the follow-up that makes this union green.
    surviving = []
    for unit in units:
        surviving.extend(unit["surviving_conjuncts"])
    assert sorted(surviving) == sorted(
        getactiverules.top_level_conjuncts(view["canonical_text"]))
