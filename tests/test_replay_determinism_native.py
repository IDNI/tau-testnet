"""Phase 9B — single-process mine-vs-replay state-hash equivalence across a
PoA->stake governance activation.

Root cause doc: demo/diagnostics/ROOT_CAUSE.md. The real-network divergence was
ultimately a PERSISTENCE bug (a node reloading after a restart lost
"sequence-only" accounts, then mined a block whose hash replay rejected — fixed
by persisting balances∪sequences keys; regression:
tests/test_account_persistence_determinism.py). It required a restart to bite.

This test does NOT restart: it drives mine (process_new_block) and replay
(rebuild_state_from_blockchain) in ONE process, and confirms they agree at every
block including H and the empty blocks after it. It therefore PASSES both before
and after the persistence fix — it is the standing guard that the in-process
lifecycle/apply_block math is deterministic across an activation, complementing
the restart-path regression above.

This test drives BOTH code paths in a single native subprocess (process-global
per-stream bv-width typing forces one subprocess per case; the native engine
also segfaults on interpreter teardown, so the child os._exit()s after
emitting its result -- see tests/test_stake_switch_e2e_native.py and
tests/test_stake_switch_spike_native.py, which this harness is modeled on):

  1. MINE path: `chain_state.process_new_block` (replay_mode=False) mines a
     chain of governance-update -> votes -> empty blocks through H+2.
  2. REPLAY path: `chain_state.rebuild_state_from_blockchain(0)`
     (replay_mode=True) replays the exact same blocks from the DB.

`consensus.engine.TauConsensusEngine.apply_block` emits a `[HASH_TRACE]`
`logger.warning` line for every block on both paths (gated on env
`TAU_HASH_TRACE`) dumping the 4 inputs to `compute_consensus_state_hash`:
consensus_rules_bytes (cons), application_rules_bytes (app), accounts_hash
(acc), consensus_meta_hash (meta). The child configures logging to stdout and
this test parses those lines to find exactly which component(s) diverge, at
which block(s) -- no guessing.

`TauConsensusEngine.verify_block_header` is monkeypatched to always return
True so the test does not need to satisfy real consensus proofs/eligibility;
this isolates the state-hash bookkeeping (the actual subject of the bug) from
header verification. Every block header carries `state_hash=""`, which makes
BOTH the mine-time and replay-time invariant checks in chain_state.py no-ops
(they only fire when a stored, non-empty state_hash disagrees with the
recomputed one) -- so both paths run to completion regardless of the
divergence, and we simply compare the logged components afterward.
"""
import json
import os
import pathlib
import re
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


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

_REPO = pathlib.Path(__file__).resolve().parent.parent
_DEMO = _REPO / "demo"


def _flatten(text: str) -> str:
    """Strip # comment lines and flatten to one line (i0 rule_text is fed raw --
    tau_native does NOT comment-strip an i0 value, only a spec build does)."""
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    return " ".join(lines)


def _rendered_revision() -> str:
    tmpl = (_DEMO / "stake_consensus_revision.tau.tmpl").read_text(encoding="utf-8")
    return _flatten(tmpl.replace("__THRESHOLD__", "100000"))


GENESIS_DEMO = _flatten((_DEMO / "genesis_consensus_demo.tau").read_text(encoding="utf-8"))
REVISION = _rendered_revision()

V1, V2, V3 = "a" * 96, "b" * 96, "c" * 96
OUTSIDER = "d" * 96  # balance 200000 -> eligible in stake mode (unused by header
                     # verification here since it's mocked, kept for parity with
                     # the stake-switch spikes/e2e test).

H = 5  # activation height; min_activation floor with 3 validators is 1+3=4.

# --- Child harness ------------------------------------------------------------
# Boots a router interpreter (i0 -> u), exactly like the other native stake-
# switch tests, then drives chain_state.process_new_block (MINE) and
# chain_state.rebuild_state_from_blockchain (REPLAY) directly -- no network,
# no real consensus proofs (verify_block_header is monkeypatched True).
_CHILD_SRC = r'''
import json, logging, os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_HASH_TRACE"] = "1"

# Capture every logger.warning (incl. [HASH_TRACE] from consensus.engine) on
# stdout, plus ERROR-level diagnostics if something rejects a block.
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("LOG %%(name)s %%(levelname)s %%(message)s"))
_root = logging.getLogger()
_root.addHandler(_handler)
_root.setLevel(logging.WARNING)

import config
config.set_database_path(os.environ["REPLAY_DB"])
import db
db.init_db()
import tau_native, tau_manager
import chain_state
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate, ConsensusRuleVote
from block import Block

V1, V2, V3 = %(V1)r, %(V2)r, %(V3)r
OUTSIDER = %(OUTSIDER)r
GENESIS_DEMO = %(GENESIS_DEMO)r
REVISION = %(REVISION)r
H = %(H)r

BALANCES = {OUTSIDER: 200000, V1: 0, V2: 0, V3: 0}

SENTINEL = "REPLAY_DETERMINISM_RESULT "

def emit(obj):
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    os._exit(0)  # native teardown segfaults; result is already flushed.

debug_notes = []

def note(msg):
    debug_notes.append(msg)
    print("NOTE " + msg)
    sys.stdout.flush()

# --- Boot a router-boot interpreter (i0 -> u), like the other native tests ---
ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(ROUTER + "\n")
boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager.last_known_tau_spec = None
tau_manager._current_prepared_spec = None
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

config.TAU_PROGRAM_FILE = boot.name
config.MINER_PUBKEY = V1

# Isolate this diagnostic from header verification entirely -- the subject
# under test is state-hash bookkeeping (engine.apply_block), not consensus
# proof / eligibility verdicts.
TauConsensusEngine.verify_block_header = lambda self, *a, **kw: True

# --- Genesis provisioning: seed the _genesis_* mirrors chain_state uses to
# reset itself on every `rebuild_state_from_blockchain(0)` call, then run that
# reset ONCE (on an empty DB) to bootstrap in-memory state + the live
# interpreter identically to how the later REPLAY-phase reset will do it. ---
chain_state._genesis_accounts_state = dict(BALANCES)
chain_state._genesis_active_validators = [V1, V2, V3]
chain_state._genesis_vote_quorum = ""       # -> DEFAULT_QUORUM_POLICY (supermajority)
chain_state._genesis_eligibility_mode = ""  # -> DEFAULT_ELIGIBILITY_MODE (validator_set)
chain_state._genesis_application_rules = ""
chain_state._genesis_consensus_rules = GENESIS_DEMO

boot_result = chain_state.rebuild_state_from_blockchain(0)
note(f"genesis bootstrap: ok={boot_result.ok}")

# --- Genesis block 0 (manually provisioned; load_genesis's artifact schema
# is not needed since we seed globals directly). ---
genesis_block = Block.create(
    block_number=0, previous_hash="0" * 64, transactions=[],
    proposer_pubkey="0" * 96, state_hash="", timestamp=1700000000,
)
db.add_block(genesis_block)
chain_state._canonical_head_hash = genesis_block.block_hash
db.save_canonical_state_atomically(
    head_hash=genesis_block.block_hash, head_num=0,
    balances=chain_state._balances, sequences=chain_state._sequence_numbers,
    application_rules=chain_state._application_rules_state,
    consensus_rules=chain_state._consensus_rules_state,
    active_consensus_id=chain_state._active_consensus_id or "",
    pending_updates=[], votes=[], scheduled=[], archival=[],
    active_validators=sorted([V1, V2, V3]),
    quorum_policy=chain_state._lifecycle_manager.quorum_policy,
    eligibility_mode=chain_state._lifecycle_manager.eligibility_mode,
)

# --- Governance update + votes (reach quorum before H) ---
update = ConsensusRuleUpdate(
    rule_revisions=[REVISION],
    activate_at_height=H,
    host_contract_patch={"eligibility_mode": "stake"},
)
update_id_hex = update.update_id_hex
note(f"update_id={update_id_hex} activate_at_height={H}")

tx_update = {
    "tx_id": "gov_update_1",
    "tx_type": "consensus_rule_update",
    "sender_pubkey": V1,
    "rule_revisions": [REVISION],
    "activate_at_height": H,
    "host_contract_patch": {"eligibility_mode": "stake"},
}
tx_vote_v1 = {
    "tx_id": "gov_vote_v1", "tx_type": "consensus_rule_vote",
    "sender_pubkey": V1, "update_id": update_id_hex, "approve": True,
}
tx_vote_v2 = {
    "tx_id": "gov_vote_v2", "tx_type": "consensus_rule_vote",
    "sender_pubkey": V2, "update_id": update_id_hex, "approve": True,
}

# --- Mine blocks 1..H+2 via the MINE path (process_new_block, replay_mode=False) ---
#
# `chain_state.process_new_block`'s fast-path invariant check
# (`if getattr(block.header, 'state_hash', "") and next_snapshot.state_hash !=
# block.header.state_hash: reject`) only skips when the header's state_hash is
# the LITERAL falsy value "" -- and `Block.create(..., state_hash="")` itself
# coerces "" to EMPTY_STATE_HASH ("0"*64, a TRUTHY string), so that shortcut
# does not actually work here: a block minted with the placeholder hash is
# unconditionally rejected unless it happens to equal the real computed hash.
# The real miner (commands/createblock.py::create_block_from_mempool) never
# relies on that skip either -- it computes the true hash via a DRY RUN of
# `engine.apply_block` against a throwaway candidate, restores the live Tau
# interpreter to its pre-dry-run spec (the dry run's governance-activation
# route already mutated it once), embeds the dry run's hash into the header,
# and only THEN performs the real, committing `process_new_block` call (whose
# own internal apply_block recomputes -- against the freshly restored,
# unmutated interpreter -- and trivially matches). This mirrors that exactly.
from consensus.state import TauStateSnapshot as _TauStateSnapshot

state = {"prev_hash": genesis_block.block_hash, "ts": 1700000000}
mine_ok = []

def _parent_snapshot_from_globals():
    app_rules = (chain_state._application_rules_state or "").encode("utf-8")
    cons_rules = (chain_state._consensus_rules_state or "").encode("utf-8")
    acc_hash = chain_state.compute_accounts_hash(chain_state._balances, chain_state._sequence_numbers)
    meta_hash = chain_state._lifecycle_manager.consensus_meta_hash()
    from consensus.state import compute_consensus_state_hash
    parent_state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)
    return _TauStateSnapshot(
        state_hash=parent_state_hash,
        tau_bytes=app_rules,
        metadata={
            "source": "chain_state",
            "balances": chain_state._balances,
            "sequence_numbers": chain_state._sequence_numbers,
            "lifecycle_manager": chain_state._lifecycle_manager,
            "active_consensus_id": chain_state._active_consensus_id,
            "consensus_rules_state": chain_state._consensus_rules_state,
        },
    )

def mine(height, txs):
    state["ts"] += 10
    candidate = Block.create(
        block_number=height, previous_hash=state["prev_hash"], transactions=txs,
        proposer_pubkey=V1, state_hash="", timestamp=state["ts"],
    )
    candidate.consensus_proof = {"signature": "00" * 48}

    dry_engine = TauConsensusEngine()
    parent_snapshot = _parent_snapshot_from_globals()
    active_view = dry_engine.derive_active_consensus(parent_snapshot, height)

    saved_full_spec = None
    try:
        iface = tau_manager.tau_direct_interface
        if iface is not None and hasattr(iface, "get_current_spec"):
            saved_full_spec = iface.get_current_spec()
    except Exception:
        saved_full_spec = None
    if saved_full_spec is None:
        saved_full_spec = tau_manager.last_known_tau_spec
    try:
        saved_shrunk_streams = tau_manager.get_runtime_shrunk_streams()
    except Exception:
        saved_shrunk_streams = None

    try:
        dry_result = dry_engine.apply_block(active_view, candidate, parent_snapshot)
    finally:
        try:
            if saved_full_spec is not None:
                tau_manager.restore_full_tau_spec(saved_full_spec, runtime_shrunk_streams=saved_shrunk_streams)
        except Exception as restore_err:
            note(f"MINE block {height}: failed to restore Tau spec after dry run: {restore_err}")

    candidate.header.state_hash = dry_result.next_snapshot.state_hash
    candidate.block_hash = __import__("block").sha256_hex(candidate.header.canonical_bytes())

    try:
        ok = chain_state.process_new_block(candidate)
    except Exception as e:
        note(f"MINE block {height} raised {type(e).__name__}: {e}")
        ok = False
    mine_ok.append([height, bool(ok)])
    if ok:
        state["prev_hash"] = candidate.block_hash
    else:
        note(f"MINE block {height} REJECTED (txs={[t.get('tx_type') for t in txs]})")
    return ok

mine(1, [tx_update])
mine(2, [tx_vote_v1])
mine(3, [tx_vote_v2])
for h in range(4, H + 3):  # H-1, H, H+1, H+2
    mine(h, [])

# --- Replay the whole chain from block 0 (REPLAY path, replay_mode=True) ---
replay_result = chain_state.rebuild_state_from_blockchain(0)
note(f"replay: ok={replay_result.ok} stopped_at={replay_result.stopped_at_block} reason={replay_result.reason}")

emit({
    "H": H,
    "update_id_hex": update_id_hex,
    "mine_ok": mine_ok,
    "replay_ok": replay_result.ok,
    "replay_stopped_at": replay_result.stopped_at_block,
    "replay_reason": replay_result.reason,
    "debug_notes": debug_notes,
})
'''


def _child_src() -> str:
    return _CHILD_SRC % {
        "V1": V1, "V2": V2, "V3": V3, "OUTSIDER": OUTSIDER,
        "GENESIS_DEMO": GENESIS_DEMO, "REVISION": REVISION, "H": H,
    }


def _run_child(tmp_path):
    script = tmp_path / "child.py"
    script.write_text(_child_src())
    env = dict(os.environ)
    env["REPLAY_DB"] = str(tmp_path / "replay_determinism.db")
    # Prepend the repo root (for config/db/chain_state/... imports) -- the
    # child does not inherit sys.path. Native tau bindings are picked up via
    # an inherited PYTHONPATH pointing at the tau-lang nanobind build (see
    # this repo's other native tests / CLAUDE.md for the exact path); if the
    # caller already exported PYTHONPATH we keep it and just prepend repo root.
    env["PYTHONPATH"] = str(_REPO) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=300,
    )
    return proc


_HASH_TRACE_RE = re.compile(
    r"\[HASH_TRACE\] blk=(?P<blk>\d+) replay=(?P<replay>True|False) "
    r"state=(?P<state>[0-9a-f]+) \| cons=(?P<cons>[0-9a-f]+) app=(?P<app>[0-9a-f]+) "
    r"acc=(?P<acc>[0-9a-f]+) meta=(?P<meta>[0-9a-f]+) \| "
    r"newly_active=(?P<newly_active>\[[^\]]*\]) "
    r"cons_rules_len=(?P<cons_rules_len>\d+) app_rules_len=(?P<app_rules_len>\d+)"
)


def _parse_hash_trace(stdout: str):
    """Return {(blk, replay_bool): {component: value, ...}} for every
    [HASH_TRACE] line found in the child's stdout."""
    out = {}
    for m in _HASH_TRACE_RE.finditer(stdout):
        blk = int(m.group("blk"))
        replay = m.group("replay") == "True"
        out[(blk, replay)] = {
            "state": m.group("state"),
            "cons": m.group("cons"),
            "app": m.group("app"),
            "acc": m.group("acc"),
            "meta": m.group("meta"),
            "newly_active": m.group("newly_active"),
            "cons_rules_len": m.group("cons_rules_len"),
            "app_rules_len": m.group("app_rules_len"),
        }
    return out


def _format_table(trace, blocks):
    header = f"{'blk':>4} {'path':<6} {'state':<16} {'cons':<16} {'app':<16} {'acc':<16} {'meta':<16} newly_active"
    lines = [header, "-" * len(header)]
    for b in blocks:
        for replay in (False, True):
            row = trace.get((b, replay))
            path = "replay" if replay else "mine"
            if row is None:
                lines.append(f"{b:>4} {path:<6} <no HASH_TRACE line captured>")
                continue
            lines.append(
                f"{b:>4} {path:<6} {row['state']:<16} {row['cons']:<16} {row['app']:<16} "
                f"{row['acc']:<16} {row['meta']:<16} {row['newly_active']}"
            )
    return "\n".join(lines)


def test_replay_determinism_across_activation(tmp_path):
    """Reproduce and pin the mine-vs-replay state-hash divergence.

    Mines a governance activation (PoA -> stake) through height H, then two
    more empty blocks (H+1, H+2), via the live MINE path
    (`chain_state.process_new_block`); then replays the identical chain from
    the DB via the REPLAY path (`chain_state.rebuild_state_from_blockchain`).
    Both paths log a `[HASH_TRACE]` line per block (env `TAU_HASH_TRACE=1`)
    dumping the 4 `compute_consensus_state_hash` inputs. This test compares
    them block-by-block for H-1, H, H+1, H+2.

    All blocks (H-1, H, H+1, H+2) must agree between the mine and replay paths:
    the in-process lifecycle/apply_block math is deterministic across an
    activation and the empty blocks after it. (The real-network divergence was a
    restart-only persistence bug — this single-process harness never triggered
    it; see the module docstring and tests/test_account_persistence_determinism.py
    for that path.) A mismatch here would mean the core apply math regressed.
    """
    proc = _run_child(tmp_path)
    result_line = next(
        (l for l in proc.stdout.splitlines() if l.startswith("REPLAY_DETERMINISM_RESULT ")),
        None,
    )
    assert result_line is not None, (
        f"child produced no verdict (STOP: setup/wiring failure)\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    result = json.loads(result_line[len("REPLAY_DETERMINISM_RESULT "):])

    assert all(ok for _, ok in result["mine_ok"]), (
        f"mining failed, cannot exercise replay divergence: {result['mine_ok']}\n"
        f"notes={result['debug_notes']}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    print(
        f"\nreplay_ok={result['replay_ok']} stopped_at={result['replay_stopped_at']} "
        f"reason={result['replay_reason']!r}"
    )

    H = result["H"]
    blocks = list(range(H - 1, H + 3))  # H-1, H, H+1, H+2
    trace = _parse_hash_trace(proc.stdout)
    table = _format_table(trace, blocks)
    print("\n" + table)

    # Sanity: the MINE path must have a trace for every block we mined --
    # this is a setup precondition, not part of the repro.
    for b in blocks:
        assert trace.get((b, False)) is not None, f"no MINE HASH_TRACE line for block {b}\n{table}"

    # H-1 (pre-activation, empty): expected to match on both paths.
    b = H - 1
    replay_row = trace.get((b, True))
    assert replay_row is not None, f"no REPLAY HASH_TRACE line for block {b} (replay aborted too early)\n{table}"
    assert trace[(b, False)] == replay_row, (
        f"block {b} (H-1): mine vs replay diverge BEFORE activation -- unexpected, "
        f"points at a test-setup bug rather than the reported activation-triggered "
        f"divergence\n{table}"
    )

    # H (activation block itself): expected to match on both paths (per
    # ROOT_CAUSE.md, "Followers rebuild cleanly through" the activation block).
    replay_row = trace.get((H, True))
    assert replay_row is not None, f"no REPLAY HASH_TRACE line for block {H} (replay aborted too early)\n{table}"
    assert trace[(H, False)] == replay_row, (
        f"block {H} (H, activation): mine vs replay diverge AT activation -- this is "
        f"earlier than ROOT_CAUSE.md's reported divergence point (H+1)\n{table}"
    )

    # H+1 (first empty block strictly after activation): must match — this is
    # the block that diverged on the real network's restart path, so the
    # in-process paths agreeing here is the core-determinism guard.
    replay_row = trace.get((H + 1, True))
    assert replay_row is not None, (
        f"no REPLAY HASH_TRACE line for block {H + 1} at all (rebuild aborted before "
        f"even attempting it)\n{table}"
    )
    assert trace[(H + 1, False)] == replay_row, (
        f"block {H + 1} (H+1): mine vs replay state-hash components diverge in-process -- "
        f"the core apply/lifecycle math regressed\n{table}\n"
        f"mine={trace[(H + 1, False)]}\nreplay={replay_row}"
    )

    # H+2: informational only -- the replay may never reach it once H+1
    # aborts the rebuild (see docstring).
    replay_row = trace.get((H + 2, True))
    if replay_row is None:
        print(f"block {H + 2} (H+2): no REPLAY trace -- rebuild did not reach it "
              f"(stopped_at={result['replay_stopped_at']})")
    else:
        print(f"block {H + 2} (H+2): mine=={'==' if trace[(H + 2, False)] == replay_row else '!='}=replay")
