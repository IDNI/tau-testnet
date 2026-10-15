"""Retractable transfers on the REAL Tau engine: mine, then replay from block 0.

A short chain is mined through the live path (`createblock` ->
`chain_state.process_new_block`) with a height park that releases, a height park
that is retracted, and a time park that releases, then rebuilt with
`chain_state.rebuild_state_from_blockchain(0)`. `[HASH_TRACE]` lines (env
`TAU_HASH_TRACE`) give the four state-hash components per block on both paths;
they must agree at every block, the park, retract and sweep blocks included, and
the replayed balances and escrow must equal the mined ones.

One subprocess per case: stream typing is process-global in the native engine and
the engine segfaults on interpreter teardown, so the child os._exit()s after
emitting its verdict (same harness as tests/test_replay_determinism_native.py).
Run this file on its own; the full native suite has a known flaky segfault.
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
SENTINEL = "RETRACTABLE_NATIVE_RESULT "
FEE = 10

_CHILD_SRC = r'''
import hashlib, json, logging, os, subprocess, sys, time
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_HASH_TRACE"] = "1"

_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("LOG %(name)s %(levelname)s %(message)s"))
logging.getLogger().addHandler(_handler)
logging.getLogger().setLevel(logging.WARNING)

SENTINEL = "RETRACTABLE_NATIVE_RESULT "
WORK = os.environ["RETRACT_WORK"]
FEE = 10
notes = []

def note(msg):
    notes.append(msg)
    print("NOTE " + msg)
    sys.stdout.flush()

def emit(obj):
    obj["notes"] = notes
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    os._exit(0)

from py_ecc.bls import G2Basic as bls
ACTORS = ("miner", "s1", "s2", "s3", "s4", "r1", "r2", "r3")
KEYS = {}
for name in ACTORS:
    sk = bls.KeyGen(hashlib.sha256(("retract-native-" + name).encode()).digest())
    KEYS[name] = {"sk": sk, "pk": bls.SkToPk(sk).hex()}
PK = {n: KEYS[n]["pk"] for n in ACTORS}

genesis_path = os.path.join(WORK, "genesis.json")
cmd = [sys.executable, "scripts/gen_genesis.py", "--validator-privkey", format(KEYS["miner"]["sk"], "064x"),
       "--base-fee", str(FEE), "--network-id", "tau-retract-native", "--out", genesis_path]
for name in ("s1", "s2", "s3", "s4"):
    cmd += ["--account", PK[name] + ":1000000"]
subprocess.run(cmd, check=True, capture_output=True)

import config
config.set_database_path(os.path.join(WORK, "node.db"))
config.TESTNET_AUTO_FAUCET = False
config.MINER_PRIVKEY = format(KEYS["miner"]["sk"], "064x")
config.MINER_PUBKEY = PK["miner"]
config.MINER_PUBKEYS = [PK["miner"]]
import db
db._db_conn = None
db.init_db()
import tau_native, tau_manager, chain_state
from commands import sendtx, createblock
from consensus.tx_signing import signing_message_bytes
from tau_testnet_cli import tx as cli_tx

chain_state.load_genesis(genesis_path)
tau_manager.tau_direct_interface = tau_native.TauInterface(config.TAU_PROGRAM_FILE)
tau_manager.tau_test_mode = False
tau_manager.tau_process_ready.set()
plan = chain_state.get_tau_restore_plan(use_persisted_state=False)
chain_state.replay_tau_restore_plan(plan, source_prefix="startup")
tau_manager.tau_ready.set()
note("booted; plan entries=%d" % len(plan))

def bal(n):
    return int(chain_state.get_balance(PK[n]))

def book():
    return chain_state._lifecycle_manager.retractable_transfers

def sign(name, payload):
    digest = hashlib.sha256(signing_message_bytes(payload)).digest()
    payload["signature"] = bls.Sign(KEYS[name]["sk"], digest).hex()
    return payload

def seq(name):
    return int(chain_state.get_sequence_number(PK[name]))

def head():
    return int(db.get_canonical_head_block()["header"]["block_number"])

def submit(payload):
    res = sendtx.queue_transaction(json.dumps(payload), propagate=False)
    if not res.get("ok"):
        note("REJECTED " + json.dumps(res, default=str)[:300])
    return res

def park(name, to, amount, **release):
    p = cli_tx.build_retractable_transfer_tx(
        sender_pubkey=PK[name], sequence_number=seq(name),
        expiration_time=int(time.time()) + 3600, expire_at_height=head() + 50,
        recipient_pubkey=PK[to], amount=amount, fee_limit="1000", **release)
    return submit(sign(name, p)), p

def retract(name, rid):
    p = cli_tx.build_retract_transfer_tx(
        sender_pubkey=PK[name], sequence_number=seq(name),
        expiration_time=int(time.time()) + 3600, expire_at_height=head() + 50,
        retractable_id=rid, fee_limit="0")
    return submit(sign(name, p))

def transfer(name, to, amount):
    p = {"tx_type": "user_tx", "sender_pubkey": PK[name], "sequence_number": seq(name),
         "expiration_time": int(time.time()) + 3600, "expire_at_height": head() + 50,
         "fee_limit": "1000",
         "operations": {"1": [[PK[name], PK[to], str(amount)]]}}
    return submit(sign(name, p))

def seal():
    res = createblock.create_block_from_mempool(allow_empty=True)
    if "block_hash" not in res:
        note("SEAL FAILED " + json.dumps(res, default=str)[:300])
    return res

def snap(label):
    return {"label": label, "height": head(),
            "bal": {n: bal(n) for n in ACTORS}, "seq": {n: seq(n) for n in ACTORS},
            "escrow": book().escrow_total(),
            "open": sorted(r["retractable_id"] for r in book().snapshot_rows())}

# Genesis carries no consensus proof and the in-process rebuild verifies it
# anyway; everything after block 0 keeps its real header verification.
from consensus.engine import TauConsensusEngine
_verify = TauConsensusEngine.verify_block_header
def _verify_but_genesis(self, *args, **kwargs):
    blk = next((a for a in args if hasattr(a, "header")), None)
    if blk is not None and blk.header.block_number == 0:
        return True
    return _verify(self, *args, **kwargs)
TauConsensusEngine.verify_block_header = _verify_but_genesis

snaps = []
snaps.append(snap("genesis"))
seal(); snaps.append(snap("warm"))            # a tip timestamp near the wall clock
base = head()
R = base + 5
_, p1 = park("s1", "r1", 500, release_at_height=R)
_, p2 = park("s2", "r2", 600, release_at_height=R)
T = int(time.time()) + 12
_, p3 = park("s3", "r3", 700, release_at_time=T)
transfer("s4", "s1", 5)
from consensus.retractable import parse_retractable_transfer
ids = {k: parse_retractable_transfer(p).retractable_id.hex()
       for k, p in (("p1", p1), ("p2", p2), ("p3", p3))}
seal(); snaps.append(snap("parks"))
retract("s2", ids["p2"])
seal(); snaps.append(snap("retract"))
seal(); snaps.append(snap("empty-1"))
seal(); snaps.append(snap("empty-2"))
seal(); snaps.append(snap("sweep-height"))
while time.time() < T + 1:
    time.sleep(0.5)
seal(); snaps.append(snap("sweep-time"))
seal(); snaps.append(snap("empty-3"))

rr = chain_state.rebuild_state_from_blockchain(0)
replayed = snap("replayed")
emit({"ids": ids, "snaps": snaps, "replay_ok": rr.ok, "replay_stopped": rr.stopped_at_block,
      "replay_reason": rr.reason, "replayed": replayed, "pk": PK, "T": T, "R": R, "fee": FEE})
'''

_HASH_TRACE_RE = re.compile(
    r"\[HASH_TRACE\] blk=(?P<blk>\d+) replay=(?P<replay>True|False) "
    r"state=(?P<state>[0-9a-f]+) \| cons=(?P<cons>[0-9a-f]+) app=(?P<app>[0-9a-f]+) "
    r"acc=(?P<acc>[0-9a-f]+) meta=(?P<meta>[0-9a-f]+)"
)


def _parse_trace(stdout):
    out = {}
    for m in _HASH_TRACE_RE.finditer(stdout):
        out[(int(m.group("blk")), m.group("replay") == "True")] = {
            k: m.group(k) for k in ("state", "cons", "app", "acc", "meta")
        }
    return out


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    work = tmp_path_factory.mktemp("retract_native")
    script = work / "child.py"
    script.write_text(_CHILD_SRC)
    env = dict(os.environ)
    env["RETRACT_WORK"] = str(work)
    env["PYTHONPATH"] = str(_REPO) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                          env=env, cwd=str(_REPO), timeout=600)
    line = next((l for l in proc.stdout.splitlines() if l.startswith(SENTINEL)), None)
    assert line is not None, (
        f"child produced no verdict\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-2000:]}")
    result = json.loads(line[len(SENTINEL):])
    result["trace"] = _parse_trace(proc.stdout)
    result["stdout"] = proc.stdout
    return result


def _snap(run, label):
    return next(s for s in run["snaps"] if s["label"] == label)


def test_mined_balances_escrow_and_fees(run):
    assert not any(n.startswith(("REJECTED", "SEAL FAILED")) for n in run["notes"]), run["notes"]
    pk = run["pk"]
    start = {n: 1_000_000 for n in ("s1", "s2", "s3", "s4")}

    after = _snap(run, "parks")
    assert after["escrow"] == 500 + 600 + 700
    assert after["bal"]["s1"] == start["s1"] - 500 - FEE + 5
    assert after["bal"]["s2"] == start["s2"] - 600 - FEE
    assert after["bal"]["s3"] == start["s3"] - 700 - FEE
    assert after["bal"]["s4"] == start["s4"] - 5 - FEE
    assert after["bal"]["miner"] == 3 * FEE + FEE
    assert all(after["bal"][r] == 0 for r in ("r1", "r2", "r3"))
    assert len(after["open"]) == 3

    retracted = _snap(run, "retract")
    assert retracted["escrow"] == 500 + 700
    assert retracted["bal"]["s2"] == start["s2"] - FEE, "refund is the amount only; the fee stays spent"
    assert retracted["bal"]["miner"] == after["bal"]["miner"], "a retract is feeless"
    assert retracted["seq"]["s2"] == 2
    assert run["ids"]["p2"] not in retracted["open"]

    for label in ("empty-1", "empty-2"):
        quiet = _snap(run, label)
        assert quiet["escrow"] == 1200 and quiet["bal"]["r1"] == 0

    swept = _snap(run, "sweep-height")
    assert swept["height"] == run["R"]
    assert swept["bal"]["r1"] == 500 and swept["bal"]["r3"] == 0 and swept["bal"]["r2"] == 0
    assert swept["escrow"] == 700

    timed = _snap(run, "sweep-time")
    assert timed["bal"]["r3"] == 700 and timed["escrow"] == 0 and timed["open"] == []
    final = _snap(run, "empty-3")
    assert final["bal"] == timed["bal"] and final["escrow"] == 0
    assert sum(final["bal"].values()) == 4 * 1_000_000, "no value created or lost"
    assert final["seq"]["s1"] == 1 and final["seq"]["s3"] == 1 and final["seq"]["s4"] == 1
    assert pk["s1"] != pk["s2"]


def test_replay_reproduces_every_block(run):
    assert run["replay_ok"], (
        f"rebuild stopped at {run['replay_stopped']}: {run['replay_reason']}\n{run['stdout'][-3000:]}")
    last = max(s["height"] for s in run["snaps"])
    trace = run["trace"]
    for blk in range(1, last + 1):
        mined, replayed = trace.get((blk, False)), trace.get((blk, True))
        assert mined is not None, f"no mine trace for block {blk}"
        assert replayed is not None, f"no replay trace for block {blk}"
        assert mined == replayed, f"block {blk} diverges: mine={mined} replay={replayed}"


def test_replayed_state_equals_mined_state(run):
    final = _snap(run, "empty-3")
    replayed = run["replayed"]
    assert replayed["bal"] == final["bal"]
    assert replayed["seq"] == final["seq"]
    assert replayed["escrow"] == final["escrow"] == 0
    assert replayed["open"] == final["open"] == []


def test_book_changes_move_the_meta_hash_at_each_event(run):
    """Park, retract and both sweeps change the committed book; empty blocks do not."""
    trace = run["trace"]
    heights = {s["label"]: s["height"] for s in run["snaps"]}

    def meta(label):
        return trace[(heights[label], False)]["meta"]

    assert meta("parks") != meta("warm")
    assert meta("retract") != meta("parks")
    assert meta("empty-1") == meta("retract")
    assert meta("empty-2") == meta("empty-1")
    assert meta("sweep-height") != meta("empty-2")
    assert meta("sweep-time") != meta("sweep-height")
    assert meta("empty-3") == meta("sweep-time")
