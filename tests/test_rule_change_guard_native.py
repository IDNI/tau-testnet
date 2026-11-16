"""The rule-change guard on the REAL Tau engine: the shipped wallet guard templates
build and step, guard verdicts match the mock expectations the door tests use, a
parked request releases through block apply, and a guard typing the approval slots
at bv[384] shares a process with the clauses that already do.

The block-apply cases run in a child process: stream typing is process-global in
the native engine and the engine can segfault on interpreter teardown, so the
child os._exit()s after emitting its verdict. Run this file on its own; the full
native suite has a known flaky segfault.
"""
import hashlib
import json
import os
import pathlib
import subprocess
import sys

import pytest

import tau_defs
import tau_policy
from consensus import sender_policy
from consensus.rule_offers import clause_body_v1
from test_rule_change_guard_doors import DOORS, KIND, MODES
from wallet_templates import live_rule, shipped_guard_templates


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = str(pathlib.Path(__file__).resolve().parent.parent)
TIMEOUT = 120.0
TIMESTAMP = 1234567890
KINDS = (
    tau_defs.RULE_CHANGE_KIND_SET_POLICY,
    tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY,
    tau_defs.RULE_CHANGE_KIND_ACCEPT_OFFER,
    tau_defs.RULE_CHANGE_KIND_SET_GUARD,
    tau_defs.RULE_CHANGE_KIND_REVOKE_GUARD,
)
PLACEHOLDER_A, PLACEHOLDER_B, PLACEHOLDER_C = "a" * 96, "b" * 96, "c" * 96


def _key(label):
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest() for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


X, Y, Z, OTHER, SENDER = (_key(n) for n in ("x", "y", "z", "other", "sender"))
GUARDS = shipped_guard_templates()
ANY = "Guard: Any policy change needs co-signer X"
TWO_OF_THREE = "Guard: 2 of 3 co-signers for any policy change"
REVOKE_ONLY = "Guard: Revoking needs a co-signer (weaker)"


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def real():
    """A real policy worker behind both consensus pools."""
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, ev)
    yield ev
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    ev.close()


def _guard_body(name, **keys):
    text = GUARDS[name]
    for placeholder, key in keys.items():
        assert placeholder in text
        text = text.replace(placeholder, key)
    return clause_body_v1(text)


def _blocked(body, kind, voted=None):
    blocked, detail = sender_policy.rule_change_blocked(
        lambda who, idx: body, SENDER, kind, TIMESTAMP, pool="apply", voted=voted)
    return blocked


# --- (a) the shipped templates ------------------------------------------------------

def test_there_are_three_shipped_guard_templates():
    assert set(GUARDS) == {ANY, TWO_OF_THREE, REVOKE_ONLY}


@pytest.mark.parametrize("name", [ANY, TWO_OF_THREE, REVOKE_ONLY])
def test_every_template_builds_and_steps(real, name):
    body = _guard_body(name, **{PLACEHOLDER_A: X, PLACEHOLDER_B: Y, PLACEHOLDER_C: Z}
                       if name == TWO_OF_THREE else {PLACEHOLDER_A: X})
    result = real.validate(body)
    assert result.ok, f"{name}: {result.error}\n{live_rule(GUARDS[name])}"
    assert isinstance(_blocked(body, 1), bool)


def test_any_change_needs_the_cosigner_for_every_kind(real):
    body = _guard_body(ANY, **{PLACEHOLDER_A: X})
    for kind in KINDS:
        assert _blocked(body, kind), f"kind {kind} with empty slots"
        assert not _blocked(body, kind, {18: X}), f"kind {kind} with X"
        assert _blocked(body, kind, {18: OTHER}), f"kind {kind} with a stranger"
        assert _blocked(body, kind, {19: X}), f"kind {kind} with X in the wrong slot"


def test_two_of_three_needs_any_two_of_the_declared_keys(real):
    body = _guard_body(TWO_OF_THREE, **{PLACEHOLDER_A: X, PLACEHOLDER_B: Y, PLACEHOLDER_C: Z})
    for kind in KINDS:
        assert _blocked(body, kind)
        for single in ({18: X}, {19: Y}, {20: Z}):
            assert _blocked(body, kind, single), single
        for pair in ({18: X, 19: Y}, {18: X, 20: Z}, {19: Y, 20: Z}):
            assert not _blocked(body, kind, pair), pair
        assert _blocked(body, kind, {18: X, 19: OTHER})
        assert _blocked(body, kind, {18: X, 20: Y})
        assert not _blocked(body, kind, {18: X, 19: Y, 20: Z})


def test_the_weaker_guard_blocks_only_revokes_and_lets_a_thief_set_a_policy(real):
    body = _guard_body(REVOKE_ONLY, **{PLACEHOLDER_A: X})
    blocking = {tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY, tau_defs.RULE_CHANGE_KIND_REVOKE_GUARD}
    for kind in KINDS:
        assert _blocked(body, kind) is (kind in blocking), kind
        assert not _blocked(body, kind, {18: X})
        assert _blocked(body, kind, {18: OTHER}) is (kind in blocking), kind


# --- (b) real verdicts against the door tests' mock expectations --------------------

_REAL_MODES = {
    "none": "((i1[t]:bv[24] > { #x000000 }:bv[24]) ? "
            "(o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]))",
    "all": "((i1[t]:bv[24] > { #x000000 }:bv[24]) ? "
           "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]))",
    "kind2": "((i1[t]:bv[24] = { #x000002 }:bv[24]) ? "
             "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]))",
}


@pytest.mark.parametrize("mode", list(MODES))
@pytest.mark.parametrize("door", DOORS)
def test_real_verdicts_match_the_mock_expectations(real, mode, door):
    body = clause_body_v1("always ( " + _REAL_MODES[mode] + " ).")
    expected = MODES[mode]({"i1": KIND[door]}) == "0"
    assert _blocked(body, int(KIND[door])) is expected


def test_the_guard_reads_the_block_timestamp(real):
    body = clause_body_v1(
        "always ( (i5[t]:bv[24] > { #x000064 }:bv[24]) ? "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).")
    assert not sender_policy.rule_change_blocked(
        lambda who, idx: body, SENDER, 1, 101, pool="apply")[0]
    assert sender_policy.rule_change_blocked(
        lambda who, idx: body, SENDER, 1, 100, pool="apply")[0]


def test_no_guard_is_never_blocked_and_never_asks_the_engine(real):
    assert sender_policy.rule_change_blocked(
        lambda who, idx: None, SENDER, 1, TIMESTAMP, pool="apply") == (False, "")
    assert real.stats().get("spawns", 0) == 0


# --- (d) the guard and the approval-tier clauses in one process ---------------------

def _tier_clause(auth, scan, partner):
    def bv24(n):
        return "{ #x%s }:bv[24]" % format(n, "06x")

    def bv384(h):
        return "{ #x%s }:bv[384]" % h

    def o5(v):
        return "(o5[t]:bv[24] = %s)" % bv24(v)

    blocked = (
        " (i1[t]:bv[24] > %s && !(i20[t]:bv[384] = %s))"
        " || (i1[t]:bv[24] > %s && !(i19[t]:bv[384] = %s))"
        " || (i1[t]:bv[24] > %s && !(i18[t]:bv[384] = %s)) "
        % (bv24(100000), bv384(partner), bv24(10000), bv384(scan), bv24(1000), bv384(auth)))
    return "( (" + blocked + ") ? " + o5(0) + " : " + o5(1) + " )"


def test_a_guard_and_the_tier_clauses_share_one_process_without_a_width_clash(real):
    guard = _guard_body(ANY, **{PLACEHOLDER_A: X})
    tier = _tier_clause(X, Y, Z)
    assert real.validate(guard).ok
    assert real.validate(tier).ok
    assert real.validate(guard).ok

    def transfer(amount, slots):
        values = {1: str(amount), **sender_policy.slot_literals(slots)}
        return sender_policy.clause_blocks(tier, values, pool="apply")[0]

    assert not transfer(500, {})
    assert transfer(2000, {})
    assert not transfer(2000, {18: X})
    assert _blocked(guard, 1)
    assert not _blocked(guard, 1, {18: X})
    assert transfer(2000, {})


# --- (c) block apply on a booted node ------------------------------------------------

SENTINEL = "RULE_CHANGE_NATIVE_RESULT "

_CHILD_SRC = r'''
import hashlib, json, logging, os, subprocess, sys, time
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"

_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("LOG %(name)s %(levelname)s %(message)s"))
logging.getLogger().addHandler(_handler)
logging.getLogger().setLevel(logging.WARNING)

SENTINEL = "RULE_CHANGE_NATIVE_RESULT "
WORK = os.environ["RULE_CHANGE_WORK"]
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
ACTORS = ("miner", "alice", "bob")
KEYS = {}
for name in ACTORS:
    sk = bls.KeyGen(hashlib.sha256(("rule-change-native-" + name).encode()).digest())
    KEYS[name] = {"sk": sk, "pk": bls.SkToPk(sk).hex()}
PK = {n: KEYS[n]["pk"] for n in ACTORS}

genesis_path = os.path.join(WORK, "genesis.json")
cmd = [sys.executable, "scripts/gen_genesis.py", "--validator-privkey", format(KEYS["miner"]["sk"], "064x"),
       "--base-fee", "10", "--network-id", "tau-rule-change-native", "--approval-slots",
       "--out", genesis_path]
for name in ("alice", "bob"):
    cmd += ["--account", PK[name] + ":1000000"]
subprocess.run(cmd, check=True, capture_output=True)

import config
config.set_database_path(os.path.join(WORK, "node.db"))
config.MINER_PRIVKEY = format(KEYS["miner"]["sk"], "064x")
config.MINER_PUBKEY = PK["miner"]
config.MINER_PUBKEYS = [PK["miner"]]
import db
db._db_conn = None
db.init_db()
import tau_native, tau_manager, chain_state
from commands import sendtx, createblock
from consensus.tx_signing import signing_message_bytes
from consensus.approvals import parse_rule_change_request
from tau_testnet_cli import tx as cli_tx

chain_state.load_genesis(genesis_path)
tau_manager.tau_direct_interface = tau_native.TauInterface(config.TAU_PROGRAM_FILE)
tau_manager.tau_test_mode = False
tau_manager.tau_process_ready.set()
plan = chain_state.get_tau_restore_plan(use_persisted_state=False)
chain_state.replay_tau_restore_plan(plan, source_prefix="startup")
tau_manager.tau_ready.set()

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

def seal():
    res = createblock.create_block_from_mempool(allow_empty=True)
    if "block_hash" not in res:
        note("SEAL FAILED " + json.dumps(res, default=str)[:300])
    return res

def book():
    return chain_state._lifecycle_manager.approval_requests

def clause(who, idx):
    return chain_state._lifecycle_manager.rule_offers.clause_for(PK[who], idx)

def request(name, kind, rule_text="", approvers=None):
    p = cli_tx.build_rule_change_request_tx(
        sender_pubkey=PK[name], sequence_number=seq(name),
        expiration_time=int(time.time()) + 3600, expire_at_height=head() + 50,
        kind=kind, rule_text=rule_text, approvers=approvers or {}, fee_limit="1000")
    res = submit(sign(name, p))
    return res, parse_rule_change_request(p).request_id.hex()

def vote(name, rid, offset=0):
    p = cli_tx.build_transfer_vote_tx(
        sender_pubkey=PK[name], sequence_number=seq(name) + offset,
        expiration_time=int(time.time()) + 3600, expire_at_height=head() + 50,
        request_id=rid, approve=True)
    return submit(sign(name, p))

def entry(rid):
    e = book().get_rule_change(bytes.fromhex(rid))
    return None if e is None else {"status": e.status, "ready": bool(e.ready),
                                   "voted": dict(e.voted)}

from consensus.engine import TauConsensusEngine
_verify = TauConsensusEngine.verify_block_header
def _verify_but_genesis(self, *args, **kwargs):
    blk = next((a for a in args if hasattr(a, "header")), None)
    if blk is not None and blk.header.block_number == 0:
        return True
    return _verify(self, *args, **kwargs)
TauConsensusEngine.verify_block_header = _verify_but_genesis

GUARD_TEXT = os.environ["RULE_CHANGE_GUARD_TEXT"]
POLICY_TEXT = ("always ( (i1[t]:bv[24] > { #x000064 }:bv[24]) ? "
               "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).")
UNBUILDABLE_TEXT = ("always ( (zz[t]:bv[24] = { #x000001 }:bv[24]) ? "
                    "(o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).")
GUARD_IDX = int(os.environ["RULE_CHANGE_GUARD_INDEX"])
out = {"pk": PK}

seal()
h0 = head()

res, guard_rid = request("alice", 4, GUARD_TEXT, {18: PK["bob"]})
out["guard_admitted"] = bool(res.get("ok"))
seal()
out["guard_status"] = entry(guard_rid)
out["guard_registered"] = clause("alice", GUARD_IDX) is not None

res, rid1 = request("alice", 1, POLICY_TEXT, {18: PK["bob"]})
out["set_admitted"] = bool(res.get("ok"))
seal()
out["parked"] = entry(rid1)
out["policy_after_park"] = clause("alice", 5)
h1 = head()

res = vote("bob", rid1)
out["vote_admitted"] = bool(res.get("ok"))
blk = seal()
out["released"] = entry(rid1)
out["released_in_vote_block"] = head() == h1 + 1 and "block_hash" in blk
out["policy_after_release"] = clause("alice", 5)

res, rid2 = request("alice", 2, "", {18: PK["bob"]})
out["revoke_a_admitted"] = bool(res.get("ok"))
seal()
res, rid3 = request("alice", 2, "", {18: PK["bob"]})
out["revoke_b_admitted"] = bool(res.get("ok"))
seal()
out["revoke_parked"] = [entry(rid2), entry(rid3)]
h3 = head()
vote("bob", rid2)
vote("bob", rid3, offset=1)
blk = seal()
out["revoke_final"] = [entry(rid2), entry(rid3)]
out["revoke_block_ok"] = head() == h3 + 1 and "block_hash" in blk
out["policy_after_revokes"] = clause("alice", 5)

before = len(notes)
res, rid4 = request("alice", 1, UNBUILDABLE_TEXT, {18: PK["bob"]})
out["unbuildable_admitted"] = bool(res.get("ok"))
out["unbuildable_code"] = res.get("code")
del notes[before:]
emit(out)
'''


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    work = tmp_path_factory.mktemp("rule-change-native")
    script = work / "child.py"
    script.write_text(_CHILD_SRC)
    env = _env()
    env["RULE_CHANGE_WORK"] = str(work)
    env["RULE_CHANGE_GUARD_INDEX"] = str(tau_defs.RULE_CHANGE_GUARD_INDEX)
    env["RULE_CHANGE_GUARD_TEXT"] = _child_guard_text()
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                          env=env, cwd=REPO, timeout=600)
    line = next((l for l in proc.stdout.splitlines() if l.startswith(SENTINEL)), None)
    assert line is not None, (
        f"child produced no verdict\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-2000:]}")
    result = json.loads(line[len(SENTINEL):])
    result["stdout"] = proc.stdout
    return result


def _child_guard_text():
    """The 'any change needs X' guard with X = the child's bob (its key is derived
    from a fixed label, so the test can compute it before the child runs)."""
    from py_ecc.bls import G2Basic as bls
    sk = bls.KeyGen(hashlib.sha256(b"rule-change-native-bob").digest())
    return GUARDS[ANY].replace(PLACEHOLDER_A, bls.SkToPk(sk).hex())


def test_a_guard_set_with_no_guard_yet_executes_in_its_own_block(run):
    assert not any(n.startswith(("REJECTED", "SEAL FAILED")) for n in run["notes"]), run["notes"]
    assert run["guard_admitted"]
    assert run["guard_status"]["status"] == 1
    assert run["guard_registered"]


def test_a_kind_1_request_under_a_blocking_guard_parks(run):
    assert run["set_admitted"]
    assert run["parked"] == {"status": 0, "ready": False, "voted": {}}
    assert run["policy_after_park"] is None


def test_a_vote_releases_the_request_in_the_same_block_and_registers_the_clause(run):
    assert run["vote_admitted"]
    assert run["released"]["status"] == 1
    assert run["released"]["voted"] == {"18": run["pk"]["bob"]}
    assert run["released_in_vote_block"]
    assert run["policy_after_release"] is not None
    assert "o5[t]" in run["policy_after_release"]


def test_a_release_that_fails_ends_failed_and_the_block_is_valid(run):
    assert run["revoke_a_admitted"] and run["revoke_b_admitted"]
    assert [e["status"] for e in run["revoke_parked"]] == [0, 0]
    assert [e["status"] for e in run["revoke_final"]] == [1, 3]
    assert run["revoke_block_ok"]
    assert run["policy_after_revokes"] is None


def test_a_body_that_does_not_build_never_reaches_a_block_through_sendtx(run):
    assert run["unbuildable_admitted"] is False
    assert run["unbuildable_code"] == "TX_REJECTED"


def test_a_release_whose_build_fails_is_soft_on_the_real_clause_builder(real):
    body = clause_body_v1(
        "always ( (zz[t]:bv[24] = { #x000001 }:bv[24]) ? "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).")
    ok, error = sender_policy.clause_builds(body, pool="apply")
    assert ok is False
    assert "undefined I/O stream" in error
