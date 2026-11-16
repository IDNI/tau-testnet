#!/usr/bin/env python3
"""Block apply time against the number of registered policy authors.

Real parts: engine.apply in proposal mode (per-transaction branch, lifecycle
clone, signature check, fee settlement) on a worker-backed shared interpreter,
the policy evaluator pool with its worker process, the clause registry inside a
real lifecycle manager, and the canonical-state commit into a SQLite file.
Stubbed: the shared interpreter holds the genesis router rule only (no
accumulated user rules), and the registry is seeded directly in memory, not
through transactions.

    python scripts/bench_policy_clauses.py --sizes 0,100,1000,10000 --dir <scratch>

Needs the native module on TAU_NATIVE_PATH or PYTHONPATH. Prints one table.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import os
import random
import resource
import statistics
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

PROPOSER = "d4" * 48
BLOCK_TS = 1_700_000_000
DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
BLOCK_TXS = 50
RECIPIENTS = 8
BALANCE = 10 ** 9
STREAM = 5


def native_path():
    return os.environ.get("TAU_NATIVE_PATH") or ""


def worker_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        p for p in (REPO, native_path(), env.get("PYTHONPATH", "")) if p)
    env["TAU_FORCE_TEST"] = "0"
    return env


if native_path():
    sys.path.insert(0, native_path())

import config  # noqa: E402
import db  # noqa: E402
import chain_state  # noqa: E402
import tau_allocator as alloc  # noqa: E402
import tau_journal as tj  # noqa: E402
import tau_policy  # noqa: E402
import tau_proposal as tp  # noqa: E402
import tau_reconstruction as tr  # noqa: E402
import tau_session as ts  # noqa: E402
from consensus import sender_policy  # noqa: E402
from consensus.clause_registry import ClauseRegistry  # noqa: E402
from consensus.engine import TauConsensusEngine  # noqa: E402
from consensus.governance import ConsensusLifecycleManager  # noqa: E402
from consensus.rule_offers import clause_body_v1  # noqa: E402
from consensus.state import TauStateSnapshot  # noqa: E402
from consensus.tx_signing import signing_message_bytes  # noqa: E402
from py_arkworks_bls12381 import G1Point, G2Point, Scalar  # noqa: E402


# --- keys, clauses, transactions ---------------------------------------------

_PK_CACHE: dict = {}


def pubkey(sk: int) -> str:
    if sk not in _PK_CACHE:
        _PK_CACHE[sk] = (G1Point() * Scalar(sk)).to_compressed_bytes().hex()
    return _PK_CACHE[sk]


def sign(tx: dict, sk: int) -> dict:
    tx.setdefault("expiration_time", 9_999_999_999)
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = (G2Point.hash_to_curve(digest, DST) * Scalar(sk)).to_compressed_bytes().hex()
    return tx


def author_sk(i: int) -> int:
    return 2_000_000 + i


def plain_sk(j: int) -> int:
    return 5_000_000 + j


def recipient_pk(k: int) -> str:
    return pubkey(9_000_000 + k)


def bv(value: int, width: int) -> str:
    return "{ #x%0*x }:bv[%d]" % (width // 4, value, width)


def clause_text(i: int, salt: int = 0) -> str:
    """Author i's clause: spend limit, recipient whitelist, time lock, or one to
    three approver slots. Every bench transfer is allowed by every shape."""
    allow, deny = f"(o5[t]:bv[24] = {bv(1, 24)})", f"(o5[t]:bv[24] = {bv(0, 24)})"
    shape = i % 4
    if shape == 0:
        cond = f"i1[t]:bv[24] > {bv(1000 + i + salt, 24)}"
    elif shape == 1:
        pks = [recipient_pk(i % RECIPIENTS), pubkey(author_sk(i + 1 + salt)),
               pubkey(author_sk(i + 2))]
        cond = "!(" + " || ".join(f"i4[t]:bv[384] = {bv(int(p, 16), 384)}" for p in pks) + ")"
    elif shape == 2:
        cond = f"i5[t]:bv[64] < {bv(1000 + i + salt, 64)}"
    else:
        slots = 1 + (i // 4) % 3
        tiers = [(0x2710 + i + salt, 18), (0x186a0 + i + salt, 19),
                 (0x2dc6c0 + i + salt, 20)][:slots]
        cond = " || ".join(
            f"(i1[t]:bv[24] > {bv(limit, 24)} && !(i{slot}[t]:bv[384] = "
            f"{bv(int(pubkey(author_sk(i + 7 * slot)), 16), 384)}))"
            for limit, slot in tiers)
    return f"always ( ( {cond} ) ? {deny} : {allow} )."


def clause_body(i: int, salt: int = 0) -> str:
    return clause_body_v1(clause_text(i, salt))


class Harness:
    """One chain state: a lifecycle manager holding `n` authors' clauses."""

    def __init__(self, n: int, workdir: str):
        self.n = n
        self.workdir = workdir
        self.engine = TauConsensusEngine(state_store=None)
        t = time.perf_counter()
        self.lm = ConsensusLifecycleManager()
        self.lm.approval_slots_active = True
        seed = {(pubkey(author_sk(i)), STREAM): clause_body(i) for i in range(n)}
        self.seed_seconds = time.perf_counter() - t
        t = time.perf_counter()
        self.lm.rule_offers.accepted_clauses = ClauseRegistry(seed)
        self.registry_seconds = time.perf_counter() - t
        self.seq: dict = {}
        self.block_no = 0
        self.snapshot = alloc.DbMappingSnapshot()
        self.evaluators: list = []
        self.ev = None
        self.router = _router()
        self.new_evaluator()

    # -- evaluator ----------------------------------------------------------

    def new_evaluator(self, **kwargs):
        if self.ev is not None:
            self.retire_evaluator()
        self.ev = TimedEvaluator(pool="apply", cwd=REPO, env=worker_env(), **kwargs)
        sender_policy.set_evaluator("apply", self.ev)
        self.ev._current()
        self.ev.stats()                       # spawn and import cost stay out of a block
        return self.ev

    def retire_evaluator(self):
        stats = self.ev.stats()
        stats["log"] = list(self.ev.log)
        self.evaluators.append(stats)
        self.ev.close()
        self.ev = None

    # -- one block ----------------------------------------------------------

    def proposal(self):
        plan = tr.plan_representation(candidate_rules=[])

        def rebuild(journal, current_plan):
            session = ts.WorkerSession.spawn(self.router, cwd=REPO, env=worker_env(),
                                             plan=current_plan)
            session.begin_proposal(alloc.Allocator(self.snapshot, width=current_plan.width))
            for entry in journal.entries():
                if entry.kind == tj.REVISION:
                    session.apply_rule(entry.rule_text, record=False,
                                       accumulate=entry.accumulate)
                else:
                    session.evaluate(entry.inputs, multi=True, record=False)
            return session

        return tp.ProposalContext(
            session=rebuild(tj.Journal(authoritative=False), plan),
            journal=tj.Journal(authoritative=False),
            allocator=alloc.Allocator(self.snapshot, width=plan.width, label="proposal"),
            plan=plan, rebuild=rebuild, lifecycle=self.lm,
        )

    def block(self, sks: list) -> float:
        """Apply one block of transfers from `sks`; seconds spent in apply."""
        self.block_no += 1
        pks = [pubkey(sk) for sk in sks]
        txs = []
        for k, (sk, pk) in enumerate(zip(sks, pks)):
            seq = self.seq.get(pk, 0)
            to = recipient_pk(sk % RECIPIENTS)
            txs.append(sign({
                "tx_id": f"b{self.block_no}-{k}", "tx_type": "user_tx",
                "sender_pubkey": pk, "sequence_number": seq, "fee_limit": "1000",
                "operations": {"1": [[pk, to, str(1 + k % 9)]]}}, sk))
        balances = {pk: BALANCE for pk in pks}
        for r in range(RECIPIENTS):
            balances[recipient_pk(r)] = 0
        sequences = {pk: self.seq.get(pk, 0) for pk in pks}
        ctx = self.proposal()
        try:
            started = time.perf_counter()
            result = self.engine.apply(
                TauStateSnapshot(b"hash", b"rules", {}), txs, BLOCK_TS,
                target_balances=balances, target_sequences=sequences,
                target_lifecycle=self.lm, proposer_pubkey=PROPOSER,
                block_height=self.block_no, proposal=ctx, session=ctx.session)
            elapsed = time.perf_counter() - started
            accepted = len(result.accepted_transactions)
        finally:
            ctx.dispose()
        if accepted != len(txs):
            raise SystemExit(f"block {self.block_no}: {accepted}/{len(txs)} applied; "
                             f"{ {t.get('tx_id'): result.receipts.get(t.get('tx_id')) for t in result.rejected_transactions[:2]} }")
        for pk in pks:
            self.seq[pk] = self.seq.get(pk, 0) + 1
        return elapsed

    # -- commit -------------------------------------------------------------

    def commit(self, mutate: int, with_accounts: bool):
        """Mutate `mutate` clauses, then write canonical state; returns
        (kwargs seconds, write seconds, hash seconds, clause rows written)."""
        rng = random.Random(self.block_no)
        picks = rng.sample(range(max(self.n, mutate)), mutate)
        for i in picks:
            self.lm.rule_offers.accepted_clauses[(pubkey(author_sk(i)), STREAM)] = \
                clause_body(i, 1 + self.block_no % 500)
        self.block_no += 1
        t = time.perf_counter()
        self.lm.consensus_meta_hash()
        hash_s = time.perf_counter() - t
        balances = {pubkey(plain_sk(j)): BALANCE for j in range(BLOCK_TXS)}
        if with_accounts:
            balances.update({pubkey(author_sk(i)): BALANCE for i in range(self.n)})
        snap = TauStateSnapshot(b"hash", b"rules", {
            "balances": balances, "sequence_numbers": {}, "lifecycle_manager": self.lm,
            "consensus_rules_state": ""})
        t = time.perf_counter()
        kwargs = chain_state._canonical_state_kwargs(
            snap, head_hash=f"{self.block_no:064x}", head_num=self.block_no)
        kwargs_s = time.perf_counter() - t
        plan = kwargs["rule_clauses"]
        stored = db.load_rule_clauses_token()
        rows = len(plan.changes) if plan.token is not None and plan.token == stored else len(plan.full_rows())
        t = time.perf_counter()
        db.save_canonical_state_atomically(**kwargs)
        return kwargs_s, time.perf_counter() - t, hash_s, rows


class TimedEvaluator(tau_policy.PolicyEvaluator):
    """The real evaluator, recording what each request cost."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.log: list = []

    def _run(self, payload, timeout):
        started, recycles = time.perf_counter(), self.recycles
        resp = super()._run(payload, timeout)
        self.log.append((payload["op"], time.perf_counter() - started,
                         bool(resp.get("built")), float(resp.get("build_seconds") or 0.0),
                         resp.get("o5"), self.recycles != recycles))
        return resp


def _router() -> str:
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} && (o9[t]:bv[24] = {bv(7, 24)}) )."


# --- measurement --------------------------------------------------------------

def med(values):
    return statistics.median(values) if values else float("nan")


def ms(seconds):
    if seconds != seconds:
        return "-"
    return f"{seconds * 1000:.1f}" if seconds >= 0.01 else f"{seconds * 1000:.3f}"


def measure(h: Harness, blocks: int, rng: random.Random) -> dict:
    out: dict = {}
    n = h.n
    plain = [plain_sk(j) for j in range(BLOCK_TXS)]
    warm = [author_sk(i) for i in range(min(BLOCK_TXS, n))]

    h.block(plain)                                            # discarded warm-up
    out["a"] = med([h.block(plain) for _ in range(blocks)])

    if n >= BLOCK_TXS:
        h.block(warm)                                         # discarded: builds the 50
        builds_before = h.ev.stats()["builds"]
        out["b"] = med([h.block(warm) for _ in range(blocks)])
        out["b_builds"] = h.ev.stats()["builds"] - builds_before

        cold_times, splits = [], []
        for round_no in range(blocks + 1):
            h.new_evaluator()                                 # empty cache: every clause unseen
            senders = [author_sk(i) for i in rng.sample(range(n), BLOCK_TXS)]
            seconds = h.block(senders)
            if round_no == 0:
                continue                                      # discarded warm-up
            cold_times.append(seconds)
            log = h.ev.log
            build = sum(b for (_o, _t, built, b, _v, _r) in log if built)
            steps = sum(t - b for (_o, t, _built, b, _v, _r) in log)
            splits.append((build, steps, sum(1 for e in log if e[2])))
        out["c"] = med(cold_times)
        out["c_build_per"] = med([b / max(k, 1) for b, _s, k in splits])
        out["c_step_per"] = med([s / BLOCK_TXS for _b, s, _k in splits])
        h.new_evaluator()
    out["d"] = med(_clone_times(h))
    return out


def _clone_times(h: Harness, repeat=200):
    times = []
    for _ in range(repeat):
        started = time.perf_counter()
        copy.deepcopy(h.lm)
        times.append(time.perf_counter() - started)
    return times


def measure_commit(h: Harness, blocks: int) -> dict:
    first = h.commit(0, with_accounts=False)
    rows = [h.commit(50, with_accounts=False) for _ in range(blocks)]
    full = [h.commit(50, with_accounts=True) for _ in range(blocks)]
    with db._db_lock:
        stored = db._db_conn.execute("SELECT COUNT(*) FROM rule_clauses_v1").fetchone()[0]
    return {
        "e0": first[1], "e_kwargs": med([r[0] for r in rows]), "e": med([r[1] for r in rows]),
        "e_rows": med([r[3] for r in rows]), "e_hash": med([r[2] for r in rows]),
        "e2": med([r[1] for r in full]), "stored": stored, "expected": len(h.lm.rule_offers.accepted_clauses),
    }


def counters(h: Harness) -> dict:
    h.retire_evaluator()
    total = {"builds": 0, "steps": 0, "live": 0, "pinned": 0, "evictions": 0,
             "recycles": 0, "fresh_fallbacks": 0, "retries": 0, "spawns": 0, "rss": 0}
    for s in h.evaluators:
        for key in ("builds", "steps", "evictions", "recycles", "fresh_fallbacks",
                    "retries", "spawns"):
            total[key] += int(s.get(key, 0))
        for key in ("live", "pinned"):
            total[key] = max(total[key], int(s.get(key, 0)))
        total["rss"] = max(total["rss"], int(s.get("rss_bytes", 0)))
    total["node_rss"] = peak_rss()
    return total


def peak_rss() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


# --- risk measurements ---------------------------------------------------------

def risk_failed_builds(h: Harness, count=20) -> dict:
    """Clause submissions that do not build, on the admission pool's evaluator."""
    good = [clause_body(i) for i in range(8)]
    bad = lambda k: f"o5[t]:bv[24] = {bv(k, 24)} && ((("      # does not parse
    out: dict = {}
    for mode in ("consecutive", "interleaved"):
        ev = TimedEvaluator(pool="admission", cwd=REPO, env=worker_env())
        try:
            for body in good:
                ev.validate(body)
            before = ev.fresh_fallbacks
            times = []
            for k in range(count):
                if mode == "interleaved":
                    ev.validate(good[k % len(good)])
                started = time.perf_counter()
                res = ev.validate(bad(k))
                times.append(time.perf_counter() - started)
                assert not res.ok
            warm_started = time.perf_counter()
            ev.verdict(good[0], _inputs(0))
            after = time.perf_counter() - warm_started
            steady = []
            for _ in range(5):
                started = time.perf_counter()
                ev.verdict(good[0], _inputs(0))
                steady.append(time.perf_counter() - started)
            out[mode] = {"per_bad": med(times), "max_bad": max(times),
                         "replacements": ev.fresh_fallbacks - before,
                         "next_verdict": after, "steady_verdict": med(steady)}
        finally:
            ev.close()
    return out


def _inputs(k: int) -> dict:
    return sender_policy.clause_inputs({
        1: "{ #x%06x }:bv[24]" % (1 + k % 9),
        3: "{ #x%s }:bv[384]" % pubkey(author_sk(0)),
        4: "{ #x%s }:bv[384]" % recipient_pk(0),
        5: str(BLOCK_TS), 12: "{ #x%s }:bv[384]" % pubkey(author_sk(0))})


def risk_recycle(h: Harness, recycles=3) -> dict:
    """Force recycles in the apply pool; verdicts before and after must agree."""
    probes = [(i, clause_body(i)) for i in range(BLOCK_TXS)]

    def verdicts(ev):
        return [ev.verdict(body, _inputs(i)).o5 for i, body in probes]

    ev = h.new_evaluator(recycle_builds=2 * BLOCK_TXS)
    base = verdicts(ev)
    rng = random.Random(7)
    pauses, equal, rows = [], [], []
    seen = 0
    while ev.recycles < recycles and len(rows) < 12:
        senders = [author_sk(i) for i in rng.sample(range(h.n), BLOCK_TXS)]
        before = ev.recycles
        seconds = h.block(senders)
        rows.append((seconds, ev.recycles - before))
        if ev.recycles != before:
            equal.append(verdicts(ev) == base)
        seen += 1
    plain = [s for s, r in rows if r == 0]
    recycled = [s for s, r in rows if r > 0]
    pause = med(recycled) - med(plain) if plain and recycled else float("nan")
    overhead = [t - b for (_o, t, _built, b, _v, _r) in ev.log if not _r]
    hit = [t - b for (_o, t, _built, b, _v, r) in ev.log if r]
    return {"recycles": ev.recycles, "identical": all(equal) and bool(equal),
            "block_plain": med(plain), "block_recycle": med(recycled), "pause": pause,
            "request_pause": med(hit) - med(overhead) if hit else float("nan"),
            "request_pause_max": max(hit) if hit else float("nan")}


# --- main ----------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sizes", default="0,100,1000,10000")
    ap.add_argument("--blocks", type=int, default=5, help="measured blocks per row")
    ap.add_argument("--dir", required=True, help="scratch directory for the SQLite files")
    ap.add_argument("--risk-at", type=int, default=1000)
    args = ap.parse_args(argv)
    sizes = [int(s) for s in args.sizes.split(",")]
    os.makedirs(args.dir, exist_ok=True)
    os.environ["TAU_FORCE_TEST"] = "0"
    rng = random.Random(1)
    table, risks = [], {}
    started_all = time.time()

    for n in sizes:
        path = os.path.join(args.dir, f"bench-{n}.sqlite")
        for suffix in ("", "-wal", "-shm"):
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass
        config.set_database_path(path)
        if getattr(db, "_db_conn", None) is not None:
            db._db_conn.close()
            db._db_conn = None
        db.init_db()
        print(f"-- N={n}: seeding", flush=True)
        h = Harness(n, args.dir)
        print(f"   seed {h.seed_seconds:.1f}s, registry {h.registry_seconds:.2f}s", flush=True)
        t = time.time()
        row = measure(h, args.blocks, rng)
        print(f"   apply rows done in {time.time() - t:.0f}s", flush=True)
        row.update(measure_commit(h, args.blocks))
        if n == args.risk_at:
            risks["failed_builds"] = risk_failed_builds(h)
            risks["recycle"] = risk_recycle(h)
        row["counters"] = counters(h)
        row["n"] = n
        table.append(row)
        sender_policy.set_evaluator("apply", None)
        db._db_conn.close()
        db._db_conn = None

    print()
    header = ("N", "a plain", "b warm", "c cold", "c build/tx", "c step/tx", "d clone",
              "e kwargs", "e save", "e rows", "e0 full", "e hash", "e2 +accts")
    print("  ".join(f"{h:>10}" for h in header), "  (ms; blocks of 50 transfers)")
    for r in table:
        cells = [str(r["n"]), ms(r["a"]), ms(r.get("b", float("nan"))),
                 ms(r.get("c", float("nan"))), ms(r.get("c_build_per", float("nan"))),
                 ms(r.get("c_step_per", float("nan"))), ms(r["d"]),
                 ms(r["e_kwargs"]), ms(r["e"]), f"{r['e_rows']:.0f}", ms(r["e0"]), ms(r["e_hash"]), ms(r["e2"])]
        print("  ".join(f"{c:>10}" for c in cells))
    print("\npath: a,b,c = engine.apply in proposal mode (per-transaction branch with lifecycle"
          " clone; b and c differ only in evaluator cache state); d = one deepcopy of the"
          " lifecycle manager; e = canonical-state kwargs (clause plan) then save, 50 changed"
          " clauses, no other accounts; e0 = the first save (whole table); e2 = the e save"
          " with an account row for every author.")

    cheader = ("N", "builds", "steps", "live", "pinned", "evict", "recycle", "fresh", "retry",
               "spawns", "worker MB", "node MB")
    print("\n" + "  ".join(f"{h:>9}" for h in cheader))
    for r in table:
        c = r["counters"]
        print("  ".join(f"{x:>9}" for x in (
            r["n"], c["builds"], c["steps"], c["live"], c["pinned"], c["evictions"],
            c["recycles"], c["fresh_fallbacks"], c["retries"], c["spawns"],
            f"{c['rss'] / 1e6:.0f}", f"{c['node_rss'] / 1e6:.0f}")))

    if risks:
        print(f"\nrisk at N={args.risk_at}")
        for mode, v in risks["failed_builds"].items():
            print(f"  (g) 20 failing submissions, {mode}: {v['per_bad'] * 1000:.0f} ms each"
                  f" (max {v['max_bad'] * 1000:.0f}), {v['replacements']} worker replacements;"
                  f" next verdict of a warm clause {v['next_verdict'] * 1000:.0f} ms"
                  f" vs {v['steady_verdict'] * 1000:.1f} ms steady")
        r = risks["recycle"]
        print(f"  (h) {r['recycles']} recycles, verdicts identical: {r['identical']};"
              f" block {r['block_plain'] * 1000:.0f} ms plain, {r['block_recycle'] * 1000:.0f} ms"
              f" with a recycle (difference {r['pause'] * 1000:.0f} ms); the triggering request"
              f" waits {r['request_pause'] * 1000:.0f} ms beyond a normal one"
              f" (largest {r['request_pause_max'] * 1000:.0f} ms)")
    print(f"\ntotal {time.time() - started_all:.0f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
