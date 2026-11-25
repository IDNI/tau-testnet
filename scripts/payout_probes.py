"""Reproducible proof probes for the Bounty 01 payout book
(stage 2). Two independent measurements, both deterministic:

(a) Interleave probe -- one evaluator session is stepped 25,000
    times with the shipped payout clauses interleaved among
    unrelated rules. The session's evaluator double derives each
    clause's legs by PARSING the clause text (the hex constants in
    the Tau source), while the reference answers come from an
    independent hand-written share table below. A step is wrong
    when the session's answer differs from the reference: a clause
    leaking into another clause's step, a misread constant, or a
    dropped leg all count. Required: 0 wrong answers.

(b) Differential probe -- an independent reference model of the
    settlement bookkeeping (caps, replay refusal, period roll,
    totals) is run against consensus.payouts.PayoutBook over a
    deterministic grid of templates x grosses x cap profiles x
    prior-spend states x operation sequences. The grid holds
    4 * 25 * 6 * 7 * 29 = 121,800 settlement paths. Required:
    0 divergences.

Run directly (full grid) via scripts/payout_interleave_probe.py
and scripts/payout_differential_probe.py; the pytest wrappers in
tests/test_payout_stage2_proofs.py run the interleave in full and
a strided subset of the differential grid.

The leg shares under test are inputs shared by both sides of the
differential (the book never computes legs -- the clause does);
share arithmetic itself is what the interleave probe checks, by
parse-versus-table. Nothing here imports the competitor's work;
the grid sizes are ours.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consensus import periods  # noqa: E402
from consensus.payouts import (  # noqa: E402
    MAX_SETTLEMENTS_KEPT,
    TEMPLATE_PERCENTAGE_ROUTE_CLAUSE,
    TEMPLATE_ROYALTY_5PCT_CLAUSE,
    TEMPLATE_WORK_ESCROW_CLAUSE,
    PayoutBook,
    PayoutShapeError,
    PayoutTerms,
)

# --- the independent share table (reference side of (a)) ------------

#: Percentage shares per leg, written by hand from the issue text:
#: the #34/#35 receive route forwards 20%, the #35 royalty takes
#: 5%, and the #63 work escrow splits 50/10/10/10/15/5.
SHARES = {
    "route20": [20],
    "royalty5": [5],
    "escrow63": [50, 10, 10, 10, 15, 5],
}

CLAUSES = {
    "route20": TEMPLATE_PERCENTAGE_ROUTE_CLAUSE,
    "royalty5": TEMPLATE_ROYALTY_5PCT_CLAUSE,
    "escrow63": TEMPLATE_WORK_ESCROW_CLAUSE,
}

#: Unrelated rules sharing the session in the interleave: their
#: verdict constants are read from the text by the double and
#: known independently here.
UNRELATED = {
    "guard_open": "always (o5[t]:bv[24] = { #x000001 }:bv[24]).",
    "guard_shut": "always (o5[t]:bv[24] = { #x000000 }:bv[24]).",
}
UNRELATED_VERDICTS = {"guard_open": 1, "guard_shut": 0}


def reference_legs(name, gross):
    return [gross * pct // 100 for pct in SHARES[name]]


# --- the parsing evaluator double (session side of (a)) -------------

_MUL_DIV = re.compile(
    r"\(\(i1\[t\]:bv\[24\] \* \{ #x([0-9a-f]+) \}:bv\[24\]\)"
    r" / \{ #x([0-9a-f]+) \}:bv\[24\]\)")
_COUNT = re.compile(r"o20\[t\]:bv\[24\] = \{ #x([0-9a-f]+) \}:bv\[24\]")
_VERDICT = re.compile(r"o5\[t\]:bv\[24\] = \{ #x([0-9a-f]+) \}:bv\[24\]")


def parse_clause(name, text):
    """Compile a clause text into a program by reading its own
    constants: (leg_count, [(multiplier, divisor), ...]) for a
    payout clause, or ("verdict", value) for an unrelated rule."""
    verdict = _VERDICT.search(text)
    if verdict and "o20" not in text:
        return ("verdict", int(verdict.group(1), 16))
    count = int(_COUNT.search(text).group(1), 16)
    pairs = [(int(m, 16), int(d, 16)) for m, d in _MUL_DIV.findall(text)]
    if len(pairs) != count:
        raise ValueError(f"{name}: text declares {count} legs, "
                         f"parsed {len(pairs)}")
    return ("legs", pairs)


class EvaluatorSession:
    """One long-lived session holding every clause's program,
    stepped alternately -- the shape of the node's single Tau
    session, in which a payout evaluation must never see another
    rule's constants."""

    def __init__(self):
        self.programs = {}
        for name, text in {**CLAUSES, **UNRELATED}.items():
            self.programs[name] = parse_clause(name, text)
        self.steps = 0

    def step(self, name, gross):
        kind, payload = self.programs[name]
        self.steps += 1
        if kind == "verdict":
            return payload
        return [gross * mul // div for mul, div in payload]


def run_interleave(steps=25_000):
    """Step one session `steps` times, payout clauses interleaved
    with unrelated rules; return (steps, wrong_answers)."""
    session = EvaluatorSession()
    names = list(CLAUSES) + list(UNRELATED)
    wrong = 0
    for s in range(steps):
        name = names[(s * 7 + 3) % len(names)]
        gross = (s * 2654435761) % 10_000 + 1
        got = session.step(name, gross)
        if name in SHARES:
            want = reference_legs(name, gross)
        else:
            want = UNRELATED_VERDICTS[name]
        if got != want:
            wrong += 1
    return session.steps, wrong


# --- the differential probe (b) --------------------------------------

OWNER = "aa" * 48
RECIPIENTS = tuple(f"{i:02x}" * 48 for i in range(0xB0, 0xB6))
ANCHOR = 1767225600  # 2026-01-01 UTC
SPAN = periods.SECONDS_PER_WEEK

TEMPLATES = {
    "route20": [20],
    "royalty5": [5],
    "split6040": [60, 40],
    "escrow63": [50, 10, 10, 10, 15, 5],
}
GROSSES = [0, 1, 2, 3, 5, 9, 10, 49, 50, 99, 100, 101, 150, 199,
           200, 499, 500, 999, 1000, 1001, 2500, 4999, 5000, 9999,
           10000]
CAP_PROFILES = [  # (max_per_execution, max_per_period)
    (1, 1), (5, 9), (100, 150), (1000, 1500), (10000, 20000),
    (3, 10000),
]


def _legs_for(template, gross):
    return [gross * pct // 100 for pct in TEMPLATES[template]]


def _chunks(amount, exec_cap):
    """Split a prior-spend amount into settlements of at most the
    per-execution cap, at most eight of them: with a tiny
    per-execution cap against a huge period cap the fraction is
    then approximated by eight max-size settlements rather than
    thousands of dust ones. Both sides run the same op list, so
    the state reached is exact either way."""
    out = []
    while amount > 0 and len(out) < 8:
        take = min(amount, exec_cap)
        out.append(take)
        amount -= take
    return out


def _prior_ops(idx, exec_cap, period_cap):
    """Seven prior-spend states, as settlement ops applied before
    the measured sequence (and themselves differentially checked)."""
    if idx == 0:
        return []
    if idx == 1:
        amt = max(1, period_cap * 10 // 100)
        return [("legs", f"p{k}", a)
                for k, a in enumerate(_chunks(amt, exec_cap))]
    if idx == 2:
        amt = max(1, period_cap * 50 // 100)
        return [("legs", f"p{k}", a)
                for k, a in enumerate(_chunks(amt, exec_cap))]
    if idx == 3:
        amt = max(1, period_cap * 90 // 100)
        return [("legs", f"p{k}", a)
                for k, a in enumerate(_chunks(amt, exec_cap))]
    if idx == 4:  # exactly the period cap
        return [("legs", f"p{k}", a)
                for k, a in enumerate(_chunks(period_cap, exec_cap))]
    if idx == 5:  # two settlements of a quarter cap each
        amt = max(1, period_cap * 25 // 100)
        return [("legs", f"p{k}", a)
                for k, a in enumerate(_chunks(amt, exec_cap))
                ] + [("legs", f"q{k}", a)
                     for k, a in enumerate(_chunks(amt, exec_cap))]
    # idx == 6: a settlement whose id the sequences reuse.
    return [("legs", "a", max(1, min(exec_cap, period_cap * 10 // 100)))]


def _sequences():
    """29 operation sequences. Ops: ("legs", sid, amount) settles
    one leg of `amount`; ("tmpl", sid, gross) settles the
    template's legs on `gross`; ("adv", periods) advances time."""
    seqs = [
        [("tmpl", "a", 1)],
        [("tmpl", "a", 1), ("tmpl", "b", 1)],
        [("tmpl", "a", 1), ("tmpl", "a", 1)],
        [("tmpl", "a", 1), ("adv", 1), ("tmpl", "a", 1)],
        [("tmpl", "a", 1), ("adv", 1), ("tmpl", "b", 1)],
        [("legs", "a", 1)],
        [("legs", "a", 7), ("legs", "b", 7)],
        [("legs", "a", 7), ("legs", "a", 7)],
        [("tmpl", "a", 1), ("legs", "b", 3)],
        [("legs", "a", 3), ("tmpl", "b", 1)],
        [("adv", 1), ("tmpl", "a", 1)],
        [("adv", 3), ("tmpl", "a", 1), ("tmpl", "b", 1)],
        [("tmpl", "a", 1), ("adv", 2), ("tmpl", "b", 1),
         ("adv", 1), ("tmpl", "c", 1)],
        [("legs", "a", 11), ("adv", 1), ("legs", "a", 11)],
        [("legs", "a", 11), ("adv", 1), ("legs", "b", 11)],
        [("tmpl", "a", 0)],
        [("tmpl", "a", 2)],
        [("tmpl", "a", 1), ("tmpl", "b", 2), ("tmpl", "c", 1)],
        [("tmpl", "a", 1), ("tmpl", "b", 1), ("tmpl", "a", 2)],
        [("legs", "a", 1), ("legs", "b", 1), ("legs", "c", 1),
         ("legs", "d", 1)],
        [("legs", "a", 100), ("tmpl", "b", 1)],
        [("tmpl", "a", 1), ("legs", "b", 100)],
        [("adv", 1), ("adv", 1), ("tmpl", "a", 1)],
        [("tmpl", "a", 1), ("adv", 5), ("tmpl", "b", 1)],
        [("legs", "a", 2), ("adv", 1), ("legs", "b", 2),
         ("adv", 1), ("legs", "c", 2)],
        [("tmpl", "a", 3)],
        [("tmpl", "a", 1), ("tmpl", "b", 3)],
        [("legs", "a", 9999)],
        [("tmpl", "a", 1), ("adv", 1), ("tmpl", "a", 2),
         ("adv", 1), ("tmpl", "a", 3)],
    ]
    assert len(seqs) == 29
    return seqs


SEQUENCES = _sequences()


def total_paths():
    return (len(TEMPLATES) * len(GROSSES) * len(CAP_PROFILES)
            * 7 * len(SEQUENCES))


class ReferenceRule:
    """The settlement bookkeeping, restated from the rules in the
    brief: a settlement id settles once while it is inside the
    kept history window (the book retains the most recent
    MAX_SETTLEMENTS_KEPT ids -- a stage-1 bound this model shares
    as an input constant); each execution's legs must be positive
    and sum to no more than the per-execution cap; a period's
    spend rolls at the period boundary and may not pass the
    period cap."""

    def __init__(self, exec_cap, period_cap):
        self.exec_cap = exec_cap
        self.period_cap = period_cap
        self.period_index = -1
        self.spent = 0
        self.settled = []
        self.paid_total = 0

    def _roll(self, ts):
        idx = (ts - ANCHOR) // SPAN if ts >= ANCHOR else -1
        if idx != self.period_index:
            self.period_index = idx
            self.spent = 0

    def settle(self, sid, legs, ts):
        """(accepted, total) under the reference rules."""
        self._roll(ts)
        amounts = [a for _r, a in legs]
        if not amounts or any(a <= 0 for a in amounts):
            return False, 0
        total = sum(amounts)
        if sid in self.settled:
            return False, 0
        if total > self.exec_cap:
            return False, 0
        if self.spent + total > self.period_cap:
            return False, 0
        self.settled.append(sid)
        if len(self.settled) > MAX_SETTLEMENTS_KEPT:
            del self.settled[: len(self.settled) - MAX_SETTLEMENTS_KEPT]
        self.spent += total
        self.paid_total += total
        return True, total


def _run_path(template, gross, profile, prior_idx, sequence):
    """Run one grid cell on both implementations; return a
    divergence description or None."""
    exec_cap, period_cap = profile
    terms = PayoutTerms(
        owner=OWNER, max_per_execution=exec_cap,
        max_per_period=period_cap, recipients=RECIPIENTS,
        period_kind=periods.PERIOD_WEEK, anchor_ts=ANCHOR,
        sequence_number=1)
    book = PayoutBook()
    book.install(terms)
    ref = ReferenceRule(exec_cap, period_cap)
    ts = ANCHOR
    # "tmpl" ops carry a gross multiplier in the sequence table
    # (the cell's gross scales them); "legs" ops carry raw amounts.
    ops = _prior_ops(prior_idx, exec_cap, period_cap)
    for op in sequence:
        if op[0] == "tmpl":
            ops.append(("tmpl", op[1], op[2] * gross))
        else:
            ops.append(op)
    for op in ops:
        if op[0] == "adv":
            ts += op[1] * SPAN
            continue
        if op[0] == "legs":
            amounts = [op[2]]
        else:
            amounts = _legs_for(template, op[2])
        legs = [(RECIPIENTS[i % len(RECIPIENTS)], a)
                for i, a in enumerate(amounts)]
        want_ok, want_total = ref.settle(op[1], legs, ts)
        if any(a <= 0 for a in amounts):
            # The production composition refuses the whole
            # execution here: legs_from_outputs raises on a
            # non-positive leg before the book is ever consulted.
            got_ok, got_total = False, 0
        else:
            try:
                total = book.check_execution(OWNER, op[1], legs, ts=ts)
                book.settle(OWNER, op[1], total, ts=ts)
                got_ok, got_total = True, total
            except PayoutShapeError:
                got_ok, got_total = False, 0
        if (got_ok, got_total) != (want_ok, want_total):
            return (f"op {op} at ts {ts}: book=({got_ok},{got_total}) "
                    f"ref=({want_ok},{want_total})")
    state = book.get(OWNER)
    # The book stores the spend of the period its last settlement
    # landed in; the reference rolls on every attempt. Compare the
    # spend effective at the final timestamp.
    current_idx = (ts - ANCHOR) // SPAN
    book_spent = (state.spent_in_period
                  if state.period_index == current_idx else 0)
    if (state.settlements != ref.settled
            or book_spent != ref.spent
            or state.paid_total != ref.paid_total):
        return (f"final state: book settlements({len(state.settlements)})"
                f"={state.settlements[:4]}... spent={book_spent} "
                f"paid={state.paid_total}; "
                f"ref settlements({len(ref.settled)})"
                f"={ref.settled[:4]}... spent={ref.spent} "
                f"paid={ref.paid_total}")
    return None


def run_differential(stride=1, limit_paths=None):
    """Run grid cells (every `stride`-th cell in row-major order);
    return (paths_run, total_paths, divergences)."""
    cells = []
    for template in TEMPLATES:
        for gross in GROSSES:
            for profile in CAP_PROFILES:
                for prior_idx in range(7):
                    for seq_idx, sequence in enumerate(SEQUENCES):
                        cells.append(
                            (template, gross, profile, prior_idx,
                             sequence))
    total = len(cells)
    divergences = []
    run = 0
    for i, cell in enumerate(cells):
        if i % stride:
            continue
        run += 1
        if limit_paths is not None and run > limit_paths:
            break
        problem = _run_path(*cell)
        if problem is not None:
            divergences.append((cell[0], cell[1], cell[2], cell[3],
                                problem))
            if len(divergences) >= 10:
                break
    return run, total, divergences
