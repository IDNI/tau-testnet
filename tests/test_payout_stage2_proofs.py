"""Payout stage 2, proof pack (Bounty 01, F7): the two measured
claims of the stage-2 entry, as tests.

(a) Interleave: one evaluator session stepped the full 25,000
    steps, payout clauses interleaved with unrelated rules, the
    session answering by parsing the shipped clause texts and the
    reference answering from an independent share table --
    0 wrong answers required.

(b) Differential: an independent reference model of the
    settlement bookkeeping against PayoutBook over a grid of
    121,800 settlement paths. The full grid runs in
    scripts/payout_differential_probe.py; here a strided subset
    runs (every 25th cell) and the grid size itself is asserted.

Method and grid definition: scripts/payout_probes.py.
"""

import importlib.util
import os

_PROBES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "scripts", "payout_probes.py")
_spec = importlib.util.spec_from_file_location(
    "payout_probes", _PROBES_PATH)
probes = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(probes)


def test_interleave_25000_steps_zero_wrong_answers():
    steps, wrong = probes.run_interleave(25_000)
    assert steps == 25_000
    assert wrong == 0


def test_differential_grid_exceeds_119145_paths_and_agrees():
    assert probes.total_paths() >= 119_145
    run, total, divergences = probes.run_differential(stride=25)
    assert total == probes.total_paths()
    assert run > 4_000
    assert divergences == []
