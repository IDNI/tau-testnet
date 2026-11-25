#!/usr/bin/env python3
"""Differential probe CLI (Bounty 01 stage 2, proof pack item (b)).

Runs the full deterministic grid -- 4 templates x 25 grosses x
6 cap profiles x 7 prior-spend states x 29 operation sequences =
121,800 settlement paths -- against an independent reference
model of the settlement bookkeeping. Exits non-zero on any
divergence. See scripts/payout_probes.py for the method.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from payout_probes import run_differential, total_paths  # noqa: E402


def main():
    run, total, divergences = run_differential(stride=1)
    print(f"differential probe: {run} of {total} paths "
          f"(grid total {total_paths()}), "
          f"{len(divergences)} divergences")
    for div in divergences:
        print("DIVERGENCE:", div)
    if divergences or run != total:
        print("FAIL")
        return 1
    print(f"OK: {total} settlement paths, 0 divergences")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
