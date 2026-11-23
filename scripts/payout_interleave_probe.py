#!/usr/bin/env python3
"""Interleave probe CLI (Bounty 01 stage 2, proof pack item (a)).

Steps ONE evaluator session 25,000 times with the shipped payout
clauses interleaved among unrelated rules, the session answering
by parsing the clause texts and the reference answering from an
independent share table. Exits non-zero unless every answer is
right. See scripts/payout_probes.py for the method.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from payout_probes import run_interleave  # noqa: E402


def main():
    steps, wrong = run_interleave(25_000)
    print(f"interleave probe: {steps} steps, {wrong} wrong answers")
    if steps != 25_000 or wrong != 0:
        print("FAIL")
        return 1
    print("OK: 25,000 steps, 0 wrong answers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
