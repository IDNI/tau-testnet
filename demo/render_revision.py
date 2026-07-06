#!/usr/bin/env python3
"""Render the stake revision template with a concrete threshold.

Usage: venv/bin/python demo/render_revision.py --stake-threshold 100000 > demo/stake_consensus_revision.tau
"""
import argparse, pathlib, sys

def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--stake-threshold", type=int, required=True)
    p.add_argument("--template", default=str(pathlib.Path(__file__).parent / "stake_consensus_revision.tau.tmpl"))
    a = p.parse_args()
    if not (0 < a.stake_threshold < (1 << 64)):
        raise SystemExit("--stake-threshold must fit bv[64] and be positive")
    text = pathlib.Path(a.template).read_text(encoding="utf-8")
    sys.stdout.write(text.replace("__THRESHOLD__", str(a.stake_threshold)))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
