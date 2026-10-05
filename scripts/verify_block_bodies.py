#!/usr/bin/env python3
"""Read-only scan of a node database for blocks whose body does not match their header.

    python scripts/verify_block_bodies.py data/node.db   # exits 1 if any block fails
"""
import argparse
import json
import sqlite3
import sys
from pathlib import Path

# Ensure we can import from the main project
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from block import Block


def _check_row(row_hash, block_data):
    """The reason a stored block is unsound, or None if it is sound."""
    try:
        block = Block.from_dict(json.loads(block_data))
    except Exception as exc:
        return str(exc) or type(exc).__name__
    if block.block_hash != row_hash:
        return f"row is stored under {row_hash} but holds block {block.block_hash}"
    return None


def get_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("db_path", help="Path to the node's SQLite database")
    return parser.parse_args(argv)


def main(argv=None):
    args = get_args(argv)
    uri = Path(args.db_path).resolve().as_uri() + "?mode=ro"
    scanned = 0
    failed = 0
    try:
        conn = sqlite3.connect(uri, uri=True)
        try:
            rows = conn.execute(
                "SELECT block_hash, block_number, block_data FROM blocks "
                "ORDER BY block_number, block_hash"
            )
            for row_hash, block_number, block_data in rows:
                scanned += 1
                reason = _check_row(row_hash, block_data)
                if reason is not None:
                    failed += 1
                    print(f"block #{block_number} {str(row_hash)[:16]}...: {reason}")
        finally:
            conn.close()
    except sqlite3.Error as exc:
        print(f"cannot read {args.db_path}: {exc}", file=sys.stderr)
        return 1

    print(f"scanned {scanned} block(s): {scanned - failed} ok, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
