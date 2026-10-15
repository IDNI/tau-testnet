#!/usr/bin/env python3
"""Timings for the retractable book at its frozen caps. Prints; asserts nothing."""
import copy
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consensus.retractable import (  # noqa: E402
    KIND_HEIGHT,
    MAX_OPEN_RETRACTABLE_PER_SENDER,
    MAX_OPEN_RETRACTABLE_TOTAL,
    RetractableBook,
    RetractableEntry,
)


def pk(n: int) -> str:
    return f"{n:096x}"


def fill(release_at, count=MAX_OPEN_RETRACTABLE_TOTAL) -> RetractableBook:
    book = RetractableBook()
    for i in range(count):
        sender = pk(i // MAX_OPEN_RETRACTABLE_PER_SENDER + 1)
        book.submit(RetractableEntry(sender, pk(10**6 + i), 10, i, KIND_HEIGHT, release_at(i)))
    return book


def timed(label, fn, repeat=1):
    start = time.perf_counter()
    for _ in range(repeat):
        out = fn()
    ms = (time.perf_counter() - start) * 1000 / repeat
    print(f"{label:<58}{ms:10.3f} ms")
    return out


def main() -> None:
    print("-- 4096 open, nothing due")
    book = fill(lambda i: 1_000_000 + i)
    timed("root() cold", lambda: (setattr(book, "_root", None), book.root()))
    timed("root() cached", book.root, repeat=1000)
    timed("deepcopy", lambda: copy.deepcopy(book), repeat=20)
    timed("release_due (nothing)", lambda: book.release_due(10, 0), repeat=1000)

    print("-- 4096 maturing in one height")
    book = fill(lambda i: 500)
    timed("deepcopy", lambda: copy.deepcopy(book), repeat=20)
    timed("release_due (all 4096)", lambda: book.release_due(500, 0))
    timed("root() after release", book.root)

    print("-- after 100k resolutions")
    book = RetractableBook()
    for i in range(100_000):
        rid = book.submit(RetractableEntry(pk(i % 5000 + 1), pk(7), 1, i, KIND_HEIGHT, 10))
        book.retract(rid)
    book.submit(RetractableEntry(pk(1), pk(7), 1, 10**6, KIND_HEIGHT, 10))
    timed("root() cold", lambda: (setattr(book, "_root", None), book.root()), repeat=100)
    timed("deepcopy", lambda: copy.deepcopy(book), repeat=1000)
    timed("deepcopy + release_due (one due)", lambda: copy.deepcopy(book).release_due(10, 0), repeat=1000)


if __name__ == "__main__":
    main()
