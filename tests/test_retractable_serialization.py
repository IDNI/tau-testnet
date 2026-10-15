import itertools

import pytest
from blake3 import blake3

from consensus.retractable import KIND_HEIGHT, KIND_TIME, RetractableBook, RetractableEntry
from consensus.serialization import (
    DOMAIN_RETRACTABLE_BOOK_V1,
    DOMAIN_RETRACTABLE_RESOLVED_V1,
    DOMAIN_RETRACTABLE_TRANSFER_V1,
    compute_request_id,
    compute_retractable_book_root,
    compute_retractable_id,
    compute_retractable_resolved_acc,
)

A = "a" * 96
B = "b" * 96
C = "c" * 96
ZERO = bytes(32)


def test_domains_are_distinct():
    assert len({DOMAIN_RETRACTABLE_TRANSFER_V1, DOMAIN_RETRACTABLE_RESOLVED_V1,
                DOMAIN_RETRACTABLE_BOOK_V1}) == 3


def test_pinned_id_vector():
    rid = compute_retractable_id(A, B, 1000, 7, KIND_HEIGHT, 123)
    assert rid.hex() == PINNED_ID


def test_id_accepts_bytes_or_hex():
    assert compute_retractable_id(A, B, 1, 1, 0, 5) == compute_retractable_id(
        bytes.fromhex(A), bytes.fromhex(B), 1, 1, 0, 5)


def test_domain_separation_from_approval_request_id():
    rid = compute_retractable_id(A, B, 1000, 7, KIND_HEIGHT, 123)
    other = compute_request_id(
        sender_pubkey=A, recipient_pubkey=B, amount=1000, sequence_number=7,
        expire_at_height=123, approvers={}, custom_inputs={})
    assert rid != other


@pytest.mark.parametrize("field,value", [
    ("sender", C), ("recipient", C), ("amount", 1001), ("seq", 8),
    ("kind", KIND_TIME), ("release_at", 124),
])
def test_id_commits_to_every_field(field, value):
    base = dict(sender=A, recipient=B, amount=1000, seq=7, kind=KIND_HEIGHT, release_at=123)
    changed = dict(base, **{field: value})
    f = lambda d: compute_retractable_id(d["sender"], d["recipient"], d["amount"],
                                         d["seq"], d["kind"], d["release_at"])
    assert f(base) != f(changed)


def _row(sender=A, recipient=B, amount=10, seq=1, kind=0, at=50):
    rid = compute_retractable_id(sender, recipient, amount, seq, kind, at)
    return (rid, sender, recipient, amount, seq, kind, at)


def test_root_order_independent():
    rows = [_row(seq=i) for i in range(4)]
    roots = {compute_retractable_book_root(list(p), 3, ZERO)
             for p in itertools.permutations(rows)}
    assert len(roots) == 1


@pytest.mark.parametrize("idx", range(1, 7))
def test_root_changes_with_any_open_field(idx):
    base = _row()
    row = list(base)
    row[idx] = {1: C, 2: C, 3: 11, 4: 2, 5: 1, 6: 51}[idx]
    assert compute_retractable_book_root([base], 0, ZERO) != compute_retractable_book_root(
        [tuple(row)], 0, ZERO)


def test_open_to_resolved_changes_root():
    book = RetractableBook()
    rid = book.submit(RetractableEntry(A, B, 10, 1, 0, 50))
    before = book.root()
    book.retract(rid)
    assert book.root() != before
    assert book.root() != compute_retractable_book_root([], 0, ZERO)


def test_root_commits_to_count_and_acc():
    assert compute_retractable_book_root([], 0, ZERO) != compute_retractable_book_root([], 1, ZERO)
    assert compute_retractable_book_root([], 0, ZERO) != compute_retractable_book_root([], 0, b"\x01" * 32)


def test_outcome_affects_acc():
    rid = b"\x05" * 32
    assert compute_retractable_resolved_acc(ZERO, rid, 1) != compute_retractable_resolved_acc(ZERO, rid, 2)
    first = compute_retractable_resolved_acc(ZERO, rid, 1)
    assert compute_retractable_resolved_acc(first, rid, 1) != first


def test_empty_root_is_stable():
    assert compute_retractable_book_root([], 0, ZERO) == RetractableBook().root()


PINNED_ID = "738b9a6a65fc4db92881ae13b8b774fd9f2019d9baee8c214e3a92fefd7ecd6e"
