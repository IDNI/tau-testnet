import copy

import pytest

import tau_defs
from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    MAX_OPEN_RETRACTABLE_PER_SENDER,
    MAX_OPEN_RETRACTABLE_TOTAL,
    MAX_RELEASE_WINDOW_BLOCKS,
    MAX_RELEASE_WINDOW_SECONDS,
    RetractableBook,
    RetractableEntry,
    validate_park_shape,
)

A = "a" * 96
B = "b" * 96
C = "c" * 96


def pk(n: int) -> str:
    return f"{n:096x}"


def park(sender=A, recipient=B, amount=100, seq=1, kind=KIND_HEIGHT, at=50):
    return RetractableEntry(sender, recipient, amount, seq, kind, at)


def test_lifecycle_park_retract():
    book = RetractableBook()
    e = park()
    rid = book.submit(e)
    assert book.knows(rid) and book.get(rid) == e
    assert book.open_count() == 1 and book.open_count_for_sender(A) == 1
    assert book.retract(rid) == e
    assert not book.knows(rid)
    assert book.open_count() == 0 and book.open_count_for_sender(A) == 0
    assert book.resolved_count == 1


def test_lifecycle_park_release():
    book = RetractableBook()
    e = park(at=10)
    book.submit(e)
    assert book.release_due(10, 0) == [e]
    assert book.open_count() == 0 and book.escrow_total() == 0
    assert book.resolved_count == 1


def test_duplicate_refused():
    book = RetractableBook()
    e = park()
    assert book.can_admit_park(e, 1, 0) == (True, "")
    book.submit(e)
    ok, reason = book.can_admit_park(e, 1, 0)
    assert not ok and "already exists" in reason
    with pytest.raises(ValueError):
        book.submit(e)


def test_per_sender_cap():
    book = RetractableBook()
    for i in range(MAX_OPEN_RETRACTABLE_PER_SENDER):
        book.submit(park(seq=i))
    ok, reason = book.can_admit_park(park(seq=999), 1, 0)
    assert not ok and str(MAX_OPEN_RETRACTABLE_PER_SENDER) in reason
    assert book.can_admit_park(park(sender=C, seq=1), 1, 0)[0]


def test_global_cap():
    book = RetractableBook()
    n = 0
    while book.open_count() < MAX_OPEN_RETRACTABLE_TOTAL:
        book.submit(park(sender=pk(n // MAX_OPEN_RETRACTABLE_PER_SENDER + 1), seq=n))
        n += 1
    ok, reason = book.can_admit_park(park(sender=pk(10**6), seq=1), 1, 0)
    assert not ok and "full" in reason
    book.retract(next(iter(book.open)))
    assert book.can_admit_park(park(sender=pk(10**6), seq=1), 1, 0)[0]


def test_park_shape_bounds():
    assert validate_park_shape(park(amount=0), 1, 0)
    assert validate_park_shape(park(amount=tau_defs.MAX_TRANSFER_VALUE + 1), 1, 0)
    assert validate_park_shape(park(amount=tau_defs.MAX_TRANSFER_VALUE), 1, 0) is None
    assert validate_park_shape(park(at=10), 10, 0)
    assert validate_park_shape(park(at=11), 10, 0) is None
    assert validate_park_shape(park(at=10 + MAX_RELEASE_WINDOW_BLOCKS), 10, 0) is None
    assert validate_park_shape(park(at=11 + MAX_RELEASE_WINDOW_BLOCKS), 10, 0)
    assert validate_park_shape(park(kind=KIND_TIME, at=1000), 1, 1000)
    assert validate_park_shape(park(kind=KIND_TIME, at=1001), 1, 1000) is None
    assert validate_park_shape(
        park(kind=KIND_TIME, at=1000 + MAX_RELEASE_WINDOW_SECONDS), 1, 1000) is None
    assert validate_park_shape(
        park(kind=KIND_TIME, at=1001 + MAX_RELEASE_WINDOW_SECONDS), 1, 1000)
    assert validate_park_shape(park(kind=7), 1, 0)


def test_release_due_height_boundary_and_order():
    book = RetractableBook()
    es = [park(seq=i, at=20) for i in range(5)]
    for e in es:
        book.submit(e)
    assert not book.has_due(19, 0)
    assert book.release_due(19, 0) == []
    assert book.has_due(20, 0)
    out = book.release_due(20, 0)
    assert [e.retractable_id for e in out] == sorted(e.retractable_id for e in es)


def test_release_due_time_boundary_and_kind_independence():
    book = RetractableBook()
    t = park(kind=KIND_TIME, at=5000)
    h = park(seq=2, kind=KIND_HEIGHT, at=50)
    book.submit(t)
    book.submit(h)
    assert book.release_due(49, 4999) == []
    assert not book.has_due(49, 4999)
    assert book.has_due(49, 5000)
    assert book.release_due(49, 5000) == [t]
    assert book.release_due(50, 5000) == [h]


def test_release_due_mixed_kinds_sorted_by_id():
    book = RetractableBook()
    es = [park(seq=i, kind=i % 2, at=10) for i in range(8)]
    for e in es:
        book.submit(e)
    out = book.release_due(10, 10)
    assert len(out) == 8
    ids = [e.retractable_id for e in out]
    assert ids == sorted(ids)


def test_retract_boundary():
    book = RetractableBook()
    e = park(at=30)
    rid = book.submit(e)
    assert book.can_admit_retract(rid, A, 29, 0) == (True, "")
    ok, reason = book.can_admit_retract(rid, A, 30, 0)
    assert not ok and "too late" in reason
    assert not book.can_admit_retract(rid, A, 31, 0)[0]

    t = park(seq=2, kind=KIND_TIME, at=900)
    tid = book.submit(t)
    assert book.can_admit_retract(tid, A, 10**9, 899)[0]
    assert not book.can_admit_retract(tid, A, 0, 900)[0]


def test_retract_rejects_stranger_and_unknown():
    book = RetractableBook()
    rid = book.submit(park())
    ok, reason = book.can_admit_retract(rid, B, 1, 0)
    assert not ok and "sender" in reason
    ok, reason = book.can_admit_retract(b"\x01" * 32, A, 1, 0)
    assert not ok and "unknown" in reason
    book.retract(rid)
    assert not book.can_admit_retract(rid, A, 1, 0)[0]
    with pytest.raises(KeyError):
        book.retract(rid)


def test_deepcopy_isolation():
    book = RetractableBook()
    e = park(at=40)
    rid = book.submit(e)
    root = book.root()
    clone = copy.deepcopy(book)
    assert clone.root() == root

    clone.retract(rid)
    clone.submit(park(seq=9, at=99))
    assert book.root() == root
    assert book.knows(rid) and book.open_count() == 1
    assert book.escrow_total() == e.amount
    assert book.open_count_for_sender(A) == 1
    assert book.resolved_count == 0
    assert book.has_due(40, 0) and not book.has_due(39, 0)

    book.release_due(40, 0)
    assert clone.open_count() == 1 and clone.resolved_count == 1


def test_escrow_totals():
    book = RetractableBook()
    r1 = book.submit(park(sender=A, recipient=B, amount=10, seq=1))
    book.submit(park(sender=A, recipient=C, amount=20, seq=2))
    book.submit(park(sender=B, recipient=A, amount=5, seq=1))
    assert book.escrow_total() == 35
    assert book.escrow_for(A) == 30 and book.escrow_for(B) == 5
    assert book.escrow_to(B) == 10 and book.escrow_to(C) == 20 and book.escrow_to(A) == 5
    book.retract(r1)
    assert book.escrow_total() == 25
    assert book.escrow_for(A) == 20 and book.escrow_to(B) == 0
    assert book.escrow_for(pk(77)) == 0


def test_snapshot_restore_roundtrip_and_bad_id():
    book = RetractableBook()
    for i in range(5):
        book.submit(park(seq=i, kind=i % 2, at=100 + i))
    book.retract(next(iter(book.open)))
    rows = [
        (bytes.fromhex(r["retractable_id"]), r["sender_pubkey"], r["recipient_pubkey"],
         r["amount"], r["sequence_number"], r["release_kind"], r["release_at"])
        for r in book.snapshot_rows()
    ]
    count, acc = book.resolved_state()
    restored = RetractableBook.restore(rows, count, acc)
    assert restored.root() == book.root()
    assert restored.escrow_total() == book.escrow_total()

    bad = list(rows)
    rid, *rest = bad[0]
    bad[0] = (b"\x00" * 32, *rest)
    with pytest.raises(ValueError):
        RetractableBook.restore(bad, count, acc)
    tampered = list(rows)
    tampered[1] = (*rows[1][:3], rows[1][3] + 1, *rows[1][4:])
    with pytest.raises(ValueError):
        RetractableBook.restore(tampered, count, acc)
    with pytest.raises(ValueError):
        RetractableBook.restore(rows + [rows[0]], count, acc)
    with pytest.raises(ValueError):
        RetractableBook.restore(rows, count, b"\x00" * 31)


def test_resolve_changes_count_and_acc_and_outcome_matters():
    a, b = RetractableBook(), RetractableBook()
    ea = park()
    ra, rb = a.submit(ea), b.submit(ea)
    assert a.root() == b.root()
    zero = a.resolved_state()
    a.retract(ra)
    b.release_due(50, 0)
    assert a.resolved_state() != zero and a.resolved_count == 1
    assert a.resolved_state() != b.resolved_state()
    assert a.root() != b.root()


def test_resolution_order_changes_acc():
    es = [park(seq=1, at=10), park(seq=2, at=10)]
    x, y = RetractableBook(), RetractableBook()
    ids = [x.submit(e) for e in es]
    for e in es:
        y.submit(e)
    x.retract(ids[0]); x.retract(ids[1])
    y.retract(ids[1]); y.retract(ids[0])
    assert x.resolved_count == y.resolved_count == 2
    assert x.resolved_acc != y.resolved_acc


def test_root_independent_of_history_size():
    book = RetractableBook()
    for i in range(100_000):
        rid = book.submit(park(sender=pk(i % 5000 + 1), seq=i))
        book.retract(rid)
    assert book.resolved_count == 100_000
    assert book.open_count() == 0
    assert len(book.root()) == 32
    attrs = vars(book)
    for name, value in attrs.items():
        if isinstance(value, (dict, list)):
            assert len(value) <= 2, name
    book.submit(park(seq=10**6))
    clone = copy.deepcopy(book)
    assert clone.root() == book.root()
