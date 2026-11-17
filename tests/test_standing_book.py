"""The standing-payment book on its own: schedule, sweep, limits, commitments.

Every test drives `StandingBook.sweep` with a scripted `attempt`, so what is
checked here is the book's bookkeeping (which period is settled when, what is
retried, what ends) independent of balances and policies, which the apply tests
cover.
"""
import copy
import datetime
import random

import pytest

import consensus.standing as standing
from consensus.standing import (
    ATTEMPT_BLOCKED,
    ATTEMPT_NO_FUNDS,
    ATTEMPT_PAID,
    KIND_BLOCKS,
    KIND_MONTHS,
    KIND_SECONDS,
    MAX_OPEN_STANDING_PER_PAYER,
    MAX_OPEN_STANDING_TOTAL,
    MAX_STANDING_ACTIONS_PER_BLOCK,
    MIN_INTERVAL_BLOCKS,
    MIN_INTERVAL_SECONDS,
    StandingBook,
    StandingShapeError,
    StandingTerms,
    add_months,
    parse_standing_payment_cancel,
    parse_standing_payment_create,
    validate_create_shape,
)

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
H = 1_000
TS = 1_767_225_600  # 2026-01-01T00:00:00Z


def utc(*args) -> int:
    return int(datetime.datetime(*args, tzinfo=datetime.timezone.utc).timestamp())


def blocks(seq=0, amount=10, interval=MIN_INTERVAL_BLOCKS, first_due=H + 10,
           periods=3, payer=A, recipient=B):
    return StandingTerms(payer, recipient, amount, seq, KIND_BLOCKS, interval,
                         first_due, periods)


def monthly(seq=0, amount=10, first_due=utc(2026, 1, 31, 9), periods=12, interval=1):
    return StandingTerms(A, B, amount, seq, KIND_MONTHS, interval, first_due, periods)


class Script:
    """attempt() that answers from a per-call list, recording what it was asked."""

    def __init__(self, default=ATTEMPT_PAID):
        self.default = default
        self.queue = []
        self.calls = []

    def __call__(self, terms):
        self.calls.append(terms.standing_id)
        return self.queue.pop(0) if self.queue else self.default


def outcomes(events, sid=None):
    return [(e["outcome"], e["period"]) for e in events
            if sid is None or e["standing_id"] == sid.hex()]


# --- calendar -----------------------------------------------------------------

def test_add_months_matches_the_standard_library_everywhere():
    rng = random.Random(7)
    for _ in range(5_000):
        ts = rng.randint(0, utc(9000, 1, 1))
        k = rng.randint(0, 600)
        d = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        total = d.month - 1 + k
        year, month = d.year + total // 12, total % 12 + 1
        last = (datetime.date(year + month // 12, month % 12 + 1, 1)
                - datetime.timedelta(days=1)).day
        expected = utc(year, month, min(d.day, last), d.hour, d.minute, d.second)
        assert add_months(ts, k) == expected


def test_the_31st_becomes_the_last_day_and_comes_back_without_drift():
    t = monthly(first_due=utc(2026, 1, 31, 9))
    assert [t.due(p) for p in range(5)] == [
        utc(2026, 1, 31, 9), utc(2026, 2, 28, 9), utc(2026, 3, 31, 9),
        utc(2026, 4, 30, 9), utc(2026, 5, 31, 9),
    ]
    leap = monthly(first_due=utc(2027, 12, 31))
    assert leap.due(2) == utc(2028, 2, 29)


def test_period_at_finds_the_window_holding_a_block():
    t = monthly(first_due=utc(2026, 1, 31), periods=3)
    assert t.period_at(0, utc(2026, 1, 30)) == -1
    assert t.period_at(0, utc(2026, 1, 31)) == 0
    assert t.period_at(0, utc(2026, 2, 27, 23, 59, 59)) == 0
    assert t.period_at(0, utc(2026, 2, 28)) == 1
    assert t.period_at(0, utc(2026, 4, 30)) == 3      # the end
    assert t.period_at(0, utc(2031, 1, 1)) == 3       # capped
    b = blocks(first_due=100, interval=128, periods=4)
    assert [b.period_at(h, 0) for h in (99, 100, 227, 228, 612, 9_999)] == [-1, 0, 0, 1, 4, 4]


# --- parsing and shape ----------------------------------------------------------

def _create(**over):
    tx = {"tx_type": "standing_payment_create", "sender_pubkey": A, "sequence_number": 4,
          "recipient_pubkey": B, "amount": 25, "interval_months": 1,
          "first_due": TS + 3_600, "periods": 12}
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def test_parse_reads_root_fields_only():
    terms = parse_standing_payment_create(_create(payload={"amount": 999}))
    assert (terms.payer_pubkey, terms.recipient_pubkey, terms.amount, terms.kind,
            terms.interval, terms.periods) == (A, B, 25, KIND_MONTHS, 1, 12)


@pytest.mark.parametrize("over,match", [
    ({"interval_months": None}, "exactly one of"),
    ({"interval_blocks": 200}, "exactly one of"),
    ({"amount": -1}, "amount"),
    ({"amount": True}, "amount"),
    ({"amount": "25"}, "amount"),
    ({"recipient_pubkey": "BB" * 48}, "recipient_pubkey"),
    ({"first_due": None}, "first_due"),
    ({"periods": 1 << 32}, "periods"),
])
def test_parse_refuses_malformed_creates(over, match):
    with pytest.raises(StandingShapeError, match=match):
        parse_standing_payment_create(_create(**over))


def test_parse_cancel_needs_a_lowercase_hex_id():
    tx = {"sender_pubkey": A, "standing_id": "ab" * 32}
    assert parse_standing_payment_cancel(tx) == (A, bytes.fromhex("ab" * 32))
    with pytest.raises(StandingShapeError):
        parse_standing_payment_cancel({"sender_pubkey": A, "standing_id": "AB" * 32})


@pytest.mark.parametrize("terms,match", [
    (blocks(amount=0), "amount"),
    (blocks(recipient=A), "recipient must differ"),
    (blocks(periods=0), "periods"),
    (blocks(periods=standing.MAX_PERIODS + 1), "periods"),
    (blocks(interval=MIN_INTERVAL_BLOCKS - 1), "interval_blocks"),
    (blocks(first_due=H), "future"),
    (blocks(first_due=H + standing.MAX_FIRST_DUE_BLOCKS + 1), "ahead"),
    (StandingTerms(A, B, 1, 0, KIND_SECONDS, MIN_INTERVAL_SECONDS - 1, TS + 10, 1), "interval_seconds"),
    (StandingTerms(A, B, 1, 0, KIND_MONTHS, 13, TS + 10, 1), "interval_months"),
    (StandingTerms(A, B, 1, 0, KIND_MONTHS, 0, TS + 10, 1), "interval_months"),
    (StandingTerms(A, B, 1, 0, 7, 1, TS + 10, 1), "unknown schedule kind"),
])
def test_shape_refusals(terms, match):
    assert match in (validate_create_shape(terms, H, TS) or "")


def test_shape_accepts_a_year_of_monthly_rent():
    assert validate_create_shape(monthly(first_due=TS + 60), H, TS) is None


def test_the_id_commits_to_every_term():
    base = blocks()
    variants = [
        blocks(seq=1), blocks(amount=11), blocks(interval=129), blocks(first_due=H + 11),
        blocks(periods=4), blocks(recipient=C), blocks(payer=C),
        StandingTerms(A, B, 10, 0, KIND_SECONDS, MIN_INTERVAL_BLOCKS, H + 10, 3),
    ]
    ids = {t.standing_id for t in variants}
    assert len(ids) == len(variants) and base.standing_id not in ids


# --- the sweep --------------------------------------------------------------------

def test_one_payment_per_period_and_nothing_before_the_due_point():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10, interval=128, periods=3))
    script = Script()
    assert book.sweep(H + 9, TS, script) == []
    assert outcomes(book.sweep(H + 10, TS, script)) == [("paid", 0)]
    for h in range(H + 11, H + 138):
        assert book.sweep(h, TS, script) == [], h
    assert outcomes(book.sweep(H + 138, TS, script)) == [("paid", 1)]
    assert outcomes(book.sweep(H + 266, TS, script)) == [("paid", 2), ("ended", 3)]
    assert not book.knows(sid) and book.resolved_count == 1
    assert len(script.calls) == 3


def test_no_catch_up_after_a_long_gap():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10, interval=128, periods=6))
    script = Script()
    # The chain was idle: the first block after the due point is 3 periods later.
    events = book.sweep(H + 10 + 3 * 128 + 5, TS, script)
    assert outcomes(events) == [("missed", 0), ("paid", 3)]
    assert events[0]["count"] == 3 and events[0]["reason"] == "window_closed"
    assert len(script.calls) == 1
    p = book.progress[sid]
    assert (p.period, p.paid_count, p.missed_count) == (4, 1, 3)


def test_an_unfunded_period_is_retried_in_its_window_then_missed():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10, interval=128, periods=2))
    script = Script(default=ATTEMPT_NO_FUNDS)
    assert outcomes(book.sweep(H + 10, TS, script)) == [("unfunded", 0)]
    assert outcomes(book.sweep(H + 11, TS, script)) == [("unfunded", 0)]
    assert book.progress[sid].tries == 2
    script.default = ATTEMPT_PAID
    assert outcomes(book.sweep(H + 12, TS, script)) == [("paid", 0)]
    assert book.progress[sid].tries == 0
    # Period 1: never funded; its window closes at the end of the schedule.
    script.default = ATTEMPT_NO_FUNDS
    book.sweep(H + 138, TS, script)
    events = book.sweep(H + 266, TS, script)
    assert outcomes(events) == [("missed", 1), ("ended", 2)]
    assert not book.knows(sid)


def test_a_retry_runs_at_most_once_per_block():
    book = StandingBook()
    book.create(blocks(first_due=H + 10))
    script = Script(default=ATTEMPT_NO_FUNDS)
    for h in range(H + 10, H + 20):
        book.sweep(h, TS, script)
    assert len(script.calls) == 10


def test_a_policy_block_misses_the_period_without_retrying():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10, interval=128, periods=2))
    script = Script(default=ATTEMPT_BLOCKED)
    assert script.calls == [] and book.knows(sid)
    events = book.sweep(H + 10, TS, script)
    assert outcomes(events) == [("missed", 0)] and events[0]["reason"] == "policy_block"
    for h in range(H + 11, H + 138):
        book.sweep(h, TS, script)
    assert len(script.calls) == 1
    script.default = ATTEMPT_PAID
    assert outcomes(book.sweep(H + 138, TS, script)) == [("paid", 1), ("ended", 2)]
    assert book.resolved_count == 1


def test_cancel_removes_an_entry_wherever_it_is():
    book = StandingBook()
    waiting = book.create(blocks(seq=0))
    queued = book.create(blocks(seq=1))
    retrying = book.create(blocks(seq=2))
    script = Script(default=ATTEMPT_NO_FUNDS)
    book.sweep(H + 10, TS, script, cap=1)          # seq order decides who is tried
    tried = script.calls[0]
    assert book.progress[tried].tries == 1
    for sid in (waiting, queued, retrying):
        book.cancel(sid)
    assert not book.terms and not book._queue and book._fresh == 0
    assert not any(book._waiting.values()) and book.resolved_count == 3
    assert book.sweep(H + 500, TS, script) == []


def test_the_cap_carries_over_oldest_first_and_reaches_everyone():
    book = StandingBook()
    payers = [f"{i:02x}" * 48 for i in range(1, 6)]
    sids = [book.create(StandingTerms(p, B, 1, s, KIND_BLOCKS, 128, H + 10, 1))
            for p in payers for s in range(4)]
    script = Script()
    seen = []
    h = H + 10
    while book.terms:
        events = book.sweep(h, TS, script, cap=3)
        paid = [e["standing_id"] for e in events if e["outcome"] == "paid"]
        assert len(paid) <= 3
        seen.extend(paid)
        h += 1
    assert sorted(seen) == sorted(s.hex() for s in sids)
    assert h - (H + 10) == -(-len(sids) // 3)


def test_fresh_dues_are_not_starved_by_retries():
    book = StandingBook()
    poor = [book.create(blocks(seq=s, payer=A)) for s in range(4)]
    rich = book.create(blocks(seq=0, payer=C, first_due=H + 11))

    def attempt(terms):
        return ATTEMPT_PAID if terms.payer_pubkey == C else ATTEMPT_NO_FUNDS

    book.sweep(H + 10, TS, attempt, cap=2)   # two of the poor ones tried
    waited, h = 0, H + 11
    while book.progress[rich].paid_count == 0:
        book.sweep(h, TS, attempt, cap=2)
        waited, h = waited + 1, h + 1
    # Unfunded retries go to the back of the queue, so the fresh entry is
    # reached within ceil(queue length / cap) blocks of becoming due.
    assert waited <= -(-len(book.terms) // 2)
    assert all(book.progress[s].tries >= 1 for s in poor)


def test_has_due_ignores_retries_so_an_idle_chain_sleeps():
    book = StandingBook()
    book.create(blocks(first_due=H + 10))
    assert not book.has_due(H + 9, TS)
    assert book.has_due(H + 10, TS)
    book.sweep(H + 10, TS, Script(default=ATTEMPT_NO_FUNDS))
    assert not book.has_due(H + 11, TS)
    book.create(blocks(seq=1, first_due=H + 20))
    book.create(blocks(seq=2, first_due=H + 20))
    book.sweep(H + 20, TS, Script(default=ATTEMPT_NO_FUNDS), cap=1)
    assert book.has_due(H + 21, TS)  # one fresh entry was held back by the cap


def test_time_and_month_schedules_read_the_block_timestamp():
    book = StandingBook()
    sid = book.create(monthly(first_due=utc(2026, 1, 31, 9), periods=2))
    script = Script()
    assert book.sweep(10_000, utc(2026, 1, 31, 8, 59, 59), script) == []
    assert outcomes(book.sweep(1, utc(2026, 1, 31, 9), script)) == [("paid", 0)]
    assert book.sweep(2, utc(2026, 2, 27, 23), script) == []
    assert outcomes(book.sweep(3, utc(2026, 2, 28, 9), script)) == [("paid", 1), ("ended", 2)]
    assert not book.knows(sid)


# --- copies, roots and restore ---------------------------------------------------

def _busy_book():
    book = StandingBook()
    book.create(blocks(seq=0))
    book.create(blocks(seq=1, periods=1))
    book.create(monthly(seq=2))
    book.create(blocks(seq=3, payer=C))
    book.sweep(H + 10, utc(2026, 1, 31, 9), Script(default=ATTEMPT_NO_FUNDS), cap=2)
    book.sweep(H + 11, utc(2026, 1, 31, 9), Script(), cap=2)
    return book


def test_a_copy_is_isolated_from_its_original():
    book = _busy_book()
    root = book.root()
    clone = copy.deepcopy(book)
    clone.sweep(H + 12, utc(2026, 1, 31, 9), Script())
    clone.cancel(next(iter(clone.terms)))
    assert book.root() == root
    assert clone.root() != root


def test_every_progress_field_moves_the_root():
    book = _busy_book()
    sid = next(iter(book.terms))
    base = book.root()
    for field in ("paid_count", "missed_count", "tries", "queued_at", "last_paid_height"):
        clone = copy.deepcopy(book)
        p = clone.progress[sid]
        clone.progress[sid] = standing.replace(p, **{field: getattr(p, field) + 1})
        clone._root = None
        assert clone.root() != base, field


def test_restore_round_trips_the_root_and_the_queue():
    book = _busy_book()
    count, acc = book.resolved_state()
    again = StandingBook.restore(book.rows(), count, acc)
    assert again.root() == book.root()
    assert again._queue == book._queue and again._waiting == book._waiting
    assert again._fresh == book._fresh and again._per_payer == book._per_payer
    a, b = Script(), Script()
    assert book.sweep(H + 12, utc(2026, 1, 31, 10), a) == \
        again.sweep(H + 12, utc(2026, 1, 31, 10), b)
    assert book.root() == again.root()


@pytest.mark.parametrize("index,value,match", [
    (3, 11, "does not match"),            # amount
    (9, 2, "inconsistent"),               # period without paid/missed to show for it
    (12, 1, "inconsistent"),              # tries while waiting
    (5, 9, "unknown kind"),
    (6, 0, "bad schedule"),
])
def test_restore_refuses_rows_the_sweep_could_not_have_written(index, value, match):
    book = StandingBook()
    book.create(blocks())
    row = list(book.rows()[0])
    row[index] = value
    with pytest.raises(ValueError, match=match):
        StandingBook.restore([tuple(row)], 0, bytes(32))


def test_is_empty_until_the_book_holds_something_and_after():
    book = StandingBook()
    assert book.is_empty()
    sid = book.create(blocks())
    assert not book.is_empty()
    book.cancel(sid)
    assert not book.is_empty()  # the resolved history keeps it in the hash


# --- admission limits -----------------------------------------------------------

def test_per_payer_and_total_limits():
    book = StandingBook()
    for s in range(MAX_OPEN_STANDING_PER_PAYER):
        book.create(blocks(seq=s))
    ok, reason = book.can_admit_create(blocks(seq=99), H, TS)
    assert not ok and "16 open" in reason
    ok, reason = book.can_admit_create(blocks(seq=0), H, TS)
    assert not ok and "already exists" in reason


def test_a_full_book_refuses_new_payers(monkeypatch):
    monkeypatch.setattr(standing, "MAX_OPEN_STANDING_TOTAL", 3)
    book = StandingBook()
    for i in range(3):
        book.create(blocks(payer=f"{i + 1:02x}" * 48))
    ok, reason = book.can_admit_create(blocks(payer=C), H, TS)
    assert not ok and "full" in reason


def test_only_the_payer_cancels():
    book = StandingBook()
    sid = book.create(blocks())
    assert book.can_admit_cancel(sid, B) == (False, "only the payer may cancel")
    assert book.can_admit_cancel(bytes(32), A)[0] is False
    assert book.can_admit_cancel(sid, A) == (True, "")


def test_the_fairness_bound_is_a_module_invariant():
    assert MIN_INTERVAL_BLOCKS * MAX_STANDING_ACTIONS_PER_BLOCK >= MAX_OPEN_STANDING_TOTAL


# --- execute and update ------------------------------------------------------------

def test_payable_period_is_the_window_holding_the_block_while_it_is_unsettled():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10, periods=2))
    every = MIN_INTERVAL_BLOCKS
    assert book.payable_period(sid, H + 9, TS)[0] == -1
    assert "not due yet" in book.payable_period(sid, H + 9, TS)[1]
    assert book.payable_period(sid, H + 10, TS) == (0, "")
    assert book.payable_period(sid, H + 10 + every - 1, TS) == (0, "")
    assert book.payable_period(sid, H + 10 + every, TS) == (1, "")
    assert book.payable_period(sid, H + 10 + 2 * every, TS)[1] == "the schedule has ended"
    assert "unknown" in book.payable_period(b"\x00" * 32, H + 10, TS)[1]
    book.execute(sid, H + 10, TS, C)
    period, why = book.payable_period(sid, H + 11, TS)
    assert period == -1 and "period 0 is already settled" in why


def test_execute_settles_like_the_sweep_and_leaves_the_entry_waiting():
    by_execute, by_sweep = StandingBook(), StandingBook()
    sid = by_execute.create(blocks(first_due=H + 10, periods=3))
    by_sweep.create(blocks(first_due=H + 10, periods=3))
    events = by_execute.execute(sid, H + 10, TS, C)
    assert outcomes(events) == [("paid", 0)] and events[0]["executor_pubkey"] == C
    swept = by_sweep.sweep(H + 10, TS, Script())
    assert outcomes(swept) == [("paid", 0)]
    assert by_execute.progress[sid] == by_sweep.progress[sid]
    assert by_execute._waiting == by_sweep._waiting and not by_execute._queue
    assert by_execute.root() == by_sweep.root()
    # The sweep of the same block has nothing left to do.
    assert by_execute.sweep(H + 10, TS, Script()) == []


def test_execute_takes_an_entry_out_of_the_retry_line():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10))
    book.sweep(H + 10, TS, Script(default=ATTEMPT_NO_FUNDS))
    assert book.describe(sid)["status"] == "retrying" and book._fresh == 0
    book.execute(sid, H + 11, TS, C)
    assert not book._queue and book.progress[sid].tries == 0
    assert book.describe(sid)["status"] == "waiting"


def test_execute_after_a_closed_window_misses_the_old_period_first():
    book = StandingBook()
    every = MIN_INTERVAL_BLOCKS
    sid = book.create(blocks(first_due=H + 10, periods=4))
    events = book.execute(sid, H + 10 + 2 * every, TS, C)
    assert [(e["outcome"], e["period"], e.get("count")) for e in events] == \
        [("missed", 0, 2), ("paid", 2, None)]
    p = book.progress[sid]
    assert (p.period, p.paid_count, p.missed_count) == (3, 1, 2)


def test_executing_the_last_period_ends_the_entry():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10, periods=1))
    events = book.execute(sid, H + 10, TS, C)
    assert outcomes(events) == [("paid", 0), ("ended", 1)]
    assert not book.knows(sid) and book.resolved_count == 1


def test_execute_refuses_what_payable_period_refuses():
    book = StandingBook()
    sid = book.create(blocks(first_due=H + 10))
    with pytest.raises(ValueError, match="not due yet"):
        book.execute(sid, H + 9, TS, C)
    root = book.root()
    book.execute(sid, H + 10, TS, C)
    with pytest.raises(ValueError, match="already settled"):
        book.execute(sid, H + 11, TS, C)
    assert book.root() != root


def test_update_resolves_the_old_version_and_inserts_the_next_one():
    book = StandingBook()
    old = book.create(blocks(seq=0, amount=10))
    new_terms = blocks(seq=1, amount=12)
    ok, why = book.can_admit_update(old, A, new_terms, H, TS)
    assert ok, why
    new, events = book.update(old, new_terms)
    assert new == new_terms.standing_id != old
    assert [(e["standing_id"], e["outcome"]) for e in events] == \
        [(old.hex(), "replaced"), (new.hex(), "created")]
    assert events[1]["version"] == 2 and events[1]["replaces"] == old.hex()
    assert book.version_of(new) == (2, old) and not book.knows(old)
    assert book.open_count_for_payer(A) == 1
    assert book.resolved_acc == standing.compute_standing_resolved_acc(
        bytes(32), old, standing.OUTCOME_REPLACED)
    row = book.describe(new)
    assert (row["version"], row["replaces"]) == (2, old.hex())
    assert book.describe(book.create(blocks(seq=5)))["replaces"] is None


@pytest.mark.parametrize("signer,terms,match", [
    (C, blocks(seq=1, payer=C), "only the payer"),
    (A, blocks(seq=1, payer=C), "only the payer"),
    (A, blocks(seq=1, first_due=H), "first_due must be in the future"),
    (A, blocks(seq=1, recipient=A), "recipient must differ"),
    (A, blocks(seq=0), "already exists"),
])
def test_update_refusals(signer, terms, match):
    book = StandingBook()
    old = book.create(blocks(seq=0))
    ok, why = book.can_admit_update(old, signer, terms, H, TS)
    assert not ok and match in why


def test_update_of_an_unknown_entry_is_refused():
    ok, why = StandingBook().can_admit_update(b"\x01" * 32, A, blocks(seq=1), H, TS)
    assert not ok and "unknown" in why


def test_the_lineage_is_committed_copied_and_restored():
    book = StandingBook()
    old = book.create(blocks(seq=0))
    new, _ = book.update(old, blocks(seq=1, amount=11))
    plain = StandingBook()
    plain.create(blocks(seq=1, amount=11))
    plain.resolved_count, plain.resolved_acc = book.resolved_count, book.resolved_acc
    plain._root = None
    # Same terms, same progress, same resolved state: only the lineage differs.
    assert plain.root() != book.root()
    clone = copy.deepcopy(book)
    assert clone.version_of(new) == (2, old)
    clone.cancel(new)
    assert book.version_of(new) == (2, old) and clone.lineage == {}
    count, acc = book.resolved_state()
    again = StandingBook.restore(book.rows(), count, acc)
    assert again.root() == book.root() and again.version_of(new) == (2, old)


@pytest.mark.parametrize("version,replaces,match", [
    (2, bytes(32), "bad version"),        # a later version replaces something
    (1, b"\x07" * 32, "bad version"),     # a first version replaces nothing
    (0, bytes(32), "bad version"),
    (2, b"\x07" * 31, "bad version"),
])
def test_restore_refuses_a_lineage_an_update_could_not_have_written(version, replaces, match):
    book = StandingBook()
    book.create(blocks())
    row = list(book.rows()[0])
    row[15], row[16] = version, replaces
    with pytest.raises(ValueError, match=match):
        StandingBook.restore([tuple(row)], 0, bytes(32))


def test_restore_refuses_an_entry_that_replaces_itself():
    book = StandingBook()
    sid = book.create(blocks())
    row = list(book.rows()[0])
    row[15], row[16] = 2, sid
    with pytest.raises(ValueError, match="bad version"):
        StandingBook.restore([tuple(row)], 0, bytes(32))


def test_parse_execute_and_update_read_root_fields_only():
    execute = {"sender_pubkey": C, "standing_id": "ab" * 32,
               "payload": {"standing_id": "cd" * 32}}
    assert standing.parse_standing_payment_execute(execute) == (C, bytes.fromhex("ab" * 32))
    with pytest.raises(StandingShapeError, match="standing_id"):
        standing.parse_standing_payment_execute({"sender_pubkey": C, "standing_id": "AB" * 32})
    update = {"sender_pubkey": A, "sequence_number": 4, "recipient_pubkey": B, "amount": 5,
              "interval_blocks": MIN_INTERVAL_BLOCKS, "first_due": H + 10, "periods": 2,
              "standing_id": "ef" * 32}
    sid, terms = standing.parse_standing_payment_update(update)
    assert sid == bytes.fromhex("ef" * 32) and terms == parse_standing_payment_create(update)
    with pytest.raises(StandingShapeError, match="standing_id"):
        standing.parse_standing_payment_update({**update, "standing_id": None})
