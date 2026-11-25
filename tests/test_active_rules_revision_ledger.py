"""Issue #42 (B02-7): the revision ledger -- closing the §6.7 bound.

B02-6 measured and pinned, as an honest bound, that the module-level
`consensus.active_rules.survival_ledger()` always read [] on this
line: the apply path records each rule step's revision receipt --
`spec_revision_before` / `spec_revision_after` included -- verbatim in
`rule_outcomes`, but `db.list_rule_outcomes()` never lifted the
interval out of the stored JSON, so the ledger's filter discarded
every row.

B02-7 closes that gap at the accessor seam:

  * `db.list_rule_outcomes()` projects the RECORDED interval out of
    the stored receipt, plus the recorded outcome name and a
    per-record `revision_status` (RECORDED / UNAVAILABLE / TAMPERED,
    the §6.6 explicit-code discipline);
  * `survival_ledger()` derives units from RECORDED rows only, and
    `survival_ledger_with_status()` classifies an empty result
    (NOT_FOUND / TAMPERED / UNAVAILABLE).

Numbers are never fabricated: a record that stored no interval (a
clause-registry record, a receipt whose counter was unreadable, a row
written before the fields existed) reads back with None revisions and
an explicit status, and never enters the ledger.

The records below are written through `db.record_rule_outcomes` in
exactly the shapes the apply path stores (revision receipt dicts and
registry record dicts), over hand-recorded spec snapshots -- the same
mock discipline as tests/test_active_rules_journal_cut.py.
"""
import db
from consensus import active_rules

TEXT_A = "always ( o26[t]:bv[24] = { #x000007 }:bv[24] && o27[t]:bv[24] = { #x000009 }:bv[24] )."
TEXT_AB = "always ( o26[t]:bv[24] = { #x000003 }:bv[24] && o27[t]:bv[24] = { #x000009 }:bv[24] )."

TX_A1 = "a1" * 16
TX_B1 = "b1" * 16
TX_A2 = "a2" * 16


def _receipt(before, after, outcome="ACCEPTED_CHANGED"):
    """A revision receipt in the shape tau_native builds at apply."""
    return {
        "outcome": outcome,
        "accepted": outcome.startswith("ACCEPTED"),
        "changed": outcome == "ACCEPTED_CHANGED",
        "delivered": True,
        "outputs": {"o0": "F"},
        "spec_revision_before": before,
        "spec_revision_after": after,
    }


def _record(block, tx, outcome):
    db.record_rule_outcomes(f"{block:064x}", block, [(tx, outcome)])


def _snapshot(revision, height, text):
    db.record_spec_snapshot(
        revision, height, text, active_rules.spec_hash_of(text))


def _record_resend_a_b_a():
    _snapshot(1, 1, TEXT_A)
    _snapshot(2, 2, TEXT_AB)
    _snapshot(3, 3, TEXT_A)
    _record(1, TX_A1, _receipt(0, 1))
    _record(2, TX_B1, _receipt(1, 2))
    _record(3, TX_A2, _receipt(2, 3))


# --- (i) one rule transaction records its revision pair --------------------

def test_single_rule_tx_records_its_revision_pair(temp_database):
    """One confirmed rule step: the stored receipt's pair (0 -> 1) is
    what the accessor returns and what the ledger's single unit
    carries -- the numbers the engine recorded, read back."""
    _snapshot(1, 1, TEXT_A)
    _record(1, TX_A1, _receipt(0, 1))

    rows = db.list_rule_outcomes()
    assert len(rows) == 1
    row = rows[0]
    assert row["tx_hash"] == TX_A1
    assert row["revision_status"] == db.REVISION_RECORDED
    assert row["spec_revision_before"] == 0
    assert row["spec_revision_after"] == 1
    assert row["outcome"] == "ACCEPTED_CHANGED"
    assert row["outcome_record"]["outputs"] == {"o0": "F"}

    ledger, code = active_rules.survival_ledger_with_status()
    assert code is None
    assert len(ledger) == 1
    unit = ledger[0]
    assert unit["tx_hash"] == TX_A1
    assert unit["block_number"] == 1
    assert unit["spec_revision_before"] == 0
    assert unit["spec_revision_after"] == 1
    assert unit["outcome"] == "ACCEPTED_CHANGED"
    assert unit["status"] == "in_force"
    assert unit["installed_fragments"] == active_rules.spec_fragments(TEXT_A)
    assert unit["surviving_fragments"] == unit["installed_fragments"]
    assert unit["displaced_fragments"] == []


# --- (ii) the A-B-A resend, pair by pair -----------------------------------

def test_resend_a_b_a_shows_each_steps_revision_pair(temp_database):
    """The named resend through the module ledger: three units, each
    carrying its own step's recorded pair, in apply order. Survival
    here is the module ledger's own semantics -- footprint membership
    in the TARGET snapshot (the latest, revision 3, where the resend
    restored A's text): B's unit is displaced by the resend, and the
    first A unit's footprint is in force again at the target because
    the resend reinstalled exactly it. (The served command ledger
    tracks conjunct instances by birth instead; that is a different
    derivation, pinned in test_active_rules_journal_cut.py.)"""
    _record_resend_a_b_a()

    rows = db.list_rule_outcomes()
    assert [(r["spec_revision_before"], r["spec_revision_after"])
            for r in rows] == [(0, 1), (1, 2), (2, 3)]
    assert all(r["revision_status"] == db.REVISION_RECORDED for r in rows)

    ledger = active_rules.survival_ledger()
    assert [(u["tx_hash"], u["spec_revision_before"], u["spec_revision_after"])
            for u in ledger] == [
                (TX_A1, 0, 1), (TX_B1, 1, 2), (TX_A2, 2, 3)]
    assert [u["status"] for u in ledger] == [
        "in_force", "displaced", "in_force"]
    assert ledger[0]["displaced_by"] == []
    assert ledger[1]["displaced_by"] == [TX_A2]
    assert ledger[2]["displaced_by"] == []


# --- (iii) the ledger matches the recorded outcomes -------------------------

def test_survival_ledger_matches_the_recorded_outcomes(temp_database):
    """Cross-check against an independent reading of the same stored
    records: `db.get_rule_tx_by_revision()` parses the stored JSON on
    its own path, and every ledger unit's `spec_revision_after` must
    name the same transaction there; every unit's interval must equal
    the interval its stored row carries. Nothing is derived from
    anything but the recorded rows and snapshots."""
    _record_resend_a_b_a()

    by_revision = db.get_rule_tx_by_revision()
    assert by_revision == {1: TX_A1, 2: TX_B1, 3: TX_A2}

    recorded = {
        r["tx_hash"]: (r["spec_revision_before"], r["spec_revision_after"])
        for r in db.list_rule_outcomes()
        if r["revision_status"] == db.REVISION_RECORDED
    }
    ledger = active_rules.survival_ledger()
    assert ledger, "ledger must not be empty over recorded intervals"
    assert [u["tx_hash"] for u in ledger] == [TX_A1, TX_B1, TX_A2]
    for unit in ledger:
        assert (unit["spec_revision_before"], unit["spec_revision_after"]) \
            == recorded[unit["tx_hash"]]
        assert by_revision[unit["spec_revision_after"]] == unit["tx_hash"]

    # The footprint story agrees with the snapshot texts themselves:
    # the first unit installed exactly TEXT_A's fragments; B's unit
    # installed the one fragment TEXT_AB adds over TEXT_A, and lost
    # exactly it when the resend restored TEXT_A.
    frags_a = active_rules.spec_fragments(TEXT_A)
    frags_ab = active_rules.spec_fragments(TEXT_AB)
    assert ledger[0]["installed_fragments"] == frags_a
    assert ledger[1]["installed_fragments"] \
        == [f for f in frags_ab if f not in frags_a]
    assert [lost["fragment"] for lost in ledger[1]["displaced_fragments"]] \
        == ledger[1]["installed_fragments"]
    assert ledger[1]["displaced_fragments"][0]["displaced_by"] == [TX_A2]
    assert ledger[2]["surviving_fragments"] \
        == ledger[2]["installed_fragments"]


# --- (iv) records without the fields: explicit status, no invention --------

def test_prefield_and_registry_records_report_unavailable(temp_database):
    """Records that stored no interval -- a clause-registry record
    (no spec_revision keys by construction) and a pre-field receipt
    shape (outcome name only) -- read back with None revisions and
    status UNAVAILABLE. Their numbers are NOT reconstructed, and they
    never enter the ledger."""
    _record(1, TX_A1, {
        "outcome": "CLAUSE_REGISTERED",
        "evidence": "clause_registry",
        "registry_root_before": "00" * 32,
        "registry_root_after": "11" * 32,
        "stored_text_sha256": "22" * 32,
        "account": "ab" * 48,
        "stream": "o5",
    })
    _record(2, TX_B1, {"outcome": "ACCEPTED_CHANGED"})

    rows = db.list_rule_outcomes()
    assert len(rows) == 2
    for row in rows:
        assert row["revision_status"] == db.REVISION_UNAVAILABLE
        assert row["spec_revision_before"] is None
        assert row["spec_revision_after"] is None
    assert rows[0]["outcome"] == "CLAUSE_REGISTERED"
    assert rows[1]["outcome"] == "ACCEPTED_CHANGED"

    ledger, code = active_rules.survival_ledger_with_status()
    assert ledger == []
    assert code == active_rules.LEDGER_UNAVAILABLE
    assert active_rules.survival_ledger() == []


def test_unreadable_counter_receipt_reports_unavailable(temp_database):
    """A receipt whose revision counter could not be read at apply
    stores before/after as None (tau_native's documented fallback).
    That is a recorded absence, not a number: UNAVAILABLE, and the
    ACCEPTED unit still does not enter the ledger."""
    _snapshot(1, 1, TEXT_A)
    _record(1, TX_A1, _receipt(None, None))

    row = db.list_rule_outcomes()[0]
    assert row["revision_status"] == db.REVISION_UNAVAILABLE
    assert row["spec_revision_before"] is None
    assert row["spec_revision_after"] is None
    assert active_rules.survival_ledger() == []
    _ledger, code = active_rules.survival_ledger_with_status()
    assert code == active_rules.LEDGER_UNAVAILABLE


def test_broken_stored_payload_reports_tampered(temp_database):
    """A stored payload that no longer parses as an outcome object --
    and one whose revision fields carry the wrong type -- read
    TAMPERED: the row exists, its content does not check out. Neither
    is silently repaired into numbers."""
    with db._db_lock:
        cur = db._db_conn.cursor()
        cur.execute(
            "INSERT INTO rule_outcomes "
            "(tx_hash, block_hash, block_number, outcome) VALUES (?, ?, ?, ?)",
            (TX_A1, f"{1:064x}", 1, "this is not a stored outcome"),
        )
        db._db_conn.commit()
    _record(2, TX_B1, {
        "outcome": "ACCEPTED_CHANGED",
        "spec_revision_before": "1",
        "spec_revision_after": "2",
    })

    rows = db.list_rule_outcomes()
    assert [r["revision_status"] for r in rows] == [
        db.REVISION_TAMPERED, db.REVISION_TAMPERED]
    assert all(r["spec_revision_before"] is None for r in rows)
    assert all(r["spec_revision_after"] is None for r in rows)

    ledger, code = active_rules.survival_ledger_with_status()
    assert ledger == []
    assert code == active_rules.LEDGER_TAMPERED


def test_no_outcomes_recorded_reports_not_found(temp_database):
    """An empty table is a different fact from an unusable one."""
    assert db.list_rule_outcomes() == []
    ledger, code = active_rules.survival_ledger_with_status()
    assert ledger == []
    assert code == active_rules.LEDGER_NOT_FOUND
    assert active_rules.survival_ledger() == []


def test_recorded_units_derive_despite_unavailable_neighbours(temp_database):
    """Mixed history: a pre-field row beside a recorded one. The
    recorded unit still derives; the unrecorded one is simply not a
    unit, and the status is None -- the records that can speak, do."""
    _snapshot(1, 1, TEXT_A)
    _record(1, TX_B1, {"outcome": "ACCEPTED_CHANGED"})
    _record(1, TX_A1, _receipt(0, 1))

    ledger, code = active_rules.survival_ledger_with_status()
    assert code is None
    assert [u["tx_hash"] for u in ledger] == [TX_A1]
