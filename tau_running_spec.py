"""The specification the engine runs, built by the engine from the committed rules.

A rule unit can revise part of an earlier one. Sent `o26 = {7} && o27 = {9}` and
then `o26 = {3}`, the engine runs `o26 = 3 && o27 = 9`, while the stored
application rules still list both units. The stored units say what was sent;
only the engine says what is in force.

The authoritative evaluator runs in a worker whose rule text carries interned
ids, so its own `current_spec()` names private numbers. This module gives the
same engine the committed rule history in canonical (full-width) form, in a
worker of its own, and reads back `current_spec()`: the text two nodes at the
same block agree on.

Only the rule entries are replayed, not the steps between them: the revised
text depends on the order of the revisions, not on the inputs or the time point
at which they arrived (measured: the same text and hash with no steps and with
steps between). The result is cached per rule history, so a read costs one
worker only after a reset or a revision commits.

PREVIEW ISOLATION (scoped to worker-backed authority). The view is rebuilt in
a FRESH worker per rebuild (`compose` spawns one `SpeculationSession`, feeds it
the canonical units, reads `current_spec()`, and closes/kills it). It NEVER
reads the node's warm evaluator, never shares an evaluator with any other
read, and never reuses a worker across rebuilds: the repo's own discriminator
test proves one shared evaluator contaminates across requests
(`test_the_same_requests_through_one_shared_evaluator_do_contaminate`), so a
shared evaluator is not a permitted source for this view. A node without the
authoritative engine answers `available: false` instead of a text.

TAMPER VS NOT-FOUND. A block with no commit record never existed here (or this
node has not synced it): `code "NOT_FOUND"`. A block WITH a commit record
whose journal rows are gone or do not chain to its journal head was altered
after commit: `code "TAMPERED"`. The two are never conflated: a deletion is
reported as tamper, not as "no commit record".

CACHE. A cached text is served only after the journal rows behind its head
are re-read and their hash chain re-verified on THIS read. A node that cached
a head keeps serving its text after the database is tampered only if the
re-verification is skipped; here it is not skipped, so tampering after caching
makes the next read refuse. Stores that cannot expose full journal rows
(legacy fakes) keep the old cache behaviour and are documented as such.

AT-BLOCK. `running_spec_at` replays the journal only up to the journal head
the block's commit record names, so an old block answers with the spec that
was in force at that block, and `spec_revision` comes from the same commit
record. No new table, no state-hash change, nothing new written at apply:
the view is read-only over pre-existing tables.

STEP ROWS. The view replays rule rows only, never steps: the revised text
depends on the order of the revisions, not on the inputs or the time point
at which they arrived. Two consequences. A step row forged WITHOUT relinking
its chain is caught by the chain verification above (TAMPERED, nothing
shown). A step row forged WITH the chain relinked cannot change the text this
read answers, because steps are not inputs to it; the divergence check that
catches a relinked step forgery is the full reconstruction's
(`WorkerSession.reconstruct(..., verify=True)`, which replays steps and
compares their fingerprints), run by the authoritative path at restart -- not
by this read. That is a deliberate scope line, not an oversight.

FOLLOW-UP (not built here). Light-client provability of the text is out of
scope for issue #42's maintainer checkpoints and is not claimed: a light
client cannot verify this text without the journal and an engine. It needs
its own gated change.
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading

import tau_journal

logger = logging.getLogger(__name__)

ACCEPTED = ("ACCEPTED_CHANGED", "ACCEPTED_NOOP")

_lock = threading.Lock()
_cached_key = None
_cached_text = None


class RunningSpecUnavailable(RuntimeError):
    """The engine could not rebuild the specification from the committed rules."""


class JournalTampered(RuntimeError):
    """A commit record exists but the journal rows it names do not verify."""


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rule_units(entries) -> list:
    """The rule texts the specification is built from, in order: the units of the
    last reset, then every accepted revision after it. A revision the engine did
    not accept changed nothing and is left out."""
    begin = 0
    for index in range(len(entries) - 1, -1, -1):
        if entries[index]["kind"] == "reset":
            begin = index
            break
    units = []
    for entry in entries[begin:]:
        if entry["kind"] == "reset":
            units.extend(text for text, _persist in entry["units"])
        elif entry.get("outcome") in ACCEPTED and entry.get("rule_text"):
            units.append(entry["rule_text"])
    return units


def _spawn():
    import config
    import tau_speculation

    cwd = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ)
    paths = [p for p in env.get("PYTHONPATH", "").split(os.pathsep) if p]
    if cwd not in paths:
        env["PYTHONPATH"] = os.pathsep.join([cwd] + paths)
    return tau_speculation.SpeculationSession(
        cwd=cwd, env=env, timeout=config.COMM_TIMEOUT)


def _units_and_fingerprints(rows) -> tuple:
    """(units, expected fingerprints) from full journal rows, aligned.

    The same selection as `rule_units`, but over the full rows: the units of
    the last reset, then every accepted revision after it. A reset unit has no
    fingerprint of its own (the reset row's fingerprint covers the whole
    reset); a revision unit carries its row's recorded semantic fingerprint,
    or None when the row recorded none.
    """
    begin = 0
    for index in range(len(rows) - 1, -1, -1):
        if rows[index]["kind"] == "reset":
            begin = index
            break
    units, fps = [], []
    for row in rows[begin:]:
        if row["kind"] == "reset":
            for text, _persist in (row.get("units") or []):
                units.append(text)
                fps.append(None)
        elif (row["kind"] == "revision" and row.get("outcome") in ACCEPTED
                and row.get("rule_text")):
            units.append(row["rule_text"])
            fps.append(row.get("result_fingerprint"))
    return units, fps


def compose(baseline: str, units, *, spawn=None, fingerprints=None) -> str:
    """Build a fresh engine on `baseline`, revise it with each unit in order and
    return its `current_spec()`. Every unit must be accepted again, as it was on
    the chain; anything else is reported, never a partial text.

    One fresh worker per rebuild, disposed after the read: the view never
    shares an evaluator with the node's warm worker or with another read.

    When `fingerprints` is given (one expected semantic fingerprint per unit,
    None where the row recorded none), each replayed revision is checked
    against the fingerprint the original execution recorded
    (`tau_journal.compare`): a replay that computes something else diverges
    and the read reports unavailable instead of serving a text nobody
    committed. The same comparison the authoritative reconstruction runs with
    `verify=True`; a receipt without outputs skips the check for that unit.
    """
    session = (spawn or _spawn)()
    try:
        session.init(baseline)
        for index, text in enumerate(units):
            receipt = session.revise(text, f"unit-{index}")
            if receipt.get("outcome") not in ACCEPTED:
                raise RunningSpecUnavailable(
                    f"unit {index} was not accepted again: {receipt.get('outcome')}")
            expected = (fingerprints or [None] * len(units))[index] \
                if fingerprints is not None else None
            outputs = receipt.get("outputs")
            if expected is not None and outputs is not None:
                try:
                    tau_journal.compare(expected, outputs, seq=index + 1,
                                        outcome=receipt.get("outcome"))
                except tau_journal.DivergenceError as exc:
                    raise RunningSpecUnavailable(
                        f"replay diverged at unit {index}: {exc}") from exc
        return session.current_spec()
    finally:
        import tau_speculation
        try:
            session.close()
        except (Exception, tau_speculation.WorkerLost):
            try:
                session.kill()
            except (Exception, tau_speculation.WorkerLost):
                pass


def _key(entries) -> str | None:
    return entries[-1]["link"] if entries else None


def _verify_prefix(rows, head_link) -> None:
    """Verify the hash chain of the journal rows up to `head_link`.

    Raises JournalTampered when no row carries the head link (rows deleted, or
    the head altered after commit) or when any row's content, sequence or link
    does not verify (`tau_journal.DivergenceError`). A `None` head names an
    empty journal and verifies trivially.
    """
    if head_link is None:
        return
    cut = None
    for index, row in enumerate(rows):
        if row["link"] == head_link:
            cut = index
            break
    if cut is None:
        raise JournalTampered(
            f"no journal row carries head link {head_link}: rows were deleted "
            f"or the head was altered after commit"
        )
    try:
        tau_journal.journal_from_rows(rows[:cut + 1]).verify_chain()
    except tau_journal.DivergenceError as exc:
        raise JournalTampered(str(exc)) from exc


def _units_from_store(store, entries, head_link=None):
    """(units, fingerprints) for a read, from full rows when the store has them.

    Full rows carry the recorded semantic fingerprint per revision, so the
    replay can be checked; slim entries (legacy stores) give units only and
    the fingerprint check is skipped for them.
    """
    rows_fn = getattr(store, "committed_journal_entries", None)
    if rows_fn is None:
        return rule_units(entries), None
    rows = rows_fn()
    if head_link is not None:
        for index, row in enumerate(rows):
            if row["link"] == head_link:
                rows = rows[:index + 1]
                break
        else:
            raise JournalTampered(
                f"no journal row carries head link {head_link}")
    return _units_and_fingerprints(rows)


def _verified_key(store, head_link):
    """The cache key, verified against the store's full journal rows.

    Returns the key when the rows behind it verify, or raises JournalTampered.
    Stores without full rows (legacy fakes) cannot verify and return the key
    unverified, preserving the old cache behaviour for them.
    """
    rows_fn = getattr(store, "committed_journal_entries", None)
    if rows_fn is None:
        return head_link
    _verify_prefix(rows_fn(), head_link)
    return head_link


def at_head(store=None):
    """The running spec at the committed head, as a read returns it.

    `{"text", "sha256", "block_hash"}`, where `block_hash` is the head the rule
    history was read with (in the same read), or `{"text": None, "sha256": None,
    "block_hash": ..., "unavailable": reason}` on a node without the
    authoritative engine or when the engine could not rebuild it.
    """
    import tau_authority

    if not tau_authority.owner().enabled:
        return _unavailable(None, "this node runs without the authoritative engine")
    if store is None:
        import db as store
    return running_spec(store)


def running_spec(store, *, baseline=None, spawn=None) -> dict:
    """`at_head` for a given journal store, program baseline and worker."""
    global _cached_key, _cached_text
    import tau_authority
    import tau_speculation

    head, entries = store.committed_rule_history()
    key = _key(entries)
    with _lock:
        if key is not None and key == _cached_key:
            # Gap fix: a cache hit is not a free pass. Re-read the rows and
            # re-verify the chain before serving the cached text, so a node
            # that cached a head refuses after the database is tampered.
            try:
                _verified_key(store, key)
            except JournalTampered as exc:
                _cached_key, _cached_text = None, None
                logger.warning("running spec cache refused: %r", exc)
                return _unavailable(head, f"the journal was altered: {exc}",
                                    code="TAMPERED")
            return _available(head, _cached_text)
        try:
            base = baseline if baseline is not None else tau_authority.program_baseline()
            if not base:
                raise RunningSpecUnavailable("no program baseline")
            _verified_key(store, key)
            units, fps = _units_from_store(store, entries)
            text = compose(base, units, spawn=spawn, fingerprints=fps)
        except JournalTampered as exc:
            _cached_key, _cached_text = None, None
            logger.warning("running spec refused: %r", exc)
            return _unavailable(head, f"the journal was altered: {exc}",
                                code="TAMPERED")
        except (Exception, tau_speculation.WorkerLost) as exc:
            # A lost or timed-out worker is this node's operational trouble, never
            # a verdict on a rule: the read says the text is unavailable, and the
            # next read tries again.
            logger.warning("running spec could not be rebuilt: %r", exc)
            return _unavailable(head, f"the engine could not rebuild it: {exc!r}")
        _cached_key, _cached_text = key, text
        return _available(head, text)


def running_spec_at(store, block_hash, *, baseline=None, spawn=None) -> dict:
    """The running spec at one committed block, plus its `spec_revision`.

    `{"text", "sha256", "block_hash", "spec_revision"}`, or the unavailable
    shape with a `code`: `"NOT_FOUND"` when no commit record names the block,
    `"TAMPERED"` when the record exists but its journal rows do not verify,
    `"UNAVAILABLE"` for an engine failure. The journal is replayed only up to
    the journal head the block's commit record names.
    """
    global _cached_key, _cached_text
    import tau_authority
    import tau_speculation

    history_at = getattr(store, "committed_rule_history_at", None)
    if history_at is None:
        return _unavailable(block_hash,
                            "this store cannot answer historical blocks",
                            code="UNAVAILABLE")
    try:
        commit, entries = history_at(block_hash)
    except Exception as exc:
        # The store raises its own JournalTampered (db.JournalTampered); a
        # commit record without its rows is tamper, never "not found".
        return _unavailable(block_hash, f"the journal was altered: {exc}",
                            code="TAMPERED")
    if commit is None:
        return _unavailable(block_hash,
                            f"no commit record for block {block_hash}",
                            code="NOT_FOUND")
    key = commit.get("journal_head")
    spec_revision = commit.get("spec_revision")
    with _lock:
        if key is not None and key == _cached_key:
            try:
                _verified_key(store, key)
            except JournalTampered as exc:
                _cached_key, _cached_text = None, None
                logger.warning("running spec cache refused: %r", exc)
                return _unavailable(block_hash, f"the journal was altered: {exc}",
                                    code="TAMPERED")
            return _available_at(block_hash, _cached_text, spec_revision)
        try:
            base = baseline if baseline is not None else tau_authority.program_baseline()
            if not base:
                raise RunningSpecUnavailable("no program baseline")
            _verified_key(store, key)
            units, fps = _units_from_store(store, entries, head_link=key)
            text = compose(base, units, spawn=spawn, fingerprints=fps)
        except JournalTampered as exc:
            _cached_key, _cached_text = None, None
            logger.warning("running spec refused: %r", exc)
            return _unavailable(block_hash, f"the journal was altered: {exc}",
                                code="TAMPERED")
        except (Exception, tau_speculation.WorkerLost) as exc:
            logger.warning("running spec could not be rebuilt: %r", exc)
            return _unavailable(block_hash,
                                f"the engine could not rebuild it: {exc!r}")
        _cached_key, _cached_text = key, text
        return _available_at(block_hash, text, spec_revision)


def _available(head, text: str) -> dict:
    return {"text": text, "sha256": _sha256(text), "block_hash": head}


def _available_at(block_hash, text: str, spec_revision) -> dict:
    out = {"text": text, "sha256": _sha256(text), "block_hash": block_hash}
    if spec_revision is not None:
        out["spec_revision"] = int(spec_revision)
    return out


def _unavailable(head, reason: str, code: str = "UNAVAILABLE") -> dict:
    return {"text": None, "sha256": None, "block_hash": head,
            "unavailable": reason, "code": code}


def reset_cache() -> None:
    global _cached_key, _cached_text
    with _lock:
        _cached_key = _cached_text = None
