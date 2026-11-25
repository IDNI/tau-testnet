"""Journal cross-check for canonical spec snapshots (Bounty 02, issue #42).

The active-rules view serves canonical spec text captured at apply time
(see db.record_spec_snapshots). The capture is composed from the
application-rules accumulation, but nothing in the stored row itself
proves the accumulation the capture read was the one the committed
journal defines -- the objection raised against PR #151's view: a
process-local source can drift from the journal-fed authority and the
view would serve the drift as fact.

This module is the cross-check. It replays the committed journal
(`tau_journal_v1`, read back through tau_journal.journal_from_rows) with
the same pointwise composition the capture uses
(consensus.engine._compose_canonical_spec_text over the accumulated
units, RESET entries re-basing the accumulation exactly as
consensus.active_rules._feed_from_scratch feeds a mirror), and compares
the result with the captured snapshots of one block:

* A block's journal segment is pinned by its block-commit record: the
  entries after the previous pinned block's journal head, up to this
  block's journal head (db.block_commit_at_height -- the same pin
  consensus.active_rules.journal_cut_at_height cuts by).
* The prefix up to the segment is link-verified (tau_journal
  .verify_entries) before anything is replayed: a deleted or altered
  row breaks the chain and reconstructs nothing.
* Inside the segment, every entry that changes the composed text is one
  spec-revision step, in order. The block's snapshots, ordered by
  revision, are matched against those step texts one for one; when the
  counts disagree, only the block-end snapshot is matched (against the
  segment's final text), because the block-end state is the one mapping
  that stays unambiguous.

On the native path the authority reconstruction replays the journal
through the interpreter itself (WorkerSession.reconstruct); the
composition replayed here is the in-tree pointwise composition the
capture itself is defined by, so the check compares the capture against
the journal through exactly the function that produced the capture's
text. A governance revision (accumulate=False) never enters the
application-rules accumulation, so a block whose only revision step is
a governance activation produces no segment step text and its snapshot
stays unverified -- recorded as such, never silently trusted.

Everything here is best-effort and read-only: callers treat any failure
as "no reconstruction", never as an exception.
"""
from __future__ import annotations

import hashlib
from typing import Dict, List, Optional, Tuple


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _preprocess(rule_text: str) -> str:
    """The canonical unit form of a rule text, as the accumulation stores it."""
    try:
        import chain_state

        return chain_state._preprocess_tau_spec_text(rule_text) or rule_text
    except Exception:
        return rule_text


def _compose(units: List[str]) -> str:
    from consensus.engine import _compose_canonical_spec_text

    return _compose_canonical_spec_text("\n".join(units))


def replay_texts(entries) -> List[str]:
    """The composed canonical text after each journal entry, in order.

    Mirrors the mirror-feeding consumption pattern
    (consensus.active_rules._feed_from_scratch): a RESET re-bases the
    accumulation to its units; a REVISION with accumulate=True appends
    its preprocessed unit under the same dedup rule
    chain_state.save_effective_tau_spec uses; every other entry leaves
    the composed text unchanged.
    """
    import tau_journal

    units: List[str] = []
    current = ""
    texts: List[str] = []
    for entry in entries:
        if entry.kind == tau_journal.RESET:
            units = [text for text, _persist in entry.units if text]
            current = _compose(units)
        elif (
            entry.kind == tau_journal.REVISION
            and entry.rule_text
            and entry.accumulate
        ):
            unit = _preprocess(entry.rule_text).strip()
            if unit and unit not in units:
                units.append(unit)
                current = _compose(units)
        texts.append(current)
    return texts


def _journal_prefix(height: int):
    """(entries, cut, prev_cut) pinning `height`'s journal segment, or None.

    `cut` is the index just past the block's journal head; `prev_cut` is
    the same for the nearest lower height that has a commit record (0
    when none). None when the height cannot be pinned: no committed
    journal, no commit record for the height, or a recorded head the
    journal no longer holds. Raises tau_journal.DivergenceError when the
    prefix's chain does not verify -- callers treat that as "no
    reconstruction" too, but it is kept distinct here so the record path
    can log it.
    """
    import db
    import tau_journal

    rows = db.committed_journal_entries()
    if not rows:
        return None
    entries = tau_journal.journal_from_rows(rows).entries()
    commit = db.block_commit_at_height(int(height))
    if commit is None:
        return None
    head = commit.get("journal_head")
    cut = None
    for i, entry in enumerate(entries):
        if entry.link == head:
            cut = i + 1
    if cut is None:
        return None
    tau_journal.verify_entries(entries[:cut])
    prev_cut = 0
    for lower in range(int(height) - 1, 0, -1):
        prev = db.block_commit_at_height(lower)
        if prev is None:
            continue
        prev_head = prev.get("journal_head")
        for i, entry in enumerate(entries):
            if entry.link == prev_head:
                prev_cut = i + 1
        break
    return entries, cut, prev_cut


def journal_engaged(height: int) -> bool:
    """True when a committed journal covers `height` with verdicts.

    Coverage starts at the first height a block-commit record pins to a
    journal head; below it (or with no committed journal at all) there
    is nothing to check a snapshot against, and the snapshot predates
    the cross-check rather than failing it.
    """
    try:
        import db

        if not db.committed_journal_entries():
            return False
        start = db.earliest_block_commit_height()
        return start is not None and int(height) >= start
    except Exception:
        return False


def verify_block_snapshots(
    height: int, snapshots
) -> List[Dict]:
    """Journal verdicts for one block's captured snapshots.

    `snapshots` is an iterable of (spec_revision, canonical_text) pairs
    in any order. Returns one dict per snapshot, in revision order:
    {spec_revision, journal_verified, journal_sha256, journal_text}.
    journal_sha256 / journal_text are the journal-derived step's hash
    and text when the step could be mapped, else None; a snapshot is
    verified only when its captured text hashes to the journal-derived
    hash of its own step.
    """
    ordered = sorted((int(revision), text) for revision, text in (snapshots or []))
    verdicts: Dict[int, Dict] = {
        revision: {
            "spec_revision": revision,
            "journal_verified": False,
            "journal_sha256": None,
            "journal_text": None,
        }
        for revision, _text in ordered
    }
    if not ordered:
        return []
    try:
        pinned = _journal_prefix(int(height))
    except Exception:
        return [verdicts[revision] for revision, _text in ordered]
    if pinned is None:
        return [verdicts[revision] for revision, _text in ordered]
    entries, cut, prev_cut = pinned
    texts = replay_texts(entries[:cut])
    segment: List[str] = []
    previous = texts[prev_cut - 1] if prev_cut > 0 else ""
    for i in range(prev_cut, cut):
        if texts[i] != previous:
            segment.append(texts[i])
            previous = texts[i]
    if len(segment) == len(ordered):
        pairs = list(zip(ordered, segment))
    elif segment:
        # Only the block-end mapping stays unambiguous when the step
        # count disagrees; the other steps keep no journal text rather
        # than a guessed one.
        pairs = [(ordered[-1], segment[-1])]
    else:
        pairs = []
    for (revision, captured), journal_text in pairs:
        verdict = verdicts[revision]
        verdict["journal_text"] = journal_text
        verdict["journal_sha256"] = _sha256(journal_text)
        verdict["journal_verified"] = _sha256(captured) == verdict["journal_sha256"]
    return [verdicts[revision] for revision, _text in ordered]


def reconstruct_snapshot(height: int, spec_revision: int) -> Optional[str]:
    """The journal-derived text for one stored snapshot, or None.

    Recomputed from the committed journal on every call, against the
    snapshots actually stored at the height: a journal tampered with
    after the snapshot was recorded yields None (its chain no longer
    verifies, or the step no longer maps) instead of a stale verdict.
    """
    try:
        import db

        stored = [
            snap
            for snap in db.get_all_spec_snapshots()
            if int(snap["height"]) == int(height)
        ]
        if not stored:
            return None
        verdicts = verify_block_snapshots(
            int(height),
            [(snap["spec_revision"], snap["canonical_text"]) for snap in stored],
        )
        for verdict in verdicts:
            if verdict["spec_revision"] == int(spec_revision):
                return verdict["journal_text"]
        return None
    except Exception:
        return None
