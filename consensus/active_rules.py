"""The rules view derived from the spec the engine actually runs (issue #42).

`gettaustate` / `getgovernance` return the append-only accumulation of
submitted rule text. Pointwise revision is not append-only: a later unit
displaces whatever part of an earlier one it contradicts, so the accumulated
text can claim rules that are not in force (and hide the surviving form of
the ones that are). This module maintains the corrective view:

* At block commit, whenever the engine's `spec_revision` has advanced past
  the newest stored snapshot, the node's canonical spec text is snapshotted
  (see `record_snapshot_after_commit`). "Canonical" is the codebase's own
  sense -- `tau_manager.get_canonical_spec()`, the full-width text that is
  safe to persist and hash, never the interpreter's possibly shrunk
  `get_current_spec()`.
* Under worker-backed authority (the production configuration) neither of
  those is the running spec: the in-process interpreter is an advisory
  mirror that is never fed application-rule revisions, and the persisted
  `full_tau_spec` row is the append-only accumulation. There the snapshot
  text comes from a dedicated interface fed from the committed journal --
  the same record a reconstruction replays -- maintained by
  `_authority_spec_text` below.
* `getactiverules` serves those snapshots and, for an account, attributes
  the effective text's top-level statements by the `i12` guard each one
  carries. Displaced clauses are absent by construction: the source is the
  engine's normalized spec after revision, not the submitted text.

Snapshots are stored data. Replay does not re-run the rules handler, so a
replayed node verifies the recorded revision progression rather than
recomputing snapshots; heights before the first snapshot have none.

For those heights the view falls back to the committed journal itself
(`journal_cut_at_height`): every block commit records the journal head it
committed, so the spec in force at any held height is the journal cut at
that head, chain-verified and fed to a one-shot mirror -- the same record
a reconstruction replays, available for blocks committed before the
snapshots existed. Answers derived that way are marked
``derived == "journal_cut"`` so the source is explicit, never silent.
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import threading
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


def _view_shape(snap: Optional[Dict]) -> Optional[Dict]:
    """Adapt a stored snapshot dict to this module's key shape.

    ADAPTATION for the #151 line (this module was adopted there with
    the getpaymentconditions command): the line's own db accessors
    (db.get_latest_spec_snapshot) name the stored text/hash
    `canonical_text`/`sha256`, while this module and the accessors
    added alongside it in db.py use `spec_text`/`spec_hash`. Snapshots
    already carrying this module's keys pass through unchanged.
    """
    if snap is None or "spec_text" in snap:
        return snap
    out = dict(snap)
    out["spec_text"] = snap.get("canonical_text")
    out["spec_hash"] = snap.get("sha256")
    return out


def spec_hash_of(text: str) -> str:
    """sha256 over the canonical spec text, as served and compared."""
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def current_spec_revision() -> Optional[int]:
    """The node's current engine spec_revision, or None when unreadable.

    The durable commit record is the committed truth; the live interpreter
    is the fallback for paths that commit outside the commit protocol.
    """
    try:
        import db

        commit = db.latest_block_commit()
        if commit is not None and commit.get("spec_revision") is not None:
            return int(commit["spec_revision"])
    except Exception:
        logger.debug("latest_block_commit spec_revision unreadable", exc_info=True)
    try:
        import tau_manager
        from tau_native import _interpreter_spec_revision

        iface = getattr(tau_manager, "tau_direct_interface", None)
        interpreter = getattr(iface, "interpreter", None)
        if interpreter is not None:
            return _interpreter_spec_revision(interpreter)
    except Exception:
        logger.debug("interpreter spec_revision unreadable", exc_info=True)
    return None


# --- Snapshot source under worker-backed authority -------------------------
#
# Production runs the authoritative worker (server.py: authority is enabled
# unless the mock configuration was requested). In that mode the two sources
# above are both wrong as snapshot text: `tau_manager.get_canonical_spec()`
# is the in-process advisory mirror, which is deliberately never fed
# application-rule revisions (chain_state._sync_inprocess_consensus), and
# the persisted `full_tau_spec` row is the append-only accumulation of
# submitted units, displaced fragments included. The committed journal is
# the codebase's own definition of the evaluator state -- it is what a
# reconstruction replays -- so the view keeps a dedicated TauInterface (the
# spec mirror) fed from the journal: REVISION rule texts in seq order, the
# same consumption pattern _sync_inprocess_consensus uses for the advisory
# mirror in non-authority mode. The mirror is passive: it evaluates nothing
# for consensus, and its text depends only on the program file and the
# committed journal, so a second node and a replay from block 0 produce the
# same text and hash.
#
# The mirror tracks how many committed entries it has consumed, the
# fingerprint (seq, kind, rule_text, link) of the last one, and the seq of
# the RESET entry it was built on. A new RESET, a journal that shrank, or a
# fingerprint mismatch (a discarded/rebuilt journal) forces a full rebuild,
# so restarts and journal rebuilds self-heal; the first call after boot
# replays the whole journal once, the same cost class as reconstruction at
# startup. Any failure poisons the mirror and yields no text: a silently
# diverged mirror is worse than a missing snapshot.

_mirror_lock = threading.Lock()
_mirror_iface = None
_mirror_consumed = 0
_mirror_fingerprint: Optional[Tuple] = None
_mirror_reset_seq: Optional[int] = None


def _authority_mode() -> bool:
    """True when this node's evaluator is the authoritative worker."""
    try:
        import tau_authority

        return bool(tau_authority.owner().enabled)
    except Exception:
        return False


def reset_spec_mirror() -> None:
    """Drop the snapshot spec mirror (tests; rebuilds self-heal anyway)."""
    global _mirror_iface, _mirror_consumed, _mirror_fingerprint
    global _mirror_reset_seq
    with _mirror_lock:
        _mirror_iface = None
        _mirror_consumed = 0
        _mirror_fingerprint = None
        _mirror_reset_seq = None


def _entry_fingerprint(entry) -> Tuple:
    return (entry.seq, entry.kind, entry.rule_text, entry.link)


def _new_mirror_iface():
    import chain_state
    import config
    from tau_native import TauInterface

    path = getattr(config, "TAU_PROGRAM_FILE", None) or "genesis.tau"
    if not os.path.isabs(path):
        path = os.path.join(
            os.path.dirname(os.path.abspath(chain_state.__file__)), path)
    return TauInterface(path)


def _feed_mirror(iface, text: str) -> None:
    iface.communicate(rule_text=text, target_output_stream_index=0)


def _feed_from_scratch(iface, entries) -> None:
    """Feed a fresh mirror interface a whole journal: the last RESET's
    units, then every REVISION text after it. The consumption pattern
    the mirror's rebuild and the journal-cut view share."""
    import tau_journal

    reset_idx = tau_journal.last_reset_index(entries)
    start = 0
    if reset_idx is not None:
        for text, _persist in entries[reset_idx].units:
            if text:
                _feed_mirror(iface, text)
        start = reset_idx + 1
    for entry in entries[start:]:
        if entry.kind == tau_journal.REVISION and entry.rule_text:
            _feed_mirror(iface, entry.rule_text)


def _rebuild_replay_check(journal) -> Optional[bool]:
    """Full-sample step-fingerprint verification of a mirror rebuild.

    Replays the committed journal through the node's own reconstruction
    path -- `WorkerSession.reconstruct` with verify=True, the replay a
    restart performs -- which re-derives every entry's outputs and
    compares them against the semantic fingerprints recorded at apply.
    A journal whose recorded step results were forged and whose links
    were re-computed passes `verify_chain` but diverges here, because
    the replay recomputes what the forged record merely claims.

    Returns True when the replay verified, False when it DIVERGED (the
    caller must serve no snapshot), and None when the verification
    machinery is unavailable in this process (no program baseline, a
    stored plan that does not hash to its recorded id, a worker that
    cannot spawn): chain verification still ran on the same rows, and a
    best-effort view must not go dark because an auxiliary check could
    not run. Only a proven divergence withholds the snapshot.
    """
    import db
    import tau_journal
    import tau_session

    entries = journal.entries()
    if not entries:
        return True
    try:
        import tau_allocator
        import tau_authority
        import tau_reconstruction

        baseline = tau_authority.program_baseline()
        if not baseline:
            return None
        plan = None
        latest = db.latest_block_commit()
        if latest is not None and latest.get("plan_json"):
            plan = tau_reconstruction.RepresentationPlan.from_json(
                latest["plan_json"])
            if latest.get("plan_id") and plan.plan_id != latest["plan_id"]:
                logger.warning(
                    "active_rules: stored representation plan does not "
                    "hash to its recorded id; replay check unavailable")
                return None
        if plan is None:
            import tau_manager

            with tau_manager.reexec_on_width_overflow():
                plan = tau_reconstruction.plan_representation(
                    history_rules=[
                        e.rule_text for e in entries
                        if e.kind == tau_journal.REVISION and e.rule_text
                    ])
        session = tau_session.WorkerSession.reconstruct(
            baseline, journal=journal, plan=plan,
            snapshot=tau_allocator.DbMappingSnapshot(), verify=True)
        try:
            return True
        finally:
            session.dispose()
    except tau_journal.DivergenceError:
        logger.warning(
            "active_rules: rebuild replay DIVERGED from the committed "
            "journal's recorded fingerprints; no snapshot", exc_info=True)
        return False
    except tau_session.WorkerLost:
        # The replay's worker died: the loss is translated here into the
        # check's own vocabulary -- unavailable, like any other way the
        # auxiliary check cannot run. The view falls back to the chain
        # verification that already ran; the loss never propagates.
        logger.warning(
            "active_rules: rebuild replay check lost its worker; serving "
            "on chain verification alone", exc_info=True)
        return None
    except Exception:
        logger.warning(
            "active_rules: rebuild replay check unavailable in this "
            "process; serving on chain verification alone", exc_info=True)
        return None


def _authority_spec_text() -> Optional[str]:
    """The running spec under worker-backed authority, from the journal.

    Returns None when the mirror cannot be built or fed; the caller then
    stores no snapshot rather than serving a text that is not in force.
    """
    global _mirror_iface, _mirror_consumed, _mirror_fingerprint
    global _mirror_reset_seq
    import db
    import tau_journal

    with _mirror_lock:
        try:
            head_link, head_seq = db.committed_journal_head()
            if _mirror_iface is not None and _mirror_fingerprint is not None \
                    and (head_link, head_seq) == (
                        _mirror_fingerprint[3], _mirror_fingerprint[0]):
                # The committed journal has not grown since the mirror
                # consumed it (the link chains the whole history, so an
                # equal head means an equal journal).
                return _mirror_iface.get_current_spec()
            journal = tau_journal.journal_from_rows(
                db.committed_journal_entries())
            # Explicit chain verification over the rows just read, before
            # the mirror is fed anything: a row whose content no longer
            # hashes to its recorded link, or a chain whose links do not
            # join up, must yield no snapshot rather than a spec that was
            # never in force. The failure lands in the except path below
            # (mirror poisoned, no text), like any mirror failure.
            journal.verify_chain()
            entries = journal.entries()
            reset_idx = tau_journal.last_reset_index(entries)
            reset_seq = entries[reset_idx].seq if reset_idx is not None \
                else None
            rebuild = (
                _mirror_iface is None
                or reset_seq != _mirror_reset_seq
                or len(entries) < _mirror_consumed
                or (_mirror_consumed > 0
                    and _entry_fingerprint(entries[_mirror_consumed - 1])
                    != _mirror_fingerprint)
            )
            if rebuild:
                iface = _new_mirror_iface()
                _feed_from_scratch(iface, entries)
                # A rebuild re-derives the mirror from the journal alone;
                # before it may speak, the journal's recorded step
                # fingerprints are verified by a full replay (the check
                # a restart performs). A proven divergence poisons the
                # mirror like any other failure; an unavailable check
                # does not (see _rebuild_replay_check).
                if _rebuild_replay_check(journal) is False:
                    raise tau_journal.DivergenceError(
                        "rebuild replay diverged from the committed "
                        "journal's recorded fingerprints")
                _mirror_iface = iface
                _mirror_reset_seq = reset_seq
            else:
                for entry in entries[_mirror_consumed:]:
                    if entry.kind == tau_journal.REVISION \
                            and entry.rule_text:
                        _feed_mirror(_mirror_iface, entry.rule_text)
            _mirror_consumed = len(entries)
            _mirror_fingerprint = _entry_fingerprint(entries[-1]) \
                if entries else None
            return _mirror_iface.get_current_spec()
        except Exception:
            logger.warning(
                "active_rules: authority spec mirror failed; no snapshot "
                "source this block", exc_info=True)
            _mirror_iface = None
            _mirror_consumed = 0
            _mirror_fingerprint = None
            _mirror_reset_seq = None
            return None


def record_snapshot_after_commit(height: int) -> Optional[Dict]:
    """Snapshot the canonical spec if spec_revision advanced. Best effort.

    Called after a block commits; never raises and never blocks the commit
    path -- a missing snapshot degrades getactiverules, not consensus.
    Returns the stored snapshot dict, or None when nothing was stored
    (no readable text/revision, or the revision did not advance).
    """
    try:
        import db
        import tau_manager

        if _authority_mode():
            # Neither the advisory mirror's canonical text nor the
            # persisted accumulation is the spec the engine runs here;
            # the journal-fed mirror is. If it cannot speak, store
            # nothing rather than serve a text that is not in force.
            text = _authority_spec_text()
            if not text:
                return None
        else:
            text = tau_manager.get_canonical_spec()
            if not text:
                try:
                    import chain_state

                    text = chain_state.get_persisted_full_tau_spec()
                except Exception:
                    text = None
            if not text:
                return None
        revision = current_spec_revision()
        if revision is None:
            return None
        latest = db.get_latest_spec_snapshot()
        if latest is not None and latest["spec_revision"] >= revision:
            return None
        digest = spec_hash_of(text)
        db.record_spec_snapshot(revision, int(height), text, digest)
        return {
            "spec_revision": revision,
            "height": int(height),
            "spec_hash": digest,
            "spec_text": text,
        }
    except Exception:
        logger.warning(
            "active_rules: failed to record spec snapshot at height %s",
            height, exc_info=True,
        )
        return None


def resolve_snapshot(height: Optional[int] = None) -> Optional[Dict]:
    """The snapshot a getactiverules query answers from.

    No height -> the latest snapshot. A height -> the newest snapshot
    committed at or before it; when every snapshot is later than the
    requested height, the earliest one (callers surface both heights, so
    the substitution is explicit in the answer, never silent).
    """
    import db

    if height is None:
        return _view_shape(db.get_latest_spec_snapshot())
    snap = db.get_spec_snapshot_at_or_before(int(height))
    if snap is not None:
        return _view_shape(snap)
    return _view_shape(db.get_earliest_spec_snapshot())


# Why a journal cut is unavailable, when it is (B02-6, issue #42):
# the read path distinguishes a height the record simply does not cover
# from a record that exists but no longer checks out -- the same
# explicit codes the answer surfaces instead of one silent None.
CUT_NOT_FOUND = "NOT_FOUND"    # no commit record (or none naming a cut)
CUT_TAMPERED = "TAMPERED"      # record exists; the journal does not verify
CUT_UNAVAILABLE = "UNAVAILABLE"  # the mirror cannot speak for the cut


def _journal_cut_at_height(
        height: int) -> Tuple[Optional[Dict], Optional[str]]:
    """`journal_cut_at_height` with its failure classified.

    Returns (cut, None) on success, else (None, code) with code one of
    CUT_NOT_FOUND / CUT_TAMPERED / CUT_UNAVAILABLE.
    """
    import db
    import tau_journal

    try:
        height = int(height)
        if height == 0:
            block_hash = db.get_genesis_hash() or None
            if not block_hash:
                return None, CUT_NOT_FOUND
            # O-5: the genesis journal entries belong in the height-0
            # cut. _commit_genesis records a genesis commit in
            # block_commits_v1 (tip = the genesis hash); its journal
            # head is the link of the last genesis entry, so the cut
            # carries the genesis rules instead of the empty
            # pre-genesis baseline. When no genesis commit exists (a
            # database predating the genesis commit), fall back to the
            # pre-genesis baseline (cut_len=0, revision 0).
            commit = db.genesis_block_commit()
            if commit is None:
                revision: Optional[int] = 0
                cut_len = 0
            else:
                revision = commit.get("spec_revision")
                if revision is None:
                    # A commit that names a journal head but no
                    # revision cannot pin the cut to a spec_revision.
                    return None, CUT_NOT_FOUND
                cut_len = -1  # resolved against the journal head below
        else:
            commit = db.block_commit_at_height(height)
            if commit is None:
                return None, CUT_NOT_FOUND
            block_hash = commit["block_hash"]
            revision = commit.get("spec_revision")
            if revision is None:
                # A commit that names a journal head but no revision
                # cannot pin the cut to a spec_revision; not an answer.
                return None, CUT_NOT_FOUND
            cut_len = -1  # resolved against the journal head below
        journal = tau_journal.journal_from_rows(
            db.committed_journal_entries())
        entries = journal.entries()
        if commit is not None:
            head_link = commit.get("journal_head")
            if head_link is None:
                return None, CUT_NOT_FOUND
            cut_len = None
            for i, entry in enumerate(entries):
                if entry.link == head_link:
                    cut_len = i + 1
            if cut_len is None:
                # The commit names a journal head the journal no
                # longer holds: rows were removed or rewritten after
                # the commit -- the record exists, the journal does
                # not match it.
                return None, CUT_TAMPERED
        # Verify the cut itself, not the whole journal: the entries at
        # or before the block's journal head are the record this answer
        # rests on, and their chain must check out (a tamper after the
        # height does not poison an earlier height's answer; a tamper
        # inside the cut does).
        try:
            tau_journal.verify_entries(entries[:cut_len])
        except Exception:
            return None, CUT_TAMPERED
        iface = _new_mirror_iface()
        _feed_from_scratch(iface, entries[:cut_len])
        text = iface.get_current_spec()
        if not text:
            return None, CUT_UNAVAILABLE
        return {
            "spec_revision": revision,
            "height": height,
            "block_hash": block_hash,
            "spec_hash": spec_hash_of(text),
            "spec_text": text,
            "derived": "journal_cut",
        }, None
    except Exception:
        logger.warning(
            "active_rules: journal cut at height %s unavailable", height,
            exc_info=True)
        return None, CUT_UNAVAILABLE


def journal_cut_at_height(height: int) -> Optional[Dict]:
    """The spec in force at `height`, derived from the committed journal.

    The stored snapshots only exist for heights committed since the view
    was introduced; the committed journal has always been there. The cut
    is every committed entry up to the journal head the canonical block
    at `height` committed (see `db.block_commit_at_height`), link-
    verified over the cut and fed to a one-shot mirror. Returns a
    snapshot-shaped dict marked ``derived == "journal_cut"`` (with the
    block hash it answers for), or None when the cut cannot be derived:
    no commit record for the height, a commit that names no journal
    head, a journal head the journal no longer holds, a journal that
    does not verify, or a mirror that cannot speak. Height 0 carries
    the genesis journal entries when a genesis commit exists (O-5);
    it is the empty pre-genesis baseline only when no genesis commit
    is recorded. `journal_cut_status` classifies the None.
    """
    cut, _code = _journal_cut_at_height(height)
    return cut


def journal_cut_status(height: int) -> Optional[str]:
    """Why the journal cut at `height` is unavailable, or None when it is.

    CUT_NOT_FOUND: no commit record for the height (or a record naming
    no journal head / no spec revision -- nothing recorded to read).
    CUT_TAMPERED: a commit record exists, but the journal it names no
    longer verifies -- a head the journal no longer holds, or a cut
    whose chain does not check out. CUT_UNAVAILABLE: the cut verifies
    but the mirror cannot speak for it.
    """
    cut, code = _journal_cut_at_height(height)
    return None if cut is not None else code


def checked_snapshot_answer(snap: Optional[Dict]) -> Optional[Dict]:
    """Step 7 stopgap (B02 §2): a stored snapshot is only served when it
    agrees with the journal cut at the snapshot's own height.

    The snapshot and the cut are two canonicalizations of the same
    committed record; they diverged systematically (the snapshot is
    composed from the append-only accumulation, the cut is the
    interpreter's normalized spec over the full genesis baseline), so
    a snapshot that disagrees with the cut is answered with the cut
    instead -- the cut's text and its sha256, with ``derived`` marking
    the source. When the snapshot and the cut agree, the snapshot is
    served unchanged. When the cut cannot be derived because no commit
    record exists (NOT_FOUND) or the mirror cannot speak
    (UNAVAILABLE), the snapshot is served as today: the cut is a check
    that runs when it can speak, not a gate that withholds the view
    for a missing record. When the cut is TAMPERED -- the journal the
    snapshot rests on no longer verifies -- the snapshot is HELD
    (None, with a hard log): O-2, fail closed for integrity, never
    serve a snapshot whose journal is broken. A snapshot with no
    height cannot be checked and is served unchanged. The comparison
    covers the served text, its sha256, and the spec revision: all
    three must agree, or the cut answers.
    """
    view = _view_shape(snap)
    if view is None:
        return None
    height = view.get("height")
    if height is None:
        return view
    cut, code = _journal_cut_at_height(int(height))
    if cut is None:
        if code == CUT_TAMPERED:
            # O-2: HOLD. The journal the snapshot rests on no longer
            # verifies; serving the snapshot would hand out an answer
            # whose integrity is already broken. Fail closed, and log
            # it hard so the hold is visible, not silent.
            logger.error(
                "active_rules: journal cut at height %s is TAMPERED; "
                "holding the stored snapshot (spec_revision %s)",
                height, view.get("spec_revision"))
            return None
        return view
    if (view.get("spec_text") != cut.get("spec_text")
            or view.get("spec_hash") != cut.get("spec_hash")
            or view.get("spec_revision") != cut.get("spec_revision")):
        return cut
    return view


def checked_snapshot_sequence(
        snapshots: List[Dict]) -> Tuple[Optional[List[Dict]], Optional[str]]:
    """Map stored snapshots to the text the view actually serves.

    O-4 (a): the per-unit ledger describes the SERVED state, so it is
    derived from the checked text of every snapshot in the served
    history, not from the stored text. Each snapshot is run through
    `checked_snapshot_answer` (the Step 7 check); the returned rows
    keep the stored snapshot's revision and height and carry the
    checked text + sha256. Returns (sequence, None) on success. When
    any snapshot's check HOLDs (its journal cut is TAMPERED -- see
    O-2), the whole history's integrity is broken: return
    (None, CUT_TAMPERED) and serve nothing rather than a ledger over
    a history that cannot be verified.
    """
    checked = []
    for snap in snapshots:
        view = checked_snapshot_answer(snap)
        if view is None:
            return None, CUT_TAMPERED
        checked.append({
            "spec_revision": snap["spec_revision"],
            "height": snap.get("height"),
            "canonical_text": view["spec_text"],
            "sha256": view["spec_hash"],
        })
    return checked, None


def resolve_answer_with_status(
        height: Optional[int] = None) -> Tuple[Optional[Dict], Optional[str]]:
    """`resolve_answer` with the no-answer case classified.

    A stored snapshot is served only after the Step 7 check against
    the journal cut at its own height (see
    `checked_snapshot_answer`); a divergent snapshot is answered
    with the cut instead.

    Returns (answer, None) whenever an answer exists, else
    (None, code) with the journal cut's failure code for the height
    (CUT_NOT_FOUND when the record does not cover it, CUT_TAMPERED
    when a record exists but its journal no longer verifies,
    CUT_UNAVAILABLE when the mirror cannot speak) -- so a caller
    answering `available: false` can say which of those it was.
    """
    import db

    if height is None:
        snap = db.get_latest_spec_snapshot()
        if snap is not None:
            # O-2: the Step 7 check may HOLD the snapshot (its cut is
            # TAMPERED) -- then there is no answer, classified
            # CUT_TAMPERED, not a served snapshot.
            answer = checked_snapshot_answer(snap)
            if answer is None:
                return None, CUT_TAMPERED
            return answer, None
        tip = db.canonical_tip_height()
        if tip is None:
            return None, CUT_NOT_FOUND
        cut, code = _journal_cut_at_height(tip)
        return cut, (None if cut is not None else code)
    snap = db.get_spec_snapshot_at_or_before(int(height))
    if snap is not None:
        # O-2: same hold as above, for the height-pinned branch.
        answer = checked_snapshot_answer(snap)
        if answer is None:
            return None, CUT_TAMPERED
        return answer, None
    cut, code = _journal_cut_at_height(int(height))
    if cut is not None:
        return cut, None
    earliest = _view_shape(db.get_earliest_spec_snapshot())
    if earliest is not None:
        return earliest, None
    return None, code


def resolve_answer(height: Optional[int] = None) -> Optional[Dict]:
    """The view a getactiverules query answers from, journal-cut aware.

    Stored snapshots remain the fast path and the answer for every
    height at or after the first snapshot. A height earlier than the
    first snapshot -- or any height on a node whose database predates
    the snapshots (written by pristine code) -- is answered from the
    journal cut at that height instead of substituting the earliest
    snapshot; the returned dict then carries ``derived`` so the source
    is explicit in the answer. With no height and no snapshot at all,
    the cut at the canonical tip answers. When neither a snapshot nor
    a cut exists, None (the caller answers `available: false`).
    """
    answer, _code = resolve_answer_with_status(height)
    return answer


# --- Account attribution -------------------------------------------------
#
# A user rule unit guards on the sender stream: `i12[t] = { #x<pubkey> }`,
# the pubkey being a bv[384] literal. After pointwise revision the surviving
# statements of the effective spec still carry the guards of the units they
# came from, which is what makes guard-based attribution possible without
# trusting the submitted (append-only) text.

_I12_GUARD_RE = re.compile(
    r"i12\s*\[\s*t\s*\]\s*(?::\s*bv\s*\[\s*\d+\s*\]\s*)?=\s*"
    r"\{\s*#x([0-9a-fA-F]+)\s*\}"
)


def split_statements(spec_text: str) -> List[str]:
    """Split a spec into its top-level statements (each ends with '.').

    A '.' terminates a statement only at bracket depth 0, so literals and
    parenthesised sub-formulas never split a statement in two.
    """
    statements: List[str] = []
    depth = 0
    start = 0
    text = spec_text or ""
    for i, ch in enumerate(text):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "." and depth == 0:
            stmt = text[start:i + 1].strip()
            if stmt:
                statements.append(stmt)
            start = i + 1
    tail = text[start:].strip()
    if tail:
        statements.append(tail)
    return statements


def guard_accounts(statement: str) -> set:
    """The distinct accounts a statement's i12 guards bind it to."""
    return {m.group(1).lower() for m in _I12_GUARD_RE.finditer(statement or "")}


def normalize_account(account: str) -> str:
    acct = (account or "").strip().lower()
    if acct.startswith("0x"):
        acct = acct[2:]
    return acct


def _unwrap_statement(statement: str) -> str:
    """The body of one top-level statement.

    Strips the terminating '.' and, for the `always ( ... )` shape rule
    units take, the wrapper itself (one level, matched parens). Anything
    else is returned with only the '.' removed.
    """
    text = (statement or "").strip()
    if text.endswith("."):
        text = text[:-1].strip()
    if text.startswith("always"):
        rest = text[len("always"):].lstrip()
        if rest.startswith("("):
            depth = 0
            for i, ch in enumerate(rest):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        if not rest[i + 1:].strip():
                            return rest[1:i]
                        break
    return text


def _split_conjuncts(body: str) -> List[str]:
    """Split a statement body on its top-level `&&` conjuncts.

    "Top-level" is the shallowest bracket depth at which `&&` occurs in
    the body, so a conjunction inside a guarded conditional stays inside
    its fragment while the assignments of a plain `always ( A && B )`
    unit become separate fragments.
    """
    depths = []
    depth = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "&" and body[i + 1:i + 2] == "&":
            depths.append(depth)
            i += 1
        i += 1
    if not depths:
        return [body]
    top = min(depths)
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(body):
        ch = body[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        elif ch == "&" and body[i + 1:i + 2] == "&" and depth == top:
            parts.append(body[start:i])
            i += 2
            start = i
            continue
        i += 1
    parts.append(body[start:])
    return parts


def spec_fragments(spec_text: str) -> List[str]:
    """Decompose a canonical spec into its rule fragments.

    A fragment is one top-level conjunct of one top-level statement,
    whitespace-normalised. Pointwise revision displaces fragments, not
    whole statements -- one `always (...)` statement can carry several
    assignments, of which a later unit may displace only one -- so the
    survival ledger below is kept at this granularity. Order is spec
    order; duplicates collapse (a fragment is either in force or not).
    """
    fragments: List[str] = []
    seen = set()
    for stmt in split_statements(spec_text):
        for part in _split_conjuncts(_unwrap_statement(stmt)):
            frag = " ".join(part.split())
            if frag and frag not in seen:
                seen.add(frag)
                fragments.append(frag)
    return fragments


# --- Survival ledger -------------------------------------------------------
#
# getactiverules answers what the spec runs NOW. The ledger answers the
# complementary question for every confirmed rule unit: is what it
# installed still in force, partly displaced, or gone -- and which later
# transaction displaced it. It is derived entirely from stored data (the
# spec snapshots and the rule_outcome receipts), never from the
# append-only accumulation and never by re-running the engine.
#
# A unit's footprint is the fragments its apply step installed: the
# fragments of the first snapshot at or after its spec_revision_after,
# minus the fragments of the last snapshot at or before its
# spec_revision_before (the empty spec when there is none). Survival is
# footprint membership in the target snapshot. A fragment lost between
# two consecutive snapshots is attributed to the accepted units whose
# apply step produced a revision inside that interval.

# Why the survival ledger is empty, when it is (B02-7, issue #42):
# the same explicit codes as the journal cut above. The ledger derives
# its units from the revision interval each recorded rule outcome
# carries (db.list_rule_outcomes lifts it out of the stored receipt).
# A record written before the interval was stored -- or one that never
# had a spec revision to report, like a clause-registry record -- has
# no interval to derive from, and its numbers are never reconstructed
# after the fact; the codes below say which case an empty ledger is.
LEDGER_NOT_FOUND = "NOT_FOUND"      # no rule outcome recorded at all
LEDGER_TAMPERED = "TAMPERED"        # records exist; a stored shape is broken
LEDGER_UNAVAILABLE = "UNAVAILABLE"  # records exist; none carries an interval


def survival_ledger_with_status(
        target: Optional[Dict] = None) -> Tuple[List[Dict], Optional[str]]:
    """`survival_ledger` with an empty result classified.

    Returns (ledger, None) when the recorded outcomes can speak --
    including a legitimately empty ledger (recorded intervals exist,
    but no ACCEPTED unit is in force at the target). Otherwise returns
    ([], code) with code one of LEDGER_NOT_FOUND (no rule outcome has
    been recorded on this node), LEDGER_TAMPERED (records exist but at
    least one stored payload no longer parses, and none carries a
    usable interval), or LEDGER_UNAVAILABLE (records exist, none of
    them carries a revision interval: pre-field records, receipts
    whose counter was unreadable, registry evidence). The code
    classifies the OUTCOME RECORDS only; the snapshot guards inside
    the derivation are unchanged.
    """
    import db

    rows = db.list_rule_outcomes()
    if not rows:
        return [], LEDGER_NOT_FOUND
    recorded = [
        row for row in rows
        if row.get("revision_status") == db.REVISION_RECORDED
    ]
    if not recorded:
        if any(row.get("revision_status") == db.REVISION_TAMPERED
               for row in rows):
            return [], LEDGER_TAMPERED
        return [], LEDGER_UNAVAILABLE
    return _derive_survival_ledger(recorded, target), None


def survival_ledger(target: Optional[Dict] = None) -> List[Dict]:
    """Per-unit survival at `target` (default: the latest snapshot).

    One entry per ACCEPTED rule outcome whose revision is in force at
    the target, in apply order. Entries carry the unit's transaction
    hash, block number, the revision interval its apply step took, its
    recorded outcome, its status ("in_force", "partially_displaced" or
    "displaced"), the fragments it installed / still has in force / lost
    (each lost fragment with its displacing transaction hashes), and the
    unit-level union of displacers. A unit that installed no new
    fragments (an ACCEPTED_NOOP receipt) is in_force with an empty
    footprint: it asserted nothing the spec did not already run.

    Only outcomes whose stored record carries its revision interval
    (db.REVISION_RECORDED) derive units; records without one are never
    given invented numbers. `survival_ledger_with_status` classifies
    an empty result.
    """
    ledger, _code = survival_ledger_with_status(target)
    return ledger


def _derive_survival_ledger(rows: List[Dict],
                            target: Optional[Dict]) -> List[Dict]:
    """The ledger derivation over pre-listed RECORDED outcome rows."""
    import db

    if target is None:
        target = _view_shape(db.get_latest_spec_snapshot())
    if target is None:
        return []
    target_revision = target["spec_revision"]
    snapshots = db.list_spec_snapshots()
    if not snapshots:
        return []
    frag_sets = {
        snap["spec_revision"]: set(spec_fragments(snap["spec_text"]))
        for snap in snapshots
    }
    if target_revision not in frag_sets:
        # A journal-cut target (journal_cut_at_height) has no stored
        # snapshot; its own text is the target fragment set. Footprints
        # still derive from the stored snapshot transitions, so a unit
        # whose install interval has no stored snapshot reads as an
        # empty footprint, exactly like an ACCEPTED_NOOP unit.
        frag_sets[target_revision] = set(spec_fragments(target["spec_text"]))
    target_frags = frag_sets.get(target_revision, set())

    units = [
        row for row in rows
        if row.get("spec_revision_after") is not None
        and row["spec_revision_after"] <= target_revision
        and (row.get("outcome") or "").startswith("ACCEPTED")
    ]

    def snapshot_at_or_before(revision: int) -> Optional[Dict]:
        found = None
        for snap in snapshots:
            if snap["spec_revision"] <= revision:
                found = snap
            else:
                break
        return found

    def snapshot_at_or_after(revision: int) -> Optional[Dict]:
        for snap in snapshots:
            if snap["spec_revision"] >= revision:
                return snap
        return None

    def displacers_of(fragment: str, installed_after_revision: int) -> List[str]:
        """Accepted units whose step first removed `fragment` from the
        spec, considering only snapshot transitions after the snapshot
        the fragment was installed into, up to the target."""
        found: List[str] = []
        pairs = zip(snapshots, snapshots[1:])
        for earlier, later in pairs:
            if later["spec_revision"] <= installed_after_revision:
                continue
            if earlier["spec_revision"] >= target_revision:
                break
            if fragment in frag_sets[earlier["spec_revision"]] \
                    and fragment not in frag_sets[later["spec_revision"]]:
                for unit in units:
                    if earlier["spec_revision"] < unit["spec_revision_after"] \
                            <= later["spec_revision"]:
                        if unit["tx_hash"] not in found:
                            found.append(unit["tx_hash"])
                break
        return found

    ledger: List[Dict] = []
    for unit in units:
        after_snap = snapshot_at_or_after(unit["spec_revision_after"])
        before_rev = unit["spec_revision_before"]
        before_snap = snapshot_at_or_before(
            before_rev if before_rev is not None else -1)
        after_frags = frag_sets.get(after_snap["spec_revision"], set()) \
            if after_snap else set()
        before_frags = frag_sets.get(before_snap["spec_revision"], set()) \
            if before_snap else set()
        installed = [f for f in spec_fragments(after_snap["spec_text"])
                     if f in after_frags - before_frags] if after_snap else []
        surviving = [f for f in installed if f in target_frags]
        lost = []
        displaced_by: List[str] = []
        for frag in installed:
            if frag in target_frags:
                continue
            killers = displacers_of(
                frag, after_snap["spec_revision"] if after_snap else 0)
            # A unit never displaces its own footprint.
            killers = [k for k in killers if k != unit["tx_hash"]]
            lost.append({"fragment": frag, "displaced_by": killers})
            for k in killers:
                if k not in displaced_by:
                    displaced_by.append(k)
        if not lost:
            status = "in_force"
        elif not surviving:
            status = "displaced"
        else:
            status = "partially_displaced"
        ledger.append({
            "tx_hash": unit["tx_hash"],
            "block_number": unit["block_number"],
            "spec_revision_before": unit["spec_revision_before"],
            "spec_revision_after": unit["spec_revision_after"],
            "outcome": unit["outcome"],
            "status": status,
            "displaced_by": displaced_by,
            "installed_fragments": installed,
            "surviving_fragments": surviving,
            "displaced_fragments": lost,
        })
    return ledger


def attribute_rules(spec_text: str, account: str) -> Tuple[List[str], List[str]]:
    """Split the effective spec for one account.

    Returns (account_rules, unattributed): the statements guarded by exactly
    this account, and the statements that cannot be attributed to a single
    account (no i12 guard, or guards naming several accounts). Statements
    guarded by exactly one OTHER account are attributable -- just not to
    this one -- and are omitted from both lists.
    """
    acct = normalize_account(account)
    mine: List[str] = []
    unattributed: List[str] = []
    for stmt in split_statements(spec_text):
        guards = guard_accounts(stmt)
        if guards == {acct}:
            mine.append(stmt)
        elif len(guards) != 1:
            unattributed.append(stmt)
    return mine, unattributed
