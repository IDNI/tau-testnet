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
* `getactiverules` serves those snapshots and, for an account, attributes
  the effective text's top-level statements by the `i12` guard each one
  carries. Displaced clauses are absent by construction: the source is the
  engine's normalized spec after revision, not the submitted text.

Snapshots are stored data. Replay does not re-run the rules handler, so a
replayed node verifies the recorded revision progression rather than
recomputing snapshots; heights before the first snapshot have none.
"""
from __future__ import annotations

import hashlib
import logging
import re
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


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
        return db.get_latest_spec_snapshot()
    snap = db.get_spec_snapshot_at_or_before(int(height))
    if snap is not None:
        return snap
    return db.get_earliest_spec_snapshot()


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
