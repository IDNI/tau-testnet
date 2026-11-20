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
    """
    import db

    if target is None:
        target = db.get_latest_spec_snapshot()
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
    target_frags = frag_sets.get(target_revision, set())

    units = [
        row for row in db.list_rule_outcomes()
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
