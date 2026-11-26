"""The active-rules view (issue #42, bounty 02).

    getactiverules [account] [height]

Serves the rules actually in force from the node's canonical spec
snapshots -- the canonical spec text composed pointwise from the
persisted application-rules accumulation, captured at apply time
whenever a rule step advances the spec revision (see
db.record_spec_snapshots). The text is composed from the accumulation
itself (the units `save_effective_tau_spec` maintains), never read from
the live interpreter or its process-global spec cache: that cache holds
a possibly shrunk, process-local form, and under worker-backed
authority it need not describe the executing session at all. The
accumulation is the same text the node's startup restore seeds the
interpreter with, so its composition is the spec the engine runs. And it is
the composition, NOT the raw append-only accumulation `gettaustate`
returns: submitted text is not rules in force, because a later revision
can displace part of an earlier one, and only the composed spec shows
what survived.

Resolution: `height` selects the latest snapshot at or before it; with no
height, the newest snapshot is served. A height before the first snapshot
answers with an explicit not-available result -- the view never guesses
from later state and never falls back to the accumulation.

With `account` (a 96-hex-char public key), the response also splits the
effective text's top-level conjuncts by attribution: `rules` holds the
conjuncts whose guard binds i12 to exactly that account, and every other
conjunct -- unguarded, or guarded on something else, or binding i12 to
more than one account -- is listed under `unattributed` rather than
dropped or guessed at.

The response also carries the per-unit survival ledger (`units`),
derived read-side from the snapshot sequence itself -- no extra state
is recorded for it. A unit is the set of conjuncts one revision's step
introduced; each conjunct is tracked across successive snapshots, so a
unit reads `in_force`, `partially_displaced` or `displaced`, and a
displaced conjunct names the revision that displaced it, the
transaction that landed on that revision (from the recorded rule
outcomes), and the conjunct that replaced it. The ledger is derived as
of the snapshot being served: asked at a past height, it reports the
survival known at that height, never from later state.
"""
import re

import api_response
from consensus import active_rules

# An i12 equality binding to a bit-vector literal, in either operand order:
# the guard form rules use to scope themselves to one sender,
# `( i12[t]:bv[384] = { #x<sender> }:bv[384] -> ... )`.
_I12_BINDING_RE = re.compile(
    r"i12\[t\](?::bv\[\d+\])?\s*=(?!=)\s*\{\s*#x([0-9a-fA-F]+)\s*\}:bv\[\d+\]"
    r"|\{\s*#x([0-9a-fA-F]+)\s*\}:bv\[\d+\]\s*=(?!=)\s*i12\[t\](?::bv\[\d+\])?"
)

_ACCOUNT_HEX_LEN = 96  # a BLS public key, and the width of the i12 stream


def _normalize_account(hex_text: str) -> str:
    """Canonical account form: the 384-bit value as 96 lowercase hex chars.

    Compared by value, so a literal written with or without leading zeros
    names the same account.
    """
    value = int(hex_text, 16)
    return format(value, "x").rjust(_ACCOUNT_HEX_LEN, "0").lower()


def _is_account_token(token: str) -> bool:
    return len(token) == _ACCOUNT_HEX_LEN and all(
        c in "0123456789abcdefABCDEF" for c in token
    )


def _split_at_depth_zero(text: str, separator: str):
    """Split `text` on `separator` occurrences at nesting depth zero.

    Depth counts (), [] and {} together: Tau literals and subformulas nest
    all three, and a separator inside any of them is not a boundary.
    """
    parts = []
    depth = 0
    start = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and text.startswith(separator, i):
            parts.append(text[start:i])
            i += len(separator)
            start = i
            continue
        i += 1
    parts.append(text[start:])
    return parts


def _unit_body(unit: str) -> str:
    """The formula inside an `always ( ... )` unit; the unit itself otherwise."""
    stripped = unit.strip()
    if stripped.startswith("always"):
        rest = stripped[len("always"):].strip()
        if rest.startswith("("):
            # The opening paren must wrap the whole rest of the unit.
            depth = 0
            for idx, ch in enumerate(rest):
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        if idx == len(rest) - 1:
                            return rest[1:-1]
                        break
    return stripped


def top_level_conjuncts(canonical_text: str):
    """The top-level conjuncts of a canonical spec text.

    The text is a sequence of `.`-terminated units; each unit contributes
    its `always ( ... )` body split on top-level `&&` (or itself, when it
    has no always wrapper). Conjuncts are returned in text order, stripped.
    """
    conjuncts = []
    for unit in _split_at_depth_zero(canonical_text or "", "."):
        if not unit.strip():
            continue
        for piece in _split_at_depth_zero(_unit_body(unit), "&&"):
            piece = piece.strip()
            if piece:
                conjuncts.append(piece)
    return conjuncts


def _conjunct_accounts(conjunct: str):
    """The distinct accounts a conjunct's guard binds i12 to (by value)."""
    accounts = set()
    for match in _I12_BINDING_RE.finditer(conjunct):
        literal = match.group(1) or match.group(2)
        accounts.add(_normalize_account(literal))
    return accounts


def split_conjuncts_by_account(canonical_text: str, account: str):
    """(the account's conjuncts, the unattributed rest), in text order.

    A conjunct belongs to the account only when its guard binds i12 to that
    one account and no other; anything else is unattributed.
    """
    mine = []
    unattributed = []
    for conjunct in top_level_conjuncts(canonical_text):
        if _conjunct_accounts(conjunct) == {account}:
            mine.append(conjunct)
        else:
            unattributed.append(conjunct)
    return mine, unattributed


# A whole conjunct that is one plain output-stream definition -- the only
# form a later revision can displace pointwise (the composer's rule in
# consensus/engine.py, matched here so the ledger can name what replaced
# a displaced conjunct).
_PLAIN_ASSIGNMENT_STREAM_RE = re.compile(
    r"^(o\d+)\[t\]:bv\[\d+\]\s*=\s*\{\s*(?:[0-9]+|#x[0-9a-fA-F]+)\s*\}:bv\[\d+\]$"
)


def _displacing_conjunct(displaced: str, present):
    """The conjunct in `present` that took `displaced`'s place, or None.

    Displacement is pointwise over plain assignments: the displacer is
    the same stream's definition in the newer text. A displaced conjunct
    of any other form has no single named replacement.
    """
    match = _PLAIN_ASSIGNMENT_STREAM_RE.match(displaced)
    if match is None:
        return None
    stream = match.group(1)
    for conjunct in present:
        candidate = _PLAIN_ASSIGNMENT_STREAM_RE.match(conjunct)
        if candidate is not None and candidate.group(1) == stream:
            return conjunct
    return None


def derive_unit_ledger(snapshots, tx_by_revision):
    """The per-unit survival ledger over a snapshot sequence.

    `snapshots` is the recorded snapshot sequence (oldest revision
    first, see db.get_all_spec_snapshots); `tx_by_revision` maps a
    spec_revision to the transaction whose rule step landed on it (see
    db.get_rule_tx_by_revision), or is empty when no outcomes were
    recorded -- attribution then reads None, never a guess.

    A conjunct instance is born at the first snapshot whose text
    contains it and survives while every later snapshot still contains
    it; the first snapshot without it is the revision that displaced
    it. (A verbatim re-submission changes no snapshot, so it is not a
    separate unit: the ledger counts units as they land in the composed
    spec, which is the only existence a wallet can act on.) Instances
    born at the same revision form one unit -- one rule step lands one
    unit -- and the unit's status follows its conjuncts: all surviving
    is `in_force`, none is `displaced`, a mix is `partially_displaced`.
    """
    instances = []
    live = {}
    for snapshot in snapshots:
        revision = snapshot["spec_revision"]
        present = top_level_conjuncts(snapshot["canonical_text"])
        present_set = set(present)
        for text, instance in list(live.items()):
            if text not in present_set:
                instance["displaced_at_revision"] = revision
                instance["displaced_by_tx"] = tx_by_revision.get(revision)
                instance["displaced_by"] = _displacing_conjunct(text, present)
                del live[text]
        for text in present:
            if text not in live:
                instance = {
                    "conjunct": text,
                    "introduced_at_revision": revision,
                    "introduced_at_height": snapshot["height"],
                    "displaced_at_revision": None,
                    "displaced_by_tx": None,
                    "displaced_by": None,
                }
                instances.append(instance)
                live[text] = instance

    units = []
    by_revision = {}
    for instance in instances:
        revision = instance["introduced_at_revision"]
        unit = by_revision.get(revision)
        if unit is None:
            unit = {
                "introduced_at_revision": revision,
                "introduced_at_height": instance["introduced_at_height"],
                "introduced_by_tx": tx_by_revision.get(revision),
                "status": "in_force",
                "conjuncts": [],
                "surviving_conjuncts": [],
                "displaced_conjuncts": [],
            }
            by_revision[revision] = unit
            units.append(unit)
        unit["conjuncts"].append(instance["conjunct"])
        if instance["displaced_at_revision"] is None:
            unit["surviving_conjuncts"].append(instance["conjunct"])
        else:
            unit["displaced_conjuncts"].append({
                "conjunct": instance["conjunct"],
                "displaced_at_revision": instance["displaced_at_revision"],
                "displaced_by_tx": instance["displaced_by_tx"],
                "displaced_by": instance["displaced_by"],
            })
    for unit in units:
        if unit["displaced_conjuncts"] and not unit["surviving_conjuncts"]:
            unit["status"] = "displaced"
        elif unit["displaced_conjuncts"]:
            unit["status"] = "partially_displaced"
    return units


def execute(raw_command: str, container):
    parts = raw_command.split()
    if not 1 <= len(parts) <= 3:
        return api_response.error_response(
            "getactiverules",
            "Usage: getactiverules [account] [height]",
            "INVALID_PARAMS",
        )
    account = None
    height = None
    for token in parts[1:]:
        if token.isdigit():
            if height is not None:
                return api_response.error_response(
                    "getactiverules", "height given twice", "INVALID_PARAMS"
                )
            height = int(token)
        elif _is_account_token(token):
            if account is not None:
                return api_response.error_response(
                    "getactiverules", "account given twice", "INVALID_PARAMS"
                )
            account = _normalize_account(token)
        else:
            return api_response.error_response(
                "getactiverules",
                "arguments must be an account (96 hex characters) and/or a height",
                "INVALID_PARAMS",
            )

    db = container.db
    try:
        if height is not None:
            snapshot = db.get_spec_snapshot_at_height(height)
        else:
            snapshot = db.get_latest_spec_snapshot()
    except Exception as exc:
        return api_response.error_response(
            "getactiverules", f"Failed to resolve spec snapshot: {exc}",
            "INTERNAL_ERROR",
        )

    if snapshot is None:
        # Explicit, per the design: snapshots exist only from the change
        # forward, and a height before the first one has no honest answer.
        data = {"available": False}
        if height is not None:
            data["requested_height"] = height
        data["message"] = (
            "no spec snapshot at or before the requested height"
            if height is not None
            else "no spec snapshot recorded yet"
        )
        return api_response.success_response("getactiverules", data)

    # Step 7 stopgap (B02 §2): serve the journal cut's text + sha256
    # when the stored snapshot diverges from the replayed journal at
    # the snapshot's own height. The snapshot is the fast path and is
    # served unchanged when it agrees; the check only replaces a
    # divergent snapshot. When NO snapshot exists the answer stays
    # not-available (the wipe contract: a wiped node answers
    # available:false) -- the cut is never substituted for a missing
    # snapshot here. The unit ledger below is derived from the CHECKED
    # snapshot sequence (O-4 (a)): the ledger describes the served
    # state, so each snapshot is mapped through the Step 7 check
    # before the ledger reads it -- the stored text and the served
    # text diverge on builtin 02 (the worker's fed form is shrunk to
    # bv[8]; the journal cut renders full-width bv[384]), so a ledger
    # read from the stored text attributes units to a state the view
    # does not serve. The permanent fix unifies the two
    # canonicalizations; until then the ledger reads the checked text
    # by construction, and the stored-vs-cut divergence is visible
    # only through the derived="journal_cut" marker.
    view = active_rules.checked_snapshot_answer(snapshot)
    if view is None:
        # O-2: the served snapshot's own journal-cut check held (its
        # cut is TAMPERED) -- hold, do not serve the snapshot. Fail
        # closed for integrity, with the code carried so the caller
        # can say why the view is unavailable.
        data = {"available": False}
        if height is not None:
            data["requested_height"] = height
        data["message"] = (
            "the journal cut for the served snapshot is TAMPERED; "
            "the active rules are not available")
        data["cut_status"] = active_rules.CUT_TAMPERED
        return api_response.success_response("getactiverules", data)
    data = {
        "available": True,
        "spec_revision": view["spec_revision"],
        "height": view["height"],
        "canonical_text": view["spec_text"],
        "sha256": view["spec_hash"],
    }
    if view.get("derived") is not None:
        data["derived"] = view["derived"]
    try:
        sequence, sequence_code = active_rules.checked_snapshot_sequence(
            db.get_all_spec_snapshots(
                upto_revision=snapshot["spec_revision"]))
    except Exception as exc:
        return api_response.error_response(
            "getactiverules",
            f"Failed to check the snapshot sequence: {exc}",
            "INTERNAL_ERROR",
        )
    if sequence is None:
        # O-2: a snapshot in the served history fails its journal-cut
        # check (TAMPERED) -- hold, do not serve a ledger over a
        # history whose integrity is broken. (Defense in depth: the
        # journal is append-only, so a tampered entry in an earlier
        # cut is in every later cut too -- the served snapshot's own
        # check would hold first; this branch catches the same failure
        # if the sequence is ever checked on its own.)
        data = {"available": False}
        if height is not None:
            data["requested_height"] = height
        data["message"] = (
            "the journal cut for a snapshot in the served history is "
            "TAMPERED; the active rules are not available")
        data["cut_status"] = sequence_code
        return api_response.success_response("getactiverules", data)
    try:
        data["units"] = derive_unit_ledger(
            sequence, db.get_rule_tx_by_revision()
        )
    except Exception as exc:
        return api_response.error_response(
            "getactiverules", f"Failed to derive unit ledger: {exc}",
            "INTERNAL_ERROR",
        )
    if height is not None:
        data["requested_height"] = height
    if account is not None:
        rules, unattributed = split_conjuncts_by_account(
            view["spec_text"], account
        )
        data["account"] = account
        data["rules"] = rules
        data["unattributed"] = unattributed
    return api_response.success_response("getactiverules", data)
