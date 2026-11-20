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
"""
import re

import api_response

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

    data = {
        "available": True,
        "spec_revision": snapshot["spec_revision"],
        "height": snapshot["height"],
        "canonical_text": snapshot["canonical_text"],
        "sha256": snapshot["sha256"],
    }
    if height is not None:
        data["requested_height"] = height
    if account is not None:
        rules, unattributed = split_conjuncts_by_account(
            snapshot["canonical_text"], account
        )
        data["account"] = account
        data["rules"] = rules
        data["unattributed"] = unattributed
    return api_response.success_response("getactiverules", data)
