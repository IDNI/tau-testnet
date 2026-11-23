"""One standing payment: open with its progress and history, or how it ended.

A standing payment is a payout rule with a repeating due schedule and one
fixed slot, named by its rule id. An id that an update superseded resolves to
the rule's current version.
"""
import re

import api_response
from commands.getstandingpayments import _tip, is_standing, standing_row

_CMD = "getstandingpayment"
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_TERMINAL = (("expired", "ended"), ("revoked", "cancelled"))


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <standing_id>", "INVALID_PARAMS"
        )
    sid = parts[1].strip().lower()
    if not _ID_RE.match(sid):
        return api_response.error_response(
            _CMD, "standing_id must be 64 hex characters.", "INVALID_PARAMS"
        )

    import db

    _head, next_height, now, book = _tip()
    key = bytes.fromhex(sid)
    found = None
    for (account, rule_id), terms in book.terms.items():
        if rule_id == key and is_standing(terms):
            found = (account, terms)
            break
    if found is None:
        # An update superseded this version: resolve its lineage to the
        # current version and answer that one.
        lineage = (getattr(book, "_lineage_by_id", {}) or {}).get(key)
        if lineage is not None:
            current = book.current_id(lineage)
            if current is not None and current != key:
                for (account, rule_id), terms in book.terms.items():
                    if rule_id == current and is_standing(terms):
                        found = (account, terms)
                        break
    if found is not None:
        account, terms = found
        state = book.state[(account, terms.rule_id)]
        try:
            history = db.get_canonical_payout_events_by_rule(terms.rule_id.hex())
        except Exception:
            history = []
        data = standing_row(terms, state, height=next_height, ts=now)
        data["history"] = history
        return api_response.success_response(_CMD, data)

    try:
        history = db.get_canonical_payout_events_by_rule(sid)
    except Exception:
        history = []
    for event in history:  # newest first
        for outcome, status in _TERMINAL:
            if event.get("outcome") == outcome:
                return api_response.success_response(_CMD, {
                    "standing_id": sid,
                    "status": status,
                    "resolved_at_height": event["block_number"],
                    "history": history,
                })
    return api_response.error_response(
        _CMD, f"Unknown standing payment: {sid}", "STANDING_PAYMENT_UNKNOWN"
    )
