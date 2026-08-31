"""Which approver sits in which slot of an address's own policy clause.

ADVISORY and node-local. This is the ONLY place a policy clause's text is
inspected, and it is never consensus-binding: a shape the regex cannot read
returns an empty map and the client falls back to explicit flags.

Why it exists: a client must declare exactly the approvers an amount requires,
because the declaration IS the inbox scoping. The wallet that generated the rule
knows them; a fresh CLI on another machine, or a recovered key, does not — and
guessing means over-declaring, which is the over-notification this feature exists
to avoid.
"""
import re

import api_response
import tau_defs
from consensus.approvals import ApprovalShapeError, _normalize_pubkey

_CMD = "getapprovalslots"

# Deliberately narrow: an approval slot compared for equality against a literal
# 96-hex pubkey, at the frozen width. Anything else is not something this can
# claim to understand.
_SLOT_PAIR_RE = re.compile(
    r"\bi(\d+)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*%d\s*\]\s*=\s*\{\s*#x([0-9a-fA-F]{96})\s*\}"
    % tau_defs.APPROVAL_SLOT_BV_WIDTH
)


def extract_slot_approvers(clause_body: str) -> dict:
    """slot index -> approver pubkey, for the pairs this can read confidently."""
    from consensus.rule_offers import strip_clause_comments

    slots = set(tau_defs.approval_slot_indices())
    found = {}
    for match in _SLOT_PAIR_RE.finditer(strip_clause_comments(clause_body or "")):
        idx = int(match.group(1))
        if idx in slots:
            found.setdefault(idx, match.group(2).lower())
    return dict(sorted(found.items()))


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address>", "INVALID_PARAMS"
        )
    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    if not tip.approval_slots_active:
        return api_response.error_response(
            _CMD, "Co-signature approvals are not active on this chain.",
            "FEATURE_INACTIVE",
        )

    clause = tip.clause_for(address, tau_defs.USER_POLICY_STREAM_INDEX)
    slots = extract_slot_approvers(clause) if clause else {}

    return api_response.success_response(_CMD, {
        "address": address,
        "advisory": True,
        "has_clause": clause is not None,
        "slots": {str(k): v for k, v in slots.items()},
        "unreadable": clause is not None and not slots,
        "note": (
            "Advisory: read from the clause text by pattern, never "
            "consensus-binding. An empty map means the clause shape could not be "
            "read confidently; declare approvers explicitly."
        ),
    })
