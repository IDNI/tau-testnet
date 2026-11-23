"""Standing payments of one account, and the rules the node pays them by (#34).

    getstandingpayments <address> [out|in|all]

`out` lists what the address pays, `in` what it receives, `all` (default) both.
A standing payment is a payout rule with a repeating due schedule and one
fixed slot: the payer pays the payee the rule's fixed amount every period,
without signing again. Each entry carries its signed terms, where the schedule
stands (`period`, `period_due`, `period_closes`, `status`), and what it has
done so far (`paid_count`, `missed_count`, `paid_total`, `last_paid_height`).

`semantics` states, from the node's own constants, how payments are made, so a
wallet can show them before it offers the feature, and a node without the
feature answers "unknown command" instead.
"""
import re
import time

import api_response
import chain_state
import consensus.payout as payout
from consensus.payout import PayoutBook, describe

_CMD = "getstandingpayments"
_ROLES = ("all", "out", "in")

# o30+k[t]:bv[24] = { <constant> }:bv[24] — the fixed amount a standing rule
# pays its one fixed slot. Anything else (an amount computed from inputs) has
# no single amount to show, and `amount` answers None.
_AMOUNT_RE = re.compile(
    r"o(\d+)\[t\]:bv\[24\]\s*=\s*\{\s*(?:#x([0-9a-fA-F]+)|(\d+))\s*\}:bv\[24\]")


def is_standing(terms) -> bool:
    """A payout rule that is a standing payment: a repeating due schedule
    with exactly one fixed slot."""
    return (terms.due_at is not None and terms.repeats
            and sum(1 for slot in terms.slots if slot) == 1)


def _fixed_slot(terms):
    for k, slot in enumerate(terms.slots):
        if slot:
            return k, slot
    return None, None


def _amount_of(terms) -> object:
    slot, _ = _fixed_slot(terms)
    if slot is None:
        return None
    match = _AMOUNT_RE.search(terms.body)
    if match is None or int(match.group(1)) != payout.SLOT_BASE + slot:
        return None
    if match.group(2) is not None:
        return int(match.group(2), 16)
    return int(match.group(3))


def standing_row(terms, state, *, height: int = 0, ts: int = 0) -> dict:
    """One standing payment as a wallet reads it: the old standing shape,
    read off the payout rule behind it, plus the rule itself under `rule`."""
    clock = terms.clock(height, ts) if (height or ts) else None
    next_due = state.next_due(terms)
    if terms.repeats:
        following = terms.due_point(state.due_index + 1)
        period_closes = following if following < terms.expires_at else terms.expires_at
    else:
        period_closes = terms.expires_at
    if state.due_done:
        status = "ended"
    elif next_due is not None and clock is not None and next_due <= clock:
        status = "due"
    else:
        status = "waiting"
    _, recipient = _fixed_slot(terms)
    row = {
        "standing_id": terms.rule_id.hex(),
        "payer_pubkey": terms.account_pubkey,
        "recipient_pubkey": recipient,
        "amount": _amount_of(terms),
        "sequence_number": terms.sequence_number,
        "schedule": ("months" if terms.due_months is not None
                     else payout.KIND_NAMES[terms.kind]),
        "interval": terms.due_every if terms.due_every is not None else terms.due_months,
        "first_due": terms.due_at,
        "periods": None,
        "end": terms.expires_at,
        "period": state.due_index,
        "period_due": next_due,
        "period_closes": period_closes,
        "status": status,
        "tries": 0,
        "paid_count": state.executions,
        "missed_count": state.missed,
        "paid_total": state.paid_total,
        "last_paid_height": state.last_height or None,
        "queued_at": None,
    }
    row["rule"] = describe(terms, state, height=height, ts=ts)
    return row


def semantics() -> dict:
    return {
        "version": 1,
        "tx_types": sorted(payout.PAYOUT_TX_TYPES),
        "schedules": {
            "blocks": {"interval": [payout.MIN_DUE_EVERY_BLOCKS, payout.MAX_PERIOD_BLOCKS],
                       "first_due_ahead_max": payout.MAX_LIFETIME_BLOCKS},
            "seconds": {"interval": [payout.MIN_DUE_EVERY_SECONDS, payout.MAX_PERIOD_SECONDS],
                        "first_due_ahead_max": payout.MAX_LIFETIME_SECONDS,
                        "clock": "block timestamp, UTC"},
            "months": {"interval": [1, payout.MAX_DUE_MONTHS],
                       "first_due_ahead_max": payout.MAX_LIFETIME_SECONDS,
                       "clock": "block timestamp, UTC",
                       "missing_day": "last day of the month",
                       "anchor": "every due point is derived from first_due (no drift)"},
        },
        "periods": "until expires_at (no fixed count)",
        "window": "a due point is payable from its due point until the next one",
        "per_period": "at most one payment per due point; no catch-up of missed points",
        "no_funds": "retried in later blocks of the same window, then missed; never partial",
        "policy": "the payer's o5 clause is not consulted; the payout rule is "
                  "the account's own authorization for these payments",
        "fee": "one fee when the rule is installed or updated; the node runs "
               "due points fee-free; revoke is fee-free",
        "cancel": "payer only, fee-free (payout_rule_revoke); a revoke in a block "
                  "ends every later payment",
        "reserved_funds": "none",
        "limits": {"rules_total": payout.MAX_PAYOUT_RULES_TOTAL,
                   "due_runs_per_block": payout.MAX_PAYOUT_DUE_RUNS_PER_BLOCK,
                   "executions_per_block": payout.MAX_PAYOUT_EXECUTIONS_PER_BLOCK},
    }


def _tip():
    """(head hash, next height, now, payout book) as one consistent read of the tip."""
    with chain_state._balance_lock, chain_state._sequence_lock, chain_state._rules_lock:
        lm = chain_state._lifecycle_manager
        head = getattr(chain_state, "_canonical_head_hash", None)
    book = getattr(lm, "payout_rules", None)
    next_height = 0
    try:
        import db

        block = db.get_canonical_head_block()
        if block:
            next_height = int(block["header"]["block_number"]) + 1
    except Exception:
        pass
    return head, next_height, int(time.time()), \
        book if isinstance(book, PayoutBook) else PayoutBook()


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2].lower() not in _ROLES):
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [out|in|all]", "INVALID_PARAMS"
        )
    from consensus.approvals import ApprovalShapeError, _normalize_pubkey

    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
    role = parts[2].lower() if len(parts) == 3 else "all"

    head, next_height, now, book = _tip()
    seen = set()
    rows = []
    for (account, rule_id), terms in book.terms.items():
        if not is_standing(terms):
            continue
        if rule_id in seen:
            continue
        if role == "out" and account != address:
            continue
        if role == "in" and _fixed_slot(terms)[1] != address:
            continue
        if role == "all" and account != address and _fixed_slot(terms)[1] != address:
            continue
        seen.add(rule_id)
        rows.append(standing_row(terms, book.state[(account, rule_id)],
                                 height=next_height, ts=now))
    rows.sort(key=lambda r: (r["schedule"], r["period_due"] if r["period_due"] is not None else 1 << 62,
                             r["standing_id"]))
    return api_response.success_response(_CMD, {
        "address": address,
        "role": role,
        "block_hash": head,
        "payments": rows,
        "semantics": semantics(),
    })
