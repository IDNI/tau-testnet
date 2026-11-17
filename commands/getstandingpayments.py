"""Standing payments of one account, and the rules the node pays them by (#34).

    getstandingpayments <address> [out|in|all]

`out` lists what the address pays, `in` what it receives, `all` (default) both.
Each entry carries its signed terms, where the sweep stands (`period`,
`period_due`, `period_closes`, `status`), and what it has done so far
(`paid_count`, `missed_count`, `paid_total`, `last_paid_height`).

`semantics` states, from the node's own constants, how payments are made, so a
wallet can show them before it offers the feature, and a node without the
feature answers "unknown command" instead.
"""
import api_response
import chain_state
import consensus.standing as standing
from consensus.standing import StandingBook

_CMD = "getstandingpayments"
_ROLES = ("all", "out", "in")


def semantics() -> dict:
    return {
        "version": 1,
        "tx_types": sorted(standing.STANDING_TX_TYPES),
        "schedules": {
            "blocks": {"interval": [standing.MIN_INTERVAL_BLOCKS, standing.MAX_INTERVAL_BLOCKS],
                       "first_due_ahead_max": standing.MAX_FIRST_DUE_BLOCKS},
            "seconds": {"interval": [standing.MIN_INTERVAL_SECONDS, standing.MAX_INTERVAL_SECONDS],
                        "first_due_ahead_max": standing.MAX_FIRST_DUE_SECONDS,
                        "clock": "block timestamp, UTC"},
            "months": {"interval": [1, standing.MAX_INTERVAL_MONTHS],
                       "first_due_ahead_max": standing.MAX_FIRST_DUE_SECONDS,
                       "clock": "block timestamp, UTC",
                       "missing_day": "last day of the month",
                       "anchor": "every due point is derived from first_due (no drift)"},
        },
        "periods": [1, standing.MAX_PERIODS],
        "window": "a period is payable from its due point until the next one",
        "per_period": "at most one payment; no catch-up of missed periods",
        "no_funds": "retried in later blocks of the same window, then missed; never partial",
        "policy": "the payer's current o5 clause is re-checked on every payment; "
                  "a block misses the period (no retry), approval slots are empty",
        "paid_by": "the end-of-block sweep once a period is due, or an execute "
                   "transaction from anyone, whichever comes first",
        "execute": "standing_payment_execute names only standing_id and pays the period "
                   "the block falls in; refused, with nothing changed, before the first "
                   "due point, after the end, when that period is already settled, "
                   "without funds or when the policy blocks it; earlier periods whose "
                   "window closed unpaid count as missed",
        "update": "standing_payment_update (payer only) ends standing_id as replaced and "
                  "starts the new terms as version + 1 with their own id, in one "
                  "transaction; the old terms are never edited",
        "fee": "one fee when an authorization is created or updated; payments the sweep "
               "makes are fee-free; an execute is paid by its sender",
        "cancel": "payer only, fee-free; a cancel in a block wins over a payment due in it",
        "ordering": "transactions in block order, then the sweep: a cancel or update "
                    "before an execute of the same authorization in a block refuses it",
        "reserved_funds": "none",
        "limits": {"open_per_payer": standing.MAX_OPEN_STANDING_PER_PAYER,
                   "open_total": standing.MAX_OPEN_STANDING_TOTAL,
                   "actions_per_block": standing.MAX_STANDING_ACTIONS_PER_BLOCK,
                   "executes_per_block": standing.MAX_STANDING_EXECUTIONS_PER_BLOCK},
    }


def _tip():
    """(head hash, standing book) as one consistent read of the canonical tip."""
    with chain_state._balance_lock, chain_state._sequence_lock, chain_state._rules_lock:
        lm = chain_state._lifecycle_manager
        head = getattr(chain_state, "_canonical_head_hash", None)
    book = getattr(lm, "standing_payments", None)
    return head, book if isinstance(book, StandingBook) else StandingBook()


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

    head, book = _tip()
    rows = []
    for sid, terms, progress in book.for_account(address):
        if role == "out" and terms.payer_pubkey != address:
            continue
        if role == "in" and terms.recipient_pubkey != address:
            continue
        rows.append(book.describe(sid))
    rows.sort(key=lambda r: (r["schedule"], r["period_due"], r["standing_id"]))
    return api_response.success_response(_CMD, {
        "address": address,
        "role": role,
        "block_hash": head,
        "payments": rows,
        "semantics": semantics(),
    })
