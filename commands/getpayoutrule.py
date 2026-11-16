"""An account's payout rule: what it pays, where it stands, what it did (#63).

    getpayoutrule <address>

Answers the installed rule with its signed terms (rule text, slots, caps,
period, end), where it stands now (`spent_this_period`, `left_this_period`,
`executions`, `paid_total`) and its history on this node, newest first. An
account without a rule answers `installed: false` with the history, so a
wallet can show that a rule was revoked or ran out.

`semantics` states, from the node's own constants, how payouts work, so a
wallet can explain them before it offers the feature.
"""
import time

import api_response
import chain_state
import consensus.payout as payout
from consensus.payout import PayoutBook, describe

_CMD = "getpayoutrule"


def semantics() -> dict:
    return {
        "version": 1,
        "tx_types": sorted(payout.PAYOUT_TX_TYPES),
        "rules_per_account": 1,
        "slots": [1, payout.MAX_SLOTS],
        "executor_data": payout.MAX_DATA,
        "abi": {
            "i2": "the account's balance at the parent block, bv[24]",
            "i5": "block timestamp, bv[64]",
            "i6": "block height, bv[64]",
            "i13": "executor public key, bv[384]",
            "i26": "paid by the rule in the current period, bv[24]",
            "i30..i37": "recipient of slot k, bv[384] (0 for an open slot nobody named)",
            "i40..i47": "executor data k, bv[24] (0 when not given)",
            "o30..o37": "amount for slot k, bv[24] (0 when not written)",
        },
        "periods": {
            "blocks": [1, payout.MAX_PERIOD_BLOCKS],
            "seconds": [1, payout.MAX_PERIOD_SECONDS],
            "anchor": "the period count starts where the rule was installed",
        },
        "lifetime_max": {"blocks": payout.MAX_LIFETIME_BLOCKS,
                         "seconds": payout.MAX_LIFETIME_SECONDS},
        "execution": "anyone may execute; the rule is stepped once, all slots are "
                     "paid or none; 1 <= total <= cap_per_execution, the period "
                     "cap and the account's balance",
        "o5": "not consulted; the payout rule is the account's own second "
              "authorization for its money",
        "rule_change_guard": "install, replace and revoke are rule changes "
                             "(kinds 6 and 7): a guarded account uses a "
                             "rule_change_request",
        "fee": "the installing account pays one fee; an execution's fee is paid "
               "by its executor; revoke is fee-free",
        "limits": {"rules_total": payout.MAX_PAYOUT_RULES_TOTAL,
                   "executions_per_block": payout.MAX_PAYOUT_EXECUTIONS_PER_BLOCK,
                   "rule_bytes": payout.MAX_RULE_BYTES},
    }


def _tip():
    """(head hash, next height, payout book) as one consistent read of the tip."""
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
    return head, next_height, book if isinstance(book, PayoutBook) else PayoutBook()


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(_CMD, f"Usage: {_CMD} <address>", "INVALID_PARAMS")
    from consensus.approvals import ApprovalShapeError, _normalize_pubkey

    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
    import db

    try:
        history = db.get_canonical_payout_events(address)
    except Exception:
        history = []
    head, next_height, book = _tip()
    terms = book.get(address)
    data = {"address": address, "block_hash": head, "installed": terms is not None}
    if terms is not None:
        data["rule"] = describe(terms, book.state_of(address),
                                height=next_height, ts=int(time.time()))
    data["history"] = history
    data["semantics"] = semantics()
    return api_response.success_response(_CMD, data)
