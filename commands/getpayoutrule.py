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
        "rules_per_account": payout.MAX_RULES_PER_ACCOUNT,
        "rule_index": "the rule's place on the account: left out for the first, "
                      f"1..{payout.MAX_RULES_PER_ACCOUNT - 1} for the others; a set "
                      "installs or replaces the rule in its place only, a revoke "
                      "names the place (rule_index, or the rule_text of a kind 7 "
                      "request); an execution names the rule by its id",
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
            "i48": "the clock at which the rule was installed, bv[64], on the "
                   "rule's own clock",
            "i49": "the clock of the rule's last paid execution, bv[64] (the "
                   "install clock until one has paid)",
            "o30..o37": "amount for slot k, bv[24] (0 when not written)",
        },
        "periods": {
            "blocks": [1, payout.MAX_PERIOD_BLOCKS],
            "seconds": [1, payout.MAX_PERIOD_SECONDS],
            "anchor": "the period count starts where the rule was installed, or "
                      "at the signed periods_from",
        },
        "due_point": {
            "term": "due_at, on the rule's own clock, signed with the rule",
            "run": "the node steps the rule once in the first block that reaches "
                   "it, after the block's transactions, with no executor (i13 = 0) "
                   "and no named recipient; i2 is the balance the block has reached",
            "runs_per_block": payout.MAX_PAYOUT_DUE_RUNS_PER_BLOCK,
            "fee": "none beyond the fee of the transaction that installed the rule",
            "repeat": "due_every (on the rule's clock, at least "
                      f"{payout.MIN_DUE_EVERY_BLOCKS} blocks or "
                      f"{payout.MIN_DUE_EVERY_SECONDS} seconds) or due_months (1.."
                      f"{payout.MAX_DUE_MONTHS} calendar months, UTC, time clock): the "
                      "node runs the rule at every such point from due_at on, each "
                      "once; a point the chain passed is not caught up",
            "retry": "due_retry (on the rule's clock, at most one period's range): "
                     "a run that found the account short is run again in each "
                     "later block, after the block's due points, at most "
                     f"{payout.MAX_PAYOUT_RETRY_RUNS_PER_BLOCK} a block, longest "
                     "waiting first, until it pays or the clock reaches the due "
                     "point plus due_retry, the next due point or the rule's end; "
                     "a refusal for another reason ends it",
        },
        "on_arrival": {
            "term": "on_arrival: true, with per_sale and a fixed slot",
            "run": "the node steps the rule once for each sale, at the end of the "
                   "block that recorded it, with no executor (i13 = 0); paid or "
                   "not, the sale is closed; money the node moves is never a sale",
            "runs_per_block": payout.MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK,
            "fee": "none: the payer pays the fee of its own payment and nothing more",
        },
        "sealed": {
            "term": "sealed: true",
            "meaning": "while the rule is installed the node takes no transaction "
                       "the account signs and the rule cannot be replaced or "
                       "revoked; money leaves the account by the rule only",
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
    keys = book.keys_of(address)
    now = int(time.time())
    terms = book.get(address)
    data = {"address": address, "block_hash": head, "installed": bool(keys)}
    if terms is not None:
        # the first place, as before several rules per account
        data["rule"] = describe(terms, book.state_of(address), height=next_height, ts=now)
    data["rules"] = [describe(book.get(k), book.state_of(k), height=next_height, ts=now)
                     for k in keys]
    data["history"] = history
    data["semantics"] = semantics()
    return api_response.success_response(_CMD, data)
