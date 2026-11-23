"""An account's payout rules: what they pay, where they stand, what they did (#63).

    getpayoutrule <address>

Answers every installed rule with its signed terms (rule text, slots, caps,
period, end), where each stands now (`spent_this_period`, `left_this_period`,
`executions`, `paid_total`) and its history on this node, newest first. An
account without a rule answers `installed: false` with the history, so a
wallet can show that a rule was revoked or ran out.

`rules` lists all of them, in install order. `rule` repeats the single entry
when the account holds exactly one, for clients written against the old
one-rule shape.

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
        "rules_per_account": "many",
        "slots": [1, payout.MAX_SLOTS],
        "executor_data": payout.MAX_DATA,
        "abi": {
            "i2": "the account's balance at the parent block, bv[24]",
            "i5": "block timestamp, bv[64]",
            "i6": "block height, bv[64]",
            "i13": "executor public key, bv[384]",
            "i26": "paid by the rule in the current period, bv[24]",
            "i27": "only with per_sale: the amount of the sale the execution names, bv[24]",
            "i28": "only with per_sale: who paid it, bv[384]",
            "i30..i37": "recipient of slot k, bv[384] (0 for an open slot nobody named)",
            "i40..i47": "executor data k, bv[24] (0 when not given)",
            "i48": "the clock at which the rule was installed, bv[64]",
            "i49": "the clock of its last paid execution, bv[64]",
            "o30..o37": "amount for slot k, bv[24] (0 when not written)",
        },
        "periods": {
            "blocks": [1, payout.MAX_PERIOD_BLOCKS],
            "seconds": [1, payout.MAX_PERIOD_SECONDS],
            "anchor": "the period count starts where the rule was installed, "
                      "or at periods_from where the rule names one",
        },
        "lifetime_max": {"blocks": payout.MAX_LIFETIME_BLOCKS,
                         "seconds": payout.MAX_LIFETIME_SECONDS},
        "due_points": "a rule with due_at is run by the node at that point, and "
                      "again every due_every / due_months; a point that could not "
                      "pay is retried while its window is open, then counted missed",
        "on_arrival": "a per-sale rule with on_arrival is run by the node once "
                      "per arrival, for every kind of credit (signed transfer, "
                      "retractable release, approver release, payout leg)",
        "sealed": "a rule installed with sealed refuses every transaction the "
                  "account signs until the rule ends",
        "update": "payout_rule_update names (account, rule_id) and new terms: "
                  "the old version is resolved as superseded and the new one "
                  "keeps its lineage, version + 1, with a fresh schedule",
        "max_fee": "max_fee_per_execution bounds the fee_limit of a manual "
                   "payout_execute",
        "execution": "anyone may execute; the rule is stepped once, all slots are "
                     "paid or none; 1 <= total <= cap_per_execution, the period "
                     "cap and the account's balance",
        "o5": "not consulted; the payout rule is the account's own second "
              "authorization for its money",
        "rule_change_guard": "install, update and revoke are rule changes "
                             "(kinds 6 and 7): a guarded account uses a "
                             "rule_change_request",
        "fee": "the installing or updating account pays one fee; an execution's "
               "fee is paid by its executor; revoke is fee-free",
        "limits": {"rules_total": payout.MAX_PAYOUT_RULES_TOTAL,
                   "executions_per_block": payout.MAX_PAYOUT_EXECUTIONS_PER_BLOCK,
                   "due_runs_per_block": payout.MAX_PAYOUT_DUE_RUNS_PER_BLOCK,
                   "arrival_runs_per_block": payout.MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK,
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
    now = int(time.time())
    lineage_by_id = getattr(book, "_lineage_by_id", {}) or {}
    rules = []
    for terms in book.get_rules(address):
        state = book.state_of(address, terms.rule_id)
        lineage = lineage_by_id.get(terms.rule_id, terms.rule_id)
        rules.append(describe(terms, state, height=next_height, ts=now,
                              lineage=lineage))
    data = {"address": address, "block_hash": head, "installed": bool(rules),
            "rules": rules}
    if len(rules) == 1:
        data["rule"] = rules[0]
    data["history"] = history
    data["semantics"] = semantics()
    return api_response.success_response(_CMD, data)
