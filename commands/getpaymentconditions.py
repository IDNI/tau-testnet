"""Two-sided payment conditions for one hypothetical transfer (issue #42).

Usage: getpaymentconditions <sender> <recipient> <amount> [<height>]

Stage 2 of the #42 design: a payer and a payee must never compare views
from different tips, so both sides of one payment are evaluated against
the SAME block. The answer names the block it answers for (height, hash,
the spec revision in force there) and is advisory: it moves nothing.

What is pinned to the block, and what is not -- stated plainly because
the two come from different records:

* The shared spec is the one in force at the requested block, resolved
  exactly as `getactiverules` resolves it (the stored snapshot, or the
  committed journal cut for a height that predates the snapshots; the
  answer carries `derived` when the cut served it).
* Each side's condition is that account's registered o5 clause (the
  clause registry, key `USER_POLICY_STREAM_INDEX`), evaluated through
  the same helper admission and apply use --
  `consensus.sender_policy.clause_blocks` -- over the same per-transfer
  input map the node builds (i1 amount, i2 sender balance, i3/i4 the
  from/to pubkey literals, i12 the sender literal, i5 the block's
  timestamp, approval slots i18..i25 fed 0 as for an ordinary
  transfer). The view therefore cannot disagree with the node's own
  verdict on the same clause and inputs.
* The clause registry in this codebase is tip state: it holds one
  current clause per (account, stream) and keeps no per-block history,
  so the clauses are read from the current registry and the answer
  says so (`clauses_from: "current_registry"`). At the tip height --
  the default -- the registry and the pinned block describe the same
  state. For a past height, treat the clause side as "the conditions
  as registered now, judged against that block's spec and timestamp".

A side with no registered clause is the neutral default: nothing was
evaluated and nothing blocks. `allowed` is the conjunction of the two
sides. i2 is the sender's current balance (an advisory input; a clause
that reads it judges the balance as it stands, as admission does).
"""
import logging
import time

import api_response
import tau_defs
from consensus import active_rules, sender_policy

logger = logging.getLogger(__name__)

_CMD = "getpaymentconditions"
_USAGE = "Usage: getpaymentconditions <sender> <recipient> <amount> [<height>]"


def _normalize_account(raw):
    """A pubkey as the registry keys it: lowercase hex, no 0x prefix."""
    acct = (raw or "").strip().lower()
    if acct.startswith("0x"):
        acct = acct[2:]
    if len(acct) != 96:
        return None
    try:
        int(acct, 16)
    except ValueError:
        return None
    return acct


def _side(clause_for, account, values):
    """One side's verdict: its registered clause over the transfer map."""
    body = clause_for(account, tau_defs.USER_POLICY_STREAM_INDEX)
    if not body:
        return {"account": account, "has_clause": False,
                "blocked": False, "detail": None}
    blocked, detail = sender_policy.clause_blocks(
        body, values, pool="admission")
    return {"account": account, "has_clause": True,
            "blocked": bool(blocked), "detail": detail}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (4, 5):
        return api_response.error_response(_CMD, _USAGE, "INVALID_PARAMS")
    sender = _normalize_account(parts[1])
    recipient = _normalize_account(parts[2])
    if sender is None or recipient is None:
        return api_response.error_response(
            _CMD, "sender and recipient must be pubkeys (96 hex chars)",
            "INVALID_PARAMS")
    try:
        amount = int(parts[3])
        height = int(parts[4]) if len(parts) == 5 else None
    except ValueError:
        return api_response.error_response(
            _CMD, "amount (and height, when given) must be integers",
            "INVALID_PARAMS")
    if amount < 0 or (height is not None and height < 0):
        return api_response.error_response(
            _CMD, "amount and height must be non-negative", "INVALID_PARAMS")

    import chain_state
    import db
    from consensus.facade import TipAdmissionView

    if height is None:
        height = db.canonical_tip_height()
        if height is None:
            return api_response.success_response(_CMD, {
                "sender": sender, "recipient": recipient,
                "amount": amount, "available": False,
            })

    commit = db.block_commit_at_height(height)
    block_hash = db.canonical_block_hash_at_height(height)
    block_ts = commit.get("block_timestamp") if commit else None
    if block_ts is None:
        block_ts = int(time.time())

    try:
        view = active_rules.resolve_answer(height)
    except Exception as exc:
        logger.exception("Failed to resolve spec view for payment conditions")
        return api_response.error_response(
            _CMD, f"Failed to resolve active rules: {exc}", "INTERNAL_ERROR")

    try:
        balance = chain_state.get_balance(sender)
    except Exception:
        balance = 0
    values = {
        1: str(amount),
        2: str(balance),
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
        5: str(int(block_ts)),
    }
    for slot in tau_defs.approval_slot_indices():
        values[slot] = "0"

    tip = TipAdmissionView()
    try:
        sender_side = _side(tip.clause_for, sender, values)
        recipient_side = _side(tip.clause_for, recipient, values)
    except Exception as exc:
        logger.exception("Failed to evaluate payment conditions")
        return api_response.error_response(
            _CMD, f"Failed to evaluate payment conditions: {exc}",
            "INTERNAL_ERROR")

    data = {
        "sender": sender,
        "recipient": recipient,
        "amount": amount,
        "available": view is not None,
        "advisory": True,
        "block": {
            "height": height,
            "block_hash": block_hash,
            "timestamp": int(block_ts),
        },
        "clauses_from": "current_registry",
        "sender_side": sender_side,
        "recipient_side": recipient_side,
        "allowed": not sender_side["blocked"]
        and not recipient_side["blocked"],
    }
    if view is not None:
        data["spec"] = {
            "spec_revision": view["spec_revision"],
            "spec_hash": view["spec_hash"],
        }
        if view.get("derived"):
            data["spec"]["derived"] = view["derived"]
    return api_response.success_response(_CMD, data)
