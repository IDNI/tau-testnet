"""Pre-flight read of one address's recipient policy (issues #47/#76).

ADVISORY and node-local, like `getapprovalslots`: this is the ONLY place a
recipient clause's hold behaviour is evaluated outside a real transfer, and
it is never consensus-binding. A wallet asks before sending money at
someone: does this recipient restrict inbound payments at all, and — for a
named sender and hold — would THIS payment be refused, and with what cap?

Usage: getrecipientpolicy <address> [<sender> [<hold> <seconds|blocks> [<amount>]]]

- With only an address: whether the gate is active, whether the address has
  a clause, whether that clause opts into inbound judging, and the escrow
  the recipient currently holds inbound (context, not a verdict).
- With a sender, hold and unit: the clause is judged for that payer
  (`sender_policy.recipient_clause_blocks`, the same helper admission and
  apply use), so a hold refusal carries the cap verified against this
  payer's own evaluation — the number a wallet prints ("accepts payments
  held for up to ..."). A rule-shaped cap is reported honestly as
  `cap_kind: "rule"` with no number.
"""
import api_response
import tau_defs
from consensus import sender_policy
from consensus.approvals import ApprovalShapeError, _normalize_pubkey

_CMD = "getrecipientpolicy"

_UNIT_CONTEXTS = {
    "seconds": tau_defs.CONTEXT_INCOMING_TIME_PARK,
    "second": tau_defs.CONTEXT_INCOMING_TIME_PARK,
    "s": tau_defs.CONTEXT_INCOMING_TIME_PARK,
    "blocks": tau_defs.CONTEXT_INCOMING_HEIGHT_PARK,
    "block": tau_defs.CONTEXT_INCOMING_HEIGHT_PARK,
    "b": tau_defs.CONTEXT_INCOMING_HEIGHT_PARK,
}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD,
            f"Usage: {_CMD} <address> [<sender> [<hold> <seconds|blocks> [<amount>]]]",
            "INVALID_PARAMS",
        )
    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    # Parse the judgement arguments BEFORE touching the tip: a malformed
    # hold or unit is a usage error, not a database lookup.
    sender = None
    hold = None
    context = None
    amount = 0
    if len(parts) >= 5:
        try:
            sender = _normalize_pubkey(parts[2])
        except ApprovalShapeError as exc:
            return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
        try:
            hold = int(parts[3])
            if hold < 0:
                raise ValueError
        except ValueError:
            return api_response.error_response(
                _CMD, "hold must be a non-negative integer", "INVALID_PARAMS")
        context = _UNIT_CONTEXTS.get(parts[4].lower())
        if context is None:
            return api_response.error_response(
                _CMD, "unit must be seconds or blocks", "INVALID_PARAMS")
        if len(parts) > 5:
            try:
                amount = int(parts[5])
                if amount < 0:
                    raise ValueError
            except ValueError:
                return api_response.error_response(
                    _CMD, "amount must be a non-negative integer", "INVALID_PARAMS")

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    active = tip.recipient_policy_active
    clause = tip.clause_for(address, tau_defs.USER_POLICY_STREAM_INDEX)
    inbound_capable = bool(clause) and sender_policy.clause_is_inbound_capable(clause)

    payload = {
        "address": address,
        "advisory": True,
        "recipient_policy_active": active,
        "has_clause": clause is not None,
        "clause": clause,
        "inbound_capable": inbound_capable,
        # No inbound-capable clause means the neutral default: the recipient
        # accepts everything, parks of any length included.
        "neutral_default": not inbound_capable,
        "escrowed_in": tip.escrowed_in(address),
        "hold_stream": tau_defs.HOLD_STREAM_INDEX,
        "context_stream": tau_defs.CONTEXT_STREAM_INDEX,
        "contexts": {
            "outgoing": tau_defs.CONTEXT_OUTGOING,
            "incoming_final": tau_defs.CONTEXT_INCOMING_FINAL,
            "incoming_time_park": tau_defs.CONTEXT_INCOMING_TIME_PARK,
            "incoming_height_park": tau_defs.CONTEXT_INCOMING_HEIGHT_PARK,
        },
    }
    if not active:
        payload["note"] = (
            "Recipient controls are not active on this chain; no recipient "
            "clause is evaluated for inbound transfers. A clause reading "
            "i17/i16 cannot deploy until governance activates the feature."
        )
        return api_response.success_response(_CMD, payload)

    if len(parts) < 5:
        payload["note"] = (
            "Advisory: pass <sender> <hold> <seconds|blocks> to judge a "
            "concrete payment against this recipient's clause."
        )
        return api_response.success_response(_CMD, payload)

    # The transfer input map for a hypothetical payment, judged exactly as
    # admission judges a real one (same helper, same pool). i2 is 0: the
    # preflight cannot know the sender's parent-block balance, and a
    # recipient cap must not depend on it.
    values = {
        1: str(amount),
        2: "0",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + address + " }:bv[384]",
        5: str(tip.next_block_timestamp),
        12: "{ #x" + sender + " }:bv[384]",
    }
    try:
        blocked, info = sender_policy.recipient_clause_blocks(
            tip.clause_for, address, values,
            hold=hold, context=context, pool="admission",
        )
    except Exception as exc:  # evaluator loss says nothing about the transfer
        return api_response.error_response(
            _CMD, f"recipient policy evaluation unavailable: {exc}",
            "EVALUATION_UNAVAILABLE")

    payload["judged"] = {
        "sender": sender,
        "hold": hold,
        "unit": "seconds" if context == tau_defs.CONTEXT_INCOMING_TIME_PARK else "blocks",
        "amount": amount,
        "blocked": blocked,
    }
    if info is not None:
        judged = dict(info)
        judged.pop("o5", None)
        payload["judged"].update(judged)
    payload["note"] = (
        "Advisory: judged with the admission evaluator against the tip "
        "clause; a real transfer is judged again at admission and at apply."
    )
    return api_response.success_response(_CMD, payload)
