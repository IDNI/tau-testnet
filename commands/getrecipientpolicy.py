"""Pre-flight read of one address's recipient policy (issues #47/#76).

Read-only. Answers the two questions a payer's wallet asks before it parks
money at someone: does this recipient restrict inbound payments at all, and
would THIS payment — this sender, this amount, this hold — be admitted?

The second question is answered by running the gate itself
(`sender_policy.recipient_clause_blocks`, the same helper admission and
apply use) against a hypothetical transfer, so the answer cannot drift from
what the chain will do. When the recipient's rule is a threshold rule, a
refusal carries the cap verified against this payer's own evaluation —
`max_hold_seconds` / `max_hold_blocks` — which is the number a wallet may
print ("accepts payments held for up to ..."). A rule-shaped cap is
reported honestly as `cap_kind: "rule"` with no number.
"""
import time

import api_response
import tau_defs
from consensus import sender_policy
from consensus.approvals import _normalize_pubkey, ApprovalShapeError

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
    if len(parts) not in (2, 6):
        return api_response.error_response(
            _CMD,
            f"Usage: {_CMD} <address> [sender amount hold unit]",
            "INVALID_PARAMS",
        )
    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    if not tip.recipient_policy_active:
        return api_response.error_response(
            _CMD, "Recipient controls are not active on this chain.",
            "FEATURE_INACTIVE",
        )

    clause = tip.clause_for(address, tau_defs.USER_POLICY_STREAM_INDEX)
    inbound_capable = bool(clause) and sender_policy.clause_is_inbound_capable(clause)
    data = {
        "address": address,
        "has_clause": clause is not None,
        "inbound_capable": inbound_capable,
        # No inbound-capable clause means the neutral default: the recipient
        # is judged exactly as before this feature existed.
        "neutral_default": not inbound_capable,
    }

    if len(parts) == 6:
        try:
            sender = _normalize_pubkey(parts[2])
            amount = int(parts[3])
            hold = int(parts[4])
        except (ApprovalShapeError, ValueError) as exc:
            return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
        context = _UNIT_CONTEXTS.get(parts[5].lower())
        if context is None:
            return api_response.error_response(
                _CMD, "unit must be 'seconds' or 'blocks'", "INVALID_PARAMS"
            )
        import chain_state

        values = {
            1: str(amount),
            2: str(chain_state.get_balance(sender)),
            3: "{ #x" + sender + " }:bv[384]",
            4: "{ #x" + address + " }:bv[384]",
            12: "{ #x" + sender + " }:bv[384]",
            5: str(int(time.time())),
        }
        blocked, info = sender_policy.recipient_clause_blocks(
            tip.clause_for, address, values,
            hold=hold, context=context, pool="admission",
        )
        data["evaluation"] = {
            "sender": sender,
            "amount": amount,
            "hold": hold,
            "unit": "seconds" if context == tau_defs.CONTEXT_INCOMING_TIME_PARK
                    else "blocks",
            "admitted": not blocked,
        }
        if blocked:
            data["evaluation"].update({
                k: v for k, v in (info or {}).items() if k != "o5"
            })

    return api_response.success_response(_CMD, data)
