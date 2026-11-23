"""Would this recipient accept this payment? Advisory, node-local (#47, #76).

    getrecipientpolicy <recipient>
        what the recipient has deployed: whether recipient policy is active,
        whether the recipient has an o5 clause, and whether that clause judges
        incoming payments (it does exactly when it reads the receive stream i17)

    getrecipientpolicy <recipient> <sender> <amount> [<hold> <seconds|blocks>]
        the verdict the recipient's clause gives this payment at the current tip,
        through the same helper admission and block apply call, plus the
        recipient's cap when a hold is refused

A wallet calls this before it offers to sign: to show "this shop accepts only
instant payments", or to explain a refusal before the payer pays for one.
Advisory in the same sense as checktx: apply judges at the block that carries
the payment, and the recipient may change their rule in between.
"""
import api_response
import tau_admission
import tau_defs
from consensus import sender_policy
from consensus.approvals import ApprovalShapeError, _normalize_pubkey

_CMD = "getrecipientpolicy"
USAGE = (f"Usage: {_CMD} <recipient> [<sender> <amount> "
         f"[<hold> <seconds|blocks>]]")


def _tip_view():
    from consensus.facade import TipAdmissionView
    return TipAdmissionView()


def _payment_inputs(tip, sender: str, recipient: str, amount: int) -> dict:
    """The per-transfer map admission builds for this payment (same keys, same
    literal forms, same order), without custom inputs."""
    from commands.sendtx import _admission_i2, _admission_timestamp, _approval_slot_feed

    values = {
        1: str(amount),
        2: _admission_i2(sender),
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
    }
    for slot in _approval_slot_feed(tip):
        values[slot] = "0"
    values[5] = str(_admission_timestamp())
    return values


def _judge(tip, body, sender, recipient, amount, hold):
    from commands.sendtx import _admission_i2, _policy_call

    budget = tau_admission.default_budget()
    values = _payment_inputs(tip, sender, recipient, amount)
    own = _admission_i2(recipient)

    def blocked(h):
        return _policy_call(lambda: sender_policy.recipient_clause_blocks(
            body, values, recipient, h, pool="admission",
            owner_balance=own, timeout=budget))[0]

    result = {"allowed": not blocked(hold)}
    if result["allowed"]:
        return result
    in_blocks = isinstance(hold, tau_defs.HeldBlocks)
    unit = "blocks" if in_blocks else "seconds"
    if hold != 0 and not blocked(0):
        cap = _policy_call(lambda: sender_policy.recipient_hold_cap(
            body, values, recipient, blocks=in_blocks, pool="admission",
            owner_balance=own, held=hold, timeout=budget))
        result["code"] = "RECIPIENT_MAX_HOLD"
        result[f"max_hold_{unit}"] = cap
    else:
        result["code"] = "RECIPIENT_POLICY"
    return result


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (2, 4, 6):
        return api_response.error_response(_CMD, USAGE, "INVALID_PARAMS")
    try:
        recipient = _normalize_pubkey(parts[1])
        sender = _normalize_pubkey(parts[2]) if len(parts) > 2 else None
        amount = int(parts[3]) if len(parts) > 3 else None
        hold = 0
        if len(parts) == 6:
            n = int(parts[4])
            if n < 0 or parts[5] not in ("seconds", "blocks"):
                raise ValueError("hold must be a non-negative integer and the unit seconds or blocks")
            hold = tau_defs.HeldBlocks(n) if parts[5] == "blocks" else n
        if amount is not None and not 0 <= amount <= tau_defs.MAX_TRANSFER_VALUE:
            raise ValueError(f"amount must be between 0 and {tau_defs.MAX_TRANSFER_VALUE}")
    except (ApprovalShapeError, TypeError, ValueError) as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    tip = _tip_view()
    active = tip.recipient_policy_active
    body = tip.clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX)
    inbound = bool(body) and sender_policy.reads_receive_stream(body)
    data = {
        "recipient": recipient,
        "recipient_policy_active": active,
        "has_policy_clause": bool(body),
        "judges_incoming": active and inbound,
    }
    if sender is None:
        return api_response.success_response(_CMD, data)

    data.update({"sender": sender, "amount": amount,
                 "hold": int(hold), "hold_unit": "blocks" if isinstance(hold, tau_defs.HeldBlocks) else "seconds"})
    if not data["judges_incoming"]:
        data.update({"allowed": True, "neutral_default": True})
        return api_response.success_response(_CMD, data)
    try:
        data.update(_judge(tip, body, sender, recipient, amount, hold))
    except tau_admission.AdmissionTimeout as exc:
        return api_response.error_response(_CMD, str(exc), "ADMISSION_TIMEOUT")
    except tau_admission.AdmissionUnavailable as exc:
        return api_response.error_response(_CMD, str(exc), "ADMISSION_UNAVAILABLE")
    return api_response.success_response(_CMD, data)
