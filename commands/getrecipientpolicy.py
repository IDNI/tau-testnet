"""Would this recipient accept this payment? Advisory, node-local (#47, #76).

    getrecipientpolicy <recipient>
        whether recipient controls are active, whether the account has an o5
        clause, and whether that clause judges incoming payments (it does
        exactly when it reads i17)

    getrecipientpolicy <recipient> <sender> <amount> [<hold> <seconds|blocks>]
        the verdict admission would give this payment, through the same
        helper block apply calls. A refused hold carries the same cap.

A hold of 0, or a call with no hold, is a plain payment. The hold is the
length the clause would see, not a release point: apply still measures a
real park against the block that carries it. i2 and i12 stay the sender's,
as they do on the transfer the helper judges.
"""
import api_response
import tau_admission
import tau_defs
from consensus.approvals import ApprovalShapeError, _normalize_pubkey
from consensus.recipient_policy import (
    CODE_PLAIN,
    HEIGHT_CODE_BASE,
    clause_reads_hold_stream,
    controls_active,
    recipient_refusal,
)
from consensus.retractable import (
    MAX_RELEASE_WINDOW_BLOCKS,
    MAX_RELEASE_WINDOW_SECONDS,
)

_CMD = "getrecipientpolicy"
_USAGE = (
    f"Usage: {_CMD} <recipient> [<sender> <amount> [<hold> <seconds|blocks>]]"
)


def _tip():
    from consensus.facade import TipAdmissionView
    return TipAdmissionView()


def _hold_code(hold: int, unit: str) -> int:
    if unit == "seconds":
        if hold > MAX_RELEASE_WINDOW_SECONDS:
            raise ValueError(
                f"hold seconds must be 0 .. {MAX_RELEASE_WINDOW_SECONDS}"
            )
        return CODE_PLAIN if hold == 0 else 1 + hold
    if hold > MAX_RELEASE_WINDOW_BLOCKS:
        raise ValueError(
            f"hold blocks must be 0 .. {MAX_RELEASE_WINDOW_BLOCKS}"
        )
    return CODE_PLAIN if hold == 0 else HEIGHT_CODE_BASE + hold


def _payment_inputs(tip, sender: str, recipient: str, amount: int) -> dict:
    """The transfer map admission builds, without custom inputs.

    Key order matches the admission transfer step. i2 and i12 are the sender.
    """
    from commands.sendtx import (
        _admission_i2,
        _admission_timestamp,
        _approval_slot_feed,
    )

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


def _parse(parts):
    if len(parts) not in (2, 4, 6):
        raise ValueError(_USAGE)
    recipient = _normalize_pubkey(parts[1])
    if len(parts) == 2:
        return recipient, None, None, CODE_PLAIN, None
    sender = _normalize_pubkey(parts[2])
    amount = int(parts[3])
    if amount < 1 or amount > tau_defs.MAX_TRANSFER_VALUE:
        raise ValueError(
            f"amount must be 1 .. {tau_defs.MAX_TRANSFER_VALUE}"
        )
    unit = None
    hold = 0
    if len(parts) == 6:
        hold = int(parts[4])
        unit = parts[5]
        if hold < 0 or unit not in ("seconds", "blocks"):
            raise ValueError(
                "hold must be a non-negative integer and the unit "
                "seconds or blocks"
            )
    code = _hold_code(hold, unit or "seconds")
    return recipient, sender, amount, code, unit


def execute(raw_command: str, container):
    parts = raw_command.split()
    try:
        recipient, sender, amount, hold_code, unit = _parse(parts)
    except (ApprovalShapeError, TypeError, ValueError) as exc:
        message = str(exc) if str(exc) else _USAGE
        return api_response.error_response(_CMD, message, "INVALID_PARAMS")

    tip = _tip()
    active = controls_active(tip)
    body = tip.clause_for(recipient, tau_defs.USER_POLICY_STREAM_INDEX) or ""
    data = {
        "advisory": True,
        "recipient": recipient,
        "recipient_controls_active": active,
        "has_policy_clause": bool(body),
        "judges_incoming": bool(active and clause_reads_hold_stream(body)),
    }
    if sender is None:
        return api_response.success_response(_CMD, data)

    data["sender"] = sender
    data["amount"] = str(amount)
    if unit == "blocks":
        data["hold_blocks"] = 0 if hold_code == CODE_PLAIN else hold_code - HEIGHT_CODE_BASE
    else:
        data["hold_seconds"] = 0 if hold_code == CODE_PLAIN else hold_code - 1

    if not active or not clause_reads_hold_stream(body):
        data["allowed"] = True
        return api_response.success_response(_CMD, data)

    from commands.sendtx import _policy_call

    budget = tau_admission.default_budget()
    try:
        refusal = _policy_call(lambda: recipient_refusal(
            body,
            _payment_inputs(tip, sender, recipient, amount),
            hold_code,
            pool="admission",
            timeout=budget,
        ))
    except tau_admission.AdmissionTimeout as exc:
        return api_response.error_response(
            _CMD,
            f"Recipient policy evaluation timed out after {budget:g}s.",
            "ADMISSION_TIMEOUT",
            {"timeout_seconds": budget, "detail": str(exc)},
        )
    except tau_admission.AdmissionUnavailable as exc:
        return api_response.error_response(
            _CMD,
            "Recipient policy evaluation is temporarily unavailable.",
            "ADMISSION_UNAVAILABLE",
        )

    data["allowed"] = refusal is None
    if refusal is not None:
        data["code"] = refusal.code
        data["message"] = refusal.message
        data.update(refusal.details)
    return api_response.success_response(_CMD, data)
