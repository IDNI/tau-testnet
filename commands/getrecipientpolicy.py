"""Does this account judge the payments made TO it, and would it take this one?

Capability reporting for recipient-side policy:

    getrecipientpolicy <address>
    getrecipientpolicy <address> <sender> <amount>
    getrecipientpolicy <address> <sender> <amount> <terms>

The first form answers from consensus state alone: whether the receive record
(i17, i50 to i54) is active on this chain, and whether the address's registered
o5 clause reads it. The second form also asks the clause whether it would take
one concrete payment that is final at once, and how long a payment to it may be
held and stay open to a recall. The third form asks about a payment with
conditions and names the condition that fails:

    <terms> = seconds|blocks [park=N] [hold=N] [recall=N] [limit=N period=N]
              [refund=N|never]

`park=N` is a retractable transfer released N seconds (or blocks) from now:
held for N and open to a recall for N.

The probe is ADVISORY and node-local, like `getapprovalpreview`: a clause may
read the clock and the payer's balance, so the answer is for now, and the
verdict that binds is the one at admission and apply.
"""
import time

import api_response
import tau_admission
import tau_defs
from consensus import recipient_policy, sender_policy
from consensus.approvals import ApprovalShapeError, _normalize_pubkey
from consensus.retractable import MAX_RELEASE_WINDOW_BLOCKS, MAX_RELEASE_WINDOW_SECONDS

_CMD = "getrecipientpolicy"
_USAGE = (
    f"Usage: {_CMD} <address> [<sender> <amount> [seconds|blocks [park=N] [hold=N] "
    f"[recall=N] [limit=N period=N] [refund=N|never]]]"
)
_UNITS = (recipient_policy.SECONDS, recipient_policy.BLOCKS)
_WINDOWS = {
    recipient_policy.SECONDS: MAX_RELEASE_WINDOW_SECONDS,
    recipient_policy.BLOCKS: MAX_RELEASE_WINDOW_BLOCKS,
}
_BOUNDED = (recipient_policy.HOLD, recipient_policy.RECALL)


class _BadTerms(ValueError):
    pass


def _length(name: str, text: str) -> int:
    if not text.isdigit():
        raise _BadTerms(f"{name} must be a whole number, got '{text}'")
    value = int(text)
    if value > tau_defs.RECEIVE_NEVER:
        raise _BadTerms(f"{name} must be at most {tau_defs.RECEIVE_NEVER}")
    return value


def parse_terms(tokens) -> recipient_policy.ReceiveRecord:
    """The record a payment with these terms would be put to the receiver with."""
    if not tokens:
        return recipient_policy.FINAL
    unit, pairs = tokens[0].lower(), tokens[1:]
    if unit not in _UNITS:
        raise _BadTerms("the terms start with the payment's clock: seconds or blocks")
    seen = {}
    for token in pairs:
        name, sep, text = token.partition("=")
        name = name.lower()
        if not sep or name not in ("park", "hold", "recall", "limit", "period", "refund"):
            raise _BadTerms(f"unknown term '{token}'")
        if name in seen:
            raise _BadTerms(f"{name} is given twice")
        if name == "refund" and text.lower() == "never":
            seen[name] = tau_defs.RECEIVE_NEVER
        else:
            seen[name] = _length(name, text)
    if "park" in seen and ("hold" in seen or "recall" in seen):
        raise _BadTerms("park=N already sets the hold and the recall window")
    if ("limit" in seen) != ("period" in seen):
        raise _BadTerms("a spending limit is limit=N together with period=N")
    record = recipient_policy.park_record(unit, seen.pop("park", 0))
    record = record._replace(**seen)
    above = recipient_policy.record_ceiling_error(record)
    if above:
        raise _BadTerms(above)
    return record


def _record_view(record: recipient_policy.ReceiveRecord) -> dict:
    never = tau_defs.RECEIVE_NEVER
    return {
        "kind": int(record.kind),
        "unit": record.unit,
        "hold": int(record.hold),
        "recall": int(record.recall),
        "limit": int(record.limit),
        "period": int(record.period),
        # None: nothing of the payment goes back to the sender by itself.
        "refund": None if int(record.refund) >= never else int(record.refund),
    }


def _open_answer(record) -> dict:
    """The probe of an account that does not judge incoming payments."""
    out = {"accepts_payment": True, "refused_condition": None, "code": None,
           "accepts_height_release": True}
    for condition in _BOUNDED:
        for unit in _UNITS:
            out[f"max_{condition}_{unit}"] = None
    return out


def _probe(clause: str, sender: str, recipient: str, amount: int, record, tip) -> dict:
    """What the clause says about one payment, as the transfer path would ask it."""
    from tau_speculation import SpeculationError, WorkerLost, WorkerTimeout
    import chain_state

    base = {
        1: str(amount),
        2: str(chain_state.get_balance(sender)),
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
    }
    if tip.approval_slots_active:
        for slot in tau_defs.approval_slot_indices():
            base[slot] = "0"
    base[5] = str(tip.next_block_timestamp)

    # One admission budget for the whole probe, however much it asks.
    probe_ends = time.monotonic() + float(tau_admission.default_budget())

    def allows(asked) -> bool:
        left = probe_ends - time.monotonic()
        if left <= 0:
            raise tau_admission.AdmissionTimeout("the probe's budget ran out")
        try:
            blocked, _detail = sender_policy.clause_blocks(
                clause, recipient_policy.receive_inputs(base, asked),
                pool="admission", timeout=left,
            )
        except WorkerTimeout as exc:
            raise tau_admission.AdmissionTimeout(str(exc)) from exc
        except (WorkerLost, SpeculationError) as exc:
            raise tau_admission.AdmissionUnavailable(str(exc)) from exc
        return not blocked

    out = _open_answer(record)
    out["accepts_payment"] = allows(record)
    if not out["accepts_payment"]:
        condition = recipient_policy.refused_condition(allows, record)
        out["refused_condition"] = condition
        out["code"] = recipient_policy.REFUSAL_CODES[condition]
        if condition == recipient_policy.SENDER:
            # A sender the account does not accept learns that and no more.
            for name in list(out):
                if name.startswith("max_"):
                    out[name] = None
            out["accepts_height_release"] = False
            return out

    # The receiver's bounds, each with every other condition at its most
    # permissive value. None: no bound within the longest window the chain
    # admits for a park. 0: nothing of the kind on that clock.
    found = {}
    for unit in _UNITS:
        window = _WINDOWS[unit]
        for condition in _BOUNDED:
            bound = recipient_policy.longest_accepted(allows, unit, condition, None, window)
            found[condition, unit] = bound or 0
            out[f"max_{condition}_{unit}"] = (
                None if found[condition, unit] >= window else found[condition, unit])
    # A release at a height is held, and open to a recall, for a block at least.
    out["accepts_height_release"] = all(
        found[condition, recipient_policy.BLOCKS] > 0 for condition in _BOUNDED)
    return out


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2 or len(parts) == 3:
        return api_response.error_response(_CMD, _USAGE, "INVALID_PARAMS")
    probing = len(parts) >= 4
    try:
        address = _normalize_pubkey(parts[1])
        sender = _normalize_pubkey(parts[2]) if probing else None
        amount = int(parts[3]) if probing else None
        record = parse_terms(parts[4:])
    except _BadTerms as exc:
        return api_response.error_response(_CMD, f"{exc}. {_USAGE}", "INVALID_PARAMS")
    except (ApprovalShapeError, TypeError, ValueError) as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
    if amount is not None and not 0 <= amount <= tau_defs.MAX_TRANSFER_VALUE:
        return api_response.error_response(
            _CMD, f"amount must be 0..{tau_defs.MAX_TRANSFER_VALUE}", "INVALID_PARAMS"
        )

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    active = tip.recipient_policy_active
    clause = tip.clause_for(address, tau_defs.USER_POLICY_STREAM_INDEX)
    reads = bool(clause) and recipient_policy.reads_receive_stream(clause)

    data = {
        # Consensus state: whether the node feeds the record and asks recipients at all.
        "active": active,
        "receive_stream": f"i{tau_defs.RECEIVE_STREAM_INDEX}",
        "receive_record": [f"i{index}" for index in tau_defs.RECEIVE_RECORD_INDICES],
        "receive_stream_width": tau_defs.RECEIVE_STREAM_BV_WIDTH,
        "address": address,
        "has_clause": clause is not None,
        # True: every payment to this address is also judged by its own clause.
        "judges_incoming": active and reads,
        "clause": clause if reads else None,
    }

    if sender is not None:
        asked = {"sender": sender, "amount": amount, "advisory": True,
                 "record": _record_view(record)}
        if not (active and reads):
            data["probe"] = {**asked, **_open_answer(record)}
        else:
            try:
                probe = _probe(clause, sender, address, amount, record, tip)
            except (tau_admission.AdmissionTimeout,
                    tau_admission.AdmissionUnavailable) as exc:
                return api_response.error_response(
                    _CMD, f"The policy evaluator could not answer: {exc}",
                    "TAU_UNAVAILABLE",
                )
            data["probe"] = {**asked, **probe}
            data["note"] = (
                "The probe asks the clause as of now. A clause may read the clock "
                "and the payer's balance, so admission and apply decide."
            )
    return api_response.success_response(_CMD, data)
