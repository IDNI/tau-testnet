"""Does this account judge the payments made TO it, and would it take this one?

Capability reporting for recipient-side policy:

    getrecipientpolicy <address>
    getrecipientpolicy <address> <sender> <amount>

The first form answers from consensus state alone: whether the receive stream
(i17) is active on this chain, and whether the address's registered o5 clause
reads it. The second form also asks the clause, for one concrete payment, whether
it would be accepted and how long a retractable transfer may be held.

The probe is ADVISORY and node-local, like `getapprovalpreview`: a clause may
read the clock and the payer's balance, so the answer is for now, and the
verdict that binds is the one at admission and apply.
"""
import api_response
import tau_admission
import tau_defs
from consensus import recipient_policy, sender_policy
from consensus.approvals import ApprovalShapeError, _normalize_pubkey
from consensus.retractable import MAX_RELEASE_WINDOW_SECONDS

_CMD = "getrecipientpolicy"
_USAGE = f"Usage: {_CMD} <address> [<sender> <amount>]"


def _probe(clause: str, sender: str, recipient: str, amount: int, tip) -> dict:
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

    def allows(value: int) -> bool:
        try:
            blocked, _detail = sender_policy.clause_blocks(
                clause, recipient_policy.receive_inputs(base, value),
                pool="admission", timeout=tau_admission.default_budget(),
            )
        except WorkerTimeout as exc:
            raise tau_admission.AdmissionTimeout(str(exc)) from exc
        except (WorkerLost, SpeculationError) as exc:
            raise tau_admission.AdmissionUnavailable(str(exc)) from exc
        return not blocked

    if not allows(tau_defs.RECEIVE_FINAL_NOW):
        return {
            "accepts_payment": False,
            "max_hold_seconds": None,
            "accepts_height_release": False,
        }
    cap = recipient_policy.max_accepted_hold(
        allows, tau_defs.RECEIVE_HOLD_UNBOUNDED, MAX_RELEASE_WINDOW_SECONDS
    )
    return {
        "accepts_payment": True,
        # None: no cap within the longest window the chain admits for a park.
        "max_hold_seconds": None if cap is None or cap >= MAX_RELEASE_WINDOW_SECONDS else cap,
        "accepts_height_release": allows(tau_defs.RECEIVE_HOLD_UNBOUNDED),
    }


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (2, 4):
        return api_response.error_response(_CMD, _USAGE, "INVALID_PARAMS")
    try:
        address = _normalize_pubkey(parts[1])
        sender = _normalize_pubkey(parts[2]) if len(parts) == 4 else None
        amount = int(parts[3]) if len(parts) == 4 else None
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
        # Consensus state: whether the node feeds i17 and asks recipients at all.
        "active": active,
        "receive_stream": f"i{tau_defs.RECEIVE_STREAM_INDEX}",
        "receive_stream_width": tau_defs.RECEIVE_STREAM_BV_WIDTH,
        "address": address,
        "has_clause": clause is not None,
        # True: every payment to this address is also judged by its own clause.
        "judges_incoming": active and reads,
        "clause": clause if reads else None,
    }

    if sender is not None:
        if not (active and reads):
            data["probe"] = {
                "sender": sender, "amount": amount, "advisory": True,
                "accepts_payment": True, "max_hold_seconds": None,
                "accepts_height_release": True,
            }
        else:
            try:
                probe = _probe(clause, sender, address, amount, tip)
            except (tau_admission.AdmissionTimeout,
                    tau_admission.AdmissionUnavailable) as exc:
                return api_response.error_response(
                    _CMD, f"The policy evaluator could not answer: {exc}",
                    "TAU_UNAVAILABLE",
                )
            data["probe"] = {"sender": sender, "amount": amount, "advisory": True, **probe}
            data["note"] = (
                "The probe asks the clause as of now. A clause may read the clock "
                "and the payer's balance, so admission and apply decide."
            )
    return api_response.success_response(_CMD, data)
