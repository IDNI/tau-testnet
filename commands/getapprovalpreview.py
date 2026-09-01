"""Which approvers does THIS transfer actually need? Advisory, node-local.

Takes a COMPLETE request draft, not just an amount: a policy clause may
legitimately depend on i2 (balance), i4 (recipient), i5 (the clock) and the
sender's custom inputs, so an amount-only probe would answer a different question
than the one asked at execution.

Enumerates the subsets of the candidate slots and returns the smallest that makes
o5 allow. NOT a greedy probe: greedy is only minimal for a clause that is
monotone in approvals, and "the all-slots probe blocks, therefore no subset
works" is simply false for one that is not. Subsets are capped, and above the cap
this reports `unavailable` rather than a wrong answer.
"""
import itertools
import json

import api_response
import tau_defs
import tau_manager
from consensus.approvals import (
    MAX_PREVIEW_SLOTS,
    ApprovalShapeError,
    _normalize_index_map,
    _normalize_pubkey,
)

_CMD = "getapprovalpreview"


def _step(inputs):
    outputs = tau_manager.communicate_with_tau_multi(
        input_stream_values=inputs, apply_rules_update=False,
    )
    o5 = outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
    # Same semantics as the transfer path: absent allows, BLOCK blocks,
    # unparseable fails closed.
    return not (o5 is not None
                and tau_manager.parse_tau_output(o5) == tau_defs.USER_POLICY_BLOCK_VALUE)


def execute(raw_command: str, container):
    parts = raw_command.split(None, 1)
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <json_draft>", "INVALID_PARAMS"
        )
    text = parts[1].strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1]
    try:
        draft = json.loads(text)
    except Exception as exc:
        return api_response.error_response(_CMD, f"Invalid JSON: {exc}", "PARSE_ERROR")
    if not isinstance(draft, dict):
        return api_response.error_response(
            _CMD, "Draft must be a JSON object.", "INVALID_PARAMS"
        )

    try:
        sender = _normalize_pubkey(draft.get("sender_pubkey"))
        recipient = _normalize_pubkey(draft.get("recipient_pubkey"))
        amount = int(draft.get("amount"))
        candidates = {idx: _normalize_pubkey(pk) for idx, pk in
                      _normalize_index_map(draft.get("approvers"), "approvers").items()}
        customs = {idx: str(v) for idx, v in
                   _normalize_index_map(draft.get("custom_inputs"), "custom_inputs").items()}
    except (ApprovalShapeError, TypeError, ValueError) as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    from consensus.facade import TipAdmissionView

    tip = TipAdmissionView()
    if not tip.approval_slots_active:
        return api_response.error_response(
            _CMD, "Co-signature approvals are not active on this chain.",
            "FEATURE_INACTIVE",
        )

    if len(candidates) > MAX_PREVIEW_SLOTS:
        return api_response.success_response(_CMD, {
            "advisory": True,
            "available": False,
            "reason": (
                f"{len(candidates)} candidate slots exceeds the {MAX_PREVIEW_SLOTS} "
                f"this can enumerate ({2 ** MAX_PREVIEW_SLOTS} subsets); declare "
                f"approvers explicitly rather than trusting a partial search."
            ),
        })

    if not tau_manager.tau_ready.is_set():
        return api_response.error_response(
            _CMD, "Tau engine is not ready.", "TAU_UNAVAILABLE"
        )

    # The same input map an ordinary transfer would be judged on.
    import chain_state
    import time as _time

    base = {
        1: str(amount),
        2: str(chain_state.get_balance(sender)),
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
    }
    for k, v in customs.items():
        base[k] = v
    # i5 is advisory here exactly as it is at admission: this is a preview, and
    # apply is authoritative.
    base[5] = str(int(_time.time()))

    slots = sorted(candidates)
    results = []
    # Hold the engine lock for the WHOLE probe so no other evaluation
    # interleaves and re-types a stream between subsets.
    with tau_manager.tau_comm_lock:
        for size in range(0, len(slots) + 1):
            for subset in itertools.combinations(slots, size):
                inputs = dict(base)
                for idx in tau_defs.approval_slot_indices():
                    inputs[idx] = "0"
                for idx in subset:
                    # WRAPPED, exactly as i3/i4/i12 above. tau_shrink interns the
                    # bv[384] pubkey literals in a clause down to bv[8] ids and
                    # recognises a value to intern by this shape; bare hex skips
                    # interning and overflows the interned slot stream
                    # ("bit-vector size 8 too small to hold value ...").
                    inputs[idx] = (
                        "{ #x" + candidates[idx] + " }:bv[%d]"
                        % tau_defs.APPROVAL_SLOT_BV_WIDTH
                    )
                try:
                    allows = _step(inputs)
                except Exception as exc:
                    return api_response.error_response(
                        _CMD, f"Evaluation failed: {exc}", "TAU_ERROR"
                    )
                results.append((list(subset), allows))
            if any(allows for _s, allows in results):
                # Smallest cardinality that works; ties break on lowest slot
                # index because `combinations` yields them in that order.
                break

    minimal = next((s for s, allows in results if allows), None)
    all_slots_allows = any(allows for s, allows in results if len(s) == len(slots))

    return api_response.success_response(_CMD, {
        "advisory": True,
        "available": True,
        "required_slots": minimal,
        "required_approvers": ({str(i): candidates[i] for i in minimal}
                              if minimal is not None else None),
        "needs_no_approval": minimal == [],
        "satisfiable": minimal is not None,
        "probes": len(results),
        "note": (
            "Advisory. Subsets are enumerated, not searched greedily, so this is "
            "minimal even for a clause that is not monotone in approvals. "
            "`satisfiable: false` means no subset of the candidates you offered "
            "makes your own policy allow this transfer."
        ) if minimal is not None or not all_slots_allows else None,
    })
