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
import tau_admission
import tau_defs
import tau_manager
from consensus.approvals import (
    MAX_PREVIEW_SLOTS,
    ApprovalShapeError,
    _normalize_index_map,
    _normalize_pubkey,
)
from consensus import recipient_policy, sender_policy

_CMD = "getapprovalpreview"


def _o5_allows(outputs):
    o5 = outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
    # Same semantics as the transfer path: absent allows, BLOCK blocks,
    # unparseable fails closed.
    return not (o5 is not None
                and tau_manager.parse_tau_output(o5) == tau_defs.USER_POLICY_BLOCK_VALUE)


def _own_clause_allows(clause, inputs):
    """False when the sender's own registered clause blocks these inputs."""
    from tau_speculation import SpeculationError, WorkerLost, WorkerTimeout

    try:
        blocked, _detail = sender_policy.clause_blocks(
            clause,
            # A previewed approval transfer carries no retractable hold;
            # the hold streams are fed (zeroed) so every clause evaluation
            # sees them, as on the transfer path.
            recipient_policy.with_hold(inputs),
            pool="admission",
            timeout=tau_admission.default_budget(),
        )
    except WorkerTimeout as exc:
        raise tau_admission.AdmissionTimeout(str(exc)) from exc
    except (WorkerLost, SpeculationError) as exc:
        raise tau_admission.AdmissionUnavailable(str(exc)) from exc
    return not blocked


def _step(inputs, clause=None):
    # The in-process interpreter holds no user rules under worker-backed authority.
    if tau_admission.enabled():
        raise RuntimeError("the in-process interpreter cannot answer under authority")
    return _o5_allows(tau_manager.communicate_with_tau_multi(
        input_stream_values=inputs, apply_rules_update=False,
    )) and _own_clause_allows(clause, inputs)


def _enumerate(slots, base, candidates, step):
    """Probe subsets by increasing size until one allows; `step` -> allows."""
    results = []
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
            results.append((list(subset), step(inputs)))
        if any(allows for _s, allows in results):
            # Smallest cardinality that works; ties break on lowest slot
            # index because `combinations` yields them in that order.
            break
    return results


def _guard_blocks(guard, kind, timestamp, voted):
    """True when the guard blocks; worker failures map to the admission errors."""
    from tau_speculation import SpeculationError, WorkerLost, WorkerTimeout

    try:
        blocked, _detail = sender_policy.rule_change_blocked(
            lambda _sender, _stream: guard, "", kind, timestamp,
            pool="admission", timeout=tau_admission.default_budget(), voted=voted,
        )
    except WorkerTimeout as exc:
        raise tau_admission.AdmissionTimeout(str(exc)) from exc
    except (WorkerLost, SpeculationError) as exc:
        raise tau_admission.AdmissionUnavailable(str(exc)) from exc
    return blocked


def _rule_change_screen(request, tip):
    from consensus import admission
    from consensus.rule_offers import clause_body_v1

    error = admission._rule_change_precondition_error(request, tip)
    if not error:
        if request.kind == tau_defs.RULE_CHANGE_KIND_SET_POLICY:
            error = admission._screen_clause_domains(request.body)
        elif request.kind == tau_defs.RULE_CHANGE_KIND_SET_GUARD:
            error = admission._screen_guard_domains(request.body)
        elif request.kind == tau_defs.RULE_CHANGE_KIND_ACCEPT_OFFER:
            error = admission._screen_clause_domains(clause_body_v1(request.rule_text))
    return {"ok": not error, "error": error or None}


def _execute_rule_change(draft):
    from commands.getapprovalrequests import KIND_NAMES
    from consensus.approvals import (
        TX_TYPE_RULE_CHANGE_REQUEST,
        parse_rule_change_request_checked,
    )
    from consensus.facade import TipAdmissionView

    tx = {
        "tx_type": TX_TYPE_RULE_CHANGE_REQUEST,
        "sender_pubkey": draft.get("sender_pubkey") or draft.get("sender"),
        "sequence_number": 0,
        "expire_at_height": 0,
        "kind": draft.get("kind"),
        "rule_text": draft.get("rule_text", ""),
        "offer_id": draft.get("offer_id", ""),
        "approvers": draft.get("approvers") or {},
    }
    request, why = parse_rule_change_request_checked(tx)
    if request is None:
        return api_response.error_response(_CMD, why, "INVALID_PARAMS")

    tip = TipAdmissionView()
    if request.approvers and not tip.approval_slots_active:
        return api_response.error_response(
            _CMD, "Co-signature approvals are not active on this chain.",
            "FEATURE_INACTIVE",
        )

    candidates = dict(request.approvers)
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
    bad_slot = next((s for s in sorted(candidates)
                     if s not in tau_defs.approval_slot_indices()), None)
    if bad_slot is not None:
        return api_response.error_response(
            _CMD, f"i{bad_slot} is not an approval slot.", "INVALID_PARAMS"
        )

    guard = tip.clause_for(request.sender_pubkey, tau_defs.RULE_CHANGE_GUARD_INDEX)
    data = {
        "request_type": "rule_change",
        "advisory": True,
        "available": True,
        "kind": request.kind,
        "kind_name": KIND_NAMES.get(request.kind, "unknown"),
        "has_guard": bool(guard),
        "screen": _rule_change_screen(request, tip),
        "escape_delay_blocks": tau_defs.RULE_CHANGE_DELAY_BLOCKS,
    }
    if not guard:
        data.update({
            "executes_immediately": True,
            "required_slots": [],
            "required_approvers": {},
            "allowing_subsets": [[]],
            "satisfiable": True,
            "probes": 0,
        })
        return api_response.success_response(_CMD, data)

    timestamp = tip.next_block_timestamp
    slots = sorted(candidates)
    probes = 0
    allowing = []
    try:
        for size in range(0, len(slots) + 1):
            for subset in itertools.combinations(slots, size):
                probes += 1
                voted = {idx: candidates[idx] for idx in subset}
                if not _guard_blocks(guard, request.kind, timestamp, voted):
                    allowing.append(list(subset))
            if allowing:
                break
    except tau_admission.AdmissionUnavailable as exc:
        return api_response.success_response(_CMD, {
            "advisory": True,
            "available": False,
            "reason": f"the approval preview could not be evaluated: {exc}",
        })
    except Exception as exc:
        return api_response.error_response(
            _CMD, f"Evaluation failed: {exc}", "TAU_ERROR"
        )

    minimal = allowing[0] if allowing else None
    data.update({
        "executes_immediately": minimal == [],
        "required_slots": minimal,
        "required_approvers": ({str(i): candidates[i] for i in minimal}
                              if minimal is not None else None),
        "allowing_subsets": allowing,
        "satisfiable": minimal is not None,
        "probes": probes,
    })
    return api_response.success_response(_CMD, data)


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

    if draft.get("request_type") == "rule_change" or "kind" in draft:
        return _execute_rule_change(draft)

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
    clause = tip.clause_for(sender, tau_defs.USER_POLICY_STREAM_INDEX)
    if tau_admission.enabled():
        # The in-process interpreter holds consensus rules only; the user's o5
        # policy lives in the authority, so the probe runs in a context of its own.
        try:
            with tau_admission.open_context(label="approval_preview") as ctx:
                results = _enumerate(
                    slots, base, candidates,
                    lambda inputs: (_o5_allows(ctx.step(inputs))
                                    and _own_clause_allows(clause, inputs)),
                )
        except (tau_admission.AdmissionUnavailable, tau_admission.StepRefused) as exc:
            return api_response.success_response(_CMD, {
                "advisory": True,
                "available": False,
                "reason": f"the approval preview could not be evaluated: {exc}",
            })
        except Exception as exc:
            return api_response.error_response(
                _CMD, f"Evaluation failed: {exc}", "TAU_ERROR"
            )
    else:
        # Hold the engine lock for the WHOLE probe so no other evaluation
        # interleaves and re-types a stream between subsets.
        try:
            with tau_manager.tau_comm_lock:
                results = _enumerate(
                    slots, base, candidates, lambda inputs: _step(inputs, clause)
                )
        except Exception as exc:
            return api_response.error_response(
                _CMD, f"Evaluation failed: {exc}", "TAU_ERROR"
            )

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
