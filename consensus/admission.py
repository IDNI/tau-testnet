from typing import Any, Dict, Optional
import os
import json
import logging

import config
import tau_defs
from tau_manager import communicate_with_tau
from consensus.serialization import compute_update_id
from consensus.facade import TipAdmissionView
from consensus.governance import normalize_validator_delta, normalize_validator_set

logger = logging.getLogger(__name__)

class AdmissionResult:
    def __init__(self, is_valid: bool, error: Optional[str] = None, data: Optional[Dict] = None):
        self.is_valid = is_valid
        self.error = error
        self.data = data or {}

def format_error(msg: str) -> AdmissionResult:
    return AdmissionResult(False, error=msg)

def success(data: Optional[Dict] = None) -> AdmissionResult:
    return AdmissionResult(True, data=data)


def _open_governance_admission() -> bool:
    return bool(getattr(config.settings.authority, "open_governance_admission", False))


def validate_user_tx_reserved_domains(tx: Dict, tip_view: TipAdmissionView) -> AdmissionResult:
    """
    Ensure user_tx does not interact with governance fields or reserved domains.
    """
    for restricted_field in ("rule_revisions", "activate_at_height", "host_contract_patch", "update_id", "approve"):
        if restricted_field in tx:
            return format_error(f"user_tx must not contain governance field: {restricted_field}")
            
    operations = tx.get("operations", {})
    if not isinstance(operations, dict):
        return format_error("Missing or invalid 'operations' in user_tx.")

    for key, val in operations.items():
        if not str(key).isdigit():
            continue
        idx = int(key)
        # Block attempts to use reserved streams in application transactions natively
        if 6 <= idx <= 11:
            return format_error(f"Invalid operation target '{key}'. Streams 6-11 are reserved for consensus ABI inputs.")

    # Screen user rule TEXT for consensus output streams. A user rule
    # writing o6/o7 (block validity / eligibility) or o9 (consensus fee)
    # would conflict with the voted consensus rules in the composed spec
    # (unsat -> DoS) or forge consensus verdicts/fees. Crude token scan,
    # same precedent as the warn-only governance check below — but HARD
    # for user txs (comment false-positives are an accepted trade-off;
    # governance revisions stay exempt because writing these streams is
    # their legitimate job).
    rule_text = operations.get("0")
    if isinstance(rule_text, str) and rule_text:
        for stream_token in ("o6", "o7", "o9"):
            if stream_token in rule_text:
                return format_error(
                    f"user_tx rule text references reserved consensus output stream '{stream_token}'."
                )

    return success()

def _check_host_contract_patch(patch: dict, active_validators: Optional[Any] = None) -> Optional[str]:
    """Static checks for host contract parameters to ensure future-proofing definitions."""
    if "proof_scheme" in patch and patch["proof_scheme"] != "bls_header_sig":
        return f"Unsupported proof_scheme inside host_contract_patch: {patch['proof_scheme']}"
    if "fork_choice_scheme" in patch and patch["fork_choice_scheme"] != "height_then_hash":
        return f"Unsupported fork_choice_scheme inside host_contract_patch: {patch['fork_choice_scheme']}"
    if "input_contract_version" in patch and patch["input_contract_version"] != 1:
        return f"Unsupported input_contract_version inside host_contract_patch: {patch['input_contract_version']}"
    if "validator_additions" in patch or "validator_removals" in patch:
        try:
            additions = set(normalize_validator_delta(patch.get("validator_additions"), "validator_additions"))
            removals = set(normalize_validator_delta(patch.get("validator_removals"), "validator_removals"))
            validators = normalize_validator_set(active_validators or [])
        except ValueError as exc:
            return str(exc)
        overlap = additions & removals
        if overlap:
            return f"Validator pubkey cannot be both added and removed: {sorted(overlap)[0][:10]}"
        next_validators = (validators - removals) | additions
        if not next_validators:
            return "Validator delta would leave no active validators."
    return None

def validate_consensus_rule_update_payload(tx: Dict, tip_view: TipAdmissionView) -> AdmissionResult:
    """
    Validate the core fields and parameters of a consensus_rule_update payload.
    """
    sender = tx.get("sender_pubkey")
    if not _open_governance_admission() and sender not in tip_view.active_validators:
        return format_error(f"Proposer {sender[:10]} is not an active validator.")

    if "rule_revisions" not in tx or not isinstance(tx["rule_revisions"], list) or len(tx["rule_revisions"]) == 0:
        return format_error("Missing or invalid 'rule_revisions' list. Must be a non-empty list.")
    
    for rev in tx["rule_revisions"]:
        if not isinstance(rev, str):
            return format_error("Every entry in 'rule_revisions' must be a string.")

    h_activate = tx.get("activate_at_height")
    if not isinstance(h_activate, int) or h_activate < 1 or h_activate > 0xFFFFFFFFFFFFFFFF:
        return format_error("Invalid or missing 'activate_at_height'. Must be integer inside range (1 <= x < 2^64).")
        
    patch = tx.get("host_contract_patch")
    if patch is not None:
        if not isinstance(patch, dict):
            return format_error("'host_contract_patch' must be a JSON dictionary if provided.")
        patch_err = _check_host_contract_patch(patch, tip_view.active_validators)
        if patch_err:
            return format_error(patch_err)

    required_min_height = tip_view.next_block_height + len(tip_view.active_validators)
    if h_activate < required_min_height:
        return format_error(f"Minimum activation delay explicitly breached: {h_activate} < {required_min_height}")

    try:
        update_id = compute_update_id(tx["rule_revisions"], tx["activate_at_height"], tx.get("host_contract_patch"))
    except ValueError as e:
        return format_error(f"Canonical derivation failed dynamically: {e}")
        
    state = tip_view.get_update_lifecycle_state(update_id.hex())
    if state is not None:
        return format_error(f"update_id {update_id.hex()[:10]} already exists in lifecycle state: {state}")

    return success({"update_id": update_id.hex()})

def stage_and_validate_consensus_revisions(tx: Dict, tip_view: TipAdmissionView) -> AdmissionResult:
    """
    Structural and isolated-compile checks for a consensus_rule_update payload.

    The historical implementation concatenated each `rev` onto the current
    consensus rules string and shipped that lump through the LIVE `i0`, which:
      a) produced a multi-`always` spec that Tau's parser rejects, and
      b) silently mutated live interpreter state (the `apply_rules_update` flag
         is ignored in `tau_native.TauInterface.communicate`).

    Production fix: build a throwaway interpreter from the current consensus
    rules text and feed each revision through `i0` on that isolated instance.
    Live mining state is never touched, and unparseable revisions are rejected
    here instead of at the activation height inside the proposer's
    `apply_block`. See `tau_native.TauInterface.compile_revisions_isolated`.

    Pass order:
      1. warn-only ABI check on the joined revisions,
      2. warn-only shadowing check on reserved consensus streams,
      3. per-revision preprocessing (syntax shape, normalization),
      4. isolated staging compile against current consensus rules.
    """
    revisions = tx["rule_revisions"]

    joined_for_abi_check = "\n".join(revisions)

    # Static ABI validation (warn-only). Activation will hard-fail if the
    # post-spec doesn't actually compile, so we don't reject here on a string
    # absence alone.
    if (tau_defs.TAU_OUTPUT_STREAM_BLOCK_VALID not in joined_for_abi_check
            or tau_defs.TAU_OUTPUT_STREAM_ELIGIBLE not in joined_for_abi_check):
        logger.warning("ABI boundaries missing o6 or o7 symbols natively.")

    # Warn if a revision touches reserved consensus-ABI streams. Crude string
    # check; Tau itself enforces strict typing at activation.
    for stream_idx in ("i6", "i7", "i8", "i9", "i10", "i11", "o6", "o7"):
        for rev in revisions:
            if stream_idx in rev and "consensus" not in rev:
                logger.warning(f"Revision potentially shadowing {stream_idx}")

    # Per-revision preprocessing (syntax shape). Anything that explodes here
    # would also explode at activation, so reject early.
    import tau_native
    try:
        for rev in revisions:
            tau_native.TauInterface.preprocess_spec_text(rev)
    except Exception as e:
        return format_error(f"Internal compiler failure natively: {e}")

    # Isolated staging compile. Skip if the live Tau interpreter isn't ready
    # (early boot, test fixtures without native bindings) — admission stays
    # available and the activation-height compile remains the backstop.
    import tau_manager
    if tau_manager.tau_ready.is_set():
        try:
            err = tau_native.TauInterface.compile_revisions_isolated(
                tip_view.current_consensus_rules,
                revisions,
            )
        except Exception as e:
            return format_error(f"Consensus update staging compile failed: {e}")
        if err:
            return format_error(f"Consensus update staging compile failed: {err}")

    return success()

def validate_consensus_rule_vote_payload(tx: Dict, tip_view: TipAdmissionView) -> AdmissionResult:
    """
    Validate the core fields and precedence of consensus_rule_vote transactions.
    """
    sender = tx.get("sender_pubkey")
    if not _open_governance_admission() and sender not in tip_view.active_validators:
        return format_error(f"Voter {sender[:10]} is not an active validator.")

    update_id = tx.get("update_id")
    if not isinstance(update_id, str):
         return format_error("Missing or malformed 'update_id' in consensus_vote.")

    approve = tx.get("approve")
    if not isinstance(approve, bool):
         return format_error("Missing or malformed 'approve' in consensus_vote; must be boolean.")
    if not approve:
         return format_error("v1 explicit disapproval explicitly rejected: approve=false is unsupported.")

    status = tip_view.get_update_lifecycle_state(update_id)
    if status is None:
         return format_error(f"Vote points natively to unknown update_id: {update_id[:10]}")
    if status != "pending":
         return format_error(f"Vote targeted update_id {update_id[:10]} resolving to non-pending state: {status}")

    if tip_view.has_duplicate_vote(update_id, sender):
         return format_error(f"Duplicate explicit vote actively suppressed for {sender[:10]} natively on {update_id[:10]}")

    return success()

def validate_mempool_admission(payload: Dict, tip_view: TipAdmissionView) -> AdmissionResult:
    """
    Primary Orchestrator Endpoint for Network Admission logic.
    Delegates dynamic logic independently based cleanly on `tx_type` exclusively.
    """
    tx_type = payload.get("tx_type", "user_tx")
    
    if "consensus_proposal" == tx_type or "bundle" in payload:
        return format_error("Legacy transaction types (consensus_proposal/bundle) explicitly deprecated and rejected natively.")

    if tx_type == "user_tx":
         return validate_user_tx_reserved_domains(payload, tip_view)
         
    elif tx_type == "consensus_rule_update":
         phase_1_eval = validate_consensus_rule_update_payload(payload, tip_view)
         if not phase_1_eval.is_valid:
              return phase_1_eval
              
         phase_2_eval = stage_and_validate_consensus_revisions(payload, tip_view)
         if not phase_2_eval.is_valid:
              return phase_2_eval
              
         # Attach the derived update_id properly
         return phase_1_eval

    elif tx_type == "consensus_rule_vote":
         return validate_consensus_rule_vote_payload(payload, tip_view)

    else:
         return format_error(f"Unknown or unsupported tx_type exclusively restricted natively: {tx_type}")
