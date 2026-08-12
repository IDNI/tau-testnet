from typing import Any, Dict, List, Optional
import os
import re
import json
import logging

import config
import tau_defs
from tau_manager import communicate_with_tau
from consensus.serialization import compute_update_id
from consensus.facade import TipAdmissionView
from consensus.governance import (
    normalize_validator_delta,
    normalize_validator_set,
    validate_quorum_policy,
    validate_eligibility_mode,
    quorum_count,
    HOST_CONTRACT_PATCH_KEYS,
    validate_fee_beneficiary,
)

logger = logging.getLogger(__name__)

# DoS bounds enforced at mempool admission (phase 1, before any expensive compile).
MAX_RULE_REVISIONS = 32
MAX_RULE_REVISIONS_BYTES = 196608   # 192 KiB total UTF-8, nests under the 262144 wire cap
MAX_TRANSFERS_PER_TX = 64
MAX_CUSTOM_INPUT_STREAMS = 16

# Input stream(s) the native fee/application path MOCKS to "0" during block apply
# (consensus/engine.py) yet feeds REAL values at mempool admission
# (commands/sendtx.py). Only i2 (balance) genuinely diverges: other txs in the
# same block may debit the account between queue time and apply time, so a rule
# reading i2 emits a different fee at admission than at inclusion (admitted, then
# rejected at block build). We reject such rule text outright. i3/i4 (from/to
# pubkeys) and i5 (block timestamp) are NOT mocked — they are immutable in the
# transfer tuple / injected by consensus, hence identical at admission and apply,
# so recipient-aware and time-aware policy rules are deterministic across both and
# are permitted. Fee/policy rules may scope on i12 (sender), i3/i4 (from/to), i5
# (time) and i1 (amount). See tau_defs.py "DETERMINISM CONSTRAINT".
APPLY_MOCKED_INPUT_STREAMS = ("i2",)


def _strip_tau_comments(rule_text: str) -> str:
    """
    Drop Tau '#' comments while preserving '#b...'/'#x...' bitvector literals,
    so a stream screen never false-positives on a stream named only in a
    comment. Mirrors tau_native.TauInterface._strip_nonliteral_hash_comments,
    kept local to avoid importing the native bindings on the admission path.
    """
    out: List[str] = []
    for line in (rule_text or "").splitlines():
        i = 0
        while i < len(line):
            ch = line[i]
            if ch != "#":
                out.append(ch)
                i += 1
                continue
            nxt = line[i + 1].lower() if i + 1 < len(line) else ""
            if nxt in ("b", "x"):  # #b.../#x... literal, not a comment
                out.append(ch)
                i += 1
                continue
            break  # comment marker -> drop the rest of this line
        out.append("\n")
    return "".join(out)


def _streams_referenced(rule_text: str, tokens) -> List[str]:
    """
    Subset of `tokens` (e.g. ('i2','i3','i4')) the rule TEXT actually
    references, after stripping comments. Word-boundary matched so custom
    streams such as i23/i40/o90 are not mistaken for i2/i4/o9.
    """
    scrubbed = _strip_tau_comments(rule_text)
    return [tok for tok in tokens if re.search(rf"\b{re.escape(tok)}\b", scrubbed)]


class AdmissionResult:
    def __init__(self, is_valid: bool, error: Optional[str] = None, data: Optional[Dict] = None,
                 code: Optional[str] = None, details: Optional[Dict] = None):
        self.is_valid = is_valid
        self.error = error
        self.data = data or {}
        # Machine-readable rejection reason, forwarded verbatim into the sendtx
        # error envelope (issue #23). `code` defaults to None here and to
        # TX_REJECTED in format_error, so a caller that never opts in behaves
        # exactly as before.
        self.code = code
        self.details = details or {}


# Keys the envelope already owns; a details kwarg using one would silently
# shadow it rather than reach the client (api_response.error_response).
_RESERVED_DETAIL_KEYS = frozenset({"code", "message"})


def format_error(msg: str, *, code: str = "TX_REJECTED", **details) -> AdmissionResult:
    """Rejection with an optional machine-readable code and detail payload.

    Both are additive: the ~30 call sites that pass only a message keep emitting
    TX_REJECTED, which is what sendtx applied to all of them before. Opt in per
    site where a client can actually act on the distinction.
    """
    clashing = sorted(_RESERVED_DETAIL_KEYS.intersection(details))
    if clashing:
        raise ValueError(
            f"format_error details may not shadow envelope keys: {clashing}"
        )
    return AdmissionResult(False, error=msg, code=code, details=details)

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

    transfers = operations.get("1")
    if isinstance(transfers, list) and len(transfers) > MAX_TRANSFERS_PER_TX:
        return format_error(f"user_tx exceeds MAX_TRANSFERS_PER_TX ({len(transfers)} > {MAX_TRANSFERS_PER_TX}).")
    custom_stream_count = sum(1 for k in operations if str(k).isdigit() and int(k) not in (0, 1))
    if custom_stream_count > MAX_CUSTOM_INPUT_STREAMS:
        return format_error(
            f"user_tx exceeds MAX_CUSTOM_INPUT_STREAMS ({custom_stream_count} > {MAX_CUSTOM_INPUT_STREAMS})."
        )

    # Which operation keys are reserved depends on the eligibility mode in force
    # (i13 only under tau_validator_set). getattr keeps the legacy contract where
    # callers that only exercise the static screens may pass no tip view at all.
    reserved_ops = tau_defs.reserved_operation_keys(getattr(tip_view, "eligibility_mode", ""))

    for key, val in operations.items():
        if not str(key).isdigit():
            continue
        idx = int(key)
        # Block attempts to use reserved streams in application transactions natively
        if 6 <= idx <= 11:
            return format_error(f"Invalid operation target '{key}'. Streams 6-11 are reserved for consensus ABI inputs.")
        # i12 is the sender pubkey the node injects at apply; a custom
        # operations["12"] would override it in the engine's input merge and
        # spoof the sender-scoped o5/o8 policy stream. i14/i15 are consensus
        # stake/mode inputs fed only at consensus evaluation — a user tx typing
        # them at a different bv width poisons the process-global stream typing
        # (Phase 0 spike S5). i13 joins them only under tau_validator_set, the
        # one mode that feeds it. Reject on every ingest path so the mempool gate
        # matches sendtx and apply. (i2-i5 are already rejected at apply via
        # RESERVED_STREAMS; i12/i14/i15 are not in that set.)
        if idx in reserved_ops:
            return format_error(
                f"Invalid operation target '{key}'. Stream {idx} is reserved "
                f"(i12 sender pubkey; i14/i15 consensus stake/mode inputs; "
                f"i13 consensus proposer pubkey under tau_validator_set)."
            )

    # Screen user rule TEXT for reserved streams. Comment-stripped and
    # word-boundary matched (so custom streams like i23/o90 are not mistaken
    # for i2/o9, and a stream named only in a comment is ignored).
    #
    #  (a) A user rule writing o6/o7 (block validity / eligibility) or o9
    #      (consensus fee) would conflict with the voted consensus rules in the
    #      composed spec (unsat -> DoS) or forge consensus verdicts/fees.
    #  (b) A user rule reading i2 (balance — mocked to "0" at block apply) emits a
    #      different o8 fee at admission than at inclusion -> admitted then
    #      rejected at block build. i3/i4/i5 are real at both points and allowed.
    #
    # HARD for user txs; governance revisions stay exempt for (a) because
    # writing those output streams is their legitimate job (see the consensus
    # revision screen, which still hard-rejects (b)).
    rule_text = operations.get("0")
    if isinstance(rule_text, str) and rule_text:
        forbidden_out = _streams_referenced(rule_text, ("o6", "o7", "o9"))
        if forbidden_out:
            return format_error(
                f"user_tx rule text references reserved consensus output stream '{forbidden_out[0]}'."
            )
        mocked_in = _streams_referenced(rule_text, APPLY_MOCKED_INPUT_STREAMS)
        if mocked_in:
            return format_error(
                f"user_tx rule text references apply-time-mocked input stream "
                f"'{mocked_in[0]}' (balance): reading i2 diverges the fee between admission "
                f"and block apply. Scope on i12/i3/i4, gate on i5, compare amount on i1."
            )
        # Same reserved set as the operations screen above, minus i12: READING the
        # sender pubkey is how a policy rule scopes itself, only WRITING it as an
        # operation is forbidden.
        typed_reserved = tuple(f"i{idx}" for idx in reserved_ops if idx != 12)
        typed_reserved_in = _streams_referenced(rule_text, typed_reserved)
        if typed_reserved_in:
            return format_error(
                f"user_tx rule text references reserved consensus input stream "
                f"'{typed_reserved_in[0]}' (proposer pubkey / stake / eligibility mode): these are "
                f"only fed at consensus evaluation steps, and typing them from a user rule can pin a "
                f"conflicting bitvector width process-wide (e.g. i13 is bv[384])."
            )

        #  (c) o5/o8 are SHARED streams: Tau composes every deployed user rule
        #      into one constraint, so a rule that writes them without gating on
        #      its author's identity applies to EVERY sender. `always (o5[t] = 0)`
        #      from any account is then a one-transaction network freeze, and
        #      `always (o8[t] = 3)` taxes every user_tx on the network — both for
        #      the price of a single deploy (issue #24, observation 1).
        #
        #      Sender-scoping was already the documented contract (tau_defs.py,
        #      README) and every shipped wallet template already complies; this
        #      only makes it enforced. i12 (sender pubkey) or i3 (from address)
        #      both count as a scope.
        #
        #      Admission-only, so it is NOT retroactive: rules already accumulated
        #      on chain keep evaluating, and apply never re-runs this screen.
        #      Deliberate limit: a reference is not proof the rule is really gated
        #      by it — `always (o5[t] = 1 || i12[t] != i12[t])` passes. Catching
        #      that needs formula analysis, not text screening. The target here is
        #      the accidental global rule, not a determined attacker (who can only
        #      author a rule that also blocks their own transfers).
        policy_out = _streams_referenced(rule_text, ("o5", "o8"))
        if policy_out and not _streams_referenced(rule_text, ("i12", "i3")):
            return format_error(
                f"user_tx rule text writes shared policy stream '{policy_out[0]}' "
                f"without a sender scope: it would apply to every account on the "
                f"network. Guard the rule on your own identity — reference i12 "
                f"(sender pubkey) or i3 (from address), e.g. "
                f"always ((i12[t]:bv[384] = {{ #x<your pubkey> }}:bv[384]) -> "
                f"{policy_out[0]}[t]:bv[24] = {{ #x000000 }}:bv[24]).",
                code="UNSCOPED_USER_RULE",
                stream=policy_out[0],
            )

    return success()

def precheck_scheduled_update(update: Any, active_validators: Optional[Any] = None) -> Dict[str, Optional[str]]:
    """Advisory re-validation of an ALREADY-SCHEDULED update against the current tip.

    An update is validated when it is submitted, but it activates later — and the
    tip moves in between. The staleness that actually bites is a host contract
    patch: a `count:N` quorum bounded against 5 validators when 2 are removed
    before it fires. This surfaces that while there is still time to act
    (issue #24, ask 4).

    STRICTLY INFORMATIONAL. Nothing here is read by consensus: no caller may skip,
    drop or reorder an activation on the strength of this verdict. That is not a
    style preference — the skip criterion would have to be identical on every node
    at every replay, and a node disagreeing about whether an update activates
    computes a different consensus_meta_hash and forks the chain. The terminal
    behaviour of a bad activation is unchanged: apply raises and the block is
    rejected network-wide. What this buys is a warning window, not a different
    outcome.

    Deliberately cheap: static Python re-checks only, no interpreter and no
    subprocess compile. A compile per scheduled update per poll would turn a read
    RPC into a process fork bomb, and it still could not prove satisfiability at
    the activation height, since the application rules accumulated between now and
    then depend on every intervening user_tx. So "ok" means "nothing statically
    wrong today", never "this will activate cleanly".
    """
    if update is None:
        # Only pending|scheduled payloads are persisted, so a restart can leave a
        # scheduled id with no text to check. Absence of a verdict, not a pass.
        return {"status": "skipped", "error": "payload not retained on this node"}

    patch = getattr(update, "host_contract_patch", None)
    if isinstance(patch, dict) and patch:
        err = _check_host_contract_patch(patch, active_validators)
        if err:
            return {"status": "fail", "error": err}

    for rev in (getattr(update, "rule_revisions", None) or []):
        if not isinstance(rev, str):
            return {"status": "fail", "error": "rule_revisions must be strings"}
        mocked_in = _streams_referenced(rev, APPLY_MOCKED_INPUT_STREAMS)
        if mocked_in:
            return {
                "status": "fail",
                "error": (f"revision references apply-time-mocked input stream "
                          f"'{mocked_in[0]}' (balance)"),
            }

    return {"status": "ok", "error": None}


def _check_host_contract_patch(patch: dict, active_validators: Optional[Any] = None) -> Optional[str]:
    """Static checks for host contract parameters to ensure future-proofing definitions."""
    # Reject anything apply_host_contract_patch would not read. Without this an
    # unknown key rides through the whole lifecycle — admitted, bound into the
    # update_id, voted on, activated — and then does nothing, so the proposal
    # reads as passed while having no effect.
    unknown = sorted(set(patch) - HOST_CONTRACT_PATCH_KEYS)
    if unknown:
        return (
            f"Unknown host_contract_patch key(s): {', '.join(unknown)}. "
            f"Supported: {', '.join(sorted(HOST_CONTRACT_PATCH_KEYS))}."
        )
    if "proof_scheme" in patch and patch["proof_scheme"] != "bls_header_sig":
        return f"Unsupported proof_scheme inside host_contract_patch: {patch['proof_scheme']}"
    if "fork_choice_scheme" in patch and patch["fork_choice_scheme"] != "height_then_hash":
        return f"Unsupported fork_choice_scheme inside host_contract_patch: {patch['fork_choice_scheme']}"
    if "input_contract_version" in patch and patch["input_contract_version"] != 1:
        return f"Unsupported input_contract_version inside host_contract_patch: {patch['input_contract_version']}"
    # Compute the post-delta validator set whenever a delta OR a vote_quorum is
    # present: a fixed-count quorum is bounded against the set it will run under.
    next_validators = None
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
    if "vote_quorum" in patch:
        policy = patch["vote_quorum"]
        err = validate_quorum_policy(policy)
        if err:
            return f"Unsupported vote_quorum inside host_contract_patch: {err}"
        # A count larger than the validator set it activates under would be
        # unreachable; reject early (the runtime also clamps, but flag the
        # proposer's mistake at admission). Use the post-delta set if this patch
        # also changes validators, else the current tip set.
        count = quorum_count(policy)
        if count is not None:
            effective_validators = (
                next_validators if next_validators is not None
                else normalize_validator_set(active_validators or [])
            )
            if count > len(effective_validators):
                return (
                    f"vote_quorum count {count} exceeds the "
                    f"{len(effective_validators)} validator(s) it would activate under."
                )
    if "eligibility_mode" in patch:
        err = validate_eligibility_mode(patch["eligibility_mode"])
        if err:
            return f"Unsupported eligibility_mode inside host_contract_patch: {err}"
    if "fee_beneficiary" in patch:
        err = validate_fee_beneficiary(patch["fee_beneficiary"])
        if err:
            return f"Unsupported fee_beneficiary inside host_contract_patch: {err}"
    return None

def validate_consensus_rule_update_payload(tx: Dict, tip_view: TipAdmissionView) -> AdmissionResult:
    """
    Validate the core fields and parameters of a consensus_rule_update payload.
    """
    sender = tx.get("sender_pubkey")
    if not _open_governance_admission() and sender not in tip_view.active_validators:
        return format_error(f"Proposer {sender[:10]} is not an active validator.")

    if "rule_revisions" not in tx or not isinstance(tx["rule_revisions"], list) or len(tx["rule_revisions"]) == 0 \
            or len(tx["rule_revisions"]) > MAX_RULE_REVISIONS:
        return format_error(
            f"Missing or invalid 'rule_revisions' list. Must be a non-empty list of at most {MAX_RULE_REVISIONS} entries."
        )

    for rev in tx["rule_revisions"]:
        if not isinstance(rev, str):
            return format_error("Every entry in 'rule_revisions' must be a string.")

    if sum(len(rev.encode("utf-8")) for rev in tx["rule_revisions"]) > MAX_RULE_REVISIONS_BYTES:
        return format_error(f"'rule_revisions' total size exceeds MAX_RULE_REVISIONS_BYTES ({MAX_RULE_REVISIONS_BYTES}).")

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
        # Structured so a wallet can treat a retry of a proposal that already
        # landed as success instead of parsing prose (issue #23). The lifecycle
        # state is already in hand, so it costs nothing to hand it over.
        return format_error(
            f"update_id {update_id.hex()[:10]} already exists in lifecycle state: {state}",
            code="DUPLICATE_UPDATE",
            update_id=update_id.hex(),
            lifecycle_state=state,
        )

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
      3. HARD reject of revisions reading apply-time-mocked inputs (i2/i3/i4),
      4. per-revision preprocessing (syntax shape, normalization),
      5. isolated staging compile against current consensus rules.
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
    for stream_idx in ("i6", "i7", "i8", "i9", "i10", "i11", "i13", "i14", "i15", "o6", "o7"):
        for rev in revisions:
            if stream_idx in rev and "consensus" not in rev:
                logger.warning(f"Revision potentially shadowing {stream_idx}")

    # HARD-reject any revision that reads an apply-time-mocked input stream.
    # Only i2 (balance) is mocked to "0" at block apply. A consensus fee rule (o9)
    # reading it would compute a different fee at admission than at inclusion — the
    # same divergence footgun the user o8 screen rejects. i3/i4/i5 are real at both
    # points. Comment-stripped, word-boundary matched.
    for rev in revisions:
        mocked_in = _streams_referenced(rev, APPLY_MOCKED_INPUT_STREAMS)
        if mocked_in:
            return format_error(
                f"Consensus revision references apply-time-mocked input stream "
                f"'{mocked_in[0]}' (balance): a fee rule reading i2 diverges between "
                f"admission and block apply."
            )

    # Per-revision preprocessing (syntax shape). Anything that explodes here
    # would also explode at activation, so reject early.
    import tau_native
    try:
        for rev in revisions:
            tau_native.TauInterface.preprocess_spec_text(rev)
    except Exception as e:
        return format_error(f"Internal compiler failure natively: {e}")

    # Isolated staging compile, in a SIGKILL-able subprocess with a hard
    # wall-clock bound. The in-process classmethod this replaced had no timeout
    # and wrote no watchdog status stamp, so a pathological revision could spin
    # forever and hang the governance submit — the same vector issue #24 fixed
    # for user op-"0" rules, which had been left live on this path.
    #
    # Skip if the live Tau interpreter isn't ready (early boot, test fixtures
    # without native bindings): admission stays available and the
    # activation-height compile in apply_block remains the correctness backstop.
    import tau_manager
    if tau_manager.tau_ready.is_set():
        timeout = tau_native.admission_compile_timeout()
        try:
            err = tau_native.compile_revisions_isolated_subprocess(
                tip_view.current_consensus_rules,
                revisions,
                timeout=timeout,
            )
        # RuleCompileTimeout subclasses NativeTauUnavailable, which subclasses
        # Exception -- so these three must stay in this order. A bare
        # `except Exception` first (as before) collapses a bounded timeout and a
        # transient worker-spawn failure into an indistinguishable rejection.
        except tau_native.RuleCompileTimeout as exc:
            logger.warning("Consensus staging compile timed out: %s", exc)
            return format_error(
                f"Consensus update staging compile timed out after {timeout}s "
                f"and was rejected.",
                code="ADMISSION_TIMEOUT",
                timeout_seconds=timeout,
            )
        except tau_native.NativeTauUnavailable as exc:
            # Cannot run the isolated compile (e.g. EMFILE/ENOMEM on spawn). Do
            # NOT fall back to the unbounded in-process path; reject promptly so
            # the proposer can resubmit.
            logger.warning("Consensus staging compile unavailable: %s", exc)
            return format_error(
                f"Consensus update staging compile could not be run: {exc}",
                code="ADMISSION_UNAVAILABLE",
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
