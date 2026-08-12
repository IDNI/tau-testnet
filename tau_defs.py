"""
Constants for Tau Interaction using Bitvectors

This module is simplified to reflect the new boolean validation model.
"""

# --- Generic Logical Values ----
# These are the primary values returned by validation logic.
TAU_VALUE_ZERO = "0"    # Represents logical false, failure, or zero.
TAU_VALUE_ONE = "1"     # Represents logical true, success, or one.

# --- Failure/Success Codes from Tau ---
# The new bitvector-based transaction validation returns a single boolean on o1.
# 0 for any failure, 1 for success.
TRANSACTION_VALIDATION_FAIL = TAU_VALUE_ZERO
TRANSACTION_VALIDATION_SUCCESS = TAU_VALUE_ONE

# --- Success / Acknowledgement Codes for other operations ---
# --- Success / Acknowledgement Codes for other operations ---
ACK_RULE_PROCESSED = TAU_VALUE_ONE
ACK_RULE_PROCESSED_SBF = TAU_VALUE_ONE

# --- Legacy Error Codes (Mapped to Generic Failure 0) ---
FAIL_INSUFFICIENT_FUNDS_SBF = TAU_VALUE_ZERO
FAIL_SRC_EQ_DEST_SBF = TAU_VALUE_ZERO
FAIL_ZERO_AMOUNT_SBF = TAU_VALUE_ZERO
FAIL_INVALID_FORMAT_SBF = TAU_VALUE_ZERO
FAIL_INVALID_SBF = TAU_VALUE_ZERO

# --- Transfer value width ---
# i1 (amount) and i2 (balance) are typed bv[24] by the SHIPPED application rules
# (rules/01, rules/03, rules/04), so 16777215 is the largest value they can carry.
# The host used to range-check both against DEFAULT_RULE_BV_WIDTH (64) instead,
# accepting amounts the rules then silently truncated mod 2^24 —
# tau_manager.normalize_rule_bitvector_sizes would have rewritten the widths, but
# it is short-circuited in production by preprocess_spec_text.
#
# Narrowing the HOST to match the rules is the safe direction: it is pure
# admission tightening, with no rule text, no vote and no state-hash effect.
# Widening the RULES to bv[64] is the unsafe one — rule files are replayed through
# i0 and accumulate into _application_rules_state, which is hashed into every
# block, so editing them diverges a restarted node from a running one.
TRANSFER_VALUE_BV_WIDTH = 24
MAX_TRANSFER_VALUE = (1 << TRANSFER_VALUE_BV_WIDTH) - 1

# --- Tau Pin/Stream Names (Symbolic, for clarity in wrapper logic) ---
# Inputs
TAU_INPUT_STREAM_RULES = "i0"
TAU_INPUT_STREAM_AMOUNT = "i1"
TAU_INPUT_STREAM_BALANCE = "i2"
TAU_INPUT_STREAM_FROM_ID = "i3"
TAU_INPUT_STREAM_TO_ID = "i4"

# Outputs
TAU_OUTPUT_STREAM_RULES = "o0"
TAU_OUTPUT_STREAM_VALIDATION_RESULT = "o1"

# --- User Policy Stream ---
# o5 is the shared user-policy output stream.
# Multiple users can write sender-scoped rules to o5; Tau composes them
# into a single logical constraint. Each user rule MUST be guarded by
# that user's sender identity (i12 sender pubkey, or i3 from-address) to
# avoid affecting other users. This is ENFORCED at mempool admission for
# both o5 and o8: rule text writing either without referencing i12 or i3
# is rejected with UNSCOPED_USER_RULE (consensus/admission.py), because a
# single unscoped `always (o5[t] = 0)` would block every account on the
# network. The screen is textual and admission-only — it cannot prove the
# scope actually gates the assignment, and rules already on chain are
# grandfathered. Rules may also read i4 (recipient) and i5
# (block timestamp) — both real at admission and apply — for recipient
# whitelists and time-locks.
#
# Semantics:
#   o5 = 0       -> explicit block (user policy rejects transfer)
#   o5 = 1       -> explicit allow  (user policy approves transfer)
#   o5 missing   -> no user policy triggered -> allow
#
# Enforced at BOTH mempool admission (commands/sendtx.py) AND block apply
# (consensus/engine.py, fee-era transfer loop): a transfer is allowed only if
# o1 passes AND (o5 absent OR o5 != 0). A policy block on ANY transfer rejects
# the WHOLE user_tx (no partial execution). Malformed/unparseable o5 fails
# closed (parse_tau_output -> 0 -> block).
USER_POLICY_STREAM_INDEX = 5
USER_POLICY_BLOCK_VALUE = 0
USER_POLICY_ALLOW_VALUE = 1

# --- Fee Streams ---
# o8: user CUSTOM FEE output stream (application rules, user-deployed).
# o9: CONSENSUS FEE output stream (consensus rules, governance-voted).
# Like i5/o5, the i8/i9 consensus ABI inputs below and the o8/o9 fee
# outputs are separate namespaces and do not conflict.
#
# During each per-transfer Tau evaluation step the node reads both streams
# and adds them to the transaction's total fee:
#   total_fee = sum over steps of (o9 + o8)
# A transfer-less user_tx is charged via one dedicated fee-query step with
# the canonical mocked transfer inputs (i1=i2=i3=i4="0", i5=block
# timestamp, i12=sender pubkey).
#
# Parse policy (see consensus/fees.py):
#   o9 STRICT  — absent -> 0 (fee model inactive); present-but-invalid ->
#                FeeRuleError (consensus failure: proposer aborts the
#                round, validator defers the block).
#   o8 LENIENT — absent -> 0 silently; invalid -> 0 + loud warning.
#
# DETERMINISM CONSTRAINT for rule authors: during block apply the node feeds
# real values on i1 (amount), i3/i4 (from/to pubkeys bv[384]), i5 (block
# timestamp), i12 (sender pubkey bv[384]) and the tx's custom input streams
# (i13+). Custom streams are merged into the SAME per-transfer evaluation step
# at both mempool admission (commands/sendtx.py) and block apply
# (consensus/engine.py), in byte-identical overlay order, so a rule combining a
# custom stream (i13+) with the transfer fields (i1/i3/i4/i5/i12) is enforced
# identically at admission and apply — passphrase confirmation, 2FA flags,
# escrow conditions and multi-party approval all gate `sendtx`, not just apply.
# i2 (balance) is the sender's balance at the PARENT block, frozen for the whole
# block (issue #20), so proposer and verifier feed the same value and a
# balance-reading POLICY rule (o5) is deterministic across both. Two transfers
# from one sender in a block therefore see the SAME pre-block balance: a
# min-balance floor does not compound within a block, and the fee/balance
# re-check at block build remains the backstop.
#
# What remains is admission-estimate drift: admission evaluates i2 against the
# current head, and the tx may land several blocks later — the same advisory
# relationship i5 has. That drift only matters for FEES, where a wrong estimate
# is quoted to the sender and then charged differently at inclusion. So rule text
# reading i2 is rejected only when it also writes o8 (user fee), and consensus o9
# revisions reading i2 remain hard-rejected (see consensus/admission.py
# APPLY_MOCKED_INPUT_STREAMS). i3/i4/i5 are immutable per-transfer / consensus-
# injected, hence identical at admission and apply, and may be read freely
# (recipient whitelists on i4, time-locks on i5). Wallets cannot know the final
# fee without simulating the same rules; admission errors return the computed
# estimate (required_fee).
CUSTOM_FEE_STREAM_INDEX = 8
CONSENSUS_FEE_STREAM_INDEX = 9

# Input Streams (additional)
TAU_INPUT_STREAM_TIMESTAMP = "i5"

# System Reserved Streams
# 0..4 are core protocol streams; 5 is consensus timestamp injected by node (i5).
# Note: i5 is a reserved INPUT stream (consensus clock). o5 is the user policy
# OUTPUT stream — these are separate namespaces and do not conflict.
# i12 (sender pubkey, node-injected) is ALSO reserved as an operations key but is
# NOT in this set: this constant is shared with the engine, which uses it for
# other purposes, so i12 is screened explicitly at every ingest/apply site
# (commands/sendtx.py, consensus/admission.py, consensus/engine.py). User custom
# input streams therefore start at i16 (i12/i14/i15 are screened explicitly at
# every ingest/apply site).
RESERVED_STREAMS = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}

# --- Tau Consensus ABI v1 ---
# Blocks and consensus metadata injected for policy evaluation.

# Inputs
TAU_INPUT_STREAM_HEIGHT = "i6"          # Block height (uint64 string)
TAU_INPUT_STREAM_CONSENSUS_TS = "i7"    # Block timestamp (uint64 string)
TAU_INPUT_STREAM_PROPOSER = "i8"        # Proposer identity (proposer_yid, lowercase hex string)
TAU_INPUT_STREAM_PARENT_HASH = "i9"     # Previous block hash (parent_hash_yid, lowercase hex string)
TAU_INPUT_STREAM_PROOF_OK = "i10"       # Proof validation result from host (1 for valid, 0 for invalid)
TAU_INPUT_STREAM_CLAIMS = "i11"         # Endorsed claims summary (claims_yid, lowercase hex string)

# Outputs
TAU_OUTPUT_STREAM_BLOCK_VALID = "o6"    # Block validity verdict (1 for accept, 0 for reject)
TAU_OUTPUT_STREAM_ELIGIBLE = "o7"       # Proposer eligibility verdict (1 for eligible, 0 for ineligible)

# --- Tau Consensus ABI v1.1 additions (stake-eligibility) ---
TAU_INPUT_STREAM_PROPOSER_STAKE = "i14"   # Proposer parent-state balance (uint64 string)
TAU_INPUT_STREAM_ELIGIBILITY_MODE = "i15" # 0 = validator_set, 1 = stake (bv[16])

# --- Tau Consensus ABI v1.2 additions (Tau-encoded validator membership) ---
# Proposer BLS pubkey fed so a consensus rule can test set membership itself
# (o7 = 1 iff i13 equals one of the validator pubkey constants baked into the
# rule text). bv[384] = 96 hex chars; fed as a wrapped literal `{ #x.. }:bv[384]`
# via the engine/shrink path, or bare `#x..` via raw TauInterface (gen_genesis).
TAU_INPUT_STREAM_PROPOSER_PUBKEY = "i13"

# Operations keys reserved OUTSIDE RESERVED_STREAMS (that set is shared with the
# engine for other purposes, so these are screened explicitly at every
# ingest/apply site: commands/sendtx.py, consensus/admission.py,
# consensus/engine.py). i12 = sender pubkey; i14/i15 = consensus stake/mode
# inputs. User custom input streams start at i13 (issue #16).
EXTRA_RESERVED_OPERATION_KEYS = (12, 14, 15)

# i13 is the proposer pubkey ONLY while the network runs eligibility_mode
# tau_validator_set: that is the one mode where the engine actually feeds i13
# (see TauConsensusEngine._build_consensus_input_streams), so it is the only mode
# where a user rule typing i13 at another width could poison process-global
# stream typing. Under validator_set / stake nothing feeds i13 and it stays an
# ordinary custom stream, so pre-existing user rules keep working.
TAU_VALIDATOR_SET_RESERVED_OPERATION_KEYS = (13,)


def reserved_operation_keys(eligibility_mode: str = "") -> tuple:
    """Operation keys a user_tx may not target, for the given eligibility mode.

    Every ingest/apply site must derive the set through this helper so admission,
    sendtx and block apply agree — a disagreement here is a consensus split."""
    if eligibility_mode == "tau_validator_set":
        return EXTRA_RESERVED_OPERATION_KEYS + TAU_VALIDATOR_SET_RESERVED_OPERATION_KEYS
    return EXTRA_RESERVED_OPERATION_KEYS
