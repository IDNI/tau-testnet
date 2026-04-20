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
# into a single logical constraint. Each user rule must be guarded by
# that user's sender identity (i3) to avoid affecting other users.
#
# Semantics:
#   o5 = 0       -> explicit block (user policy rejects transfer)
#   o5 = 1       -> explicit allow  (user policy approves transfer)
#   o5 missing   -> no user policy triggered -> allow
#
# The engine enforces: allow only if o1 passes AND (o5 is absent OR o5 != 0).
USER_POLICY_STREAM_INDEX = 5
USER_POLICY_BLOCK_VALUE = 0
USER_POLICY_ALLOW_VALUE = 1

# Input Streams (additional)
TAU_INPUT_STREAM_TIMESTAMP = "i5"

# System Reserved Streams
# 0..4 are core protocol streams; 5 is consensus timestamp injected by node (i5).
# Note: i5 is a reserved INPUT stream (consensus clock). o5 is the user policy
# OUTPUT stream — these are separate namespaces and do not conflict.
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
