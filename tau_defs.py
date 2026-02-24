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
