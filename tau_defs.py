"""
Constants for Tau Interaction using Bitvectors

This module is simplified to reflect the new boolean validation model.
"""

# --- Generic Logical Values ----
# These are the primary values returned by validation logic.
TAU_VALUE_ZERO = "#b0"  # Represents logical false, failure, or zero.
TAU_VALUE_ONE = "#b1"   # Represents logical true, success, or one.

# --- Failure/Success Codes from Tau ---
# The new bitvector-based transaction validation returns a single boolean on o1.
# #b0 for any failure, #b1 for success.
TRANSACTION_VALIDATION_FAIL = TAU_VALUE_ZERO
TRANSACTION_VALIDATION_SUCCESS = TAU_VALUE_ONE

# --- Success / Acknowledgement Codes for other operations ---
ACK_RULE_PROCESSED = TAU_VALUE_ONE

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
