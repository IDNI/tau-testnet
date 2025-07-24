# SBF Definitions for Tau Interaction

# Based on tool_code.tau definitions and existing Python patterns

# Command Encoding Input Placeholders (actual values are generated dynamically)
# These might not be strictly needed if encoding functions are always used,
# but can be useful for reference or testing.
# GETTIMESTAMP_CMD_SBF = "x1' & x2" # 01
# GETMEMPOOL_CMD_SBF = "x1 & x2'" # 10 # Corrected based on tool_code.tau logic
# SENDTX_CMD_SBF = "x1' & x2'" # 00 # Corrected based on tool_code.tau logic

# Output Codes from Tau (match patterns expected from tool_code.tau output streams)
# Fail codes for sendTx
# FAIL_CODE_INVALID_COMMAND_SBF = "x0'" # Older, less precise. Use FAIL_INVALID_SBF or SBF_LOGICAL_ZERO.
# FAIL_CODE_SRC_EQ_DEST_SBF     = "x0001'" # Older, less precise. Use FAIL_SRC_EQ_DEST_SBF.
# FAIL_CODE_ZERO_AMOUNT_SBF     = "x0002'" # Older, less precise. Use FAIL_ZERO_AMOUNT_SBF.
# FAIL_CODE_INSUFFICIENT_FUNDS_SBF = "{x0003'}:sbf" # This one was correct, same as FAIL_INSUFFICIENT_FUNDS_SBF.

# Success codes for other commands - These MUST match the exact SBF string Tau prints
# CODE_X2000_SBF = "x2000" # Match code_x2000() := {x2000'}:sbf. (Output for getMempool)
# CODE_X3000_SBF = "x3000" # Match code_x3000() := {x3000'}:sbf. (Output for getTimestamp)

# --- Generic SBF Base Values ----
# These are primarily for internal logic or Python-side interpretations if needed.
# Tau usually outputs specific codes for specific conditions.
# SBF_LOGICAL_ZERO = "{x0'}:sbf" # Represents logical false or zero generally. Matches Tau's fail_invalid().
SBF_LOGICAL_ZERO = "0" # Represents logical false or zero generally.
SBF_LOGICAL_ONE = "{x0}:sbf"    # Represents logical true or one generally.

# --- Failure Codes from Tau --- 
# These MUST match exactly what the Tau program (`tool_code.tau`) outputs.
# fail_invalid()         := {x0'}:sbf.
# fail_src_eq_dest()     := {x0001'}:sbf.
# fail_zero_amount()     := {x0002'}:sbf.
# fail_insufficient_funds() := {x0003'}:sbf.

FAIL_INVALID_SBF = SBF_LOGICAL_ZERO          # General failure / invalid input.
FAIL_SRC_EQ_DEST_SBF = "{x0001'}:sbf"         # Transfer failure: Source equals Destination.
FAIL_ZERO_AMOUNT_SBF = "{x0002'}:sbf"         # Transfer failure: Amount is zero.
FAIL_INSUFFICIENT_FUNDS_SBF = "{x0003'}:sbf"  # Transfer failure: Insufficient funds (Amount > Sender Balance).
FAIL_INVALID_FORMAT_SBF = "{x0004'}:sbf"      # Transfer failure: Invalid transaction format (not a 16-bit minterm).

# --- Success / Acknowledgement Codes from Tau --- 
# ack_rule_processed()   := {x1001}:sbf.
# ack_custom_processed() := {x1002}:sbf. # Not currently used in tool_code.tau outputting to o0/o1

ACK_RULE_PROCESSED_SBF = "{x1001}:sbf"       # Rule processed successfully.
# ACK_CUSTOM_PROCESSED_SBF = "{x1002}:sbf"    # Custom asset processed successfully (placeholder if used later).


# --- Obsolete or less precise constants (kept for reference during transition, can be removed later) ---
# FAIL_CODE_INVALID_COMMAND_SBF = "x0'" # Older, less precise. Use FAIL_INVALID_SBF or SBF_LOGICAL_ZERO.
# FAIL_CODE_SRC_EQ_DEST_SBF     = "x0001'" # Older, less precise. Use FAIL_SRC_EQ_DEST_SBF.
# FAIL_CODE_ZERO_AMOUNT_SBF     = "x0002'" # Older, less precise. Use FAIL_ZERO_AMOUNT_SBF.
# FAIL_CODE_INSUFFICIENT_FUNDS_SBF = "{x0003'}:sbf" # This one was correct, same as FAIL_INSUFFICIENT_FUNDS_SBF.

# SBF_ZERO = "0" # Using SBF_LOGICAL_ZERO ("{x0'}:sbf") for SBF context is more explicit.
                 # Tau itself uses "0" in SBF expressions, which is fine there.

# --- Codes used by Python wrapper logic for commands NOT primarily validated by Tau --- 
# (Or for interpreting generic Tau outputs for specific Python-handled commands)
# These are illustrative and depend on command_handler logic.
ACK_GETMEMPOOL_EMPTY_SBF = SBF_LOGICAL_ZERO    # Example: Mempool is empty
ACK_GETMEMPOOL_NONEMPTY_SBF = SBF_LOGICAL_ONE  # Example: Mempool has data
ACK_GETTIMESTAMP_SBF = SBF_LOGICAL_ONE         # Example: Timestamp command success (actual time sent differently)


# --- Tau Pin Names (Symbolic, for clarity in wrapper logic) ---
TAU_INPUT_STREAM_RULES = "i0"       # For rule proposals
TAU_INPUT_STREAM_TRANSFERS = "i1"   # For coin transfers
# TAU_INPUT_STREAM_CUSTOM_ASSETS = "i2" # Example for custom assets (if added)

TAU_OUTPUT_STREAM_OP0 = "o0"        # Output for new rules
TAU_OUTPUT_STREAM_OP1_DEFAULT = "o1" # Default/main output stream, oten for transfers or general status

# Tau Pin Names (Illustrative - for clarity in wrapper logic)
# These are not SBF values but symbolic names matching the Tau program's i/o console stream names.
# TAU_INPUT_STREAM_CUSTOM_ASSETS = "i2" # Example for custom assets
# TAU_INPUT_STREAM_GETMEMPOOL_TRIGGER = "i3" # Example for triggering getMempool
# TAU_INPUT_STREAM_GETTIMESTAMP_TRIGGER = "i4" # Example for triggering getCurrentTimestamp

# General SBF Codes / Base Values
# These should match the Tau program's definitions if they are used directly as outputs.
# For failure/success codes, Tau usually defines specific patterns. 