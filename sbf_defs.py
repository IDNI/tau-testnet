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
FAIL_CODE_INVALID_COMMAND_SBF = "x0'" # Match fail_code_invalid_command() := {x0'}:sbf.
FAIL_CODE_SRC_EQ_DEST_SBF     = "x0001'"# Match fail_code_src_eq_dest() := {x0001'}:sbf.
FAIL_CODE_ZERO_AMOUNT_SBF     = "x0002'"# Match fail_code_zero_amount() := {x0002'}:sbf.
FAIL_CODE_INSUFFICIENT_FUNDS_SBF = "{x0003'}:sbf" # New: Insufficient funds for transfer

# Success codes for other commands - These MUST match the exact SBF string Tau prints
# CODE_X2000_SBF = "x2000" # Match code_x2000() := {x2000'}:sbf. (Output for getMempool)
# CODE_X3000_SBF = "x3000" # Match code_x3000() := {x3000'}:sbf. (Output for getTimestamp)

# Generic Tau output for zero/false
SBF_ZERO = "0" 

# --- Failure Codes from Tau --- 
# These MUST match exactly what the Tau program (`tool_code.tau`) outputs.
FAIL_INVALID_SBF = "{x0'}:sbf"                 # General failure. Matches `fail_invalid()`
FAIL_SRC_EQ_DEST_SBF = "{x0001'}:sbf"          # Src == Dest. Matches `fail_src_eq_dest()`
FAIL_ZERO_AMOUNT_SBF = "{x0002'}:sbf"          # Amount is zero. Matches `fail_zero_amount()`
FAIL_INSUFFICIENT_FUNDS_SBF = "{x0003'}:sbf" # Insufficient funds. Matches `fail_insufficient_funds()`

# --- Success / Acknowledgement Codes from Tau --- 
ACK_RULE_PROCESSED_SBF = "{x1001}:sbf"       # Rule processed successfully
ACK_CUSTOM_PROCESSED_SBF = "{x1002}:sbf"    # Custom asset processed successfully (currently unused)

# --- Generic SBF Base Values ----
# These are primarily for internal logic or Python-side interpretations if needed.
# Tau usually outputs specific codes for specific conditions.
SBF_LOGICAL_ZERO = "{x0'}:sbf" # Represents logical false or zero generally
SBF_LOGICAL_ONE = "{x0}:sbf"    # Represents logical true or one generally

# --- Codes used by Python wrapper logic for commands NOT primarily validated by Tau --- 
# (Or for interpreting generic Tau outputs for specific Python-handled commands)
ACK_GETMEMPOOL_EMPTY_SBF = SBF_LOGICAL_ZERO    # Example: Mempool is empty
ACK_GETMEMPOOL_NONEMPTY_SBF = SBF_LOGICAL_ONE  # Example: Mempool has data
ACK_GETTIMESTAMP_SBF = SBF_LOGICAL_ONE         # Example: Timestamp command success (actual time sent differently)


# --- Tau Pin Names (Symbolic, for clarity in wrapper logic) ---
TAU_INPUT_STREAM_RULES = "i0"       # For rule proposals
TAU_INPUT_STREAM_TRANSFERS = "i1"   # For coin transfers
TAU_OUTPUT_STREAM_MAIN = "o1"       # Master output stream

# Tau Pin Names (Illustrative - for clarity in wrapper logic)
# These are not SBF values but symbolic names matching the Tau program's i/o console stream names.
# TAU_INPUT_STREAM_CUSTOM_ASSETS = "i2" # Example for custom assets
# TAU_INPUT_STREAM_GETMEMPOOL_TRIGGER = "i3" # Example for triggering getMempool
# TAU_INPUT_STREAM_GETTIMESTAMP_TRIGGER = "i4" # Example for triggering getCurrentTimestamp

# General SBF Codes / Base Values
# These should match the Tau program's definitions if they are used directly as outputs.
# For failure/success codes, Tau usually defines specific patterns. 