import utils
import json
import sbf_defs
from db import get_mempool_txs
import logging

logger = logging.getLogger(__name__)

def encode_command(command_parts):
    """Encodes the getMempool command (01) into an SBF atom."""
    logger.debug("Encoding getMempool command.")
    # Command 10 from genesis.tau logic
    bit_pattern = "10" + "0" * 9
    sbf_atom = utils.bits_to_sbf_atom(bit_pattern)
    logger.debug(f"Encoded SBF for Tau: {sbf_atom}")
    return sbf_atom

def decode_output(output_sbf_str, original_input_sbf_str):
    """
    Decodes the SBF output string from Tau specifically for a getMempool command.
    Returns True on expected success output, False otherwise.
    """
    output_sbf_str = output_sbf_str.strip()
    logger.debug(f"Decoding Tau output: {output_sbf_str}")
    logger.debug(f"Expecting success code: {sbf_defs.CODE_X2000_SBF}")

    if output_sbf_str == sbf_defs.CODE_X2000_SBF:
        logger.debug("Matched CODE_X2000_SBF.")
        return True # Indicate success
    elif output_sbf_str == sbf_defs.SBF_ZERO:
         logger.debug("Matched SBF_ZERO -> Generic Failure.")
         return False # Indicate failure
    else:
        logger.debug(f"Output {output_sbf_str} did not match known codes.")
        return False # Indicate unexpected output / failure

def handle_result(decoded_success, sbf_input, mempool_state):
    """
    Handles the decoded result for a getMempool command.

    Args:
        decoded_success (bool): True if Tau indicated success, False otherwise.
        sbf_input (str): The original SBF input sent to Tau (unused here).
        mempool_state (dict): Dictionary containing 'mempool' list and 'lock'.

    Returns:
        str: The final message to send back to the client (mempool contents or error).
    """
    # The Tau part of getmempool might become obsolete or change later.
    # For now, we ignore decoded_success and always return the current DB mempool.
    try:
        txs = get_mempool_txs()
        if txs:
            # Return raw entries, including 'json:' prefix
            result_message = "MEMPOOL:\n" + "\n".join(txs)
        else:
            result_message = "MEMPOOL: Empty"
    except Exception as e:
        result_message = f"ERROR: Failed to retrieve mempool from database: {e}"

    # Keep the Tau failure check just in case, but prioritize DB access
    if not decoded_success:
        # Determine if it was explicit failure (0) or unexpected output
        # For now, treat both as errors for the user
        # Prepend Tau error to the DB result if DB access failed
        tau_error = "ERROR: Tau program indicated failure or produced unexpected output for getMempool."
        if "ERROR: Failed to retrieve mempool" in result_message:
             result_message = tau_error + "\n" + result_message
        # Otherwise, maybe just log the Tau error? For now, let DB result stand if it succeeded.
        print(f"  [WARN][getmempool] {tau_error}")

    return result_message 