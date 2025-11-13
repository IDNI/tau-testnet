import utils
import sbf_defs
import datetime
import logging

logger = logging.getLogger(__name__)

def encode_command(command_parts):
    """Encodes the getCurrentTimestamp command (10) into an SBF atom."""
    logger.debug("Encoding getCurrentTimestamp command.")
    # Command 01 from genesis.tau logic
    bit_pattern = "01" + "0" * 9
    sbf_atom = utils.bits_to_sbf_atom(bit_pattern)
    logger.debug(f"Encoded SBF for Tau: {sbf_atom}")
    return sbf_atom

def decode_output(output_sbf_str, original_input_sbf_str):
    """
    Decodes the SBF output string from Tau specifically for a getCurrentTimestamp command.
    Returns True on expected success output, False otherwise.
    """
    output_sbf_str = output_sbf_str.strip()
    logger.debug(f"Decoding Tau output: {output_sbf_str}")
    logger.debug(f"Expecting success code: {sbf_defs.CODE_X3000_SBF}")

    if output_sbf_str == sbf_defs.CODE_X3000_SBF:
        logger.debug("Matched CODE_X3000_SBF.")
        return True # Indicate success
    elif output_sbf_str == sbf_defs.SBF_ZERO:
        logger.debug("Matched SBF_ZERO -> Generic Failure.")
        return False # Indicate failure
    else:
        logger.debug(f"Output {output_sbf_str} did not match known codes.")
        return False # Indicate unexpected output / failure

def handle_result(decoded_success, sbf_input, mempool_state):
    """
    Handles the decoded result for a getCurrentTimestamp command.

    Args:
        decoded_success (bool): True if Tau indicated success, False otherwise.
        sbf_input (str): The original SBF input sent to Tau (unused here).
        mempool_state (dict): Unused here.

    Returns:
        str: The final message to send back to the client (timestamp or error).
    """
    if decoded_success:
        current_time = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result_message = f"Current Timestamp (UTC): {current_time}"
    else:
        result_message = "ERROR: Tau program indicated failure or produced unexpected output for getCurrentTimestamp."
    return result_message 