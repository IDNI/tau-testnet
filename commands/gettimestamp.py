import datetime
import logging

import utils

logger = logging.getLogger(__name__)


def encode_command(command_parts):
    """Encodes the getCurrentTimestamp command into a Tau literal."""
    logger.debug("Encoding getCurrentTimestamp command.")
    bit_pattern = "01" + "0" * 9
    tau_literal = utils.bits_to_tau_literal(bit_pattern, length=len(bit_pattern))
    logger.debug("Encoded Tau literal for getCurrentTimestamp: %s", tau_literal)
    return tau_literal


def decode_output(output_tau_str, original_input_tau_str):
    """
    Decodes Tau output for the getCurrentTimestamp command.
    Tau is no longer authoritative for this operation, so we treat any response as success.
    """
    logger.debug("Decoding Tau output: %s", output_tau_str.strip())
    return True


def handle_result(decoded_success, tau_input, mempool_state):
    """
    Handles the decoded result for a getTimestamp command.
    """
    # Tau is no longer authoritative for timestamp. Server provides it.
    # This function might not be used if we switch to local execution.
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return f"Current Timestamp (UTC): {now}"

def execute(raw_command: str, container):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return f"Current Timestamp (UTC): {now}"
