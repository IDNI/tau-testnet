import logging

import utils
from db import get_mempool_txs

logger = logging.getLogger(__name__)


def encode_command(command_parts):
    """Encodes the getMempool command into a Tau literal."""
    logger.debug("Encoding getMempool command.")
    bit_pattern = "10" + "0" * 9  # Command ID for getMempool
    tau_literal = utils.bits_to_tau_literal(bit_pattern, length=len(bit_pattern))
    logger.debug("Encoded Tau literal for getMempool: %s", tau_literal)
    return tau_literal


def decode_output(output_tau_str, original_input_tau_str):
    """
    Decodes the Tau output string for a getMempool command.
    Returns True on expected success output, False otherwise.
    """
    output_tau_str = output_tau_str.strip()
    logger.debug("Decoding Tau output: %s", output_tau_str.strip())
    return True


def handle_result(decoded_success, tau_input, mempool_state):
    """
    Handles the decoded result for a getMempool command.
    """
    try:
        txs = get_mempool_txs()
        if txs:
            result_message = "MEMPOOL:\n" + "\n".join(txs)
        else:
            result_message = "MEMPOOL: Empty"
    except Exception as e:
        result_message = f"ERROR: Failed to retrieve mempool from database: {e}"

    if not decoded_success:
        tau_error = "ERROR: Tau program indicated failure or produced unexpected output for getMempool."
        if result_message.startswith("ERROR: Failed to retrieve mempool"):
            result_message = tau_error + "\n" + result_message
        logger.warning("[getmempool] %s", tau_error)

    return result_message
