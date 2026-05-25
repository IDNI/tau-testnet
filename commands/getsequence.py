import db
import api_response


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            "getsequence", "Usage: getsequence <address>", "INVALID_PARAMS"
        )

    address = parts[1]
    seq = container.chain_state.get_sequence_number(address)

    pending_seq = db.get_pending_sequence(address)
    if pending_seq is not None and pending_seq >= seq:
        seq = pending_seq + 1

    return api_response.success_response(
        "getsequence", {"address": address, "sequence_number": int(seq)}
    )
