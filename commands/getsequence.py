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

    # The tip goes out alongside the sequence because a client needs BOTH to
    # build a transaction -- the sequence and the height its expire_at_height is
    # measured from -- and asking for the height any other way means getblocks,
    # which returns the entire chain.
    head = db.get_canonical_head_block()
    tip_height = 0
    if head:
        try:
            tip_height = int(head["header"]["block_number"])
        except (KeyError, TypeError, ValueError):
            tip_height = 0

    return api_response.success_response(
        "getsequence",
        {"address": address, "sequence_number": int(seq), "tip_height": tip_height},
    )
