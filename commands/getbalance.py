import api_response


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            "getbalance", "Usage: getbalance <address>", "INVALID_PARAMS"
        )

    address = parts[1]
    bal = container.chain_state.get_balance(address)
    return api_response.success_response(
        "getbalance", {"address": address, "balance": str(bal)}
    )
