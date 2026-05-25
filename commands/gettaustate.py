import api_response


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return api_response.error_response(
            "gettaustate", "Usage: gettaustate", "INVALID_PARAMS"
        )

    state = container.chain_state.get_rules_state()
    return api_response.success_response("gettaustate", {"rules_state": state or ""})
