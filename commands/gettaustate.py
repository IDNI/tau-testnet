import api_response
import tau_defs


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return api_response.error_response(
            "gettaustate", "Usage: gettaustate", "INVALID_PARAMS"
        )

    state = container.chain_state.get_rules_state()
    # Capabilities this node enforces, so wallets can discover them without
    # reading the rules (issues #47/#76): an account can refuse incoming
    # transfers (recipient_policy) and can cap how long a payment to it may
    # be held (recipient_max_hold). Empty while the feature is inactive.
    capabilities = []
    if tau_defs.RECIPIENT_CONTROLS_ACTIVE:
        capabilities.extend(["recipient_policy", "recipient_max_hold"])
    return api_response.success_response(
        "gettaustate", {"rules_state": state or "", "capabilities": capabilities},
    )
