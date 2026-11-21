import api_response
import tau_defs


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return api_response.error_response(
            "gettaustate", "Usage: gettaustate", "INVALID_PARAMS"
        )

    state = container.chain_state.get_rules_state()
    # Capabilities let a wallet detect whether recipient-side policy is
    # active on this node before deploying an inbound-only rule (issues
    # #47/#76): an old node has no such field, which means inactive.
    return api_response.success_response(
        "gettaustate",
        {
            "rules_state": state or "",
            "capabilities": tau_defs.node_capabilities(),
        },
    )
