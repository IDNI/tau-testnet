from typing import TYPE_CHECKING

import api_response

if TYPE_CHECKING:
    from app.container import ServiceContainer


def execute(cmd: str, container: 'ServiceContainer') -> str:
    """
    Returns a list of all known account addresses.
    Usage: getallaccounts
    """
    try:
        with container.chain_state._balance_lock:
            addresses = list(container.chain_state._balances.keys())
    except Exception as exc:
        return api_response.error_response(
            "getallaccounts", f"Failed to read account list: {exc}", "INTERNAL_ERROR"
        )
    return api_response.success_response("getallaccounts", {"accounts": addresses})
