"""The chain id (genesis block hash) programmable-payment transactions must sign."""
import api_response
from consensus.chain_binding import current_chain_id

_CMD = "getchainid"


def execute(raw_command: str, container):
    chain_id = current_chain_id()
    if not chain_id:
        return api_response.error_response(_CMD, "chain id not known yet (no genesis block)", "UNAVAILABLE")
    return api_response.success_response(_CMD, {"chain_id": chain_id})
