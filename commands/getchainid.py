"""Return this node's chain id: the genesis block hash.

Clients sign the new programmable-payments transaction types (grants,
standing payments, receive routes, payout rules) with this value as
``chain_id`` so a transaction cannot be replayed on another Tau network.
"""
import api_response
import db

_CMD = "getchainid"


def execute(raw_command: str, container):
    chain_id = db.get_genesis_hash() or ""
    return api_response.success_response(_CMD, {"chain_id": chain_id})
