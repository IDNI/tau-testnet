"""The genesis faucet: a grant of coins that a new account receives.

The amount is consensus data. The genesis pins it in
`consensus_meta.mechanism_specific_metadata.faucet_amount`, and no vote changes
it: a per-node value would give two honest nodes different balances for the
same block.
"""
from __future__ import annotations

from typing import Any, Optional

import tau_defs
from errors import BlockchainBug

_MISSING = object()

#: The amount of a network whose genesis names none: no faucet.
DEFAULT_FAUCET_AMOUNT = 0


def validate_faucet_amount(value: Any) -> Optional[str]:
    """An error text for a genesis value that is not a valid amount, else None."""
    if isinstance(value, bool) or not isinstance(value, int):
        return "must be an integer"
    if not 0 <= value <= tau_defs.MAX_TRANSFER_VALUE:
        return f"must be in [0, {tau_defs.MAX_TRANSFER_VALUE}]"
    return None


def amount(lifecycle) -> int:
    """The grant of the network that `lifecycle` belongs to. 0 is no faucet."""
    # The genesis load validates the amount, so a missing or bad value here is a node bug.
    value = getattr(lifecycle, "faucet_amount", _MISSING)
    if value is _MISSING:
        raise BlockchainBug("lifecycle manager has no faucet_amount")
    err = validate_faucet_amount(value)
    if err is not None:
        raise BlockchainBug(f"lifecycle faucet_amount {err}: {value!r}")
    return value


def has_account(balances, sequences, address) -> bool:
    """Whether `address` is a key of the balance map or of the sequence map.

    The accounts hash covers only these two maps, so `last_transfer_ts` makes no record.
    """
    return address in balances or address in (sequences or {})


def spendable(balances, sequences, address, grant: int) -> int:
    """The stored balance of `address`, or the pending grant if it has no record.

    The one grant rule for every read and write. A recorded balance of 0 gets nothing.
    """
    if has_account(balances, sequences, address):
        return int(balances.get(address, 0))
    return grant


def faucet_pending(balances, sequences, address, grant: int) -> bool:
    """Whether the next touch of `address` makes its record with the grant."""
    return bool(grant) and not has_account(balances, sequences, address)


def granted(parent_balances, parent_sequences, balances, sequences, grant: int) -> int:
    """The coins that the grants of one block add to the supply."""
    if not grant:
        return 0
    before = set(parent_balances or {}) | set(parent_sequences or {})
    after = set(balances or {}) | set(sequences or {})
    return grant * len(after - before)
