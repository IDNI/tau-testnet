"""The genesis faucet: a grant of coins that a new account receives.

The amount is consensus data. The genesis pins it in
`consensus_meta.mechanism_specific_metadata.faucet_amount`, and no vote changes
it: a per-node value would give two honest nodes different balances for the
same block.
"""
from __future__ import annotations

from typing import Any, Optional

import tau_defs

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
    value = getattr(lifecycle, "faucet_amount", DEFAULT_FAUCET_AMOUNT)
    if validate_faucet_amount(value) is not None:
        return DEFAULT_FAUCET_AMOUNT
    return value
