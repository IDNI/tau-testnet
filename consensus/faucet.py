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


def has_account(balances, sequences, address) -> bool:
    """Whether the chain holds a record for `address`.

    A record is a key of the balance map or of the sequence map: the accounts
    hash covers both maps, and a reload restores both. `last_transfer_ts` is
    not hashed, so it makes no record.
    """
    return address in balances or address in (sequences or {})


def spendable(balances, sequences, address, grant: int) -> int:
    """What `address` can spend: its stored balance, or the pending grant.

    The ONE grant rule, for every read and every write: an address with no
    record has the grant pending, and a write through this value makes the
    record with the grant in it. A recorded balance of 0 gets nothing.
    """
    if has_account(balances, sequences, address):
        return int(balances.get(address, 0))
    return grant


def granted(parent_balances, parent_sequences, balances, sequences, grant: int) -> int:
    """The coins that the grants of one block add to the supply."""
    if not grant:
        return 0
    before = set(parent_balances or {}) | set(parent_sequences or {})
    after = set(balances or {}) | set(sequences or {})
    return grant * len(after - before)
