"""Transaction checks that mempool admission and block apply share.

A proposer can put any transaction into a block, so a check that runs only at
admission does not bind it. Admission and apply call the same functions here.
"""
from __future__ import annotations

from typing import Any, Optional, Tuple

from consensus.approvals import TX_TYPE_APPROVAL_REQUEST
from consensus.retractable import TX_TYPE_RETRACTABLE_TRANSFER
from consensus.rule_offers import TX_TYPE_RULE_OFFER
from consensus import bls

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_AMOUNT_LIMIT = 1 << 256

APPLY_REASON_TRANSFER = "invalid_transfer"
APPLY_REASON_RECIPIENT_KEY = "invalid_recipient_key"


def validate_bls_pubkey(key_hex: Any, key_name: str) -> Optional[str]:
    """Error text when `key_hex` is not a valid BLS12-381 public key, else None."""
    if not isinstance(key_hex, str) or len(key_hex) != 96 or not set(key_hex) <= _HEX_DIGITS:
        return f"Invalid {key_name}: must be a 96-character hex BLS12-381 public key."
    if not bls.pubkey_valid(bytes.fromhex(key_hex)):
        return f"Invalid {key_name}: not a valid BLS12-381 public key."
    return None


def check_transfer(transfer: Any, sender_pubkey: Any) -> Optional[str]:
    """Error text for one user_tx transfer, or None when it is valid."""
    if not (isinstance(transfer, (list, tuple)) and len(transfer) == 3):
        return f"invalid transfer format: {transfer!r}"
    from_addr, to_addr, amount = transfer
    if not isinstance(sender_pubkey, str) or from_addr != sender_pubkey:
        return "'from' address does not match sender_pubkey"
    for value, name in ((from_addr, "'from' address"), (to_addr, "'to' address")):
        err = validate_bls_pubkey(value, name)
        if err:
            return err
    if to_addr.lower() == from_addr.lower():
        return "'to' address is the sender"
    if isinstance(amount, bool) or not isinstance(amount, (str, int)):
        return f"invalid amount: {amount!r}"
    try:
        amount_int = int(amount)
    except ValueError:
        return f"invalid amount: {amount!r}"
    if not 0 < amount_int < _AMOUNT_LIMIT:
        return f"amount must be positive and below 2**256: {amount!r}"
    return None


def _recipient_keys(tx: dict) -> list:
    tx_type = tx.get("tx_type", "user_tx")
    if tx_type in (TX_TYPE_RULE_OFFER, TX_TYPE_RETRACTABLE_TRANSFER):
        return [("recipient_pubkey", tx.get("recipient_pubkey"))]
    if tx_type == TX_TYPE_APPROVAL_REQUEST:
        keys = [("recipient_pubkey", tx.get("recipient_pubkey"))]
        approvers = tx.get("approvers")
        if isinstance(approvers, dict):
            keys.extend(("approver", key) for key in approvers.values())
        return keys
    return []


def apply_tx_error(tx: dict) -> Optional[Tuple[str, str]]:
    """(receipt reason, detail) when block apply must refuse `tx`, else None.

    Checks each transfer of a user_tx and the recipient keys of the other types.
    The signature check runs before this one, in the apply loop.
    """
    if tx.get("tx_type", "user_tx") == "user_tx":
        operations = tx.get("operations")
        transfers = operations.get("1") if isinstance(operations, dict) else None
        if transfers is not None:
            if not isinstance(transfers, list):
                return APPLY_REASON_TRANSFER, "transfers (key '1') must be a list"
            sender = tx.get("sender_pubkey")
            for index, transfer in enumerate(transfers):
                error = check_transfer(transfer, sender)
                if error:
                    return APPLY_REASON_TRANSFER, f"transfer #{index + 1}: {error}"
    for name, key in _recipient_keys(tx):
        err = validate_bls_pubkey(key, name)
        if err:
            return APPLY_REASON_RECIPIENT_KEY, err
    return None
