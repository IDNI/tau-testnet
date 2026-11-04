"""BLS public-key checks used at mempool admission."""
from __future__ import annotations

from typing import Any, Optional

from consensus.tx_signing import decode_pubkey

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def validate_bls_pubkey(key_hex: Any, key_name: str) -> Optional[str]:
    """Error text when `key_hex` is not a valid BLS12-381 public key, else None."""
    if not isinstance(key_hex, str) or len(key_hex) != 96 or not set(key_hex) <= _HEX_DIGITS:
        return f"Invalid {key_name}: must be a 96-character hex BLS12-381 public key."
    if decode_pubkey(bytes.fromhex(key_hex)) is None:
        return f"Invalid {key_name}: not a valid BLS12-381 public key."
    return None
