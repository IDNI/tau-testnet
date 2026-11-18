"""BLS12-381 G2Basic verification and public-key validation, on arkworks.

One entry point for transaction signatures, block header proofs and sendtx key
checks, so a single code path decides what counts as a valid key or signature.

INJECTION POINT
---------------
Tests that need to control a verdict patch `consensus.bls.verify`. Its verdicts
must equal py_ecc G2Basic.Verify's (and `pubkey_valid` must equal KeyValidate's)
on every input, or nodes running different backends split on which blocks and
transactions are valid.
"""
from __future__ import annotations

from typing import Optional

from py_arkworks_bls12381 import G1Point, G2Point, GT

DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

_FIELD_MODULUS = int(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    16,
)
_MASK_381 = (1 << 381) - 1
_G1_GENERATOR = G1Point()
_G1_IDENTITY = G1Point.identity()


def _g1_encoding_canonical(data: bytes) -> bool:
    # arkworks decodes any infinity-flagged input as the identity, ignoring body and sort flag.
    z = int.from_bytes(data, "big")
    if not (z >> 383) & 1:
        return False
    body = z & _MASK_381
    is_infinity = body == 0
    if bool((z >> 382) & 1) != is_infinity:
        return False
    if is_infinity:
        return not (z >> 381) & 1
    return body < _FIELD_MODULUS


def _g2_encoding_canonical(data: bytes) -> bool:
    # py_ecc gives the second 48-byte half no flags: any set top bit exceeds the modulus.
    z1 = int.from_bytes(data[:48], "big")
    z2 = int.from_bytes(data[48:], "big")
    if not (z1 >> 383) & 1:
        return False
    body = z1 & _MASK_381
    is_infinity = body == 0 and z2 == 0
    if bool((z1 >> 382) & 1) != is_infinity:
        return False
    if is_infinity:
        return not (z1 >> 381) & 1
    return body < _FIELD_MODULUS and z2 < _FIELD_MODULUS


def _decode_pubkey(pk: bytes) -> Optional[G1Point]:
    if not (isinstance(pk, bytes) and len(pk) == 48):
        return None
    if not _g1_encoding_canonical(pk):
        return None
    point = G1Point.from_compressed_bytes(pk)
    # Identity pk with identity sig satisfies the pairing equation for any message.
    if point == _G1_IDENTITY:
        return None
    return point


def pubkey_valid(pk: bytes) -> bool:
    """True for a canonical, on-curve, in-subgroup, non-identity G1 key. Never raises."""
    try:
        return _decode_pubkey(pk) is not None
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:  # pyo3 panics derive from BaseException, not Exception
        return False


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """BLS12-381 G2Basic verify, pk in G1 (48 bytes), sig in G2 (96 bytes). Never raises."""
    try:
        pk_point = _decode_pubkey(pk)
        if pk_point is None:
            return False
        if not isinstance(msg, bytes):
            return False
        if not (isinstance(sig, bytes) and len(sig) == 96):
            return False
        if not _g2_encoding_canonical(sig):
            return False
        sig_point = G2Point.from_compressed_bytes(sig)
        msg_point = G2Point.hash_to_curve(msg, DST)
        return bool(GT.pairing_check([_G1_GENERATOR, -pk_point], [sig_point, msg_point]))
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:  # pyo3 panics derive from BaseException, not Exception
        return False
