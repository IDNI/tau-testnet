"""Real BLS12-381 keys and signatures for tests.

arkworks signatures and public keys are byte-identical to py_ecc's G2Basic and
about 100x faster to produce, so fixtures can sign every transaction for real.
"""
import hashlib
from typing import Any, Dict

from py_arkworks_bls12381 import G1Point, G2Point, Scalar

from consensus.tx_signing import signing_message_bytes

# Spelled out, not imported: a wrong DST in the verifier must not be masked by a matching signer.
DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
CURVE_ORDER = 52435875175126190479447740508185965837690552500527637822603658699938581184513

SK_ALICE = 0xA11CE
SK_BOB = 0xB0B
SK_CAROL = 0xCA401
SK_MALLORY = 0xBAD

FAR_FUTURE = 9999999999


def check_sk(sk: int) -> int:
    # Scalar() silently reduces mod r, which would alias distinct keys.
    if not (isinstance(sk, int) and 0 < sk < CURVE_ORDER):
        raise ValueError("secret key must satisfy 0 < sk < r")
    return sk


def pubkey_hex(sk: int) -> str:
    return (G1Point() * Scalar(check_sk(sk))).to_compressed_bytes().hex()


def sign_message(sk: int, msg: bytes) -> bytes:
    return (G2Point.hash_to_curve(msg, DST) * Scalar(check_sk(sk))).to_compressed_bytes()


def sign_payload(payload: Dict[str, Any], sk: int) -> Dict[str, Any]:
    """Set payload["signature"] over the payload's canonical signing bytes."""
    digest = hashlib.sha256(signing_message_bytes(payload)).digest()
    payload["signature"] = sign_message(sk, digest).hex()
    return payload


def sign_tx(tx: Dict[str, Any], sk: int = SK_ALICE) -> Dict[str, Any]:
    """sign_payload for a test transaction that leaves out envelope fields the preimage needs."""
    tx.setdefault("sequence_number", 0)
    tx.setdefault("expiration_time", FAR_FUTURE)
    tx.setdefault("fee_limit", "0")
    return sign_payload(tx, sk)
