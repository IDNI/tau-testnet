"""Canonical transaction signing preimage and signature verification.

WHY THIS EXISTS
---------------
Transaction signatures used to be verified in exactly one place: mempool
admission (`commands/sendtx.py`). Block application never re-checked them --
`chain_state._process_new_block_locked` verifies the header proof, the engine's
`verify_block_header` and the timestamp, and `TauConsensusEngine.apply` reads
`sender_pubkey` as fact. `commands/createblock._validate_signature` exists but is
referenced only by tests.

For ordinary transfers that is tolerable: forging one forges a transfer the
sender could have made anyway, and the balance and sequence checks still bind.
It is NOT tolerable for a feature whose whole promise is independent
co-signatures -- a malicious proposer could otherwise mint a co-signature
bearing an approver's `sender_pubkey` and release parked funds with no approver
involved.

So the preimage and the verify live here, once, and both the admission path and
the apply path call them. Keeping them in one module is the point: two
implementations of a signing preimage is a consensus split waiting to happen.

INJECTION POINT
---------------
Tests that need to control the verdict patch `consensus.tx_signing._bls_verify`.
The backend's verdicts must equal py_ecc G2Basic.Verify's on every input, or
nodes running different backends split on which transactions apply.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Tuple

from py_arkworks_bls12381 import G1Point, G2Point, GT

from consensus.approvals import (
    TX_TYPE_APPROVAL_REQUEST,
    TX_TYPE_TRANSFER_VOTE,
)
from consensus.retractable import (
    TX_TYPE_RETRACT_TRANSFER,
    TX_TYPE_RETRACTABLE_TRANSFER,
)
from consensus.rule_offers import (
    TX_TYPE_RULE_OFFER,
    TX_TYPE_RULE_OFFER_ACCEPT,
    TX_TYPE_RULE_OFFER_REJECT,
)

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


def _bls_verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    """BLS12-381 G2Basic verify, pk in G1 (48 bytes), sig in G2 (96 bytes). Never raises."""
    try:
        if not (isinstance(pk, bytes) and len(pk) == 48):
            return False
        if not isinstance(msg, bytes):
            return False
        if not (isinstance(sig, bytes) and len(sig) == 96):
            return False
        if not (_g1_encoding_canonical(pk) and _g2_encoding_canonical(sig)):
            return False
        pk_point = G1Point.from_compressed_bytes(pk)
        # Identity pk with identity sig satisfies the pairing equation for any message.
        if pk_point == _G1_IDENTITY:
            return False
        sig_point = G2Point.from_compressed_bytes(sig)
        msg_point = G2Point.hash_to_curve(msg, DST)
        return bool(GT.pairing_check([_G1_GENERATOR, -pk_point], [sig_point, msg_point]))
    except (KeyboardInterrupt, SystemExit, GeneratorExit):
        raise
    except BaseException:  # pyo3 panics derive from BaseException, not Exception
        return False


def signing_message_bytes(payload: Dict[str, Any]) -> bytes:
    """CONSENSUS-FROZEN. Canonical bytes over the signed fields of a transaction.

    Per-type field allowlist: a field absent from this dict is NOT signed and
    therefore NOT authenticated, so adding one to a transaction type without
    adding it here lets a proposer rewrite it freely.
    """
    tx_type = payload.get("tx_type", "user_tx")
    signing_dict = {
        "sender_pubkey": payload["sender_pubkey"],
        "sequence_number": payload["sequence_number"],
        "expiration_time": payload["expiration_time"],
        "fee_limit": payload["fee_limit"],
        "tx_type": tx_type,
    }
    # The height deadline is signed for EVERY type, or a proposer could strip it
    # and revive a transaction its owner had let expire. Included only when
    # present, so the bytes of a transaction written before heights existed are
    # unchanged and its signature still verifies -- admission is what requires
    # the field on anything new. approval_request and rule_offer set it again
    # below with the same value, which is a no-op on a dict.
    if payload.get("expire_at_height") is not None:
        signing_dict["expire_at_height"] = payload["expire_at_height"]
    if tx_type == "user_tx":
        signing_dict["operations"] = payload.get("operations", {})
    elif tx_type == "consensus_rule_update":
        signing_dict["rule_revisions"] = payload.get("rule_revisions", [])
        signing_dict["activate_at_height"] = payload.get("activate_at_height")
        if "host_contract_patch" in payload:
            signing_dict["host_contract_patch"] = payload["host_contract_patch"]
    elif tx_type == "consensus_rule_vote":
        signing_dict["update_id"] = payload.get("update_id")
        signing_dict["approve"] = payload.get("approve", True)
    elif tx_type == TX_TYPE_RULE_OFFER:
        signing_dict["recipient_pubkey"] = payload.get("recipient_pubkey")
        signing_dict["rule_text"] = payload.get("rule_text")
        signing_dict["expire_at_height"] = payload.get("expire_at_height")
    elif tx_type == TX_TYPE_RULE_OFFER_ACCEPT:
        signing_dict["offer_id"] = payload.get("offer_id")
        # The accepted text is signed: it is what actually enters the acceptor's
        # specification, and the apply path re-derives offer_id from it.
        signing_dict["rule_text"] = payload.get("rule_text")
    elif tx_type == TX_TYPE_RULE_OFFER_REJECT:
        signing_dict["offer_id"] = payload.get("offer_id")
    elif tx_type == TX_TYPE_APPROVAL_REQUEST:
        # EVERY field that decides what the parked transfer will do must be in
        # here. Anything omitted is unauthenticated, and this transaction is
        # applied LATER, from hash-bound state, by a different transaction --
        # so a proposer who could rewrite the recipient or the amount would be
        # redirecting funds the sender never agreed to send.
        signing_dict["recipient_pubkey"] = payload.get("recipient_pubkey")
        signing_dict["amount"] = payload.get("amount")
        signing_dict["expire_at_height"] = payload.get("expire_at_height")
        signing_dict["approvers"] = payload.get("approvers", {})
        signing_dict["custom_inputs"] = payload.get("custom_inputs", {})
    elif tx_type == TX_TYPE_TRANSFER_VOTE:
        signing_dict["request_id"] = payload.get("request_id")
        signing_dict["approve"] = payload.get("approve", True)
        # Signed even though it carries no consensus meaning: it rides in the
        # block merkle root via block.compute_tx_hash either way, so leaving it
        # unsigned would let a proposer put words in an approver's mouth.
        signing_dict["reason"] = payload.get("reason", "")
    elif tx_type == TX_TYPE_RETRACTABLE_TRANSFER:
        # Every field that fixes where the escrowed funds go and when is signed;
        # the release is applied later by a sweep no signature covers.
        signing_dict["recipient_pubkey"] = payload.get("recipient_pubkey")
        signing_dict["amount"] = payload.get("amount")
        signing_dict["release_at_height"] = payload.get("release_at_height")
        signing_dict["release_at_time"] = payload.get("release_at_time")
    elif tx_type == TX_TYPE_RETRACT_TRANSFER:
        signing_dict["retractable_id"] = payload.get("retractable_id")

    return json.dumps(signing_dict, sort_keys=True, separators=(",", ":")).encode()


def verify_tx_signature(payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Verify a transaction's BLS signature. Returns (ok, reason).

    `reason` is non-empty only when ok is False, so a caller can put it straight
    into a receipt log. Never raises: a malformed signature or pubkey is a
    verification failure, not an exception, because this runs inside block apply
    where an exception would take down the whole block.
    """
    sender_pubkey = payload.get("sender_pubkey")
    signature = payload.get("signature")
    if not isinstance(sender_pubkey, str) or not isinstance(signature, str):
        return False, "missing sender_pubkey or signature"

    try:
        msg_hash = hashlib.sha256(signing_message_bytes(payload)).digest()
    except (KeyError, TypeError) as exc:
        return False, f"unsignable payload: {exc}"

    try:
        sig_bytes = bytes.fromhex(signature)
        pubkey_bytes = bytes.fromhex(sender_pubkey)
    except ValueError:
        return False, "signature or sender_pubkey is not valid hex"

    try:
        if not _bls_verify(pubkey_bytes, msg_hash, sig_bytes):
            return False, "signature does not verify against sender_pubkey"
    except Exception as exc:
        return False, f"cryptographic error during verification: {exc}"

    return True, ""
