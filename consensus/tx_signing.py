"""Canonical transaction signing preimage and signature verification.

WHY THIS EXISTS
---------------
`sender_pubkey` is only a claim until its signature is checked, and every
account-scoped rule (balance, sequence, policy clause, approvals) trusts it.
Signatures are verified at mempool admission (`commands/sendtx.py`) and again for
every transaction at block apply, at one site at the top of the apply loop in
`TauConsensusEngine.apply`. Without the apply check a proposer could include a
transfer from any account, or a rule offer or a vote in anyone's name.

The preimage and the verify live here, once, and both paths call them. Two
implementations of a signing preimage would be a consensus split waiting to
happen.

INJECTION POINT
---------------
Tests that need to control the verdict patch `consensus.bls.verify`, which also
decides block header proofs. The backend's verdicts must equal py_ecc
G2Basic.Verify's on every input, or nodes running different backends split on
which transactions apply.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional, Tuple

from consensus import bls
from consensus.approvals import (
    TX_TYPE_APPROVAL_REQUEST,
    TX_TYPE_RULE_CHANGE_CANCEL,
    TX_TYPE_RULE_CHANGE_REQUEST,
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
from consensus.standing import (
    TX_TYPE_STANDING_CANCEL,
    TX_TYPE_STANDING_CREATE,
    TX_TYPE_STANDING_EXECUTE,
)

# The Bounty 01 transaction types are bound to the network they were
# signed for (see network_binding below). The pre-existing types predate
# network binding and keep their CONSENSUS-FROZEN preimage bytes.
NETWORK_BOUND_TX_TYPES = frozenset(
    {TX_TYPE_STANDING_CREATE, TX_TYPE_STANDING_EXECUTE, TX_TYPE_STANDING_CANCEL}
)

_network_binding_override: Optional[str] = None
_network_binding_cache: Optional[str] = None


def set_network_binding(binding: Optional[str]) -> None:
    """Pin the network identity bound into the Bounty 01 preimages.

    Node startup pins the identity of the chain it loaded; tests pin a
    foreign identity to prove a transaction signed for another network
    is refused. Passing None releases the pin and drops the cached
    resolution, so the next lookup re-resolves against the current chain.
    """
    global _network_binding_override, _network_binding_cache
    _network_binding_override = binding
    _network_binding_cache = None


def network_binding() -> str:
    """The network identity bound into the Bounty 01 signing preimage.

    Resolves, in order: the explicit pin, the genesis hash of the local
    chain (the identity two nodes compare when they peer), and the
    configured network id. The resolved value is cached for the life of
    the process: a signer and a verifier in one process must never watch
    it move under them, and every node that has loaded its chain resolves
    the same genesis hash.
    """
    global _network_binding_cache
    if _network_binding_override is not None:
        return _network_binding_override
    if _network_binding_cache is None:
        _network_binding_cache = _resolve_network_binding()
    return _network_binding_cache


def _resolve_network_binding() -> str:
    try:
        import db

        # Only an already-open connection: resolving a signature must
        # never create a database as a side effect.
        if db._db_conn is not None:
            genesis = db.get_genesis_hash()
            if genesis:
                return genesis
    except Exception:
        pass
    import config

    return str(config.NETWORK_ID)


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
    if tx_type in NETWORK_BOUND_TX_TYPES:
        # The network identity is signed for the Bounty 01 types, so a
        # transaction signed for another network's genesis cannot verify
        # on this one, however valid its signature is over there: the
        # preimage it was made over names a different network. Sequence
        # numbers alone cannot give this -- two networks that share a
        # genesis-era account state would accept each other's replays.
        signing_dict["network_id"] = network_binding()
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
    elif tx_type == TX_TYPE_RULE_CHANGE_REQUEST:
        # Everything the request id commits to, so the approvers' votes bind
        # the exact change and a proposer cannot swap the body or the slots.
        signing_dict["kind"] = payload.get("kind")
        signing_dict["rule_text"] = payload.get("rule_text", "")
        signing_dict["offer_id"] = payload.get("offer_id", "")
        signing_dict["approvers"] = payload.get("approvers", {})
    elif tx_type == TX_TYPE_RULE_CHANGE_CANCEL:
        signing_dict["request_id"] = payload.get("request_id")
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
    elif tx_type == TX_TYPE_STANDING_CREATE:
        # EVERY field that fixes the authorization's terms is signed: the
        # authorization is applied later, over many blocks, by execute
        # transactions the payer does not sign -- so a proposer who could
        # rewrite the recipient, the amount or the end condition here
        # would be redirecting future debits the payer never agreed to.
        signing_dict["recipient_pubkey"] = payload.get("recipient_pubkey")
        signing_dict["amount"] = payload.get("amount")
        signing_dict["period_kind"] = payload.get("period_kind")
        signing_dict["anchor_timestamp"] = payload.get("anchor_timestamp")
        signing_dict["window_start_offset"] = payload.get("window_start_offset")
        signing_dict["window_end_offset"] = payload.get("window_end_offset")
        signing_dict["final_period"] = payload.get("final_period")
        signing_dict["max_occurrences"] = payload.get("max_occurrences")
        signing_dict["max_total"] = payload.get("max_total")
        signing_dict["supersedes_id"] = payload.get("supersedes_id")
    elif tx_type == TX_TYPE_STANDING_EXECUTE:
        signing_dict["standing_id"] = payload.get("standing_id")
    elif tx_type == TX_TYPE_STANDING_CANCEL:
        signing_dict["standing_id"] = payload.get("standing_id")

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
        if not bls.verify(pubkey_bytes, msg_hash, sig_bytes):
            return False, "signature does not verify against sender_pubkey"
    except Exception as exc:
        return False, f"cryptographic error during verification: {exc}"

    return True, ""
