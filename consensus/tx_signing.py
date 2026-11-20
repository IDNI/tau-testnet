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
from typing import Any, Dict, Tuple

from consensus import bls
from consensus.approvals import (
    TX_TYPE_APPROVAL_REQUEST,
    TX_TYPE_RULE_CHANGE_CANCEL,
    TX_TYPE_RULE_CHANGE_REQUEST,
    TX_TYPE_TRANSFER_VOTE,
)
from consensus.payout_rules import (
    TX_TYPE_EXECUTE_PAYOUT_RULE,
    TX_TYPE_INSTALL_PAYOUT_RULE,
    TX_TYPE_REMOVE_PAYOUT_RULE,
)
from consensus.standing_payments import (
    TX_TYPE_CANCEL_STANDING_PAYMENT,
    TX_TYPE_CREATE_STANDING_PAYMENT,
    TX_TYPE_EXECUTE_STANDING_PAYMENT,
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
    elif tx_type == TX_TYPE_CREATE_STANDING_PAYMENT:
        # Every field that fixes the authorization is signed: the apply path
        # installs exactly these root fields (the recipient comes from
        # sender_pubkey itself), so anything omitted here could be rewritten
        # by a proposer into a different authorization than the payer chose —
        # above all the recipient, the amount and the end condition.
        signing_dict["standing_recipient_pubkey"] = payload.get("standing_recipient_pubkey")
        signing_dict["standing_amount"] = payload.get("standing_amount")
        signing_dict["standing_schedule"] = payload.get("standing_schedule")
        signing_dict["standing_signed_day"] = payload.get("standing_signed_day")
        signing_dict["standing_anchor_ts"] = payload.get("standing_anchor_ts")
        signing_dict["standing_window_seconds"] = payload.get("standing_window_seconds")
        signing_dict["standing_final_ts"] = payload.get("standing_final_ts")
        signing_dict["standing_max_occurrences"] = payload.get("standing_max_occurrences")
        signing_dict["standing_max_total"] = payload.get("standing_max_total")
        signing_dict["standing_fee_limit"] = payload.get("standing_fee_limit")
        signing_dict["standing_policy_version_ref"] = payload.get("standing_policy_version_ref")
        signing_dict["standing_allow_catch_up"] = payload.get("standing_allow_catch_up")
        signing_dict["standing_version"] = payload.get("standing_version")
    elif tx_type == TX_TYPE_CANCEL_STANDING_PAYMENT:
        # The id names the exact authorization (a hash of its signed terms),
        # so signing it binds the cancellation to that authorization alone.
        signing_dict["standing_auth_id"] = payload.get("standing_auth_id")
    elif tx_type == TX_TYPE_EXECUTE_STANDING_PAYMENT:
        # Same binding: an execution signature covers exactly one
        # authorization; the terms executed are the book's, never the
        # submitter's, so there is nothing else to sign.
        signing_dict["standing_auth_id"] = payload.get("standing_auth_id")
    elif tx_type == TX_TYPE_INSTALL_PAYOUT_RULE:
        # Every field that fixes the rule is signed: the declared recipient
        # set, the leg program, both caps and the period shape. The apply
        # path installs exactly these root fields, so anything omitted here
        # could be rewritten by a proposer into a different rule than the
        # owner chose — above all the recipients and the caps.
        signing_dict["payout_recipients"] = payload.get("payout_recipients")
        signing_dict["payout_legs"] = payload.get("payout_legs")
        signing_dict["payout_max_per_execution"] = payload.get("payout_max_per_execution")
        signing_dict["payout_max_per_period"] = payload.get("payout_max_per_period")
        signing_dict["payout_period_seconds"] = payload.get("payout_period_seconds")
        signing_dict["payout_period_anchor_ts"] = payload.get("payout_period_anchor_ts")
        signing_dict["payout_version"] = payload.get("payout_version")
    elif tx_type == TX_TYPE_REMOVE_PAYOUT_RULE:
        # Nothing beyond the signer's identity (sender_pubkey is always
        # signed): a removal names the signer's own rule, and there is no
        # field a proposer could rewrite to redirect it.
        pass
    elif tx_type == TX_TYPE_EXECUTE_PAYOUT_RULE:
        # The execution's inputs are signed: which rule, which settlement,
        # and the base amount the stored program computes over. The legs
        # themselves are the book's computation, never the submitter's, so
        # there is nothing else to sign.
        signing_dict["payout_rule_id"] = payload.get("payout_rule_id")
        signing_dict["payout_settlement_id"] = payload.get("payout_settlement_id")
        signing_dict["payout_base_amount"] = payload.get("payout_base_amount")

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
