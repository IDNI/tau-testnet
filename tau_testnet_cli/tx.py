"""Transaction builders, BLS signing, and submission for the Tau Testnet CLI.

Reuses the canonical signer in ``commands.sendtx._get_signing_message_bytes``
so the wire format and signature-verification path stay identical to the
existing ``wallet.py`` flow and the existing test suite.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Mapping

from py_ecc.bls import G2Basic

from commands.sendtx import _get_signing_message_bytes
from tau_manager import DEFAULT_RULE_BV_WIDTH
from wallet import _parse_privkey

from tau_testnet_cli import rpc as rpc_mod


MAX_TAU_TRANSFER_AMOUNT = (1 << DEFAULT_RULE_BV_WIDTH) - 1
DEFAULT_EXPIRY_SECONDS = 600
# Blocks, not seconds: the height deadline every transaction carries. Mirrors
# tau_defs.DEFAULT_TX_EXPIRY_BLOCKS, kept here so the CLI has no import of the
# node package.
DEFAULT_EXPIRY_BLOCKS = 1_000


def _check_expire_at_height(expire_at_height: Any) -> int:
    """Every builder takes one. A transaction without it is refused at
    admission, so building one that cannot be sent helps nobody."""
    if not isinstance(expire_at_height, int) or isinstance(expire_at_height, bool):
        raise ValueError("expire_at_height must be an integer block height")
    if expire_at_height < 1:
        raise ValueError("expire_at_height must be a positive block height")
    return expire_at_height


# --------------------------------------------------------------------------- #
# Validation helpers
# --------------------------------------------------------------------------- #


def validate_transfer_amount(amount: int) -> None:
    if amount < 0 or amount > MAX_TAU_TRANSFER_AMOUNT:
        raise ValueError(
            f"transfer amount must be in [0, {MAX_TAU_TRANSFER_AMOUNT}] "
            f"(bv[{DEFAULT_RULE_BV_WIDTH}]), got {amount}"
        )


def parse_transfer_flag(flag_value: str) -> tuple[str, int]:
    """Parse a ``--transfer pubkey:amount`` argument."""
    if ":" not in flag_value:
        raise ValueError(
            f"--transfer expects 'pubkey:amount', got {flag_value!r}"
        )
    addr, amount_str = flag_value.split(":", 1)
    addr = addr.strip()
    amount_str = amount_str.strip()
    try:
        amount = int(amount_str)
    except ValueError as exc:
        raise ValueError(
            f"--transfer amount must be an integer, got {amount_str!r}"
        ) from exc
    if not addr:
        raise ValueError("--transfer 'pubkey' part is empty")
    return addr, amount


# --------------------------------------------------------------------------- #
# Payload builders
# --------------------------------------------------------------------------- #


def build_user_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    operations: Mapping[str, Any],
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='user_tx'`` payload (without signature)."""
    if not operations:
        raise ValueError("transaction must contain at least one operation")
    return {
        "tx_type": "user_tx",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "operations": dict(operations),
        "fee_limit": str(fee_limit),
    }


def build_consensus_rule_update_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    rule_revisions: list[str],
    activate_at_height: int,
    host_contract_patch: dict | None = None,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='consensus_rule_update'`` payload (without signature)."""
    if not isinstance(rule_revisions, list) or not all(
        isinstance(r, str) for r in rule_revisions
    ):
        raise ValueError("rule_revisions must be a list of strings")
    if not isinstance(activate_at_height, int) or activate_at_height < 1:
        raise ValueError("activate_at_height must be a positive integer")

    payload: dict[str, Any] = {
        "tx_type": "consensus_rule_update",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "rule_revisions": list(rule_revisions),
        "activate_at_height": activate_at_height,
    }
    if host_contract_patch is not None:
        payload["host_contract_patch"] = host_contract_patch
    return payload


def build_consensus_rule_vote_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    update_id: str,
    approve: bool = True,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='consensus_rule_vote'`` payload (without signature).

    ``approve`` is hard-coded ``True`` by the CLI surface — ``approve=False`` is
    rejected by ``consensus.admission`` server-side.
    """
    return {
        "tx_type": "consensus_rule_vote",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "update_id": update_id,
        "approve": approve,
    }


# --------------------------------------------------------------------------- #
# Signing & submission
# --------------------------------------------------------------------------- #


def _coerce_sk_int(private_key: int | str | bytes) -> int:
    if isinstance(private_key, int):
        if private_key < 0 or private_key >= 1 << 256:
            raise ValueError("private key int out of 32-byte range")
        return private_key
    if isinstance(private_key, (bytes, bytearray)):
        raw = bytes(private_key)
        if len(raw) != 32:
            raise ValueError(f"private key bytes must be 32 long, got {len(raw)}")
        return int.from_bytes(raw, "big")
    if isinstance(private_key, str):
        raw = _parse_privkey(private_key)
        return int.from_bytes(raw, "big")
    raise TypeError(f"unsupported private_key type: {type(private_key).__name__}")


def sign_tx(payload: dict, private_key: int | str | bytes) -> dict:
    """Compute the BLS signature and store it under ``signature`` (hex).

    Returns the same ``payload`` dict (mutated). Reuses the canonical signing
    bytes from :func:`commands.sendtx._get_signing_message_bytes` so the
    signature is byte-for-byte compatible with ``wallet.py`` and the
    governance integration tests.
    """
    sk_int = _coerce_sk_int(private_key)
    msg_bytes = _get_signing_message_bytes(payload)
    msg_hash = hashlib.sha256(msg_bytes).digest()
    sig = G2Basic.Sign(sk_int, msg_hash)
    payload["signature"] = sig.hex()
    return payload


def get_sequence(
    pubkey: str,
    *,
    host: str,
    port: int,
    timeout: float = rpc_mod.DEFAULT_TIMEOUT,
) -> int:
    """Fetch the next sequence number for ``pubkey`` from the node."""
    return get_sequence_and_tip(pubkey, host=host, port=port, timeout=timeout)[0]


def get_sequence_and_tip(
    pubkey: str,
    *,
    host: str,
    port: int,
    timeout: float = rpc_mod.DEFAULT_TIMEOUT,
) -> tuple[int, int]:
    """The next sequence number for ``pubkey`` and the node's tip height.

    One call, because a transaction needs both: the sequence to order it, and
    the height its ``expire_at_height`` is counted from. A node too old to
    report ``tip_height`` yields 0, and the caller falls back to getblocks.
    """
    return get_sequence_tip_and_network(pubkey, host=host, port=port, timeout=timeout)[:2]


def get_sequence_tip_and_network(
    pubkey: str,
    *,
    host: str,
    port: int,
    timeout: float = rpc_mod.DEFAULT_TIMEOUT,
) -> tuple[int, int, str]:
    """Sequence number, tip height and the network's genesis hash, in one call.

    The genesis hash is what the types bound to a network sign
    (``consensus/network_binding.py``). A node too old to report it yields "".
    """
    response = rpc_mod.send_command(
        f"getsequence {pubkey}", host, port, timeout=timeout
    )
    try:
        parsed = json.loads(response)
    except (ValueError, TypeError):
        raise RuntimeError(f"unexpected getsequence response: {response!r}")
    if not isinstance(parsed, dict):
        raise RuntimeError(f"unexpected getsequence response: {response!r}")
    if parsed.get("status") == "error":
        err = parsed.get("error", {}) or {}
        raise RuntimeError(
            f"node rejected getsequence: {err.get('code', 'ERROR')} {err.get('message', '')}".strip()
        )
    data = parsed.get("data") or {}
    seq = data.get("sequence_number")
    if not isinstance(seq, int):
        raise RuntimeError(f"unexpected getsequence response: {response!r}")
    tip = data.get("tip_height")
    if not isinstance(tip, int) or isinstance(tip, bool):
        tip = 0
    genesis_hash = data.get("genesis_hash")
    if not isinstance(genesis_hash, str):
        genesis_hash = ""
    return seq, tip, genesis_hash


def bind_to_network(payload: dict, genesis_hash: str) -> dict:
    """Name the network in a payload whose type signs it; call before signing.

    Other types are returned untouched. Raises ``ValueError`` when the type needs
    the network and ``genesis_hash`` is empty.
    """
    from consensus.network_binding import BOUND_TX_TYPES, FIELD

    if payload.get("tx_type") in BOUND_TX_TYPES:
        if not genesis_hash:
            raise ValueError(
                "the node did not report its genesis hash, and this transaction "
                "type is signed for one network"
            )
        payload[FIELD] = genesis_hash
    return payload


def submit_tx(
    payload: dict,
    *,
    host: str,
    port: int,
    timeout: float = rpc_mod.DEFAULT_TIMEOUT,
) -> str:
    """Send ``sendtx '<payload>'`` to the node and return the raw response."""
    blob = json.dumps(payload, separators=(",", ":"))
    return rpc_mod.send_command(
        f"sendtx '{blob}'", host, port, timeout=timeout
    )


#: Waits in seconds before each retry after ESTIMATE_BUSY: the node runs one
#: estimate at a time, so the slot is often free again soon.
ESTIMATE_BUSY_BACKOFF = (0.5, 1.0, 2.0)


def estimate_fee(
    payload: dict,
    *,
    host: str,
    port: int,
    timeout: float = rpc_mod.DEFAULT_TIMEOUT,
    backoff: tuple = ESTIMATE_BUSY_BACKOFF,
) -> str:
    """The node's fee estimate for a signed draft, from ``checktx estimate``.

    Raises RuntimeError with the node's own code and message when the node
    gives no estimate.
    """
    blob = json.dumps(payload, separators=(",", ":"))
    for delay in (*backoff, None):
        response = rpc_mod.send_command(
            f"checktx estimate '{blob}'", host, port, timeout=timeout
        )
        try:
            parsed = json.loads(response)
        except (ValueError, TypeError):
            raise RuntimeError(f"unexpected checktx response: {response!r}")
        if not isinstance(parsed, dict):
            raise RuntimeError(f"unexpected checktx response: {response!r}")
        if parsed.get("status") == "error":
            err = parsed.get("error", {}) or {}
            if err.get("code") == "ESTIMATE_BUSY" and delay is not None:
                time.sleep(delay)
                continue
            raise RuntimeError(
                f"{err.get('code', 'ERROR')} {err.get('message', '')}".strip()
            )
        fee = (parsed.get("data") or {}).get("estimated_fee")
        if not isinstance(fee, str) or not fee.isdigit():
            raise RuntimeError(f"no estimated_fee in the checktx response: {response!r}")
        return fee


def build_rule_offer_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    recipient_pubkey: str,
    rule_text: str,
    expire_at_height: int,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='rule_offer'`` payload (without signature)."""
    if not isinstance(recipient_pubkey, str) or len(recipient_pubkey) != 96:
        raise ValueError("recipient_pubkey must be a 96-character hex public key")
    if recipient_pubkey.lower() == (sender_pubkey or "").lower():
        raise ValueError("recipient_pubkey must differ from the sender")
    if not isinstance(rule_text, str) or not rule_text.strip():
        raise ValueError("rule_text must be a non-empty string")
    if not isinstance(expire_at_height, int) or expire_at_height < 1:
        raise ValueError("expire_at_height must be a positive integer")

    return {
        "tx_type": "rule_offer",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient_pubkey.lower(),
        "rule_text": rule_text,
        "expire_at_height": expire_at_height,
    }


def build_rule_offer_accept_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    offer_id: str,
    rule_text: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='rule_offer_accept'`` payload (without signature).

    ``rule_text`` must be the offered text VERBATIM: the node recomputes the
    offer id from it, so any reformatting makes the accept unapplicable.
    """
    if not isinstance(offer_id, str) or len(offer_id) != 64:
        raise ValueError("offer_id must be a 64-character hex string")
    if not isinstance(rule_text, str) or not rule_text.strip():
        raise ValueError("rule_text must be a non-empty string")

    return {
        "tx_type": "rule_offer_accept",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "offer_id": offer_id.lower(),
        "rule_text": rule_text,
    }


def build_rule_offer_reject_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    offer_id: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='rule_offer_reject'`` payload (without signature)."""
    if not isinstance(offer_id, str) or len(offer_id) != 64:
        raise ValueError("offer_id must be a 64-character hex string")

    return {
        "tx_type": "rule_offer_reject",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "offer_id": offer_id.lower(),
    }


# --------------------------------------------------------------------------- #
# Higher-level user-tx assembly (used by `tau-testnet tx send`)
# --------------------------------------------------------------------------- #


def assemble_operations(
    *,
    sender_pubkey: str,
    to: str | None = None,
    amount: int | None = None,
    transfers: list[str] | None = None,
    rule_file: str | Path | None = None,
    operations_json: str | Path | None = None,
) -> dict[str, Any]:
    """Assemble the ``operations`` dict from CLI flags.

    Order of precedence: ``--operations-json`` overrides everything; otherwise
    ``--rule-file``, ``--to/--amount``, and ``--transfer`` are merged into a
    single dict (matches ``wallet.cmd_send`` behaviour).
    """
    if operations_json is not None:
        text = Path(operations_json).read_text(encoding="utf-8")
        try:
            obj = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"--operations-json file is not valid JSON: {exc}"
            ) from exc
        if not isinstance(obj, dict):
            raise ValueError("--operations-json must contain a JSON object")
        return obj

    operations: dict[str, Any] = {}

    if rule_file is not None:
        rule_text = Path(rule_file).read_text(encoding="utf-8").strip()
        if not rule_text:
            raise ValueError("--rule-file is empty")
        operations["0"] = rule_text

    transfer_list: list[list[str]] = []
    if to is not None or amount is not None:
        if to is None or amount is None:
            raise ValueError("--to and --amount must be supplied together")
        validate_transfer_amount(amount)
        transfer_list.append([sender_pubkey, to.strip(), str(amount)])

    if transfers:
        for raw in transfers:
            addr, amt = parse_transfer_flag(raw)
            validate_transfer_amount(amt)
            transfer_list.append([sender_pubkey, addr, str(amt)])

    if transfer_list:
        operations["1"] = transfer_list

    return operations


def build_and_sign_user_tx(
    *,
    private_key: int | str | bytes,
    sender_pubkey: str,
    sequence_number: int,
    operations: Mapping[str, Any],
    expire_at_height: int,
    fee_limit: str | int = "0",
    expiry_seconds: int = DEFAULT_EXPIRY_SECONDS,
    now: int | None = None,
) -> dict:
    """One-call helper: build a user_tx, sign it, return the signed payload."""
    if now is None:
        now = int(time.time())
    payload = build_user_tx(
        sender_pubkey=sender_pubkey,
        sequence_number=sequence_number,
        expiration_time=now + int(expiry_seconds),
        expire_at_height=expire_at_height,
        operations=operations,
        fee_limit=fee_limit,
    )
    return sign_tx(payload, private_key)


def build_approval_request_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    recipient_pubkey: str,
    amount: int,
    expire_at_height: int,
    approvers: dict,
    custom_inputs: dict | None = None,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='approval_request'`` payload (without signature).

    `approvers` maps an approval slot index (18..25) to a 96-hex pubkey, and it
    should name ONLY the approvers this amount actually requires: the declaration
    is what fills approvers' inboxes, so naming extras notifies people whose
    signature the sender's policy never asks for.

    `custom_inputs` (streams >= 26) is sender data the approvers can read -- a
    comment to a partner, or a 2FA code. Anything here is PUBLIC and permanent.
    """
    if not isinstance(recipient_pubkey, str) or len(recipient_pubkey) != 96:
        raise ValueError("recipient_pubkey must be a 96-character hex public key")
    if not isinstance(amount, int) or amount < 1:
        raise ValueError("amount must be a positive integer")
    if not isinstance(expire_at_height, int) or expire_at_height < 1:
        raise ValueError("expire_at_height must be a positive integer")
    if not isinstance(approvers, dict) or not approvers:
        raise ValueError("at least one approver must be declared")

    normalized = {}
    for slot, pubkey in approvers.items():
        try:
            idx = int(slot)
        except (TypeError, ValueError):
            raise ValueError(f"approver slot {slot!r} is not a stream index")
        if not isinstance(pubkey, str) or len(pubkey) != 96:
            raise ValueError(f"approver for slot {idx} must be a 96-hex public key")
        normalized[str(idx)] = pubkey.lower()
    if len(set(normalized.values())) != len(normalized):
        raise ValueError("approvers must be distinct accounts")
    if (sender_pubkey or "").lower() in set(normalized.values()):
        raise ValueError("the sender may not be their own approver")

    customs = {}
    for stream, value in (custom_inputs or {}).items():
        try:
            idx = int(stream)
        except (TypeError, ValueError):
            raise ValueError(f"custom input {stream!r} is not a stream index")
        customs[str(idx)] = str(value)

    return {
        "tx_type": "approval_request",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient_pubkey.lower(),
        "amount": amount,
        "expire_at_height": expire_at_height,
        "approvers": normalized,
        "custom_inputs": customs,
    }


def build_rule_change_request_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    kind: int,
    rule_text: str = "",
    offer_id: str = "",
    approvers: dict | None = None,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='rule_change_request'`` payload (without signature).

    Kinds 1 and 4 carry the clause in ``rule_text``; kind 3 carries the exact
    offered text and the offer id; kind 6 carries a payout rule's canonical spec
    text (``payout_spec_text`` without a sequence number) and kind 8 a receive
    route's (``route_spec_text``); kinds 2, 5, 7 and 9 carry neither. Zero
    approvers is
    valid: the time escape alone can release the request.
    """
    if isinstance(kind, bool) or kind not in range(1, 10):
        raise ValueError("kind must be 1..9")
    has_body = kind in (1, 3, 4, 6, 8)
    if has_body and not (isinstance(rule_text, str) and rule_text.strip()):
        raise ValueError("this kind needs a non-empty rule text")
    if not has_body and rule_text:
        raise ValueError("this kind carries no rule text")
    if kind == 3:
        if not isinstance(offer_id, str) or len(offer_id) != 64:
            raise ValueError("offer_id must be a 64-character hex string")
    elif offer_id:
        raise ValueError("this kind carries no offer id")

    normalized = {}
    for slot, pubkey in (approvers or {}).items():
        try:
            idx = int(slot)
        except (TypeError, ValueError):
            raise ValueError(f"approver slot {slot!r} is not a stream index")
        if not isinstance(pubkey, str) or len(pubkey) != 96:
            raise ValueError(f"approver for slot {idx} must be a 96-hex public key")
        normalized[str(idx)] = pubkey.lower()
    if len(set(normalized.values())) != len(normalized):
        raise ValueError("approvers must be distinct accounts")
    if (sender_pubkey or "").lower() in set(normalized.values()):
        raise ValueError("the sender may not be their own approver")

    tx = {
        "tx_type": "rule_change_request",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "kind": kind,
        "approvers": normalized,
    }
    if rule_text:
        tx["rule_text"] = rule_text
    if offer_id:
        tx["offer_id"] = offer_id.lower()
    return tx


def build_rule_change_cancel_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    request_id: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='rule_change_cancel'`` payload (without signature)."""
    if not isinstance(request_id, str) or len(request_id) != 64:
        raise ValueError("request_id must be a 64-character hex string")
    return {
        "tx_type": "rule_change_cancel",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "request_id": request_id.lower(),
    }


def build_transfer_vote_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    request_id: str,
    approve: bool = True,
    reason: str = "",
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='transfer_vote'`` payload (without signature).

    Feeless, so an approver bot needs no funded account. A decline does not kill
    the request -- it records a refusal to fill one slot, and the transfer still
    goes through if the sender's policy did not need that slot.
    """
    if not isinstance(request_id, str) or len(request_id) != 64:
        raise ValueError("request_id must be a 64-character hex string")
    if not isinstance(approve, bool):
        raise ValueError("approve must be a boolean")
    if not isinstance(reason, str):
        raise ValueError("reason must be a string")

    tx = {
        "tx_type": "transfer_vote",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "request_id": request_id.lower(),
        "approve": approve,
    }
    if reason:
        tx["reason"] = reason
    return tx


def build_retractable_transfer_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    recipient_pubkey: str,
    amount: int,
    release_at_height: int | None = None,
    release_at_time: int | None = None,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='retractable_transfer'`` payload (without signature).

    Exactly one release point. Admission refuses a park that could be mined at or
    after its own release, so the deadline is clamped to it: ``expire_at_height``
    to ``release_at_height``, or ``expiration_time`` below ``release_at_time``.
    """
    if not isinstance(recipient_pubkey, str) or len(recipient_pubkey) != 96:
        raise ValueError("recipient_pubkey must be a 96-character hex public key")
    if not isinstance(amount, int) or isinstance(amount, bool) or amount < 1:
        raise ValueError("amount must be a positive integer")
    if (release_at_height is None) == (release_at_time is None):
        raise ValueError("give exactly one of release_at_height and release_at_time")
    expire_at_height = _check_expire_at_height(expire_at_height)

    tx = {
        "tx_type": "retractable_transfer",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient_pubkey.lower(),
        "amount": amount,
    }
    if release_at_height is not None:
        if not isinstance(release_at_height, int) or isinstance(release_at_height, bool) \
                or release_at_height < 1:
            raise ValueError("release_at_height must be a positive block height")
        tx["release_at_height"] = release_at_height
        expire_at_height = min(expire_at_height, release_at_height)
    else:
        if not isinstance(release_at_time, int) or isinstance(release_at_time, bool) \
                or release_at_time < 1:
            raise ValueError("release_at_time must be a positive unix timestamp")
        tx["release_at_time"] = release_at_time
        expiration_time = min(expiration_time, release_at_time - 1)
    tx["expiration_time"] = expiration_time
    tx["expire_at_height"] = expire_at_height
    return tx


def build_retract_transfer_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    retractable_id: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='retract_transfer'`` payload (without signature).

    Feeless. It must be INCLUDED in a block before the release point, so send it
    with margin: a feeless transaction sorts last when the mempool is backed up.
    """
    if not isinstance(retractable_id, str) or len(retractable_id) != 64:
        raise ValueError("retractable_id must be a 64-character hex string")
    return {
        "tx_type": "retract_transfer",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "retractable_id": retractable_id.lower(),
    }


_STANDING_INTERVAL_FIELDS = ("interval_blocks", "interval_seconds", "interval_months")


def build_standing_payment_create_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    recipient_pubkey: str,
    amount: int,
    first_due: int,
    periods: int,
    interval_blocks: int | None = None,
    interval_seconds: int | None = None,
    interval_months: int | None = None,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='standing_payment_create'`` payload (without signature).

    Exactly one interval. Admission refuses a create that could be mined at or
    after its own first due point, so the deadline is clamped to it:
    ``expire_at_height`` to ``first_due`` for a block schedule, ``expiration_time``
    below ``first_due`` for a time schedule.
    """
    if not isinstance(recipient_pubkey, str) or len(recipient_pubkey) != 96:
        raise ValueError("recipient_pubkey must be a 96-character hex public key")
    for name, value in (("amount", amount), ("first_due", first_due), ("periods", periods)):
        if not isinstance(value, int) or isinstance(value, bool) or value < 1:
            raise ValueError(f"{name} must be a positive integer")
    given = {
        name: value for name, value in zip(
            _STANDING_INTERVAL_FIELDS, (interval_blocks, interval_seconds, interval_months)
        ) if value is not None
    }
    if len(given) != 1:
        raise ValueError("give exactly one of interval_blocks, interval_seconds, interval_months")
    (name, interval), = given.items()
    if not isinstance(interval, int) or isinstance(interval, bool) or interval < 1:
        raise ValueError(f"{name} must be a positive integer")
    expire_at_height = _check_expire_at_height(expire_at_height)
    if name == "interval_blocks":
        expire_at_height = min(expire_at_height, first_due)
    else:
        expiration_time = min(expiration_time, first_due - 1)
    return {
        "tx_type": "standing_payment_create",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": expire_at_height,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient_pubkey.lower(),
        "amount": amount,
        name: interval,
        "first_due": first_due,
        "periods": periods,
    }


def build_standing_payment_update_tx(*, standing_id: str, **create_fields) -> dict:
    """Construct a ``tx_type='standing_payment_update'`` payload (without signature).

    Takes exactly the fields of :func:`build_standing_payment_create_tx` for the
    NEW terms, plus the id of the authorization they replace. The new version
    gets its own id (its terms and this transaction's sequence number); the old
    one ends when the update lands.
    """
    if not isinstance(standing_id, str) or len(standing_id) != 64:
        raise ValueError("standing_id must be a 64-character hex string")
    payload = build_standing_payment_create_tx(**create_fields)
    payload["tx_type"] = "standing_payment_update"
    payload["standing_id"] = standing_id.lower()
    return payload


def build_standing_payment_execute_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    standing_id: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='standing_payment_execute'`` payload (without signature).

    Anyone may send it. It names the authorization only: the node pays the
    period the block falls in, from the stored terms, or refuses. The sender
    pays the fee.
    """
    if not isinstance(standing_id, str) or len(standing_id) != 64:
        raise ValueError("standing_id must be a 64-character hex string")
    return {
        "tx_type": "standing_payment_execute",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "standing_id": standing_id.lower(),
    }


def build_standing_payment_cancel_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    standing_id: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='standing_payment_cancel'`` payload (without signature).

    Feeless. It must be INCLUDED in a block before the next due point to stop
    that payment, so send it with margin.
    """
    if not isinstance(standing_id, str) or len(standing_id) != 64:
        raise ValueError("standing_id must be a 64-character hex string")
    return {
        "tx_type": "standing_payment_cancel",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "standing_id": standing_id.lower(),
    }


def build_payout_rule_set_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    rule_text: str,
    slots: list,
    cap_per_execution: int,
    cap_per_period: int,
    expires_at: int,
    period_blocks: int | None = None,
    period_seconds: int | None = None,
    per_sale: bool = False,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='payout_rule_set'`` payload (without signature).

    ``per_sale``: the rule pays only against sales the chain recorded (signed
    transfers into the account), once per sale; executions name one.

    ``slots`` lists one entry per slot: a recipient's 96-hex key, or "" for an
    open slot the executor names. ``expires_at`` is on the period's clock: a
    height with ``period_blocks``, a unix time with ``period_seconds``.
    """
    if (period_blocks is None) == (period_seconds is None):
        raise ValueError("give exactly one of period_blocks and period_seconds")
    clean = []
    for k, slot in enumerate(slots or []):
        if slot in ("", None, "open"):
            clean.append("")
        elif isinstance(slot, str) and len(slot) == 96:
            clean.append(slot.lower())
        else:
            raise ValueError(f"slot {k} must be a 96-hex public key or open")
    tx = {
        "tx_type": "payout_rule_set",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "rule_text": rule_text,
        "slots": clean,
        "cap_per_execution": int(cap_per_execution),
        "cap_per_period": int(cap_per_period),
        "expires_at": int(expires_at),
    }
    if period_blocks is not None:
        tx["period_blocks"] = int(period_blocks)
    else:
        tx["period_seconds"] = int(period_seconds)
    if per_sale:
        tx["per_sale"] = True
    return tx


def build_payout_rule_revoke_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='payout_rule_revoke'`` payload (without signature). Feeless."""
    return {
        "tx_type": "payout_rule_revoke",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
    }


def build_payout_execute_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    account_pubkey: str,
    rule_id: str,
    recipients: dict | None = None,
    data: dict | None = None,
    sale_id: str | None = None,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='payout_execute'`` payload (without signature).

    ``rule_id`` pins the exact rule: if the account replaced its rule since,
    the execution is refused instead of running the new one. ``recipients``
    names keys for open slots ({slot: pubkey}); ``data`` fills i40+k ({k: value}).
    """
    if not isinstance(account_pubkey, str) or len(account_pubkey) != 96:
        raise ValueError("account_pubkey must be a 96-character hex public key")
    if not isinstance(rule_id, str) or len(rule_id) != 64:
        raise ValueError("rule_id must be a 64-character hex string")
    tx = {
        "tx_type": "payout_execute",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "account_pubkey": account_pubkey.lower(),
        "rule_id": rule_id.lower(),
        "recipients": {str(int(k)): v.lower() for k, v in (recipients or {}).items()},
        "data": {str(int(k)): int(v) for k, v in (data or {}).items()},
    }
    if sale_id is not None:
        if not isinstance(sale_id, str) or len(sale_id) != 64:
            raise ValueError("sale_id must be a 64-character transaction hash")
        tx["sale_id"] = sale_id.lower()
    return tx


def build_receive_route_set_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    destination_pubkey: str,
    share_bps: int,
    min_amount: int = 0,
    active_from: int = 0,
    expires_at: int = 0,
    locked: bool = False,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='receive_route_set'`` payload (without signature).

    ``share_bps`` is the routed share in basis points (2000 = 20%). The optional
    terms are left out at their defaults, so the payload reads like the spec a
    guarded account would file: a minimum credit, a start and an end (unix
    seconds, block time), and ``locked``, which needs an end.
    """
    if not isinstance(destination_pubkey, str) or len(destination_pubkey) != 96:
        raise ValueError("destination_pubkey must be a 96-character hex public key")
    if isinstance(share_bps, bool) or not isinstance(share_bps, int):
        raise ValueError("share_bps must be an integer")
    if locked and not expires_at:
        raise ValueError("a locked route needs an end (expires_at)")
    tx = {
        "tx_type": "receive_route_set",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "destination_pubkey": destination_pubkey.lower(),
        "share_bps": share_bps,
    }
    for name, value in (("min_amount", min_amount), ("active_from", active_from),
                        ("expires_at", expires_at)):
        if value:
            tx[name] = int(value)
    if locked:
        tx["locked"] = True
    return tx


def build_receive_route_remove_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='receive_route_remove'`` payload (without signature). Feeless."""
    return {
        "tx_type": "receive_route_remove",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
    }


def build_receive_route_release_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    owner_pubkey: str,
    route_id: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='receive_route_release'`` payload (without signature).

    Signed by the route's DESTINATION. ``route_id`` pins the exact route: if
    the owner replaced it since, the release is refused. Feeless.
    """
    if not isinstance(owner_pubkey, str) or len(owner_pubkey) != 96:
        raise ValueError("owner_pubkey must be a 96-character hex public key")
    if not isinstance(route_id, str) or len(route_id) != 64:
        raise ValueError("route_id must be a 64-character hex string")
    return {
        "tx_type": "receive_route_release",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "owner_pubkey": owner_pubkey.lower(),
        "route_id": route_id.lower(),
    }


_DAY_ORDER = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


def build_envelope_send_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    recipient_pubkey: str,
    amount: int,
    expires_at: int,
    caps: list | None = None,
    period_blocks: int | None = None,
    period_seconds: int | None = None,
    recurring: bool = False,
    clock: str | None = None,
    not_before: int | None = None,
    hold: int | None = None,
    days: list | None = None,
    hours: list | None = None,
    refund_idle: int | None = None,
    at_end: str | None = None,
    utc_offset: int | None = None,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='envelope_send'`` payload (without signature).

    ``amount`` leaves the sender at once and waits in the envelope for the
    recipient to spend. Optional conditions, all on the envelope's one clock:
    a spending limit (``caps[n]`` in period n, ``recurring`` repeats the last
    cap; exactly one period clock), ``not_before``, ``hold``, ``days`` and
    ``hours`` (seconds clock only; read at ``utc_offset``, quarter hours east
    of UTC, UTC when left out), ``refund_idle``, and ``at_end``
    (``"release"``, the default, or ``"refund"``). Without caps, ``clock`` names
    the clock. Optional fields are left out when not given, so the signed bytes
    of a spending-limit envelope do not change.
    """
    if not isinstance(recipient_pubkey, str) or len(recipient_pubkey) != 96:
        raise ValueError("recipient_pubkey must be a 96-character hex public key")
    if caps is not None:
        if (period_blocks is None) == (period_seconds is None):
            raise ValueError("give exactly one of period_blocks and period_seconds")
        if not isinstance(caps, (list, tuple)) or not caps:
            raise ValueError("caps must be a non-empty list of amounts")
        kind = "blocks" if period_blocks is not None else "seconds"
        if clock is not None and clock != kind:
            raise ValueError(f"clock {clock} does not match the period's clock {kind}")
    else:
        if period_blocks is not None or period_seconds is not None or recurring:
            raise ValueError("a period and recurring need caps")
        if clock not in ("blocks", "seconds"):
            raise ValueError("an envelope without caps needs clock 'blocks' or 'seconds'")
    tx = {
        "tx_type": "envelope_send",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient_pubkey.lower(),
        "amount": int(amount),
        "expires_at": int(expires_at),
    }
    if caps is not None:
        tx["caps"] = [int(c) for c in caps]
        if period_blocks is not None:
            tx["period_blocks"] = int(period_blocks)
        else:
            tx["period_seconds"] = int(period_seconds)
        if recurring:
            tx["recurring"] = True
    else:
        tx["clock"] = clock
    if not_before is not None:
        tx["not_before"] = int(not_before)
    if hold is not None:
        tx["hold"] = int(hold)
    if days:
        names = [str(d).lower()[:3] for d in days]
        if any(d not in _DAY_ORDER for d in names):
            raise ValueError(f"days must be among {list(_DAY_ORDER)}")
        tx["days"] = [d for d in _DAY_ORDER if d in names]
    if hours:
        tx["hours"] = sorted({int(h) for h in hours})
    if refund_idle is not None:
        tx["refund_idle"] = int(refund_idle)
    if at_end is not None and at_end != "release":
        if at_end != "refund":
            raise ValueError("at_end must be 'release' or 'refund'")
        tx["at_end"] = "refund"
    if utc_offset:
        if not isinstance(utc_offset, int) or not -48 <= utc_offset <= 56:
            raise ValueError("utc_offset is in quarter hours east of UTC, -48..56")
        if not (days or hours):
            raise ValueError("utc_offset needs days or hours")
        tx["utc_offset"] = int(utc_offset)
    return tx


def build_envelope_spend_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    envelope_id: str,
    to_pubkey: str,
    amount: int,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='envelope_spend'`` payload (without signature).

    Signed by the envelope's RECIPIENT; pays ``to_pubkey`` (anyone, the
    recipient included) out of the envelope. The fee is the recipient's.
    """
    if not isinstance(envelope_id, str) or len(envelope_id) != 64:
        raise ValueError("envelope_id must be a 64-character hex string")
    if not isinstance(to_pubkey, str) or len(to_pubkey) != 96:
        raise ValueError("to_pubkey must be a 96-character hex public key")
    return {
        "tx_type": "envelope_spend",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "envelope_id": envelope_id.lower(),
        "to_pubkey": to_pubkey.lower(),
        "amount": int(amount),
    }


def build_envelope_release_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
    expire_at_height: int,
    envelope_id: str,
    fee_limit: str | int = "0",
) -> dict:
    """Construct a ``tx_type='envelope_release'`` payload (without signature).

    Signed by the envelope's SENDER: everything left goes to the recipient now.
    Feeless.
    """
    if not isinstance(envelope_id, str) or len(envelope_id) != 64:
        raise ValueError("envelope_id must be a 64-character hex string")
    return {
        "tx_type": "envelope_release",
        "sender_pubkey": sender_pubkey,
        "sequence_number": sequence_number,
        "expiration_time": expiration_time,
        "expire_at_height": _check_expire_at_height(expire_at_height),
        "fee_limit": str(fee_limit),
        "envelope_id": envelope_id.lower(),
    }
