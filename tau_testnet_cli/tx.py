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
        "operations": dict(operations),
        "fee_limit": str(fee_limit),
    }


def build_consensus_rule_update_tx(
    *,
    sender_pubkey: str,
    sequence_number: int,
    expiration_time: int,
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
    response = rpc_mod.send_command(
        f"getsequence {pubkey}", host, port, timeout=timeout
    )
    if response.startswith("SEQUENCE: "):
        return int(response.split(": ", 1)[1].strip())
    if response.startswith("ERROR:"):
        raise RuntimeError(f"node rejected getsequence: {response}")
    raise RuntimeError(f"unexpected getsequence response: {response!r}")


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
        operations=operations,
        fee_limit=fee_limit,
    )
    return sign_tx(payload, private_key)
