"""Derive an approval request's id without submitting anything.

Mirrors `getofferid`: the id is a function of the request's identifying content
alone — sender, recipient, amount, sequence, expiry, the approver map and the
custom inputs — and excludes the transaction envelope, so a client can compute
it up front, show it to the user, and later reference it from a vote.

`sequence_number` is part of the id so two otherwise identical transfers from
one sender get distinct ids instead of the second colliding with the first.
"""
import json

import api_response
from consensus.approvals import (
    ApprovalShapeError,
    _normalize_index_map,
    _normalize_pubkey,
    validate_request_shape,
    ApprovalRequest,
)
from consensus.serialization import compute_request_id

_CMD = "getrequestid"


def execute(raw_command: str, container):
    parts = raw_command.split(None, 1)
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <json_payload>", "INVALID_PARAMS"
        )

    text = parts[1].strip()
    # Clients quote the JSON argument; tolerate either quoting style.
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        text = text[1:-1]

    try:
        payload = json.loads(text)
    except Exception as exc:
        return api_response.error_response(_CMD, f"Invalid JSON: {exc}", "PARSE_ERROR")
    if not isinstance(payload, dict):
        return api_response.error_response(
            _CMD, "Payload must be a JSON object.", "INVALID_PARAMS"
        )

    try:
        sender = _normalize_pubkey(payload.get("sender_pubkey"))
        recipient = _normalize_pubkey(payload.get("recipient_pubkey"))
        approvers_raw = _normalize_index_map(payload.get("approvers"), "approvers")
        approvers = {idx: _normalize_pubkey(pk) for idx, pk in approvers_raw.items()}
        customs = {idx: str(v) for idx, v in
                   _normalize_index_map(payload.get("custom_inputs"), "custom_inputs").items()}
        amount = int(payload.get("amount"))
        sequence_number = int(payload.get("sequence_number", 0))
        expire_at_height = int(payload.get("expire_at_height"))
    except (ApprovalShapeError, TypeError, ValueError) as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    request_id = compute_request_id(
        sender_pubkey=sender, recipient_pubkey=recipient, amount=amount,
        sequence_number=sequence_number, expire_at_height=expire_at_height,
        approvers=approvers, custom_inputs=customs,
    )

    # Shape problems are REPORTED, not fatal: the id is still well defined, and
    # a client computing it up front may not have picked an expiry height yet.
    shape_error = validate_request_shape(
        ApprovalRequest(
            sender_pubkey=sender, recipient_pubkey=recipient, amount=amount,
            sequence_number=sequence_number, expire_at_height=expire_at_height,
            approvers=approvers, custom_inputs=customs,
        ),
        next_height=0,
    )

    data = {
        "request_id": request_id.hex(),
        "input_echo": {
            "sender_pubkey": sender,
            "recipient_pubkey": recipient,
            "amount": amount,
            "sequence_number": sequence_number,
            "expire_at_height": expire_at_height,
            "approvers": {str(k): v for k, v in sorted(approvers.items())},
            "custom_inputs": {str(k): v for k, v in sorted(customs.items())},
        },
    }
    if shape_error:
        data["shape_error"] = shape_error
    return api_response.success_response(_CMD, data)
