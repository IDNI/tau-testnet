"""Derive a retractable transfer's id without submitting anything.

The id is a function of sender, recipient, amount, sequence number and the
release point alone, so a client can show it before signing and later name it
in a retract.
"""
import json
import time

import api_response
import db
from consensus.retractable import (
    KIND_HEIGHT,
    RetractableEntry,
    RetractableShapeError,
    parse_retractable_transfer,
    validate_park_shape,
)

_CMD = "getretractableid"


def execute(raw_command: str, container):
    parts = raw_command.split(None, 1)
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <json_payload>", "INVALID_PARAMS"
        )
    text = parts[1].strip()
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

    normalized = dict(payload)
    for key in ("sender_pubkey", "recipient_pubkey"):
        if isinstance(normalized.get(key), str):
            normalized[key] = normalized[key].strip().lower()
    normalized.setdefault("sequence_number", 0)
    try:
        entry = parse_retractable_transfer(normalized)
    except RetractableShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    data = {
        "retractable_id": entry.retractable_id.hex(),
        "input_echo": {
            "sender_pubkey": entry.sender_pubkey,
            "recipient_pubkey": entry.recipient_pubkey,
            "amount": entry.amount,
            "sequence_number": entry.sequence_number,
            ("release_at_height" if entry.kind == KIND_HEIGHT else "release_at_time"):
                entry.release_at,
        },
    }
    shape_error = _shape_error(entry)
    if shape_error:
        data["shape_error"] = shape_error
    return api_response.success_response(_CMD, data)


def _shape_error(entry: RetractableEntry):
    head = db.get_canonical_head_block()
    next_height = head["header"]["block_number"] + 1 if head else 0
    return validate_park_shape(entry, next_height, int(time.time()))
