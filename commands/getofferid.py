"""Derive a rule offer's id without submitting anything.

Mirrors `getupdateid`: the id is a function of the offer's identifying content
alone (offerer, recipient, rule text, expiry) and excludes the transaction
envelope, so a client can compute it up front, show it to the user, and later
reference it from an accept or reject.
"""
import json

import api_response
from consensus.rule_offers import (
    MAX_OFFER_RULE_BYTES,
    MAX_OFFER_WINDOW_BLOCKS,
    RuleOfferShapeError,
    normalize_acceptor_pubkey,
    normalize_offer_rule_text,
)
from consensus.serialization import compute_offer_id

_CMD = "getofferid"


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
        offerer = normalize_acceptor_pubkey(payload.get("sender_pubkey"))
        recipient = normalize_acceptor_pubkey(payload.get("recipient_pubkey"))
    except RuleOfferShapeError as exc:
        return api_response.error_response(
            _CMD, f"Invalid public key: {exc}", "INVALID_PARAMS"
        )
    if offerer == recipient:
        return api_response.error_response(
            _CMD, "recipient_pubkey must differ from sender_pubkey.", "INVALID_PARAMS"
        )

    rule_text = payload.get("rule_text")
    if not isinstance(rule_text, str) or not rule_text.strip():
        return api_response.error_response(
            _CMD, "rule_text must be a non-empty string.", "INVALID_PARAMS"
        )
    if len(rule_text.encode("utf-8")) > MAX_OFFER_RULE_BYTES:
        return api_response.error_response(
            _CMD,
            f"rule_text exceeds {MAX_OFFER_RULE_BYTES} bytes.",
            "INVALID_PARAMS",
        )

    expire_at = payload.get("expire_at_height")
    if isinstance(expire_at, bool) or not isinstance(expire_at, int):
        return api_response.error_response(
            _CMD, "expire_at_height must be an integer.", "INVALID_PARAMS"
        )
    if expire_at < 1 or expire_at > 0xFFFFFFFFFFFFFFFF:
        return api_response.error_response(
            _CMD, "expire_at_height must be in range 1..2^64-1.", "INVALID_PARAMS"
        )

    # Shape is reported but not fatal: the id is well defined either way, and a
    # client may legitimately want the id of an offer it knows will be refused.
    shape_error = None
    target_stream = None
    try:
        _body, target_stream = normalize_offer_rule_text(rule_text)
    except RuleOfferShapeError as exc:
        shape_error = str(exc)

    try:
        offer_id = compute_offer_id(
            offerer_pubkey=offerer,
            recipient_pubkey=recipient,
            rule_text=rule_text,
            expire_at_height=expire_at,
        )
    except ValueError as exc:
        return api_response.error_response(
            _CMD, f"Serialization failed: {exc}", "INVALID_PARAMS"
        )

    data = {
        "offer_id": offer_id.hex(),
        "input_echo": {
            "sender_pubkey": offerer,
            "recipient_pubkey": recipient,
            "rule_text": rule_text,
            "expire_at_height": expire_at,
        },
        "target_stream": target_stream,
        "max_offer_window_blocks": MAX_OFFER_WINDOW_BLOCKS,
    }
    if shape_error:
        data["shape_error"] = shape_error
    return api_response.success_response(_CMD, data)
