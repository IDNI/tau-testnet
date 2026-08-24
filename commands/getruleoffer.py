"""Full detail for one rule offer, including its complete rule text.

`getruleoffers` returns previews; this returns the body a recipient needs to
read before deciding, and the text an accept must repeat verbatim (the apply
path recomputes the offer digest from it).
"""
import api_response
import db
from consensus.rule_offers import RuleOfferShapeError, normalize_offer_rule_text

_CMD = "getruleoffer"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <offer_id>", "INVALID_PARAMS"
        )

    offer_id = parts[1].strip().lower()
    try:
        raw = bytes.fromhex(offer_id)
    except ValueError:
        return api_response.error_response(
            _CMD, "offer_id must be hex.", "INVALID_PARAMS"
        )
    if len(raw) != 32:
        return api_response.error_response(
            _CMD, "offer_id must be 32 bytes (64 hex chars).", "INVALID_PARAMS"
        )

    database = getattr(container, "db", db) or db
    try:
        rows = database.load_rule_offers()
    except Exception as exc:
        return api_response.error_response(
            _CMD, f"Failed to read rule offers: {exc}", "INTERNAL_ERROR"
        )

    match = next((r for r in rows if (r.get("offer_id") or "").lower() == offer_id), None)
    if match is None:
        return api_response.error_response(
            _CMD, f"Unknown offer {offer_id[:16]}.", "OFFER_UNKNOWN"
        )

    data = dict(match)
    try:
        body, target_stream = normalize_offer_rule_text(match.get("rule_text") or "")
        data["clause_body"] = body
        data["target_stream"] = target_stream
    except RuleOfferShapeError as exc:
        # A resolved row may have had its text dropped (it is node-local), and
        # a stored offer can predate a shape rule; report rather than fail.
        data["clause_body"] = None
        data["target_stream"] = None
        data["shape_error"] = str(exc)

    return api_response.success_response(_CMD, data)
