import json

import api_response
from consensus.serialization import compute_update_id


def execute(raw_command: str, container):
    parts = raw_command.split(None, 1)
    if len(parts) < 2:
        return api_response.error_response(
            "getupdateid", "Usage: getupdateid <json_payload>", "INVALID_PARAMS"
        )

    try:
        payload = json.loads(parts[1])
    except Exception as e:
        return api_response.error_response(
            "getupdateid", f"Invalid JSON: {e}", "PARSE_ERROR"
        )

    revisions = payload.get("rule_revisions")
    if not isinstance(revisions, list) or len(revisions) == 0:
        return api_response.error_response(
            "getupdateid", "rule_revisions must be a non-empty list.", "INVALID_PARAMS"
        )
    for i, rev in enumerate(revisions):
        if not isinstance(rev, str) or len(rev) == 0:
            return api_response.error_response(
                "getupdateid",
                f"rule_revisions[{i}] must be a non-empty string.",
                "INVALID_PARAMS",
            )

    h = payload.get("activate_at_height")
    if isinstance(h, float) or isinstance(h, bool):
        return api_response.error_response(
            "getupdateid",
            "activate_at_height must be integer, not float.",
            "INVALID_PARAMS",
        )
    if not isinstance(h, int) or h < 1 or h > 0xFFFFFFFFFFFFFFFF:
        return api_response.error_response(
            "getupdateid",
            "activate_at_height must be integer in range 1..2^64-1.",
            "INVALID_PARAMS",
        )

    patch = payload.get("host_contract_patch")
    if patch is not None and not isinstance(patch, dict):
        return api_response.error_response(
            "getupdateid",
            "host_contract_patch must be an object if provided.",
            "INVALID_PARAMS",
        )

    try:
        uid = compute_update_id(revisions, h, patch)
    except ValueError as e:
        return api_response.error_response(
            "getupdateid", f"Serialization failed: {e}", "GOVERNANCE_ERROR"
        )

    input_echo = {
        "rule_revisions": revisions,
        "activate_at_height": h,
    }
    if patch:
        input_echo["host_contract_patch"] = patch

    return api_response.success_response(
        "getupdateid", {"update_id": uid.hex(), "input_echo": input_echo}
    )
