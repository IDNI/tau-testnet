import json
from consensus.serialization import compute_update_id

def execute(raw_command: str, container):
    parts = raw_command.split(None, 1)
    if len(parts) < 2:
        return json.dumps({"status": "error", "error": "Usage: getupdateid <json_payload>"})

    try:
        payload = json.loads(parts[1])
    except Exception as e:
        return json.dumps({"status": "error", "error": f"Invalid JSON: {e}"})

    # --- Validation (admission-grade for payload shape) ---

    revisions = payload.get("rule_revisions")
    if not isinstance(revisions, list) or len(revisions) == 0:
        return json.dumps({"status": "error", "error": "rule_revisions must be a non-empty list."})
    for i, rev in enumerate(revisions):
        if not isinstance(rev, str) or len(rev) == 0:
            return json.dumps({"status": "error", "error": f"rule_revisions[{i}] must be a non-empty string."})

    h = payload.get("activate_at_height")
    if isinstance(h, float) or (isinstance(h, bool)):
        return json.dumps({"status": "error", "error": "activate_at_height must be integer, not float."})
    if not isinstance(h, int) or h < 1 or h > 0xFFFFFFFFFFFFFFFF:
        return json.dumps({"status": "error", "error": "activate_at_height must be integer in range 1..2^64-1."})

    patch = payload.get("host_contract_patch")
    if patch is not None:
        if not isinstance(patch, dict):
            return json.dumps({"status": "error", "error": "host_contract_patch must be an object if provided."})

    try:
        uid = compute_update_id(revisions, h, patch)
    except ValueError as e:
        return json.dumps({"status": "error", "error": f"Serialization failed: {e}"})

    return json.dumps({
        "status": "ok",
        "update_id": uid.hex(),
        "input_echo": {
            "rule_revisions": revisions,
            "activate_at_height": h,
            **({"host_contract_patch": patch} if patch else {}),
        },
    })
