import json
import logging

import api_response

logger = logging.getLogger(__name__)


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            "history", "Usage: history <address>", "INVALID_PARAMS"
        )

    history_addr = parts[1]
    items = []
    db_module = container.db

    for entry in db_module.get_mempool_txs():
        if entry.startswith("json:"):
            try:
                payload = json.loads(entry[5:])
            except Exception:
                logger.debug("Skipping invalid mempool json entry for history")
                continue

            ops = payload.get("operations", {}).get("1", [])
            if payload.get("sender_pubkey") == history_addr or any(
                isinstance(op, (list, tuple)) and history_addr in op for op in ops
            ):
                items.append(payload)

    return api_response.success_response(
        "history", {"address": history_addr, "transactions": items}
    )
