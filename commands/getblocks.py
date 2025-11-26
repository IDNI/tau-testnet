import json
import logging

logger = logging.getLogger(__name__)

def execute(raw_command: str, container):
    logger.debug("getblocks requested")
    try:
        blocks = container.db.get_all_blocks()
        return json.dumps({"blocks": blocks}, separators=(",", ":")) + "\r\n"
    except Exception:
        logger.exception("getblocks failed")
        return "ERROR: Failed to fetch blocks\r\n"
