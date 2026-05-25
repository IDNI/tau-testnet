import logging

import api_response

logger = logging.getLogger(__name__)


def execute(raw_command: str, container):
    logger.debug("getblocks requested")
    try:
        blocks = container.db.get_all_blocks()
    except Exception as exc:
        logger.exception("getblocks failed")
        return api_response.error_response(
            "getblocks", f"Failed to fetch blocks: {exc}", "INTERNAL_ERROR"
        )
    return api_response.success_response("getblocks", {"blocks": blocks})
