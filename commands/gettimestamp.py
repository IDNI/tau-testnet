import datetime
import logging

import api_response

logger = logging.getLogger(__name__)


def execute(raw_command: str, container):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return api_response.success_response("gettimestamp", {"timestamp": now})
