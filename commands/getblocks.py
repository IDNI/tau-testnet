"""Block listing, optionally windowed to the most recent N.

`getblocks` with no argument returns every block, which is what the original
handler did unconditionally -- so it stays the default for the scripts and
follower tooling that walk the whole chain.

The optional limit exists because the CLI has always sent one: `tau-testnet
blocks --limit 10` builds `getblocks 10`, and this handler used to ignore
every argument and return the full chain anyway. On a long chain that silently
blew the CLI's 4 MiB read ceiling (exit code 3) instead of returning ten
blocks.

`db.get_all_blocks()` orders by `block_number` ASC and is not
canonical-filtered, so the tail is the highest-numbered rows, forks included.
The window is taken from that tail -- "recent", matching the CLI's own
`--limit` help -- and the slice is returned still in ascending order, so a
client's indexing does not flip meaning when the flag is added.
"""
import logging

import api_response

logger = logging.getLogger(__name__)

_USAGE = "Usage: getblocks [limit]"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 2:
        return api_response.error_response("getblocks", _USAGE, "INVALID_PARAMS")

    limit = None
    if len(parts) == 2:
        try:
            limit = int(parts[1])
        except ValueError:
            return api_response.error_response(
                "getblocks",
                f"limit must be a positive integer. {_USAGE}",
                "INVALID_PARAMS",
            )
        if limit < 1:
            return api_response.error_response(
                "getblocks",
                f"limit must be >= 1. {_USAGE}",
                "INVALID_PARAMS",
            )

    logger.debug("getblocks requested (limit=%s)", limit)
    try:
        # Prefer a SQL window so `getblocks 10` does not parse the whole chain
        # while holding `_db_lock`. Tests and older db stubs only implement
        # get_all_blocks(); slice in memory in that case.
        if limit is None:
            blocks = container.db.get_all_blocks()
            total = len(blocks)
        elif hasattr(container.db, "get_recent_blocks") and hasattr(container.db, "get_block_count"):
            total = container.db.get_block_count()
            blocks = container.db.get_recent_blocks(limit)
        else:
            blocks = container.db.get_all_blocks()
            total = len(blocks)
            blocks = blocks[-limit:]
    except Exception as exc:
        logger.exception("getblocks failed")
        return api_response.error_response(
            "getblocks", f"Failed to fetch blocks: {exc}", "INTERNAL_ERROR"
        )

    # `total` and `truncated` are additive: without them a client cannot tell a
    # short window from a short chain, which is the whole point of asking for
    # one. Existing consumers read `blocks` only.
    return api_response.success_response(
        "getblocks",
        {"blocks": blocks, "total": total, "truncated": len(blocks) < total},
    )
