"""Block listing: the whole chain, the most recent N, or a page by height.

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

`getblocks <limit> <start>` is the paged form. It returns every row with
`start <= block_number < start + limit`, forks included, so one height is
never split over two pages. `next_start` is the first block number above the
page, or null when the page holds the tip. A chain of any length is read by
following `next_start` from 0 with a page size that keeps each answer small.
"""
import logging

import api_response

logger = logging.getLogger(__name__)

_USAGE = "Usage: getblocks [limit] [start]"
# SQLite INTEGER is 64-bit signed. A larger value makes the query raise.
_MAX_ARG = 2**63 - 1


def _parse_int(text: str, name: str, minimum: int, kind: str):
    try:
        value = int(text)
    except ValueError:
        return None, api_response.error_response(
            "getblocks",
            f"{name} must be a {kind} integer. {_USAGE}",
            "INVALID_PARAMS",
        )
    if value < minimum:
        return None, api_response.error_response(
            "getblocks",
            f"{name} must be >= {minimum}. {_USAGE}",
            "INVALID_PARAMS",
        )
    if value > _MAX_ARG:
        return None, api_response.error_response(
            "getblocks",
            f"{name} must be <= {_MAX_ARG}. {_USAGE}",
            "INVALID_PARAMS",
        )
    return value, None


def _execute_page(container, limit: int, start: int):
    logger.debug("getblocks page requested (limit=%s, start=%s)", limit, start)
    try:
        blocks, next_start = container.db.get_blocks_in_height_range(start, limit)
        total = container.db.get_block_count()
    except Exception as exc:
        logger.exception("getblocks failed")
        return api_response.error_response(
            "getblocks", f"Failed to fetch blocks: {exc}", "INTERNAL_ERROR"
        )
    return api_response.success_response(
        "getblocks",
        {
            "blocks": blocks,
            "total": total,
            "truncated": next_start is not None,
            "start": start,
            "next_start": next_start,
        },
    )


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 3:
        return api_response.error_response("getblocks", _USAGE, "INVALID_PARAMS")

    limit = None
    if len(parts) >= 2:
        limit, error = _parse_int(parts[1], "limit", 1, "positive")
        if error:
            return error
    if len(parts) == 3:
        start, error = _parse_int(parts[2], "start", 0, "non-negative")
        if error:
            return error
        return _execute_page(container, limit, start)

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
