"""Output helpers for the Tau Testnet CLI."""

from __future__ import annotations

import json
import sys
from typing import Any


def print_result(value: Any, *, json_mode: bool, file=None) -> None:
    """Print ``value`` either as JSON (when ``json_mode``) or human-readable text."""
    out = file or sys.stdout
    if json_mode:
        print(json.dumps(value, indent=2, sort_keys=False, default=str), file=out)
        return

    if isinstance(value, str):
        print(value, file=out)
    elif isinstance(value, (dict, list)):
        print(json.dumps(value, indent=2, sort_keys=False, default=str), file=out)
    elif value is None:
        return
    else:
        print(str(value), file=out)


def parse_json_response(response: str) -> Any:
    """Try to decode a server response as JSON; return the original string on failure."""
    try:
        return json.loads(response)
    except (json.JSONDecodeError, ValueError):
        return response


def print_error(message: str) -> None:
    """Print a CLI error to stderr (no traceback)."""
    print(f"error: {message}", file=sys.stderr)
