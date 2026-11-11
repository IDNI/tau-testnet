"""The consensus number rule for block and transaction JSON.

Every number is an integer from -2**63 to 2**64 - 1. With integers only, the JSON
text of a number is its decimal digits, so every node counts the same block bytes.
"""
from __future__ import annotations

import json
from typing import Any, Optional

INT_MIN = -(1 << 63)
INT_MAX = (1 << 64) - 1


def _refuse_constant(name: str) -> Any:
    raise ValueError(f"{name} is not a JSON number")


def loads_strict(text: str | bytes) -> Any:
    """`json.loads` that refuses `NaN`, `Infinity` and `-Infinity`."""
    return json.loads(text, parse_constant=_refuse_constant)


def _all_numbers_valid(value: Any) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, (str, bool)) or item is None:
            continue
        if isinstance(item, int):
            if not INT_MIN <= item <= INT_MAX:
                return False
        elif isinstance(item, float):
            return False
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)
    return True


def number_error(value: Any) -> Optional[str]:
    """A reason when `value` holds a float or an integer outside the range, else None."""
    # A block can be 18 MiB, so build the path of the bad number only when one exists.
    if _all_numbers_valid(value):
        return None
    stack = [(value, "$")]
    while stack:
        item, path = stack.pop()
        if isinstance(item, bool) or item is None or isinstance(item, str):
            continue
        if isinstance(item, int):
            if not INT_MIN <= item <= INT_MAX:
                return f"number at {path} is an integer outside {INT_MIN}..{INT_MAX}"
        elif isinstance(item, float):
            return f"number at {path} is not an integer: {item!r}"
        elif isinstance(item, dict):
            stack.extend((v, f"{path}.{k}") for k, v in item.items())
        elif isinstance(item, (list, tuple)):
            stack.extend((v, f"{path}[{i}]") for i, v in enumerate(item))
    return None
