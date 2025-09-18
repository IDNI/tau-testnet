"""Logging configuration helpers for the Tau Testnet server."""
from __future__ import annotations

import logging
import os
from typing import Any, Optional

_DEFAULT_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
_DEFAULT_DATEFMT = "%Y-%m-%d %H:%M:%S"

_configured = False


def _coerce_level(level: Optional[Any]) -> int:
    """Translate a human readable level into the logging module's numeric level."""
    if isinstance(level, int):
        return level
    if isinstance(level, str):
        level = level.strip().upper()
        numeric = getattr(logging, level, None)
        if isinstance(numeric, int):
            return numeric
    env_default = os.environ.get("TAU_LOG_LEVEL", "INFO").strip().upper()
    return getattr(logging, env_default, logging.INFO)


def configure(logging_settings: Optional[Any] = None, *, force: bool = True) -> None:
    """Configure root logging once. Accepts a settings object or mapping."""
    global _configured
    if _configured and not force:
        return

    level = None
    fmt = None
    datefmt = None

    if logging_settings is not None:
        # Support dataclass/object with attributes or mapping semantics
        if isinstance(logging_settings, dict):
            level = logging_settings.get("level")
            fmt = logging_settings.get("format")
            datefmt = logging_settings.get("datefmt")
        else:
            level = getattr(logging_settings, "level", None)
            fmt = getattr(logging_settings, "format", None)
            datefmt = getattr(logging_settings, "datefmt", None)

    level = _coerce_level(level)
    fmt = fmt or os.environ.get("TAU_LOG_FORMAT", _DEFAULT_FORMAT)
    datefmt = datefmt or os.environ.get("TAU_LOG_DATEFMT", _DEFAULT_DATEFMT)

    logging.basicConfig(level=level, format=fmt, datefmt=datefmt, force=force)
    logging.captureWarnings(True)

    # Quiet very chatty libraries if needed
    logging.getLogger("asyncio").setLevel(max(logging.WARNING, level))

    _configured = True
