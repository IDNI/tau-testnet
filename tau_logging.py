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
    """Configure logging for tau-specific loggers only. Third-party loggers are kept quiet."""
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

    # Configure formatter
    formatter = logging.Formatter(fmt, datefmt)

    # Set root logger level to WARNING to reduce noise from third-party modules
    root_logger = logging.getLogger()
    root_logger.setLevel(max(logging.WARNING, level))

    # Remove any existing handlers from root logger to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Add console handler to root logger
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Set tau-specific loggers to the desired level (they will inherit the handler from root)
    tau_logger_patterns = [
        "tau",
        "network",
        "commands",
        "chain_state",
        "db",
        "block",
        "sbf_defs",
        "utils",
        "tau_manager",
        "server",
        "app",
    ]

    for pattern in tau_logger_patterns:
        tau_logger = logging.getLogger(pattern)
        tau_logger.setLevel(level)

    # Set third-party loggers to WARNING or higher to reduce noise
    third_party_loggers = [
        "asyncio",
        "trio",
        "libp2p",
        "multiaddr",
        "yamux",
        "urllib3",
        "requests",
        "PIL",
        "matplotlib",
        "numpy",
        "scipy",
        "parso",
        "jedi",
    ]

    for logger_name in third_party_loggers:
        logging.getLogger(logger_name).setLevel(max(logging.WARNING, level))

    # Ensure warnings are captured
    logging.captureWarnings(True)

    _configured = True
