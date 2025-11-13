"""Global registry for the active NetworkService instance.

This lightweight indirection avoids importing the full service module from
callers such as commands/sendtx.py, which would otherwise introduce circular
dependencies (NetworkService already imports sendtx)."""

from __future__ import annotations

from typing import Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .service import NetworkService


_default_service: Optional["NetworkService"] = None


def register(service: "NetworkService") -> None:
    global _default_service
    _default_service = service


def unregister(service: "NetworkService") -> None:
    global _default_service
    if _default_service is service:
        _default_service = None


def get() -> Optional["NetworkService"]:
    return _default_service

