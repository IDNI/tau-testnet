"""Errors that depend on the node, not on the block, during block apply.

Such an error must never become a transaction verdict: another node, or this
node after the cause is gone, reaches a different result. A broad catch at an
apply site lets these errors pass, so the apply of the whole block stops with
no verdict. A new local error class must go into local_apply_errors().
"""
from __future__ import annotations

import functools
import sqlite3


@functools.cache
def local_apply_errors() -> tuple[type[BaseException], ...]:
    # Imported on first use: tau_shrink loads this package through db before
    # it defines its classes.
    import tau_reconstruction
    import tau_shrink
    import tau_speculation
    from errors import (
        DatabaseError,
        TauCommunicationError,
        TauEngineCrash,
        TauSpecIntegrationError,
    )
    from tau_allocator import AllocatorCapacityExceeded

    return (
        tau_shrink.ShrinkUnavailable,
        tau_shrink.ShrinkWidthOverflow,
        AllocatorCapacityExceeded,
        tau_shrink.ShrinkTypeConflict,
        TauSpecIntegrationError,
        tau_shrink.ShrinkAuditFailure,
        tau_reconstruction.RepresentationConflict,
        tau_reconstruction.ReconstructionMismatch,
        tau_speculation.SpeculationError,
        TauCommunicationError,
        TauEngineCrash,
        MemoryError,
        RecursionError,
        OSError,
        DatabaseError,
        sqlite3.Error,
    )


@functools.cache
def deterministic_apply_errors() -> tuple[type[BaseException], ...]:
    """Subclasses of a local class that every node reaches from the block alone."""
    from tau_policy import PolicyBuildError, PolicyStepError

    return (PolicyBuildError, PolicyStepError)


def is_local_apply_error(exc: BaseException) -> bool:
    return (isinstance(exc, local_apply_errors())
            and not isinstance(exc, deterministic_apply_errors()))


# The error keeps its own class, so a caller can still test the class.
_OWNER_ATTR = "apply_tx_id"


def mark_owner(exc: BaseException, tx_id) -> None:
    """Name the transaction that was open at apply. The first, innermost name stays."""
    if tx_id is not None and getattr(exc, _OWNER_ATTR, None) is None:
        setattr(exc, _OWNER_ATTR, tx_id)


def owner_of(exc: BaseException):
    """The key of the transaction that met the local error, or None."""
    return getattr(exc, _OWNER_ATTR, None)
