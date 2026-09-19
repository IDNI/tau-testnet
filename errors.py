"""Central exception hierarchy for the Tau Testnet server."""
from __future__ import annotations


class TauTestnetError(Exception):
    """Base exception for all custom errors raised by the Tau Testnet server."""


class ConfigurationError(TauTestnetError):
    """Raised when configuration loading or validation fails."""


class DatabaseError(TauTestnetError):
    """Raised for database related issues (initialization, queries, etc.)."""


class TauEngineCrash(TauTestnetError):
    """Raised for catastrophic failures of the Tau environment (e.g. process exits unexpectedly, pipes closed)."""


class TauEngineBug(TauTestnetError):
    """Raised for errors reported by the Tau interpreter (e.g. `(Error)` output, evaluation failures)."""


class TauSpecRejected(TauTestnetError):
    """The engine refused the TEXT OR VALUE it was given; the input is at fault.

    Deliberately NOT a TauEngineBug: W0 measured that a parse/type rejection is a
    clean no-op -- `step` returns None, neither `spec_revision` nor `time_point`
    advances, no type is established, and the interpreter keeps accepting later
    revisions. Treating it as an engine crash (dumping a crash log) is what made a
    malformed user rule indistinguishable from a node failure to an external
    monitor.
    """


class TauSpecIntegrationError(TauTestnetError):
    """The engine refused text THIS NODE generated from valid canonical input.

    Same engine diagnostic as TauSpecRejected, opposite owner: the author's rule
    was fine and the runtime representation we built from it was not. Must never
    be reported as an author-invalid rule -- that is exactly how the shrink
    half-typing defect stayed invisible.
    """


class BlockchainBug(TauTestnetError):
    """Raised for internal errors, invalid states, or unhandled exceptions in the Python blockchain routing/logic."""


class TauCommunicationError(TauTestnetError):
    """Raised when communication with the Tau process fails."""
    def __init__(self, message: str, last_state: str | None = None):
        super().__init__(message)
        self.last_state = last_state


class CommandError(TauTestnetError):
    """Raised when a client command cannot be processed correctly."""


class DependencyError(TauTestnetError):
    """Raised when dependency wiring or injection fails."""


class NetworkError(TauTestnetError):
    """Raised when the network service encounters unrecoverable issues."""
