"""Central exception hierarchy for the Tau Testnet server."""
from __future__ import annotations


class TauTestnetError(Exception):
    """Base exception for all custom errors raised by the Tau Testnet server."""


class ConfigurationError(TauTestnetError):
    """Raised when configuration loading or validation fails."""


class DatabaseError(TauTestnetError):
    """Raised for database related issues (initialization, queries, etc.)."""


class TauProcessError(TauTestnetError):
    """Raised when the Tau process fails to start or stops unexpectedly."""


class TauCommunicationError(TauTestnetError):
    """Raised when communication with the Tau process fails."""


class CommandError(TauTestnetError):
    """Raised when a client command cannot be processed correctly."""


class DependencyError(TauTestnetError):
    """Raised when dependency wiring or injection fails."""


class NetworkError(TauTestnetError):
    """Raised when the network service encounters unrecoverable issues."""
