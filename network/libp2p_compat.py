"""Centralized py-libp2p adaptation layer for tau-testnet.

This module owns every place we adapt py-libp2p. Tau protocol logic
(handlers, gossip topics, DHT namespaces) stays in `network/service.py`,
`network/gossip.py`, `network/dht_manager.py`. Generic libp2p plumbing
(identity adapters, host lifecycle helpers, stream primitives, DHT
validator-wrap mechanics, trio↔async bridge, QUIC shim) lives here.

INVARIANT: this module has NO import-time side effects. Every shim is an
explicit function call from a known site. In particular,
`apply_quic_cleanup_shim()` is not invoked at module load — the caller
(today: top of `network/service.py`) decides when to install it.

API surface lands incrementally per the unification plan
(`.claude/plans/we-need-to-unify-cozy-corbato.md`):
- A2 — identity adapters
- A3 — host lifecycle (NetworkNotifee, PeerstorePersistence, build_tau_resource_manager,
        attach_resource_manager, collect_listen_addrs, wait_for_listening)
- A4 — discovery (ensure_peer_id, seed_peerstore)
- A5 — stream primitives (bounded_stream_read, close_stream_safely)
- A6 — DHT validator wrap (install_validating_dht)
- A7 — trio↔async bridge (run_trio_from_thread)
- A9 — QUIC shim (apply_quic_cleanup_shim)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Optional

import multiaddr
import nacl.utils
import trio
from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from libp2p.abc import IHost, INotifee
from libp2p.crypto.keys import KeyPair, KeyType, PrivateKey, PublicKey
from libp2p.peer.id import ID
from libp2p.peer.peerstore import PERMANENT_ADDR_TTL
from libp2p.rcmgr.connection_limits import ConnectionLimits
from libp2p.rcmgr.manager import ResourceLimits, ResourceManager

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Identity adapters (A2)
# --------------------------------------------------------------------------

IDENTITY_SEED_SIZE = 32


class Ed25519PublicKeyCompat(PublicKey):
    """NaCl-backed Ed25519 public key with libp2p PublicKey interface."""

    def __init__(self, verify_key: VerifyKey) -> None:
        self._verify_key = verify_key

    def to_bytes(self) -> bytes:
        return bytes(self._verify_key)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ed25519PublicKeyCompat":
        return cls(VerifyKey(data))

    def get_type(self) -> KeyType:
        return KeyType.Ed25519

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            self._verify_key.verify(data, signature)
        except BadSignatureError:
            return False
        return True


class Ed25519PrivateKeyCompat(PrivateKey):
    """NaCl-backed Ed25519 private key with libp2p PrivateKey interface."""

    def __init__(self, signing_key: SigningKey) -> None:
        self._signing_key = signing_key

    @classmethod
    def generate(cls) -> "Ed25519PrivateKeyCompat":
        seed = nacl.utils.random(IDENTITY_SEED_SIZE)
        return cls(SigningKey(seed))

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ed25519PrivateKeyCompat":
        if len(data) != IDENTITY_SEED_SIZE:
            raise ValueError(
                f"Ed25519 identity seed must be {IDENTITY_SEED_SIZE} bytes, got {len(data)}"
            )
        return cls(SigningKey(data))

    def to_bytes(self) -> bytes:
        return bytes(self._signing_key)

    def get_type(self) -> KeyType:
        return KeyType.Ed25519

    def sign(self, data: bytes) -> bytes:
        return self._signing_key.sign(data).signature

    def get_public_key(self) -> PublicKey:
        return Ed25519PublicKeyCompat(self._signing_key.verify_key)


def keypair_from_seed(seed: bytes) -> KeyPair:
    """libp2p KeyPair from a 32-byte Ed25519 seed."""
    priv = Ed25519PrivateKeyCompat.from_bytes(seed)
    return KeyPair(private_key=priv, public_key=priv.get_public_key())


def generate_seed() -> bytes:
    """Fresh 32-byte Ed25519 seed suitable for `keypair_from_seed`."""
    return nacl.utils.random(IDENTITY_SEED_SIZE)


# --------------------------------------------------------------------------
# Host plumbing (A3)
# --------------------------------------------------------------------------


class NetworkNotifee(INotifee):
    """Bridge swarm connection events to an async callback.

    The callback receives `(event_name, conn)` where event_name is
    "connected" or "disconnected". Stream and listen events are no-ops.
    """

    def __init__(self, callback) -> None:
        self._callback = callback

    async def opened_stream(self, network, stream) -> None:
        return

    async def closed_stream(self, network, stream) -> None:
        return

    async def connected(self, network, conn) -> None:
        if self._callback:
            await self._callback("connected", conn)

    async def disconnected(self, network, conn) -> None:
        if self._callback:
            await self._callback("disconnected", conn)

    async def listen(self, network, multiaddr) -> None:
        return

    async def listen_close(self, network, multiaddr) -> None:
        return


class PeerstorePersistence:
    """DB-backed peerstore persistence.

    `path` is treated as an enable/disable flag — when falsy, load() returns
    an empty dict and save() is a no-op. This keeps test runs deterministic
    by avoiding stale addrs across runs.
    """

    def __init__(self, path: Optional[str]) -> None:
        self._path = path

    def load(self) -> Dict[str, List[str]]:
        if not self._path:
            return {}
        import db
        try:
            return db.load_peers_basic()
        except Exception:
            return {}

    def save(self, peer_id_to_addrs: Dict[str, List[str]]) -> None:
        if not self._path:
            return
        import db
        try:
            for pid, addrs in peer_id_to_addrs.items():
                db.upsert_peer_basic(
                    pid,
                    [str(addr) for addr in addrs],
                    agent=None,
                    network_id=None,
                    genesis_hash=None,
                )
        except Exception:
            logger.debug("Peerstore persistence failed", exc_info=True)


def build_tau_resource_manager(config) -> ResourceManager:
    """Construct ResourceManager with Tau's connection/rate-limit presets.

    Named build_tau_* to flag NetworkConfig coupling — this is not a generic
    libp2p helper, it knows the Tau config field names.

    Mirrors the original logic at network/host.py (pre-A3): max_connections
    drives both ResourceLimits and ConnectionLimits, conn_high_water is the
    inbound cap, conn_low_water is the pending-inbound cap.
    """
    res_limits = ResourceLimits(
        max_connections=config.max_connections,
        max_streams=10000,
    )
    conn_limits = ConnectionLimits(
        max_established_total=config.max_connections,
        max_established_inbound=config.conn_high_water,
        max_established_per_peer=config.conn_high_water,
        max_pending_inbound=config.conn_low_water,
    )
    return ResourceManager(
        limits=res_limits,
        connection_limits=conn_limits,
        enable_metrics=True,
        enable_rate_limiting=True,
        connections_per_peer_per_sec=config.rate_limit_per_peer,
        burst_connections_per_peer=config.burst_per_peer,
    )


def attach_resource_manager(host: IHost, rm: ResourceManager) -> None:
    """Idempotently re-attach ResourceManager to host network if supported.

    `new_host(resource_manager=rm)` already sets RM, but the original code
    (network/host.py pre-A3) re-attached it explicitly via
    `network.set_resource_manager(rm)` behind a hasattr guard. Preserved
    byte-for-byte: likely defensive against a libp2p 0.5.x quirk where the
    constructor kwarg wasn't always honored. Revisit after the 0.6.0 bump.
    """
    network = host.get_network()
    if hasattr(network, "set_resource_manager"):
        network.set_resource_manager(rm)


def collect_listen_addrs(host: IHost) -> List[multiaddr.Multiaddr]:
    """Return host listen addresses with fallback chain for the py-libp2p quirk
    where `host.get_addrs()` can return [] right after start.

    Order: host.get_addrs() → network.get_addrs() → iterate network.listeners.
    Strips trailing /p2p/<id> suffix (some shims include it, callers don't want it).
    Returns ONLY observed addresses — no config fallback. Callers needing config
    fallback (e.g. logging) should layer it on themselves.
    """
    addrs = list(host.get_addrs() or [])
    network = host.get_network()
    get_addrs = getattr(network, "get_addrs", None)
    if not addrs and callable(get_addrs):
        try:
            addrs = list(get_addrs() or [])
        except Exception:
            pass
    listeners = getattr(network, "listeners", None)
    if not addrs and listeners:
        gathered: List[multiaddr.Multiaddr] = []
        iterable = listeners.values() if isinstance(listeners, dict) else listeners
        for listener in iterable:
            getter = getattr(listener, "get_addrs", None)
            if callable(getter):
                try:
                    gathered.extend(getter() or [])
                except Exception:
                    continue
        if gathered:
            addrs = gathered
    return [_strip_p2p_suffix(a) for a in addrs]


def _strip_p2p_suffix(addr: multiaddr.Multiaddr) -> multiaddr.Multiaddr:
    addr_str = str(addr)
    if "/p2p/" in addr_str:
        addr_str = addr_str.split("/p2p/")[0]
    return multiaddr.Multiaddr(addr_str)


async def wait_for_listening(host: IHost, *, timeout: float = 5.0) -> List[multiaddr.Multiaddr]:
    """Poll `collect_listen_addrs` until at least one address is observed.

    Raises `trio.TooSlowError` if the timeout elapses with no addresses.
    """
    with trio.fail_after(timeout):
        while True:
            addrs = collect_listen_addrs(host)
            if addrs:
                return addrs
            await trio.sleep(0.05)


def ensure_peer_id(peer_id: Any) -> ID:
    """Coerce ID-or-base58-string to libp2p ID.

    Raises whatever `ID.from_base58` raises on malformed input (today
    `ValueError`). Callers that want to swallow should wrap the call.
    """
    if isinstance(peer_id, ID):
        return peer_id
    return ID.from_base58(peer_id)


def seed_peerstore(
    host: IHost,
    peer_id: Any,
    addrs: Iterable[Any],
    *,
    ttl: int = PERMANENT_ADDR_TTL,
    strict: bool = False,
) -> List[multiaddr.Multiaddr]:
    """Parse `addrs` into Multiaddrs, register them in `host`'s peerstore
    under `peer_id`, and return the parsed addrs.

    `addrs` items can be strings or Multiaddr instances. `peer_id` can be an
    ID or base58 string.

    Errors:
    - strict=False (default): per-addr parse failures and peerstore errors
      are silently skipped. Used for live peer gossip where some addrs may be
      junk and we just want best-effort persistence.
    - strict=True: re-raise the first parse / peerstore error. Used by tests
      and upgrade validation.
    """
    if strict:
        pid = ensure_peer_id(peer_id)
        parsed = [a if isinstance(a, multiaddr.Multiaddr) else multiaddr.Multiaddr(a)
                  for a in addrs]
        host.get_peerstore().add_addrs(pid, parsed, ttl)
        return parsed

    try:
        pid = ensure_peer_id(peer_id)
    except Exception:
        return []
    parsed: List[multiaddr.Multiaddr] = []
    for a in addrs:
        try:
            parsed.append(a if isinstance(a, multiaddr.Multiaddr) else multiaddr.Multiaddr(a))
        except Exception:
            continue
    if not parsed:
        return parsed
    try:
        host.get_peerstore().add_addrs(pid, parsed, ttl)
    except Exception:
        pass
    return parsed


def seed_peerstore_persisted(host: IHost, persistence: PeerstorePersistence) -> None:
    """Load persisted peer addrs from DB and seed the host's peerstore.

    Best-effort: per-peer parse errors are silently ignored. Used by
    HostManager at startup to restore connectivity hints across restarts.
    """
    peers = persistence.load()
    peerstore = host.get_peerstore()
    for pid, addrs in peers.items():
        try:
            peerstore.add_addrs(
                ID.from_base58(pid),
                [multiaddr.Multiaddr(a) for a in addrs],
                PERMANENT_ADDR_TTL,
            )
        except Exception:
            pass


# --------------------------------------------------------------------------
# Stream primitives (A5)
#
# These wrap libp2p stream quirks; JSON / handler dispatch stays in
# `network/service.py` because that is Tau protocol behavior.
# --------------------------------------------------------------------------


async def bounded_stream_read(
    stream,
    limit: int,
    *,
    empty_timeout: Optional[float] = None,
) -> bytes:
    """Read up to `limit` bytes from `stream`, returning bytes.

    Contract:
    - Returns at most `limit` bytes.
    - Returns b"" if the read yields None (some libp2p versions return None
      on graceful close instead of b"").
    - If `empty_timeout` is set and no bytes arrive in `empty_timeout`
      seconds, returns b"". Never raises `trio.TooSlowError`, never returns
      None. The timeout exists for callers that send empty requests (some
      tests/debug tools "send" by writing nothing and closing) — libp2p
      won't deliver b"" as data, so a naive `stream.read()` would block
      forever.
    """
    if empty_timeout is None:
        data = await stream.read(limit)
        return data if data is not None else b""

    data: Optional[bytes] = b""
    with trio.move_on_after(empty_timeout) as scope:
        data = await stream.read(limit)
    if scope.cancelled_caught or data is None:
        return b""
    return data


async def close_stream_safely(stream) -> None:
    """`await stream.close()` wrapped so close errors do not mask handler errors.

    Use inside `finally` blocks. Logs at DEBUG on failure.
    """
    try:
        await stream.close()
    except Exception:
        logger.debug("stream.close() raised", exc_info=True)


# --------------------------------------------------------------------------
# DHT validator wrap (A6)
# --------------------------------------------------------------------------


class _DHTNamespaceValidatorWrapper:
    """Adapter from `bool`-returning Tau validator to libp2p's `Validator` protocol.

    libp2p's per-namespace validator expects `validate(key, value)` to raise on
    failure and `select(key, records)` to return an index. Tau validators return
    `bool`, so wrap them.
    """

    def __init__(self, namespace: str, func) -> None:
        self.ns = namespace
        self.func = func

    def validate(self, key, value):
        from libp2p.records.utils import InvalidRecordType
        if not self.func(key, value):
            raise InvalidRecordType(f"Validation failed for {self.ns}")

    def select(self, key: str, records: list) -> int:
        if not records:
            raise ValueError("No records to select from")
        return 0


def install_validating_dht(
    dht,
    namespace_validators: Dict[str, Any],
    record_validator,
    key_validator,
):
    """Install per-namespace validators, value_store.put guard, and
    provider_store.add_provider guard onto an initialized `KadDHT`.

    Args:
        dht: A KadDHT instance with .validator, .value_store, .provider_store.
        namespace_validators: ns -> callable(key_bytes, value_bytes) -> bool.
        record_validator: callable(key_bytes, value_bytes) -> bool. Wraps
            value_store.put — raises ValueError on False.
        key_validator: callable(key_bytes) -> bool. Wraps
            provider_store.add_provider — raises ValueError on False.

    Returns:
        (orig_value_store_put, orig_provider_add) so the caller can undo the
        wraps on teardown. Either may be None if the corresponding store was
        absent on the dht.

    Raises:
        RuntimeError: if `dht.validator` exposes neither `.validators` nor
            `._validators`. This is a deliberate failure — silent no-op would
            mean bad records get accepted (security regression).
    """
    validation_map = None
    if hasattr(dht, "validator"):
        if hasattr(dht.validator, "validators"):
            validation_map = dht.validator.validators
        elif hasattr(dht.validator, "_validators"):
            validation_map = dht.validator._validators

    if validation_map is None:
        raise RuntimeError(
            "libp2p Validator shape changed: neither `.validators` nor "
            "`._validators` is exposed by dht.validator. Update "
            "network.libp2p_compat.install_validating_dht for the new shape."
        )

    for ns, func in namespace_validators.items():
        validation_map[ns] = _DHTNamespaceValidatorWrapper(ns, func)

    orig_put = None
    value_store = getattr(dht, "value_store", None)
    if value_store is not None:
        orig_put = value_store.put

        def validating_put(key: bytes, value: bytes, validity: float = 0.0):
            logger.debug("Validating put for key: %s", key)
            if not record_validator(key, value):
                logger.debug("Validation failed for key: %s", key)
                raise ValueError("DHT record failed validation")
            return orig_put(key, value, validity)

        value_store.put = validating_put

    orig_add = None
    provider_store = getattr(dht, "provider_store", None)
    if provider_store is not None:
        orig_add = provider_store.add_provider

        def validating_add(key: bytes, provider_info):
            if not key_validator(key):
                raise ValueError("Invalid DHT provider key")
            return orig_add(key, provider_info)

        provider_store.add_provider = validating_add

    return orig_put, orig_add


# --------------------------------------------------------------------------
# Trio↔async bridge (A7)
# --------------------------------------------------------------------------


def run_trio_from_thread(async_callable, *args, token, timeout: Optional[float] = None):
    """Run an async callable on a trio nursery thread, returning its result.

    Use from a non-trio thread (e.g. background workers, tests calling DHT
    helpers). Wraps `trio.from_thread.run` so callers don't repeat the
    boilerplate around `RunFinishedError` / `Cancelled` / `RuntimeError`
    (the trio loop may have shut down or never started).

    If `timeout` is set, the callable runs inside `trio.move_on_after(timeout)`;
    if the timeout fires, returns None.

    Returns the callable's result, or None on shutdown / cancellation / timeout.
    Other exceptions raised by `async_callable` propagate to the caller.
    """
    if timeout is None:
        try:
            return trio.from_thread.run(async_callable, *args, trio_token=token)
        except (trio.RunFinishedError, trio.Cancelled, RuntimeError):
            return None

    async def _bounded():
        with trio.move_on_after(timeout):
            return await async_callable(*args)
        return None

    try:
        return trio.from_thread.run(_bounded, trio_token=token)
    except (trio.RunFinishedError, trio.Cancelled, RuntimeError):
        return None


# --------------------------------------------------------------------------
# QUIC shim (A9) — transitional, no-op once libp2p >= 0.6.0 fixes the upstream
# `QUICStream._cleanup_resources` `NoneType` await race.
#
# IMPORTANT: this is a FUNCTION, not a module-load side effect. Callers must
# invoke `apply_quic_cleanup_shim()` explicitly (today: top of
# `network/service.py`).
# --------------------------------------------------------------------------


def apply_quic_cleanup_shim() -> bool:
    """Patch `QUICStream._cleanup_resources` to swallow `TypeError("NoneType ... await")`
    during stream close.

    Source bug: `QUICStream._cleanup_resources` body is byte-for-byte identical
    between libp2p v0.5.0 and v0.6.0, and the 0.6.0 changelog does NOT call out
    an upstream fix. The shim is kept always-on (no version gate) because the
    underlying race still exists on 0.6.0. Drop when an upstream fix lands and
    is verified empirically. TODO: file upstream issue referencing
    `QUICStream._cleanup_resources` NoneType-await race.

    Returns:
        True if the shim was applied.
        False if libp2p QUIC transport is unavailable (no-op).
    """
    try:
        from libp2p.transport.quic.stream import QUICStream
    except Exception:
        logger.debug("libp2p QUIC transport unavailable; QUIC shim is a no-op", exc_info=True)
        return False

    try:
        import libp2p as _libp2p
        version_str = getattr(_libp2p, "__version__", "<unknown>")
    except Exception:
        version_str = "<unknown>"

    orig_cleanup = QUICStream._cleanup_resources

    async def _safe_cleanup_resources(self) -> None:
        try:
            await orig_cleanup(self)
        except TypeError as e:
            if "NoneType" in str(e) and "await" in str(e):
                logger.debug("Swallowed benign cleanup error in QUICStream: %s", e)
            else:
                raise

    QUICStream._cleanup_resources = _safe_cleanup_resources
    logger.info("Applied libp2p QUIC cleanup shim (libp2p %s)", version_str)
    return True


__all__ = [
    # Identity (A2)
    "IDENTITY_SEED_SIZE",
    "Ed25519PublicKeyCompat",
    "Ed25519PrivateKeyCompat",
    "keypair_from_seed",
    "generate_seed",
    # Host plumbing (A3)
    "NetworkNotifee",
    "PeerstorePersistence",
    "build_tau_resource_manager",
    "attach_resource_manager",
    "collect_listen_addrs",
    "wait_for_listening",
    "seed_peerstore_persisted",
    # Discovery (A4)
    "ensure_peer_id",
    "seed_peerstore",
    # Stream primitives (A5)
    "bounded_stream_read",
    "close_stream_safely",
    # DHT validator wrap (A6)
    "install_validating_dht",
    # Trio↔async bridge (A7)
    "run_trio_from_thread",
    # QUIC shim (A9)
    "apply_quic_cleanup_shim",
]
