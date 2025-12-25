"""Environment-aware configuration for the Tau Testnet server."""
from __future__ import annotations

import copy
import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from errors import ConfigurationError


DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DEFAULT_PROD_DB_PATH = "node.db"


@dataclass
class ServerSettings:
    host: str = "127.0.0.1"
    port: int = 65432
    buffer_size: int = 1024

    def validate(self) -> None:
        if not self.host:
            raise ConfigurationError("Server host must be provided.")
        if not (0 <= self.port <= 65535):
            raise ConfigurationError(f"Invalid server port: {self.port}")
        if self.buffer_size <= 0:
            raise ConfigurationError("Buffer size must be positive.")


@dataclass
class TauSettings:
    program_file: str = 'genesis.tau'
    docker_image: str = 'tau'
    container_workdir: str = '/data'
    ready_signal: str = "Execution step: 0"

    def validate(self) -> None:
        if not self.program_file:
            raise ConfigurationError("Tau program file path must be provided.")
        if not self.docker_image:
            raise ConfigurationError("Tau Docker image must be configured.")
        if not self.container_workdir:
            raise ConfigurationError("Tau container workdir must be provided.")
        if not self.ready_signal:
            raise ConfigurationError("Tau ready signal must be provided.")


@dataclass
class TimeoutSettings:
    process_timeout: int = 120
    comm_timeout: int = 99999
    client_wait_timeout: int = 10
    shutdown_timeout: int = 1

    def validate(self) -> None:
        for name, value in asdict(self).items():
            if value <= 0:
                raise ConfigurationError(f"Timeout '{name}' must be greater than zero (got {value}).")


@dataclass
class DatabaseSettings:
    path: str = DEFAULT_PROD_DB_PATH

    def validate(self) -> None:
        if not self.path:
            raise ConfigurationError("Database path must be configured.")


@dataclass
class NetworkSettings:
    network_id: str = "tau-local"
    genesis_hash: str = "GENESIS"
    listen: List[str] = field(default_factory=lambda: ["/ip4/127.0.0.1/tcp/0"])
    bootstrap_peers: List[Dict[str, Any]] = field(default_factory=list)
    peerstore_path: Optional[str] = None
    # Optional path to a private key file for persistent libp2p identity
    identity_key_path: Optional[str] = None

    def validate(self) -> None:
        if not self.network_id:
            raise ConfigurationError("Network ID must be configured.")
        if not self.genesis_hash:
            raise ConfigurationError("Genesis hash must be configured.")
        for peer in self.bootstrap_peers:
            if not isinstance(peer, dict):
                raise ConfigurationError("Bootstrap peer entries must be dictionaries.")
            if "peer_id" not in peer or "addrs" not in peer:
                raise ConfigurationError(f"Invalid bootstrap peer entry: {peer}")
            if not isinstance(peer["addrs"], list):
                raise ConfigurationError(f"Bootstrap peer addrs must be a list: {peer}")


@dataclass
class LoggingSettings:
    level: str = "INFO"
    format: str = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    datefmt: str = "%Y-%m-%d %H:%M:%S"

    def validate(self) -> None:
        if not self.level:
            raise ConfigurationError("Logging level must be provided.")
        if not self.format:
            raise ConfigurationError("Logging format must be provided.")


@dataclass
class DHTSettings:
    record_ttl: int = 24 * 60 * 60
    validator_namespaces: List[str] = field(default_factory=lambda: ["block", "tx", "state"])
    bootstrap_peers: List[Dict[str, Any]] = field(default_factory=list)

    def validate(self) -> None:
        if self.record_ttl <= 0:
            raise ConfigurationError("DHT record TTL must be positive.")
        for namespace in self.validator_namespaces:
            if not isinstance(namespace, str) or not namespace.strip():
                raise ConfigurationError(f"Invalid DHT validator namespace: {namespace!r}")
        for peer in self.bootstrap_peers:
            if not isinstance(peer, dict):
                raise ConfigurationError("DHT bootstrap peer entries must be dictionaries.")
            if "peer_id" not in peer or "addrs" not in peer:
                raise ConfigurationError(f"Invalid DHT bootstrap peer entry: {peer}")
            if not isinstance(peer["addrs"], list):
                raise ConfigurationError(f"DHT bootstrap peer addrs must be a list: {peer}")


@dataclass
class AuthoritySettings:
    miner_pubkey: str = (
        "91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6"
    )
    miner_privkey: Optional[str] = (
        "11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09"
    )
    block_signature_scheme: str = "bls_g2"
    state_locator_namespace: str = "state"

    def validate(self) -> None:
        if not (isinstance(self.miner_pubkey, str) and len(self.miner_pubkey) == 96):
            raise ConfigurationError("Authority miner_pubkey must be a 96-character hex string.")
        try:
            bytes.fromhex(self.miner_pubkey)
        except ValueError as exc:
            raise ConfigurationError("Authority miner_pubkey must be valid hexadecimal.") from exc
        if self.miner_privkey:
            if not (isinstance(self.miner_privkey, str) and len(self.miner_privkey) == 64):
                raise ConfigurationError("Authority miner_privkey must be a 64-character hex string.")
            try:
                bytes.fromhex(self.miner_privkey)
            except ValueError as exc:
                raise ConfigurationError("Authority miner_privkey must be valid hexadecimal.") from exc
        if not isinstance(self.block_signature_scheme, str) or not self.block_signature_scheme:
            raise ConfigurationError("Authority block_signature_scheme must be a non-empty string.")
        if not isinstance(self.state_locator_namespace, str) or not self.state_locator_namespace.strip():
            raise ConfigurationError("Authority state_locator_namespace must be a non-empty string.")


@dataclass
class Settings:
    env: str
    server: ServerSettings
    tau: TauSettings
    timeouts: TimeoutSettings
    database: DatabaseSettings
    network: NetworkSettings
    dht: DHTSettings
    logging: LoggingSettings
    authority: AuthoritySettings

    def validate(self) -> None:
        self.server.validate()
        self.tau.validate()
        self.timeouts.validate()
        self.database.validate()
        self.network.validate()
        self.dht.validate()
        self.logging.validate()
        self.authority.validate()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "env": self.env,
            "server": asdict(self.server),
            "tau": asdict(self.tau),
            "timeouts": asdict(self.timeouts),
            "database": asdict(self.database),
            "network": asdict(self.network),
            "dht": asdict(self.dht),
            "logging": asdict(self.logging),
            "authority": asdict(self.authority),
        }


BASE_DEFAULTS: Dict[str, Any] = {
    "server": asdict(ServerSettings()),
    "tau": asdict(TauSettings()),
    "timeouts": asdict(TimeoutSettings()),
    "database": asdict(DatabaseSettings()),
    "network": {
        "network_id": "tau-local",
        "genesis_hash": "GENESIS",
        "listen": ["/ip4/127.0.0.1/tcp/0"], 
        "bootstrap_peers": [
            {
                "peer_id": "12D3KooWDpWEYxBy8y84AssrPSLaq9DxC7Lncmn5wERJnAWZFnYC", #MAIN NODE
                "addrs": ["/ip4/127.0.0.1/tcp/4001"],
            },
        ],
        "peerstore_path": None,
        # Persist the libp2p identity here unless --ephemeral-identity is set.
        "identity_key_path": os.path.join(DATA_DIR, "identity.key"),
    },
    "dht": asdict(DHTSettings()),
    "logging": asdict(LoggingSettings()),
    "authority": asdict(AuthoritySettings()),
}

ENVIRONMENT_OVERRIDES: Dict[str, Dict[str, Any]] = {
    "development": {},
    "test": {
        "logging": {"level": "DEBUG"},
        "timeouts": {
            "process_timeout": 60,
            "comm_timeout": 60,
            "client_wait_timeout": 5,
            "shutdown_timeout": 1,
        },
    },
    "production": {
        "logging": {"level": "WARNING"},
        "timeouts": {
            "client_wait_timeout": 15,
            "shutdown_timeout": 5,
        },
    },
}

_ENV_VALUE_CASTERS: Dict[str, Any] = {
    "TAU_HOST": ("server", "host", str),
    "TAU_PORT": ("server", "port", int),
    "TAU_BUFFER_SIZE": ("server", "buffer_size", int),
    "TAU_PROGRAM_FILE": ("tau", "program_file", str),
    "TAU_DOCKER_IMAGE": ("tau", "docker_image", str),
    "TAU_CONTAINER_WORKDIR": ("tau", "container_workdir", str),
    "TAU_READY_SIGNAL": ("tau", "ready_signal", str),
    "TAU_PROCESS_TIMEOUT": ("timeouts", "process_timeout", int),
    "TAU_COMM_TIMEOUT": ("timeouts", "comm_timeout", int),
    "TAU_CLIENT_WAIT_TIMEOUT": ("timeouts", "client_wait_timeout", int),
    "TAU_SHUTDOWN_TIMEOUT": ("timeouts", "shutdown_timeout", int),
    "TAU_DB_PATH": ("database", "path", str),
    "TAU_NETWORK_ID": ("network", "network_id", str),
    "TAU_GENESIS_HASH": ("network", "genesis_hash", str),
    "TAU_NETWORK_LISTEN": ("network", "listen", lambda value: [addr.strip() for addr in value.split(',') if addr.strip()]),
    "TAU_BOOTSTRAP_PEERS": ("network", "bootstrap_peers", lambda value: json.loads(value)),
    "TAU_PEERSTORE_PATH": ("network", "peerstore_path", str),
    "TAU_IDENTITY_KEY_PATH": ("network", "identity_key_path", str),
    "TAU_DHT_TTL": ("dht", "record_ttl", int),
    "TAU_DHT_VALIDATORS": (
        "dht",
        "validator_namespaces",
        lambda value: [ns.strip() for ns in value.split(',') if ns.strip()],
    ),
    "TAU_DHT_BOOTSTRAP": ("dht", "bootstrap_peers", lambda value: json.loads(value)),
    "TAU_LOG_LEVEL": ("logging", "level", str),
    "TAU_LOG_FORMAT": ("logging", "format", str),
    "TAU_LOG_DATEFMT": ("logging", "datefmt", str),
    "TAU_MINER_PUBKEY": ("authority", "miner_pubkey", str),
    "TAU_MINER_PRIVKEY": ("authority", "miner_privkey", str),
    "TAU_BLOCK_SIGNATURE_SCHEME": ("authority", "block_signature_scheme", str),
    "TAU_STATE_LOCATOR_NAMESPACE": ("authority", "state_locator_namespace", str),
}


def _deep_merge(base: Dict[str, Any], overrides: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in overrides.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def _overrides_from_env() -> Dict[str, Any]:
    overrides: Dict[str, Any] = {}
    for env_key, (section, key, caster) in _ENV_VALUE_CASTERS.items():
        raw = os.environ.get(env_key)
        if raw is None:
            continue
        try:
            parsed = caster(raw)
        except Exception as exc:  # pragma: no cover - configuration error path
            raise ConfigurationError(f"Failed to coerce environment variable {env_key}: {exc}") from exc
        overrides.setdefault(section, {})[key] = parsed
    return overrides


def _settings_from_dict(env: str, payload: Dict[str, Any]) -> Settings:
    return Settings(
        env=env,
        server=ServerSettings(**payload["server"]),
        tau=TauSettings(**payload["tau"]),
        timeouts=TimeoutSettings(**payload["timeouts"]),
        database=DatabaseSettings(**payload["database"]),
        network=NetworkSettings(**payload["network"]),
        dht=DHTSettings(**payload["dht"]),
        logging=LoggingSettings(**payload["logging"]),
        authority=AuthoritySettings(**payload["authority"]),
    )


def load_settings(env: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Settings:
    env_name = (env or os.environ.get("TAU_ENV", "development")).lower()
    base = copy.deepcopy(BASE_DEFAULTS)
    env_specific = ENVIRONMENT_OVERRIDES.get(env_name, {})
    base = _deep_merge(base, copy.deepcopy(env_specific))
    base = _deep_merge(base, _overrides_from_env())
    if overrides:
        base = _deep_merge(base, overrides)
    settings_obj = _settings_from_dict(env_name, base)
    settings_obj.validate()
    return settings_obj


def _sync_legacy_exports(current: Settings) -> None:
    global HOST, PORT, BUFFER_SIZE
    global TAU_PROGRAM_FILE, TAU_DOCKER_IMAGE, CONTAINER_WORKDIR, TAU_READY_SIGNAL
    global PROCESS_TIMEOUT, COMM_TIMEOUT, CLIENT_WAIT_TIMEOUT, SHUTDOWN_TIMEOUT
    global STRING_DB_PATH
    global BOOTSTRAP_PEERS, NETWORK_ID, GENESIS_HASH, NETWORK_LISTEN, PEERSTORE_PATH, peerstore_path
    global DHT_RECORD_TTL, DHT_VALIDATOR_NAMESPACES, DHT_BOOTSTRAP_PEERS
    global LOGGING
    global MINER_PUBKEY, MINER_PRIVKEY, BLOCK_SIGNATURE_SCHEME, STATE_LOCATOR_NAMESPACE

    HOST = current.server.host
    PORT = current.server.port
    BUFFER_SIZE = current.server.buffer_size

    TAU_PROGRAM_FILE = current.tau.program_file
    TAU_DOCKER_IMAGE = current.tau.docker_image
    CONTAINER_WORKDIR = current.tau.container_workdir
    TAU_READY_SIGNAL = current.tau.ready_signal

    PROCESS_TIMEOUT = current.timeouts.process_timeout
    COMM_TIMEOUT = current.timeouts.comm_timeout
    CLIENT_WAIT_TIMEOUT = current.timeouts.client_wait_timeout
    SHUTDOWN_TIMEOUT = current.timeouts.shutdown_timeout

    STRING_DB_PATH = current.database.path

    NETWORK_ID = current.network.network_id
    GENESIS_HASH = current.network.genesis_hash
    NETWORK_LISTEN = current.network.listen
    BOOTSTRAP_PEERS = current.network.bootstrap_peers
    PEERSTORE_PATH = current.network.peerstore_path
    peerstore_path = current.network.peerstore_path

    DHT_RECORD_TTL = current.dht.record_ttl
    DHT_VALIDATOR_NAMESPACES = current.dht.validator_namespaces
    DHT_BOOTSTRAP_PEERS = current.dht.bootstrap_peers

    LOGGING = current.logging
    MINER_PUBKEY = current.authority.miner_pubkey
    MINER_PRIVKEY = current.authority.miner_privkey
    BLOCK_SIGNATURE_SCHEME = current.authority.block_signature_scheme
    STATE_LOCATOR_NAMESPACE = current.authority.state_locator_namespace


def reload_settings(env: Optional[str] = None, overrides: Optional[Dict[str, Any]] = None) -> Settings:
    global settings
    settings = load_settings(env=env or settings.env, overrides=overrides)
    _sync_legacy_exports(settings)
    return settings


def set_database_path(path: str) -> None:
    if not path:
        raise ConfigurationError("Database path cannot be empty.")
    settings.database.path = path
    settings.database.validate()
    _sync_legacy_exports(settings)


settings: Settings = load_settings()
_sync_legacy_exports(settings)

__all__ = [
    "settings",
    "reload_settings",
    "set_database_path",
    "Settings",
    "ServerSettings",
    "TauSettings",
    "TimeoutSettings",
    "DatabaseSettings",
    "NetworkSettings",
    "DHTSettings",
    "LoggingSettings",
    "AuthoritySettings",
    "DATA_DIR",
    "DEFAULT_PROD_DB_PATH",
    "HOST",
    "PORT",
    "BUFFER_SIZE",
    "TAU_PROGRAM_FILE",
    "TAU_DOCKER_IMAGE",
    "CONTAINER_WORKDIR",
    "TAU_READY_SIGNAL",
    "PROCESS_TIMEOUT",
    "COMM_TIMEOUT",
    "CLIENT_WAIT_TIMEOUT",
    "SHUTDOWN_TIMEOUT",
    "STRING_DB_PATH",
    "BOOTSTRAP_PEERS",
    "NETWORK_ID",
    "GENESIS_HASH",
    "NETWORK_LISTEN",
    "PEERSTORE_PATH",
    "peerstore_path",
    "DHT_RECORD_TTL",
    "DHT_VALIDATOR_NAMESPACES",
    "DHT_BOOTSTRAP_PEERS",
    "LOGGING",
    "MINER_PUBKEY",
    "MINER_PRIVKEY",
    "BLOCK_SIGNATURE_SCHEME",
    "STATE_LOCATOR_NAMESPACE",
]

# Feature flags
TESTNET_AUTO_FAUCET = True
