from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Set

from libp2p.kad_dht import common as dht_common
from libp2p.kad_dht.kad_dht import KadDHT, DHTMode
from libp2p.peer.peerinfo import PeerInfo

from .config import NetworkConfig

logger = logging.getLogger(__name__)


class DHTManager:
    def __init__(self, config: NetworkConfig) -> None:
        self._config = config
        self._dht: Optional[KadDHT] = None
        self._dht_manager: Optional[Any] = None
        self._dht_validators: Dict[str, Callable[[bytes, bytes], bool]] = {}
        self._dht_allowed_namespaces: Set[str] = set()
        self._dht_value_store_put: Optional[Callable[..., Any]] = None
        self._dht_value_store_put: Optional[Callable[..., Any]] = None
        self._dht_provider_add: Optional[Callable[..., Any]] = None
        self._trio_token = None

    def set_trio_token(self, token) -> None:
        self._trio_token = token

    def get_record_sync(self, key: bytes, timeout: float = 5.0) -> bytes | None:
        """
        Retrieves a record from the DHT synchronously, bridging to the network thread if needed.
        """
        import trio
        
        # Try local store first
        if self._dht and getattr(self._dht, "value_store", None):
            val = self._dht.value_store.get(key)
            if val:
                return getattr(val, "value", val)
        
        # If not local and we have a token, try network
        if self._dht and self._trio_token:
            try:
                async def _get_value_with_timeout() -> bytes | None:
                    with trio.move_on_after(timeout):
                        return await self._dht.get_value(key)
                    return None

                # Execute async get_value on the trio thread (bounded by timeout).
                return trio.from_thread.run(_get_value_with_timeout, trio_token=self._trio_token)
            except (trio.RunFinishedError, trio.Cancelled, RuntimeError):
                # Network might be down or shutting down
                return None
            except Exception as e:
                logger.warning("DHT sync retrieval failed: %s", e)
                return None
        
        return None

    def set_dht(self, dht: KadDHT, manager: Any) -> None:
        self._dht = dht
        self._dht_manager = manager
        self._setup_dht_validators()

    @property
    def dht(self) -> Optional[KadDHT]:
        return self._dht

    @property
    def routing_table(self):
        if self._dht:
            return self._dht.routing_table
        return None

    @property
    def peer_routing(self):
        if self._dht:
            return self._dht.peer_routing
        return None

    def _setup_dht_validators(self) -> None:
        if self._dht is None:
            return
        
        # Configure TTL
        # Note: In the original code, this accessed self._config.dht_record_ttl
        # But NetworkConfig object passed here might not have it directly if it's nested in Settings.
        # We'll assume the caller configures global DHT settings or we pass the full config.
        # For now, let's assume standard defaults or that dht_common is configured globally.
        
        self._register_default_dht_validators()

        value_store = getattr(self._dht, "value_store", None)
        logger.debug("DHT value_store: %s", value_store)
        if value_store is not None and self._dht_value_store_put is None:
            original_put = value_store.put

            def validating_put(key: bytes, value: bytes, validity: float = 0.0):
                logger.debug("Validating put for key: %s", key)
                if not self._validate_dht_record(key, value):
                    logger.debug("Validation failed for key: %s", key)
                    raise ValueError("DHT record failed validation")
                return original_put(key, value, validity)

            value_store.put = validating_put
            self._dht_value_store_put = original_put

        provider_store = getattr(self._dht, "provider_store", None)
        if provider_store is not None and self._dht_provider_add is None:
            original_add = provider_store.add_provider

            def validating_add(key: bytes, provider_info: Any):
                if not self._validate_dht_key(key):
                    raise ValueError("Invalid DHT provider key")
                return original_add(key, provider_info)

            provider_store.add_provider = validating_add
            self._dht_provider_add = original_add

    def _register_default_dht_validators(self) -> None:
        self.register_validator("block", self._validate_block_record)
        self.register_validator("tx", self._validate_tx_record)
        self.register_validator("state", self._validate_state_record)
        self.register_validator("formula", self._validate_formula_record)

    def _validate_block_record(self, key: bytes, value: bytes) -> bool:
        import json
        try:
            key_str = key.decode("ascii")
            if not key_str.startswith("block:"):
                return False
            block_hash = key_str.split(":", 1)[1]
            
            data = json.loads(value.decode("utf-8"))
            if data.get("block_hash") != block_hash:
                return False
            return True
        except Exception:
            return False

    def _validate_tx_record(self, key: bytes, value: bytes) -> bool:
        # For tx, the key is tx:{tx_id}
        # The value should be the canonical transaction bytes?
        # The test says:
        # tx_id, canonical = sendtx._compute_transaction_message_id(tx_payload)
        # dht.value_store.put(f"tx:{tx_id}".encode(), canonical_bytes)
        # So we need to re-compute ID from value and check if it matches key.
        from commands import sendtx
        try:
            key_str = key.decode("ascii")
            if not key_str.startswith("tx:"):
                return False
            tx_id = key_str.split(":", 1)[1]
            
            # Value is canonical bytes.
            # We need to compute ID from it.
            # sendtx._compute_transaction_message_id takes dict.
            # But here we have bytes.
            # If value is JSON, we can parse it.
            # But test passes canonical_bytes which might be JSON string encoded?
            # Test: canonical_bytes = canonical.encode()
            # canonical is string.
            
            # sendtx._compute_transaction_message_id returns (id, canonical_str)
            # So we can just hash the value?
            # sendtx logic:
            # canonical = json.dumps(tx, sort_keys=True, separators=(",", ":"))
            # msg_id = hashlib.sha256(canonical.encode()).hexdigest()
            
            import hashlib
            computed_id = hashlib.sha256(value).hexdigest()
            return computed_id == tx_id
        except Exception:
            return False

    def _validate_state_record(self, key: bytes, value: bytes) -> bool:
        """
        Validate a `state:<hash>` record.

        Back-compat: older code/tests store JSON blobs under `state:<id>` that look like:
          {"block_hash": "<id>", "accounts": {...}}

        New mode (Tau rules snapshot distribution): store the raw Tau specification bytes
        under `state:<blake3_hex>`, validated by hashing the bytes and comparing to the
        key suffix.
        """
        import json
        try:
            key_str = key.decode("ascii")
            if not key_str.startswith("state:"):
                return False
            suffix = key_str.split(":", 1)[1]
        except Exception:
            return False

        # 1) Legacy JSON payload (keep accepting for existing tests/protocols)
        try:
            data = json.loads(value.decode("utf-8"))
            if isinstance(data, dict) and data.get("block_hash") == suffix:
                return True
        except Exception:
            pass

        # 2) Raw Tau state bytes: validate by hash
        try:
            from poa.state import compute_state_hash

            return compute_state_hash(value) == suffix
        except Exception:
            return False

    def put_record_sync(self, key: bytes, value: bytes, timeout: float = 5.0) -> bool:
        """
        Best-effort synchronous DHT publish helper.

        - Always writes to the local value_store (so local lookups work immediately).
        - If running with a Trio token, also performs a network `put_value` so peers
          can fetch the record via KadDHT lookups.
        """
        # Debug: show what we're storing for state snapshots (balances + tau spec).
        if logger.isEnabledFor(logging.DEBUG):
            try:
                key_str = key.decode("ascii", errors="replace")
            except Exception:
                key_str = repr(key)
            if key_str.startswith("state:"):
                try:
                    decoded = value.decode("utf-8", errors="replace")
                except Exception:
                    decoded = repr(value)
                # Try to label payload type.
                label = "raw"
                if isinstance(decoded, str) and decoded.lstrip().startswith("{"):
                    try:
                        import json

                        parsed = json.loads(decoded)
                        if isinstance(parsed, dict) and "accounts" in parsed:
                            label = "accounts_snapshot"
                        else:
                            label = "state_json"
                    except Exception:
                        label = "state_text"
                else:
                    label = "tau_spec"
                logger.debug("DHT put_record_sync (%s) key=%s value=%s", label, key, decoded)

        # Local store first
        if self._dht and getattr(self._dht, "value_store", None):
            try:
                self._dht.value_store.put(key, value)
            except Exception:
                return False

        # Network replication if possible
        if self._dht and self._trio_token:
            try:
                import trio

                def _put() -> None:
                    return None

                # Run `put_value` on the Trio thread. Note: KadDHT.put_value is async.
                trio.from_thread.run(
                    self._dht.put_value,
                    key,
                    value,
                    trio_token=self._trio_token,
                )
            except (trio.RunFinishedError, trio.Cancelled, RuntimeError):
                return True  # local store already succeeded
            except Exception as exc:
                logger.debug("DHT put_record_sync network publish failed: %s", exc)
                return True  # local store already succeeded

        return True

    def _validate_formula_record(self, key: bytes, value: bytes) -> bool:
        """
        Validates a formula record.
        Key: formula:<hash>
        Value: raw bytes of the formula (rules text)
        Validation: SHA256(value) == hash
        """
        import hashlib
        try:
            key_str = key.decode("ascii")
            if not key_str.startswith("formula:"):
                return False
            expected_hash = key_str.split(":", 1)[1]
            
            # Compute hash of the value
            # We use SHA256 for formula hashes in DHT keys
            computed_hash = hashlib.sha256(value).hexdigest()
            
            return computed_hash == expected_hash
        except Exception:
            return False

    def register_validator(self, namespace: str, validator: Callable[[bytes, bytes], bool]):
        self._dht_validators[namespace] = validator
        self._dht_allowed_namespaces.add(namespace)

    def _extract_dht_namespace(self, key: bytes) -> Optional[str]:
        try:
            key_str = key.decode("ascii")
        except UnicodeDecodeError:
            return None
        if ":" not in key_str:
            return None
        namespace, suffix = key_str.split(":", 1)
        if not suffix:
            return None
        return namespace

    def _validate_dht_key(self, key: bytes) -> bool:
        namespace = self._extract_dht_namespace(key)
        if namespace is None:
            return False
        if self._dht_allowed_namespaces and namespace not in self._dht_allowed_namespaces:
            return False
        return True

    def _validate_dht_record(self, key: bytes, value: bytes) -> bool:
        if not self._validate_dht_key(key):
            logger.debug("Invalid DHT key: %s", key)
            return False
        namespace = self._extract_dht_namespace(key)
        if namespace and namespace in self._dht_validators:
            try:
                res = self._dht_validators[namespace](key, value)
                logger.debug("Validator for %s returned %s", namespace, res)
                return res
            except Exception:
                logger.debug("DHT validator for %s raised exception", namespace, exc_info=True)
                return False
        logger.debug("No validator for namespace %s, allowing", namespace)
        return True
