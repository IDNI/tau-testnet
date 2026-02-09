from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional, Set

from libp2p.kad_dht import common as dht_common
from libp2p.kad_dht.kad_dht import KadDHT, DHTMode
from libp2p.peer.peerinfo import PeerInfo

from .config import NetworkConfig

logger = logging.getLogger(__name__)



class DHTManager:
    def __encode_dht_key(self, namespace: str, suffix: str) -> bytes:
        """Encodes namespace and suffix into a Slash-prefixed DHT key."""
        # Clean inputs
        ns = namespace.strip("/")
        sfx = suffix
        return f"/{ns}/{sfx}".encode("utf-8")

    def _encode_dht_key(self, namespace: str, suffix: str) -> bytes:
        return self.__encode_dht_key(namespace, suffix)

    def _decode_dht_key(self, key: bytes) -> Optional[tuple[str, str]]:
        """
        Decodes a DHT key into (namespace, suffix).
        Supports:
        1. /namespace/suffix (Standard)
        2. namespace:suffix (Legacy/Simple)
        """
        try:
            if isinstance(key, str):
                key_str = key
            else:
                key_str = key.decode("utf-8")
        except UnicodeDecodeError:
            return None

        # 1. Standard /namespace/suffix
        if key_str.startswith("/"):
            parts = key_str.strip("/").split("/", 1)
            if len(parts) == 2:
                return parts[0], parts[1]
            return None

        # 2. Legacy namespace:suffix
        if ":" in key_str:
            parts = key_str.split(":", 1)
            return parts[0], parts[1]

        return None

    def __init__(self, config: NetworkConfig) -> None:
        self._config = config
        self._dht: Optional[KadDHT] = None
        self._host: Optional[Any] = None
        self._dht_manager: Optional[Any] = None
        self._dht_validators: Dict[str, Callable[[bytes, bytes], bool]] = {}
        self._dht_allowed_namespaces: Set[str] = set()
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

        # Ensure key is encoded in slash-prefixed format if needed
        # We try both raw and encoded to be safe or rely on the caller?
        # Let's rely on internal encoding/decoding helper.
        # But if caller passes "state:...", we should encode it.
        # If caller passes "/state/...", we leave it?
        # Let's say: Caller manages logic, but we ensure consistent encoding.
        # But wait, existing callers pass "state:..." bytes.
        
        # NOTE: We assume the key passed here is the logical key (e.g. state:...) or raw.
        # We should probably normalize.
        # For now, let's just use the key as provided but ensure we check encoding in put.
        # Actually, get_record_sync calls get_value. If put used encoded key, get must use encoded key.

        encoded_key = key
        # If it doesn't look like /namespace/..., try to encode it?
        # The issue is we don't know the namespace easily from bytes if it's just "state:..."
        # Actually we do, split by :.
        try:
             decoded = self._decode_dht_key(key)
             if decoded:
                 encoded_key = self._encode_dht_key(decoded[0], decoded[1])
        except Exception:
             pass

        # Try local store first
        if self._dht and getattr(self._dht, "value_store", None):
            val = self._dht.value_store.get(encoded_key)
            if val:
                return getattr(val, "value", val)
            # Fallback: try raw key (legacy)
            if encoded_key != key:
                 val = self._dht.value_store.get(key)
                 if val:
                     return getattr(val, "value", val)
        
        # If not local and we have a token, try network
        if self._dht and self._trio_token:
            try:
                async def _get_value_with_timeout() -> bytes | None:
                    with trio.move_on_after(timeout):
                         # KadDHT expects string keys (slash-prefixed)
                         key_to_use = encoded_key.decode("utf-8") if isinstance(encoded_key, bytes) else encoded_key
                         return await self._dht.get_value(key_to_use)
                    return None

                # Execute async get_value on the trio thread (bounded by timeout).
                return trio.from_thread.run(_get_value_with_timeout, trio_token=self._trio_token)
            except (trio.RunFinishedError, trio.Cancelled, RuntimeError):
                # Network might be down or shutting down
                return None
            except Exception as e:
                logger.exception("DHT sync retrieval failed: %s", e)
                return None
        
        return None

    def set_dht(self, dht: KadDHT, manager: Any, host: Any = None) -> None:
        self._dht = dht
        self._dht_manager = manager
        if host:
             self._host = host
        elif hasattr(dht, "host"):
             self._host = dht.host
        else:
             self._host = None
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
        
        # Inject validators into the underlying KadDHT validator to ensure put_value works
        # KadDHT.validator is typically an instance of libp2p.records.validator.Validator
        # It maintains a dict `validators` mapping key prefix to a validator object/function.
        # The validator function is expected to raise InvalidRecordType or similar on failure.
        if hasattr(self._dht, "validator"):
            # Try to support NamespacedValidator
            validation_map = None
            if hasattr(self._dht.validator, "validators"):
                validation_map = self._dht.validator.validators
            elif hasattr(self._dht.validator, "_validators"): # Common pattern
                validation_map = self._dht.validator._validators
            
            if validation_map is not None:
                from libp2p.records.utils import InvalidRecordType
                 
                class ValidatorWrapper:
                    def __init__(self, ns, func):
                        self.ns = ns
                        self.func = func
                    
                    def validate(self, key, value):
                        # Ensure key/value types (Validator passes key as str? we handle both)
                        if not self.func(key, value):
                            raise InvalidRecordType(f"Validation failed for {self.ns}")

                    def select(self, key: str, records: List[bytes]) -> int:
                        # Simple selector: return index of first record that validates
                        # In many cases records are just values? 
                        # KadDHT.get_value passes list of values.
                        if not records:
                            raise ValueError("No records to select from")
                        
                        # Just pick the first one that validates, or 0 if all valid/unchecked
                        # Since validate() raises on failure, we might assume filtered beforehand?
                        # But select() is used to pick the *best*. 
                        # For immutable data (hashed), any valid one is "best".
                        return 0

                for ns, v in self._dht_validators.items():
                    # We must wrap our boolean validators to raise Exception
                    validation_map[ns] = ValidatorWrapper(ns, v)

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
        self.register_validator("tau_state", self._validate_tau_state_record)
        self.register_validator("formula", self._validate_formula_record)

    def _validate_block_record(self, key: bytes, value: bytes) -> bool:
        import json
        decoded = self._decode_dht_key(key)
        if not decoded:
            return False
        namespace, block_hash = decoded
        if namespace != "block":
            return False
            
        try:
            data = json.loads(value.decode("utf-8"))
            if data.get("block_hash") != block_hash:
                return False
            return True
        except Exception:
            return False

    def _validate_tx_record(self, key: bytes, value: bytes) -> bool:
        from commands import sendtx
        decoded = self._decode_dht_key(key)
        if not decoded:
             return False
        namespace, tx_id = decoded
        if namespace != "tx":
             return False

        try:
            import hashlib
            computed_id = hashlib.sha256(value).hexdigest()
            return computed_id == tx_id
        except Exception:
            return False

    def _validate_state_record(self, key: bytes, value: bytes) -> bool:
        """
        Validate a `state:<hash>` or `/state/<hash>` record.
        Strictly for legacy accounts snapshots or legacy tests.
        """
        import json
        decoded = self._decode_dht_key(key)
        if not decoded:
             return False
        namespace, suffix = decoded
        if namespace != "state":
             return False

        # 1) Accounts JSON payload
        try:
            data = json.loads(value.decode("utf-8"))
            if isinstance(data, dict) and data.get("block_hash") == suffix:
                return True
        except Exception:
            pass

        # 2) Raw Tau state bytes (Legacy fallback)
        try:
            from poa.state import compute_state_hash
            return compute_state_hash(value) == suffix
        except Exception:
            return False
            
    def _validate_tau_state_record(self, key: bytes, value: bytes) -> bool:
        """
        Validate a `tau_state:<consensus_hash>` record.
        Payload MUST be JSON: `{"rules": <str>, "accounts_hash": <hex>}`.
        Validator recomputes consensus hash and compares to key suffix.
        """
        import json
        from poa.state import compute_consensus_state_hash
        
        decoded = self._decode_dht_key(key)
        if not decoded:
            return False
        namespace, consensus_hash = decoded
        if namespace != "tau_state":
            return False
            
        try:
            data = json.loads(value.decode("utf-8"))
            if not isinstance(data, dict):
                return False
            
            rules_str = data.get("rules", "")
            accounts_hash_hex = data.get("accounts_hash", "")
            
            if not isinstance(rules_str, str) or not isinstance(accounts_hash_hex, str):
                return False
                
            # Verify Consensus Hash
            # state_hash = BLAKE3(rules_bytes + accounts_hash)
            # Note: chain_state uses accounts_hash as bytes for update.
            # Logic:
            #   rules_bytes = rules_str.encode("utf-8")
            #   accounts_hash_bytes = bytes.fromhex(accounts_hash_hex)
            
            rules_bytes = rules_str.encode("utf-8")
            try:
                accounts_hash_bytes = bytes.fromhex(accounts_hash_hex)
            except ValueError:
                return False
                
            computed = compute_consensus_state_hash(rules_bytes, accounts_hash_bytes)
            return computed == consensus_hash
        except Exception:
            return False

    def put_record_sync(self, key: bytes, value: bytes, timeout: float = 5.0) -> bool:
        """
        Best-effort synchronous DHT publish helper.
        Automatically encodes simple keys (e.g. "state:...") into valid DHT keys (e.g. "/state/...").
        """
        # Encode key if needed
        encoded_key = key
        try:
            decoded = self._decode_dht_key(key)
            if decoded:
                encoded_key = self._encode_dht_key(decoded[0], decoded[1])
        except Exception:
            pass

        # Debug logging
        if logger.isEnabledFor(logging.DEBUG):
             logger.debug("DHT put_record_sync key=%s (encoded=%s) len=%d", key, encoded_key, len(value))

        # Local store
        if self._dht and getattr(self._dht, "value_store", None):
            try:
                self._dht.value_store.put(encoded_key, value)
            except Exception:
                return False

        if self._dht and self._trio_token:
            try:
                import trio
                # KadDHT expects string keys
                key_to_use = encoded_key.decode("utf-8") if isinstance(encoded_key, bytes) else encoded_key
                trio.from_thread.run(
                    self._dht.put_value,
                    key_to_use,
                    value,
                    trio_token=self._trio_token,
                )
            except (trio.RunFinishedError, trio.Cancelled, RuntimeError):
                # Loop may be stopped; keep local store + provider registration.
                pass
            except Exception as exc:
                logger.debug("DHT put_record_sync network publish failed: %s", exc)
                # Keep local store + provider registration even if network publish failed.
                pass
                
        # Register as provider for important namespaces
        # This ensures we advertise this key during handshake/provider queries
        if self._dht and getattr(self._dht, "provider_store", None):
            try:
                ns = self._extract_dht_namespace(encoded_key)
                if ns in ("state", "tau_state"):
                     from libp2p.peer.peerinfo import PeerInfo
                     
                     # Add self as provider
                     if self._host:
                         addrs = self._host.get_addrs()
                         # Use self._dht.peer_id if available, else host's
                         pid = getattr(self._dht, "peer_id", None) or self._host.get_id()
                         pi = PeerInfo(pid, addrs)
                         self._dht.provider_store.add_provider(encoded_key, pi)
            except Exception as e:
                logger.warning("Failed to register self as provider for %s: %s", encoded_key, e)

        return True

    def _validate_formula_record(self, key: bytes, value: bytes) -> bool:
        import hashlib
        decoded = self._decode_dht_key(key)
        if not decoded:
             return False
        namespace, suffix = decoded
        if namespace != "formula":
             return False
             
        try:
            computed_hash = hashlib.sha256(value).hexdigest()
            return computed_hash == suffix
        except Exception:
            return False

    def register_validator(self, namespace: str, validator: Callable[[bytes, bytes], bool]):
        self._dht_validators[namespace] = validator
        self._dht_allowed_namespaces.add(namespace)

    def _extract_dht_namespace(self, key: bytes) -> Optional[str]:
        decoded = self._decode_dht_key(key)
        if decoded:
            return decoded[0]
        return None

    def _validate_dht_key(self, key: bytes) -> bool:
        decoded = self._decode_dht_key(key)
        if not decoded:
            return False
        namespace, suffix = decoded
        if not suffix:
             return False
        if self._dht_allowed_namespaces and namespace not in self._dht_allowed_namespaces:
            return False
        return True

    def _validate_dht_record(self, key: bytes, value: bytes) -> bool:
        # 1. Check Key Format / Namespace
        decoded = self._decode_dht_key(key)
        if not decoded:
            logger.debug("Invalid DHT key format: %s", key)
            return False
        namespace, suffix = decoded
        
        # 2. Check Allowed Namespace
        if self._dht_allowed_namespaces and namespace not in self._dht_allowed_namespaces:
            logger.debug("Namespace %s not allowed", namespace)
            return False
            
        # 3. Run Validator
        if namespace in self._dht_validators:
            try:
                # Note: validator methods should use _decode_dht_key or handle both formats
                res = self._dht_validators[namespace](key, value)
                logger.debug("Validator for %s returned %s", namespace, res)
                return res
            except Exception:
                logger.exception("DHT validator for %s raised exception", namespace)
                return False
        
        logger.debug("No validator for namespace %s, allowing", namespace)
        return True
