import threading
import json
import logging
import os
from typing import Dict, List, Optional
import db
import tau_manager
import config
import tau_native
from consensus import TauConsensusEngine, TauStateSnapshot, compute_state_hash
from consensus.fees import FeeRuleError
from block import Block
import hashlib
from consensus.state import compute_state_hash as compute_rules_hash, compute_consensus_state_hash

def compute_accounts_hash(balances: Dict[str, int], sequences: Dict[str, int]) -> bytes:
    """
    Computes a canonical hash of the accounts state (balances + sequences).
    Normalizes keys so missing sequence/balance entries default to 0.
    """
    keys = set(balances.keys()) | set(sequences.keys())
    normalized_balances: Dict[str, int] = {}
    normalized_sequences: Dict[str, int] = {}
    for addr in keys:
        if not isinstance(addr, str):
            continue
        normalized_balances[addr] = int(balances.get(addr, 0))
        normalized_sequences[addr] = int(sequences.get(addr, 0))
    snapshot = {
        "balances": normalized_balances,
        "sequences": normalized_sequences,
    }
    canonical_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    json_bytes = canonical_json.encode("utf-8")
    digest = hashlib.sha256(json_bytes).digest()

    # Debug log to trace determinism issues
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "compute_accounts_hash: %s len=%s content=%s...",
            digest.hex(),
            len(json_bytes),
            canonical_json[:100],
        )

    return digest



logger = logging.getLogger(__name__)

# Lock for thread-safe reorg/fork-choice processing
_chain_lock = threading.RLock()

# Lock for thread-safe access to balances
_balance_lock = threading.Lock()

# In-memory balance table
# Maps full BLS public key hex strings to integer amounts
_balances = {}

from dataclasses import dataclass

@dataclass
class IngestResult:
    status: str
    message: str

@dataclass
class RebuildResult:
    """Outcome of a state-rebuild replay.

    `ok=False` means the replay aborted before reaching the requested head
    (state-hash invariant mismatch, header-verification failure, fee-rule
    failure, or an unexpected error). Callers MUST NOT advance the canonical
    head on a failed rebuild — the in-memory state is frozen at the last block
    replayed successfully, so advertising a further head would violate the
    "advertised head == applied-state head" invariant (Bug B / Phase 9A).
    """
    ok: bool
    stopped_at_block: Optional[int] = None
    computed_hash: str = ""
    stored_hash: str = ""
    reason: str = ""

# Lock for thread-safe access to sequence numbers
_sequence_lock = threading.Lock()

# In-memory sequence numbers table: maps address to sequence number
_sequence_numbers = {}

# Lock for thread-safe access to rules state
_rules_lock = threading.Lock()

# In-memory rules state storage
# In-memory rules state storage
_application_rules_state = ""
_consensus_rules_state = ""
_active_consensus_id = "tau_poa_v1"
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate, normalize_validator_set
_lifecycle_manager = ConsensusLifecycleManager()

_canonical_head_hash = ""
_tau_engine_state_hash = ""  # last known Tau engine snapshot hash (best-effort)

# DHT Client for storing formulas
_dht_client = None

def set_dht_client(client):
    """Sets the DHT client for storing formulas."""
    global _dht_client
    _dht_client = client
    # Hydrate DHT with currently loaded items so we can advertise them
    try:
        if _dht_client:
             _republish_state_to_dht()
        else:
             logger.warning("set_dht_client called with None client; skipping hydration")
    except Exception as e:
        logger.error("Failed to hydrate DHT with persisted state: %s", e)


def rehydrate_dht_state() -> bool:
    """
    Republish the currently loaded chain/tau snapshot into DHT.
    Returns True when the republish attempt completed without exceptions.
    """
    if not _dht_client:
        return False
    try:
        _republish_state_to_dht()
        return True
    except Exception as e:
        logger.error("rehydrate_dht_state failed: %s", e)
        return False


def _republish_state_to_dht():
    """
    Publishes the currently loaded state (rules and accounts) to the local DHT value store.
    """
    global _canonical_head_hash, _application_rules_state, _consensus_rules_state, _tau_engine_state_hash
    global _active_consensus_id
    
    if not _canonical_head_hash:
        return

    logger.info("Hydrating DHT with persisted state for block %s...", _canonical_head_hash)
    
    # 1. Publish Accounts
    publish_accounts_snapshot(_canonical_head_hash)
    
    # 2. Publish Tau State / Rules
    with _balance_lock, _sequence_lock, _rules_lock:
         acc_hash = compute_accounts_hash(_balances, _sequence_numbers)
         app_rules_bytes = (_application_rules_state or "").encode("utf-8")
         cons_rules_bytes = (_consensus_rules_state or "").encode("utf-8")
         meta_hash = _lifecycle_manager.consensus_meta_hash()
    
    state_hash = compute_consensus_state_hash(cons_rules_bytes, app_rules_bytes, acc_hash, meta_hash)
    
    if state_hash != _tau_engine_state_hash:
        logger.info("Updating stale _tau_engine_state_hash during hydration: %s -> %s", _tau_engine_state_hash, state_hash)
        _tau_engine_state_hash = state_hash

    if state_hash:
        publish_tau_state_snapshot(state_hash, cons_rules_bytes, app_rules_bytes, meta_hash, acc_hash)



def publish_tau_state_snapshot(state_hash: str, consensus_rules: bytes, application_rules: bytes, meta_hash: bytes, accounts_hash: bytes) -> bool:
    """
    Publish the serialized Tau/rules snapshot into the DHT under `tau_state:<hash>`.
    Payload is JSON: `{"consensus_rules": <str>, "application_rules": <str>, "meta_hash": <hex>, "accounts_hash": <hex>}`.
    """
    if not state_hash or not isinstance(state_hash, str):
        return False
    if consensus_rules is None or application_rules is None:
        return False
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return False
        
    try:
        # Construct JSON payload
        payload = json.dumps({
            "consensus_rules": consensus_rules.decode("utf-8"),
            "application_rules": application_rules.decode("utf-8"),
            "meta_hash": meta_hash.hex(),
            "accounts_hash": accounts_hash.hex()
        }).encode("utf-8")
        
        key = f"tau_state:{state_hash}".encode("ascii")
    except Exception:
        return False

    try:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Publishing Tau state snapshot to DHT key=%s len=%s state_hash=%s",
                key,
                len(payload),
                state_hash,
            )

        # Prefer network replication if supported by the DHT manager wrapper.
        if hasattr(_dht_client, "put_record_sync"):
            return bool(_dht_client.put_record_sync(key, payload))

        # Fallback: local store only
        _dht_client.dht.value_store.put(key, payload)
        return True
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to publish tau state snapshot to DHT: {exc}")
        return False


def fetch_tau_state_snapshot(state_hash: str) -> Optional[tuple[str, str, str, str]]:
    """
    Fetch a serialized Tau rules snapshot from the DHT `tau_state:<hash>`.
    Returns (consensus_rules, application_rules, meta_hash_hex, accounts_hash_hex).
    """
    if not state_hash or not isinstance(state_hash, str):
        return None
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return None
    try:
        key = f"tau_state:{state_hash}".encode("ascii")
    except Exception:
        return None

    try:
        source = "unknown"
        if hasattr(_dht_client, "get_record_sync"):
            val_bytes = _dht_client.get_record_sync(key, timeout=2.0)
            source = "get_record_sync"
        else:
            val = _dht_client.dht.value_store.get(key)
            val_bytes = getattr(val, "value", val) if val else None
            source = "local_value_store"
            
        if val_bytes is None:
            return None
            
        # Parse JSON payload
        decoded = val_bytes.decode("utf-8")
        data = json.loads(decoded)
        if isinstance(data, dict):
            # Old un-split format cannot be revalidated against the consensus hash
            # (the producer no longer writes it), so reject rather than trust it.
            if "rules" in data:
                return None

            consensus_rules = data.get("consensus_rules")
            application_rules = data.get("application_rules")
            meta_hash = data.get("meta_hash")
            accounts_hash = data.get("accounts_hash")

            # Revalidate the fetched payload against the requested consensus hash.
            # Mirror the producer-side / DHT-admission recompute so a consumer never
            # trusts a tampered or mismatched snapshot retrieved from the network.
            if not isinstance(consensus_rules, str) or not isinstance(application_rules, str) \
               or not isinstance(meta_hash, str) or not isinstance(accounts_hash, str):
                return None
            try:
                accounts_hash_bytes = bytes.fromhex(accounts_hash)
                meta_hash_bytes = bytes.fromhex(meta_hash)
            except ValueError:
                return None
            if len(accounts_hash_bytes) != 32:
                return None
            computed_state_hash = compute_consensus_state_hash(
                consensus_rules.encode("utf-8"),
                application_rules.encode("utf-8"),
                accounts_hash_bytes,
                meta_hash_bytes,
            )
            if computed_state_hash != state_hash:
                logger.warning(
                    "Rejecting fetched tau_state snapshot: recomputed hash %s != requested %s",
                    computed_state_hash,
                    state_hash,
                )
                return None

            if logger.isEnabledFor(logging.DEBUG) and isinstance(consensus_rules, str):
                try:
                    logger.debug(
                        "Fetched Tau state snapshot source=%s len=%s has_newline=%s preview=%r",
                        source,
                        len(application_rules or ""),
                        "\n" in (application_rules or ""),
                        (application_rules or "")[:200],
                    )
                except Exception:
                    logger.debug("Fetched Tau state snapshot (debug logging failed)")
            return consensus_rules, application_rules, meta_hash, accounts_hash
        return None
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to fetch tau state snapshot from DHT: {exc}")
        return None


def publish_accounts_snapshot(block_hash: str) -> bool:
    """
    Publish the resulting account table (balances + sequence numbers) for a block
    into the DHT.

    Key:   state:<block_hash>
    Value: JSON bytes: {"block_hash": "<block_hash>", "accounts": {addr: {"balance": int, "sequence": int}}}
    """
    if not block_hash or not isinstance(block_hash, str):
        return False
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return False

    with _balance_lock, _sequence_lock:
        keys = set(_balances.keys()) | set(_sequence_numbers.keys())
        accounts = {
            addr: {
                "balance": int(_balances.get(addr, 0)),
                "sequence": int(_sequence_numbers.get(addr, 0)),
            }
            for addr in keys
            if isinstance(addr, str)
        }
    payload = json.dumps(
        {"block_hash": block_hash, "accounts": accounts},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    try:
        key = f"{config.STATE_LOCATOR_NAMESPACE}:{block_hash}".encode("ascii")
    except Exception:
        return False

    try:
        if logger.isEnabledFor(logging.DEBUG):
             try:
                 # Avoid logging full payload for large state
                 data_obj = json.loads(payload.decode("utf-8"))
                 accs = data_obj.get("accounts", {})
                 acc_count = len(accs)
                 # Sample first 10
                 sample = dict(list(accs.items())[:10])
                 logger.debug(
                     "Publishing accounts snapshot key=%s block=%s count=%d sample=%s...",
                     key, block_hash, acc_count, sample
                 )
             except Exception:
                 logger.debug(
                     "Publishing accounts snapshot key=%s block=%s len=%d",
                     key, block_hash, len(payload)
                 )

        if hasattr(_dht_client, "put_record_sync"):
            return bool(_dht_client.put_record_sync(key, payload))
        _dht_client.dht.value_store.put(key, payload)
        return True
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to publish accounts snapshot to DHT: {exc}")
        return False


def fetch_accounts_snapshot(block_hash: str) -> Optional[tuple[Dict[str, int], Dict[str, int]]]:
    """
    Fetch the account table snapshot (balances + sequences) for a block from DHT.
    """
    if not block_hash or not isinstance(block_hash, str):
        return None
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return None

    try:
        key = f"{config.STATE_LOCATOR_NAMESPACE}:{block_hash}".encode("ascii")
    except Exception:
        return None

    try:
        if hasattr(_dht_client, "get_record_sync"):
            val_bytes = _dht_client.get_record_sync(key, timeout=2.0)
        else:
            val = _dht_client.dht.value_store.get(key)
            val_bytes = getattr(val, "value", val) if val else None
        if not val_bytes:
            return None
        if not isinstance(val_bytes, (bytes, bytearray)):
            val_bytes = bytes(val_bytes)
        data = json.loads(val_bytes.decode("utf-8"))
        if not isinstance(data, dict):
            return None
        accounts = data.get("accounts")
        if not isinstance(accounts, dict):
            return None
        balances: Dict[str, int] = {}
        sequences: Dict[str, int] = {}
        for addr, row in accounts.items():
            if not isinstance(addr, str):
                continue
            if isinstance(row, dict):
                try:
                    balances[addr] = int(row.get("balance", 0))
                except Exception:
                    balances[addr] = 0
                try:
                    sequences[addr] = int(row.get("sequence", 0))
                except Exception:
                    sequences[addr] = 0
            else:
                # Back-compat: allow {addr: balance} only
                try:
                    balances[addr] = int(row)
                except Exception:
                    balances[addr] = 0
                sequences[addr] = 0
        return balances, sequences
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to fetch accounts snapshot from DHT: {exc}")
        return None

# Genesis address and balance used across tests and reconstruction
GENESIS_ADDRESS = "a1fe40d5e4f155a1af7cb5804ec1ecba9ee3fb1f594e8a7b398b7ed69a6b0ccfd5bb6fd6d8ff965f8e1eb98d5abe7d2b"
GENESIS_BALANCE = 10000

# Pre-funded accounts from the loaded genesis artifact; used to seed rebuilds
# so a full replay reproduces exactly the load_genesis starting state.
_genesis_accounts_state: dict = {}
# Genesis consensus baseline (validator set + quorum policy), captured at
# load_genesis and re-seeded on every full rebuild so a synced/reorged node
# does not end up with an empty validator set.
_genesis_active_validators: list = []
_genesis_vote_quorum: str = ""
_genesis_eligibility_mode: str = ""
# Genesis rule text, re-seeded on full rebuild so the replayed state hash
# matches the mined chain (the reorg path replays only the new suffix, not
# the genesis block, so its rules would otherwise be lost).
_genesis_application_rules: str = ""
_genesis_consensus_rules: str = ""


def _validate_block_timestamp(block: Block, parent_block_data: Optional[Dict]) -> tuple[bool, str]:
    import time
    import config
    
    current_time = int(time.time())
    max_allowed_timestamp = current_time + config.MAX_BLOCK_FUTURE_DRIFT_SECONDS
    
    if block.header.timestamp > max_allowed_timestamp:
        return False, f"Block timestamp {block.header.timestamp} is too far in the future (max allowed {max_allowed_timestamp})"
        
    if block.header.block_number > 0:
        parent_timestamp = int(parent_block_data['header']['timestamp']) if parent_block_data else 0
        if block.header.timestamp < parent_timestamp:
            return False, f"Block timestamp {block.header.timestamp} is less than parent block timestamp {parent_timestamp}"
            
    return True, ""


def process_new_block(block: Block) -> bool:
    """
    Standard network/import block ingestion path.
    Enforces strict derivation, verification, and pure simulation before persistence.
    """
    global _lifecycle_manager, _application_rules_state, _consensus_rules_state, _tau_engine_state_hash, _canonical_head_hash, _active_consensus_id
    from errors import TauTestnetError, BlockchainBug
    import db
    
    try:
        current_head = db.get_canonical_head()
        current_head_hash = current_head.get('block_hash') if current_head else ''
        
        # Fast path: cleanly extends the canonical chain
        if block.header.previous_hash == current_head_hash or current_head_hash == '':
            parent_block_data = db.get_block_by_hash(current_head_hash) if current_head_hash else None
            from consensus.state import TauStateSnapshot, compute_consensus_state_hash
            engine = TauConsensusEngine()
            
            # 1. Load Canonical Parent Snapshot natively
            app_rules = (_application_rules_state or "").encode('utf-8')
            cons_rules = (_consensus_rules_state or "").encode('utf-8')
            acc_hash = compute_accounts_hash(_balances, _sequence_numbers)
            meta_hash = _lifecycle_manager.consensus_meta_hash()
            state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)
            
            parent_snapshot = TauStateSnapshot(
                state_hash=state_hash,
                tau_bytes=app_rules,
                metadata={
                    "source": "chain_state",
                    "balances": _balances,
                    "sequence_numbers": _sequence_numbers,
                    "lifecycle_manager": _lifecycle_manager,
                    "active_consensus_id": _active_consensus_id,
                    "consensus_rules_state": _consensus_rules_state,
                }
            )

            # 2. Derive Active consensus / execute with compatibility for tests that
            # still monkeypatch the legacy engine surface.
            active_view = None
            if hasattr(engine, "derive_active_consensus"):
                active_view = engine.derive_active_consensus(parent_snapshot, block.header.block_number)

            proof_ok = getattr(block, "verify_consensus_proof", lambda: True)()
            try:
                if active_view is not None:
                    verify_ok = engine.verify_block_header(active_view, block, {"proof_ok": proof_ok})
                else:
                    verify_ok = engine.verify_block_header(block)
            except TypeError:
                verify_ok = engine.verify_block_header(block)

            if not verify_ok:
                logger.error(f"[BLOCKCHAIN] Block #{block.header.block_number} failed network verification.")
                return False

            valid_ts, ts_reason = _validate_block_timestamp(block, parent_block_data)
            if not valid_ts:
                logger.error(f"[BLOCKCHAIN] Block #{block.header.block_number} timestamp invalid: {ts_reason}")
                return False

            # Fee model: fees are emitted by the consensus rules on Tau
            # stream o9 — unknowable without Tau. Defer (retry/resync
            # later) rather than validate user_tx blocks on guessed fees.
            has_user_tx = any(
                isinstance(tx, dict) and tx.get("tx_type", "user_tx") == "user_tx"
                for tx in (block.transactions or [])
            )
            if has_user_tx and not tau_manager.tau_ready.wait(timeout=5):
                logger.error(
                    "[BLOCKCHAIN] Tau unavailable; deferring block #%s (cannot evaluate fees for user transactions).",
                    block.header.block_number,
                )
                return False

            # 4. Pure Apply Block Executor
            if active_view is not None and hasattr(engine, "apply_block"):
                try:
                    apply_result = engine.apply_block(active_view, block, parent_snapshot)
                except FeeRuleError as exc:
                    # Voted consensus rules emitted an invalid fee (o9).
                    # Strict: reject/defer rather than guess.
                    logger.error(
                        "[BLOCKCHAIN] Fee rule failure applying block #%s: %s",
                        block.header.block_number, exc,
                    )
                    return False
                except ValueError as exc:
                    # e.g. a governance activation that would empty the validator set:
                    # reject the block instead of crashing ingestion.
                    logger.error(
                        "[BLOCKCHAIN] Governance activation failed for block #%s: %s",
                        block.header.block_number, exc,
                    )
                    return False
                next_snapshot = apply_result.next_snapshot
            else:
                temp_balances = dict(_balances)
                temp_sequences = dict(_sequence_numbers)
                exec_result = engine.apply(
                    parent_snapshot,
                    block.transactions,
                    block.header.timestamp,
                    target_balances=temp_balances,
                    target_sequences=temp_sequences,
                )
                next_app_rules = exec_result.snapshot.tau_bytes.decode('utf-8', errors='ignore')
                next_cons_rules = _consensus_rules_state
                next_acc_hash = compute_accounts_hash(temp_balances, temp_sequences)
                next_meta_hash = _lifecycle_manager.consensus_meta_hash()
                next_state_hash = block.header.state_hash or compute_consensus_state_hash(
                    next_cons_rules.encode('utf-8'),
                    next_app_rules.encode('utf-8'),
                    next_acc_hash,
                    next_meta_hash,
                )
                next_snapshot = TauStateSnapshot(
                    state_hash=next_state_hash,
                    tau_bytes=exec_result.snapshot.tau_bytes,
                    metadata={
                        "balances": temp_balances,
                        "sequence_numbers": temp_sequences,
                        "lifecycle_manager": _lifecycle_manager,
                        "consensus_rules_state": next_cons_rules,
                    },
                )
            
            # 5. Invariant Checks
            # Fast path ensures the block is valid, but the generated state hash MUST match exactly.
            if getattr(block.header, 'state_hash', "") and next_snapshot.state_hash != block.header.state_hash:
                 logger.error(f"[BLOCKCHAIN] State hash mismatch for extending block #{block.header.block_number}")
                 return False
                 
            # 6. Atomically persist block + returned post state
            db.add_block(block)
            
            with _balance_lock, _sequence_lock, _rules_lock:
                _balances.clear()
                _balances.update(next_snapshot.metadata["balances"])
                _sequence_numbers.clear()
                _sequence_numbers.update(next_snapshot.metadata["sequence_numbers"])
                
                _lifecycle_manager = next_snapshot.metadata["lifecycle_manager"]
                
                new_app_rules = next_snapshot.tau_bytes.decode('utf-8', errors='ignore')
                if new_app_rules != _application_rules_state:
                    # We already hold _rules_lock here, so avoid re-entering it
                    # via save_application_rules_state().
                    _application_rules_state = new_app_rules
                    
                _consensus_rules_state = next_snapshot.metadata["consensus_rules_state"]
                
                # Fetch active_consensus_id if it's updated in the consensus component natively
                if "active_consensus_id" in next_snapshot.metadata:
                    _active_consensus_id = next_snapshot.metadata["active_consensus_id"]
                
                _tau_engine_state_hash = next_snapshot.state_hash
                _canonical_head_hash = block.block_hash
                
            db.save_canonical_state_atomically(
                head_hash=_canonical_head_hash,
                head_num=block.header.block_number,
                balances=_balances,
                sequences=_sequence_numbers,
                application_rules=_application_rules_state,
                consensus_rules=_consensus_rules_state,
                active_consensus_id=_active_consensus_id,
                pending_updates=_persistable_update_payloads(_lifecycle_manager),
                votes=[{"update_id": uid.hex() if isinstance(uid, bytes) else uid, "voter_pubkey": p.hex() if isinstance(p, bytes) else p} for uid, ps in _lifecycle_manager.votes.items() for p in ps],
                scheduled=[(h, uid.hex() if isinstance(uid, bytes) else uid) for h, uid in _lifecycle_manager.scheduled_updates],
                archival=[uid.hex() if isinstance(uid, bytes) else uid for uid in _lifecycle_manager.archival_updates],
                active_validators=sorted(normalize_validator_set(_lifecycle_manager.active_validators)),
                # Persist the governance-mutable consensus params on the block-apply
                # path too (not just commit_state_to_db); otherwise an activated
                # quorum_policy / eligibility_mode change is lost on restart.
                quorum_policy=_lifecycle_manager.quorum_policy,
                eligibility_mode=_lifecycle_manager.eligibility_mode,
            )
            
            # Optional: mempool eviction triggers could be mapped here using `apply_result.mempool_hints`
            return True
        else:
            # Reorg or Orphan Path (delegates to legacy ingest and rebuild)
            res = ingest_block(block)
            if res.status == "added":
                maybe_update_canonical_head()
                return True
            return False

    except Exception as e:
        if isinstance(e, TauTestnetError):
            raise
        logger.error(f"[BLOCKCHAIN_BUG] Unhandled exception in process_new_block: {e}", exc_info=True)
        raise BlockchainBug(f"Unhandled exception in process_new_block: {e}") from e

def _rebuild_state_from_blockchain_internal(start_block=0, path_hashes=None):
    """
    Rebuilds or updates the chain state by replaying transactions from the database.
    If start_block is 0, it clears existing state.
    """
    
    
    print(f"[INFO][chain_state] Starting blockchain state reconstruction from block {start_block}...")
    global _canonical_head_hash, _tau_engine_state_hash, _application_rules_state, _consensus_rules_state
    global _active_consensus_id, _lifecycle_manager
    
    if start_block == 0:
        # Clear current state for a full rebuild
        with _balance_lock, _sequence_lock, _rules_lock:
            _balances.clear()
            _sequence_numbers.clear()
            # Re-seed genesis rule text (the reorg path replays only the new
            # suffix, not the genesis block, so these would otherwise be lost
            # and the replayed state hash would diverge from the mined chain).
            _application_rules_state = _genesis_application_rules
            _consensus_rules_state = _genesis_consensus_rules
            _active_consensus_id = "tau_poa_v1"
            # Re-seed the genesis validator set + quorum policy so a rebuilt
            # node verifies blocks against the correct PoA set (governance
            # updates in replayed blocks mutate from this baseline).
            _lifecycle_manager = ConsensusLifecycleManager(
                active_validators=list(_genesis_active_validators)
            )
            _lifecycle_manager.quorum_policy = _genesis_vote_quorum
            _lifecycle_manager.eligibility_mode = _genesis_eligibility_mode
            _lifecycle_manager.recompute_approval_threshold()
            _tau_engine_state_hash = ""
            _canonical_head_hash = ''
        print("[INFO][chain_state] Cleared existing in-memory state for full rebuild.")

        # Reset the live Tau interpreter to the genesis consensus spec before
        # replay. `engine.apply_block` routes activation revisions through `i0`
        # against the live interpreter, so replaying activated blocks against
        # an arbitrary current spec would stack revisions and produce a
        # divergent post-state. Reorgs always reach this branch via
        # `reorg_to -> _rebuild_state_from_blockchain_internal(0, ...)`.
        if tau_manager.tau_ready.is_set():
            try:
                with open(config.TAU_PROGRAM_FILE, "r", encoding="utf-8", errors="replace") as f:
                    genesis_spec_text = f.read()
                tau_manager.restore_full_tau_spec(genesis_spec_text)
                # `genesis.tau` is the application program only (o0..); it does
                # NOT define the consensus streams o6/o7. Replay the genesis-
                # derived restore plan (consensus rules first, then application
                # units + builtin rules) so the replay interpreter matches a
                # freshly-started node. Without this, `verify_block_header`'s
                # `o6 = i10` query hits an undefined o6 -> 0 and every synced
                # block is rejected ("Block #N rejected by Tau rules (o6: 0)").
                # `_consensus_rules_state` / `_application_rules_state` were just
                # re-seeded to their genesis values above, so use_persisted_state
                # here yields exactly the genesis baseline (block-derived rule
                # updates are re-applied by the per-block replay that follows).
                replay_tau_restore_plan(
                    get_tau_restore_plan(use_persisted_state=True),
                    source_prefix="rebuild",
                )
                print(f"[INFO][chain_state] Reset live Tau interpreter to {config.TAU_PROGRAM_FILE} + genesis consensus/builtin rules for replay.")
            except Exception:
                logger.exception("Failed to reset Tau interpreter before rebuild; replay activation determinism is not guaranteed.")

        # Initialize genesis state from the loaded genesis artifact so rebuild
        # matches load_genesis exactly (multi-account aware). Fallbacks: read
        # data/genesis.json directly, else the legacy hardcoded seed (tests).
        seed_accounts = dict(_genesis_accounts_state)
        if not seed_accounts:
            genesis_path = os.path.join(os.path.dirname(__file__), "data", "genesis.json")
            try:
                with open(genesis_path, "r", encoding="utf-8") as f:
                    seed_accounts = {
                        k: int(v) for k, v in json.load(f).get("accounts_state", {}).items()
                    }
            except Exception:
                seed_accounts = {}
        with _balance_lock, _sequence_lock:
            if seed_accounts:
                _balances.update(seed_accounts)
                for addr in seed_accounts:
                    _sequence_numbers.setdefault(addr, 0)
                print(f"[INFO][chain_state] Initialized {len(seed_accounts)} genesis account(s) from artifact.")
            else:
                _balances[GENESIS_ADDRESS] = GENESIS_BALANCE
                print(f"[INFO][chain_state] Initialized genesis balance: {GENESIS_ADDRESS[:10]}... = {GENESIS_BALANCE}")

    import db
    if path_hashes is not None:
        block_rows = [db.get_block_by_hash(h) for h in path_hashes]
        block_rows = [b for b in block_rows if b is not None]
    else:
        # Get all blocks from database, ordered by block number
        block_rows = db.get_canonical_blocks_at_or_after_height(start_block)
    
    if not block_rows:
        print(f"[INFO][chain_state] No new blocks found since block {start_block -1}. State is up to date.")
        return RebuildResult(ok=True)

    print(f"[INFO][chain_state] Found {len(block_rows)} blocks to replay.")

    total_transactions_processed = 0
    last_block_number = start_block - 1
    
    # Process each block in chronological order
    # Process each block in chronological order
    for block_idx, block_data in enumerate(block_rows):
        try:
            # block_data is already a dict from db.get_canonical_blocks_at_or_after_height
            block_number = block_data['header']['block_number']
            block_hash = block_data['block_hash'][:16] + "..."
            transactions = block_data.get('transactions', [])
            
            print(f"[INFO][chain_state] Processing block #{block_number} ({block_hash}) with {len(block_data.get('transactions', []))} transactions")
            
            block = Block.from_dict(block_data)
            engine = TauConsensusEngine()
            
            # 1. Load Parent Snapshot
            app_rules = (_application_rules_state or "").encode('utf-8')
            cons_rules = (_consensus_rules_state or "").encode('utf-8')
            acc_hash = compute_accounts_hash(_balances, _sequence_numbers)
            meta_hash = _lifecycle_manager.consensus_meta_hash()
            state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)
            
            # Build input parent_snapshot natively utilizing runtime state
            parent_snapshot = TauStateSnapshot(
                state_hash=state_hash,
                tau_bytes=app_rules,
                metadata={
                    "source": "chain_state",
                    "balances": _balances,
                    "sequence_numbers": _sequence_numbers,
                    "lifecycle_manager": _lifecycle_manager,
                    "active_consensus_id": _active_consensus_id,
                    "consensus_rules_state": _consensus_rules_state,
                }
            )

            # 2. Derive Active Consensus
            active_view = engine.derive_active_consensus(parent_snapshot, block_number)
            
            # 3. Verify Block Header
            # We must not bypass verification during rebuild.
            # Passing proof_ok bypasses independent cryptography re-checks here because db integrity guarantees it,
            # but consensus verdicts on Tau rules (o6) will run.
            if tau_manager.tau_ready.is_set():
                if not engine.verify_block_header(active_view, block, {"proof_ok": True}):
                    print(f"[ERROR][chain_state] Block #{block_number} verification failed. Aborting rebuild!")
                    return RebuildResult(ok=False, stopped_at_block=block_number,
                                         reason="header verification failed")
            else:
                print(f"[WARN][chain_state] Tau unavailable during rebuild; skipping header verification for block #{block_number}.")
            
            # 4. Execute Core Block Application Natively
            try:
                apply_result = engine.apply_block(active_view, block, parent_snapshot, replay_mode=True)
            except FeeRuleError as e:
                print(f"[ERROR][chain_state] Fee rule failure replaying block #{block_number}: {e}")
                return RebuildResult(ok=False, stopped_at_block=block_number,
                                     reason=f"fee rule failure: {e}")
            next_snapshot = apply_result.next_snapshot
            
            # 5. Execute Required Invariant Replay Checks (comparing state hashes)
            # Block 0 is exempt by design, not to paper over a hash mismatch:
            # genesis accounts/rules are seeded axiomatically above (and in
            # load_genesis), but block 0 carries an empty tx list, so its state
            # is not reconstructible by replaying its own contents. The genesis
            # meta-hash recipe is unified with the runtime (gen_genesis.py and
            # ConsensusLifecycleManager.consensus_meta_hash both use
            # host_contract={} + the pinned vote_quorum), so the parent snapshot
            # built at line ~761 already matches block 0's embedded state_hash;
            # this guard simply skips re-deriving it from the empty block body.
            if block_number != 0 and getattr(block.header, 'state_hash', "") not in ("", "0"*64) and next_snapshot.state_hash != block.header.state_hash:
                 # Legacy blocks generated prior to Phase 2 might lack this.
                 print(f"[ERROR][chain_state] Block #{block_number} state_hash invariant mismatch!")
                 print(f"  Computed: {next_snapshot.state_hash}\n  Block: {block.header.state_hash}")
                 return RebuildResult(ok=False, stopped_at_block=block_number,
                                      computed_hash=next_snapshot.state_hash,
                                      stored_hash=block.header.state_hash,
                                      reason="state_hash invariant mismatch")
                 
            # 6. Atomically Replace In-Memory State
            with _balance_lock, _sequence_lock, _rules_lock:
                _balances.clear()
                _balances.update(next_snapshot.metadata["balances"])
                _sequence_numbers.clear()
                _sequence_numbers.update(next_snapshot.metadata["sequence_numbers"])
                
                _lifecycle_manager = next_snapshot.metadata["lifecycle_manager"]
                
                new_app_rules = next_snapshot.tau_bytes.decode('utf-8', errors='ignore')
                if new_app_rules != _application_rules_state:
                    _application_rules_state = new_app_rules
                    
                _consensus_rules_state = next_snapshot.metadata["consensus_rules_state"]
                _tau_engine_state_hash = next_snapshot.state_hash
            
            total_transactions_processed += len(apply_result.accepted_tx_ids)
            
            # Log results
            if apply_result.invalid_tx_ids:
                print(f"[WARN][chain_state]   {len(apply_result.invalid_tx_ids)} transactions logically invalid in block #{block_number}")
            
            print(f"[DEBUG][chain_state]   Processed {len(apply_result.accepted_tx_ids)} accepted transactions")
            last_block_number = block_number

        except json.JSONDecodeError as e:
            print(f"[ERROR][chain_state] Failed to parse block #{block_idx}: {e}")
            _bn = (block_data.get('header') or {}).get('block_number') if isinstance(block_data, dict) else None
            return RebuildResult(ok=False, stopped_at_block=_bn, reason=f"json decode error: {e}")
        except KeyError as e:
            print(f"[ERROR][chain_state] Missing required field in block #{block_idx}: {e}")
            _bn = (block_data.get('header') or {}).get('block_number') if isinstance(block_data, dict) else None
            return RebuildResult(ok=False, stopped_at_block=_bn, reason=f"missing field: {e}")
        except Exception as e:
            print(f"[ERROR][chain_state] Unexpected error processing block #{block_idx}: {e}")
            _bn = (block_data.get('header') or {}).get('block_number') if isinstance(block_data, dict) else None
            return RebuildResult(ok=False, stopped_at_block=_bn, reason=f"unexpected error: {e}")

        # Update the last processed block hash after successfully processing a block
        _canonical_head_hash = block_data['block_hash']
    
    # Print final state summary
    print(f"[INFO][chain_state] Blockchain state reconstruction completed!")
    print(f"[INFO][chain_state] - Processed {len(block_rows)} blocks")
    print(f"[INFO][chain_state] - Processed {total_transactions_processed} transactions")
    
    with _balance_lock:
        non_zero_balances = {addr: bal for addr, bal in _balances.items() if bal > 0}
        print(f"[INFO][chain_state] - Final state: {len(non_zero_balances)} accounts with non-zero balances")
        for addr, balance in non_zero_balances.items():
            print(f"[INFO][chain_state]   {addr[:10]}... = {balance}")
    
    with _sequence_lock:
        active_sequences = {addr: seq for addr, seq in _sequence_numbers.items() if seq > 0}
        print(f"[INFO][chain_state] - Final state: {len(active_sequences)} accounts with sequence numbers")
        for addr, seq in active_sequences.items():
            print(f"[INFO][chain_state]   {addr[:10]}... seq = {seq}")

    return RebuildResult(ok=True, stopped_at_block=last_block_number)

def rebuild_state_from_blockchain(start_block=0) -> RebuildResult:
    return _rebuild_state_from_blockchain_internal(start_block)

def _hex_bytes(h: str) -> bytes:
    return bytes.fromhex(h)

def load_genesis(genesis_json_path: str):
    import json
    import os
    import db
    import block as block_module
    
    if not os.path.exists(genesis_json_path):
        raise FileNotFoundError(f"Missing genesis artifact: {genesis_json_path}")
        
    with open(genesis_json_path, "r", encoding="utf-8") as f:
        genesis_data = json.load(f)

    # Remember the artifact's pre-funded accounts for rebuild/reorg seeding,
    # regardless of whether the DB is fresh or already provisioned.
    global _genesis_accounts_state, _genesis_active_validators, _genesis_vote_quorum
    global _genesis_eligibility_mode
    global _genesis_application_rules, _genesis_consensus_rules
    _genesis_accounts_state = {
        k: int(v) for k, v in genesis_data.get("accounts_state", {}).items()
    }
    _gmeta = genesis_data.get("consensus_meta", {}) or {}
    _genesis_active_validators = list(_gmeta.get("active_validators", []) or [])
    _genesis_vote_quorum = (_gmeta.get("mechanism_specific_metadata", {}) or {}).get("vote_quorum", "")
    _genesis_eligibility_mode = (_gmeta.get("mechanism_specific_metadata", {}) or {}).get("eligibility_mode", "")
    _genesis_application_rules = genesis_data.get("application_rules", "")
    _genesis_consensus_rules = genesis_data.get("consensus_rules", "")

    db.init_db()

    # 1. Evaluate if empty
    latest = db.get_canonical_head_block()
    
    if not latest:
        print("[INFO][chain_state] No persistent state found, provisioning Genesis Block 0.")
        block_0_payload = genesis_data["block_0"]
        genesis_block = block_module.Block.from_dict(block_0_payload)
        db.add_block(genesis_block)
        
        # Load memory state
        with _balance_lock, _sequence_lock, _rules_lock:
            _balances.clear()
            _balances.update(genesis_data["accounts_state"])
            _sequence_numbers.clear()
            for addr in _balances.keys():
                _sequence_numbers[addr] = 0
                
            global _application_rules_state, _consensus_rules_state, _active_consensus_id, _tau_engine_state_hash, _canonical_head_hash
            _application_rules_state = genesis_data["application_rules"]
            _consensus_rules_state = genesis_data["consensus_rules"]
            _active_consensus_id = ""
            _canonical_head_hash = genesis_block.block_hash
            _tau_engine_state_hash = genesis_block.header.state_hash
            
            # Setup genesis consensus meta
            global _lifecycle_manager
            meta = genesis_data["consensus_meta"]
            _lifecycle_manager = ConsensusLifecycleManager(
                pending_updates=[],
                scheduled_updates=[],
                archival_updates=[],
                votes={}
            )
            _lifecycle_manager.active_validators = normalize_validator_set(meta["active_validators"])
            # Genesis may pin the quorum policy network-wide; overrides the local config knob.
            _lifecycle_manager.quorum_policy = meta.get("mechanism_specific_metadata", {}).get("vote_quorum", "")
            _lifecycle_manager.eligibility_mode = meta.get("mechanism_specific_metadata", {}).get("eligibility_mode", "")
            _lifecycle_manager.recompute_approval_threshold()

        commit_state_to_db(genesis_block.block_hash, 0)
        print(f"[INFO][chain_state] Genesis provisioned. Block 0 Hash: {genesis_block.block_hash}")
        return

    # 2. Existing chain logic: Validate Genesis hash matches
    db_genesis_hash = db.get_genesis_hash()
    if not db_genesis_hash:
        raise ValueError("FATAL: Database initialized but Genesis Block 0 is missing!")

    expected_genesis_hash = genesis_data["block_0"]["hash"]
    db_genesis = db.get_block_by_hash(db_genesis_hash)
    if db_genesis_hash != expected_genesis_hash:
        header_derived_hash = ""
        try:
            expected_block = block_module.Block.from_dict(genesis_data["block_0"])
            header_derived_hash = block_module.sha256_hex(expected_block.header.canonical_bytes())
        except Exception:
            header_derived_hash = ""

        expected_header = genesis_data["block_0"].get("header", {})
        actual_header = (db_genesis or {}).get("header", {})
        headers_match = all(actual_header.get(key) == val for key, val in expected_header.items())

        if headers_match and db_genesis_hash in {"GENESIS", header_derived_hash} and db_genesis:
            if db.normalize_genesis_hash(db_genesis_hash, expected_genesis_hash, db_genesis):
                db_genesis_hash = expected_genesis_hash
                db_genesis = db.get_block_by_hash(db_genesis_hash)

    if db_genesis_hash != expected_genesis_hash:
        raise ValueError(f"FATAL: Database initialized but Genesis Block 0 mismatched! Expected: {expected_genesis_hash}, Found: {db_genesis_hash}")

    if not db_genesis:
        raise ValueError("FATAL: Database corrupted! Genesis hash found but block body missing.")

    # Validate header fields match exactly
    for key, expected_val in genesis_data["block_0"]["header"].items():
        actual_val = db_genesis.get("header", {}).get(key)
        if actual_val != expected_val:
            raise ValueError(f"FATAL: Genesis Block 0 header field '{key}' mismatched! Expected: {expected_val}, Found: {actual_val}")
    loaded = load_state_from_db()
    if loaded:
        if not _lifecycle_manager.active_validators:
            meta = genesis_data["consensus_meta"]
            _lifecycle_manager.active_validators = normalize_validator_set(meta.get("active_validators", []))
            # Genesis may pin the quorum policy network-wide; overrides the local config knob.
            _lifecycle_manager.quorum_policy = meta.get("mechanism_specific_metadata", {}).get("vote_quorum", "")
            _lifecycle_manager.eligibility_mode = meta.get("mechanism_specific_metadata", {}).get("eligibility_mode", "")
            _lifecycle_manager.recompute_approval_threshold()
            commit_state_to_db(_canonical_head_hash, latest["header"]["block_number"] if latest else 0)
        print(f"[INFO][chain_state] State loaded successfully. Last known block hash: '{_canonical_head_hash[:16]}...'")
    else:
        print("[WARN][chain_state] DB has blocks but no canonical state! Rebuilding.")
        rebuild = rebuild_state_from_blockchain(start_block=0)
        latest = db.get_canonical_head_block()
        if rebuild.ok and latest:
            commit_state_to_db(latest["block_hash"], latest["block_number"])
        elif not rebuild.ok:
            # Preserve "advertised head == applied-state head": commit only the
            # head we actually replayed (_canonical_head_hash), never the DB tip.
            good = db.get_block_by_hash(_canonical_head_hash) if _canonical_head_hash else None
            good_num = good['header']['block_number'] if good else 0
            logger.error(
                "[chain_state] Startup rebuild aborted at block #%s (reason=%s); "
                "committing last-good head %s... (num %s) instead of DB tip.",
                rebuild.stopped_at_block, rebuild.reason,
                (_canonical_head_hash or '')[:16], good_num,
            )
            if _canonical_head_hash:
                commit_state_to_db(_canonical_head_hash, good_num)
        
def get_balance(address_hex: str) -> int:
    """Returns the balance of the given address. Returns 0 if address not found."""
    with _balance_lock:
        if address_hex not in _balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
            return int(getattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000))
        return _balances.get(address_hex, 0)

def get_committed_balance(address: str) -> int:
    """Raw committed balance lookup (no auto-faucet shim). Used for advisory
    eligibility dry-runs; consensus verification reads parent-snapshot balances
    instead."""
    with _balance_lock:
        return int(_balances.get(address, 0))

def update_balances_after_transfer(from_address_hex: str, to_address_hex: str, amount: int) -> bool:
    """
    Updates balances for a transfer. Assumes validation (including sufficient funds)
    has already occurred.
    Returns True if update was successful, False otherwise (e.g., an unexpected issue).
    """
    if amount <= 0:
        print(f"[WARN][chain_state] Attempted to update balance with non-positive amount: {amount}")
        return False # Should have been caught by Tau

    with _balance_lock:
        current_from_balance = _balances.get(from_address_hex, 0)

        if from_address_hex not in _balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
            current_from_balance = int(getattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000))

        # Enforce sufficient funds during balance updates to avoid negative balances
        if current_from_balance < amount:
            print(f"[ERROR][chain_state] Insufficient funds for {from_address_hex[:10]}... to send {amount}. Has: {current_from_balance}.")
            return False

        current_to_balance = _balances.get(to_address_hex, 0)
        
        _balances[from_address_hex] = current_from_balance - amount
        _balances[to_address_hex] = current_to_balance + amount
        
        print(f"[INFO][chain_state] Balances updated: {from_address_hex[:10]}... now {_balances[from_address_hex]}, {to_address_hex[:10]}... now {_balances[to_address_hex]}")
        return True


from contextlib import contextmanager

@contextmanager
def get_all_state_locks():
    """
    Context manager to acquire all state locks (balances, sequences, rules)
    to ensure a consistent global snapshot.
    """
    with _balance_lock:
        with _sequence_lock:
            with _rules_lock:
                yield

def get_sequence_number(address_hex: str) -> int:
    """Returns the current sequence number for the given address (defaults to 0)."""
    with _sequence_lock:
        return _sequence_numbers.get(address_hex, 0)

def increment_sequence_number(address_hex: str):
    """Increments the sequence number for the given address."""
    with _sequence_lock:
        _sequence_numbers[address_hex] = _sequence_numbers.get(address_hex, 0) + 1


def fetch_formula_from_dht(formula_hash: str) -> Optional[str]:
    """
    Retrieves a formula from the DHT using its hash.
    Returns the formula content as a string if found, None otherwise.
    """
    if not _dht_client or not _dht_client.dht:
        print("[WARN][chain_state] DHT client not available for formula retrieval")
        return None
        
    try:
        key = f"formula:{formula_hash}".encode('ascii')
        # We use get_value which should return the value if found
        # Note: libp2p KadDHT.get_value returns the value bytes
        # It's an async method usually, but here we might be in sync context?
        # Wait, chain_state is mostly sync.
        # If KadDHT methods are async, we might have a problem calling them from sync code.
        # But save_rules_state called value_store.put which is sync (in-memory store).
        # However, real DHT operations are async.
        # For now, let's assume we are accessing the local value store or we need to bridge to async.
        # But wait, save_rules_state used `_dht_client.dht.value_store.put`. That is the LOCAL storage.
        # If we want to retrieve from the network, we need `dht.get_value(key)`.
        # That is definitely async.
        # But maybe for this task, we just want to verify we can retrieve what we stored?
        # If we stored it in local value_store, we can retrieve it from local value_store.
        
        if hasattr(_dht_client, "get_record_sync"):
            val_bytes = _dht_client.get_record_sync(key)
            if val_bytes:
                return val_bytes.decode('utf-8')
            else:
                print(f"[DEBUG][chain_state] Formula {formula_hash} not found in DHT (local or network)")
                return None
        
        # Fallback for old clients (local check only)
        val = _dht_client.dht.value_store.get(key)
        if val:
            return val.decode('utf-8')
        else:
            print(f"[DEBUG][chain_state] Formula {formula_hash} not found in local DHT store")
            return None
            
    except Exception as e:
        print(f"[ERROR][chain_state] Failed to fetch formula from DHT: {e}")
        return None
        

def _normalize_spec_fragment(spec_text: str) -> str:
    text = (spec_text or "").strip()
    if text and not text.endswith("."):
        text += "."
    return text

def _preprocess_tau_spec_text(spec_text: str) -> str:
    return tau_native.TauInterface.preprocess_spec_text(spec_text or "")


def _load_tau_bootstrap_spec() -> str:
    try:
        with open(config.TAU_PROGRAM_FILE, "r", encoding="utf-8", errors="replace") as f:
            return _preprocess_tau_spec_text(f.read())
    except Exception:
        logger.exception("Failed to load Tau bootstrap program from %s", config.TAU_PROGRAM_FILE)
        return ""


def get_tau_restore_state() -> str:
    """
    Returns a Tau-native restoreable spec. The application rules natively encode the
    entire spec (due to u state retention). No concatenation needed.
    """
    with _rules_lock:
        app = (_application_rules_state or "").strip()
        cons = (_consensus_rules_state or "").strip()

    return app if app else cons


def get_rules_state() -> str:
    """
    Returns a Tau-native restoreable spec. The application rules natively encode the
    entire spec (due to u state retention). No concatenation needed.
    """
    with _rules_lock:
        app = (_application_rules_state or "").strip()
        cons = (_consensus_rules_state or "").strip()

    return app if app else cons


def get_persisted_full_tau_spec() -> str:
    try:
        return db.get_chain_state_value("full_tau_spec", "")
    except Exception:
        logger.exception("Failed to load persisted full Tau spec from DB")
        return ""


def get_tau_restore_plan(use_persisted_state: bool = True) -> List[Dict[str, object]]:
    """
    Returns an ordered replay plan for i0 updates after the native interpreter has been
    initialized with `config.TAU_PROGRAM_FILE` (normally `genesis.tau`).
    """
    if use_persisted_state:
        with _rules_lock:
            consensus_snapshot = _consensus_rules_state or ""
            application_snapshot = _application_rules_state or ""
    else:
        genesis_path = os.path.join(os.path.dirname(__file__), "data", "genesis.json")
        try:
            with open(genesis_path, "r", encoding="utf-8") as f:
                genesis_data = json.load(f)
        except Exception:
            logger.exception("Failed to load genesis data from %s", genesis_path)
            return []
        consensus_snapshot = genesis_data.get("consensus_rules", "")
        application_snapshot = ""

    normalized_consensus = _preprocess_tau_spec_text(consensus_snapshot)
    # The application snapshot is now a canonical raw accumulation of newline-
    # separated rule units. Replay them ONE-BY-ONE in order (preserves u-state
    # override/retraction semantics; the interpreter re-shrinks each on the way in).
    application_units = [
        u for u in (application_snapshot or "").split("\n") if u.strip()
    ]
    application_unit_set = set(application_units)

    plan: List[Dict[str, object]] = []
    if normalized_consensus:
        plan.append({
            "label": "consensus_rules",
            "text": normalized_consensus,
            "persist": False,
        })
    for u_idx, unit in enumerate(application_units, start=1):
        plan.append({
            "label": f"application_rule_{u_idx}",
            "text": unit,
            "persist": False,
        })

    for idx, rule_text in enumerate(load_builtin_rules_from_disk(), start=1):
        normalized_rule = _preprocess_tau_spec_text(rule_text)
        if not normalized_rule:
            continue
        # Exact-unit dedup (NOT substring) against the application accumulation.
        if normalized_rule in application_unit_set:
            continue
        plan.append({
            "label": f"builtin_rule_{idx}",
            "text": normalized_rule,
            "persist": True,
        })

    return plan


def replay_tau_restore_plan(plan: List[Dict[str, object]], *, source_prefix: str = "restore") -> bool:
    """Replay an ordered i0 restore plan into the live Tau interpreter.

    Shared by the startup bootstrap callback and the rebuild-from-genesis path
    so both reconstruct an IDENTICAL interpreter (consensus rules o6/o7 +
    application rules + builtin rules) and identical in-memory rule state. The
    rebuild path previously reset the interpreter to the application-only
    program file (`genesis.tau`) and skipped this replay, leaving o6/o7
    undefined -- so verifying a synced block's validity (`o6 = i10`) always
    returned 0 and aborted the rebuild. Returns True if any replayed unit was
    persistence-bearing (caller decides whether to commit).
    """
    if not plan:
        return False
    persist_needed = False
    for idx, entry in enumerate(plan, start=1):
        rule_text = str(entry.get("text") or "")
        label = str(entry.get("label") or f"rule_{idx}")
        should_persist = bool(entry.get("persist"))
        tau_manager.communicate_with_tau(
            rule_text=rule_text,
            target_output_stream_index=0,
            source=f"{source_prefix}:{label}",
            apply_rules_update=should_persist,
            wait_for_ready=False,
        )
        persist_needed = persist_needed or should_persist
    return persist_needed


def get_application_rules_state() -> str:
    with _rules_lock:
        return _application_rules_state

def get_consensus_rules_state() -> str:
    with _rules_lock:
        return _consensus_rules_state

def save_application_rules_state(rules_content: str):
    global _application_rules_state
    with _rules_lock:
        _application_rules_state = rules_content or ""


def _persistable_update_payloads(lm) -> list:
    """Payload rows for `consensus_updates_v2`: PENDING *and* SCHEDULED updates
    (Phase 9C / Finding 2).

    Previously only PENDING updates' payloads were persisted. A node restarting
    in the window between an update being approved-and-scheduled and its
    activation height reloaded the scheduled (height, uid) entry but NOT the
    payload, so `process_height_transitions` at H found `uid not in
    update_payloads` and silently skipped applying the revision/patch -> fork
    from peers. Persisting scheduled payloads here is node-local durability: the
    pending vs scheduled *status* is tracked separately (the pending set and the
    scheduled list), so this does NOT change `consensus_meta_hash`.
    """
    uids = set(lm.pending_updates) | {uid for _, uid in lm.scheduled_updates}
    rows = []
    for uid in uids:
        u = lm.update_payloads.get(uid)
        if u is None:
            continue
        rows.append({
            "update_id": uid.hex() if isinstance(uid, bytes) else uid,
            "rule_revisions": u.rule_revisions,
            "activate_at_height": u.activate_at_height,
            "host_contract_patch": u.host_contract_patch,
            "proposer_pubkey": u.proposer_pubkey,
        })
    return rows

def save_effective_tau_spec(canonical_rule_text: str):
    """
    Append ONE canonical (full-width, pre-shrink) application rule to the raw
    application-rules accumulation. The accumulation -- not the interpreter's
    composed (and possibly shrunk) spec -- is the authoritative, hashed
    application-rules state, mirroring how consensus rules use
    `"\\n".join(rule_revisions)`. Because it is canonical full-width text, the
    consensus state hash is independent of the node-local shrink width.
    """
    global _application_rules_state
    unit = _preprocess_tau_spec_text(canonical_rule_text)
    if not unit:
        return
    with _rules_lock:
        units = [u for u in (_application_rules_state or "").split("\n") if u.strip()]
        if unit not in units:  # idempotent: dedup exact units (re-apply / replay)
            units.append(unit)
        _application_rules_state = "\n".join(units)
        snapshot = _application_rules_state
    try:
        db.set_chain_state_value("full_tau_spec", snapshot)
    except Exception:
        logger.exception("Failed to persist application-rules accumulation")
        
def save_consensus_rules_state(rules_content: str):
    global _consensus_rules_state
    with _rules_lock:
        _consensus_rules_state = rules_content or ""

def load_state_from_db() -> bool:
    """
    Loads chain state from the database into the in-memory caches.
    Returns True if accounts were found in the database, False if no state exists.
    """
    import db
    
    balances, sequences, app_rules, cons_rules, cons_id, last_processed_block_hash, pending_updates, votes, scheduled, archival = db.load_chain_state()
    
    def _update_id_bytes(value):
        if isinstance(value, bytes):
            return value
        return bytes.fromhex(value)

    votes_map = {}
    for v in votes:
        votes_map.setdefault(_update_id_bytes(v['update_id']), []).append(v['voter_pubkey'])
    
    if not balances and not last_processed_block_hash:
        return False
        
    with _balance_lock, _sequence_lock, _rules_lock:
        _balances.clear()
        _sequence_numbers.clear()
        _balances.update(balances)
        _sequence_numbers.update(sequences)
        
        global _application_rules_state, _consensus_rules_state, _active_consensus_id, _lifecycle_manager
        
        _application_rules_state = app_rules
        _consensus_rules_state = cons_rules
        _active_consensus_id = cons_id
        active_validators = []
        raw_active_validators = db.get_chain_state_value("active_validators", "")
        if raw_active_validators:
            try:
                loaded_active_validators = json.loads(raw_active_validators)
                if isinstance(loaded_active_validators, list):
                    active_validators = loaded_active_validators
            except json.JSONDecodeError:
                logger.warning("Ignoring malformed active_validators chain_state entry.")

        scheduled_updates = [(height, _update_id_bytes(uid)) for height, uid in scheduled]
        archival_updates = [_update_id_bytes(uid) for uid in archival]
        # `consensus_updates_v2` now stores payloads for pending AND scheduled
        # updates (Phase 9C). The PENDING *set* must exclude scheduled uids —
        # they are tracked in `scheduled_updates` and counting them as pending
        # too would corrupt `consensus_meta_hash` and re-run scheduling logic.
        _scheduled_uid_set = {uid for _, uid in scheduled_updates}
        pending_update_ids = [
            uid for uid in (_update_id_bytes(p['update_id']) for p in pending_updates)
            if uid not in _scheduled_uid_set
        ]

        _lifecycle_manager = ConsensusLifecycleManager(
            pending_updates=pending_update_ids,
            scheduled_updates=scheduled_updates,
            archival_updates=archival_updates,
            votes=votes_map,
            active_validators=active_validators
        )
        # Restore the quorum policy from the persisted canonical state so a node
        # reloading from disk reproduces the same threshold as a freshly-rebuilt
        # or freshly-synced peer — including a policy changed by an activated
        # governance patch. Legacy DBs written before quorum was persisted have
        # no 'quorum_policy' row; fall back to the genesis value (such a DB
        # cannot contain an activated quorum change, so genesis is correct). A
        # sentinel default distinguishes "row absent" from a persisted "".
        _MISSING = "\x00missing"
        persisted_quorum = db.get_chain_state_value("quorum_policy", _MISSING)
        _lifecycle_manager.quorum_policy = (
            _genesis_vote_quorum if persisted_quorum == _MISSING else persisted_quorum
        )
        persisted_mode = db.get_chain_state_value("eligibility_mode", _MISSING)
        _lifecycle_manager.eligibility_mode = (
            _genesis_eligibility_mode if persisted_mode == _MISSING else persisted_mode
        )
        _lifecycle_manager.recompute_approval_threshold()
        for p in pending_updates:
            update = ConsensusRuleUpdate(
                rule_revisions=p['rule_revisions'],
                activate_at_height=p['activate_at_height'],
                host_contract_patch=p.get('host_contract_patch'),
                proposer_pubkey=p.get('proposer_pubkey')
            )
            _lifecycle_manager.update_payloads[_update_id_bytes(p['update_id'])] = update

        global _tau_engine_state_hash
        _tau_engine_state_hash = ""
        
        global _canonical_head_hash
        _canonical_head_hash = last_processed_block_hash
        
    return True

def commit_state_to_db(block_hash: str, block_number: int):
    """
    Commits the in-memory state (balances, sequence numbers, rules, proposals, votes) to the database atomically,
    associating it with the provided block_hash.
    """
    # Snapshot state under locks
    with _balance_lock, _sequence_lock, _rules_lock:
        balances_snapshot = _balances.copy()
        sequences_snapshot = _sequence_numbers.copy()
        app_rules_snapshot = _application_rules_state
        cons_rules_snapshot = _consensus_rules_state
        cons_id_snapshot = _active_consensus_id
        pending_updates_list = _persistable_update_payloads(_lifecycle_manager)
        votes_list = [{"update_id": k.hex() if isinstance(k, bytes) else k, "voter_pubkey": pub.hex() if isinstance(pub, bytes) else pub} for k, v in _lifecycle_manager.votes.items() for pub in v]
        scheduled_list = [(h, uid.hex() if isinstance(uid, bytes) else uid) for h, uid in _lifecycle_manager.scheduled_updates]
        archival_list = [uid.hex() if isinstance(uid, bytes) else uid for uid in _lifecycle_manager.archival_updates]
        active_validators_list = sorted(normalize_validator_set(_lifecycle_manager.active_validators))
        quorum_policy_snapshot = _lifecycle_manager.quorum_policy
        eligibility_mode_snapshot = _lifecycle_manager.eligibility_mode

    db.save_canonical_state_atomically(
        block_hash, block_number,
        balances_snapshot, sequences_snapshot,
        app_rules_snapshot, cons_rules_snapshot, cons_id_snapshot,
        pending_updates_list, votes_list, scheduled_list, archival_list,
        active_validators=active_validators_list,
        quorum_policy=quorum_policy_snapshot,
        eligibility_mode=eligibility_mode_snapshot,
    )

def tick_governance(height: int):
    """
    Called when a block is accepted at the given height. Let the ConsensusLifecycleManager
    execute precise transitions, and if any updates activate, apply them here.

    Production block application drives activation through `engine.apply_block`;
    this helper exists to support tests and out-of-band lifecycle ticks. Both
    paths must agree, so we route revisions through `i0` here as well.
    """
    global _active_consensus_id, _consensus_rules_state

    # Snapshot the activated set without holding _rules_lock across the Tau
    # call: the lock is non-reentrant, and even with apply_rules_update=False
    # we don't want to block readers of `_consensus_rules_state` /
    # `_application_rules_state` for the duration of pointwise revision.
    with _rules_lock:
        newly_active = _lifecycle_manager.process_height_transitions(height)

    if not newly_active:
        return

    # Route every activated revision through `i0` in declaration order. The
    # genesis routing emits `Updated specification:` and tau_native rebuilds
    # the interpreter, so the live spec advances exactly like user_tx ops['0']
    # application-rule changes.
    #
    # Activation revisions intentionally do NOT trigger the rules-handler
    # (`apply_rules_update=False`): consensus provenance is updated via the
    # deterministic `"\n".join(rule_revisions)` tag written into
    # `_consensus_rules_state` below, not via the live spec extracted from
    # stdout. Letting the handler fire would briefly write a partially-
    # stripped intermediate into `_application_rules_state` and persist a
    # polluted `full_tau_spec` to the DB.
    import tau_manager
    for update in newly_active:
        logger.info("Governance activated consensus update: %s", update.update_id_hex)
        tag = f"governance_activation:{update.update_id_hex[:16]}"
        for rev in update.rule_revisions:
            if not isinstance(rev, str) or not rev.strip():
                continue
            tau_manager.communicate_with_tau(
                rule_text=rev,
                target_output_stream_index=0,
                source=tag,
                apply_rules_update=False,
            )

    last_update = newly_active[-1]
    with _rules_lock:
        # Provenance tag of the most recently activated revisions, used for
        # state hashing. Live spec lives in the Tau interpreter; the
        # post-block snapshot commit will not overwrite this.
        _consensus_rules_state = "\n".join(last_update.rule_revisions)
        _active_consensus_id = last_update.update_id_hex[:16]


def initialize_persistent_state(genesis_json_path: str = "data/genesis.json"):
    """
    Initializes persistent chain state from the database and verifies it against the blockchain.
    On first startup (no state and no blocks), initializes genesis state from the genesis artifact.
    On mismatch between stored state and blockchain, rebuilds and commits state.
    """
    print("[DEBUG][chain_state] > initialize_persistent_state started")
    
    load_genesis(genesis_json_path)

    print("[DEBUG][chain_state] Verifying consistency between loaded state and blockchain head...")
    latest = db.get_canonical_head_block()
    latest_hash = latest['block_hash'] if latest else ''
    latest_num = latest['header']['block_number'] if latest else 0
    
    if _canonical_head_hash != latest_hash:
        print(f"[WARN][chain_state] State-DB mismatch! State hash: '{_canonical_head_hash[:16]}...', DB hash: '{latest_hash[:16]}...'.")
        print("[INFO][chain_state] Triggering full state rebuild due to mismatch.")
        rebuild = rebuild_state_from_blockchain(start_block=0)
        if rebuild.ok:
            print(f"[DEBUG][chain_state] Rebuild complete. Committing state with latest block hash: '{latest_hash[:16]}...'")
            commit_state_to_db(latest_hash, latest_num)
        else:
            # Do not advertise a head we never applied (Bug B). Commit the head
            # we actually replayed to keep advertised head == applied state.
            good = db.get_block_by_hash(_canonical_head_hash) if _canonical_head_hash else None
            good_num = good['header']['block_number'] if good else 0
            logger.error(
                "[chain_state] Startup rebuild aborted at block #%s (reason=%s); "
                "committing last-good head %s... (num %s) instead of DB tip %s....",
                rebuild.stopped_at_block, rebuild.reason,
                (_canonical_head_hash or '')[:16], good_num, (latest_hash or '')[:16],
            )
            if _canonical_head_hash:
                commit_state_to_db(_canonical_head_hash, good_num)
    else:
        print(f"[INFO][chain_state] Persistent state is consistent and up-to-date with the blockchain.")

    print("[DEBUG][chain_state] > initialize_persistent_state finished")


def load_builtin_rules_from_disk() -> list[str]:
    """
    Load built-in Tau rule statements from the local `rules/` directory.

    Each file is expected to contain one or more Tau rule statements. Lines starting with '#'
    are treated as comments and ignored.
    """
    import os

    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    if not os.path.isdir(rules_dir):
        return []

    rules: list[str] = []
    for fname in sorted(os.listdir(rules_dir)):
        path = os.path.join(rules_dir, fname)
        # Keep existing convention: only numeric-prefixed rule files are injected.
        if not (os.path.isfile(path) and fname and fname[0].isdigit()):
            continue
        with open(path, "r", encoding="utf-8") as f:
            # Read all lines, filter out comments, and join into a single Tau input.
            rule_text = " ".join([line.strip() for line in f if not line.strip().startswith("#")]).strip()
        if rule_text:
            rules.append(rule_text)
    return rules


def _is_reachable_from_genesis(b_hash: str) -> bool:
    import config, db
    try:
        path = db.get_chain_path(b_hash, db.get_genesis_hash())
        return True
    except ValueError:
        return False

def select_best_head(candidates: list[tuple[str, int]]) -> str | None:
    if not candidates:
        return None
        
    def score(cand):
        block_hash, height = cand
        return (-height, bytes.fromhex(block_hash))
        
    best = min(candidates, key=score)
    return best[0]

def ingest_block(block: Block) -> IngestResult:
    import db, config
    engine = TauConsensusEngine()
    # NOTE: legacy verify signature (no active_view): membership/stake gates and
    # the parent-state stake input do NOT run here. This pre-filter only checks
    # the Tau o6 verdict; canonical acceptance re-verifies with full parent
    # state via process_new_block / the rebuild path.
    if not engine.verify_block_header(block):
        return IngestResult('invalid', "Block verification failed")
    
    existing = db.get_block_by_hash(block.block_hash)
    if existing:
        return IngestResult('known', "Block already exists")
    
    # Enforce parent linkage rules for non-genesis
    parent = db.get_block_by_hash(block.header.previous_hash)
    
    valid_ts, ts_reason = _validate_block_timestamp(block, parent)
    if not valid_ts:
        return IngestResult('invalid', f"Timestamp validation failed: {ts_reason}")

    if parent:
        parent_num = int(parent['header'].get('block_number', -1))
        if block.header.block_number != parent_num + 1:
            return IngestResult('invalid', f"Block number {block.header.block_number} is not +1 of parent {parent_num}")
    elif block.header.previous_hash != db.get_genesis_hash() and block.block_hash != db.get_genesis_hash():
        # Parent missing, store as orphan
        db.add_block(block)
        return IngestResult('orphan', f"Block stored as orphan (missing parent {block.header.previous_hash})")
        
    db.add_block(block)
    return IngestResult('added', "Block ingested to DB")

def maybe_update_canonical_head() -> Optional[bool]:
    """Evaluate candidate heads and reorg to the best one if it beats the
    current canonical head.

    Returns reorg_to's verdict: True if the head advanced, False if a reorg was
    attempted but ABORTED by a rebuild failure (head unchanged — a later
    candidate evaluation may retry), or None if there was nothing to do.
    """
    import db
    candidates = db.get_candidate_heads()
    if not candidates:
        return None

    valid_cands = []
    for cand_hash, cand_height in candidates:
        if _is_reachable_from_genesis(cand_hash):
            valid_cands.append((cand_hash, cand_height))

    best_hash = select_best_head(valid_cands)
    if not best_hash:
        return None

    with _chain_lock:
        current_head = db.get_canonical_head()
        current_hash = current_head.get('block_hash') if current_head else ''
        if best_hash != current_hash:
            return reorg_to(best_hash)
    return None

def reorg_to(new_head_hash: str) -> Optional[bool]:
    """Reorg the canonical head to `new_head_hash`.

    Returns True if the head advanced (state rebuilt + committed), False if the
    reorg was ABORTED because the rebuild replay failed (canonical head left
    unchanged; in-memory state restored to the prior head), or None for a no-op
    (already at target, or the target path is unreachable).
    """
    import db, config

    current_head = db.get_canonical_head()
    old_head_hash = current_head.get('block_hash') if current_head else db.get_genesis_hash()

    if old_head_hash == new_head_hash:
        return None

    try:
        new_path = db.get_chain_path(new_head_hash, db.get_genesis_hash())
    except ValueError:
        return None

    old_path = []
    if old_head_hash != db.get_genesis_hash():
        try:
            old_path = db.get_chain_path(old_head_hash, db.get_genesis_hash())
        except ValueError:
            pass
            
    common_prefix_len = 0
    for n_h, o_h in zip(new_path, old_path):
        if n_h == o_h:
            common_prefix_len += 1
        else:
            break
            
    new_suffix = new_path[common_prefix_len:]
    old_suffix = old_path[common_prefix_len:]
    
    # Phase 2: Mempool Diffs
    old_txs = {}
    from block import compute_tx_hash
    for shash in old_suffix:
        b = db.get_block_by_hash(shash)
        if b:
            for tx in b.get('transactions', []):
                tx_id = compute_tx_hash(tx) if isinstance(tx, dict) else tx
                old_txs[tx_id] = tx
                
    new_txs = set()
    for shash in new_suffix:
        b = db.get_block_by_hash(shash)
        if b:
            for tx in b.get('transactions', []):
                tx_id = compute_tx_hash(tx) if isinstance(tx, dict) else tx
                new_txs.add(tx_id)
                
    # Phase 3: Apply State Rebuild
    db.reset_mempool_reservations()
    rebuild = _rebuild_state_from_blockchain_internal(0, path_hashes=new_path)

    # Phase 3b: Abort guard (Bug B). If the replay failed, the in-memory state
    # is frozen at the last block it replayed successfully — NOT at new_head.
    # Committing new_head here would advertise a head ahead of applied state
    # (the exact silent inconsistency that masked the mine-vs-replay
    # divergence). Instead: keep the DB canonical head where it was, restore
    # in-memory + live-interpreter state to the (known-good) prior head by
    # replaying it, and report failure. Mempool reservations were unreserved
    # above; they stay pending (no chain change), so no txs are lost.
    if rebuild is None or not rebuild.ok:
        stopped = getattr(rebuild, 'stopped_at_block', None)
        computed = getattr(rebuild, 'computed_hash', '') or ''
        stored = getattr(rebuild, 'stored_hash', '') or ''
        reason = getattr(rebuild, 'reason', 'unknown') if rebuild else 'no result'
        logger.error(
            "[chain_state] Reorg to %s... ABORTED: rebuild failed at block #%s "
            "(reason=%s, computed=%s..., stored=%s...). Canonical head NOT "
            "advanced; restoring prior head %s...",
            new_head_hash[:16], stopped, reason, computed[:16], stored[:16],
            (old_head_hash or '')[:16],
        )
        # Restore consistent state at the prior head. old_path==[] (prior head
        # was genesis) resets to the genesis baseline; a non-empty old_path
        # replays the known-good canonical chain.
        restore = _rebuild_state_from_blockchain_internal(0, path_hashes=old_path)
        if restore is None or not restore.ok:
            logger.error(
                "[chain_state] Reorg abort recovery FAILED to restore prior head "
                "%s... (reason=%s). In-memory state may be inconsistent.",
                (old_head_hash or '')[:16],
                getattr(restore, 'reason', 'no result') if restore else 'no result',
            )
        return False

    # Phase 4: Atomic Commit of Rebuilt State
    with _balance_lock, _sequence_lock, _rules_lock:
        b = dict(_balances)
        s = dict(_sequence_numbers)
        app_r = _application_rules_state
        cons_r = _consensus_rules_state
        cons_id = _active_consensus_id
        pending_updates_list = _persistable_update_payloads(_lifecycle_manager)
        votes_list = [{"update_id": k.hex() if isinstance(k, bytes) else k, "voter_pubkey": pub.hex() if isinstance(pub, bytes) else pub} for k, v in _lifecycle_manager.votes.items() for pub in v]
        scheduled_list = [(h, uid.hex() if isinstance(uid, bytes) else uid) for h, uid in _lifecycle_manager.scheduled_updates]
        archival_list = [uid.hex() if isinstance(uid, bytes) else uid for uid in _lifecycle_manager.archival_updates]
        active_validators_list = sorted(normalize_validator_set(_lifecycle_manager.active_validators))
        head_num = db.get_block_by_hash(new_head_hash)['header']['block_number']
        db.save_canonical_state_atomically(
            new_head_hash,
            head_num,
            b,
            s,
            app_r,
            cons_r,
            cons_id,
            pending_updates_list,
            votes_list,
            scheduled_list,
            archival_list,
            active_validators=active_validators_list,
            quorum_policy=_lifecycle_manager.quorum_policy,
            eligibility_mode=_lifecycle_manager.eligibility_mode,
        )
    
    # Phase 5: Mempool Restore
    if new_txs:
        db.remove_mempool_by_hashes(list(new_txs))
        
    import time, json
    for tx_id, tx in old_txs.items():
        if tx_id not in new_txs:
            try:
                db.add_mempool_tx(json.dumps(tx, separators=(",", ":")), tx_id, int(time.time() * 1000))
            except Exception as e:
                logger.error(f"[chain_state] Failed to restore tx {tx_id} to mempool: {e}")

    return True

