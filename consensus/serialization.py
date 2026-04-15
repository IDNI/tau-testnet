import json
from typing import Any, Dict, Optional

# --- Primitive Canonical Serialization ---

def encode_uint64(val: int) -> bytes:
    """Encode an unsigned 8-byte big-endian integer. Used for heights and timestamps."""
    if not isinstance(val, int) or val < 0 or val > 0xFFFFFFFFFFFFFFFF:
        raise ValueError(f"Value must be an unsigned 64-bit integer, got {val}")
    return val.to_bytes(8, byteorder="big", signed=False)

def encode_uint32(val: int) -> bytes:
    """Encode an unsigned 4-byte big-endian integer. Used for other protocol integers and string lengths."""
    if not isinstance(val, int) or val < 0 or val > 0xFFFFFFFF:
        raise ValueError(f"Value must be an unsigned 32-bit integer, got {val}")
    return val.to_bytes(4, byteorder="big", signed=False)

def encode_bool(val: bool) -> bytes:
    """Encode a boolean as a single byte: 0x01 for True, 0x00 for False."""
    if not isinstance(val, bool):
        raise ValueError(f"Value must be a boolean, got {val}")
    return b"\x01" if val else b"\x00"

def encode_string(val: str) -> bytes:
    """Encode a string as UTF-8 with a 4-byte big-endian length prefix."""
    if not isinstance(val, str):
        raise ValueError(f"Value must be a string, got {val}")
    encoded = val.encode("utf-8")
    return encode_uint32(len(encoded)) + encoded

def _coerce_fixed_bytes(val: Any, expected_len: int, label: str) -> bytes:
    if isinstance(val, (bytes, bytearray)):
        out = bytes(val)
    elif isinstance(val, str):
        try:
            out = bytes.fromhex(val)
        except ValueError as exc:
            raise ValueError(f"{label} must be valid hex") from exc
    else:
        raise ValueError(f"Value must be exactly {expected_len} bytes, got {type(val)}")
    if len(out) != expected_len:
        raise ValueError(f"Value must be exactly {expected_len} bytes, got {len(out)}")
    return out


def encode_hash32(val: bytes) -> bytes:
    """Encode a 32-byte fixed-width hash. Accepts raw bytes or a 64-char hex string."""
    return _coerce_fixed_bytes(val, 32, "hash32")

def encode_pubkey48(val: bytes) -> bytes:
    """Encode a 48-byte BLS12-381 public key. Accepts raw bytes or a 96-char hex string."""
    return _coerce_fixed_bytes(val, 48, "pubkey48")


# --- Canonical JSON ---

def canonical_json(data: Any) -> bytes:
    """
    Produce canonical JSON serialization (sorted keys, no whitespace separators).
    Used for claims_yid and other deterministic JSON requirements.
    """
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


# --- Tau Input Canonicalization ---

def canonicalize_proposer_yid(proposer_pubkey: str) -> str:
    """
    Validates and canonicalizes proposer_pubkey for Tau i8 (proposer_yid).
    Validates exactly 96 hex characters, no 0x prefix.
    Returns: lowercase hex string.
    """
    if not isinstance(proposer_pubkey, str):
        raise ValueError("proposer_pubkey must be a string")
    if proposer_pubkey.startswith("0x"):
        raise ValueError("proposer_pubkey must not have 0x prefix")
    if len(proposer_pubkey) != 96:
        raise ValueError(f"proposer_pubkey must be exactly 96 chars, got {len(proposer_pubkey)}")
    try:
        bytes.fromhex(proposer_pubkey)
    except ValueError:
        raise ValueError("proposer_pubkey contains non-hex characters")
    return proposer_pubkey.lower()

def canonicalize_parent_hash_yid(previous_hash: str) -> str:
    """
    Validates and canonicalizes previous_hash for Tau i9 (parent_hash_yid).
    Validates exactly 64 hex characters, no 0x prefix.
    Returns: lowercase hex string.
    """
    if not isinstance(previous_hash, str):
        raise ValueError("previous_hash must be a string")
    if previous_hash.startswith("0x"):
        raise ValueError("previous_hash must not have 0x prefix")
    if len(previous_hash) != 64:
        raise ValueError(f"previous_hash must be exactly 64 chars, got {len(previous_hash)}")
    try:
        bytes.fromhex(previous_hash)
    except ValueError:
        raise ValueError("previous_hash contains non-hex characters")
    return previous_hash.lower()


# --- Governance Object Serialization ---

from blake3 import blake3
from typing import List, Union

def encode_rule_revisions(revisions: List[str]) -> bytes:
    """
    Serialize multiple revisions as a length-prefixed concatenated sequence.
    revisions: list of exact UTF-8 source bytes (as python strings).
    """
    if not isinstance(revisions, list):
        raise ValueError("revisions must be a list of strings")
    out = bytearray()
    out.extend(encode_uint32(len(revisions))) # number of revisions
    for rev in revisions:
        out.extend(encode_string(rev))
    return bytes(out)

def encode_host_contract_patch(patch: Dict[str, Union[int, str, bool]]) -> bytes:
    """
    Serialize host_contract_patch.
    Fields are ordered by key bytes in ascending lexicographic order.
    """
    if not isinstance(patch, dict):
        raise ValueError("patch must be a dictionary")
    
    encoded_pairs = []
    for k, v in patch.items():
        k_bytes = encode_string(k)
        if isinstance(v, bool):
            # Must check bool before int because bool is a subclass of int in Python!
            v_bytes = b"\x01" + encode_bool(v) # Type tag 1 for bool
        elif isinstance(v, int):
            # Use uint32 for generic protocol integers in patch, unless it's a specific height/timestamp (which we might need uint64 for, 
            # but usually host_contract config are small ints). We will use an 8-byte int if it's explicitly typed, 
            # but to be deterministic, we'll assume uint64 for all ints in patches to avoid overflow issues, or standard uint32 
            # since the plan says "integers as big-endian fixed-width... other protocol integers as 4 bytes". 
            # Let's use 4 bytes (uint32) as specified for "other protocol integers".
            v_bytes = b"\x02" + encode_uint32(v) # Type tag 2 for uint32
        elif isinstance(v, str):
            v_bytes = b"\x03" + encode_string(v) # Type tag 3 for string
        else:
            raise ValueError(f"Unsupported property type for key {k}: {type(v)}")
        encoded_pairs.append((k, k_bytes, v_bytes))
    
    # Sort lexicographically by original key bytes
    encoded_pairs.sort(key=lambda pair: pair[0].encode("utf-8"))
    
    out = bytearray()
    out.extend(encode_uint32(len(encoded_pairs)))
    for k, k_bytes, v_bytes in encoded_pairs:
        out.extend(k_bytes)
        out.extend(v_bytes)
    return bytes(out)


def compute_update_id(revisions: List[str], activate_at_height: int, patch: Optional[Dict[str, Union[int, str, bool]]] = None) -> bytes:
    """
    Derives update_id as BLAKE3(canonical_serialization(consensus_rule_update_payload)).
    Exclude sender_pubkey, sequence_number, expiration_time, fee_limit, and signature.
    Returns 32-byte hash.
    """
    out = bytearray()
    out.extend(encode_rule_revisions(revisions))
    out.extend(encode_uint64(activate_at_height))
    out.extend(encode_bool(patch is not None))
    if patch is not None:
        out.extend(encode_host_contract_patch(patch))
    return blake3(bytes(out)).digest()


# --- Checkpoint Object Serialization ---

def compute_checkpoint_hash(height: int, consensus_rules: str, accounts_hash: bytes, pre_checkpoint_consensus_meta_hash: bytes) -> bytes:
    """
    checkpoint_hash = BLAKE3(height_bytes || consensus_rules_bytes || accounts_hash || pre_checkpoint_consensus_meta_hash)
    """
    if len(accounts_hash) != 32:
        raise ValueError("accounts_hash must be exactly 32 bytes")
    if len(pre_checkpoint_consensus_meta_hash) != 32:
        raise ValueError("pre_checkpoint_consensus_meta_hash must be exactly 32 bytes")
        
    out = bytearray()
    out.extend(encode_uint64(height))
    out.extend(encode_string(consensus_rules)) # The plan says "exact UTF-8 bytes", encode_string prepends length. Or did it say just the bytes?
    # "The exact UTF-8 bytes of consensus_rules at the checkpoint height."
    # If the plan means literal bytes without length prefix for checkpoint hashing, let's use exact encoding.
    # But usually it's length-prefixed. Wait, the plan specifically states:
    # `height_bytes || consensus_rules_bytes || accounts_hash || pre_checkpoint_consensus_meta_hash`
    # Let's provide length-prefixed string, since `consensus_rules` length is variable, to prevent ambiguity.
    out.extend(encode_string(consensus_rules))
    out.extend(accounts_hash)
    out.extend(pre_checkpoint_consensus_meta_hash)
    
    return blake3(bytes(out)).digest()

# --- Consensus Meta Serialization ---

def encode_vote_record(update_id: bytes, voter_pubkey: bytes) -> bytes:
    """Serialize a single vote record."""
    out = bytearray()
    out.extend(encode_hash32(update_id))
    out.extend(encode_pubkey48(voter_pubkey))
    return bytes(out)

def encode_activation_schedule_entry(activate_at_height: int, update_id: bytes) -> bytes:
    """Serialize a single activation schedule entry."""
    out = bytearray()
    out.extend(encode_uint64(activate_at_height))
    out.extend(encode_hash32(update_id))
    return bytes(out)

def encode_checkpoint_reference(height: int, checkpoint_hash: bytes) -> bytes:
    """Serialize a single checkpoint reference."""
    out = bytearray()
    out.extend(encode_uint64(height))
    out.extend(encode_hash32(checkpoint_hash))
    return bytes(out)

def encode_consensus_meta(
    host_contract: Dict[str, Union[int, str, bool]],
    active_validators: List[bytes],
    pending_updates: List[bytes],
    vote_records: List[tuple[bytes, bytes]], # (update_id, voter_pubkey)
    activation_schedule: List[tuple[int, bytes]], # (height, update_id)
    checkpoint_references: List[tuple[int, bytes]], # (height, checkpoint_hash)
    mechanism_specific_metadata: Optional[Dict[str, Union[int, str, bool]]] = None
) -> bytes:
    """
    Canonical serialization of the full consensus_meta object.
    Automatically sorts collections according to canonical rules.
    """
    out = bytearray()
    
    # 1. Host Contract
    out.extend(encode_host_contract_patch(host_contract))
    
    # 2. Active Validator Set (sorted by public key raw bytes)
    sorted_validators = sorted(active_validators)
    out.extend(encode_uint32(len(sorted_validators)))
    for val in sorted_validators:
        out.extend(encode_pubkey48(val))
        
    # 3. Pending Updates (sorted by update_id raw bytes)
    sorted_pending = sorted(pending_updates)
    out.extend(encode_uint32(len(sorted_pending)))
    for pid in sorted_pending:
        out.extend(encode_hash32(pid))
        
    # 4. Vote Records (sorted by update_id, then voter_pubkey)
    sorted_votes = sorted(vote_records, key=lambda x: (x[0], x[1]))
    out.extend(encode_uint32(len(sorted_votes)))
    for uid, vid in sorted_votes:
        out.extend(encode_vote_record(uid, vid))
        
    # 5. Activation Schedule (sorted by height, then update_id)
    sorted_schedule = sorted(activation_schedule, key=lambda x: (x[0], x[1]))
    out.extend(encode_uint32(len(sorted_schedule)))
    for h, uid in sorted_schedule:
        out.extend(encode_activation_schedule_entry(h, uid))
        
    # 6. Checkpoint References (sorted by height, then checkpoint_hash)
    sorted_checkpoints = sorted(checkpoint_references, key=lambda x: (x[0], x[1]))
    out.extend(encode_uint32(len(sorted_checkpoints)))
    for h, ch in sorted_checkpoints:
        out.extend(encode_checkpoint_reference(h, ch))
        
    # 7. Mechanism-Specific Metadata
    out.extend(encode_bool(mechanism_specific_metadata is not None))
    if mechanism_specific_metadata is not None:
        out.extend(encode_host_contract_patch(mechanism_specific_metadata)) # Use same encode schema as host contract map
        
    return bytes(out)

def compute_consensus_meta_hash(
    host_contract: Dict[str, Union[int, str, bool]],
    active_validators: List[bytes],
    pending_updates: List[bytes],
    vote_records: List[tuple[bytes, bytes]],
    activation_schedule: List[tuple[int, bytes]],
    checkpoint_references: List[tuple[int, bytes]],
    mechanism_specific_metadata: Optional[Dict[str, Union[int, str, bool]]] = None
) -> bytes:
    """Compute BLAKE3 hash of canonical consensus_meta."""
    meta_bytes = encode_consensus_meta(
        host_contract, active_validators, pending_updates, 
        vote_records, activation_schedule, checkpoint_references, 
        mechanism_specific_metadata
    )
    return blake3(meta_bytes).digest()
