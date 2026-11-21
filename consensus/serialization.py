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

VALIDATOR_DELTA_FIELDS = {"validator_additions", "validator_removals"}


def _encode_string_list(values: List[str], *, canonicalize: bool) -> bytes:
    if not isinstance(values, list):
        raise ValueError("list value must be a list")
    if not all(isinstance(item, str) for item in values):
        raise ValueError("list value must contain only strings")
    items = sorted(set(values)) if canonicalize else list(values)
    out = bytearray()
    out.extend(encode_uint32(len(items)))
    for item in items:
        out.extend(encode_string(item))
    return bytes(out)


def encode_host_contract_patch(patch: Dict[str, Union[int, str, bool, List[str]]]) -> bytes:
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
        elif isinstance(v, list):
            v_bytes = b"\x04" + _encode_string_list(v, canonicalize=k in VALIDATOR_DELTA_FIELDS)
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


def compute_update_id(revisions: List[str], activate_at_height: int, patch: Optional[Dict[str, Union[int, str, bool, List[str]]]] = None) -> bytes:
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
    host_contract: Dict[str, Union[int, str, bool, List[str]]],
    active_validators: List[bytes],
    pending_updates: List[bytes],
    vote_records: List[tuple[bytes, bytes]], # (update_id, voter_pubkey)
    activation_schedule: List[tuple[int, bytes]], # (height, update_id)
    checkpoint_references: List[tuple[int, bytes]], # (height, checkpoint_hash)
    mechanism_specific_metadata: Optional[Dict[str, Union[int, str, bool, List[str]]]] = None
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
    host_contract: Dict[str, Union[int, str, bool, List[str]]],
    active_validators: List[bytes],
    pending_updates: List[bytes],
    vote_records: List[tuple[bytes, bytes]],
    activation_schedule: List[tuple[int, bytes]],
    checkpoint_references: List[tuple[int, bytes]],
    mechanism_specific_metadata: Optional[Dict[str, Union[int, str, bool, List[str]]]] = None
) -> bytes:
    """Compute BLAKE3 hash of canonical consensus_meta."""
    meta_bytes = encode_consensus_meta(
        host_contract, active_validators, pending_updates, 
        vote_records, activation_schedule, checkpoint_references, 
        mechanism_specific_metadata
    )
    return blake3(meta_bytes).digest()


# --- Rule Sharing Object Serialization ---
#
# Canonical encodings for the rule-offer book and the accepted-clause registry.
# Both roots are folded into consensus_meta.mechanism_specific_metadata, so
# these functions are CONSENSUS-FROZEN: changing any of them changes the state
# hash of every chain that carries a rule offer.

def encode_rule_offer(
    offerer_pubkey: Union[bytes, str],
    recipient_pubkey: Union[bytes, str],
    rule_text: str,
    expire_at_height: int,
) -> bytes:
    """Canonical serialization of a rule offer's identifying content.

    Excludes sequence_number, expiration_time, fee_limit and signature, exactly
    as compute_update_id does for governance updates, so the id is a property
    of the offer rather than of the transaction that carried it.
    """
    out = bytearray()
    out.extend(encode_pubkey48(offerer_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_string(rule_text))
    out.extend(encode_uint64(expire_at_height))
    return bytes(out)


def compute_offer_id(
    offerer_pubkey: Union[bytes, str],
    recipient_pubkey: Union[bytes, str],
    rule_text: str,
    expire_at_height: int,
) -> bytes:
    """Derive offer_id as BLAKE3(encode_rule_offer(...)). Returns 32 bytes."""
    return blake3(
        encode_rule_offer(
            offerer_pubkey=offerer_pubkey,
            recipient_pubkey=recipient_pubkey,
            rule_text=rule_text,
            expire_at_height=expire_at_height,
        )
    ).digest()


def encode_rule_offer_entry(
    offer_id: Union[bytes, str],
    offerer_pubkey: Union[bytes, str],
    recipient_pubkey: Union[bytes, str],
    expire_at_height: int,
) -> bytes:
    """One outstanding-offer entry as bound into the state hash.

    Carries offerer/recipient/expiry even though offer_id already commits to
    them: it makes the bound book self-describing, so expiry and recipient
    authorization are decidable from hashed state alone rather than from a
    node-local payload store that may not have the row.
    """
    out = bytearray()
    out.extend(encode_hash32(offer_id))
    out.extend(encode_pubkey48(offerer_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_uint64(expire_at_height))
    return bytes(out)


def encode_rule_offer_book(
    offered: List[tuple],
    resolved: List[Union[bytes, str]],
) -> bytes:
    """Canonical serialization of the whole offer book.

    `offered` holds (offer_id, offerer, recipient, expire_at_height) tuples,
    sorted here by raw offer_id bytes. `resolved` holds bare offer ids: the
    terminal status is deliberately NOT hashed, because the observable effect
    of an acceptance is the clause registry and the application-rules state,
    both of which are already bound.
    """
    entries = sorted(
        (
            _coerce_fixed_bytes(offer_id, 32, "offer_id"),
            offerer,
            recipient,
            expire_at,
        )
        for offer_id, offerer, recipient, expire_at in offered
    )
    out = bytearray()
    out.extend(encode_uint32(len(entries)))
    for offer_id, offerer, recipient, expire_at in entries:
        out.extend(
            encode_rule_offer_entry(offer_id, offerer, recipient, expire_at)
        )

    resolved_ids = sorted(
        _coerce_fixed_bytes(item, 32, "offer_id") for item in resolved
    )
    out.extend(encode_uint32(len(resolved_ids)))
    for offer_id in resolved_ids:
        out.extend(encode_hash32(offer_id))
    return bytes(out)


def compute_rule_offer_book_root(
    offered: List[tuple],
    resolved: List[Union[bytes, str]],
) -> bytes:
    """BLAKE3 of the canonical offer book. Returns 32 bytes."""
    return blake3(encode_rule_offer_book(offered, resolved)).digest()


DOMAIN_POLICY_VERSIONS_V1 = b"tau.policy.versions.v1"


def compute_policy_versions_root(
    versions: List[tuple],
) -> bytes:
    """BLAKE3 of the per-policy version record. Returns 32 bytes.

    `versions` holds (sender_pubkey, target_stream, version) triples,
    sorted here by (sender, stream): the count of policy writes the
    rule-offers book has recorded for each account's policy. A policy
    that was never written has no entry (version 0 is the absence of a
    record, not a stored zero), so a chain that never touches policies
    hashes exactly as it did before this root existed.
    """
    entries = sorted(
        (str(sender), int(stream), int(version))
        for sender, stream, version in versions
    )
    out = bytearray()
    out.extend(encode_string(DOMAIN_POLICY_VERSIONS_V1.decode()))
    out.extend(encode_uint32(len(entries)))
    for sender, stream, version in entries:
        out.extend(encode_pubkey48(sender))
        out.extend(encode_uint32(stream))
        out.extend(encode_uint64(version))
    return blake3(bytes(out)).digest()


DOMAIN_CLAUSE_ENTRY_V1 = b"tau.clause.entry.v1"
DOMAIN_CLAUSE_ROOT_V1 = b"tau.clause.root.v1"

# Multiset hash: each entry becomes 1024 lanes of 16 bits, summed per lane
# modulo 2**16 and bound with the count, so one change is one vector update.
CLAUSE_LANES = 1024
CLAUSE_LANE_BITS = 16
CLAUSE_STATE_BYTES = CLAUSE_LANES * 4
CLAUSE_LANE_MASK = int.from_bytes(b"\xff\xff\x00\x00" * CLAUSE_LANES, "little")
# One bit above every lane, so a lane can be subtracted without borrowing.
CLAUSE_LANE_BIAS = int.from_bytes(b"\x00\x00\x01\x00" * CLAUSE_LANES, "little")


def encode_clause_entry(acceptor: Any, stream: int, body: str) -> bytes:
    """Canonical bytes of one registry entry."""
    return (
        DOMAIN_CLAUSE_ENTRY_V1
        + encode_pubkey48(acceptor)
        + encode_uint32(int(stream))
        + encode_string(body)
    )


def clause_entry_vector(acceptor: Any, stream: int, body: str) -> int:
    """The entry's lane vector as one little-endian integer."""
    digest = blake3(encode_clause_entry(acceptor, stream, body)).digest(
        length=CLAUSE_STATE_BYTES
    )
    return int.from_bytes(digest, "little") & CLAUSE_LANE_MASK


def clause_state_add(state: int, vector: int) -> int:
    return (state + vector) & CLAUSE_LANE_MASK


def clause_state_remove(state: int, vector: int) -> int:
    return (state + CLAUSE_LANE_BIAS - vector) & CLAUSE_LANE_MASK


def clause_root_from_state(count: int, state: int) -> bytes:
    """32-byte registry root from the entry count and the lane sum."""
    return blake3(
        DOMAIN_CLAUSE_ROOT_V1
        + encode_uint64(count)
        + state.to_bytes(CLAUSE_STATE_BYTES, "little")
    ).digest()


def compute_clause_registry_root(clauses: Dict[tuple, str]) -> bytes:
    """Root of a whole registry, computed by adding every entry."""
    state = 0
    for (acceptor, stream), body in clauses.items():
        state = clause_state_add(state, clause_entry_vector(acceptor, stream, body))
    return clause_root_from_state(len(clauses), state)


# --- Co-signature approval requests ------------------------------------------
#
# CONSENSUS-FROZEN. Every preimage here carries an explicit domain tag, so a
# request id can never collide with an offer id or an update id even if the
# remaining bytes happen to line up. Maps are serialized in ascending NUMERIC
# key order -- string order would put stream 10 before stream 9 and two nodes
# using different orders would compute different ids.

DOMAIN_APPROVAL_REQUEST_V1 = b"tau.approval.request.v1"
DOMAIN_APPROVAL_VOTE_V1 = b"tau.approval.vote.v1"


def _encode_index_map(mapping: Dict[Any, Any], value_encoder) -> bytes:
    """uint32 count, then (uint32 index, encoded value) in ascending index order."""
    items = sorted((int(k), v) for k, v in (mapping or {}).items())
    out = bytearray()
    out.extend(encode_uint32(len(items)))
    for idx, val in items:
        out.extend(encode_uint32(idx))
        out.extend(value_encoder(val))
    return bytes(out)


def encode_approval_request(
    *,
    sender_pubkey: Any,
    recipient_pubkey: Any,
    amount: int,
    sequence_number: int,
    expire_at_height: int,
    approvers: Dict[Any, Any],
    custom_inputs: Dict[Any, Any],
) -> bytes:
    """Canonical bytes a request id commits to.

    `sequence_number` is included so two otherwise identical transfers from the
    same sender get distinct ids instead of colliding on the second one.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_APPROVAL_REQUEST_V1.decode()))
    out.extend(encode_pubkey48(sender_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(sequence_number)))
    out.extend(encode_uint64(int(expire_at_height)))
    out.extend(_encode_index_map(approvers, encode_pubkey48))
    out.extend(_encode_index_map(custom_inputs, lambda v: encode_string(str(v))))
    return bytes(out)


def compute_request_id(**kwargs) -> bytes:
    """BLAKE3 of the canonical approval request. Returns 32 bytes."""
    return blake3(encode_approval_request(**kwargs)).digest()


def encode_approval_request_entry(
    request_id: Any,
    entry_sender: Any,
    entry_recipient: Any,
    amount: int,
    expire_at_height: int,
    approvers: Dict[Any, Any],
    custom_inputs: Dict[Any, Any],
    voted: Dict[Any, Any],
    declined: Any,
    status: int,
) -> bytes:
    """One open-or-resolved request, as the state root sees it.

    `voted` is in here because it is what decides whether the transfer executes:
    it must be hash-bound or a node could disagree about which approvers have
    signed. The vote `reason` is NOT here -- it is signed and inside the block
    merkle root via `block.compute_tx_hash`, but it carries no consensus meaning.
    """
    out = bytearray()
    out.extend(encode_hash32(request_id))
    out.extend(encode_pubkey48(entry_sender))
    out.extend(encode_pubkey48(entry_recipient))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(expire_at_height)))
    out.extend(_encode_index_map(approvers, encode_pubkey48))
    out.extend(_encode_index_map(custom_inputs, lambda v: encode_string(str(v))))
    out.extend(_encode_index_map(voted, encode_pubkey48))
    declined_sorted = sorted(int(d) for d in (declined or ()))
    out.extend(encode_uint32(len(declined_sorted)))
    for slot in declined_sorted:
        out.extend(encode_uint32(slot))
    out.extend(bytes([int(status) & 0xFF]))
    return bytes(out)


def encode_approval_request_book(open_entries: list, resolved: list) -> bytes:
    """Canonical serialization of the whole request book.

    Open entries sorted by raw request id; resolved contributes bare ids only,
    also sorted. Terminal status of a resolved request is deliberately absent:
    node-local, re-derivable by replay, and hashing it would make the root
    depend on colour rather than consensus meaning -- the same choice
    `encode_rule_offer_book` makes.
    """
    encoded_open = sorted(
        encode_approval_request_entry(*entry) for entry in (open_entries or [])
    )
    resolved_ids = sorted(
        _coerce_fixed_bytes(r, 32, "request_id") for r in (resolved or [])
    )
    out = bytearray()
    out.extend(encode_uint32(len(encoded_open)))
    for blob in encoded_open:
        out.extend(blob)
    out.extend(encode_uint32(len(resolved_ids)))
    for rid in resolved_ids:
        out.extend(encode_hash32(rid))
    return bytes(out)


def compute_approval_request_book_root(
    open_entries: list, resolved: list, rule_change_entries: Optional[list] = None
) -> bytes:
    """BLAKE3 of the canonical request book. Returns 32 bytes.

    Rule-change requests append a tagged section only when there is one, so a
    book without them keeps the root it always had.
    """
    book = encode_approval_request_book(open_entries, resolved)
    if rule_change_entries:
        book += encode_rule_change_book(rule_change_entries)
    return blake3(book).digest()


# --- Rule-change requests ----------------------------------------------------

DOMAIN_RULE_CHANGE_REQUEST_V1 = b"tau.rule_change.request.v1"
DOMAIN_RULE_CHANGE_ENTRY_V1 = b"tau.rule_change.entry.v1"
DOMAIN_RULE_CHANGE_BOOK_V1 = b"tau.rule_change.book.v1"


def compute_rule_change_body_hash(body: str) -> bytes:
    """BLAKE3 of the normalized clause body; of the empty string when there is none."""
    return blake3(str(body or "").encode("utf-8")).digest()


def encode_rule_change_request(
    *,
    sender_pubkey: Any,
    sequence_number: int,
    kind: int,
    body_hash: Any,
    offer_id: str,
    approvers: Dict[Any, Any],
    expire_at_height: int,
) -> bytes:
    """Canonical bytes a rule-change request id commits to."""
    out = bytearray()
    out.extend(encode_string(DOMAIN_RULE_CHANGE_REQUEST_V1.decode()))
    out.extend(encode_pubkey48(sender_pubkey))
    out.extend(encode_uint64(int(sequence_number)))
    out.extend(bytes([int(kind) & 0xFF]))
    out.extend(encode_hash32(body_hash))
    out.extend(encode_string(str(offer_id or "")))
    out.extend(_encode_index_map(approvers, encode_pubkey48))
    out.extend(encode_uint64(int(expire_at_height)))
    return bytes(out)


def compute_rule_change_request_id(**kwargs) -> bytes:
    """BLAKE3 of the canonical rule-change request. Returns 32 bytes."""
    return blake3(encode_rule_change_request(**kwargs)).digest()


def encode_rule_change_entry(
    request_id: Any,
    sender_pubkey: Any,
    kind: int,
    body_hash: Any,
    offer_id: str,
    approvers: Dict[Any, Any],
    voted: Dict[Any, Any],
    created_height: int,
    expire_at_height: int,
    status: int,
    declined: Any = (),
    ready: bool = False,
) -> bytes:
    """One request in any status, as the state root sees it.

    `ready` decides when the change is written and `declined` decides who may
    still vote, so both are bound: nodes must agree on them.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_RULE_CHANGE_ENTRY_V1.decode()))
    out.extend(encode_hash32(request_id))
    out.extend(encode_pubkey48(sender_pubkey))
    out.extend(bytes([int(kind) & 0xFF]))
    out.extend(encode_hash32(body_hash))
    out.extend(encode_string(str(offer_id or "")))
    out.extend(_encode_index_map(approvers, encode_pubkey48))
    out.extend(_encode_index_map(voted, encode_pubkey48))
    out.extend(encode_uint64(int(created_height)))
    out.extend(encode_uint64(int(expire_at_height)))
    out.extend(bytes([int(status) & 0xFF]))
    declined_sorted = sorted(int(d) for d in (declined or ()))
    out.extend(encode_uint32(len(declined_sorted)))
    for slot in declined_sorted:
        out.extend(encode_uint32(slot))
    out.extend(bytes([1 if ready else 0]))
    return bytes(out)


def encode_rule_change_book(entries: list) -> bytes:
    """Entries sorted by their encoding, count-prefixed, under a domain tag."""
    encoded = sorted(encode_rule_change_entry(*entry) for entry in (entries or []))
    out = bytearray()
    out.extend(encode_string(DOMAIN_RULE_CHANGE_BOOK_V1.decode()))
    out.extend(encode_uint32(len(encoded)))
    for blob in encoded:
        out.extend(blob)
    return bytes(out)


# --- Retractable transfers ---------------------------------------------------

DOMAIN_RETRACTABLE_TRANSFER_V1 = b"tau.retractable.transfer.v1"
DOMAIN_RETRACTABLE_RESOLVED_V1 = b"tau.retractable.resolved.v1"
DOMAIN_RETRACTABLE_BOOK_V1 = b"tau.retractable.book.v1"


def compute_retractable_id(
    sender_pubkey: Any,
    recipient_pubkey: Any,
    amount: int,
    sequence_number: int,
    kind: int,
    release_at: int,
) -> bytes:
    """BLAKE3 of the canonical parked transfer. Returns 32 bytes.

    Content-derived because the apply-time tx_id differs between proposer and
    validators; sequence_number keeps identical transfers from colliding.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_RETRACTABLE_TRANSFER_V1.decode()))
    out.extend(encode_pubkey48(sender_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(sequence_number)))
    out.extend(bytes([int(kind) & 0xFF]))
    out.extend(encode_uint64(int(release_at)))
    return blake3(bytes(out)).digest()


def compute_retractable_resolved_acc(acc: Any, retractable_id: Any, outcome: int) -> bytes:
    """Fold one resolution into the running commitment. Order-dependent by design."""
    out = bytearray()
    out.extend(encode_string(DOMAIN_RETRACTABLE_RESOLVED_V1.decode()))
    out.extend(encode_hash32(acc))
    out.extend(encode_hash32(retractable_id))
    out.extend(bytes([int(outcome) & 0xFF]))
    return blake3(bytes(out)).digest()


def encode_retractable_entry(
    retractable_id: Any,
    sender_pubkey: Any,
    recipient_pubkey: Any,
    amount: int,
    sequence_number: int,
    kind: int,
    release_at: int,
) -> bytes:
    out = bytearray()
    out.extend(encode_hash32(retractable_id))
    out.extend(encode_pubkey48(sender_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(sequence_number)))
    out.extend(bytes([int(kind) & 0xFF]))
    out.extend(encode_uint64(int(release_at)))
    return bytes(out)


def compute_retractable_book_root(
    open_entries: list, resolved_count: int, resolved_acc: Any
) -> bytes:
    """BLAKE3 of the book: sorted open entries, then the resolved commitment.

    `open_entries` are tuples in encode_retractable_entry argument order. Open
    and resolved are separate count-prefixed sections, so no status byte.
    """
    encoded = sorted(encode_retractable_entry(*e) for e in (open_entries or []))
    out = bytearray()
    out.extend(encode_string(DOMAIN_RETRACTABLE_BOOK_V1.decode()))
    out.extend(encode_uint32(len(encoded)))
    for blob in encoded:
        out.extend(blob)
    out.extend(encode_uint64(int(resolved_count)))
    out.extend(encode_hash32(resolved_acc))
    return blake3(bytes(out)).digest()


# --- Receive routes (Bounty 01, issue #35) ------------------------------------

DOMAIN_RECEIVE_ROUTE_V1 = b"tau.receive_route.v1"
DOMAIN_RECEIVE_ROUTE_TAU_V1 = b"tau.receive_route.tau.v1"
DOMAIN_RECEIVE_ROUTE_BOOK_V1 = b"tau.receive_route.book.v1"


def compute_receive_route_id(
    owner_pubkey: Any,
    destination_pubkey: Any,
    bps: int,
    min_amount: int,
    activation_ts: int,
    expiry_ts: int,
    locked_until_ts: int,
    version: int,
) -> bytes:
    """BLAKE3 of the canonical receive route. Returns 32 bytes.

    Content-derived from the signed fields alone, like the retractable id:
    the apply-time tx_id differs between proposer and validators, so it can
    never be part of a route's identity. `version` keeps a replacement route
    from colliding with the route it supersedes.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_RECEIVE_ROUTE_V1.decode()))
    out.extend(encode_pubkey48(owner_pubkey))
    out.extend(encode_pubkey48(destination_pubkey))
    out.extend(encode_uint64(int(bps)))
    out.extend(encode_uint64(int(min_amount)))
    out.extend(encode_uint64(int(activation_ts)))
    out.extend(encode_uint64(int(expiry_ts)))
    out.extend(encode_uint64(int(locked_until_ts)))
    out.extend(encode_uint64(int(version)))
    return blake3(bytes(out)).digest()


def compute_receive_route_tau_id(
    owner_pubkey: Any,
    destination_pubkey: Any,
    clause_text: str,
    min_amount: int,
    activation_ts: int,
    expiry_ts: int,
    locked_until_ts: int,
    version: int,
) -> bytes:
    """BLAKE3 of a Tau-form (clause) receive route. Returns 32 bytes.

    The Tau-form counterpart of compute_receive_route_id, under its own
    domain: where the declared form hashes a fixed share (bps), this form
    hashes the owner's clause TEXT — the clause is a signed field of the
    route, so a tampered clause is a different, unknown route, and no
    Tau-form id can ever collide with a declared-form id over the same
    terms. A Tau-form route carries no bps (its shape requires bps 0),
    so the share is not a field here.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_RECEIVE_ROUTE_TAU_V1.decode()))
    out.extend(encode_pubkey48(owner_pubkey))
    out.extend(encode_pubkey48(destination_pubkey))
    out.extend(encode_string(str(clause_text or "")))
    out.extend(encode_uint64(int(min_amount)))
    out.extend(encode_uint64(int(activation_ts)))
    out.extend(encode_uint64(int(expiry_ts)))
    out.extend(encode_uint64(int(locked_until_ts)))
    out.extend(encode_uint64(int(version)))
    return blake3(bytes(out)).digest()


def encode_receive_route_entry(
    route_id: Any,
    owner_pubkey: Any,
    destination_pubkey: Any,
    bps: int,
    min_amount: int,
    activation_ts: int,
    expiry_ts: int,
    locked_until_ts: int,
    version: int,
    form: int = 1,
    clause_text: str = "",
) -> bytes:
    out = bytearray()
    out.extend(encode_hash32(route_id))
    out.extend(encode_pubkey48(owner_pubkey))
    out.extend(encode_pubkey48(destination_pubkey))
    out.extend(encode_uint64(int(bps)))
    out.extend(encode_uint64(int(min_amount)))
    out.extend(encode_uint64(int(activation_ts)))
    out.extend(encode_uint64(int(expiry_ts)))
    out.extend(encode_uint64(int(locked_until_ts)))
    out.extend(encode_uint64(int(version)))
    if int(form) != 1:
        # The Tau form's signed fields, appended only for Tau-form
        # entries: a declared-form entry's record stays byte-identical
        # to the encoding before the clause form existed.
        out.extend(encode_uint64(int(form)))
        out.extend(encode_string(str(clause_text or "")))
    return bytes(out)


def compute_receive_route_book_root(entries: list) -> bytes:
    """BLAKE3 of the route book: the sorted encoded entries, count-prefixed.

    `entries` are tuples in encode_receive_route_entry argument order. There
    is no resolved section: a removed route leaves the book entirely, and the
    history of removals lives in block history, not in state.
    """
    encoded = sorted(encode_receive_route_entry(*e) for e in (entries or []))
    out = bytearray()
    out.extend(encode_string(DOMAIN_RECEIVE_ROUTE_BOOK_V1.decode()))
    out.extend(encode_uint32(len(encoded)))
    for blob in encoded:
        out.extend(blob)
    return blake3(bytes(out)).digest()


# --- Standing payments (Bounty 01, issue #34) ---------------------------------

DOMAIN_STANDING_PAYMENT_V1 = b"tau.standing_payment.v1"
DOMAIN_STANDING_PAYMENT_TAU_V1 = b"tau.standing_payment.tau.v1"
DOMAIN_STANDING_PAYMENT_BOOK_V1 = b"tau.standing_payment.book.v1"


def compute_standing_payment_id(
    payer_pubkey: Any,
    recipient_pubkey: Any,
    amount: int,
    schedule_kind: int,
    signed_day: int,
    anchor_ts: int,
    window_seconds: int,
    final_ts: int,
    max_occurrences: int,
    max_total: int,
    fee_limit: int,
    policy_version_ref: int,
    allow_catch_up: int,
    version: int,
    catch_up_periods: int = 0,
) -> bytes:
    """BLAKE3 of the canonical standing-payment authorization. Returns 32 bytes.

    Content-derived from the signed fields alone, like the receive-route id:
    every term the payer signed is in the hash, so a tampered copy of an
    authorization is a different, unknown authorization — never the same one
    with different terms. `version` keeps an update from colliding with the
    version it supersedes. FIX 9's `catch_up_periods` (default 0, no
    catch-up) is appended only when non-zero — the same non-default gate
    the book root uses for the retry section — so an authorization that
    does not sign a catch-up count keeps the id it had before the term
    existed, and two authorizations that differ only in a non-zero count
    are different authorizations.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_STANDING_PAYMENT_V1.decode()))
    out.extend(encode_pubkey48(payer_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(schedule_kind)))
    out.extend(encode_uint64(int(signed_day)))
    out.extend(encode_uint64(int(anchor_ts)))
    out.extend(encode_uint64(int(window_seconds)))
    out.extend(encode_uint64(int(final_ts)))
    out.extend(encode_uint64(int(max_occurrences)))
    out.extend(encode_uint64(int(max_total)))
    out.extend(encode_uint64(int(fee_limit)))
    out.extend(encode_uint64(int(policy_version_ref)))
    out.extend(encode_uint64(int(allow_catch_up)))
    out.extend(encode_uint64(int(version)))
    if int(catch_up_periods):
        out.extend(encode_uint64(int(catch_up_periods)))
    return blake3(bytes(out)).digest()


def compute_standing_payment_tau_id(
    payer_pubkey: Any,
    recipient_pubkey: Any,
    amount: int,
    schedule_kind: int,
    signed_day: int,
    anchor_ts: int,
    window_seconds: int,
    final_ts: int,
    max_occurrences: int,
    max_total: int,
    fee_limit: int,
    policy_version_ref: int,
    allow_catch_up: int,
    clause_text: str,
    version: int,
    due_retry_seconds: int = 0,
    catch_up_periods: int = 0,
) -> bytes:
    """BLAKE3 of a Tau-form (clause) standing-payment authorization.

    The Tau-form counterpart of compute_standing_payment_id, under its
    own domain: every signed term of the declared form is hashed the
    same way, and the payer's clause TEXT is hashed with them — the
    clause is a signed field of the authorization, so a tampered clause
    is a different, unknown authorization, and no Tau-form id can ever
    collide with a declared-form id over the same terms. FIX 5 adds
    `due_retry_seconds` (default 0, no retry): a signed term of the
    clause form, so two authorizations that differ only in their retry
    window are different authorizations.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_STANDING_PAYMENT_TAU_V1.decode()))
    out.extend(encode_pubkey48(payer_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(schedule_kind)))
    out.extend(encode_uint64(int(signed_day)))
    out.extend(encode_uint64(int(anchor_ts)))
    out.extend(encode_uint64(int(window_seconds)))
    out.extend(encode_uint64(int(final_ts)))
    out.extend(encode_uint64(int(max_occurrences)))
    out.extend(encode_uint64(int(max_total)))
    out.extend(encode_uint64(int(fee_limit)))
    out.extend(encode_uint64(int(policy_version_ref)))
    out.extend(encode_uint64(int(allow_catch_up)))
    out.extend(encode_string(str(clause_text or "")))
    out.extend(encode_uint64(int(version)))
    out.extend(encode_uint64(int(due_retry_seconds)))
    if int(catch_up_periods):
        out.extend(encode_uint64(int(catch_up_periods)))
    return blake3(bytes(out)).digest()


def encode_standing_payment_record(
    auth_id: Any,
    payer_pubkey: Any,
    recipient_pubkey: Any,
    amount: int,
    schedule_kind: int,
    signed_day: int,
    anchor_ts: int,
    window_seconds: int,
    final_ts: int,
    max_occurrences: int,
    max_total: int,
    fee_limit: int,
    policy_version_ref: int,
    allow_catch_up: int,
    version: int,
    settled_periods: Any,
    total_paid: int,
    last_execution_ts: int,
    cancelled: int,
    cancelled_ts: int,
    form: int = 1,
    clause_text: str = "",
    due_retry_seconds: int = 0,
    catch_up_periods: int = 0,
) -> bytes:
    """One authorization for the book root: signed fields + live progress.

    The progress (settled-period markers, cumulative total, cancellation) is
    consensus state exactly like the terms: two nodes that disagree about
    whether a period was paid disagree about the state root.
    """
    out = bytearray()
    out.extend(encode_hash32(auth_id))
    out.extend(encode_pubkey48(payer_pubkey))
    out.extend(encode_pubkey48(recipient_pubkey))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(schedule_kind)))
    out.extend(encode_uint64(int(signed_day)))
    out.extend(encode_uint64(int(anchor_ts)))
    out.extend(encode_uint64(int(window_seconds)))
    out.extend(encode_uint64(int(final_ts)))
    out.extend(encode_uint64(int(max_occurrences)))
    out.extend(encode_uint64(int(max_total)))
    out.extend(encode_uint64(int(fee_limit)))
    out.extend(encode_uint64(int(policy_version_ref)))
    out.extend(encode_uint64(int(allow_catch_up)))
    out.extend(encode_uint64(int(version)))
    periods = sorted(int(p) for p in (settled_periods or ()))
    out.extend(encode_uint32(len(periods)))
    for period in periods:
        out.extend(encode_uint64(period))
    out.extend(encode_uint64(int(total_paid)))
    out.extend(encode_uint64(int(last_execution_ts)))
    out.extend(encode_uint64(int(cancelled)))
    out.extend(encode_uint64(int(cancelled_ts)))
    if int(form) != 1:
        # The Tau form's signed fields, appended only for Tau-form
        # records: a declared-form record stays byte-identical to the
        # encoding before the clause form existed. FIX 5 appends the
        # signed due_retry term here too, so a declared record is
        # still byte-identical and a clause-form record pins its retry
        # window.
        out.extend(encode_uint64(int(form)))
        out.extend(encode_string(str(clause_text or "")))
        out.extend(encode_uint64(int(due_retry_seconds)))
    # FIX 9: the signed catch-up bound is a term of BOTH forms (the
    # calendar machinery is shared). Like the ids, it is appended only
    # when non-zero, after the form-specific tail: a record whose
    # authorization signs no catch-up count stays byte-identical to
    # the encoding before the term existed.
    if int(catch_up_periods):
        out.extend(encode_uint64(int(catch_up_periods)))
    return bytes(out)


def encode_paid_period_fact(
    auth_id: Any,
    payer_pubkey: Any,
    period_index: int,
    period_start_ts: int,
    period_end_ts: int,
    amount: int,
    execution_ts: int,
) -> bytes:
    out = bytearray()
    out.extend(encode_hash32(auth_id))
    out.extend(encode_pubkey48(payer_pubkey))
    out.extend(encode_uint64(int(period_index)))
    out.extend(encode_uint64(int(period_start_ts)))
    out.extend(encode_uint64(int(period_end_ts)))
    out.extend(encode_uint64(int(amount)))
    out.extend(encode_uint64(int(execution_ts)))
    return bytes(out)


def encode_standing_retry(
    auth_id: Any,
    period_index: int,
    due_ts: int,
    retry_until: int,
    recorded_height: int,
) -> bytes:
    """One owed due_retry for the book root (FIX 5).

    A retry is consensus state exactly like a settled-period marker:
    two nodes that disagree about which due points are owed disagree
    about what the next block's sweep settles, so the root must cover
    it. Row order is (auth_id, period_index, due_ts, retry_until,
    recorded_height).
    """
    out = bytearray()
    out.extend(encode_hash32(auth_id))
    out.extend(encode_uint64(int(period_index)))
    out.extend(encode_uint64(int(due_ts)))
    out.extend(encode_uint64(int(retry_until)))
    out.extend(encode_uint64(int(recorded_height)))
    return bytes(out)


def compute_standing_payment_book_root(
    records: list, facts: list, retries: list = ()
) -> bytes:
    """BLAKE3 of the standing-payment book: records + paid-period facts.

    `records` are tuples in encode_standing_payment_record argument order and
    `facts` in encode_paid_period_fact argument order. Facts outlive their
    authorization (an update supersedes the entry, never the history), so
    they are rooted separately instead of nested inside a record. FIX 5
    adds `retries` (tuples in encode_standing_retry argument order): owed
    due_retries are consensus state too, and default to none, so a book
    with no retry owed roots exactly as it did before the term existed.
    """
    encoded_records = sorted(encode_standing_payment_record(*r) for r in (records or []))
    encoded_facts = sorted(encode_paid_period_fact(*f) for f in (facts or []))
    encoded_retries = sorted(encode_standing_retry(*r) for r in (retries or []))
    out = bytearray()
    out.extend(encode_string(DOMAIN_STANDING_PAYMENT_BOOK_V1.decode()))
    out.extend(encode_uint32(len(encoded_records)))
    for blob in encoded_records:
        out.extend(blob)
    out.extend(encode_uint32(len(encoded_facts)))
    for blob in encoded_facts:
        out.extend(blob)
    if encoded_retries:
        # The retries section appears only when a retry is owed: a
        # book with no retry owed roots exactly as it did before the
        # term existed (the same non-default gate the metadata roots
        # use). A non-empty retry set can never collide with an empty
        # one — the count and the sorted blobs pin it.
        out.extend(encode_uint32(len(encoded_retries)))
        for blob in encoded_retries:
            out.extend(blob)
    return blake3(bytes(out)).digest()


# --- Payout rules (Bounty 01, issue #63) -------------------------------------

DOMAIN_PAYOUT_RULE_V1 = b"tau.payout_rule.v1"
DOMAIN_PAYOUT_RULE_TAU_V1 = b"tau.payout_rule.tau.v1"
DOMAIN_PAYOUT_RULE_PERIODS_FROM_V1 = b"tau.payout_rule.periods_from.v1"
DOMAIN_PAYOUT_RULE_BOOK_V1 = b"tau.payout_rule.book.v1"


def _encode_pubkey_list(pubkeys) -> bytes:
    out = bytearray()
    out.extend(encode_uint32(len(pubkeys or ())))
    for pubkey in (pubkeys or ()):
        out.extend(encode_pubkey48(pubkey))
    return bytes(out)


def _encode_leg_list(legs) -> bytes:
    out = bytearray()
    out.extend(encode_uint32(len(legs or ())))
    for recipient, mode, value in (legs or ()):
        out.extend(encode_pubkey48(recipient))
        out.extend(encode_uint64(int(mode)))
        out.extend(encode_uint64(int(value)))
    return bytes(out)


def compute_payout_rule_id(
    owner_pubkey: Any,
    recipients: Any,
    legs: Any,
    max_per_execution: int,
    max_per_period: int,
    period_seconds: int,
    period_anchor_ts: int,
    version: int,
    rule_index: int = 0,
    shared_cap_id: str = "",
    shared_cap_amount: int = 0,
) -> bytes:
    """BLAKE3 of the canonical payout rule. Returns 32 bytes.

    Content-derived from the signed fields alone, like the receive-route
    and standing-payment ids: the declared recipient set, the leg program,
    both caps and the period shape are all inside the hash, so a tampered
    copy of a rule is a different, unknown rule — never the same one with
    different terms. `version` keeps a replacement from colliding with the
    rule it supersedes. The recipient set is encoded sorted (it is a set);
    the leg program is encoded in its declared order (it is a program).

    FIX 7 (multi-rule): `rule_index` — the rule's slot in its owner's book
    (0..MAX_RULES_PER_OWNER-1) — is appended after `version`, the same
    append-at-the-end discipline as the FIX 5 standing due-retry term: two
    rules of one owner that differ only in slot are different rules with
    different ids, and a slot-0 rule hashes exactly as before only in the
    sense that matters — the slot is a signed field, so it is inside.

    FIX 8 (shared cap): `shared_cap_id` and `shared_cap_amount` — the
    shared period cap the rule names, if any — are appended after the
    slot, by the same discipline: a rule that draws on a shared cap is a
    different rule from the same terms without one, and two rules naming
    different shared caps (or different amounts) never collide.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_PAYOUT_RULE_V1.decode()))
    out.extend(encode_pubkey48(owner_pubkey))
    out.extend(_encode_pubkey_list(sorted(recipients or ())))
    out.extend(_encode_leg_list(legs))
    out.extend(encode_uint64(int(max_per_execution)))
    out.extend(encode_uint64(int(max_per_period)))
    out.extend(encode_uint64(int(period_seconds)))
    out.extend(encode_uint64(int(period_anchor_ts)))
    out.extend(encode_uint64(int(version)))
    out.extend(encode_uint64(int(rule_index)))
    out.extend(encode_string(str(shared_cap_id or "")))
    out.extend(encode_uint64(int(shared_cap_amount)))
    return blake3(bytes(out)).digest()


def compute_payout_rule_tau_id(
    owner_pubkey: Any,
    recipients: Any,
    clause_text: str,
    max_per_execution: int,
    max_per_period: int,
    period_seconds: int,
    period_anchor_ts: int,
    version: int,
    rule_index: int = 0,
    shared_cap_id: str = "",
    shared_cap_amount: int = 0,
) -> bytes:
    """BLAKE3 of a Tau-form payout rule. Returns 32 bytes.

    The Tau-form counterpart of compute_payout_rule_id, under its own
    domain: where the declared form hashes a leg PROGRAM, this form hashes
    the owner's clause TEXT — the clause is a signed field of the rule, so
    a tampered clause is a different, unknown rule, and no Tau-form id can
    ever collide with a declared-form id over the same terms. The FIX 7
    slot term is appended after `version`, exactly as in the declared
    form, and the FIX 8 shared-cap terms after the slot.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_PAYOUT_RULE_TAU_V1.decode()))
    out.extend(encode_pubkey48(owner_pubkey))
    out.extend(_encode_pubkey_list(sorted(recipients or ())))
    out.extend(encode_string(str(clause_text or "")))
    out.extend(encode_uint64(int(max_per_execution)))
    out.extend(encode_uint64(int(max_per_period)))
    out.extend(encode_uint64(int(period_seconds)))
    out.extend(encode_uint64(int(period_anchor_ts)))
    out.extend(encode_uint64(int(version)))
    out.extend(encode_uint64(int(rule_index)))
    out.extend(encode_string(str(shared_cap_id or "")))
    out.extend(encode_uint64(int(shared_cap_amount)))
    return blake3(bytes(out)).digest()


def compute_payout_rule_periods_from_id(
    owner_pubkey: Any,
    recipients: Any,
    legs: Any,
    clause_text: str,
    form: int,
    max_per_execution: int,
    max_per_period: int,
    period_seconds: int,
    period_anchor_ts: int,
    periods_from_ts: int,
    version: int,
    rule_index: int = 0,
    shared_cap_id: str = "",
    shared_cap_amount: int = 0,
) -> bytes:
    """BLAKE3 of a payout rule that carries a `periods_from` anchor.

    The periods-from counterpart of the two ids above, under its own
    domain: a rule whose periods count from a signed fixed start
    (periods_from_ts) instead of the recorded install anchor is a
    different rule from the same terms without it — the period grid its
    caps are counted on differs, so the anchor is inside the hash, and
    the form is encoded so a declared-form and a Tau-form rule over the
    same terms and anchor never collide either. Entries WITHOUT
    periods_from keep the original ids byte-for-byte; this function is
    only ever called for entries that carry the anchor.

    Fold adaptation (FIX 9 line): the FIX 7 slot and FIX 8 shared-cap
    terms are appended after `version`, exactly as in the declared and
    Tau ids on this line — the G4 line this function came from has
    neither, and without them two periods-from rules differing only in
    slot or shared cap would collide in this domain.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_PAYOUT_RULE_PERIODS_FROM_V1.decode()))
    out.extend(encode_pubkey48(owner_pubkey))
    out.extend(_encode_pubkey_list(sorted(recipients or ())))
    out.extend(encode_uint64(int(form)))
    if int(form) == 2:
        out.extend(encode_string(str(clause_text or "")))
    else:
        out.extend(_encode_leg_list(legs))
    out.extend(encode_uint64(int(max_per_execution)))
    out.extend(encode_uint64(int(max_per_period)))
    out.extend(encode_uint64(int(period_seconds)))
    out.extend(encode_uint64(int(period_anchor_ts)))
    out.extend(encode_uint64(int(periods_from_ts)))
    out.extend(encode_uint64(int(version)))
    out.extend(encode_uint64(int(rule_index)))
    out.extend(encode_string(str(shared_cap_id or "")))
    out.extend(encode_uint64(int(shared_cap_amount)))
    return blake3(bytes(out)).digest()


def encode_payout_rule_record(
    rule_id: Any,
    owner_pubkey: Any,
    recipients: Any,
    legs: Any,
    max_per_execution: int,
    max_per_period: int,
    period_seconds: int,
    period_anchor_ts: int,
    version: int,
    period_totals: Any,
    form: int = 1,
    clause_text: str = "",
    rule_index: int = 0,
    shared_cap_id: str = "",
    shared_cap_amount: int = 0,
    periods_from_ts: int = 0,
) -> bytes:
    """One payout rule for the book root: signed fields + live period totals.

    The per-period paid totals are consensus state exactly like the terms:
    two nodes that disagree about how much a rule already paid this period
    disagree about whether the next execution is within its cap. The form
    and (for the Tau form) the clause text are signed fields of the rule,
    so they are rooted too — appended after the totals so the declared
    form's field order is untouched. The FIX 7 slot term is appended last,
    after the clause text, by the same discipline, and the FIX 8
    shared-cap terms after the slot. A periods_from anchor, when the rule
    carries one, is appended after them, and ONLY then: a rule without
    the anchor encodes byte-identically to before the field existed, so
    existing book roots do not move.
    """
    out = bytearray()
    out.extend(encode_hash32(rule_id))
    out.extend(encode_pubkey48(owner_pubkey))
    out.extend(_encode_pubkey_list(sorted(recipients or ())))
    out.extend(_encode_leg_list(legs))
    out.extend(encode_uint64(int(max_per_execution)))
    out.extend(encode_uint64(int(max_per_period)))
    out.extend(encode_uint64(int(period_seconds)))
    out.extend(encode_uint64(int(period_anchor_ts)))
    out.extend(encode_uint64(int(version)))
    totals = sorted((int(i), int(t)) for i, t in (period_totals or ()))
    out.extend(encode_uint32(len(totals)))
    for index, total in totals:
        out.extend(encode_uint64(index))
        out.extend(encode_uint64(total))
    out.extend(encode_uint64(int(form)))
    out.extend(encode_string(str(clause_text or "")))
    out.extend(encode_uint64(int(rule_index)))
    out.extend(encode_string(str(shared_cap_id or "")))
    out.extend(encode_uint64(int(shared_cap_amount)))
    if int(periods_from_ts):
        out.extend(encode_uint64(int(periods_from_ts)))
    return bytes(out)


def encode_payout_settlement(
    rule_id: Any,
    settlement_id: Any,
    base_amount: int,
    total: int,
    execution_ts: int,
) -> bytes:
    """One settled execution for the book root.

    Settlements are rooted separately from the rule records, like the
    standing book's paid-period facts: they outlive the rule version that
    produced them, so removing and reinstalling the same rule can never
    reset a settlement and pay the same execution twice.
    """
    out = bytearray()
    out.extend(encode_hash32(rule_id))
    out.extend(encode_hash32(settlement_id))
    out.extend(encode_uint64(int(base_amount)))
    out.extend(encode_uint64(int(total)))
    out.extend(encode_uint64(int(execution_ts)))
    return bytes(out)


def compute_payout_rule_book_root(records: list, settlements: list) -> bytes:
    """BLAKE3 of the payout-rule book: rule records + settlement records.

    `records` are tuples in encode_payout_rule_record argument order and
    `settlements` in encode_payout_settlement argument order.
    """
    encoded_records = sorted(encode_payout_rule_record(*r) for r in (records or []))
    encoded_settlements = sorted(
        encode_payout_settlement(*s) for s in (settlements or [])
    )
    out = bytearray()
    out.extend(encode_string(DOMAIN_PAYOUT_RULE_BOOK_V1.decode()))
    out.extend(encode_uint32(len(encoded_records)))
    for blob in encoded_records:
        out.extend(blob)
    out.extend(encode_uint32(len(encoded_settlements)))
    for blob in encoded_settlements:
        out.extend(blob)
    return blake3(bytes(out)).digest()


# --- Grants (Bounty 01, stages 2-5) --------------------------------------------

DOMAIN_GRANT_V1 = b"tau.grant.v1"
# The Tau-form (clause) grant's own domain (Bounty 01, FIX 5): a grant
# whose release schedule is the funder's Tau clause, not the declared
# program. The clause TEXT and the signed periods_from anchor are hashed
# with the declared terms, so a tampered clause or anchor is a different,
# unknown grant — and no Tau-form id can ever collide with a declared-form
# id over the same terms, mirroring the standing-payment Tau domain.
DOMAIN_GRANT_TAU_V1 = b"tau.grant.tau.v1"
DOMAIN_GRANT_SHARED_CAP_V1 = b"tau.grant.shared_cap.v1"
DOMAIN_GRANT_BOOK_V1 = b"tau.grant.book.v1"


def compute_grant_id(
    funder_pubkey: Any,
    beneficiary_pubkey: Any,
    total_amount: int,
    release_per_period: int,
    schedule_kind: int,
    signed_day: int,
    start_ts: int,
    deadline_ts: int,
    locked_until_ts: int,
    window_start_ts: int,
    window_end_ts: int,
    inactivity_seconds: int,
    version: int,
) -> bytes:
    """BLAKE3 of the canonical grant. Returns 32 bytes.

    Content-derived from the signed fields alone, like the standing-payment
    and payout-rule ids: the parties, the total, the release schedule, the
    deadline and every time condition are inside the hash, so a tampered
    copy of a grant is a different, unknown grant — never the same one with
    different terms. `version` distinguishes two grants of one funder to
    one beneficiary whose other terms are identical.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_GRANT_V1.decode()))
    out.extend(encode_pubkey48(funder_pubkey))
    out.extend(encode_pubkey48(beneficiary_pubkey))
    out.extend(encode_uint64(int(total_amount)))
    out.extend(encode_uint64(int(release_per_period)))
    out.extend(encode_uint64(int(schedule_kind)))
    out.extend(encode_uint64(int(signed_day)))
    out.extend(encode_uint64(int(start_ts)))
    out.extend(encode_uint64(int(deadline_ts)))
    out.extend(encode_uint64(int(locked_until_ts)))
    out.extend(encode_uint64(int(window_start_ts)))
    out.extend(encode_uint64(int(window_end_ts)))
    out.extend(encode_uint64(int(inactivity_seconds)))
    out.extend(encode_uint64(int(version)))
    return blake3(bytes(out)).digest()


def compute_grant_tau_id(
    funder_pubkey: Any,
    beneficiary_pubkey: Any,
    total_amount: int,
    release_per_period: int,
    schedule_kind: int,
    signed_day: int,
    start_ts: int,
    deadline_ts: int,
    locked_until_ts: int,
    window_start_ts: int,
    window_end_ts: int,
    inactivity_seconds: int,
    version: int,
    form: int,
    clause_text: str,
    periods_from_ts: int,
) -> bytes:
    """BLAKE3 of a Tau-form (clause) grant. Returns 32 bytes.

    The Tau-form counterpart of compute_grant_id, under its own domain:
    every signed term of the declared form is hashed the same way, and
    the funder's clause TEXT plus the signed periods_from anchor are
    hashed with them — the clause is a signed field of the grant, so a
    tampered clause is a different, unknown grant, and no Tau-form id
    can ever collide with a declared-form id over the same terms.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_GRANT_TAU_V1.decode()))
    out.extend(encode_pubkey48(funder_pubkey))
    out.extend(encode_pubkey48(beneficiary_pubkey))
    out.extend(encode_uint64(int(total_amount)))
    out.extend(encode_uint64(int(release_per_period)))
    out.extend(encode_uint64(int(schedule_kind)))
    out.extend(encode_uint64(int(signed_day)))
    out.extend(encode_uint64(int(start_ts)))
    out.extend(encode_uint64(int(deadline_ts)))
    out.extend(encode_uint64(int(locked_until_ts)))
    out.extend(encode_uint64(int(window_start_ts)))
    out.extend(encode_uint64(int(window_end_ts)))
    out.extend(encode_uint64(int(inactivity_seconds)))
    out.extend(encode_uint64(int(version)))
    out.extend(encode_uint64(int(form)))
    out.extend(encode_string(str(clause_text or "")))
    out.extend(encode_uint64(int(periods_from_ts)))
    return blake3(bytes(out)).digest()


def encode_grant_record(
    grant_id: Any,
    funder_pubkey: Any,
    beneficiary_pubkey: Any,
    total_amount: int,
    release_per_period: int,
    schedule_kind: int,
    signed_day: int,
    start_ts: int,
    deadline_ts: int,
    locked_until_ts: int,
    window_start_ts: int,
    window_end_ts: int,
    inactivity_seconds: int,
    version: int,
    total_spent: int,
    last_draw_ts: int,
    refunded: int,
    refunded_amount: int,
    refunded_ts: int,
    form: int = 1,
    clause_text: str = "",
    periods_from_ts: int = 0,
) -> bytes:
    """One grant for the book root: signed fields + live progress.

    The progress is consensus state exactly like the terms: two nodes that
    disagree about how much a grant already paid out, or whether its
    refund settled, disagree about what the next draw or sweep may do.
    """
    out = bytearray()
    out.extend(encode_hash32(grant_id))
    out.extend(encode_pubkey48(funder_pubkey))
    out.extend(encode_pubkey48(beneficiary_pubkey))
    out.extend(encode_uint64(int(total_amount)))
    out.extend(encode_uint64(int(release_per_period)))
    out.extend(encode_uint64(int(schedule_kind)))
    out.extend(encode_uint64(int(signed_day)))
    out.extend(encode_uint64(int(start_ts)))
    out.extend(encode_uint64(int(deadline_ts)))
    out.extend(encode_uint64(int(locked_until_ts)))
    out.extend(encode_uint64(int(window_start_ts)))
    out.extend(encode_uint64(int(window_end_ts)))
    out.extend(encode_uint64(int(inactivity_seconds)))
    out.extend(encode_uint64(int(version)))
    out.extend(encode_uint64(int(total_spent)))
    out.extend(encode_uint64(int(last_draw_ts)))
    out.extend(encode_uint64(int(refunded)))
    out.extend(encode_uint64(int(refunded_amount)))
    out.extend(encode_uint64(int(refunded_ts)))
    if int(form) != 1:
        # The Tau form's signed fields, appended only for Tau-form
        # records: a declared-form record stays byte-identical to the
        # encoding before the clause form existed.
        out.extend(encode_uint64(int(form)))
        out.extend(encode_string(str(clause_text or "")))
        out.extend(encode_uint64(int(periods_from_ts)))
    return bytes(out)


def compute_grant_shared_cap_id(
    funder_pubkey: Any,
    cap_amount: int,
    period_seconds: int,
    period_anchor_ts: int,
    version: int,
) -> bytes:
    """BLAKE3 of the canonical shared cap. Returns 32 bytes.

    Content-derived from the signed fields alone: a funder's shared cap is
    identified by exactly the terms they signed — the amount, the period
    shape and the version.
    """
    out = bytearray()
    out.extend(encode_string(DOMAIN_GRANT_SHARED_CAP_V1.decode()))
    out.extend(encode_pubkey48(funder_pubkey))
    out.extend(encode_uint64(int(cap_amount)))
    out.extend(encode_uint64(int(period_seconds)))
    out.extend(encode_uint64(int(period_anchor_ts)))
    out.extend(encode_uint64(int(version)))
    return blake3(bytes(out)).digest()


def encode_grant_shared_cap_record(
    cap_id: Any,
    funder_pubkey: Any,
    cap_amount: int,
    period_seconds: int,
    period_anchor_ts: int,
    version: int,
    period_totals: Any,
) -> bytes:
    """One shared cap for the book root: signed fields + live period totals.

    The per-period drawn totals are consensus state exactly like the cap:
    two nodes that disagree about how much a funder's grants already drew
    this period disagree about whether the next draw fits the shared cap —
    the totals are what "counted exactly once" is made of.
    """
    out = bytearray()
    out.extend(encode_hash32(cap_id))
    out.extend(encode_pubkey48(funder_pubkey))
    out.extend(encode_uint64(int(cap_amount)))
    out.extend(encode_uint64(int(period_seconds)))
    out.extend(encode_uint64(int(period_anchor_ts)))
    out.extend(encode_uint64(int(version)))
    totals = sorted((int(i), int(t)) for i, t in (period_totals or ()))
    out.extend(encode_uint32(len(totals)))
    for index, total in totals:
        out.extend(encode_uint64(index))
        out.extend(encode_uint64(total))
    return bytes(out)


def compute_grant_book_root(records: list, shared_caps: list) -> bytes:
    """BLAKE3 of the grant book: grant records + shared-cap records.

    `records` are tuples in encode_grant_record argument order and
    `shared_caps` in encode_grant_shared_cap_record argument order.
    """
    encoded_records = sorted(encode_grant_record(*r) for r in (records or []))
    encoded_caps = sorted(
        encode_grant_shared_cap_record(*c) for c in (shared_caps or [])
    )
    out = bytearray()
    out.extend(encode_string(DOMAIN_GRANT_BOOK_V1.decode()))
    out.extend(encode_uint32(len(encoded_records)))
    for blob in encoded_records:
        out.extend(blob)
    out.extend(encode_uint32(len(encoded_caps)))
    for blob in encoded_caps:
        out.extend(blob)
    return blake3(bytes(out)).digest()
