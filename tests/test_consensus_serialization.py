import pytest
from consensus.serialization import (
    encode_uint64,
    encode_uint32,
    encode_bool,
    encode_string,
    encode_hash32,
    encode_pubkey48,
    canonical_json
)

def test_encode_uint64():
    assert encode_uint64(0) == b"\x00" * 8
    assert encode_uint64(255) == b"\x00" * 7 + b"\xff"
    assert encode_uint64(1) == b"\x00" * 7 + b"\x01"
    assert encode_uint64(0xFFFFFFFFFFFFFFFF) == b"\xff" * 8
    
    with pytest.raises(ValueError):
        encode_uint64(-1)
    
    with pytest.raises(ValueError):
        encode_uint64(0x10000000000000000)

def test_encode_uint32():
    assert encode_uint32(0) == b"\x00" * 4
    assert encode_uint32(255) == b"\x00" * 3 + b"\xff"
    assert encode_uint32(0xFFFFFFFF) == b"\xff" * 4
    
    with pytest.raises(ValueError):
        encode_uint32(-1)
        
    with pytest.raises(ValueError):
        encode_uint32(0x100000000)

def test_encode_bool():
    assert encode_bool(True) == b"\x01"
    assert encode_bool(False) == b"\x00"
    
    with pytest.raises(ValueError):
        encode_bool(1) # should strictly require bool
    
    with pytest.raises(ValueError):
        encode_bool(None)

def test_encode_string():
    assert encode_string("") == b"\x00\x00\x00\x00"
    assert encode_string("hello") == b"\x00\x00\x00\x05hello"
    
    # Test multi-byte utf-8 character
    s = "hello\u2022" # bullet point
    encoded_str = s.encode('utf-8')
    assert encode_string(s) == encode_uint32(len(encoded_str)) + encoded_str
    
    with pytest.raises(ValueError):
        encode_string(b"hello")

def test_encode_hash32():
    assert encode_hash32(b"\x00" * 32) == b"\x00" * 32
    assert encode_hash32(b"\xff" * 32) == b"\xff" * 32
    
    with pytest.raises(ValueError):
        encode_hash32(b"\x00" * 31)
        
    with pytest.raises(ValueError):
        encode_hash32(b"\x00" * 33)

def test_encode_pubkey48():
    assert encode_pubkey48(b"\x00" * 48) == b"\x00" * 48
    
    with pytest.raises(ValueError):
        encode_pubkey48(b"\x00" * 47)

def test_canonical_json():
    # Test key sorting and whitespace removal
    d1 = {"b": 2, "a": 1}
    assert canonical_json(d1) == b'{"a":1,"b":2}'
    
    # Test strict equivalence required
    d2 = {"x": True, "y": None, "z": [1, 2, 3]}
    assert canonical_json(d2) == b'{"x":true,"y":null,"z":[1,2,3]}'
    
    # Nested dict sorting
    d3 = {"outer": {"b": 2, "a": 1}}
    assert canonical_json(d3) == b'{"outer":{"a":1,"b":2}}'

def test_canonicalize_proposer_yid():
    from consensus.serialization import canonicalize_proposer_yid
    valid_pubkey = "a" * 96
    assert canonicalize_proposer_yid(valid_pubkey) == valid_pubkey
    
    valid_pubkey_upper = ("a" * 95) + "B"
    assert canonicalize_proposer_yid(valid_pubkey_upper) == ("a" * 95) + "b"
    
    with pytest.raises(ValueError, match="0x prefix"):
        canonicalize_proposer_yid("0x" + valid_pubkey)
        
    with pytest.raises(ValueError, match="exactly 96 chars"):
        canonicalize_proposer_yid("a" * 95)
        
    with pytest.raises(ValueError, match="non-hex"):
        canonicalize_proposer_yid(("a" * 95) + "z")

def test_canonicalize_parent_hash_yid():
    from consensus.serialization import canonicalize_parent_hash_yid
    valid_hash = "b" * 64
    assert canonicalize_parent_hash_yid(valid_hash) == valid_hash
    
    valid_hash_upper = ("b" * 63) + "C"
    assert canonicalize_parent_hash_yid(valid_hash_upper) == ("b" * 63) + "c"
    
    with pytest.raises(ValueError, match="0x prefix"):
        canonicalize_parent_hash_yid("0x" + valid_hash)
        
    with pytest.raises(ValueError, match="exactly 64 chars"):
        canonicalize_parent_hash_yid("b" * 63)
        
    with pytest.raises(ValueError, match="non-hex"):
        canonicalize_parent_hash_yid(("b" * 63) + "z")

def test_encode_rule_revisions():
    from consensus.serialization import encode_rule_revisions, encode_uint32, encode_string
    revs = ["abc", "defg"]
    encoded = encode_rule_revisions(revs)
    expected = encode_uint32(2) + encode_string("abc") + encode_string("defg")
    assert encoded == expected
    
def test_encode_host_contract_patch():
    from consensus.serialization import encode_host_contract_patch, encode_uint32, encode_string, encode_bool
    patch = {
        "proof_scheme": "bls",
        "fork_choice": True,
        "max_block_size": 1000
    }
    encoded = encode_host_contract_patch(patch)
    
    # Keys lexicographically: fork_choice, max_block_size, proof_scheme
    expected = bytearray()
    expected.extend(encode_uint32(3)) # num pairs
    
    # fork_choice (bool) -> tag 1
    expected.extend(encode_string("fork_choice"))
    expected.extend(b"\x01" + encode_bool(True))
    
    # max_block_size (int) -> tag 2
    expected.extend(encode_string("max_block_size"))
    expected.extend(b"\x02" + encode_uint32(1000))
    
    # proof_scheme (str) -> tag 3
    expected.extend(encode_string("proof_scheme"))
    expected.extend(b"\x03" + encode_string("bls"))
    
    assert encoded == bytes(expected)

def test_compute_update_id():
    from consensus.serialization import compute_update_id
    revisions = ["logic"]
    activate_at_height = 100
    
    id1 = compute_update_id(revisions, activate_at_height)
    id2 = compute_update_id(revisions, activate_at_height)
    assert id1 == id2
    assert len(id1) == 32
    
    id3 = compute_update_id(revisions, activate_at_height, patch={"a": 1})
    assert id1 != id3

def test_compute_checkpoint_hash():
    from consensus.serialization import compute_checkpoint_hash
    height = 50
    rules = "tau rules"
    accounts_hash = b"\x11" * 32
    meta_hash = b"\x22" * 32
    
    c_hash = compute_checkpoint_hash(height, rules, accounts_hash, meta_hash)
    assert len(c_hash) == 32
    
    with pytest.raises(ValueError):
        compute_checkpoint_hash(height, rules, b"\x11" * 31, meta_hash)

def test_encode_consensus_meta():
    from consensus.serialization import encode_consensus_meta, compute_consensus_meta_hash
    
    host_contract = {"version": 1}
    # out of order to test sorting
    val2 = b"\x22" * 48
    val1 = b"\x11" * 48
    active_validators = [val2, val1] 
    
    up2 = b"\xbb" * 32
    up1 = b"\xaa" * 32
    pending_updates = [up2, up1]
    
    # vote records (update_id, voter_pubkey) - sorting check: up2 first here, up1 second
    vote_records = [(up2, val1), (up1, val2), (up1, val1)]
    
    # schedule (height, update_id)
    sched = [(200, up1), (100, up2), (100, up1)]
    
    # checkpoints (height, checkpoint_hash)
    chk2 = b"\xdd" * 32
    chk1 = b"\xcc" * 32
    checkpoints = [(50, chk2), (40, chk1)]
    
    encoded = encode_consensus_meta(
        host_contract, active_validators, pending_updates,
        vote_records, sched, checkpoints, mechanism_specific_metadata=None
    )
    
    assert isinstance(encoded, bytes)
    assert len(encoded) > 0
    
    # Hash derivation test
    meta_hash = compute_consensus_meta_hash(
        host_contract, active_validators, pending_updates,
        vote_records, sched, checkpoints, mechanism_specific_metadata={"pow": True}
    )
    assert len(meta_hash) == 32
    
    meta_hash_2 = compute_consensus_meta_hash(
        host_contract, active_validators, pending_updates,
        vote_records, sched, checkpoints, mechanism_specific_metadata={"pow": True}
    )
    assert meta_hash == meta_hash_2
