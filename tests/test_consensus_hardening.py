"""
Regression tests for the consensus-hardening fixes (see README "Consensus
boundary" and "State hash"):

  * Fix 1 — the governance vote-quorum policy is resolved deterministically
    (never from per-node config) and is bound into the consensus state hash.
    Without this, two nodes with a divergent TAU_VALIDATOR_VOTE_QUORUM could
    compute identical state hashes while reaching different governance
    outcomes — a silent fork.

  * Fix 2 — the governance activation delay is enforced in the engine block
    path, not only at mempool admission. A crafted block (which never passed
    admission) must not be able to submit a rule update that activates before
    the validator set can react — in the limit, reaching quorum and activating
    in the same block.
"""
from consensus.governance import ConsensusLifecycleManager, DEFAULT_QUORUM_POLICY
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot

# Distinct 96-hex (48-byte) validator pubkeys.
V1, V2, V3, V4, V5 = ("11" * 48, "22" * 48, "33" * 48, "44" * 48, "55" * 48)


def _make_lm(validators, quorum_policy=""):
    lm = ConsensusLifecycleManager(
        active_validators=[bytes.fromhex(v) for v in validators]
    )
    lm.quorum_policy = quorum_policy
    lm.recompute_approval_threshold()
    return lm


# --------------------------------------------------------------------------- #
# Fix 1: quorum bound into the state hash + deterministic resolution
# --------------------------------------------------------------------------- #

def test_quorum_policy_changes_meta_hash():
    """Two managers differing ONLY in resolved quorum policy must produce
    distinct consensus_meta_hash values, proving the policy is committed to
    consensus state (a config-driven divergence becomes a hash mismatch, not a
    silent fork)."""
    superm = _make_lm([V1, V2, V3], "supermajority")
    major = _make_lm([V1, V2, V3], "majority")
    assert superm.consensus_meta_hash() != major.consensus_meta_hash()


def test_meta_hash_stable_for_same_policy():
    """Same inputs => same hash (determinism / no accidental ordering deps)."""
    a = _make_lm([V3, V1, V2], "supermajority")
    b = _make_lm([V1, V2, V3], "supermajority")
    assert a.consensus_meta_hash() == b.consensus_meta_hash()


def test_empty_quorum_ignores_config(monkeypatch):
    """An unpinned quorum policy resolves to DEFAULT_QUORUM_POLICY regardless
    of the local config knob. N=5 is chosen so supermajority (4) and majority
    (3) thresholds differ, making the assertion sharp."""
    import config
    monkeypatch.setattr(
        config.settings.authority, "validator_vote_quorum", "majority", raising=False
    )
    lm = _make_lm([V1, V2, V3, V4, V5], quorum_policy="")  # genesis did not pin
    assert lm.effective_quorum_policy() == DEFAULT_QUORUM_POLICY == "supermajority"
    # supermajority of 5 = ceil(2*5/3) = 4; if config were consulted ("majority")
    # the threshold would be 3.
    assert lm.approval_threshold == 4


def test_genesis_pinned_majority_threshold():
    lm = _make_lm([V1, V2, V3, V4, V5], quorum_policy="majority")
    assert lm.effective_quorum_policy() == "majority"
    assert lm.approval_threshold == 3  # 5 // 2 + 1


# --------------------------------------------------------------------------- #
# Fix 2: activation delay enforced in the engine block path
# --------------------------------------------------------------------------- #

def _update_tx(activate_at_height, salt="a", sender=V1):
    return {
        "tx_type": "consensus_rule_update",
        "tx_id": f"u_{activate_at_height}_{salt}",
        "sender_pubkey": sender,
        "rule_revisions": [f"always (o6[t]:bv[16] = {{ 1 }}:bv[16]). % {salt}"],
        "activate_at_height": activate_at_height,
        "operations": {},
    }


def _apply_update(lm, tx, block_height):
    engine = TauConsensusEngine()
    snap = TauStateSnapshot(state_hash="0" * 64, tau_bytes=b"", metadata={})
    engine.apply(
        snap, [tx], 1_000_000_000,
        target_balances={}, target_sequences={},
        target_lifecycle=lm, block_height=block_height,
    )


def test_activation_delay_soft_no_op_when_too_early():
    """activate_at_height < block_height + N is a soft no-op: the update never
    enters pending, so it can never reach quorum or activate."""
    lm = _make_lm([V1, V2, V3, V4, V5])  # N = 5
    # min_activation = block_height(10) + 5 = 15; 14 is one short.
    _apply_update(lm, _update_tx(14), block_height=10)
    assert lm.pending_updates == set()
    assert lm.update_payloads == {}


def test_activation_delay_accepts_at_floor():
    """activate_at_height == block_height + N is accepted (boundary)."""
    lm = _make_lm([V1, V2, V3, V4, V5])  # N = 5, floor = 15
    _apply_update(lm, _update_tx(15), block_height=10)
    assert len(lm.pending_updates) == 1


def test_activation_delay_blocks_same_block_activation():
    """The headline attack: an update that wants to activate at the current
    block height is refused, so quorum-and-activate-in-one-block is impossible
    via the block path."""
    lm = _make_lm([V1, V2, V3, V4, V5])
    _apply_update(lm, _update_tx(10), block_height=10)  # activate == inclusion
    assert lm.pending_updates == set()


def test_activation_delay_skipped_without_block_height():
    """Legacy apply() calls that omit block_height keep the pre-fix behavior
    (no height floor), so non-consensus callers are unaffected."""
    lm = _make_lm([V1, V2, V3])
    engine = TauConsensusEngine()
    snap = TauStateSnapshot(state_hash="0" * 64, tau_bytes=b"", metadata={})
    engine.apply(
        snap, [_update_tx(1)], 1_000_000_000,
        target_balances={}, target_sequences={}, target_lifecycle=lm,
    )
    assert len(lm.pending_updates) == 1


# --------------------------------------------------------------------------- #
# Fix 4: block-header BLS signature is actually verified (host proof = i10)
# --------------------------------------------------------------------------- #

def _signed_block(sk_int, *, block_number=1, tamper=False):
    """Build a block whose consensus_proof is a real BLS sig over its header."""
    import hashlib
    from py_ecc.bls import G2Basic
    from block import Block

    pk_hex = G2Basic.SkToPk(sk_int).hex()
    block = Block.create(
        block_number=block_number,
        previous_hash="00" * 32,
        transactions=[],
        proposer_pubkey=pk_hex,
        state_hash="ab" * 32,
    )
    msg = hashlib.sha256(block.header.canonical_bytes()).digest()
    block.consensus_proof = G2Basic.Sign(sk_int, msg).hex()
    if tamper:
        # flip the header AFTER signing -> signature no longer matches
        block.header.state_hash = "cd" * 32
    return block


def test_block_verify_consensus_proof_accepts_valid_signature():
    assert _signed_block(0xA11CE).verify_consensus_proof() is True


def test_block_verify_consensus_proof_rejects_tampered_header():
    """A block re-signed body / mutated header must fail (no forging)."""
    assert _signed_block(0xA11CE, tamper=True).verify_consensus_proof() is False


def test_block_verify_consensus_proof_rejects_wrong_key():
    """consensus_proof signed by a different key than proposer_pubkey fails."""
    import hashlib
    from py_ecc.bls import G2Basic
    from block import Block

    proposer = G2Basic.SkToPk(0xA11CE).hex()
    block = Block.create(
        block_number=1, previous_hash="00" * 32, transactions=[],
        proposer_pubkey=proposer, state_hash="ab" * 32,
    )
    msg = hashlib.sha256(block.header.canonical_bytes()).digest()
    block.consensus_proof = G2Basic.Sign(0xB0B, msg).hex()  # signed by attacker key
    assert block.verify_consensus_proof() is False


def test_block_verify_consensus_proof_rejects_missing_proof():
    from block import Block
    block = Block.create(
        block_number=1, previous_hash="00" * 32, transactions=[],
        proposer_pubkey="11" * 48, state_hash="ab" * 32,
    )
    block.consensus_proof = None
    assert block.verify_consensus_proof() is False
    block.consensus_proof = "00" * 96  # well-formed length, not a valid sig
    assert block.verify_consensus_proof() is False


def test_block_verify_consensus_proof_genesis_exempt():
    """Block 0 is provisioned directly and carries no proposer signature."""
    from block import Block
    genesis = Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey="00" * 48, state_hash="ab" * 32,
    )
    genesis.consensus_proof = None
    assert genesis.verify_consensus_proof() is True
