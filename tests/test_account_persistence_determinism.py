"""Phase 9B root-cause regression — sequence-only accounts survive a reload.

The mine-vs-replay state-hash divergence at the first block a node mined AFTER
a restart (root-caused via the docker demo, demo/diagnostics/ROOT_CAUSE.md) was
NOT in the lifecycle/apply_block math (that path is deterministic) — it was in
persistence:

`db.save_canonical_state_atomically` wrote the accounts table by iterating
`balances.items()` only. A validator who submits a governance tx (proposal or
vote) but holds no funds gets its `sequence_number` incremented while never
appearing in `balances` — a "sequence-only" account. It was therefore dropped
on persist. `compute_consensus_state_hash`'s accounts_hash keys on
balances ∪ sequences, so after a restart the node reloaded a SMALLER account
set than a from-genesis replay reconstructs, and the next block it mined carried
a state hash every follower's replay rejected (rebuild abort -> frozen head).

These tests pin the fix: the sequence-only account round-trips, and the
accounts_hash is byte-identical before commit and after reload.
"""
import chain_state
from consensus.governance import ConsensusLifecycleManager

FUNDED = "8c" * 48       # 96-hex, has a balance
GOV_SENDER = "b5" * 48   # 96-hex, balance 0 but seq incremented (governance tx sender)


def test_sequence_only_account_survives_commit_reload(temp_database):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances[FUNDED] = 150000
    chain_state._sequence_numbers[FUNDED] = 0
    # GOV_SENDER exists ONLY in sequences (voted/proposed, holds no funds).
    chain_state._sequence_numbers[GOV_SENDER] = 1
    chain_state._application_rules_state = "app"
    chain_state._consensus_rules_state = "cons"
    chain_state._active_consensus_id = ""
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=[FUNDED])

    acc_before = chain_state.compute_accounts_hash(
        chain_state._balances, chain_state._sequence_numbers)

    chain_state.commit_state_to_db("head-hash", 8)
    # Clobber in-memory state (simulate a restart).
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    assert chain_state.load_state_from_db() is True

    # The sequence-only account must be restored (this is the fix).
    assert GOV_SENDER in chain_state._sequence_numbers, (
        "sequence-only governance sender was dropped on persist/reload"
    )
    assert chain_state.get_sequence_number(GOV_SENDER) == 1

    # And the accounts_hash — the actual consensus input — is unchanged, so a
    # node mining after this reload produces the same state hash as a replay.
    acc_after = chain_state.compute_accounts_hash(
        chain_state._balances, chain_state._sequence_numbers)
    assert acc_after == acc_before


def test_reload_accounts_hash_matches_prereset(temp_database):
    """A fuller mix: funded accounts, a funded+sequenced account, and two
    sequence-only senders. accounts_hash must survive the reload byte-for-byte."""
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances["8c" * 48] = 150000
    chain_state._balances["93" * 48] = 850000
    chain_state._sequence_numbers["93" * 48] = 1        # funded + sequenced
    chain_state._sequence_numbers["86" * 48] = 1        # sequence-only
    chain_state._sequence_numbers["8d" * 48] = 1        # sequence-only
    chain_state._application_rules_state = "app"
    chain_state._consensus_rules_state = "cons"
    chain_state._active_consensus_id = ""
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["8c" * 48])

    acc_before = chain_state.compute_accounts_hash(
        chain_state._balances, chain_state._sequence_numbers)

    chain_state.commit_state_to_db("head-hash", 9)
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    assert chain_state.load_state_from_db() is True

    for addr in ("86" * 48, "8d" * 48):
        assert chain_state.get_sequence_number(addr) == 1

    acc_after = chain_state.compute_accounts_hash(
        chain_state._balances, chain_state._sequence_numbers)
    assert acc_after == acc_before
