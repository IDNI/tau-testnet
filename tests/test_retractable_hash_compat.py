import json
import subprocess
import sys
from pathlib import Path

from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.retractable import KIND_HEIGHT, RetractableBook, RetractableEntry
from consensus.state import compute_consensus_meta_hash

A = "a" * 96
B = "b" * 96
KEY = "retractable_transfers_root"


def test_meta_always_carries_the_root_key():
    mech = build_mechanism_metadata("supermajority")
    assert KEY in mech
    assert mech[KEY] == RetractableBook().root().hex()


def test_empty_book_root_deterministic():
    assert RetractableBook().root() == RetractableBook().root()
    assert len(RetractableBook().root()) == 32


def test_runtime_hash_matches_builder_for_empty_book():
    lm = ConsensusLifecycleManager()
    mech = build_mechanism_metadata(lm.effective_quorum_policy())
    expected = compute_consensus_meta_hash(
        host_contract={},
        active_validators=list(lm.active_validators),
        pending_updates=[],
        vote_records=[],
        activation_schedule=lm.scheduled_updates,
        checkpoint_references=[],
        mechanism_specific_metadata=mech,
    )
    assert lm.consensus_meta_hash() == expected


def test_runtime_hash_binds_the_book():
    lm = ConsensusLifecycleManager()
    empty = lm.consensus_meta_hash()
    rid = lm.retractable_transfers.submit(RetractableEntry(A, B, 5, 1, KIND_HEIGHT, 50))
    parked = lm.consensus_meta_hash()
    assert parked != empty
    lm.retractable_transfers.retract(rid)
    assert lm.consensus_meta_hash() not in (empty, parked)


def test_explicit_root_passes_through():
    assert build_mechanism_metadata("supermajority", retractable_transfers_root="ab" * 32)[KEY] == "ab" * 32


def test_gen_genesis_agrees_with_runtime(tmp_path):
    repo = Path(__file__).resolve().parent.parent
    out = tmp_path / "genesis.json"
    key = "11" * 32
    subprocess.run(
        [sys.executable, "scripts/gen_genesis.py", "--validator-privkey", key, "--out", str(out)],
        cwd=repo, check=True, capture_output=True,
    )
    genesis = json.loads(out.read_text())
    assert genesis["consensus_meta"]["mechanism_specific_metadata"][KEY] == RetractableBook().root().hex()
