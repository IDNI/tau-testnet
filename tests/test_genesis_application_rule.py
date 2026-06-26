"""
Regression guard for the genesis application rule (the i0 -> u[t] join).

Background: genesis.tau bootstraps a Tau interpreter whose only spec-update
mechanism is the conditional

    ((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)

Every rule the node applies (wallet policy AND consensus revisions) is fed on
i0 and joined into the running spec via the special `u` stream. A fragment that
was originally commented out --

    & { u[t] = i0[t] & { u[t] = i0[t] } }

-- was accidentally uncommented (commit 06af7a4) and then flattened onto one
line (a233af9), corrupting the rule in genesis.tau, data/genesis.json, and
networks/*/genesis.json. The native engine happens to normalize the garbage
away (0 & X = 0), so it stayed invisible -- but it is non-canonical and fragile
against any tau-lang build that parses `{ formula }` strictly.

These tests pin the canonical clean form and the internal hash consistency of
the genesis artifacts so the corruption (or a desynced hand-edit) cannot
reappear unnoticed.
"""
import json
import os
import sys
import unittest
from pathlib import Path

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from chain_state import compute_accounts_hash
from consensus.serialization import compute_consensus_meta_hash
from consensus.state import compute_consensus_state_hash
from block import Block, BlockHeader, sha256_hex

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRACKED_GENESIS_JSON = [
    os.path.join(project_root, "networks", "tau-testnet-v2", "genesis.json"),
]
# data/genesis.json is the runtime copy; include it only when present.
_runtime = os.path.join(project_root, "data", "genesis.json")
if os.path.exists(_runtime):
    TRACKED_GENESIS_JSON.append(_runtime)

# The corrupt fragment, in any spacing the flatten step could produce.
_CORRUPT_MARKER = "{ u[t]"


class TestGenesisApplicationRule(unittest.TestCase):
    def test_genesis_tau_uses_clean_i0_u_join(self):
        text = Path(GENESIS_TAU).read_text(encoding="utf-8")
        # The join mechanism must be present ...
        self.assertIn("u[t] = i0[t]", text)
        self.assertIn("o0[t] = 0", text)
        # ... and the accidentally-uncommented garbage tail must be gone.
        self.assertNotIn(
            _CORRUPT_MARKER, text,
            "genesis.tau carries the corrupt `& { u[t] = i0[t] & {...} }` tail; "
            "restore the clean `( u[t] = i0[t] && o0[t] = 0 )` form.",
        )

    def test_artifact_application_rules_match_genesis_tau(self):
        tau = Path(GENESIS_TAU).read_text(encoding="utf-8").strip()
        for path in TRACKED_GENESIS_JSON:
            with self.subTest(path=path):
                doc = json.loads(Path(path).read_text(encoding="utf-8"))
                self.assertEqual(
                    doc["application_rules"].strip(), tau,
                    f"{path} application_rules drifted from genesis.tau",
                )
                self.assertNotIn(_CORRUPT_MARKER, doc["application_rules"])

    def test_artifact_hashes_are_internally_consistent(self):
        """state_hash and block hash must recompute from the artifact's own
        committed domains -- guards against a hand-edit of application_rules
        that forgets to refresh the dependent hashes."""
        for path in TRACKED_GENESIS_JSON:
            with self.subTest(path=path):
                g = json.loads(Path(path).read_text(encoding="utf-8"))
                meta = g["consensus_meta"]
                accts = {a: int(b) for a, b in g["accounts_state"].items()}
                accounts_hash = compute_accounts_hash(accts, {a: 0 for a in accts})
                meta_hash = compute_consensus_meta_hash(
                    host_contract={
                        "proof_scheme": meta["proof_scheme"],
                        "fork_choice_scheme": meta["fork_choice_scheme"],
                        "input_contract_version": meta["input_contract_version"],
                    },
                    active_validators=[bytes.fromhex(v) for v in meta["active_validators"]],
                    pending_updates=[],
                    vote_records=[],
                    activation_schedule=[],
                    checkpoint_references=[],
                    mechanism_specific_metadata=meta.get("mechanism_specific_metadata") or {},
                )
                state_hash = compute_consensus_state_hash(
                    g["consensus_rules"].encode("utf-8"),
                    g["application_rules"].encode("utf-8"),
                    accounts_hash,
                    meta_hash,
                )
                hdr = g["block_0"]["header"]
                self.assertEqual(
                    state_hash, hdr["state_hash"],
                    f"{path}: header.state_hash stale vs recomputed",
                )
                block_hash = sha256_hex(BlockHeader(
                    block_number=hdr["block_number"],
                    previous_hash=hdr["previous_hash"],
                    timestamp=hdr["timestamp"],
                    merkle_root=hdr["merkle_root"],
                    state_hash=hdr["state_hash"],
                    proposer_pubkey=hdr["proposer_pubkey"],
                ).canonical_bytes())
                self.assertEqual(
                    block_hash, g["block_0"]["hash"],
                    f"{path}: block_0.hash stale vs recomputed header",
                )
                # Block.from_dict must agree too.
                self.assertEqual(Block.from_dict(g["block_0"]).block_hash, g["block_0"]["hash"])


if __name__ == "__main__":
    unittest.main()
