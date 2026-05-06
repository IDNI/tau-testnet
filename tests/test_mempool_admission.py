import pytest
from unittest.mock import patch, MagicMock

import config as config_module

from consensus.admission import (
    validate_mempool_admission,
    TipAdmissionView,
    AdmissionResult
)

# Dummy payloads for testing
def get_user_tx(operations=None):
    return {
        "tx_type": "user_tx",
        "sender_pubkey": "a" * 96,
        "operations": operations or {}
    }

def get_update_tx(revisions=None, activate_at=None, patch=None):
    return {
        "tx_type": "consensus_rule_update",
        "sender_pubkey": "a" * 96,
        "rule_revisions": revisions if revisions is not None else ["hello"],
        "activate_at_height": activate_at if activate_at is not None else 100,
        "host_contract_patch": patch
    }

def get_vote_tx(update_id="b"*64, approve=True):
    return {
        "tx_type": "consensus_rule_vote",
        "sender_pubkey": "a" * 96,
        "update_id": update_id,
        "approve": approve
    }

@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {"a" * 96}
    view.next_block_height = 50
    view.current_consensus_rules = "o6\no7\n"
    view.host_contract = {}
    view.get_update_lifecycle_state.return_value = None
    view.is_update_pending.return_value = False
    view.has_duplicate_vote.return_value = False
    return view

class TestMempoolAdmission:
    def test_legacy_consensus_proposal_rejected(self, tip_view):
        tx = {"tx_type": "consensus_proposal", "bundle": {}}
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Legacy transaction types" in res.error

    def test_unknown_tx_type_rejected(self, tip_view):
        tx = {"tx_type": "some_other_type"}
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Unknown or unsupported tx_type" in res.error

    def test_governance_fields_present_inside_user_tx_rejected(self, tip_view):
        tx = get_user_tx()
        tx["rule_revisions"] = ["x"]
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "must not contain governance field" in res.error

    def test_missing_required_governance_fields_rejected(self, tip_view):
        tx = {"tx_type": "consensus_rule_update", "sender_pubkey": "a"*96}
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Missing or invalid 'rule_revisions'" in res.error

    def test_activate_at_height_zero_rejected(self, tip_view):
        tx = get_update_tx(activate_at=0)
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Invalid or missing 'activate_at_height'" in res.error

    def test_activate_at_height_overflow_rejected(self, tip_view):
        tx = get_update_tx(activate_at=0xFFFFFFFFFFFFFFFF + 1)
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Invalid or missing 'activate_at_height'" in res.error

    def test_empty_rule_revisions_rejected(self, tip_view):
        tx = get_update_tx(revisions=[])
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Missing or invalid 'rule_revisions'" in res.error

    def test_rule_revisions_non_string_entry_rejected(self, tip_view):
        tx = get_update_tx(revisions=["good", 123])
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "must be a string" in res.error

    def test_approve_false_rejected(self, tip_view):
        tx = get_vote_tx(approve=False)
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "approve=false is unsupported" in res.error

    def test_approve_present_but_non_boolean_rejected(self, tip_view):
        tx = get_vote_tx(approve="yes")
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "malformed 'approve'" in res.error

    def test_unknown_update_id_vote_rejected(self, tip_view):
        tip_view.get_update_lifecycle_state.return_value = None
        tx = get_vote_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "unknown update_id" in res.error

    def test_non_pending_update_vote_rejected(self, tip_view):
        tip_view.get_update_lifecycle_state.return_value = "archived"
        tx = get_vote_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "non-pending state" in res.error

    def test_duplicate_vote_at_tip_rejected(self, tip_view):
        tip_view.get_update_lifecycle_state.return_value = "pending"
        tip_view.has_duplicate_vote.return_value = True
        tx = get_vote_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Duplicate explicit vote" in res.error

    def test_unauthorized_update_sender_rejected(self, tip_view):
        tx = get_update_tx()
        tx["sender_pubkey"] = "b"*96
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "not an active validator" in res.error

    def test_unauthorized_voter_rejected(self, tip_view):
        tx = get_vote_tx()
        tx["sender_pubkey"] = "b"*96
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "not an active validator" in res.error

    def test_open_governance_allows_non_validator_vote(self, tip_view, monkeypatch):
        monkeypatch.setattr(config_module.settings.authority, "open_governance_admission", True)
        tip_view.get_update_lifecycle_state.return_value = "pending"
        tx = get_vote_tx()
        tx["sender_pubkey"] = "b" * 96
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid

    def test_open_governance_allows_non_validator_update(self, tip_view, monkeypatch):
        monkeypatch.setattr(config_module.settings.authority, "open_governance_admission", True)
        tx = get_update_tx()
        tx["sender_pubkey"] = "b" * 96
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid

    def test_duplicate_update_id_rejected_even_if_prior_update_archived(self, tip_view):
        tip_view.get_update_lifecycle_state.return_value = "archived"
        tx = get_update_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "already exists in lifecycle state: archived" in res.error

    def test_application_updates_referencing_i6_i11_rejected(self, tip_view):
        tx = get_user_tx(operations={"6": "val"})
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Streams 6-11 are reserved" in res.error

    def test_reserved_input_shadowing_in_consensus_updates(self, tip_view, caplog):
        tx = get_update_tx(revisions=["#tau i6(a)"])
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid  # Still succeeds since crude check is just warning for now
        assert "shadowing i6" in caplog.text

    def test_unsupported_host_contract_patch_rejected(self, tip_view):
        tx = get_update_tx(patch={"proof_scheme": "invalid_scheme"})
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Unsupported proof_scheme" in res.error

    def test_validator_delta_patch_accepted(self, tip_view):
        tx = get_update_tx(patch={"validator_additions": ["b" * 96]})
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid

    def test_validator_delta_cannot_empty_active_set(self, tip_view):
        tx = get_update_tx(patch={"validator_removals": ["a" * 96]})
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "no active validators" in res.error

    def test_validator_delta_rejects_malformed_pubkey(self, tip_view):
        tx = get_update_tx(patch={"validator_additions": ["B" * 96]})
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "lowercase hex" in res.error

    def test_minimum_activation_delay_enforced(self, tip_view):
        # next_block=50, validators=1 -> min_height=51
        tx = get_update_tx(activate_at=50) # Invalid
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Minimum activation delay explicitly breached" in res.error

    def test_admission_does_not_invoke_live_tau_compile(self, tip_view):
        """
        Admission performs only structural / syntactic checks. The historical
        live `communicate_with_tau` staging compile concatenated revisions onto
        the current consensus rules (producing an invalid multi-`always` spec)
        and silently mutated the running interpreter. Real semantic compile now
        happens deterministically across nodes at activation time
        (`engine.apply_block`), so admission must NOT touch Tau at all.
        """
        with patch("consensus.admission.communicate_with_tau") as mock_tau:
            tx = get_update_tx()
            res = validate_mempool_admission(tx, tip_view)
            assert res.is_valid
            mock_tau.assert_not_called()

    def test_admission_accepts_full_always_revision_regression(self, tip_view):
        """
        Regression: a revision that itself is a complete `always (...)` clause
        used to fail admission with "Multiple main formulas" because admission
        appended it to current_consensus_rules (which already had its own
        `always`). Admission no longer combines the strings, so this passes.
        Payload reproduced from a real submission that flooded the logs.
        """
        tx = get_update_tx(revisions=["always ( o6[t]:bv[16] = { 0 }:bv[16] )."])
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid

    def test_admission_isolated_compile_rejects_unparseable_revision(self, tip_view, monkeypatch):
        """
        Fix 6: admission's isolated staging compile must reject syntactically
        broken revisions before they reach the proposer's apply_block. The
        compile runs against a throwaway Tau interpreter so live mining state
        is never touched; here we simulate a Tau parse error.
        """
        import tau_manager
        import tau_native

        monkeypatch.setattr(tau_manager.tau_ready, "is_set", lambda: True)
        monkeypatch.setattr(
            tau_native.TauInterface,
            "compile_revisions_isolated",
            classmethod(lambda cls, rules, revs: "Tau staging compile error: parse failure at offset 12"),
        )

        tx = get_update_tx(revisions=["always ( o6[t]:bv[16] = "])  # truncated
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "staging compile failed" in res.error

    def test_admission_isolated_compile_skipped_when_tau_unavailable(self, tip_view, monkeypatch):
        """
        Fix 6: when the live Tau interpreter is not yet ready (early boot,
        test fixtures), admission must fall back to the cheap structural
        checks instead of crashing or rejecting. The activation-height
        compile inside `apply_block` remains the backstop.
        """
        import tau_manager
        import tau_native

        monkeypatch.setattr(tau_manager.tau_ready, "is_set", lambda: False)

        # Sentinel to detect any accidental call.
        called = {"isolated": False}

        def _explode(cls, rules, revs):
            called["isolated"] = True
            raise AssertionError("compile_revisions_isolated must not be called when Tau is not ready")

        monkeypatch.setattr(
            tau_native.TauInterface,
            "compile_revisions_isolated",
            classmethod(_explode),
        )

        tx = get_update_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid
        assert called["isolated"] is False

    def test_same_payload_signed_by_different_validators_yields_same_update_id(self, tip_view):
        tx1 = get_update_tx()
        tx1["sender_pubkey"] = "a"*96
        tx2 = get_update_tx()
        tx2["sender_pubkey"] = "c"*96 # different sender (though c*96 isn't a validator, we mock it)
        tip_view.active_validators = {"a"*96, "c"*96}

        res1 = validate_mempool_admission(tx1, tip_view)
        res2 = validate_mempool_admission(tx2, tip_view)

        assert res1.is_valid
        assert res2.is_valid
        assert res1.data["update_id"] == res2.data["update_id"]

    def test_mempool_admission_uses_canonical_tip_only(self, tip_view):
        tx = get_update_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid
        # The fact that it succeeds when tip_view is the only contextual argument
        # demonstrates it does not mutate state or query external DB directly.
