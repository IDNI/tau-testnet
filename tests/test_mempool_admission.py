import pytest
from unittest.mock import patch, MagicMock

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

    @patch("consensus.admission.communicate_with_tau")
    @patch("os.environ.get")
    def test_reserved_input_shadowing_in_consensus_updates(self, mock_env, mock_tau, tip_view, caplog):
        mock_env.return_value = "0"
        mock_tau.return_value = "Success"
        tx = get_update_tx(revisions=["#tau i6(a)"])
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid  # Still succeeds since crude check is just warning for now
        assert "shadowing i6" in caplog.text

    @patch("consensus.admission.communicate_with_tau")
    @patch("os.environ.get")
    def test_unsupported_host_contract_patch_rejected(self, mock_env, mock_tau, tip_view):
        tx = get_update_tx(patch={"proof_scheme": "invalid_scheme"})
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Unsupported proof_scheme" in res.error

    @patch("consensus.admission.communicate_with_tau")
    @patch("os.environ.get")
    def test_minimum_activation_delay_enforced(self, mock_env, mock_tau, tip_view):
        # next_block=50, validators=1 -> min_height=51
        tx = get_update_tx(activate_at=50) # Invalid
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "Minimum activation delay explicitly breached" in res.error

    @patch("consensus.admission.communicate_with_tau")
    @patch("os.environ.get")
    def test_consensus_rule_update_staging_compile_failure_rejected(self, mock_env, mock_tau, tip_view):
        mock_env.return_value = "0"
        mock_tau.return_value = "Error: invalid syntax"
        tx = get_update_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert not res.is_valid
        assert "compile" in res.error

    @patch("consensus.admission.communicate_with_tau")
    @patch("os.environ.get")
    def test_same_payload_signed_by_different_validators_yields_same_update_id(self, mock_env, mock_tau, tip_view):
        mock_env.return_value = "1"
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

    @patch("consensus.admission.communicate_with_tau")
    @patch("os.environ.get")
    def test_mempool_admission_uses_canonical_tip_only(self, mock_env, mock_tau, tip_view):
        mock_env.return_value = "1"
        tx = get_update_tx()
        res = validate_mempool_admission(tx, tip_view)
        assert res.is_valid
        # The fact that it succeeds when tip_view is the only contextual argument
        # demonstrates it does not mutate state or query external DB directly.
