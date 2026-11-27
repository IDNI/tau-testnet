"""An op-0 user_tx meets the same rule screens at block apply as at admission.

A proposer can include a tx that never passed admission, so apply runs the shared
rule screen on every path, replay included, and refuses reserved operation keys.
"""
import hashlib

import pytest
from py_ecc.bls import G2Basic
from unittest.mock import MagicMock, patch

from block import Block
from consensus.admission import TipAdmissionView, validate_mempool_admission
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

pytestmark = pytest.mark.usefixtures("mock_policy_evaluators")

HEIGHT = 20
TX_ID = "tx"
FUNDS = 100000


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)      # rule author
SK_MALLORY, MALLORY = _key(66666)  # block proposer

GUARD = f"(i12[t]:bv[384] = {{ #x{ALICE} }}:bv[384])"
ZERO = "{ #x000000 }:bv[24]"

# context -> (approval slots active, eligibility mode)
CONTEXTS = {
    "slots_off": (False, ""),
    "slots_on": (True, ""),
    "validator_set": (False, "tau_validator_set"),
}

# Reason slug the apply receipt carries, and the admission code it must match.
REASON_TO_CODE = {
    "reserved_output_stream": "TX_REJECTED",
    "fee_reads_balance": "TX_REJECTED",
    "reserved_input_stream": "TX_REJECTED",
    "rule_fragment": "RULE_FRAGMENT",
    "reserved_operation_key": "TX_REJECTED",
    "temporal_reference": "TEMPORAL_REFERENCE",
    "unscoped_user_rule": "UNSCOPED_USER_RULE",
    "width_mismatch": "WIDTH_MISMATCH",
    "mixed_output_rule": "MIXED_OUTPUT_RULE",
    "rule_with_transfers": "RULE_WITH_TRANSFERS",
    # A sender-guarded o5 rule is the wrong shape for a routed clause.
    "rule_not_applied": "CLAUSE_SHAPE",
}

I14 = "always ( o13[t]:bv[24] = i14[t]:bv[24] )."
I15 = "always ( o13[t]:bv[24] = i15[t]:bv[24] )."
I13 = "always ( o13[t]:bv[24] = i13[t]:bv[24] )."
I18 = "always ( o13[t]:bv[24] = i18[t]:bv[24] )."
I18_UNTYPED = "always ( o13[t]:bv[24] = i18[t] )."
I25 = "always ( o13[t]:bv[384] = i25[t]:bv[384] )."
O8_READS_I2 = (
    f"always ( {GUARD} ? (o8[t]:bv[24] = i2[t]:bv[24]) : (o8[t]:bv[24] = {ZERO}) )."
)
UNSCOPED_O5 = f"always ( o5[t]:bv[24] = {ZERO} )."
UNSCOPED_O8 = "always ( o8[t]:bv[24] = { #x0f4240 }:bv[24] )."
MIXED_O5_O8 = f"always ( o5[t]:bv[24] = {{ #x000001 }}:bv[24] && o8[t]:bv[24] = {ZERO} )."
ROUTED_O5 = "always ( o5[t]:bv[24] = i1[t]:bv[24] )."
FREE_I1 = "always ( o13[t]:bv[24] = i1[t]:bv[24] )."
GUARDED_O8_I1 = (
    f"always ( {GUARD} ? (o8[t]:bv[24] = i1[t]:bv[24]) : (o8[t]:bv[24] = {ZERO}) )."
)
GUARDED_O5 = f"always ( {GUARD} -> (o5[t]:bv[24] = {ZERO}) )."
U_RULE = "always ( u[t] = 0 )."
THIS_READ = "always ( o13[t]:bv[24] = this[t] )."
UNKNOWN_STREAM = "always ( foo[t] = 0 )."
ROUTED_O5_WRITING_U = (
    "always ( o5[t]:bv[24] = i1[t]:bv[24] && "
    "u[t] = { o5[t]:bv[24] = { #x000002 }:bv[24] }:tau )."
)

UNTYPED_FREE = "always ( o13[t] = i1[t]:bv[24] )."
OPERATOR_FREE = "always ( F ( o13[t]:bv[24] = i1[t]:bv[24] ) )."
CONSTRAINT_FREE = "always ( [t > 3] && o13[t]:bv[24] = i1[t]:bv[24] )."
EXISTS_FREE = "always ( ex x ( o13[t]:bv[24] = i1[t]:bv[24] ) )."
TWO_UNITS_FREE = f"{FREE_I1} always ( o14[t]:bv[24] = i1[t]:bv[24] )."
OUTSIDE_CONJUNCT_FREE = f"{FREE_I1[:-1]} && ( o14[t]:bv[24] = i1[t]:bv[24] )."
LOOKBACK_FREE = "always ( o13[t]:bv[24] = i1[t-1]:bv[24] )."
OPERATOR_ROUTED_O5 = "always ( o5[t]:bv[24] = i1[t]:bv[24] && F ( i1[t]:bv[24] = 1 ) )."
UNTYPED_ROUTED_O5 = "always ( o5[t]:bv[24] = i1[t] )."

TRANSFER = {"1": [[ALICE, MALLORY, "10"]]}

# Accumulated-rule rows refused at apply: (rule, context, reason slug).
REFUSED_RULES = [
    pytest.param(I14, "slots_off", "reserved_input_stream", id="i14-slots-off"),
    pytest.param(I14, "slots_on", "reserved_input_stream", id="i14-slots-on"),
    pytest.param(I15, "slots_off", "reserved_input_stream", id="i15-slots-off"),
    pytest.param(I15, "slots_on", "reserved_input_stream", id="i15-slots-on"),
    pytest.param(I13, "validator_set", "reserved_input_stream", id="i13-validator-set"),
    pytest.param(I18, "slots_on", "reserved_input_stream", id="i18-bv24"),
    pytest.param(I18_UNTYPED, "slots_on", "rule_fragment", id="i18-untyped"),
    pytest.param(I25, "slots_on", "reserved_input_stream", id="i25-bv384"),
    pytest.param(O8_READS_I2, "slots_off", "fee_reads_balance", id="o8-reads-i2-slots-off"),
    pytest.param(O8_READS_I2, "slots_on", "fee_reads_balance", id="o8-reads-i2-slots-on"),
    pytest.param(UNSCOPED_O8, "slots_off", "unscoped_user_rule", id="unscoped-o8-slots-off"),
    pytest.param(UNSCOPED_O8, "slots_on", "unscoped_user_rule", id="unscoped-o8-slots-on"),
    pytest.param(U_RULE, "slots_off", "rule_fragment", id="u-rule-slots-off"),
    pytest.param(U_RULE, "slots_on", "rule_fragment", id="u-rule-slots-on"),
    pytest.param(THIS_READ, "slots_off", "rule_fragment", id="this-read"),
    pytest.param(UNKNOWN_STREAM, "slots_off", "rule_fragment", id="unknown-stream"),
    pytest.param(UNTYPED_FREE, "slots_off", "rule_fragment", id="untyped-stream"),
    pytest.param(OPERATOR_FREE, "slots_on", "rule_fragment", id="operator-word"),
    pytest.param(CONSTRAINT_FREE, "slots_off", "rule_fragment", id="time-constraint"),
    pytest.param(EXISTS_FREE, "slots_off", "rule_fragment", id="quantifier"),
    pytest.param(TWO_UNITS_FREE, "slots_off", "rule_fragment", id="two-units"),
    pytest.param(OUTSIDE_CONJUNCT_FREE, "slots_off", "rule_fragment", id="outside-conjunct"),
    pytest.param(LOOKBACK_FREE, "slots_off", "temporal_reference", id="lookback"),
]

# Every shape the parity matrix runs in every context: (rule or None, extra operations).
MATRIX_ROWS = {
    "i14": (I14, {}),
    "i15": (I15, {}),
    "i13": (I13, {}),
    "i18": (I18, {}),
    "i18_untyped": (I18_UNTYPED, {}),
    "i25": (I25, {}),
    "o8_reads_i2": (O8_READS_I2, {}),
    "unscoped_o5": (UNSCOPED_O5, {}),
    "unscoped_o8": (UNSCOPED_O8, {}),
    "mixed_o5_o8": (MIXED_O5_O8, {}),
    "routed_with_transfer": (ROUTED_O5, TRANSFER),
    "u_rule": (U_RULE, {}),
    "this_read": (THIS_READ, {}),
    "unknown_stream": (UNKNOWN_STREAM, {}),
    "untyped_stream": (UNTYPED_FREE, {}),
    "operator_word": (OPERATOR_FREE, {}),
    "time_constraint": (CONSTRAINT_FREE, {}),
    "quantifier": (EXISTS_FREE, {}),
    "two_units": (TWO_UNITS_FREE, {}),
    "outside_conjunct": (OUTSIDE_CONJUNCT_FREE, {}),
    "lookback": (LOOKBACK_FREE, {}),
    "routed_operator_word": (OPERATOR_ROUTED_O5, {}),
    "routed_untyped": (UNTYPED_ROUTED_O5, {}),
    "opkey_18": (None, {"18": "5"}),
    "opkey_18_with_rule": (FREE_I1, {"18": "5"}),
    "ctl_free_i1": (FREE_I1, {}),
    "ctl_guarded_o8_i1": (GUARDED_O8_I1, {}),
    "ctl_guarded_o5": (GUARDED_O5, {}),
    "ctl_routed_o5": (ROUTED_O5, {}),
}


def _tip(slots, mode):
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {ALICE}
    view.next_block_height = 50
    view.eligibility_mode = mode
    view.approval_slots_active = slots
    view.clause_for.return_value = None
    return view


def _tx(rule, extra=None):
    operations = dict(extra or {})
    if rule is not None:
        operations["0"] = rule
    tx = {"tx_id": TX_ID, "tx_type": "user_tx", "sender_pubkey": ALICE,
          "sequence_number": 0, "expiration_time": 9999999999,
          "expire_at_height": 5000, "fee_limit": "100", "operations": operations}
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(SK_ALICE, digest).hex()
    return tx


def _apply(tx, context, *, replay_mode=False):
    """Apply one tx; returns (result, post lifecycle, rule texts fed, custom steps fed)."""
    slots, mode = CONTEXTS[context]
    lm = ConsensusLifecycleManager(active_validators=[MALLORY])
    if mode:
        lm.eligibility_mode = mode
    if slots:
        lm.activate_approval_slots()
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: FUNDS, MALLORY: FUNDS},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": slots},
    )
    block = Block.create(block_number=HEIGHT, previous_hash="00" * 32, transactions=[tx],
                         proposer_pubkey=MALLORY, timestamp=1234567890)
    fed, persisted, steps = [], [], []

    def _single(**kw):
        text = str(kw.get("rule_text") or "")
        if text:
            fed.append(text)
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def _multi(**kw):
        steps.append(kw)
        return {1: "1", 5: "1", 8: "0", 9: "0"}

    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = TauConsensusEngine().apply_block(
            view, block, parent, replay_mode=replay_mode)
    return result, result.next_snapshot.metadata["lifecycle_manager"], fed, steps


def _outcome(result):
    return next(o for o in result.outcomes if o.tx_id == TX_ID)


def _balances(result):
    balances = result.next_snapshot.metadata["balances"]
    return {ALICE: balances.get(ALICE), MALLORY: balances.get(MALLORY)}


def _admit(tx, context):
    return validate_mempool_admission(tx, _tip(*CONTEXTS[context]))


def _assert_refused_untouched(result, fed, reason):
    assert TX_ID in result.invalid_tx_ids
    assert result.accepted_tx_ids == []
    assert _outcome(result).reason == reason
    assert fed == []
    assert _balances(result) == {ALICE: FUNDS, MALLORY: FUNDS}


# --- accumulated rule ---------------------------------------------------------

@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("rule,context,reason", REFUSED_RULES)
def test_apply_refuses_an_accumulated_rule_admission_refuses(rule, context, reason, replay_mode):
    result, _, fed, _ = _apply(_tx(rule), context, replay_mode=replay_mode)
    _assert_refused_untouched(result, fed, reason)


@pytest.mark.parametrize("context", ["slots_off", "slots_on"])
def test_apply_keeps_a_scoped_fee_rule_and_a_free_stream_rule(context):
    for rule in (GUARDED_O8_I1, FREE_I1):
        result, _, fed, _ = _apply(_tx(rule), context)
        assert result.accepted_tx_ids == [TX_ID]
        assert any(rule in text for text in fed)


@pytest.mark.parametrize("context", ["slots_off", "slots_on"])
def test_apply_never_accumulates_a_guarded_o5_rule(context):
    result, post, fed, _ = _apply(_tx(GUARDED_O5), context)
    _assert_refused_untouched(result, fed, "rule_not_applied")
    assert post.rule_offers.clause_for(ALICE, 5) is None


def test_apply_keeps_a_custom_input_read_that_is_not_reserved():
    result, _, fed, _ = _apply(_tx(I13), "slots_off")
    assert result.accepted_tx_ids == [TX_ID]
    assert any(I13 in text for text in fed)


# --- routed o5 clause ---------------------------------------------------------

@pytest.mark.parametrize("context", ["slots_off", "slots_on"])
@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("rule,extra,reason", [
    pytest.param(MIXED_O5_O8, {}, "mixed_output_rule", id="mixed-o5-o8"),
    pytest.param(ROUTED_O5, TRANSFER, "rule_with_transfers", id="rule-with-transfers"),
])
def test_apply_refuses_a_routed_clause_admission_refuses(rule, extra, reason, replay_mode, context):
    result, post, fed, steps = _apply(_tx(rule, extra), context, replay_mode=replay_mode)
    _assert_refused_untouched(result, fed, reason)
    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert steps == []


@pytest.mark.parametrize("context", ["slots_off", "slots_on"])
@pytest.mark.parametrize("replay_mode", [False, True])
def test_apply_refuses_a_routed_clause_that_writes_the_update_stream(replay_mode, context):
    result, post, fed, steps = _apply(
        _tx(ROUTED_O5_WRITING_U), context, replay_mode=replay_mode)
    assert TX_ID in result.invalid_tx_ids
    assert fed == []
    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert steps == []


@pytest.mark.parametrize("context", list(CONTEXTS))
def test_apply_registers_a_routed_clause_that_passes_the_screen(context):
    result, post, fed, _ = _apply(_tx(ROUTED_O5), context)
    assert result.accepted_tx_ids == [TX_ID]
    assert post.rule_offers.clause_for(ALICE, 5) is not None
    assert not any("o5[t]" in text for text in fed)


# --- operation keys -----------------------------------------------------------

@pytest.mark.parametrize("replay_mode", [False, True])
def test_apply_refuses_an_approval_slot_operation_key_once_slots_are_on(replay_mode):
    result, _, fed, steps = _apply(_tx(None, {"18": "5"}), "slots_on", replay_mode=replay_mode)
    _assert_refused_untouched(result, fed, "reserved_operation_key")
    assert steps == []


def test_a_slot_key_is_an_ordinary_custom_input_before_activation():
    tx = _tx(None, {"18": "5"})
    assert _admit(tx, "slots_off").is_valid
    result, _, _, steps = _apply(tx, "slots_off")
    assert result.accepted_tx_ids == [TX_ID]
    assert any(step["input_stream_values"].get(18) == ["5"] for step in steps)


# --- admission and apply agree ------------------------------------------------

@pytest.mark.parametrize("context", list(CONTEXTS))
@pytest.mark.parametrize("row", list(MATRIX_ROWS))
def test_admission_and_apply_reach_the_same_verdict(row, context):
    rule, extra = MATRIX_ROWS[row]
    admitted = _admit(_tx(rule, extra), context)
    result, _, _, _ = _apply(_tx(rule, extra), context)

    refused_at_apply = TX_ID in result.invalid_tx_ids
    assert (not admitted.is_valid) == refused_at_apply, (admitted.code, admitted.error)
    if refused_at_apply:
        assert REASON_TO_CODE[_outcome(result).reason] == admitted.code
