"""Resource limits on the op-0 rules that accumulate in the shared spec.

Every accepted occurrence counts, repeats included, and the counters never
decrease. Admission and block apply run one check against the same numbers.
"""
import itertools
from dataclasses import asdict, replace
from unittest.mock import MagicMock, patch

import pytest

from block import Block
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from consensus import sender_policy
from consensus.admission import (
    RULE_BUDGET_CODE,
    RULE_BUDGET_REASON,
    TipAdmissionView,
    _check_host_contract_patch,
    counts_toward_shared_budget,
    shared_rule_budget_error,
    shared_rule_shape,
    validate_mempool_admission,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import (
    DEFAULT_SHARED_RULE_LIMITS,
    HOST_CONTRACT_PATCH_KEYS,
    ConsensusLifecycleManager,
    SharedRuleLimits,
    build_mechanism_metadata,
    validate_shared_rule_limits,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_fragment import MAX_WIDTH, RuleShape
from consensus.serialization import compute_update_id
from consensus.state import TauStateSnapshot

pytestmark = pytest.mark.usefixtures("mock_policy_evaluators")

OFFERER = pubkey_hex(SK_ALICE)
ACCEPTOR = pubkey_hex(SK_BOB)
AUTHOR = pubkey_hex(SK_CAROL)
HEIGHT = 20
GOOD_LIMITS = asdict(DEFAULT_SHARED_RULE_LIMITS)
ZERO = "{ #x000000 }:bv[24]"
ROUTED_O5 = "always ( o5[t]:bv[24] = i1[t]:bv[24] )."


def rule(k: int) -> str:
    """Three nodes, depth two, on a free output stream."""
    return f"always ( o{12 + k}[t]:bv[24] = i1[t]:bv[24] )."


def chain_rule(comparisons: int) -> str:
    """4n-1 nodes, n+1 levels deep."""
    cmp = "o12[t]:bv[24] = i1[t]:bv[24]"
    return "always ( " + " && ".join([cmp] * comparisons) + " )."


WIDE_RULE = (
    f"always ((i12[t]:bv[384] = {{ #x{AUTHOR} }}:bv[384]) -> o12[t]:bv[24] = {ZERO})."
)


# --- limits validation --------------------------------------------------------

def _with(**changes):
    return {**GOOD_LIMITS, **changes}


def test_defaults():
    assert DEFAULT_SHARED_RULE_LIMITS == SharedRuleLimits(
        occurrences=10, total_nodes=80, rule_nodes=32, rule_depth=8,
        rule_bytes=1024, width=384,
    )
    assert DEFAULT_SHARED_RULE_LIMITS.width == MAX_WIDTH
    assert validate_shared_rule_limits(GOOD_LIMITS) is None
    assert "shared_rule_limits" in HOST_CONTRACT_PATCH_KEYS


GOOD_VALUES = [
    _with(occurrences=0, total_nodes=0),
    _with(occurrences=2**31 - 1, total_nodes=2**31 - 1),
    _with(rule_nodes=1, rule_depth=1, rule_bytes=1, width=1),
    _with(rule_nodes=2**31 - 1, rule_depth=2**31 - 1, rule_bytes=2**31 - 1),
]

BAD_VALUES = [
    pytest.param(None, id="none"),
    pytest.param([], id="list"),
    pytest.param({}, id="empty"),
    pytest.param({k: v for k, v in GOOD_LIMITS.items() if k != "width"}, id="missing-key"),
    pytest.param({**GOOD_LIMITS, "extra": 1}, id="extra-key"),
    pytest.param(_with(occurrences=True), id="bool-occurrences"),
    pytest.param(_with(width=True), id="bool-width"),
    pytest.param(_with(occurrences="10"), id="string"),
    pytest.param(_with(occurrences=1.0), id="float"),
    pytest.param(_with(occurrences=-1), id="negative-occurrences"),
    pytest.param(_with(total_nodes=-1), id="negative-total"),
    pytest.param(_with(occurrences=2**31), id="occurrences-high"),
    pytest.param(_with(total_nodes=2**31), id="total-high"),
    pytest.param(_with(rule_nodes=0), id="rule-nodes-zero"),
    pytest.param(_with(rule_depth=0), id="rule-depth-zero"),
    pytest.param(_with(rule_bytes=0), id="rule-bytes-zero"),
    pytest.param(_with(rule_nodes=2**31), id="rule-nodes-high"),
    pytest.param(_with(width=0), id="width-zero"),
    pytest.param(_with(width=385), id="width-385"),
]


@pytest.mark.parametrize("value", GOOD_VALUES)
def test_good_limits_validate(value):
    assert validate_shared_rule_limits(value) is None


@pytest.mark.parametrize("value", BAD_VALUES)
def test_bad_limits_are_refused(value):
    assert isinstance(validate_shared_rule_limits(value), str)


# --- the check ----------------------------------------------------------------

LIMITS = SharedRuleLimits(
    occurrences=3, total_nodes=20, rule_nodes=5, rule_depth=4, rule_bytes=100, width=48,
)


def shape(**changes) -> RuleShape:
    base = dict(nodes=3, depth=2, comparisons=1, unit_bytes=50, refs=(), max_width=24)
    return RuleShape(**{**base, **changes})


def test_a_shape_inside_every_limit_passes():
    assert shape_ok(shape())


def shape_ok(s, count=0, nodes=0):
    return shared_rule_budget_error(s, LIMITS, count, nodes) is None


@pytest.mark.parametrize("field,limit,message", [
    ("nodes", 5, "5 per rule"),
    ("depth", 4, "limit is 4"),
    ("unit_bytes", 100, "limit is 100"),
    ("max_width", 48, "bv[48]"),
])
def test_each_per_rule_limit_is_inclusive(field, limit, message):
    assert shape_ok(shape(**{field: limit}))
    error = shared_rule_budget_error(shape(**{field: limit + 1}), LIMITS, 0, 0)
    assert error is not None
    assert str(limit + 1) in error and message in error


def test_occurrence_limit_is_inclusive():
    assert shape_ok(shape(), count=2)
    error = shared_rule_budget_error(shape(), LIMITS, 3, 0)
    assert "3" in error and "limit is 3" in error


def test_total_node_limit_is_inclusive():
    assert shape_ok(shape(nodes=3), nodes=17)
    error = shared_rule_budget_error(shape(nodes=3), LIMITS, 0, 18)
    assert "18" in error and "adds 3" in error and "limit is 20" in error


def test_zero_occurrences_refuses_every_rule():
    closed = replace(LIMITS, occurrences=0)
    assert shared_rule_budget_error(shape(), closed, 0, 0) is not None


def test_zero_total_nodes_refuses_every_rule():
    closed = replace(LIMITS, total_nodes=0)
    assert shared_rule_budget_error(shape(), closed, 0, 0) is not None


def test_measured_shapes():
    assert shared_rule_shape(rule(0)).nodes == 3
    assert shared_rule_shape(chain_rule(4)).nodes == 15
    assert shared_rule_shape(chain_rule(5)).nodes == 19
    assert shared_rule_shape(WIDE_RULE).max_width == 384


def test_only_non_o5_rules_count():
    assert counts_toward_shared_budget(rule(0))
    assert not counts_toward_shared_budget(ROUTED_O5)


# --- apply --------------------------------------------------------------------

_SEQ = itertools.count()
_SEQUENCES = {}


def user_tx(text, *, fee_limit="100", sender_sk=SK_CAROL, seq=None, extra=None):
    sender = pubkey_hex(sender_sk)
    if seq is None:
        seq = _SEQUENCES.get(sender, 0)
        _SEQUENCES[sender] = seq + 1
    ops = {"0": text, **(extra or {})}
    return sign_payload({
        "tx_id": f"b-{next(_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "operations": ops,
    }, sender_sk)


@pytest.fixture(autouse=True)
def fresh_sequences():
    _SEQUENCES.clear()
    sender_policy.set_evaluator("apply", MockPolicyEvaluator(pool="apply"))
    yield
    sender_policy.set_evaluator("apply", None)


def fresh_lm(limits=None, count=0, nodes=0):
    lm = ConsensusLifecycleManager(active_validators=[OFFERER])
    if limits is not None:
        lm.shared_rule_limits = limits
    lm.shared_rule_count = count
    lm.shared_rule_nodes = nodes
    return lm


def apply(txs, lm, *, replay_mode=False, fee=0):
    """Apply one block; returns (result, post-block lifecycle manager)."""
    persisted = []
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {OFFERER: 1000, ACCEPTOR: 1000, AUTHOR: 1000},
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
        active_validators=[bytes.fromhex(OFFERER)],
        mechanism_specific_metadata={"poa": True},
    )
    block = Block.create(block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
                         proposer_pubkey=OFFERER, timestamp=1234567890)

    def single(**kw):
        text = str(kw.get("rule_text") or "")
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def multi(**kw):
        return {1: "1", 5: "1", 8: "0", 9: str(fee)}

    with patch("tau_manager.communicate_with_tau", side_effect=single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("chain_state.save_application_rules_state", create=True), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = TauConsensusEngine().apply_block(
            view, block, parent, replay_mode=replay_mode)
    return result, result.next_snapshot.metadata["lifecycle_manager"]


def reasons(result):
    return {o.tx_id: o.reason for o in result.outcomes if o.reason}


def usage(lm):
    return (lm.shared_rule_count, lm.shared_rule_nodes)


@pytest.mark.parametrize("replay_mode", [False, True])
def test_every_occurrence_counts_including_repeats(replay_mode):
    txs = [user_tx(rule(0)), user_tx(rule(1)), user_tx(rule(0))]
    result, lm = apply(txs, fresh_lm(), replay_mode=replay_mode)
    assert len(result.accepted_tx_ids) == 3
    assert usage(lm) == (3, 9)


def test_counters_continue_from_the_parent_state():
    result, lm = apply([user_tx(rule(0))], fresh_lm(count=4, nodes=30))
    assert result.accepted_tx_ids
    assert usage(lm) == (5, 33)


def test_a_clause_an_offer_and_an_accept_do_not_count():
    from test_rule_offer_apply import _offer, decision_tx, offer_tx

    offer = _offer()
    txs = [
        user_tx(ROUTED_O5),
        offer_tx(offer),
        decision_tx(offer, accept=True),
        user_tx(rule(0)),
    ]
    result, lm = apply(txs, fresh_lm())
    assert len(result.accepted_tx_ids) == 4
    assert lm.rule_offers.clause_for(ACCEPTOR, 5) is not None
    assert usage(lm) == (1, 3)


def test_a_rule_the_fragment_screen_refuses_does_not_count():
    bad = user_tx("always ( foo[t] = 0 ).")
    result, lm = apply([bad, user_tx(rule(0), seq=0)], fresh_lm())
    assert reasons(result)[bad["tx_id"]] == "rule_fragment"
    assert usage(lm) == (1, 3)


def test_a_rule_rejected_at_fee_settlement_leaves_the_counters_alone():
    tx = user_tx(rule(0), fee_limit="1")
    result, lm = apply([tx], fresh_lm(), fee=7)
    assert reasons(result)[tx["tx_id"]] == "fee_limit_exceeded"
    assert usage(lm) == (0, 0)


def test_the_eleventh_occurrence_is_refused_and_the_block_stays_valid():
    txs = [user_tx(rule(i)) for i in range(11)]
    result, lm = apply(txs, fresh_lm())
    assert result.next_snapshot is not None
    assert result.accepted_tx_ids == [t["tx_id"] for t in txs[:10]]
    assert result.invalid_tx_ids == [txs[10]["tx_id"]]
    assert reasons(result)[txs[10]["tx_id"]] == RULE_BUDGET_REASON
    assert usage(lm) == (10, 30)


def test_every_occurrence_past_the_limit_is_refused():
    txs = [user_tx(rule(0)), user_tx(rule(1)), user_tx(rule(2))]
    result, lm = apply(txs, fresh_lm(replace(DEFAULT_SHARED_RULE_LIMITS, occurrences=1)))
    assert result.accepted_tx_ids == [txs[0]["tx_id"]]
    assert set(result.invalid_tx_ids) == {txs[1]["tx_id"], txs[2]["tx_id"]}
    assert usage(lm) == (1, 3)


def test_the_aggregate_node_limit_refuses_the_rule_that_crosses_it():
    limits = replace(DEFAULT_SHARED_RULE_LIMITS, total_nodes=7)
    txs = [user_tx(rule(i)) for i in range(3)]
    result, lm = apply(txs, fresh_lm(limits))
    assert result.accepted_tx_ids == [t["tx_id"] for t in txs[:2]]
    assert reasons(result)[txs[2]["tx_id"]] == RULE_BUDGET_REASON
    assert usage(lm) == (2, 6)


PER_RULE_CASES = [
    pytest.param(chain_rule(9), {}, id="nodes"),
    pytest.param(chain_rule(3), {"rule_nodes": 100, "rule_depth": 3}, id="depth"),
    pytest.param(rule(0), {"rule_bytes": 20}, id="bytes"),
    pytest.param(WIDE_RULE, {"width": 48}, id="width"),
]


@pytest.mark.parametrize("text,limit_changes", PER_RULE_CASES)
@pytest.mark.parametrize("replay_mode", [False, True])
def test_each_per_rule_limit_refuses_at_apply(text, limit_changes, replay_mode):
    limits = replace(DEFAULT_SHARED_RULE_LIMITS, **limit_changes)
    tx = user_tx(text)
    result, lm = apply([tx], fresh_lm(limits), replay_mode=replay_mode)
    assert reasons(result)[tx["tx_id"]] == RULE_BUDGET_REASON
    assert usage(lm) == (0, 0)


def test_live_and_replay_reach_the_same_counters():
    txs = [user_tx(rule(i)) for i in range(4)] + [user_tx(ROUTED_O5)]
    _, live = apply(txs, fresh_lm())
    _SEQUENCES.clear()
    _, replayed = apply(txs, fresh_lm(), replay_mode=True)
    assert usage(live) == usage(replayed) == (4, 12)
    assert live.consensus_meta_hash() == replayed.consensus_meta_hash()


# --- admission and apply agree --------------------------------------------------

def tip(limits, count, nodes):
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {AUTHOR}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = False
    view.clause_for.return_value = None
    view.shared_rule_budget = (limits, count, nodes)
    return view


PARITY_CORPUS = [
    pytest.param(rule(0), DEFAULT_SHARED_RULE_LIMITS, 10, 30, id="occurrences"),
    pytest.param(rule(0), replace(DEFAULT_SHARED_RULE_LIMITS, total_nodes=7), 2, 6, id="aggregate"),
    pytest.param(chain_rule(9), DEFAULT_SHARED_RULE_LIMITS, 0, 0, id="rule-nodes"),
    pytest.param(chain_rule(3), replace(DEFAULT_SHARED_RULE_LIMITS, rule_nodes=100, rule_depth=3), 0, 0, id="depth"),
    pytest.param(rule(0), replace(DEFAULT_SHARED_RULE_LIMITS, rule_bytes=20), 0, 0, id="bytes"),
    pytest.param(WIDE_RULE, replace(DEFAULT_SHARED_RULE_LIMITS, width=48), 0, 0, id="width"),
    pytest.param(rule(0), replace(DEFAULT_SHARED_RULE_LIMITS, occurrences=0), 0, 0, id="closed"),
]


@pytest.mark.parametrize("text,limits,count,nodes", PARITY_CORPUS)
def test_admission_and_apply_refuse_the_same_rules(text, limits, count, nodes):
    tx = user_tx(text)
    admitted = validate_mempool_admission(tx, tip(limits, count, nodes))
    assert not admitted.is_valid
    assert admitted.code == RULE_BUDGET_CODE

    _SEQUENCES.clear()
    tx = user_tx(text)
    result, lm = apply([tx], fresh_lm(limits, count, nodes))
    assert reasons(result)[tx["tx_id"]] == RULE_BUDGET_REASON
    assert usage(lm) == (count, nodes)


@pytest.mark.parametrize("text", [rule(0), WIDE_RULE, chain_rule(4)])
def test_admission_and_apply_both_accept_a_rule_inside_the_limits(text):
    tx = user_tx(text)
    admitted = validate_mempool_admission(tx, tip(DEFAULT_SHARED_RULE_LIMITS, 9, 60))
    assert admitted.code != RULE_BUDGET_CODE
    _SEQUENCES.clear()
    tx = user_tx(text)
    result, lm = apply([tx], fresh_lm(count=9, nodes=60))
    assert result.accepted_tx_ids == [tx["tx_id"]]
    assert lm.shared_rule_count == 10


def test_admission_does_not_budget_a_routed_clause():
    tx = user_tx(ROUTED_O5)
    closed = replace(DEFAULT_SHARED_RULE_LIMITS, occurrences=0)
    admitted = validate_mempool_admission(tx, tip(closed, 0, 0))
    assert admitted.code != RULE_BUDGET_CODE


def test_the_tip_view_reads_the_canonical_lifecycle_manager():
    lm = fresh_lm(count=3, nodes=9)
    with patch("chain_state._lifecycle_manager", lm):
        assert TipAdmissionView().shared_rule_budget == (
            DEFAULT_SHARED_RULE_LIMITS, 3, 9)


# --- governance ---------------------------------------------------------------

def test_a_valid_patch_is_admitted_and_applied_without_touching_counters():
    new = _with(occurrences=20, total_nodes=200)
    assert _check_host_contract_patch({"shared_rule_limits": new}) is None
    lm = fresh_lm(count=4, nodes=12)
    lm.apply_host_contract_patch({"shared_rule_limits": new})
    assert asdict(lm.shared_rule_limits) == new
    assert usage(lm) == (4, 12)


@pytest.mark.parametrize("value", [
    pytest.param(v.values[0], id=v.id) for v in BAD_VALUES
])
def test_an_invalid_patch_is_refused_at_admission_and_at_apply(value):
    assert isinstance(_check_host_contract_patch({"shared_rule_limits": value}), str)
    lm = fresh_lm()
    with pytest.raises(ValueError, match="shared_rule_limits"):
        lm.apply_host_contract_patch({"shared_rule_limits": value})
    assert lm.shared_rule_limits == DEFAULT_SHARED_RULE_LIMITS


def test_the_patch_enters_the_update_id():
    a = compute_update_id(["x"], 5, {"shared_rule_limits": GOOD_LIMITS})
    b = compute_update_id(["x"], 5, {"shared_rule_limits": _with(width=48)})
    c = compute_update_id(["x"], 5, {"shared_rule_limits": dict(reversed(GOOD_LIMITS.items()))})
    assert a != b
    assert a == c


def test_a_raised_limit_admits_the_next_rule():
    lm = fresh_lm(count=10, nodes=30)
    first = user_tx(rule(0))
    result, _ = apply([first], lm)
    assert reasons(result)[first["tx_id"]] == RULE_BUDGET_REASON

    lm.apply_host_contract_patch({"shared_rule_limits": _with(occurrences=11)})
    _SEQUENCES.clear()
    second = user_tx(rule(0))
    result, post = apply([second], lm)
    assert result.accepted_tx_ids == [second["tx_id"]]
    assert usage(post) == (11, 33)
    admitted = validate_mempool_admission(
        user_tx(rule(1)), tip(post.shared_rule_limits, *usage(post)))
    assert admitted.code == RULE_BUDGET_CODE


def test_a_limit_lowered_below_usage_refuses_the_next_rule():
    lm = fresh_lm(count=5, nodes=15)
    lm.apply_host_contract_patch({"shared_rule_limits": _with(occurrences=2)})
    assert usage(lm) == (5, 15)
    tx = user_tx(rule(0))
    result, post = apply([tx], lm)
    assert reasons(result)[tx["tx_id"]] == RULE_BUDGET_REASON
    assert usage(post) == (5, 15)


# --- the hash -----------------------------------------------------------------

def test_limits_and_counters_are_in_the_mechanism_metadata():
    meta = build_mechanism_metadata("supermajority")
    assert meta["shared_rule_limits"] == GOOD_LIMITS
    assert meta["shared_rule_count"] == 0
    assert meta["shared_rule_nodes"] == 0


@pytest.mark.parametrize("name", list(GOOD_LIMITS))
def test_each_limit_changes_the_meta_hash(name):
    lm = fresh_lm()
    base = lm.consensus_meta_hash()
    lm.shared_rule_limits = replace(
        DEFAULT_SHARED_RULE_LIMITS, **{name: getattr(DEFAULT_SHARED_RULE_LIMITS, name) - 1})
    assert lm.consensus_meta_hash() != base


@pytest.mark.parametrize("name", ["shared_rule_count", "shared_rule_nodes"])
def test_each_counter_changes_the_meta_hash(name):
    lm = fresh_lm()
    base = lm.consensus_meta_hash()
    setattr(lm, name, 1)
    assert lm.consensus_meta_hash() != base


def test_a_fork_carries_the_budget_state():
    lm = fresh_lm(replace(DEFAULT_SHARED_RULE_LIMITS, occurrences=4), 2, 6)
    clone = lm.fork()
    assert clone.shared_rule_limits == lm.shared_rule_limits
    assert usage(clone) == (2, 6)
    clone.shared_rule_count += 1
    assert lm.shared_rule_count == 2



# --- shipped templates --------------------------------------------------------

def test_every_web_wallet_template_fits_the_default_per_rule_limits():
    from test_web_wallet_examples import get_templates

    limits = DEFAULT_SHARED_RULE_LIMITS
    for text in get_templates():
        shape = shared_rule_shape(text)
        assert shape is not None, text
        assert shape.nodes <= limits.rule_nodes, text
        assert shape.depth <= limits.rule_depth, text
        assert shape.unit_bytes <= limits.rule_bytes, text
        assert shape.max_width <= limits.width, text


def test_the_score_gate_template_measures_as_documented():
    from test_web_wallet_examples import get_templates

    shape = shared_rule_shape(get_templates()[4])
    assert (shape.nodes, shape.depth, shape.unit_bytes, shape.max_width) == (24, 5, 247, 24)
