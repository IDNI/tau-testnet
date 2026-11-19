"""Recipient controls: an account refuses incoming transfers and caps holds.

Issues #47 (recipient-side o5 policy: refuse payments from unknown senders)
and #76 (recipient-side cap on how long a payment to an account may be held,
0 = instant only, refused at park with a reason).

Coverage, in increasing realism:
- pure helpers (hold length, cap extraction, guarded-unit scan),
- the admission gate (`commands.sendtx._recipient_gate`) against a fake
  admission Tau step and the mock policy evaluator (clause mode) or a
  scripted second pass (guarded mode),
- block apply through the real engine with a scripted o5: the gate is
  consensus-enforced, the refusal reason is distinct, and i17 is fed the
  same value admission fed,
- the feature-off screens (a node without the feature refuses an i17 rule
  at deploy and never runs the gate),
- `gettaustate` capability reporting.

Mock evaluator throughout for the clause path; the real one is in
test_clause_registration_native.py. The guarded-mode second pass is scripted
by the fake step / scripted o5, because the native engine is not built in
this environment (see the module docstring of the design doc).
"""
import itertools
import json
from unittest.mock import patch

import pytest

import tau_defs
from block import Block
from bls_keys import sign_payload
from consensus import recipient_policy, sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import KIND_HEIGHT, KIND_TIME
from consensus.rule_offers import clause_body_v1
from consensus.state import TauStateSnapshot
from commands import sendtx
from commands.gettaustate import execute as gettaustate_execute

import test_approval_apply as ap

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
HOLD = tau_defs.HOLD_LENGTH_STREAM_INDEX
HEIGHT = 20
TS = 1234567890
ALLOWED = ap.ALICE
SENDER = ap.ALICE
RECIPIENT = ap.BOB
STRANGER = ap.STRANGER

_SEQ = itertools.count()

# A guarded unit for the recipient: inert (allows) unless the policy subject
# is the recipient, in which case it applies the recipient's verdict. The
# else-branch MUST allow: in the first pass i12 is the sender, so a guarded
# unit that blocked there would block every transfer in the chain.
ALLOWLIST_UNIT = (
    "always ((i12[t]:bv[384] = { #x" + RECIPIENT + " }:bv[384]) ? "
    "((i3[t]:bv[384] = { #x" + ALLOWED + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24])) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]))."
)
CAP600_UNIT = (
    "always ((i12[t]:bv[384] = { #x" + RECIPIENT + " }:bv[384]) ? "
    "((i17[t]:bv[64] <= {600}:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24])) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]))."
)
ALLOWLIST_CLAUSE = clause_body_v1(
    "always ((i3[t]:bv[384] = { #x" + ALLOWED + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]))."
)
CAP600_CLAUSE = clause_body_v1(
    "always ((i17[t]:bv[64] <= {600}:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]))."
)
CAP0_CLAUSE = clause_body_v1(
    "always ((i17[t]:bv[64] <= {0}:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]))."
)
AMOUNT_CLAUSE = clause_body_v1(
    "always ((i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]))."
)


@pytest.fixture(autouse=True)
def _reset_evaluators():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


# --- pure helpers ------------------------------------------------------------


def test_hold_length_plain_transfer_is_zero():
    assert recipient_policy.hold_length_for_transfer(height=HEIGHT, timestamp=TS) == 0


def test_hold_length_time_park_is_seconds_to_release():
    assert recipient_policy.hold_length_for_transfer(
        kind=KIND_TIME, release_at=TS + 3600, height=HEIGHT, timestamp=TS,
    ) == 3600


def test_hold_length_height_park_is_blocks_to_release():
    assert recipient_policy.hold_length_for_transfer(
        kind=KIND_HEIGHT, release_at=HEIGHT + 600, height=HEIGHT, timestamp=TS,
    ) == 600


def test_hold_length_never_negative():
    assert recipient_policy.hold_length_for_transfer(
        kind=KIND_TIME, release_at=TS - 10, height=HEIGHT, timestamp=TS,
    ) == 0
    assert recipient_policy.hold_length_for_transfer(
        kind=KIND_HEIGHT, release_at=HEIGHT - 5, height=HEIGHT, timestamp=TS,
    ) == 0


@pytest.mark.parametrize("text,want", [
    ("(i17[t]:bv[64] <= { #x000258 }:bv[64]) ? allow : block", 600),
    ("(i17[t]:bv[64] <= {600}:bv[64]) ? allow : block", 600),
    ("(i17[t]:bv[64] < {600}:bv[64]) ? allow : block", 599),
    ("(i17[t]:bv[64] > { #x000258 }:bv[64]) ? block : allow", 600),
    ("(i17[t]:bv[64] >= {601}:bv[64]) ? block : allow", 600),
    ("({ #x000258 }:bv[64] >= i17[t]:bv[64]) ? allow : block", 600),
    ("({600}:bv[64] < i17[t]:bv[64]) ? block : allow", 600),
    ("(i3[t]:bv[384] = { #xaa }:bv[384]) ? allow : block", None),
    ("(i17[t]:bv[64] <= {600}:bv[64] && i17[t]:bv[64] <= {3600}:bv[64])", None),
    ("(i17[t]:bv[64] < {0}:bv[64]) ? allow : block", None),
    ("(i17[t]:bv[64] <= {600}:bv[24]) ? allow : block", None),
])
def test_extract_hold_cap(text, want):
    assert recipient_policy.extract_hold_cap(text) == want


def test_guarded_unit_scan_matches_recipient_key_only():
    assert recipient_policy.recipient_may_have_guarded_unit(ALLOWLIST_UNIT, RECIPIENT)
    assert not recipient_policy.recipient_may_have_guarded_unit(ALLOWLIST_UNIT, STRANGER)
    assert not recipient_policy.recipient_may_have_guarded_unit("", RECIPIENT)
    assert recipient_policy.recipient_may_have_guarded_unit(
        ALLOWLIST_UNIT.upper(), RECIPIENT)
    # The unit also names the allowlisted sender: the scan is a "may have"
    # heuristic, and that false positive costs one extra step, by design.
    assert recipient_policy.recipient_may_have_guarded_unit(ALLOWLIST_UNIT, SENDER)


def test_recipient_unit_hold_cap():
    assert recipient_policy.recipient_unit_hold_cap(CAP600_UNIT, RECIPIENT) == 600
    assert recipient_policy.recipient_unit_hold_cap(ALLOWLIST_UNIT, RECIPIENT) is None
    assert recipient_policy.recipient_unit_hold_cap("", RECIPIENT) is None
    two_caps = CAP600_UNIT + "\n" + CAP600_UNIT.replace("{600}", "{3600}")
    assert recipient_policy.recipient_unit_hold_cap(two_caps, RECIPIENT) is None


# --- admission gate ----------------------------------------------------------

class _FakeTipView:
    def __init__(self, clauses=None):
        self._clauses = clauses or {}

    def clause_for(self, pubkey, stream):
        return self._clauses.get((pubkey, stream))


class _FakeAdmissionTau:
    def __init__(self, step=None):
        self.budget = 5
        self.calls = []
        self._step = step

    def step_multi(self, inputs, source=None, **kwargs):
        self.calls.append((dict(inputs), source))
        if self._step is not None:
            return self._step(inputs)
        return {1: "1", 5: "1", 8: "0", 9: "0"}


def _gate_inputs(sender=SENDER, recipient=RECIPIENT, amount=100, hold=0):
    return {
        1: str(amount),
        2: "1000000",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
        HOLD: str(hold),
        5: str(TS),
    }


def _gate(tip_view, values, hold, hold_unit="seconds", tau=None, rules_text=""):
    return sendtx._recipient_gate(
        tip_view, RECIPIENT, values, hold, hold_unit,
        tau or _FakeAdmissionTau(), rules_text, 1, (SENDER, RECIPIENT, 100),
    )


def _clause_evaluator():
    """Mock evaluator: allowlist by sender, cap by hold, amount cap."""
    evaluator = MockPolicyEvaluator(pool="admission")
    evaluator.set_verdict(
        ALLOWLIST_CLAUSE,
        lambda inputs: "0" if inputs.get("i3") != "#x" + ALLOWED else "1",
    )
    evaluator.set_verdict(
        CAP600_CLAUSE,
        lambda inputs: "0" if int(inputs.get("i17", "0")) > 600 else "1",
    )
    evaluator.set_verdict(
        CAP0_CLAUSE,
        lambda inputs: "0" if int(inputs.get("i17", "0")) > 0 else "1",
    )
    evaluator.set_verdict(
        AMOUNT_CLAUSE,
        lambda inputs: "0" if int(inputs.get("i1", "0")) > 1000 else "1",
    )
    return evaluator


def _tip_with_clause(body):
    return _FakeTipView({(RECIPIENT, STREAM): body})


def test_gate_allows_when_recipient_has_no_policy():
    sender_policy.set_evaluator("admission", _clause_evaluator())
    tau = _FakeAdmissionTau()
    assert _gate(_FakeTipView(), _gate_inputs(), 0, tau=tau) is None
    assert tau.calls == [], "no second pass when the recipient has no guarded unit"


def test_gate_clause_allowlist_blocks_unknown_sender():
    sender_policy.set_evaluator("admission", _clause_evaluator())
    refusal = _gate(_tip_with_clause(ALLOWLIST_CLAUSE), _gate_inputs(sender=STRANGER), 0)
    assert refusal is not None
    assert refusal["code"] == "RECIPIENT_POLICY_BLOCK"
    assert refusal["details"]["recipient_pubkey"] == RECIPIENT


def test_gate_clause_allowlist_allows_known_sender():
    sender_policy.set_evaluator("admission", _clause_evaluator())
    assert _gate(_tip_with_clause(ALLOWLIST_CLAUSE), _gate_inputs(), 0) is None


def test_gate_clause_cap_blocks_long_park_with_the_cap():
    sender_policy.set_evaluator("admission", _clause_evaluator())
    refusal = _gate(
        _tip_with_clause(CAP600_CLAUSE), _gate_inputs(hold=3600), 3600,
    )
    assert refusal is not None
    assert refusal["code"] == "RECIPIENT_MAX_HOLD"
    assert refusal["details"]["max_hold"] == 600
    assert refusal["details"]["hold"] == 3600
    assert "600" in refusal["message"]


def test_gate_clause_cap_allows_short_park_and_plain_transfer():
    sender_policy.set_evaluator("admission", _clause_evaluator())
    tip = _tip_with_clause(CAP600_CLAUSE)
    assert _gate(tip, _gate_inputs(hold=600), 600) is None
    assert _gate(tip, _gate_inputs(hold=0), 0) is None


def test_gate_clause_cap_zero_means_instant_only():
    sender_policy.set_evaluator("admission", _clause_evaluator())
    tip = _tip_with_clause(CAP0_CLAUSE)
    refusal = _gate(tip, _gate_inputs(hold=1), 1)
    assert refusal["code"] == "RECIPIENT_MAX_HOLD"
    assert refusal["details"]["max_hold"] == 0
    assert _gate(tip, _gate_inputs(hold=0), 0) is None


def test_gate_clause_block_not_caused_by_hold_is_policy_not_max_hold():
    # The amount clause blocks a big transfer at any hold, including 0: the
    # zero-hold probe also blocks, so the refusal is an allowlist refusal.
    sender_policy.set_evaluator("admission", _clause_evaluator())
    tip = _tip_with_clause(AMOUNT_CLAUSE)
    refusal = _gate(tip, _gate_inputs(amount=5000, hold=3600), 3600)
    assert refusal["code"] == "RECIPIENT_POLICY_BLOCK"


def _guarded_o5(kind):
    """Just the o5 VALUE a guarded unit returns (for the apply harness).

    Unlike `_guarded_step` (a whole fake Tau step, returning the outputs
    dict), this returns the "0"/"1" the scripted o5 policy feeds back.
    """
    def policy(vals):
        i12 = vals.get(12, "")
        if i12 != "{ #x" + RECIPIENT + " }:bv[384]":
            return "1"  # the unit is inert unless the subject is the recipient
        hold = int(vals.get(HOLD, "0") or "0")
        sender = vals.get(3, "")
        if kind == "allowlist":
            return "1" if sender == "{ #x" + ALLOWED + " }:bv[384]" else "0"
        if kind == "cap600":
            return "1" if hold <= 600 else "0"
        return "1"  # pragma: no cover
    return policy


def _guarded_step(kind):
    """A Tau step implementing the guarded unit in `kind`."""
    def step(inputs):
        i12 = inputs.get(12, "")
        if i12 != "{ #x" + RECIPIENT + " }:bv[384]":
            return {1: "1", 5: "1", 8: "0", 9: "0"}
        hold = int(inputs.get(HOLD, "0"))
        sender = inputs.get(3, "")
        if kind == "allowlist":
            o5 = "1" if sender == "{ #x" + ALLOWED + " }:bv[384]" else "0"
        elif kind == "cap600":
            o5 = "1" if hold <= 600 else "0"
        else:  # pragma: no cover
            o5 = "1"
        return {1: "1", 5: o5, 8: "0", 9: "0"}
    return step


def test_gate_guarded_allowlist_blocks_unknown_sender():
    tau = _FakeAdmissionTau(step=_guarded_step("allowlist"))
    refusal = _gate(_FakeTipView(), _gate_inputs(sender=STRANGER), 0,
                    tau=tau, rules_text=ALLOWLIST_UNIT)
    assert refusal["code"] == "RECIPIENT_POLICY_BLOCK"
    # The gate itself makes two steps: the second pass (i12=recipient) and
    # the zero-hold probe. (The first pass is the caller's transfer step.)
    assert len(tau.calls) == 2
    assert tau.calls[0][0][12] == "{ #x" + RECIPIENT + " }:bv[384]"
    assert tau.calls[1][0][HOLD] == "0"


def test_gate_guarded_allowlist_allows_known_sender_without_probe():
    tau = _FakeAdmissionTau(step=_guarded_step("allowlist"))
    assert _gate(_FakeTipView(), _gate_inputs(), 0, tau=tau, rules_text=ALLOWLIST_UNIT) is None
    assert len(tau.calls) == 1, "second pass only; no probe when it allows"


def test_gate_guarded_cap_blocks_long_park_with_the_cap():
    tau = _FakeAdmissionTau(step=_guarded_step("cap600"))
    refusal = _gate(
        _FakeTipView(), _gate_inputs(hold=3600), 3600,
        tau=tau, rules_text=CAP600_UNIT,
    )
    assert refusal["code"] == "RECIPIENT_MAX_HOLD"
    assert refusal["details"]["max_hold"] == 600
    assert refusal["details"]["hold"] == 3600


def test_gate_guarded_cap_allows_short_park():
    tau = _FakeAdmissionTau(step=_guarded_step("cap600"))
    assert _gate(_FakeTipView(), _gate_inputs(hold=600), 600,
                 tau=tau, rules_text=CAP600_UNIT) is None
    assert len(tau.calls) == 1


def test_gate_skips_second_pass_without_a_guarded_unit():
    tau = _FakeAdmissionTau(step=_guarded_step("allowlist"))
    assert _gate(_FakeTipView(), _gate_inputs(), 0, tau=tau, rules_text="") is None
    assert tau.calls == []


# --- feature-off screens ------------------------------------------------------

def test_feature_off_rule_screen_forbids_i17():
    with patch.object(tau_defs, "RECIPIENT_CONTROLS_ACTIVE", False):
        assert "i17" in tau_defs.rule_text_forbidden_input_streams()
        assert tau_defs.HOLD_LENGTH_STREAM_INDEX not in tau_defs.reserved_operation_keys("all")


def test_feature_off_gate_never_runs():
    with patch.object(tau_defs, "RECIPIENT_CONTROLS_ACTIVE", False):
        tau = _FakeAdmissionTau(step=_guarded_step("allowlist"))
        assert _gate(_FakeTipView(), _gate_inputs(), 0, tau=tau, rules_text=ALLOWLIST_UNIT) is None
        assert tau.calls == []


def test_feature_on_rule_screen_allows_i17():
    assert "i17" not in tau_defs.rule_text_forbidden_input_streams()
    assert tau_defs.HOLD_LENGTH_STREAM_INDEX in tau_defs.reserved_operation_keys("all")


# --- block apply through the real engine --------------------------------------

class RecipientChain:
    """Applies blocks through the real engine with a scripted o5."""

    def __init__(self, o5_policy=None, rules_text=""):
        self.height = HEIGHT
        self.rules_text = rules_text
        self.o5_policy = o5_policy or (lambda vals: "1")
        self.multi_calls = []
        self.lifecycle = ConsensusLifecycleManager(active_validators=[ap.ALICE])
        self.lifecycle.activate_approval_slots()
        balances = {pk: 1_000_000 for pk in (ap.ALICE, ap.BOB, ap.STRANGER)}
        self.snapshot = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": balances,
                "sequence_numbers": {},
                "last_transfer_ts": {},
                "lifecycle_manager": self.lifecycle,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )

    def apply(self, txs):
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=self.snapshot.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ap.ALICE)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash="00" * 32, transactions=txs,
            proposer_pubkey=ap.ALICE, timestamp=TS,
        )
        rules_text = self.rules_text

        def single(**kwargs):
            return "T"

        def multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            self.multi_calls.append(dict(vals))
            return {1: str(vals.get(1, "0")), 5: self.o5_policy(vals), 8: "0", 9: "0"}

        with patch("tau_manager.communicate_with_tau", side_effect=single), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=multi), \
             patch("chain_state.get_application_rules_state", return_value=rules_text), \
             patch("chain_state.save_application_rules_state"), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = TauConsensusEngine().apply_block(view, block, self.snapshot)
        self.snapshot = result.next_snapshot
        self.lifecycle = self.snapshot.metadata["lifecycle_manager"]
        self.height += 1
        return result


def _base(tx_type, sender, seq, fee_limit="100"):
    return {
        "tx_id": f"{tx_type}-{next(_SEQ)}", "tx_type": tx_type,
        "sender_pubkey": sender, "sequence_number": seq,
        "expiration_time": 9999999999, "expire_at_height": 5000,
        "fee_limit": fee_limit,
    }


def _transfer_tx(sk, pubkey, recipient, amount, seq):
    tx = _base("user_tx", pubkey, seq)
    tx["operations"] = {"1": [[pubkey, recipient, str(amount)]]}
    return sign_payload(tx, sk)


def _park_tx(sk, pubkey, recipient, amount, seq, release_at_time=None,
             release_at_height=None):
    tx = _base("retractable_transfer", pubkey, seq)
    tx.update(recipient_pubkey=recipient, amount=amount,
              release_at_time=release_at_time, release_at_height=release_at_height)
    return sign_payload(tx, sk)


def _outcome(result, tx):
    return [o for o in result.outcomes if o.tx_id == tx["tx_id"]][0]


def _transfer_steps(chain):
    return [vals for vals in chain.multi_calls if 12 in vals]


def test_apply_plain_transfer_to_allowlisted_recipient_allowed():
    chain = RecipientChain(o5_policy=_guarded_o5("allowlist"), rules_text=ALLOWLIST_UNIT)
    tx = _transfer_tx(ap.SK_ALICE, SENDER, RECIPIENT, 100, 0)
    result = chain.apply([tx])
    assert result.invalid_tx_ids == [], _outcome(result, tx).receipt_logs
    assert _outcome(result, tx).reason is None
    # i17 is fed (0 for a plain transfer) on the transfer step.
    steps = _transfer_steps(chain)
    assert steps and all(step.get(HOLD) == "0" for step in steps)


def test_apply_plain_transfer_to_guarded_recipient_blocked():
    # The recipient allows only STRANGER; ALICE is not allowlisted.
    def stranger_only(vals):
        i12 = vals.get(12, "")
        if i12 != "{ #x" + RECIPIENT + " }:bv[384]":
            return "1"
        return "1" if vals.get(3) == "{ #x" + STRANGER + " }:bv[384]" else "0"
    chain = RecipientChain(o5_policy=stranger_only, rules_text=ALLOWLIST_UNIT)
    tx = _transfer_tx(ap.SK_ALICE, SENDER, RECIPIENT, 100, 0)
    result = chain.apply([tx])
    assert result.invalid_tx_ids == [tx["tx_id"]], _outcome(result, tx).receipt_logs
    assert _outcome(result, tx).reason == "recipient_policy_block"
    steps = _transfer_steps(chain)
    assert len(steps) == 3, "pass + second pass + zero-hold probe"


def test_apply_long_park_to_capped_recipient_blocked():
    chain = RecipientChain(o5_policy=_guarded_o5("cap600"), rules_text=CAP600_UNIT)
    tx = _park_tx(ap.SK_ALICE, SENDER, RECIPIENT, 100, 0, release_at_time=TS + 3600)
    result = chain.apply([tx])
    assert result.invalid_tx_ids == [tx["tx_id"]], _outcome(result, tx).receipt_logs
    assert _outcome(result, tx).reason == "recipient_max_hold"
    assert chain.lifecycle.retractable_transfers.open == {}
    # The escrow step fed the park's hold (3600s) on i17.
    steps = _transfer_steps(chain)
    assert steps and steps[0].get(HOLD) == "3600"


def test_apply_short_park_to_capped_recipient_allowed():
    chain = RecipientChain(o5_policy=_guarded_o5("cap600"), rules_text=CAP600_UNIT)
    tx = _park_tx(ap.SK_ALICE, SENDER, RECIPIENT, 100, 0, release_at_time=TS + 600)
    result = chain.apply([tx])
    assert result.invalid_tx_ids == [], _outcome(result, tx).receipt_logs
    assert len(chain.lifecycle.retractable_transfers.open) == 1
    steps = _transfer_steps(chain)
    assert steps and steps[0].get(HOLD) == "600"


def test_apply_long_park_to_unguarded_recipient_allowed_without_second_pass():
    chain = RecipientChain(o5_policy=_guarded_o5("cap600"), rules_text="")
    tx = _park_tx(ap.SK_ALICE, SENDER, RECIPIENT, 100, 0, release_at_time=TS + 3600)
    result = chain.apply([tx])
    assert result.invalid_tx_ids == [], _outcome(result, tx).receipt_logs
    assert len(chain.lifecycle.retractable_transfers.open) == 1
    steps = _transfer_steps(chain)
    assert len(steps) == 1, "no second pass without a guarded unit"
    assert steps[0].get(HOLD) == "3600"


def test_apply_height_park_feeds_hold_in_blocks():
    chain = RecipientChain(o5_policy=_guarded_o5("cap600"), rules_text=CAP600_UNIT)
    tx = _park_tx(ap.SK_ALICE, SENDER, RECIPIENT, 100, 0, release_at_height=HEIGHT + 600)
    result = chain.apply([tx])
    assert result.invalid_tx_ids == [], _outcome(result, tx).receipt_logs
    steps = _transfer_steps(chain)
    assert steps and steps[0].get(HOLD) == "600"


# --- gettaustate capabilities -------------------------------------------------

class _Container:
    def __init__(self, rules=""):
        self.chain_state = self

    def get_rules_state(self):
        return ""


def test_gettaustate_reports_recipient_capabilities():
    response = json.loads(gettaustate_execute("gettaustate", _Container()))
    assert response["status"] == "ok"
    assert response["data"]["capabilities"] == ["recipient_policy", "recipient_max_hold"]


def test_gettaustate_capabilities_empty_when_feature_off():
    with patch.object(tau_defs, "RECIPIENT_CONTROLS_ACTIVE", False):
        response = json.loads(gettaustate_execute("gettaustate", _Container()))
    assert response["data"]["capabilities"] == []
