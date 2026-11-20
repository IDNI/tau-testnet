"""Recipient controls: issues #47 (inbound allow-list) + #76 (max hold time).

Every acceptance case maps to a named test (the maintainer asked for
exactly this map on 2026-11-20):

    #47.1  allow-list admits A, refuses B
            -> test_47_1_allowlist_admits_sender_a_refuses_sender_b
    #47.2  neutral default: no policy allows everyone
            -> test_47_2_neutral_default_no_policy_allows_everyone
    #47.3  batch atomicity: one refused output fails the whole tx
            -> test_47_3_batch_atomicity_one_refused_output_fails_whole_tx
    #47.4  one unit carries inbound + outbound
            -> test_47_4_one_unit_carries_inbound_and_outbound
    #47.5  capability reporting + deploy refusal on a gate-less node
            -> test_47_5_capability_reporting_and_deploy_refusal_on_gate_less_node
    #76.1  cap 0 admits plain, refuses every park
            -> test_76_1_cap_zero_admits_plain_refuses_every_park
    #76.2  cap 600s admits a 10-minute park, refuses an hour park
            -> test_76_2_cap_600s_admits_10min_park_refuses_hour_park
    #76.3  neutral default: no policy parks any length
            -> test_76_3_neutral_default_no_policy_parks_any_length
    #76.4  retract never gated
            -> test_76_4_retract_never_gated
    #76.5  refusal message carries the cap
            -> test_76_5_refusal_message_carries_cap
    #76.6  capability reporting + deploy refusal (cap rule)
            -> test_76_6_capability_reporting_and_deploy_refusal

Extras: guarded-mode block/pass live at apply, sender-pass overlay,
non-monotonic rule reported honestly (cap_kind "rule", no number),
unit-blind hold rule refused at deploy, wrong-width recipient streams
refused, fee NOT charged on a recipient block at apply, activation
audit refusing on an i17/i16 collision in the spec, cooldown mutual
exclusion, per-payer caps, and the memorable moment (height park to a
capped recipient refused with the cap in the receipt while a seconds
park to the same recipient passes).

Mock mode (conftest: TAU_ENV=test, TAU_FORCE_TEST=1) scripts the
recipient clause's verdicts with MockPolicyEvaluator; the clause BODY
text is real and passes the real deploy screens, so the same bodies
mean the same thing under the native engine. Admission tests go through
the real `_recipient_gate_refusal` helper and, where marked, the real
`sendtx.queue_transaction` wire-up.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

import chain_state
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_tx
from consensus import sender_policy
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import (
    TauStateSnapshot,
    compute_consensus_meta_hash,
    compute_consensus_state_hash,
)

ALICE = pubkey_hex(SK_ALICE)    # sender A
BOB = pubkey_hex(SK_BOB)        # recipient R
CAROL = pubkey_hex(SK_CAROL)    # sender B / second recipient S
MALLORY = pubkey_hex(SK_MALLORY)  # sender C
PROPOSER = "b" * 96

pytestmark = pytest.mark.usefixtures("mock_policy_evaluators")


def _hex64(value: int) -> str:
    return f"{value:016x}"


def _lit384(pubkey: str) -> str:
    return "{ #x" + pubkey.lower() + " }:bv[384]"


def _lit64(value: int) -> str:
    return "{ #x" + _hex64(value) + " }:bv[64]"


# -- clause bodies (real Tau text; passes the deploy screens) -----------------

def allowlist_body(allowed: str) -> str:
    """Inbound (contexts 1/2/3) admits only `allowed`; outbound allows all."""
    return (
        "always ( (((i16[t]:bv[64] = " + _lit64(1) + ") || "
        "(i16[t]:bv[64] = " + _lit64(2) + ") || "
        "(i16[t]:bv[64] = " + _lit64(3) + ")) && "
        "!(i3[t]:bv[384] = " + _lit384(allowed) + ")) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )


def cap_body(seconds_cap: int, blocks_cap: int) -> str:
    """Time parks (ctx 2) hold <= seconds_cap; height parks (ctx 3) hold <=
    blocks_cap; final payments (ctx 1) always admitted."""
    return (
        "always ( ((i16[t]:bv[64] = " + _lit64(2) + ") && "
        "(i17[t]:bv[64] > " + _lit64(seconds_cap) + ")) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(((i16[t]:bv[64] = " + _lit64(3) + ") && "
        "(i17[t]:bv[64] > " + _lit64(blocks_cap) + ")) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24])) )."
    )


def combined_body(inbound_allowed: str, outbound_allowed: str) -> str:
    """One unit: inbound (ctx 1/2/3) admits only `inbound_allowed`,
    outbound (ctx 0) admits only `outbound_allowed`."""
    return (
        "always ( ((((i16[t]:bv[64] = " + _lit64(1) + ") || "
        "(i16[t]:bv[64] = " + _lit64(2) + ") || "
        "(i16[t]:bv[64] = " + _lit64(3) + ")) && "
        "!(i3[t]:bv[384] = " + _lit384(inbound_allowed) + ")) || "
        "((i16[t]:bv[64] = " + _lit64(0) + ") && "
        "!(i4[t]:bv[384] = " + _lit384(outbound_allowed) + "))) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )


def per_payer_cap_body(cap_a: int, cap_b: int, sender_b: str) -> str:
    """Time parks: A capped at cap_a, sender_b capped at cap_b."""
    return (
        "always ( ((i16[t]:bv[64] = " + _lit64(2) + ") && "
        "(i3[t]:bv[384] = " + _lit384(ALICE) + ") && "
        "(i17[t]:bv[64] > " + _lit64(cap_a) + ")) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(((i16[t]:bv[64] = " + _lit64(2) + ") && "
        "(i3[t]:bv[384] = " + _lit384(sender_b) + ") && "
        "(i17[t]:bv[64] > " + _lit64(cap_b) + ")) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24])) )."
    )


def unit_blind_body(seconds_cap: int) -> str:
    """Reads i17 but never i16: a unit-blind hold rule, refused at deploy."""
    return (
        "always ( (i17[t]:bv[64] > " + _lit64(seconds_cap) + ") ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )


def wrong_width_body() -> str:
    """i17 typed bv[24] instead of bv[64]: refused by the width screen."""
    return (
        "always ( ((i16[t]:bv[64] = " + _lit64(2) + ") && "
        "(i17[t]:bv[24] > { #x0258 }:bv[24])) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )


# -- scripted verdicts (mirror the body text above, on bare mock inputs) -----

def _bare(inputs, stream):
    value = inputs.get(f"i{stream}", "")
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "")


def _decide_allowlist(allowed):
    def decide(inputs):
        ctx = int(_bare(inputs, 16) or 0)
        if ctx in (1, 2, 3):
            return "1" if _bare(inputs, 3).lower() == f"#x{allowed.lower()}" else "0"
        return "1"
    return decide


def _decide_cap(seconds_cap, blocks_cap):
    def decide(inputs):
        ctx = int(_bare(inputs, 16) or 0)
        hold = int(_bare(inputs, 17) or 0)
        if ctx == 2:
            return "0" if hold > seconds_cap else "1"
        if ctx == 3:
            return "0" if hold > blocks_cap else "1"
        return "1"
    return decide


def _decide_combined(inbound_allowed, outbound_allowed):
    def decide(inputs):
        ctx = int(_bare(inputs, 16) or 0)
        if ctx in (1, 2, 3):
            return "1" if _bare(inputs, 3).lower() == f"#x{inbound_allowed.lower()}" else "0"
        return "1" if _bare(inputs, 4).lower() == f"#x{outbound_allowed.lower()}" else "0"
    return decide


def _decide_per_payer(cap_a, cap_b, sender_b):
    def decide(inputs):
        ctx = int(_bare(inputs, 16) or 0)
        hold = int(_bare(inputs, 17) or 0)
        sender = _bare(inputs, 3).lower()
        if ctx == 2 and sender == f"#x{ALICE.lower()}":
            return "0" if hold > cap_a else "1"
        if ctx == 2 and sender == f"#x{sender_b.lower()}":
            return "0" if hold > cap_b else "1"
        return "1"
    return decide


def _install(body, decide):
    """Script one verdict on both the admission and the apply evaluator."""
    sender_policy.evaluator("admission").set_verdict(body, decide)
    sender_policy.evaluator("apply").set_verdict(body, decide)


# -- stub tip view -------------------------------------------------------------

class _StubTip:
    def __init__(self, clauses=None, *, active=True, height=50, timestamp=1700000000):
        self._clauses = clauses or {}
        self.recipient_policy_active = active
        self.approval_slots_active = False
        self.eligibility_mode = ""
        self.next_block_height = height
        self.next_block_timestamp = timestamp
        self._retractables = {}

    def clause_for(self, pubkey, stream):
        return self._clauses.get((str(pubkey).lower(), stream))

    def get_retractable(self, rid):
        return self._retractables.get(bytes(rid))

    def escrowed_in(self, pubkey):
        return 0

    def get_rule_change_request(self, request_id_hex):
        return None

    def get_offer(self, offer_id):
        return None

    def open_requests_for_sender(self, sender_pubkey):
        return 0


def _values(sender, recipient, *, amount=10, timestamp=1700000000):
    return {
        1: str(amount),
        2: "100000",
        3: _lit384(sender),
        4: _lit384(recipient),
        5: str(timestamp),
        12: _lit384(sender),
    }


def _gate(tip, recipient, sender, *, hold=0, context=1):
    from commands.sendtx import _recipient_gate_refusal

    return _recipient_gate_refusal(
        tip, recipient, _values(sender, recipient),
        hold=hold, context=context, budget=None,
        transfer_details={"sender": sender, "recipient": recipient, "amount": 10},
        transfer_index=1,
    )


# -- apply harness (modeled on tests/test_user_rule_apply_screen.py) -----------

def _parent_snapshot(balances, *, recipient_on=True, clauses=None,
                     open_parks=None, timestamp=1700000000, tau_bytes=b""):
    lm = ConsensusLifecycleManager()
    lm.active_validators = [PROPOSER]
    if recipient_on:
        lm.activate_recipient_policy()
    if clauses:
        for (pubkey, stream), body in clauses.items():
            lm.rule_offers.accepted_clauses[(pubkey.lower(), stream)] = body
    if open_parks:
        from consensus.retractable import RetractableBook, RetractableEntry, ZERO_ACC
        rows = []
        for sender, recipient, amount, seq, kind, release_at in open_parks:
            entry = RetractableEntry(sender, recipient, amount, seq, kind, release_at)
            rows.append((entry.retractable_id, sender, recipient, amount, seq, kind, release_at))
        lm.retractable_transfers = RetractableBook.restore(rows, 0, ZERO_ACC)
    acc_hash = chain_state.compute_accounts_hash(balances, {})
    meta_hash = compute_consensus_meta_hash(
        host_contract={}, active_validators=[PROPOSER],
        pending_updates=[], vote_records=[],
        activation_schedule=[], checkpoint_references=[],
    )
    state_hash = compute_consensus_state_hash(b"", b"", acc_hash, meta_hash)
    return TauStateSnapshot(
        state_hash=state_hash,
        tau_bytes=tau_bytes,
        metadata={
            "balances": dict(balances),
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "active_consensus_id": "tau_poa_v1",
            "last_transfer_ts": {},
            "consensus_rules_state": b"",
        },
    )


def _block(txs, block_number=1, timestamp=1700000000):
    import block as block_mod

    return block_mod.Block.create(
        block_number=block_number,
        previous_hash="0" * 64,
        transactions=txs,
        proposer_pubkey=PROPOSER,
        timestamp=timestamp,
    )


def _apply(txs, balances=None, *, recipient_on=True, clauses=None,
           open_parks=None, multi=None, tau_bytes=b""):
    """Apply `txs` in one block; returns (result, outcomes, balances).

    `outcomes` maps tx_id -> TransactionOutcome (status "applied"/"invalid",
    reason, receipt_logs — the receipt log line is the persisted detail
    trail, so a max-hold refusal's cap is asserted there). `multi` may be
    a dict of o-stream values or a callable(inputs) -> dict, so a test can
    branch the mock on the guarded step's i12.
    """
    engine = TauConsensusEngine()
    parent = _parent_snapshot(
        balances or {ALICE: 1_000_000, BOB: 1_000_000, CAROL: 1_000_000,
                     MALLORY: 1_000_000},
        recipient_on=recipient_on, clauses=clauses, open_parks=open_parks,
        tau_bytes=tau_bytes,
    )
    view = engine.derive_active_consensus(parent, 1)
    blk = _block(txs)
    multi_map = multi if multi is not None else {1: "1", 5: "1", 8: "0", 9: "0"}
    steps = []

    def _multi(*args, **kwargs):
        inputs = kwargs.get("input_stream_values", {})
        steps.append(kwargs)
        if callable(multi_map):
            return multi_map(inputs)
        return dict(multi_map)

    with patch("tau_manager.tau_ready") as mock_ready, \
            patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
            patch("tau_manager.communicate_with_tau", return_value="ok"), \
            patch("chain_state.get_application_rules_state",
                  return_value=tau_bytes.decode("utf-8", errors="ignore")):
        mock_ready.is_set.return_value = True
        result = engine.apply_block(view, blk, parent)
    outcomes = {o.tx_id: o for o in result.outcomes}
    return result, outcomes, result.next_snapshot.metadata["balances"], steps


def _tx(tx_id, sender_sk, sender, ops, *, seq=0, fee_limit="50", tx_type="user_tx"):
    payload = {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "fee_limit": fee_limit,
        "operations": ops,
    }
    return sign_tx(payload, sender_sk)


def _transfer_tx(tx_id, sender_sk, sender, recipient, amount=100, *, seq=0):
    return _tx(tx_id, sender_sk, sender, {"1": [[sender, recipient, amount]]}, seq=seq)


def _park_tx(tx_id, sender_sk, sender, recipient, amount=100, *,
             release_at_height=None, release_at_time=None, seq=0):
    payload = {
        "tx_id": tx_id,
        "tx_type": "retractable_transfer",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "fee_limit": "50",
        "recipient_pubkey": recipient,
        "amount": amount,
    }
    if release_at_height is not None:
        payload["release_at_height"] = release_at_height
    if release_at_time is not None:
        payload["release_at_time"] = release_at_time
    return sign_tx(payload, sender_sk)


def _retract_tx(tx_id, sender_sk, sender, rid, *, seq=0):
    payload = {
        "tx_id": tx_id,
        "tx_type": "retract_transfer",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "fee_limit": "50",
        "retractable_id": rid.hex(),
    }
    return sign_tx(payload, sender_sk)


def _is_refused(outcome):
    return outcome is not None and outcome.status == "invalid"

# ---------------------------------------------------------------------------
# #47 — inbound allow-list
# ---------------------------------------------------------------------------

def test_47_1_allowlist_admits_sender_a_refuses_sender_b_at_admission_and_apply():
    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    tip = _StubTip({(BOB, 5): body})

    # Admission: A -> R admitted, B -> R refused, A -> S untouched.
    assert _gate(tip, BOB, ALICE) is None
    refusal = _gate(tip, BOB, CAROL)
    assert refusal is not None and refusal["ok"] is False
    assert refusal["code"] == "TX_REJECTED"
    assert refusal["details"]["recipient_policy"]["reason"] == "recipient_policy_block"
    assert refusal["details"]["recipient_policy"]["code"] == "RECIPIENT_POLICY_BLOCK"
    assert _gate(tip, CAROL, ALICE) is None

    # Apply: the same verdicts, the same recipient.
    clauses = {(BOB, 5): body}
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t1", SK_ALICE, ALICE, BOB)], clauses=clauses)
    assert outcomes["t1"].status == "applied"
    assert balances[BOB] == 1_000_100
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t2", SK_CAROL, CAROL, BOB)], clauses=clauses)
    assert _is_refused(outcomes["t2"])
    assert outcomes["t2"].reason == "recipient_policy_block"
    assert balances[BOB] == 1_000_000
    assert balances[CAROL] == 1_000_000


def test_47_2_neutral_default_no_policy_allows_everyone():
    # No clause anywhere: every sender admitted, admission and apply.
    tip = _StubTip({})
    assert _gate(tip, BOB, ALICE) is None
    assert _gate(tip, BOB, CAROL) is None
    assert _gate(tip, BOB, MALLORY) is None
    _, outcomes, balances, _ = _apply([
        _transfer_tx("t1", SK_ALICE, ALICE, BOB),
        _transfer_tx("t2", SK_CAROL, CAROL, BOB, seq=0),
    ])
    # (Two txs in one block: the second sender's sequence is independent.)
    assert outcomes["t1"].status == "applied"
    assert outcomes["t2"].status == "applied"
    assert balances[BOB] == 1_000_200

    # A clause that never mentions o5 is the same neutral default.
    neutral = "always ( o13[t]:bv[24] = i13[t]:bv[24] )."
    tip = _StubTip({(BOB, 5): neutral})
    assert _gate(tip, BOB, CAROL) is None


def test_47_3_batch_atomicity_one_refused_output_fails_whole_tx():
    carol_body = allowlist_body(MALLORY)
    _install(carol_body, _decide_allowlist(MALLORY))
    clauses = {(CAROL, 5): carol_body}
    tx = _tx("t1", SK_ALICE, ALICE, {
        "1": [[ALICE, BOB, 100], [ALICE, CAROL, 50]],
    })
    _, outcomes, balances, _ = _apply([tx], clauses=clauses)
    assert _is_refused(outcomes["t1"])
    assert outcomes["t1"].reason == "recipient_policy_block"
    # Atomicity: the good output did not move either.
    assert balances[BOB] == 1_000_000
    assert balances[CAROL] == 1_000_000
    assert balances[ALICE] == 1_000_000


def test_47_4_one_unit_carries_inbound_and_outbound():
    body = combined_body(ALICE, CAROL)
    _install(body, _decide_combined(ALICE, CAROL))
    tip = _StubTip({(BOB, 5): body})
    # Inbound: A admitted, B refused.
    assert _gate(tip, BOB, ALICE) is None
    refusal = _gate(tip, BOB, CAROL)
    assert refusal is not None
    assert refusal["details"]["recipient_policy"]["reason"] == "recipient_policy_block"
    # Outbound (context 0): BOB -> CAROL admitted, BOB -> ALICE refused.
    # The sender pass carries i16=0/i17=0, so the outbound branch judges:
    # judged directly through clause_blocks, the same helper Step 3 uses.
    from consensus.sender_policy import clause_blocks, sender_pass_inputs

    blocked, _ = clause_blocks(
        body, sender_pass_inputs(_values(BOB, CAROL)), pool="admission")
    assert not blocked
    blocked, _ = clause_blocks(
        body, sender_pass_inputs(_values(BOB, ALICE)), pool="admission")
    assert blocked

    # Apply: inbound A -> BOB passes, B -> BOB refused; outbound
    # BOB -> CAROL passes, BOB -> ALICE refused.
    clauses = {(BOB, 5): body}
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t1", SK_ALICE, ALICE, BOB)], clauses=clauses)
    assert outcomes["t1"].status == "applied"
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t2", SK_CAROL, CAROL, BOB)], clauses=clauses)
    assert _is_refused(outcomes["t2"])
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t3", SK_BOB, BOB, CAROL)], clauses=clauses)
    assert outcomes["t3"].status == "applied"
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t4", SK_BOB, BOB, ALICE)], clauses=clauses)
    assert _is_refused(outcomes["t4"])
    # The refusal is the SENDER side: BOB's own outbound branch (context 0)
    # refuses BOB -> ALICE before any recipient is consulted.
    assert outcomes["t4"].reason == "user_policy_block"


def test_47_5_capability_reporting_and_deploy_refusal_on_gate_less_node():
    # Capability reporting: getgovernance says whether the gate is live.
    import types
    import db as _db

    import chain_state as _cs
    from commands import getgovernance

    container = types.SimpleNamespace(chain_state=_cs, db=_db)
    old_lm = _cs._lifecycle_manager
    try:
        lm_off = ConsensusLifecycleManager()
        _cs._lifecycle_manager = lm_off
        payload = json.loads(getgovernance.execute("getgovernance", container))
        caps = payload["data"]["capabilities"]["recipient_controls"]
        assert caps["active"] is False
        assert caps["hold_stream"] == 17
        assert caps["context_stream"] == 16
        assert caps["preflight_command"] == "getrecipientpolicy"

        lm_on = ConsensusLifecycleManager()
        lm_on.activate_recipient_policy()
        _cs._lifecycle_manager = lm_on
        payload = json.loads(getgovernance.execute("getgovernance", container))
        assert payload["data"]["capabilities"]["recipient_controls"]["active"] is True
        assert payload["data"]["recipient_policy_active"] is True
    finally:
        _cs._lifecycle_manager = old_lm

    # Deploy refusal on a gate-less node: an inbound-capable rule tx is
    # refused RECIPIENT_POLICY_INACTIVE while the flag is off, admitted
    # once governance activates it.
    from consensus.admission import validate_rule_change_request_payload
    from consensus.approvals import TX_TYPE_RULE_CHANGE_REQUEST

    body = allowlist_body(ALICE)
    tx = {
        "tx_type": TX_TYPE_RULE_CHANGE_REQUEST,
        "kind": tau_defs.RULE_CHANGE_KIND_SET_POLICY,
        "sender_pubkey": BOB,
        "sequence_number": 0,
        "expire_at_height": 5000,
        "rule_text": body,
    }
    tip_off = _StubTip({}, active=False)
    result = validate_rule_change_request_payload(tx, tip_off)
    assert not result.is_valid
    assert result.code == "RECIPIENT_POLICY_INACTIVE"
    assert "not active on this chain" in result.error
    tip_on = _StubTip({}, active=True)
    result = validate_rule_change_request_payload(tx, tip_on)
    assert result.is_valid, result.error


# ---------------------------------------------------------------------------
# #76 — max hold time
# ---------------------------------------------------------------------------

def test_76_1_cap_zero_admits_plain_refuses_every_park():
    body = cap_body(0, 0)
    _install(body, _decide_cap(0, 0))
    tip = _StubTip({(BOB, 5): body})
    # Admission: plain transfer admitted; both park kinds refused.
    assert _gate(tip, BOB, ALICE, hold=0, context=1) is None
    for hold, context in ((1, 2), (3600, 2), (1, 3), (100, 3)):
        refusal = _gate(tip, BOB, ALICE, hold=hold, context=context)
        assert refusal is not None, (hold, context)
        assert refusal["code"] == "RECIPIENT_MAX_HOLD"
        rp = refusal["details"]["recipient_policy"]
        assert rp["hold"] == hold
        if context == 2:
            assert rp["unit"] == "seconds"
            assert rp["max_hold_seconds"] == 0
        else:
            assert rp["unit"] == "blocks"
            assert rp["max_hold_blocks"] == 0

    # Apply: plain passes; a 1-second park and a 1-block park are refused.
    clauses = {(BOB, 5): body}
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t1", SK_ALICE, ALICE, BOB)], clauses=clauses)
    assert outcomes["t1"].status == "applied"
    _, outcomes, balances, _ = _apply(
        [_park_tx("p1", SK_ALICE, ALICE, BOB, release_at_time=1700000001)],
        clauses=clauses)
    assert _is_refused(outcomes["p1"])
    assert outcomes["p1"].reason == "recipient_max_hold"
    assert balances[BOB] == 1_000_000
    _, outcomes, balances, _ = _apply(
        [_park_tx("p2", SK_ALICE, ALICE, BOB, release_at_height=2)],
        clauses=clauses)
    assert _is_refused(outcomes["p2"])
    assert outcomes["p2"].reason == "recipient_max_hold"


def test_76_2_cap_600s_admits_10min_park_refuses_hour_park():
    body = cap_body(600, 10)
    _install(body, _decide_cap(600, 10))
    tip = _StubTip({(BOB, 5): body})
    # Admission: 600s admitted, 3600s refused with the cap in the details.
    assert _gate(tip, BOB, ALICE, hold=600, context=2) is None
    refusal = _gate(tip, BOB, ALICE, hold=3600, context=2)
    assert refusal["code"] == "RECIPIENT_MAX_HOLD"
    rp = refusal["details"]["recipient_policy"]
    assert rp["hold"] == 3600 and rp["unit"] == "seconds"
    assert rp["max_hold_seconds"] == 600
    assert rp["cap_kind"] == "threshold"

    # Apply: the 10-minute park lands, the hour park is refused, and the
    # refusal's log line carries the cap (the persisted detail trail).
    clauses = {(BOB, 5): body}
    _, outcomes, balances, _ = _apply(
        [_park_tx("p1", SK_ALICE, ALICE, BOB, release_at_time=1700000600)],
        clauses=clauses)
    assert outcomes["p1"].status == "applied"
    _, outcomes, balances, _ = _apply(
        [_park_tx("p2", SK_ALICE, ALICE, BOB, release_at_time=1700003600)],
        clauses=clauses)
    assert _is_refused(outcomes["p2"])
    assert outcomes["p2"].reason == "recipient_max_hold"
    assert any("max_hold_seconds=600" in log for log in outcomes["p2"].receipt_logs)
    assert any("hold=3600" in log for log in outcomes["p2"].receipt_logs)


def test_76_3_neutral_default_no_policy_parks_any_length():
    tip = _StubTip({})
    assert _gate(tip, BOB, ALICE, hold=10**9, context=2) is None
    assert _gate(tip, BOB, ALICE, hold=10**9, context=3) is None
    _, outcomes, balances, _ = _apply([
        _park_tx("p1", SK_ALICE, ALICE, BOB, release_at_time=1700000000 + 86400),
        _park_tx("p2", SK_CAROL, CAROL, BOB, release_at_height=1000, seq=0),
    ])
    assert outcomes["p1"].status == "applied"
    assert outcomes["p2"].status == "applied"


def test_76_4_retract_never_gated():
    from consensus.retractable import KIND_HEIGHT, RetractableEntry
    from consensus.admission import validate_retract_transfer_payload

    body = cap_body(0, 0)
    _install(body, _decide_cap(0, 0))
    # An open park to the capped recipient, parked before the cap existed.
    entry = RetractableEntry(ALICE, BOB, 100, 0, KIND_HEIGHT, 100)
    tip = _StubTip({(BOB, 5): body}, height=50)
    tip._retractables[entry.retractable_id] = {
        "sender_pubkey": ALICE, "release_kind": KIND_HEIGHT, "release_at": 100,
    }
    tx = {
        "tx_type": "retract_transfer",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "retractable_id": entry.retractable_id.hex(),
    }
    result = validate_retract_transfer_payload(tx, tip)
    assert result.is_valid, result.error

    # Apply: the retract lands and the escrow returns to the sender, even
    # though the recipient's cap is 0.
    _, outcomes, balances, _ = _apply(
        [_retract_tx("r1", SK_ALICE, ALICE, entry.retractable_id)],
        clauses={(BOB, 5): body},
        open_parks=[(ALICE, BOB, 100, 0, KIND_HEIGHT, 100)],
        balances={ALICE: 999_900, BOB: 1_000_000, CAROL: 1_000_000,
                  MALLORY: 1_000_000},
    )
    assert outcomes["r1"].status == "applied", outcomes["r1"]
    assert balances[ALICE] == 1_000_000


def test_76_5_refusal_message_carries_cap():
    body = cap_body(600, 10)
    _install(body, _decide_cap(600, 10))
    tip = _StubTip({(BOB, 5): body})
    refusal = _gate(tip, BOB, ALICE, hold=3600, context=2)
    assert refusal["code"] == "RECIPIENT_MAX_HOLD"
    assert "3600" in refusal["message"]
    rp = refusal["details"]["recipient_policy"]
    assert rp["max_hold_seconds"] == 600
    assert rp["cap_kind"] == "threshold"

    # Apply: the receipt log line carries hold, unit and cap.
    _, outcomes, balances, _ = _apply(
        [_park_tx("p1", SK_ALICE, ALICE, BOB, release_at_time=1700003600)],
        clauses={(BOB, 5): body})
    assert _is_refused(outcomes["p1"])
    logs = " ".join(outcomes["p1"].receipt_logs)
    assert "recipient_max_hold" in logs
    assert "hold=3600" in logs and "unit=seconds" in logs
    assert "max_hold_seconds=600" in logs


def test_76_6_capability_reporting_and_deploy_refusal():
    # A cap rule cannot deploy while the gate is off; it deploys once active.
    from consensus.admission import validate_rule_change_request_payload
    from consensus.approvals import TX_TYPE_RULE_CHANGE_REQUEST

    body = cap_body(600, 10)
    tx = {
        "tx_type": TX_TYPE_RULE_CHANGE_REQUEST,
        "kind": tau_defs.RULE_CHANGE_KIND_SET_POLICY,
        "sender_pubkey": BOB,
        "sequence_number": 0,
        "expire_at_height": 5000,
        "rule_text": body,
    }
    result = validate_rule_change_request_payload(tx, _StubTip({}, active=False))
    assert not result.is_valid
    assert result.code == "RECIPIENT_POLICY_INACTIVE"
    assert "not active on this chain" in result.error
    result = validate_rule_change_request_payload(tx, _StubTip({}, active=True))
    assert result.is_valid, result.error

    # getrecipientpolicy judges a concrete payment against the cap.
    from commands import getrecipientpolicy

    _install(body, _decide_cap(600, 10))
    tip = _StubTip({(BOB, 5): body})
    with patch("consensus.facade.TipAdmissionView", lambda: tip):
        payload = json.loads(getrecipientpolicy.execute(
            f"getrecipientpolicy {BOB} {ALICE} 3600 seconds", None))
    judged = payload["data"]["judged"]
    assert judged["blocked"] is True
    assert judged["reason"] == "recipient_max_hold"
    assert judged["max_hold_seconds"] == 600
    assert judged["cap_kind"] == "threshold"
    with patch("consensus.facade.TipAdmissionView", lambda: tip):
        payload = json.loads(getrecipientpolicy.execute(
            f"getrecipientpolicy {BOB} {ALICE} 600 seconds", None))
    assert payload["data"]["judged"]["blocked"] is False

# ---------------------------------------------------------------------------
# Extras — guarded mode, overlay, honesty, screens, fee, activation
# ---------------------------------------------------------------------------

def test_guarded_mode_blocks_at_apply_and_passes_when_spec_allows():
    # A guarded unit of the recipient's, present in the spec, vetoes a
    # transfer the clause mode admits. The mock branches on i12: when the
    # guarded step sets i12 to BOB, o5 is 0; otherwise 1.
    body = allowlist_body(ALICE)  # clause mode admits A -> BOB
    _install(body, _decide_allowlist(ALICE))
    spec = (
        "always ( (i12[t]:bv[384] = " + _lit384(BOB) + ") ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )

    def multi(inputs):
        i12 = str(inputs.get(12, ""))
        if i12.startswith("{"):
            i12 = i12[1:i12.index("}")].strip()
        return {1: "1", 5: "0" if i12.lower() == f"#x{BOB.lower()}" else "1",
                8: "0", 9: "0"}

    _, outcomes, balances, steps = _apply(
        [_transfer_tx("t1", SK_ALICE, ALICE, BOB)],
        clauses={(BOB, 5): body}, multi=multi,
        tau_bytes=spec.encode())
    assert _is_refused(outcomes["t1"])
    assert outcomes["t1"].reason == "recipient_policy_block"
    assert any("guarded" in log for log in outcomes["t1"].receipt_logs)
    assert balances[BOB] == 1_000_000
    assert any(kw.get("input_stream_values", {}).get(12) is not None
               for kw in steps)

    # The same transfer passes when the guarded step allows it.
    def multi_allow(inputs):
        return {1: "1", 5: "1", 8: "0", 9: "0"}

    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t2", SK_ALICE, ALICE, BOB)],
        clauses={(BOB, 5): body}, multi=multi_allow,
        tau_bytes=spec.encode())
    assert outcomes["t2"].status == "applied"
    assert balances[BOB] == 1_000_100


def test_sender_pass_overlay_keeps_inbound_rules_off_outgoing():
    # BOB's clause refuses CAROL inbound; BOB's own payment to CAROL must
    # not be judged by the inbound branch (i16=0, i17=0 on the sender pass).
    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    tip = _StubTip({(BOB, 5): body})
    assert _gate(tip, CAROL, BOB, context=0) is None
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t1", SK_BOB, BOB, CAROL)], clauses={(BOB, 5): body})
    assert outcomes["t1"].status == "applied"
    assert balances[CAROL] == 1_000_100


def test_self_transfer_exempt_from_recipient_gate():
    # #127's self-transfer wart, and why it cannot recur here: a
    # self-transfer is refused upstream by the transfer shape check
    # ("'to' address is the sender") before any policy is consulted, so
    # the recipient gate never sees it — and never refuses it either.
    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t1", SK_BOB, BOB, BOB)], clauses={(BOB, 5): body})
    assert _is_refused(outcomes["t1"])
    assert outcomes["t1"].reason != "recipient_policy_block"
    assert not any("recipient policy" in log
                   for log in outcomes["t1"].receipt_logs)


def test_non_monotonic_rule_reports_cap_kind_rule_with_no_number():
    # A rule that refuses hold 1 but admits 0 and 2 has no cap to print:
    # the candidate (1, from `i17 > 1`) fails verification, so the refusal
    # is reported honestly as cap_kind "rule".
    body = (
        "always ( ((i16[t]:bv[64] = " + _lit64(2) + ") && "
        "(i17[t]:bv[64] > " + _lit64(1) + ")) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )

    def decide(inputs):
        ctx = int(_bare(inputs, 16) or 0)
        hold = int(_bare(inputs, 17) or 0)
        if ctx == 2 and hold == 1:
            return "0"
        return "1"

    _install(body, decide)
    tip = _StubTip({(BOB, 5): body})
    refusal = _gate(tip, BOB, ALICE, hold=1, context=2)
    assert refusal["code"] == "RECIPIENT_MAX_HOLD"
    rp = refusal["details"]["recipient_policy"]
    assert rp["cap_kind"] == "rule"
    assert "max_hold_seconds" not in rp
    assert "max_hold_blocks" not in rp


def test_per_payer_caps_never_reported_to_the_wrong_payer():
    body = per_payer_cap_body(600, 60, CAROL)
    _install(body, _decide_per_payer(600, 60, CAROL))
    tip = _StubTip({(BOB, 5): body})
    # A (cap 600): 300 admitted, 700 refused with A's cap, not B's 60.
    assert _gate(tip, BOB, ALICE, hold=300, context=2) is None
    refusal = _gate(tip, BOB, ALICE, hold=700, context=2)
    assert refusal["details"]["recipient_policy"]["max_hold_seconds"] == 600
    # B (cap 60): 61 refused with B's cap.
    refusal = _gate(tip, BOB, CAROL, hold=61, context=2)
    assert refusal["details"]["recipient_policy"]["max_hold_seconds"] == 60


def test_unit_blind_hold_rule_refused_at_deploy():
    from consensus.admission import validate_rule_change_request_payload
    from consensus.approvals import TX_TYPE_RULE_CHANGE_REQUEST

    tx = {
        "tx_type": TX_TYPE_RULE_CHANGE_REQUEST,
        "kind": tau_defs.RULE_CHANGE_KIND_SET_POLICY,
        "sender_pubkey": BOB,
        "sequence_number": 0,
        "expire_at_height": 5000,
        "rule_text": unit_blind_body(600),
    }
    result = validate_rule_change_request_payload(tx, _StubTip({}, active=True))
    assert not result.is_valid
    assert "unit-blind recipient hold rule" in result.error


def test_wrong_width_recipient_stream_refused_at_deploy():
    from consensus.admission import validate_rule_change_request_payload
    from consensus.approvals import TX_TYPE_RULE_CHANGE_REQUEST

    tx = {
        "tx_type": TX_TYPE_RULE_CHANGE_REQUEST,
        "kind": tau_defs.RULE_CHANGE_KIND_SET_POLICY,
        "sender_pubkey": BOB,
        "sequence_number": 0,
        "expire_at_height": 5000,
        "rule_text": wrong_width_body(),
    }
    result = validate_rule_change_request_payload(tx, _StubTip({}, active=True))
    assert not result.is_valid


def test_fee_not_charged_on_recipient_block_at_apply():
    # The consensus fee (o9=5) is deducted from an accepted transfer and
    # NOT from a transfer the recipient refuses (engine.py: fee settles
    # only when `charge_fee and accepted_in_block and not hard_reject`).
    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    clauses = {(BOB, 5): body}
    multi = {1: "1", 5: "1", 8: "0", 9: "5"}
    parent = {ALICE: 1_000_000, BOB: 1_000_000, CAROL: 1_000_000,
              MALLORY: 1_000_000, PROPOSER: 1_000_000}
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t1", SK_ALICE, ALICE, BOB)], clauses=clauses,
        multi=multi, balances=parent)
    assert outcomes["t1"].status == "applied"
    assert balances[ALICE] == 1_000_000 - 100 - 5
    assert balances[BOB] == 1_000_100
    assert balances[PROPOSER] == 1_000_005
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t2", SK_CAROL, CAROL, BOB)], clauses=clauses,
        multi=multi, balances=parent)
    assert _is_refused(outcomes["t2"])
    assert balances[CAROL] == 1_000_000
    assert balances[BOB] == 1_000_000
    assert balances[PROPOSER] == 1_000_000


def test_activation_audit_refuses_on_stream_collision_in_spec():
    # A complete spec that already reads i17 (e.g. a rule the network
    # deployed for something else) blocks activation: the streams are
    # reserved exactly at activation, never silently shared.
    from consensus.approvals import audit_recipient_stream_collisions

    spec_with_i17 = (
        "always ( (i17[t]:bv[64] > " + _lit64(5) + ") ? "
        "(o13[t]:bv[24] = { #x000001 }:bv[24]) : "
        "(o13[t]:bv[24] = { #x000000 }:bv[24]) )."
    )
    findings = audit_recipient_stream_collisions([("spec", spec_with_i17)])
    assert findings, "a spec reading i17 must block activation"
    assert audit_recipient_stream_collisions([("spec", "always (o13[t]:bv[24] = i13[t]:bv[24]).")]) == []


def test_cooldown_mutual_exclusion():
    # #140's open debt, discharged with guards, not docs alone: while the
    # cooldown feed is live, activation raises; and the reserved-key set
    # refuses to hold both flags at once.
    import tau_defs as _td

    lm = ConsensusLifecycleManager()
    with patch.object(_td, "COOLDOWN_STREAM_ACTIVE", True):
        with pytest.raises(ValueError):
            lm.activate_recipient_policy()
    lm2 = ConsensusLifecycleManager()
    lm2.activate_recipient_policy()
    assert lm2.recipient_policy_active is True
    # Reserved keys refuse to hold both flags at once (cooldown live AND
    # recipient active) — never silently share i16.
    with patch.object(_td, "COOLDOWN_STREAM_ACTIVE", True):
        with pytest.raises(ValueError):
            _td.reserved_operation_keys(recipient_policy_active=True)
    # The predicate the governance path consults:
    with patch.object(_td, "COOLDOWN_STREAM_ACTIVE", True):
        assert _td.recipient_policy_conflicts_with_cooldown() is True
    assert _td.recipient_policy_conflicts_with_cooldown() is False


def test_memorable_moment_height_park_refused_while_seconds_park_passes():
    # The memorable moment: one recipient, one cap (600s / 10 blocks). A
    # 600-block height park is refused with max_hold_blocks=10 in the
    # receipt while a 600-second park to the same recipient passes.
    body = cap_body(600, 10)
    _install(body, _decide_cap(600, 10))
    clauses = {(BOB, 5): body}
    _, outcomes, balances, _ = _apply(
        [_park_tx("p1", SK_ALICE, ALICE, BOB, release_at_time=1700000600)],
        clauses=clauses)
    assert outcomes["p1"].status == "applied"
    _, outcomes, balances, _ = _apply(
        [_park_tx("p2", SK_ALICE, ALICE, BOB, release_at_height=601)],
        clauses=clauses)
    assert _is_refused(outcomes["p2"])
    assert outcomes["p2"].reason == "recipient_max_hold"
    logs = " ".join(outcomes["p2"].receipt_logs)
    assert "hold=600" in logs and "unit=blocks" in logs
    assert "max_hold_blocks=10" in logs


def test_sabotage_gate_disabled_acceptance_tests_fail():
    # Sabotage check: with the gate disabled (flag off), the acceptance
    # behaviour disappears — the very transfers the gate must refuse are
    # admitted, so the acceptance tests above would fail on this build.
    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    _, outcomes, balances, _ = _apply(
        [_transfer_tx("t1", SK_CAROL, CAROL, BOB)],
        clauses={(BOB, 5): body}, recipient_on=False)
    assert outcomes["t1"].status == "applied"
    assert balances[BOB] == 1_000_100
    body2 = cap_body(600, 10)
    _install(body2, _decide_cap(600, 10))
    _, outcomes, balances, _ = _apply(
        [_park_tx("p1", SK_ALICE, ALICE, BOB, release_at_time=1700003600)],
        clauses={(BOB, 5): body2}, recipient_on=False)
    assert outcomes["p1"].status == "applied"


# ---------------------------------------------------------------------------
# getrecipientpolicy command
# ---------------------------------------------------------------------------

def test_getrecipientpolicy_reports_neutral_default_and_inactive():
    from commands import getrecipientpolicy

    tip = _StubTip({})
    with patch("consensus.facade.TipAdmissionView", lambda: tip):
        payload = json.loads(getrecipientpolicy.execute(
            f"getrecipientpolicy {BOB}", None))
    result = payload["data"]
    assert result["recipient_policy_active"] is True
    assert result["has_clause"] is False
    assert result["neutral_default"] is True

    tip_off = _StubTip({}, active=False)
    with patch("consensus.facade.TipAdmissionView", lambda: tip_off):
        payload = json.loads(getrecipientpolicy.execute(
            f"getrecipientpolicy {BOB}", None))
    assert payload["data"]["recipient_policy_active"] is False
    assert "not active" in payload["data"]["note"]


def test_getrecipientpolicy_rejects_bad_params():
    from commands import getrecipientpolicy

    payload = json.loads(getrecipientpolicy.execute("getrecipientpolicy", None))
    assert payload["status"] == "error"
    payload = json.loads(getrecipientpolicy.execute(
        f"getrecipientpolicy {BOB} {ALICE} -1 seconds", None))
    assert payload["status"] == "error"
    payload = json.loads(getrecipientpolicy.execute(
        f"getrecipientpolicy {BOB} {ALICE} 10 fortnights", None))
    assert payload["status"] == "error"

# ---------------------------------------------------------------------------
# Full sendtx wire-up (real queue_transaction, real TipAdmissionView, temp DB)
# ---------------------------------------------------------------------------

from contextlib import ExitStack
import os
import time

import db as _db
from bls_keys import sign_payload


@pytest.fixture
def sendtx_env(temp_database):
    """Full sendtx wire-up: temp DB, active recipient gate, mocked Tau."""
    lm = ConsensusLifecycleManager()
    lm.activate_recipient_policy()
    chain_state._lifecycle_manager = lm
    chain_state._balances[ALICE] = 1_000_000
    chain_state._balances[CAROL] = 1_000_000
    stack = ExitStack()
    ready = stack.enter_context(patch("tau_manager.tau_ready"))
    ready.is_set.return_value = True
    stack.enter_context(patch(
        "tau_manager.communicate_with_tau_multi", return_value={1: "1"}))
    stack.enter_context(patch(
        "tau_manager.communicate_with_tau", return_value="x1001"))
    stack.enter_context(patch(
        "tau_native.compile_revisions_isolated_subprocess", return_value=None))
    stack.enter_context(patch(
        "commands.sendtx.chain_state.get_sequence_number", return_value=1))
    stack.enter_context(patch(
        "commands.sendtx.db.get_pending_sequence", return_value=None))
    stack.enter_context(patch(
        "commands.sendtx.validate_bls_pubkey", return_value=None))
    stack.enter_context(patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}))
    yield stack
    stack.close()


def _register_clause(pubkey, body):
    with _db._db_lock:
        _db._db_conn.execute(
            "INSERT OR REPLACE INTO rule_clauses_v1 "
            "(acceptor_pubkey, target_stream, clause_body) VALUES (?, ?, ?)",
            (pubkey.lower(), 5, body),
        )
        _db._db_conn.commit()


def _queue(payload):
    from commands import sendtx

    with patch("commands.sendtx.db.add_mempool_tx") as mock_add:
        result = sendtx.queue_transaction(json.dumps(payload), propagate=False)
    return result, mock_add


def _sendtx_payload(sender, sk, ops, *, seq=1):
    return sign_payload({
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "operations": ops,
        "fee_limit": "100",
    }, sk)


def test_sendtx_allowlist_refuses_b_end_to_end(sendtx_env):
    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    _register_clause(BOB, body)

    result, _ = _queue(_sendtx_payload(ALICE, SK_ALICE, {"1": [[ALICE, BOB, 100]]}))
    assert result["ok"] is True, result
    result, _ = _queue(_sendtx_payload(CAROL, SK_CAROL, {"1": [[CAROL, BOB, 100]]}))
    assert result["ok"] is False, result
    assert result["code"] == "TX_REJECTED"
    assert result["details"]["recipient_policy"]["reason"] == "recipient_policy_block"


def test_sendtx_cap_600s_refuses_hour_park_end_to_end(sendtx_env):
    body = cap_body(600, 10)
    _install(body, _decide_cap(600, 10))
    _register_clause(BOB, body)
    now = int(time.time())

    def park_payload(release_at_time, sk=SK_ALICE, sender=ALICE):
        return sign_payload({
            "tx_type": "retractable_transfer",
            "sender_pubkey": sender,
            "sequence_number": 1,
            "expiration_time": release_at_time - 60,
            "expire_at_height": 5000,
            "recipient_pubkey": BOB,
            "amount": 100,
            "release_at_time": release_at_time,
            "fee_limit": "100",
        }, sk)

    result, _ = _queue(park_payload(now + 600))
    assert result["ok"] is True, result
    result, _ = _queue(park_payload(now + 3600))
    assert result["ok"] is False, result
    assert result["code"] == "RECIPIENT_MAX_HOLD"
    assert result["details"]["recipient_policy"]["max_hold_seconds"] == 600


def test_sendtx_guarded_refusal_carries_mode(sendtx_env):
    # A plain transfer the clause admits is refused by the guarded unit in
    # the running spec — and the envelope says so (mode=guarded), so a
    # wallet can tell a guarded veto from a clause refusal.
    from commands import sendtx as _sendtx_mod

    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    _register_clause(BOB, body)
    guarded = (
        "always ( ((i12[t]:bv[384] = " + _lit384(BOB) + ") && "
        "(i4[t]:bv[384] = " + _lit384(BOB) + ") && "
        "(i16[t]:bv[64] = " + _lit64(1) + ")) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    )
    old_rules = chain_state._application_rules_state
    chain_state._application_rules_state = guarded
    try:
        def multi(*args, **kwargs):
            inputs = kwargs.get("input_stream_values", {})
            i12 = str(inputs.get(12, ""))
            if i12.startswith("{"):
                i12 = i12[1:i12.index("}")].strip()
            # The guarded step (i12 == bob) vetoes; every other step allows.
            return {1: "1", 5: "0" if i12.lower() == f"#x{BOB.lower()}" else "1"}

        with patch("tau_manager.communicate_with_tau_multi",
                   side_effect=multi):
            result, _ = _queue(
                _sendtx_payload(ALICE, SK_ALICE, {"1": [[ALICE, BOB, 100]]}))
        assert result["ok"] is False, result
        assert result["code"] == "TX_REJECTED"
        rp = result["details"]["recipient_policy"]
        assert rp["reason"] == "recipient_policy_block"
        assert rp["mode"] == "guarded"
    finally:
        chain_state._application_rules_state = old_rules


def test_sendtx_rule_offer_not_gated(sendtx_env):
    # rule_offer is how a recipient RECEIVES a policy offer: the offer
    # itself is never judged by the recipient gate (it is not a payment).
    body = allowlist_body(ALICE)
    _install(body, _decide_allowlist(ALICE))
    _register_clause(BOB, body)
    payload = sign_payload({
        "tx_type": "rule_offer",
        "sender_pubkey": ALICE,
        "sequence_number": 1,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "recipient_pubkey": BOB,
        "rule_text": body,
        "fee_limit": "100",
    }, SK_ALICE)
    result, _ = _queue(payload)
    # The offer may fail on other (offer-shape) grounds, but never on the
    # recipient gate: no recipient_policy refusal in the envelope.
    assert "recipient_policy" not in str(result.get("details", {})), result
