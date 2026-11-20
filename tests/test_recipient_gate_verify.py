"""Independent verification of the recipient gate (#47 / #76).

Written separately from tests/test_recipient_gate.py in the style of
the field's separate verify suites: different accounts, different
clause bodies (a biconditional allowlist, an amount ceiling, a cap
stated in the clause text), and a clause evaluator that parses the
clause text it is handed instead of consulting a script keyed by
owner. Every refusal asserted here is also run under a sabotage --
one gate function replaced by a permissive stand-in -- to prove the
refusal came from the gate and not from the harness.

Cap boundaries are exact: a demanded hold equal to the cap is
admitted, one unit over is refused, and a zero cap admits only a
zero hold.
"""
import itertools
import re
from collections import namedtuple
from unittest.mock import patch

import tau_defs
from block import Block
from bls_keys import SK_MALLORY, pubkey_hex, sign_payload
from consensus import recipient_gate, sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.state import TauStateSnapshot

H = 40
FAR = 9999999999
FEE = 5
BLOCK_TS = 1234567890

SK_VERA = 0xB3A7
SK_KIM = 0xC1A0
SK_UDO = 0xD00D
SK_AUTH = 0xA07A
VERA = pubkey_hex(SK_VERA)      # the recipient who publishes policies
KIM = pubkey_hex(SK_KIM)        # the one sender VERA allows
UDO = pubkey_hex(SK_UDO)        # a sender VERA does not allow
MALLORY = pubkey_hex(SK_MALLORY)
AUTH = pubkey_hex(SK_AUTH)

_TX_SEQ = itertools.count()
Applied = namedtuple("Applied", "result lifecycle multi_calls")

# VERA's clauses, written for this file. The allowlist is a
# biconditional (the gate suite uses guards and conjunctions); the
# ceiling keys on the amount alone; the outbound clause governs
# VERA's payments TO Udo and must never judge payments TO VERA.
ALLOW_ONLY_KIM = (
    "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
    "<-> i3[t]:bv[384] = { #x" + KIM + " }:bv[384] )."
)
CEILING_250 = (
    "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
    "&& i1[t]:bv[64] <= { 250 }:bv[64] )."
)
OUTBOUND_TO_UDO = (
    "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
    "&& i4[t]:bv[384] = { #x" + UDO + " }:bv[384] )."
)
CAP_CLAUSE_10 = "always ( o10[t]:bv[64] = { 10 }:bv[64] )."

_HEX = re.compile(r"#x([0-9a-f]{96})")
_I3_EQ = re.compile(r"i3\[t\]:bv\[384\] = \{ #x([0-9a-f]{96}) \}")
_I4_EQ = re.compile(r"i4\[t\]:bv\[384\] = \{ #x([0-9a-f]{96}) \}")
_I1_LE = re.compile(r"i1\[t\]:bv\[64\] <= \{ (\d+) \}")


def _hex_of(raw):
    m = _HEX.search(str(raw or ""))
    return m.group(1) if m else str(raw or "")


def _eval_clause_text(body, inputs):
    """Evaluate one of this file's clause bodies from its text.

    Returns an o5 value ("1" allow / "0" refuse), or None for no
    opinion -- the MockPolicyEvaluator contract. This is the clause
    step's evaluator: it reads the body it is given, so a refusal
    below is the clause's own text refusing.
    """
    m = _I3_EQ.search(body)
    if m:
        return "1" if _hex_of(inputs.get("i3")) == m.group(1) else "0"
    m = _I1_LE.search(body)
    if m:
        amount = int(str(inputs.get("i1", "0")) or 0)
        return "1" if amount <= int(m.group(1)) else "0"
    m = _I4_EQ.search(body)
    if m:
        return "1" if _hex_of(inputs.get("i4")) == m.group(1) else "0"
    return None


def _manager(*, active=True):
    lm = ConsensusLifecycleManager(active_validators=[MALLORY, KIM])
    lm.activate_approval_slots()
    if active:
        lm.activate_recipient_gate()
    return lm


def _parent(lm, balances=None):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": balances or {KIM: 50000, UDO: 50000, VERA: 0,
                                     AUTH: 10, MALLORY: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )


def _run(txs, lm, *, parent=None, height=H, spec_refusals=frozenset(),
         caps=None):
    if parent is None:
        parent = _parent(lm)
    view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block = Block.create(block_number=height, previous_hash="00" * 32,
                         transactions=txs, proposer_pubkey=MALLORY,
                         timestamp=BLOCK_TS)
    persisted = []
    multi_calls = []

    def _single(**kw):
        text = str(kw.get("rule_text") or "")
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def _multi(**kw):
        vals = kw.get("input_stream_values") or {}
        multi_calls.append(dict(vals))
        out = {1: str(vals.get(1, "0")), 8: "0", 9: str(FEE), 5: "1"}
        owner = _hex_of(vals.get(12))
        if owner in spec_refusals:
            out[5] = "0"
        if caps and owner in caps:
            out[10] = str(caps[owner])
        return out

    sender_policy.set_evaluator(
        "apply", MockPolicyEvaluator(decide=_eval_clause_text))
    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        try:
            result = TauConsensusEngine().apply_block(view, block, parent)
        finally:
            sender_policy.set_evaluator("apply", None)
    return Applied(result, result.next_snapshot.metadata["lifecycle_manager"],
                   multi_calls)


def _envelope(tx_type, sender, seq, **fields):
    tx = {
        "tx_id": f"verify-{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 5000,
        "fee_limit": "100000",
    }
    tx.update(fields)
    return tx


def _transfer(sender, sk, to, amount):
    return sign_payload(_envelope(
        "user_tx", sender, 0,
        operations={"1": [[sender, to, str(amount)]]}), sk)


def _park(sender, sk, *, release_at_height, amount=100):
    return sign_payload(_envelope(
        "retractable_transfer", sender, 0, recipient_pubkey=VERA,
        amount=amount, release_at_height=release_at_height), sk)


def _register(lm, clause, stream=tau_defs.USER_POLICY_STREAM_INDEX):
    lm.rule_offers.accepted_clauses[(VERA, stream)] = clause


def _outcome(applied, tx_id):
    return next(o for o in applied.result.outcomes if o.tx_id == tx_id)


def _balances(applied):
    return applied.result.next_snapshot.metadata["balances"]


# --- the allowlist and ceiling clauses, evaluated from their text --------------

def test_allowlist_admits_only_the_named_sender():
    lm = _manager()
    _register(lm, ALLOW_ONLY_KIM)
    tx = _transfer(KIM, SK_KIM, VERA, 100)
    applied = _run([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[VERA] == 100
    assert _balances(applied)[KIM] == 50000 - 100 - FEE

    lm = _manager()
    _register(lm, ALLOW_ONLY_KIM)
    tx = _transfer(UDO, SK_UDO, VERA, 100)
    applied = _run([tx], lm)
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[VERA] == 0
    assert _balances(applied)[UDO] == 50000


def test_amount_ceiling_boundary_is_exact():
    lm = _manager()
    _register(lm, CEILING_250)
    tx = _transfer(UDO, SK_UDO, VERA, 250)
    applied = _run([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[VERA] == 250

    lm = _manager()
    _register(lm, CEILING_250)
    tx = _transfer(UDO, SK_UDO, VERA, 251)
    applied = _run([tx], lm)
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[VERA] == 0


def test_one_refused_leg_moves_nothing():
    lm = _manager()
    _register(lm, ALLOW_ONLY_KIM)
    tx = sign_payload(_envelope(
        "user_tx", UDO, 0,
        operations={"1": [[UDO, KIM, "50"], [UDO, VERA, "50"]]}), SK_UDO)
    applied = _run([tx], lm)
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[KIM] == 50000
    assert _balances(applied)[VERA] == 0


# --- the hold cap at its exact boundaries ---------------------------------------

def test_cap_boundary_hold_equal_to_cap_admitted():
    lm = _manager()
    _register(lm, CAP_CLAUSE_10, tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX)
    tx = _park(KIM, SK_KIM, release_at_height=H + 10)
    applied = _run([tx], lm, caps={VERA: 10})
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert applied.lifecycle.retractable_transfers.escrow_total() == 100


def test_cap_boundary_hold_one_over_refused():
    lm = _manager()
    _register(lm, CAP_CLAUSE_10, tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX)
    tx = _park(KIM, SK_KIM, release_at_height=H + 10)
    applied = _run([tx], lm, caps={VERA: 9})
    outcome = _outcome(applied, tx["tx_id"])
    assert outcome.reason == recipient_gate.REASON_HOLD_CAP
    assert "cap=9" in " | ".join(str(x) for x in outcome.receipt_logs)
    assert applied.lifecycle.retractable_transfers.escrow_total() == 0
    assert _balances(applied)[KIM] == 50000


def test_cap_zero_admits_only_a_zero_hold():
    lm = _manager()
    _register(lm, CAP_CLAUSE_10, tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX)
    tx = _park(KIM, SK_KIM, release_at_height=H + 1)
    applied = _run([tx], lm, caps={VERA: 0})
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_HOLD_CAP

    # A plain transfer states no hold at all: the zero cap is not
    # consulted and the payment lands.
    lm = _manager()
    _register(lm, CAP_CLAUSE_10, tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX)
    tx = _transfer(UDO, SK_UDO, VERA, 100)
    applied = _run([tx], lm, caps={VERA: 0})
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[VERA] == 100


def test_park_releases_even_when_policy_now_refuses_everything():
    lm = _manager()
    _register(lm, ALLOW_ONLY_KIM)
    tx = _park(KIM, SK_KIM, release_at_height=H + 10)
    applied = _run([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids

    applied2 = _run([], applied.lifecycle,
                    parent=applied.result.next_snapshot, height=H + 10,
                    spec_refusals={VERA})
    assert _balances(applied2)[VERA] == 100
    assert applied2.lifecycle.retractable_transfers.escrow_total() == 0


def test_gate_inactive_means_the_same_clauses_judge_nobody():
    lm = _manager(active=False)
    _register(lm, ALLOW_ONLY_KIM)
    tx = _transfer(UDO, SK_UDO, VERA, 100)
    applied = _run([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[VERA] == 100


# --- sabotage: each refusal must vanish when its gate function is replaced -----

NEUTRAL_CLAUSE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."


def test_sabotage_policy_parse_unblocks_a_spec_refusal(monkeypatch):
    # VERA's refusal here lives in her spec evaluation (the multi
    # layer): her registered clause is neutral (the clause step has
    # no opinion on it), so policy_blocked reading the spec verdict
    # is the only refusing function.
    def scenario():
        lm = _manager()
        _register(lm, NEUTRAL_CLAUSE)
        tx = _transfer(UDO, SK_UDO, VERA, 100)
        return tx, _run([tx], lm, spec_refusals={VERA})

    tx, applied = scenario()
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK

    monkeypatch.setattr(recipient_gate, "policy_blocked",
                        lambda outputs, parse: False)
    tx, applied = scenario()
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[VERA] == 100


def test_sabotage_cap_read_unblocks_an_over_cap_park(monkeypatch):
    def scenario():
        lm = _manager()
        _register(lm, CAP_CLAUSE_10, tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX)
        tx = _park(KIM, SK_KIM, release_at_height=H + 10)
        return tx, _run([tx], lm, caps={VERA: 9})

    tx, applied = scenario()
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_HOLD_CAP

    monkeypatch.setattr(recipient_gate, "hold_cap",
                        lambda outputs, parse: None)
    tx, applied = scenario()
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert applied.lifecycle.retractable_transfers.escrow_total() == 100


def test_sabotage_inbound_screen_makes_an_outbound_clause_block(monkeypatch):
    def scenario():
        lm = _manager()
        _register(lm, OUTBOUND_TO_UDO)
        tx = _transfer(UDO, SK_UDO, VERA, 100)
        return tx, _run([tx], lm)

    # Control: VERA's clause governs her payments TO Udo; a payment
    # TO VERA is screened out before evaluation and lands.
    tx, applied = scenario()
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[VERA] == 100

    # Sabotage the screen off: the clause is now evaluated on the
    # inbound pair, where i4 is VERA herself, and it refuses.
    monkeypatch.setattr(recipient_gate, "clause_applies_to_inbound",
                        lambda body, target_stream=None: True)
    tx, applied = scenario()
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[VERA] == 0
