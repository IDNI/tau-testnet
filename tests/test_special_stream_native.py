"""The update stream `u` against the REAL engine.

The genesis router feeds each op-0 rule on i0 and writes it to `u`. A user rule
that also writes `u` shares that output with the router, so it revises the router
and every later rule is acknowledged but never takes effect.

1. CHARACTERIZATION. After `always u[t] = 0.` a later rule's output vanishes; the
   control run without it shows the output.

2. LIVE APPLY. A block built directly (no admission): a tx carrying the u rule,
   a tx installing a fee rule scoped to another account, then that account's
   transfer. The u tx is rejected as `rule_fragment` and never reaches the
   engine or the accumulated rules, and the fee rule still takes effect.

3. REPLAY. The same block under `replay_mode=True` gives the same result.

Children run in their own process: the engine types streams process-wide.
"""
import pytest

from test_reserved_output_native import (
    _PREAMBLE,
    _run_child,
    requires_native,
)

U_RULE = "always u[t] = 0."
LATER_RULE = "always o21[t]:bv[8] = { 9 }:bv[8]."
FEE_RULE_BODY = "o8[t]:bv[24] = { #x000005 }:bv[24]"
AMOUNT = 100
FEE = 10
O8_FEE = 5

_CHARACTERIZE_BODY = r'''
iface, revise = boot_interface()


def step():
    return iface.communicate_multi(input_stream_values={
        "1": "100", "2": "1000", "3": A, "4": B, "5": "0", "6": "5",
        "7": "1000", "8": A, "9": A, "10": "1", "11": A, "12": A,
    })


def stream(outputs, index):
    value = outputs.get(index, outputs.get(str(index)))
    return None if value is None else str(value)


if os.environ["WITH_U_RULE"] == "1":
    revise(os.environ["U_RULE"])
revise(os.environ["LATER_RULE"])
emit({"o21": stream(step(), 21)})
'''


_APPLY_BODY = r'''
from unittest.mock import MagicMock

import config
config.set_database_path(os.path.join(tempfile.mkdtemp(), "special.sqlite"))
import db
db.init_db()
import tau_manager
import tau_shrink
import chain_state
from block import Block
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_tx
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot

A = pubkey_hex(SK_ALICE)
B = pubkey_hex(SK_BOB)
C = pubkey_hex(SK_CAROL)
tau_shrink.set_shrink_width_from_db()
iface, revise = boot_interface(through_manager=True)
tau_manager.set_rules_handler(chain_state.save_effective_tau_spec)

U_RULE = os.environ["U_RULE"]
FEE_RULE = (
    "always ( ( i12[t]:bv[384] = { #x" + B + " }:bv[384] ) -> ( "
    + os.environ["FEE_RULE_BODY"] + " ) )."
)
REPLAY = os.environ["REPLAY_MODE"] == "1"
AMOUNT = int(os.environ["AMOUNT"])


def rule_tx(tx_id, sender, sk, rule):
    return sign_tx({"tx_id": tx_id, "tx_type": "user_tx", "sender_pubkey": sender,
                    "sequence_number": 0, "fee_limit": "1000",
                    "operations": {"0": rule}}, sk)


tx_u = rule_tx("u-tx", A, SK_ALICE, U_RULE)
tx_fee = rule_tx("fee-tx", C, SK_CAROL, FEE_RULE)
tx_transfer = sign_tx({"tx_id": "transfer-tx", "tx_type": "user_tx", "sender_pubkey": B,
                       "sequence_number": 0, "fee_limit": "1000",
                       "operations": {"1": [[B, A, str(AMOUNT)]]}}, SK_BOB)

lifecycle = ConsensusLifecycleManager(active_validators=[PROPOSER])
parent_app_rules = GENESIS["application_rules"]
parent = TauStateSnapshot(
    state_hash="0" * 64, tau_bytes=parent_app_rules.encode("utf-8"),
    metadata={"balances": {A: 1000, B: 1000, C: 1000}, "sequence_numbers": {},
              "last_transfer_ts": {}, "lifecycle_manager": lifecycle,
              "active_consensus_id": ""},
)
block = Block.create(block_number=1, previous_hash="0" * 64,
                     transactions=[tx_u, tx_fee, tx_transfer],
                     proposer_pubkey=PROPOSER, timestamp=1700000000)
view = ActiveConsensusView(target_height=1,
                           consensus_rules=GENESIS["consensus_rules"],
                           active_validators=[bytes.fromhex(PROPOSER)])

engine = TauConsensusEngine(state_store=MagicMock())
engine._state_store.commit.side_effect = lambda snap: snap
result = engine.apply_block(view, block, parent, replay_mode=REPLAY)

outcomes = {o.tx_id: o for o in result.outcomes}
balances = result.next_snapshot.metadata["balances"]
saved = chain_state.get_application_rules_state() or ""
emit({
    "accepted": sorted(result.accepted_tx_ids),
    "invalid": sorted(result.invalid_tx_ids),
    "u_reason": outcomes["u-tx"].reason if "u-tx" in outcomes else None,
    "u_in_saved_state": chain_state._preprocess_tau_spec_text(U_RULE) in saved,
    "fee_rule_in_saved_state": chain_state._preprocess_tau_spec_text(FEE_RULE) in saved,
    "sender_balance": balances.get(B),
})
'''


def _characterize(tmp_path, with_u):
    return _run_child(
        tmp_path, "characterize", _CHARACTERIZE_BODY,
        {"WITH_U_RULE": "1" if with_u else "0", "U_RULE": U_RULE,
         "LATER_RULE": LATER_RULE},
    )


@requires_native
def test_a_later_rule_takes_effect_without_the_u_rule(tmp_path):
    assert int(_characterize(tmp_path, with_u=False)["o21"]) == 9


@requires_native
def test_a_u_rule_makes_a_later_rule_vanish(tmp_path):
    o21 = _characterize(tmp_path, with_u=True)["o21"]
    assert o21 is None or int(o21) != 9


def _apply(tmp_path, replay):
    return _run_child(
        tmp_path, "apply", _APPLY_BODY,
        {"U_RULE": U_RULE, "FEE_RULE_BODY": FEE_RULE_BODY,
         "REPLAY_MODE": "1" if replay else "0", "AMOUNT": str(AMOUNT)},
    )


@requires_native
@pytest.mark.parametrize("replay", [False, True], ids=["live", "replay"])
def test_apply_rejects_the_u_rule_and_the_fee_rule_still_applies(tmp_path, replay):
    out = _apply(tmp_path, replay)

    assert out["invalid"] == ["u-tx"], out
    assert out["accepted"] == ["fee-tx", "transfer-tx"], out
    assert out["u_reason"] == "rule_fragment", out
    assert not out["u_in_saved_state"], "the rejected rule was persisted"
    assert out["fee_rule_in_saved_state"], out
    assert out["sender_balance"] == 1000 - AMOUNT - FEE - O8_FEE, out
