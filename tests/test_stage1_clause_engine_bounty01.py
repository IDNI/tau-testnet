"""Bounty 01, stage 1 (FIX 2): standing payments + receive routes in
Tau clause form, at the engine seam.

The clause form at block apply and admission, with the policy pools
scripted (the sender-policy mock): the node steps the payer's /
owner's clause over the node-built input map, decodes the legs from
its outputs, checks them through the books, and settles through the
ordinary transfer seam. The clause scripts below compute their legs
in Python from the stepped inputs — they stand in for the clause's
own Tau arithmetic, which the native suite
(test_stage1_clause_form_native.py) runs for real.

Covered: a clause-form standing authorization installs with its form
in the event and executes under a third party, the clause seeing the
per-period cap at i1, the executor at i4 and the recorded period
paid total at i26; admission and apply agree, in both directions (an
admissible execution settles; an over-cap or out-of-set execution is
refused at admission and settles nothing at apply); a clause that
does not build, or writes a blocking o5, settles nothing; a
clause-form route splits a 101 credit at the clause's 20% and the
routed share never re-triggers the destination's own clause route;
an over-cap clause route and a non-building route clause leave the
credit whole and the transfer accepted.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from block import Block
from consensus import sender_policy
from consensus.admission import (
    validate_execute_standing_payment_payload,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.receive_routes import (
    FORM_TAU_CLAUSE as ROUTE_FORM_TAU_CLAUSE,
    parse_install_receive_route,
)
from consensus.standing_payments import (
    FORM_TAU_CLAUSE,
    parse_create_standing_payment,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7
AMOUNT = 250

# The clause bodies the scripted pools serve outputs for. Their text
# is a signed field of the entry; the mock keys on the exact body.
SCLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 200 }:bv[64]))"
)
RCLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = i1[t]:bv[64] / { 5 }:bv[64]))"
)


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator
SK_PAYER, PAYER = _key(22222)        # standing payer / route owner
SK_RECIPIENT, RECIPIENT = _key(33333)
SK_EXECUTOR, EXECUTOR = _key(55555)  # any third party may execute
SK_DEST, DEST = _key(66666)          # route destination
SK_SECOND, SECOND = _key(77777)      # second-hop destination

_TX_SEQ = itertools.count()


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _lm():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.activate_approval_slots()
    return lm


class _Chain:
    """Threads apply_block results into the next block's parent snapshot
    (the standing engine suite's harness, verbatim)."""

    def __init__(self, balances, lm=None, ts=TS):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT

    def apply(self, txs, fee=FEE, allow=True):
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.balances),
                "sequence_numbers": dict(self.sequences),
                "last_transfer_ts": {},
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ALICE)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash="00" * 32,
            transactions=txs, proposer_pubkey=ALICE, timestamp=self.ts,
        )

        def _fake_multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            amount = int(str(vals.get(1, "0")) or 0)
            return {1: str(amount), 8: "0", 9: str(fee), 5: "1" if allow else "0"}

        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, block, parent)
        md = result.next_snapshot.metadata
        self.balances = md["balances"]
        self.sequences = md["sequence_numbers"]
        self.lm = md["lifecycle_manager"]
        self.height += 1
        return result


@pytest.fixture(autouse=True)
def _reset_pool_overrides():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def _script(body, outputs_fn=None, *, fail_build=False):
    """Serve `outputs_fn(inputs) -> outputs dict` for `body` in both
    pools. Returns the captured input maps, in call order."""
    captured = []

    def _serve(inputs):
        captured.append(dict(inputs))
        return outputs_fn(inputs) if outputs_fn is not None else {}

    for pool in ("apply", "admission"):
        ev = MockPolicyEvaluator(pool=pool)
        if fail_build:
            ev.fail_build(body, "mock build failure")
        else:
            ev.set_outputs(body, _serve)
        sender_policy.set_evaluator(pool, ev)
    return captured


def _create_clause_tx(seq, **kw):
    return _sign({
        "tx_id": f"sclause-create-{next(_TX_SEQ)}",
        "tx_type": "create_standing_payment",
        "sender_pubkey": PAYER,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_recipient_pubkey": RECIPIENT,
        "standing_amount": kw.get("amount", AMOUNT),
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": TS - 100,
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": kw.get("max_occurrences", 0),
        "standing_max_total": kw.get("max_total", 100_000),
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
        "standing_form": FORM_TAU_CLAUSE,
        "standing_clause": kw.get("clause", SCLAUSE),
    }, SK_PAYER)


def _execute_tx(sender, sk, auth_id, seq):
    return _sign({
        "tx_id": f"sclause-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_standing_payment",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_auth_id": auth_id.hex(),
    }, sk)


def _install_route_clause_tx(owner, sk, destination, seq, **kw):
    return _sign({
        "tx_id": f"rclause-install-{next(_TX_SEQ)}",
        "tx_type": "install_receive_route",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "route_destination_pubkey": destination,
        "route_bps": 0,
        "route_min_amount": kw.get("min_amount", 0),
        "route_activation_ts": 0,
        "route_expiry_ts": 0,
        "route_locked_until_ts": 0,
        "route_version": 1,
        "route_form": ROUTE_FORM_TAU_CLAUSE,
        "route_clause": kw.get("clause", RCLAUSE),
    }, sk)


def _transfer(sender, sk, to, amount, seq):
    return _sign({
        "tx_id": f"tr-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[sender, to, str(amount)]]},
    }, sk)


class _TipView(TipAdmissionView):
    """The real facade view over the chain's books, at the chain's ts."""

    def __init__(self, chain):
        self._chain = chain

    @property
    def next_block_timestamp(self):
        return self._chain.ts

    def _tip_standing_book(self):
        return self._chain.lm.standing_payments

    def get_balance(self, pubkey):
        return self._chain.balances.get(pubkey, 0)


def _funded_chain():
    return _Chain({
        ALICE: 0, PAYER: 100_000, RECIPIENT: 1000, EXECUTOR: 1000,
        DEST: 1000, SECOND: 0,
    })


def _created_chain(**kw):
    chain = _funded_chain()
    create = _create_clause_tx(seq=0, **kw)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    return chain, parse_create_standing_payment(create).auth_id


def _pay_200(inputs):
    return {"o30": "1", "o31": "0", "o32": "200"}


# --- standing -----------------------------------------------------------------


def test_clause_standing_installs_and_executes():
    captured = _script(SCLAUSE, _pay_200)
    chain, auth_id = _created_chain()
    entry = chain.lm.standing_payments.get(auth_id)
    assert entry is not None and entry.form == FORM_TAU_CLAUSE

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 + 200
    assert chain.balances[PAYER] == 100_000 - FEE - 200
    book = chain.lm.standing_payments
    assert book.total_executed(auth_id) == (1, 200)
    assert book.paid_for_period(auth_id, 0).amount == 200
    # The clause was stepped over the node-built map: the per-period
    # cap at i1, the executor at i4 (in the worker's bare #x form),
    # nothing yet paid at i26.
    stepped = captured[-1]
    assert stepped["i1"] == str(AMOUNT)
    assert stepped["i4"] == "#x" + EXECUTOR
    assert stepped["i26"] == "0"


def test_clause_standing_admission_agrees_with_apply():
    _script(SCLAUSE, _pay_200)
    chain, auth_id = _created_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    admitted = validate_execute_standing_payment_payload(
        execute, _TipView(chain))
    assert admitted.is_valid and admitted.data["amount"] == 200
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    # Once settled, admission refuses the same execution, as apply did.
    again = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    refused = validate_execute_standing_payment_payload(
        again, _TipView(chain))
    assert not refused.is_valid


def test_clause_standing_over_cap_settles_nothing():
    _script(SCLAUSE, lambda inputs: {"o30": "1", "o31": "0", "o32": "251"})
    chain, auth_id = _created_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    admitted = validate_execute_standing_payment_payload(
        execute, _TipView(chain))
    assert not admitted.is_valid  # refused at admission...
    result = chain.apply([execute])
    assert execute["tx_id"] not in result.accepted_tx_ids  # ...and at apply
    assert chain.balances[RECIPIENT] == 1000
    assert chain.lm.standing_payments.total_executed(auth_id) == (0, 0)


def test_clause_standing_out_of_set_and_unbuildable_settle_nothing():
    _script(SCLAUSE, lambda inputs: {"o30": "1", "o31": "1", "o32": "10"})
    chain, auth_id = _created_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] not in result.accepted_tx_ids
    assert chain.lm.standing_payments.total_executed(auth_id) == (0, 0)

    _script(SCLAUSE, fail_build=True)
    chain, auth_id = _created_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] not in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000


def test_clause_standing_blocking_o5_settles_nothing():
    _script(SCLAUSE, lambda inputs: {
        "o5": "0", "o30": "1", "o31": "0", "o32": "200"})
    chain, auth_id = _created_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] not in result.accepted_tx_ids
    assert chain.lm.standing_payments.total_executed(auth_id) == (0, 0)


# --- routes ---------------------------------------------------------------------


def _fifth(inputs):
    return {"o30": "1", "o31": "0", "o32": str(int(inputs["i1"]) // 5)}


def _half(inputs):
    return {"o30": "1", "o31": "0", "o32": str(int(inputs["i1"]) // 2)}


def test_clause_route_splits_101_and_never_retriggers():
    _script(RCLAUSE, _fifth)
    chain = _funded_chain()
    install = _install_route_clause_tx(RECIPIENT, SK_RECIPIENT, DEST, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    entry = chain.lm.receive_routes.get(RECIPIENT)
    assert entry is not None and entry.form == ROUTE_FORM_TAU_CLAUSE
    # The destination's own clause route (50%) must NOT fire on the
    # routed share: routing is single-hop in the clause form too.
    install2 = _install_route_clause_tx(DEST, SK_DEST, SECOND, seq=0)
    result = chain.apply([install2])
    assert install2["tx_id"] in result.accepted_tx_ids

    tx = _transfer(PAYER, SK_PAYER, RECIPIENT, 101, seq=0)
    result = chain.apply([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 - FEE + 81
    assert chain.balances[DEST] == 1000 - FEE + 20  # the share, kept whole
    assert chain.balances[SECOND] == 0


def test_clause_route_over_cap_and_unbuildable_land_whole():
    _script(RCLAUSE, lambda inputs: {"o30": "1", "o31": "0", "o32": "95"})
    chain = _funded_chain()
    install = _install_route_clause_tx(RECIPIENT, SK_RECIPIENT, DEST, seq=0)
    chain.apply([install])
    tx = _transfer(PAYER, SK_PAYER, RECIPIENT, 101, seq=0)
    result = chain.apply([tx])
    # The transfer is accepted; the credit lands whole (cap is 90).
    assert tx["tx_id"] in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 - FEE + 101
    assert chain.balances[DEST] == 1000

    _script(RCLAUSE, fail_build=True)
    chain = _funded_chain()
    install = _install_route_clause_tx(RECIPIENT, SK_RECIPIENT, DEST, seq=0)
    chain.apply([install])
    tx = _transfer(PAYER, SK_PAYER, RECIPIENT, 101, seq=0)
    result = chain.apply([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 - FEE + 101
    assert chain.balances[DEST] == 1000


def test_clause_route_install_event_and_id_are_the_tau_forms():
    _script(RCLAUSE, _fifth)
    chain = _funded_chain()
    install = _install_route_clause_tx(RECIPIENT, SK_RECIPIENT, DEST, seq=0)
    entry = parse_install_receive_route(install)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    stored = chain.lm.receive_routes.get(RECIPIENT)
    assert stored.route_id == entry.route_id
    assert stored.clause_text == RCLAUSE
