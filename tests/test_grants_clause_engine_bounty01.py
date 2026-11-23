"""Bounty 01, FIX 5: grants in Tau clause form, at the engine seam.

The clause form at block apply and admission, with the policy pools
scripted (the sender-policy mock): the node steps the funder's clause
over the node-built input map, decodes the released amount from its
o30, checks it through the book, and credits the beneficiary
directly. The clause scripts below compute their released amount in
Python from the stepped inputs — they stand in for the clause's own
Tau arithmetic, which the native suite
(test_grants_clause_native.py) runs for real.

Covered: a clause-form grant installs with its form in the event and
draws under a third party, the clause seeing the draw amount at i1,
the held amount at i2, the drawer at i4 and the total spent at i27;
admission and apply agree, in both directions (an admissible draw
settles; an over-schedule or unbuildable clause draw is refused at
admission and settles nothing at apply); a clause that writes a
blocking o5 settles nothing; named case 5 end-to-end (500 x 3 draws,
4th refused, refund exactly 3500); the release boundaries follow the
signed periods_from, not the install day.
"""
import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from block import Block
from consensus import sender_policy
from consensus.admission import validate_draw_grant_payload
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.grants import (
    FORM_TAU_CLAUSE,
    GrantBook,
    parse_create_grant,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
FEE = 7
WEEK = 604_800
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
DEADLINE = DEC1 + 8 * WEEK


def _grant_clause(anchor, release=500, total=5000, weeks=8):
    """The canonical grants clause (same text as the book suite's)."""
    def rel(amount):
        return f"((o30[t]:bv[64] = {{ {amount} }}:bv[64]))"

    clause = rel(total)
    for k in range(weeks, 0, -1):
        clause = (
            f"((i5[t]:bv[64] < {{ {anchor + k * WEEK} }}:bv[64]) "
            f"? {rel(min(total, release * k))} : {clause})"
        )
    return (
        f"((i5[t]:bv[64] < {{ {anchor} }}:bv[64]) "
        f"? {rel(0)} : {clause})"
    )


CLAUSE = _grant_clause(DEC1)


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator / fee beneficiary
SK_FUNDER, FUNDER = _key(22222)      # the grant's funder
SK_BOB, BOB = _key(33333)            # the beneficiary
SK_EXECUTOR, EXECUTOR = _key(55555)  # any third party may submit a draw

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
    (the grants engine suite's harness, verbatim)."""

    def __init__(self, balances, lm=None, ts=DEC1 - 100):
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


def _release_for(anchor, release=500, total=5000):
    """The scripted clause: the released amount for the stepped ts,
    computed from the signed periods_from anchor — what the clause's
    own Tau arithmetic names in the native suite."""
    def _serve(inputs):
        ts = int(inputs.get("i5", "0"))
        if ts < anchor:
            return {"o30": "0"}
        periods = (ts - anchor) // WEEK + 1
        return {"o30": str(min(total, release * periods))}

    return _serve


def _create_clause_tx(seq, **kw):
    return _sign({
        "tx_id": f"gclause-create-{next(_TX_SEQ)}",
        "tx_type": "create_grant",
        "sender_pubkey": FUNDER,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "grant_beneficiary_pubkey": BOB,
        "grant_total_amount": kw.get("total", 5000),
        "grant_release_per_period": kw.get("release", 500),
        "grant_schedule": "weekly",
        "grant_signed_day": 0,
        "grant_start_ts": kw.get("start_ts", DEC1),
        "grant_deadline_ts": DEADLINE,
        "grant_locked_until_ts": 0,
        "grant_window_start_ts": 0,
        "grant_window_end_ts": 0,
        "grant_inactivity_seconds": 0,
        "grant_version": 1,
        "grant_form": FORM_TAU_CLAUSE,
        "grant_clause": kw.get("clause", CLAUSE),
        "grant_periods_from_ts": kw.get("periods_from_ts", DEC1),
    }, SK_FUNDER)


def _draw_tx(sender, sk, grant_id, amount, seq):
    return _sign({
        "tx_id": f"gclause-draw-{next(_TX_SEQ)}",
        "tx_type": "draw_grant",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "grant_id": grant_id.hex(),
        "grant_draw_amount": amount,
    }, sk)


class _TipView(TipAdmissionView):
    """The real facade view over the chain's books, at the chain's ts."""

    def __init__(self, chain):
        self._chain = chain

    @property
    def next_block_timestamp(self):
        return self._chain.ts

    def _tip_grant_book(self):
        return self._chain.lm.grants

    def get_balance(self, pubkey):
        return self._chain.balances.get(pubkey, 0)


def _funded_chain():
    return _Chain({ALICE: 0, FUNDER: 100000, BOB: 0, EXECUTOR: 1000})


def _created_chain(**kw):
    chain = _funded_chain()
    create = _create_clause_tx(seq=0, **kw)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    return chain, parse_create_grant(create).grant_id


def _book(chain):
    return chain.lm.grants


# --- installation and draws -----------------------------------------------------


def test_clause_grant_installs_and_draws_under_a_third_party():
    captured = _script(CLAUSE, _release_for(DEC1))
    chain, grant_id = _created_chain()
    entry = _book(chain).get(grant_id)
    assert entry is not None and entry.form == FORM_TAU_CLAUSE
    assert entry.clause_text == CLAUSE and entry.periods_from_ts == DEC1
    assert chain.balances[FUNDER] == 100000 - 5000 - FEE
    assert _book(chain).held_total() == 5000

    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    assert chain.balances[BOB] == 500
    assert chain.balances[EXECUTOR] == 1000 - FEE
    assert _book(chain).accounting(grant_id)["drawn"] == 500
    (event,) = result.next_snapshot.metadata["grant_events"]
    assert event["action"] == "drawn" and event["amount"] == 500
    # The clause was stepped over the node-built map: the draw amount
    # at i1, the held amount at i2, the funder at i3, the drawer at i4
    # (in the worker's bare #x form), the block ts at i5, nothing spent
    # yet at i27.
    stepped = captured[-1]
    assert stepped["i1"] == "500"
    assert stepped["i2"] == "5000"
    assert stepped["i3"] == "#x" + FUNDER
    assert stepped["i4"] == "#x" + EXECUTOR
    assert stepped["i5"] == str(DEC1 + 10)
    assert stepped["i27"] == "0"


def test_clause_grant_admission_agrees_with_apply():
    _script(CLAUSE, _release_for(DEC1))
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    admitted = validate_draw_grant_payload(draw, _TipView(chain))
    assert admitted.is_valid and admitted.data["amount"] == 500
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    # Once settled, admission refuses the same draw, as apply did.
    again = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=1)
    refused = validate_draw_grant_payload(again, _TipView(chain))
    assert not refused.is_valid


def test_clause_grant_over_schedule_cap_settles_nothing():
    _script(CLAUSE, lambda inputs: {"o30": "2000"})
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 2 * WEEK + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    admitted = validate_draw_grant_payload(draw, _TipView(chain))
    assert not admitted.is_valid  # refused at admission...
    result = chain.apply([draw])
    assert draw["tx_id"] in result.invalid_tx_ids  # ...and at apply
    assert chain.balances[BOB] == 0
    assert _book(chain).accounting(grant_id)["drawn"] == 0


def test_clause_grant_that_does_not_build_settles_nothing():
    _script(CLAUSE, fail_build=True)
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    refused = validate_draw_grant_payload(draw, _TipView(chain))
    assert not refused.is_valid
    result = chain.apply([draw])
    assert draw["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 0


def test_clause_grant_with_a_blocking_o5_settles_nothing():
    _script(CLAUSE, lambda inputs: {
        "o5": "0", "o30": "500"})
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    refused = validate_draw_grant_payload(draw, _TipView(chain))
    assert not refused.is_valid
    result = chain.apply([draw])
    assert draw["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 0


def test_clause_grant_with_no_released_output_settles_nothing():
    _script(CLAUSE, lambda inputs: {})
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    refused = validate_draw_grant_payload(draw, _TipView(chain))
    assert not refused.is_valid
    result = chain.apply([draw])
    assert draw["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 0


# --- named case 5, end-to-end -----------------------------------------------------


def test_named_case_5_in_clause_form_end_to_end():
    """5000 from Dec 1, 500/week, as a clause; Bob spends 1500; a 4th
    draw in the third week is refused; 3500 returns at the deadline."""
    _script(CLAUSE, _release_for(DEC1))
    chain, grant_id = _created_chain()
    assert chain.balances[FUNDER] == 100000 - 5000 - FEE
    assert _book(chain).held_total() == 5000

    for week in range(3):
        chain.ts = DEC1 + week * WEEK + 10
        draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=week)
        result = chain.apply([draw])
        assert draw["tx_id"] in result.accepted_tx_ids
    assert chain.balances[BOB] == 1500
    assert _book(chain).accounting(grant_id)["drawn"] == 1500

    # A 4th draw in the third week: the clause names 1500 released and
    # 1500 is spent, so nothing is spendable.
    chain.ts = DEC1 + 2 * WEEK + 20
    fourth = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=3)
    result = chain.apply([fourth])
    assert fourth["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 1500

    # The deadline block carries no transaction at all: the sweep refunds
    # exactly 3500 to the funder, fee-free.
    chain.ts = DEADLINE
    funder_before = chain.balances[FUNDER]
    result = chain.apply([])
    assert chain.balances[FUNDER] - funder_before == 3500
    assert _book(chain).held_total() == 0
    assert _book(chain).accounting(grant_id) == {
        "principal": 5000, "drawn": 1500, "held": 0, "refunded": 3500,
    }


def test_clause_grant_periods_from_anchor_at_apply():
    """Installed Dec 1, periods_from Dec 15: nothing is drawable on
    Dec 1 (the clause names 0 released there) and the first 500 draws
    on Dec 15 — the boundary follows the signed anchor, not the
    install day."""
    anchor = DEC1 + 2 * WEEK
    clause = _grant_clause(anchor)
    _script(clause, _release_for(anchor))
    chain, grant_id = _created_chain(
        clause=clause, periods_from_ts=anchor)
    chain.ts = DEC1 + 10
    early = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([early])
    assert early["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 0
    chain.ts = anchor + 10
    # The refused draw consumed no sequence number, so the next draw
    # still uses seq 0.
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    assert chain.balances[BOB] == 500


def test_clause_grant_visible_via_the_facade():
    _script(CLAUSE, _release_for(DEC1))
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 10
    view = _TipView(chain)
    got = view.get_grant(grant_id)
    assert got is not None and got["grant_id"] == grant_id.hex()
    assert got["form"] == FORM_TAU_CLAUSE
    assert got["clause_text"] == CLAUSE
    assert got["periods_from_ts"] == DEC1
    assert got["released"] == 500 and got["spendable"] == 500
