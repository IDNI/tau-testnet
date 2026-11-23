"""Bounty 01, FIX 5 (due_retry): a signed retry term in clause form, at
the engine seam.

The competitor's #160 commit 7722a42 adds a signed `due_retry` term:
a due point refused because the account holds less than the rule pays
is run again in each later block, at most 4 a block, longest waiting
first, until it pays / its window closes / the next due point comes /
the rule ends. FIX 5 answers it in clause form, on the standing
payment's end-of-block sweep — the same sweep that refunds expired
grants, run after them so a refund landing in the block is visible to
the retry's balance.

The sweep is the ONLY recording path, and this file pins why: a
refused execution never reaches apply — admission refuses it first
(see test_execute_refused_at_admission_when_short) — and a rejected
transaction's lifecycle fork is discarded with it, so no recording in
the transaction loop could ever survive. The node observes the
shortfall itself, at the end of the block, exactly as the
competitor's node-side due-point run does. A due point the node finds
payable is left alone: settling un-attempted due points is the node
sweep's job (FIX 3, awaiting the o5 decision), not the retry's.

Covered, with the policy pools scripted (the sender-policy mock) and
the clause scripts computing their legs in Python from the stepped
inputs — the native suite (test_standing_due_retry_native.py) runs
the same clauses for real: a short due point is discovered and owed
after the create block and settles nothing in the discovery block; a
retry settles in a later block once funded, fee-free, exactly once;
while still short it stays owed; at most 4 attempts a block with 5
owed; a cap refusal and a declared-form authorization record nothing;
the window closing and the next due point coming end the retry (the
next period is then discovered in its turn); cancel ends it; an
executor's transaction paying the period clears it.
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
from consensus.standing_payments import (
    FORM_DECLARED,
    FORM_TAU_CLAUSE,
    parse_create_standing_payment,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7
AMOUNT = 250
DAY = 86_400
RETRY_WEEK = 7 * DAY

PAY_FULL_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 250 }:bv[64]))"
)
OVER_CAP_CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 251 }:bv[64]))"
)


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator
SK_PAYER, PAYER = _key(22222)        # standing payer (short: 100 < 250)
SK_RECIPIENT, RECIPIENT = _key(33333)
SK_EXECUTOR, EXECUTOR = _key(55555)  # funder / any third party
SK_SECOND, SECOND = _key(77777)
SK_THIRD, THIRD = _key(88888)
SK_FOURTH, FOURTH = _key(99999)
SK_FIFTH, FIFTH = _key(10101)

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


def _pay_250(inputs):
    return {"o30": "1", "o31": "0", "o32": "250"}


def _pay_251(inputs):
    return {"o30": "1", "o31": "0", "o32": "251"}


def _create_clause_tx(payer, sk, recipient, seq, **kw):
    return _sign({
        "tx_id": f"retry-create-{next(_TX_SEQ)}",
        "tx_type": "create_standing_payment",
        "sender_pubkey": payer,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_recipient_pubkey": recipient,
        "standing_amount": kw.get("amount", AMOUNT),
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": kw.get("anchor_ts", TS - 100),
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": kw.get("max_total", 100_000),
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
        "standing_form": FORM_TAU_CLAUSE,
        "standing_clause": kw.get("clause", PAY_FULL_CLAUSE),
        "standing_due_retry_seconds": kw.get("due_retry_seconds", RETRY_WEEK),
    }, sk)


def _create_declared_tx(payer, sk, recipient, seq, **kw):
    return _sign({
        "tx_id": f"retry-create-declared-{next(_TX_SEQ)}",
        "tx_type": "create_standing_payment",
        "sender_pubkey": payer,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_recipient_pubkey": recipient,
        "standing_amount": kw.get("amount", AMOUNT),
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": kw.get("anchor_ts", TS - 100),
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": kw.get("max_total", 100_000),
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
        "standing_form": FORM_DECLARED,
    }, sk)


def _execute_tx(sender, sk, auth_id, seq):
    return _sign({
        "tx_id": f"retry-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_standing_payment",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_auth_id": auth_id.hex(),
    }, sk)


def _cancel_tx(sender, sk, auth_id, seq):
    return _sign({
        "tx_id": f"retry-cancel-{next(_TX_SEQ)}",
        "tx_type": "cancel_standing_payment",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_auth_id": auth_id.hex(),
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


def _funded_chain(**balances):
    base = {ALICE: 0, PAYER: 100, RECIPIENT: 1000, EXECUTOR: 1000}
    base.update(balances)
    return _Chain(base)


def _created_chain(**kw):
    """A chain with one live clause-form authorization whose payer is
    short (100, minus the 7 create fee, against a 250 period): the
    create block's own sweep discovers the short due point and owes
    its retry."""
    _script(PAY_FULL_CLAUSE, _pay_250)
    chain = _funded_chain()
    create = _create_clause_tx(PAYER, SK_PAYER, RECIPIENT, seq=0, **kw)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    return chain, parse_create_standing_payment(create).auth_id


def _book(chain):
    return chain.lm.standing_payments


def _events(result):
    return result.next_snapshot.metadata.get("standing_payment_events", [])


# --- discovery ------------------------------------------------------------------


def test_short_due_point_is_discovered_and_owed_after_the_create_block():
    chain, auth_id = _created_chain()
    # The payer is short (93 after the create fee): the due point is
    # owed a retry, and nothing settled in the discovery block.
    owed = _book(chain).owed_retries()
    assert len(owed) == 1
    assert owed[0].auth_id == auth_id and owed[0].period_index == 0
    assert owed[0].due_ts == TS - 100
    assert owed[0].retry_until == TS - 100 + RETRY_WEEK
    assert owed[0].recorded_height == HEIGHT
    assert chain.balances[PAYER] == 100 - FEE
    assert chain.balances[RECIPIENT] == 1000
    assert _book(chain).total_executed(auth_id) == (0, 0)


def test_execute_refused_at_admission_when_short():
    """Why the sweep is the only recording path: a refused execution
    never reaches apply — admission refuses it first."""
    chain, auth_id = _created_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = validate_execute_standing_payment_payload(execute, _TipView(chain))
    assert not result.is_valid
    assert "insufficient funds" in (result.error or "")


# --- the retry run -----------------------------------------------------------------


def test_retry_settles_in_a_later_block_once_funded_fee_free():
    chain, auth_id = _created_chain()
    fund = _transfer(EXECUTOR, SK_EXECUTOR, PAYER, 500, seq=0)
    result = chain.apply([fund])
    assert fund["tx_id"] in result.accepted_tx_ids
    # The funding landed in this block, so the retry ran at the end of
    # it: exactly 250 moved, and the retry itself charged no fee.
    assert chain.balances[PAYER] == 100 - FEE + 500 - AMOUNT
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert chain.balances[EXECUTOR] == 1000 - FEE - 500
    assert _book(chain).owed_retries() == []
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    events = [e for e in _events(result) if e.get("action") == "retry_executed"]
    assert len(events) == 1
    assert events[0]["auth_id"] == auth_id.hex()
    assert events[0]["amount"] == AMOUNT and events[0]["retry"] is True
    assert events[0]["period_index"] == 0


def test_retry_stays_owed_while_still_short_then_settles():
    chain, auth_id = _created_chain()
    # An empty block: the retry runs (it was owed in an earlier block)
    # and finds the payer still short — it stays owed.
    result = chain.apply([])
    assert _book(chain).owed_retries() != []
    assert chain.balances[RECIPIENT] == 1000
    assert _book(chain).total_executed(auth_id) == (0, 0)
    # Funded in the next block, it settles in that block's sweep.
    fund = _transfer(EXECUTOR, SK_EXECUTOR, PAYER, 500, seq=0)
    chain.apply([fund])
    assert _book(chain).owed_retries() == []
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT


def test_retry_attempts_at_most_four_per_block_with_five_owed():
    _script(PAY_FULL_CLAUSE, _pay_250)
    payers = [
        (SK_PAYER, PAYER), (SK_SECOND, SECOND), (SK_THIRD, THIRD),
        (SK_FOURTH, FOURTH), (SK_FIFTH, FIFTH),
    ]
    balances = {ALICE: 0, RECIPIENT: 1000, EXECUTOR: 10_000}
    for _sk, pk in payers:
        balances[pk] = 100
    chain = _Chain(balances)
    creates = [
        _create_clause_tx(pk, sk, RECIPIENT, seq=0)
        for sk, pk in payers
    ]
    result = chain.apply(creates)
    for create in creates:
        assert create["tx_id"] in result.accepted_tx_ids
    auth_ids = [
        parse_create_standing_payment(c).auth_id for c in creates
    ]
    payer_by_auth = {
        parse_create_standing_payment(c).auth_id: c["sender_pubkey"]
        for c in creates
    }
    assert len(_book(chain).owed_retries()) == 5
    # Fund all five in one block: the sweep attempts the four longest
    # waiting (all due at once, so the four smallest auth ids) and the
    # fifth stays owed, its funding untouched.
    funds = [
        _transfer(EXECUTOR, SK_EXECUTOR, pk, 500, seq=i)
        for i, (_sk, pk) in enumerate(payers)
    ]
    chain.apply(funds)
    owed = _book(chain).owed_retries()
    assert len(owed) == 1
    assert owed[0].auth_id == max(auth_ids)
    assert chain.balances[RECIPIENT] == 1000 + 4 * AMOUNT
    assert chain.balances[payer_by_auth[max(auth_ids)]] == 100 - FEE + 500


def test_cap_refusal_records_no_retry():
    _script(OVER_CAP_CLAUSE, _pay_251)
    chain = _funded_chain()
    create = _create_clause_tx(
        PAYER, SK_PAYER, RECIPIENT, seq=0, clause=OVER_CAP_CLAUSE)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    # The clause names 251 against the 250 cap: refused for the cap,
    # not for the balance — and a cap refusal owes no retry.
    assert _book(chain).owed_retries() == []
    assert chain.balances[RECIPIENT] == 1000


def test_declared_form_records_no_retry():
    chain = _funded_chain()
    create = _create_declared_tx(PAYER, SK_PAYER, RECIPIENT, seq=0)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    assert _book(chain).owed_retries() == []


# --- the retry ends ------------------------------------------------------------------


def test_window_expiry_ends_the_retry():
    chain, auth_id = _created_chain(due_retry_seconds=3600)
    assert len(_book(chain).owed_retries()) == 1
    chain.ts = TS + 7200  # past due (TS-100) + 3600
    result = chain.apply([])
    assert _book(chain).owed_retries() == []
    events = [e for e in _events(result) if e.get("action") == "due_retry_ended"]
    assert len(events) == 1
    assert events[0]["auth_id"] == auth_id.hex()
    assert "retry window" in events[0]["reason"]
    assert chain.balances[RECIPIENT] == 1000


def test_next_due_point_ends_the_retry_and_the_next_is_discovered():
    chain, auth_id = _created_chain(due_retry_seconds=2 * DAY)
    assert len(_book(chain).owed_retries()) == 1
    chain.ts = TS + DAY  # period 1 is now due: period 0's next came
    result = chain.apply([])
    events = [e for e in _events(result) if e.get("action") == "due_retry_ended"]
    assert len(events) == 1 and events[0]["period_index"] == 0
    assert "next due point" in events[0]["reason"]
    # ... and period 1, due and short, is discovered in its turn.
    owed = _book(chain).owed_retries()
    assert len(owed) == 1
    assert owed[0].auth_id == auth_id and owed[0].period_index == 1
    assert chain.balances[RECIPIENT] == 1000


def test_cancel_ends_the_retry():
    chain, auth_id = _created_chain()
    cancel = _cancel_tx(PAYER, SK_PAYER, auth_id, seq=1)
    result = chain.apply([cancel])
    assert cancel["tx_id"] in result.accepted_tx_ids
    assert _book(chain).owed_retries() == []


def test_executor_tx_paying_the_period_clears_the_retry():
    chain, auth_id = _created_chain()
    # Funding and the execution in ONE block: the transaction settles
    # the period before the sweep runs, so the sweep finds nothing
    # owed — and the period is paid exactly once, by the transaction.
    fund = _transfer(EXECUTOR, SK_EXECUTOR, PAYER, 500, seq=0)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    result = chain.apply([fund, execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert chain.balances[PAYER] == 100 - FEE + 500 - AMOUNT
    assert _book(chain).owed_retries() == []
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    events = [e for e in _events(result) if e.get("action") == "retry_executed"]
    assert events == []
