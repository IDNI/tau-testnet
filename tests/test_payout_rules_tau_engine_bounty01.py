"""Bounty 01, issue #63 (G4): Tau-form payout rules at the engine seam.

The Tau form of the payout rule at block apply, with the policy pools
scripted (the sender-policy mock): the node steps the owner's clause over
the node-built input map, decodes the legs from its outputs, checks them
against the declared set, both caps and the balance through the book, and
settles every leg through the ordinary transfer seam with the payout-leg
credit class. The clause scripts below compute their legs in Python from
the stepped inputs — they stand in for the clause's own Tau arithmetic,
which the native suite (test_payout_tau_rule_native.py) runs for real.

Covered: install lands with the form in its event; named case 2 expressed
as a Tau clause (5% of the base the clause reads at i1) pays 5 on 101,
once; the clause sees the executor at i4 and the per-period paid total at
i26; a leg above the per-execution cap settles nothing; an out-of-range
candidate index settles nothing; two legs are atomic under a seam block;
a blocking o5 and a clause that does not build settle nothing; a Tau-form
leg is never split by a receive route; admission and apply agree.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from block import Block
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.payout_rules import (
    FORM_TAU_RULE,
    PayoutRuleBook,
    parse_install_payout_rule,
)
from consensus.receive_routes import ReceiveRouteEntry
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7
WEEK = 604_800

SID_1 = "11" * 32
SID_2 = "22" * 32
SID_3 = "33" * 32

# The clause body the scripted pools serve outputs for. Its text is a
# signed field of the rule; the mock keys on the exact body, like the
# sender-policy suite's clauses.
CLAUSE = (
    "(i5[t]:bv[64] < { 1800003600 }:bv[64]) "
    "? ((o30[t]:bv[64] = { 1 }:bv[64]) && (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 5 }:bv[64])) "
    ": ((o30[t]:bv[64] = { 0 }:bv[64]) && (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 0 }:bv[64]))"
)


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator / fee beneficiary
SK_OWNER, OWNER = _key(22222)        # the payout rule's owner
SK_ARTIST, ARTIST = _key(33333)      # a declared recipient
SK_WORKER, WORKER = _key(44444)      # a declared recipient
SK_EXECUTOR, EXECUTOR = _key(55555)  # any third party may submit an execution
SK_RDEST, RDEST = _key(66666)        # receive-route destination

# Candidate indices are positions in the entry's canonical (sorted)
# recipient tuple — computed, never assumed.
IDX = {pk: i for i, pk in enumerate(sorted([ARTIST, WORKER]))}

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
    """Threads apply_block results into the next block's parent snapshot.

    The slice-5 harness verbatim; `block_amount=N` makes the scripted
    seam evaluator refuse only the transfer of exactly N.
    """

    def __init__(self, balances, lm=None, ts=TS):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT

    def apply(self, txs, fee=FEE, allow=True, block_amount=None):
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
            allowed = allow and amount != block_amount
            return {1: str(amount), 8: "0", 9: str(fee), 5: "1" if allowed else "0"}

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


def _script(outputs_fn=None, *, fail_build=False):
    """Serve `outputs_fn(inputs) -> outputs dict` for CLAUSE in both pools.

    Returns the captured input maps, one per clause step, in call order.
    """
    captured = []

    def _serve(inputs):
        captured.append(dict(inputs))
        return outputs_fn(inputs) if outputs_fn is not None else {}

    for pool in ("apply", "admission"):
        ev = MockPolicyEvaluator(pool=pool)
        if fail_build:
            ev.fail_build(CLAUSE, "mock build failure")
        else:
            ev.set_outputs(CLAUSE, _serve)
        sender_policy.set_evaluator(pool, ev)
    return captured


def _royalty_outputs(inputs):
    """The 5% royalty as a clause: 500 bps of the base read at i1.

    The rules this script serves declare ARTIST as their only recipient,
    so ARTIST is candidate index 0 in those entries' canonical tuples.
    """
    amount = int(inputs["i1"]) * 500 // 10_000
    return {"o30": "1", "o31": "0", "o32": str(amount)}


def _install_tau_tx(owner, sk, seq, fee_limit="100", **kw):
    return _sign({
        "tx_id": f"payout-tau-install-{next(_TX_SEQ)}",
        "tx_type": "install_payout_rule",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "payout_recipients": kw.get("recipients", [ARTIST]),
        "payout_form": FORM_TAU_RULE,
        "payout_clause": kw.get("clause", CLAUSE),
        "payout_max_per_execution": kw.get("max_per_execution", 0),
        "payout_max_per_period": kw.get("max_per_period", 0),
        "payout_period_seconds": kw.get("period_seconds", WEEK),
        "payout_period_anchor_ts": kw.get("anchor_ts", TS - 100),
        "payout_version": kw.get("version", 1),
    }, sk)


def _execute_tx(sender, sk, rule_id, settlement_id, base, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"payout-tau-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_payout_rule",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "payout_rule_id": rule_id.hex(),
        "payout_settlement_id": settlement_id,
        "payout_base_amount": base,
    }, sk)


def _funded_chain():
    return _Chain({
        ALICE: 0, OWNER: 100000, ARTIST: 1000, WORKER: 0,
        EXECUTOR: 1000, RDEST: 0,
    })


def _installed_chain(**kw):
    chain = _funded_chain()
    install = _install_tau_tx(OWNER, SK_OWNER, seq=0, **kw)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    return chain, parse_install_payout_rule(install).rule_id


def _book(chain):
    return chain.lm.payout_rules


# --- install ---------------------------------------------------------------------


def test_tau_install_lands_and_event_carries_the_form():
    chain = _funded_chain()
    install = _install_tau_tx(OWNER, SK_OWNER, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    entry = _book(chain).get(OWNER)
    assert entry is not None and entry.form == FORM_TAU_RULE
    assert entry.clause_text == CLAUSE and entry.legs == ()
    (event,) = result.next_snapshot.metadata["payout_events"]
    assert event["action"] == "installed" and event["form"] == FORM_TAU_RULE
    assert chain.balances[OWNER] == 100000 - FEE


# --- named case 2 as a Tau clause: 5% on 101 pays 5, once --------------------------


def test_royalty_as_a_tau_clause_pays_5_on_101_once():
    captured = _script(_royalty_outputs)
    chain, rule_id = _installed_chain()
    owner_after_install = chain.balances[OWNER]

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 5
    assert chain.balances[OWNER] == owner_after_install - 5
    assert chain.balances[EXECUTOR] == 1000 - FEE
    (event,) = result.next_snapshot.metadata["payout_events"]
    assert event["action"] == "executed" and event["form"] == FORM_TAU_RULE
    assert event["total"] == 5
    assert event["legs"] == [{"recipient_pubkey": ARTIST, "amount": 5}]

    # The clause was stepped over the node-built map: the base at i1, the
    # owner's balance at i2, owner at i3, the EXECUTOR at i4, the block
    # timestamp at i5, and nothing paid yet at i26.
    (seen,) = captured
    assert seen["i1"] == "101"
    assert seen["i2"] == str(owner_after_install)
    assert seen["i3"] == "#x" + OWNER
    assert seen["i4"] == "#x" + EXECUTOR
    assert seen["i5"] == str(TS)
    assert seen["i26"] == "0"

    # A repeat execution carrying the same settlement id settles nothing.
    again = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=1)
    result = chain.apply([again])
    assert again["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000 + 5

    # A different settlement settles — and the clause now reads the
    # period's recorded paid total (5) at i26.
    captured.clear()
    other = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_2, 101, seq=1)
    result = chain.apply([other])
    assert other["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 10
    (seen,) = captured
    assert seen["i26"] == "5"


# --- the node checks the clause's legs ------------------------------------------------


def test_tau_clause_leg_above_per_execution_cap_settles_nothing():
    _script(lambda inputs: {"o30": "1", "o31": "0", "o32": "600"})
    chain, rule_id = _installed_chain(max_per_execution=500)
    owner_after_install = chain.balances[OWNER]
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 1, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000
    assert chain.balances[OWNER] == owner_after_install
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))
    assert _book(chain).period_total(rule_id, 0) == 0

    # At the cap the same clause settles: the refusal was the cap, not
    # the form.
    _script(lambda inputs: {"o30": "1", "o31": "0", "o32": "500"})
    ok = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 1, seq=0)
    result = chain.apply([ok])
    assert ok["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 500


def test_tau_clause_out_of_range_candidate_settles_nothing():
    _script(lambda inputs: {"o30": "1", "o31": "7", "o32": "5"})
    chain, rule_id = _installed_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000 and chain.balances[WORKER] == 0
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))


def test_tau_clause_two_legs_atomic_under_a_seam_block():
    def two_legs(inputs):
        return {
            "o30": "2",
            "o31": str(IDX[WORKER]), "o32": "700",
            "o33": str(IDX[ARTIST]), "o34": "5",
        }

    _script(two_legs)
    chain, rule_id = _installed_chain(recipients=[ARTIST, WORKER])
    owner_after_install = chain.balances[OWNER]
    blocked = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([blocked], block_amount=5)
    assert blocked["tx_id"] in result.invalid_tx_ids
    assert chain.balances[WORKER] == 0 and chain.balances[ARTIST] == 1000
    assert chain.balances[OWNER] == owner_after_install
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))

    allowed = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([allowed])
    assert allowed["tx_id"] in result.accepted_tx_ids
    assert chain.balances[WORKER] == 700 and chain.balances[ARTIST] == 1005


def test_tau_clause_blocking_o5_settles_nothing():
    _script(lambda inputs: {"o5": "{ #x000000 }:bv[24]", "o30": "1",
                            "o31": "0", "o32": "5"})
    chain, rule_id = _installed_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))


def test_tau_clause_that_does_not_build_settles_nothing():
    _script(fail_build=True)
    chain, rule_id = _installed_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))


def test_tau_leg_is_never_split_by_a_receive_route():
    _script(_royalty_outputs)
    chain, rule_id = _installed_chain()
    chain.lm.receive_routes.install(ReceiveRouteEntry(
        owner_pubkey=ARTIST, destination_pubkey=RDEST, bps=5000,
        min_amount=0, activation_ts=0, expiry_ts=0, locked_until_ts=0,
        version=1,
    ), TS)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 5  # whole, not split
    assert chain.balances[RDEST] == 0
    assert result.next_snapshot.metadata["routing_events"] == []


# --- admission and apply agree ---------------------------------------------------------


class _TipView(TipAdmissionView):
    """The real facade view over an injected book, at a fixed timestamp."""

    def __init__(self, book, balances):
        self._book = book
        self._balances = balances

    @property
    def next_block_timestamp(self):
        return TS

    def _tip_payout_book(self):
        return self._book

    def get_balance(self, pubkey):
        return self._balances.get(pubkey, 0)


def test_tau_admission_agrees_with_apply():
    from consensus.admission import (
        validate_execute_payout_rule_payload,
        validate_install_payout_rule_payload,
    )

    captured = _script(_royalty_outputs)
    empty = _TipView(PayoutRuleBook(), {OWNER: 100000})
    install = _install_tau_tx(OWNER, SK_OWNER, seq=0)
    assert validate_install_payout_rule_payload(install, empty).is_valid

    book = PayoutRuleBook()
    entry = parse_install_payout_rule(install)
    book.install(entry, TS)
    live = _TipView(book, {OWNER: 100000})

    due = validate_execute_payout_rule_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, entry.rule_id, SID_1, 101, seq=0),
        live)
    assert due.is_valid and due.data["total"] == 5
    assert due.data["legs"] == [{"recipient_pubkey": ARTIST, "amount": 5}]
    # Admission stepped the clause over the same map apply builds: the
    # executor is the transaction's sender, the paid total the tip's.
    (seen,) = captured
    assert seen["i4"] == "#x" + EXECUTOR and seen["i26"] == "0"
    assert seen["i5"] == str(TS)

    # After the settlement lands, admission refuses the repeat — it has
    # paid, once — reading the same book state as apply.
    book.execute(entry.rule_id, bytes.fromhex(SID_1), 101, TS, 100000,
                 clause_legs=((ARTIST, 5),))
    assert not validate_execute_payout_rule_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, entry.rule_id, SID_1, 101, seq=0),
        live).is_valid

    # A clause whose legs break the cap is refused at admission too.
    capped = _install_tau_tx(OWNER, SK_OWNER, seq=0, max_per_execution=4)
    capped_entry = parse_install_payout_rule(capped)
    capped_book = PayoutRuleBook()
    capped_book.install(capped_entry, TS)
    capped_live = _TipView(capped_book, {OWNER: 100000})
    assert not validate_execute_payout_rule_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, capped_entry.rule_id, SID_3,
                    101, seq=0),
        capped_live).is_valid
