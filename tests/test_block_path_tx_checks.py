"""Block apply runs the transfer and recipient key checks of admission.

A proposer can put any transaction into a block. These tests build such
blocks with real keys and real signatures and apply them, live and on replay.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import config
import db
import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from block import Block
from bls_keys import (
    INVALID_PUBKEYS,
    SK_ALICE,
    SK_CAROL,
    SK_MALLORY,
    pubkey_hex,
    sign_tx,
)
from chain_state import compute_accounts_hash
from consensus.admission import TipAdmissionView, validate_user_tx_reserved_domains
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_checks import (
    APPLY_REASON_RECIPIENT_KEY,
    APPLY_REASON_TRANSFER,
    apply_tx_error,
    check_transfer,
)

SK_PROPOSER = 0x9909
ALICE = pubkey_hex(SK_ALICE)
CAROL = pubkey_hex(SK_CAROL)
MALLORY = pubkey_hex(SK_MALLORY)
PROPOSER = pubkey_hex(SK_PROPOSER)
INT_ADDRESS = 12345
HEIGHT = 10
FEE = 5
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."


def _transfer(sender, sk, transfers, *, seq=0, tx_id="tx", fee_limit="0"):
    return sign_tx({
        "tx_id": tx_id,
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expire_at_height": 1000,
        "fee_limit": fee_limit,
        "operations": {"1": transfers},
    }, sk)


def _offer(recipient, *, tx_id="offer", seq=0):
    return sign_tx({
        "tx_id": tx_id,
        "tx_type": "rule_offer",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expire_at_height": 500,
        "recipient_pubkey": recipient,
        "rule_text": OFFER_RULE,
    }, SK_ALICE)


def _tau_multi(fee):
    def _multi(**kw):
        values = kw.get("input_stream_values") or {}
        return {1: str(values.get(1, "0")), 5: "1", 8: "0", 9: str(fee)}
    return _multi


@pytest.fixture
def engine(monkeypatch):
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False, raising=False)
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_tau_multi(0)), \
         patch("tau_manager.communicate_with_tau", return_value="ok"):
        ready.is_set.return_value = True
        store = MagicMock()
        store.commit.side_effect = lambda snap: snap
        yield TauConsensusEngine(state_store=store)


def _apply(engine, txs, balances, *, sequences=None, replay_mode=False):
    return engine.apply(
        TauStateSnapshot(b"hash", b"rules", {}), txs, 1_700_000_000,
        target_balances=balances,
        target_sequences=sequences if sequences is not None else {},
        target_lifecycle=ConsensusLifecycleManager(active_validators=[PROPOSER]),
        proposer_pubkey=PROPOSER,
        block_height=HEIGHT,
        replay_mode=replay_mode,
    )


def _reason(result, tx_id):
    return result.receipts[tx_id].get("reason")


# --- transfers at apply ----------------------------------------------------------

def test_a_genuine_transfer_is_applied(engine):
    balances = {ALICE: 1000}
    result = _apply(engine, [_transfer(ALICE, SK_ALICE, [[ALICE, CAROL, "100"]])], balances)
    assert [t["tx_id"] for t in result.accepted_transactions] == ["tx"]
    assert balances == {ALICE: 900, CAROL: 100}


@pytest.mark.parametrize("replay_mode", [False, True])
def test_a_transfer_from_a_foreign_account_is_refused(engine, replay_mode):
    """Mallory signs her own transaction, but the transfer moves Alice's coins."""
    balances = {ALICE: 1000, MALLORY: 0}
    steal = _transfer(MALLORY, SK_MALLORY, [[ALICE, MALLORY, "500"]])
    result = _apply(engine, [steal], balances, replay_mode=replay_mode)
    assert result.accepted_transactions == []
    assert _reason(result, "tx") == APPLY_REASON_TRANSFER
    assert balances == {ALICE: 1000, MALLORY: 0}


@pytest.mark.parametrize("replay_mode", [False, True])
@pytest.mark.parametrize("transfer", [
    [ALICE, ALICE, "1"],
    [ALICE, CAROL, "0"],
    [ALICE, CAROL, str(2 ** 256)],
    [ALICE, INVALID_PUBKEYS[1][1], "1"],
], ids=["to-sender", "zero-amount", "amount-too-large", "to-not-in-subgroup"])
def test_an_invalid_transfer_is_refused(engine, replay_mode, transfer):
    balances = {ALICE: 1000}
    result = _apply(engine, [_transfer(ALICE, SK_ALICE, [transfer])], balances,
                    replay_mode=replay_mode)
    assert result.accepted_transactions == []
    assert _reason(result, "tx") == APPLY_REASON_TRANSFER
    assert balances == {ALICE: 1000}


def test_an_int_address_is_refused_and_a_restart_keeps_the_state_hash(engine, temp_database):
    balances, sequences = {ALICE: 1000}, {}
    to_int = _transfer(ALICE, SK_ALICE, [[ALICE, INT_ADDRESS, "10"]], tx_id="int-addr")
    genuine = _transfer(ALICE, SK_ALICE, [[ALICE, CAROL, "7"]], tx_id="genuine")
    result = _apply(engine, [to_int, genuine], balances, sequences=sequences)
    assert _reason(result, "int-addr") == APPLY_REASON_TRANSFER
    assert [t["tx_id"] for t in result.accepted_transactions] == ["genuine"]
    assert balances == {ALICE: 993, CAROL: 7}

    db.save_canonical_state_atomically("head", 1, balances, sequences, "", "", "", [], [], [], [])
    loaded_balances, loaded_sequences = db.load_chain_state()[:2]
    assert compute_accounts_hash(loaded_balances, loaded_sequences) == \
        compute_accounts_hash(balances, sequences)


def test_a_refused_transfer_pays_no_fee_and_keeps_the_sequence(monkeypatch):
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False, raising=False)
    balances, sequences = {ALICE: 1000, MALLORY: 50}, {}
    steal = _transfer(MALLORY, SK_MALLORY, [[ALICE, MALLORY, "500"]], fee_limit="100")
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_tau_multi(FEE)), \
         patch("tau_manager.communicate_with_tau", return_value="ok"):
        ready.is_set.return_value = True
        store = MagicMock()
        store.commit.side_effect = lambda snap: snap
        result = _apply(TauConsensusEngine(state_store=store), [steal], balances,
                        sequences=sequences)
    assert _reason(result, "tx") == APPLY_REASON_TRANSFER
    assert result.receipts["tx"]["fee_charged"] == 0
    assert balances == {ALICE: 1000, MALLORY: 50}
    assert sequences.get(MALLORY, 0) == 0


# --- recipient keys at apply -----------------------------------------------------

def _signed(tx_type, **fields):
    return sign_tx({"tx_id": tx_type, "tx_type": tx_type, "sender_pubkey": ALICE,
                    "sequence_number": 0, "expire_at_height": 500, **fields}, SK_ALICE)


@pytest.mark.parametrize("label,bad_key", INVALID_PUBKEYS)
@pytest.mark.parametrize("make", [
    lambda key: _signed("rule_offer", recipient_pubkey=key, rule_text=OFFER_RULE),
    lambda key: _signed("approval_request", recipient_pubkey=key, amount=10,
                        approvers={"18": CAROL}, custom_inputs={}),
    lambda key: _signed("approval_request", recipient_pubkey=CAROL, amount=10,
                        approvers={"18": key}, custom_inputs={}),
    lambda key: _signed("retractable_transfer", recipient_pubkey=key, amount=10,
                        release_at_height=20),
], ids=["offer-recipient", "request-recipient", "request-approver", "park-recipient"])
def test_an_invalid_recipient_key_is_refused(make, label, bad_key):
    reason, detail = apply_tx_error(make(bad_key))
    assert reason == APPLY_REASON_RECIPIENT_KEY
    assert detail


def test_valid_recipient_keys_pass():
    assert apply_tx_error(_signed("retractable_transfer", recipient_pubkey=CAROL,
                                  amount=10, release_at_height=20)) is None
    assert apply_tx_error(_offer(CAROL)) is None


@pytest.mark.parametrize("replay_mode", [False, True])
def test_a_rule_offer_to_an_invalid_key_is_refused_at_apply(engine, replay_mode):
    result = _apply(engine, [_offer(INVALID_PUBKEYS[0][1])], {ALICE: 1000},
                    replay_mode=replay_mode)
    assert result.accepted_transactions == []
    assert _reason(result, "offer") == APPLY_REASON_RECIPIENT_KEY


# --- check_transfer, shared by sendtx, admission and apply -----------------------

@pytest.mark.parametrize("transfer,error", [
    ([ALICE, CAROL], "invalid transfer format"),
    ("not-a-transfer", "invalid transfer format"),
    ([CAROL, ALICE, "1"], "does not match sender_pubkey"),
    ([ALICE, INT_ADDRESS, "1"], "'to' address"),
    ([ALICE, ALICE, "1"], "'to' address is the sender"),
    ([ALICE, ALICE.upper(), "1"], "'to' address is the sender"),
    ([ALICE, CAROL, "0"], "amount must be positive"),
    ([ALICE, CAROL, -1], "amount must be positive"),
    ([ALICE, CAROL, 2 ** 256], "amount must be positive"),
    ([ALICE, CAROL, True], "invalid amount"),
    ([ALICE, CAROL, 1.5], "invalid amount"),
    ([ALICE, CAROL, "ten"], "invalid amount"),
])
def test_check_transfer_refuses(transfer, error):
    assert error in check_transfer(transfer, ALICE)


@pytest.mark.parametrize("label,bad_key", INVALID_PUBKEYS)
def test_check_transfer_refuses_an_invalid_key(label, bad_key):
    assert "'to' address" in check_transfer([ALICE, bad_key, "1"], ALICE)
    assert "'from' address" in check_transfer([bad_key, CAROL, "1"], bad_key)


def test_check_transfer_accepts_a_valid_transfer():
    assert check_transfer([ALICE, CAROL, "1"], ALICE) is None
    assert check_transfer((ALICE, CAROL, 2 ** 256 - 1), ALICE) is None


def _tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.eligibility_mode = ""
    view.approval_slots_active = False
    return view


@pytest.mark.parametrize("transfer", [
    [CAROL, ALICE, "1"],
    [ALICE, ALICE, "1"],
    [ALICE, CAROL, "0"],
])
def test_admission_refuses_what_apply_refuses(transfer):
    tx = {"sender_pubkey": ALICE, "operations": {"1": [transfer]}}
    result = validate_user_tx_reserved_domains(tx, _tip_view())
    assert result.is_valid is False
    assert result.code == "TX_INVALID"
    assert check_transfer(transfer, ALICE) in result.error


# --- proposal mode and direct apply agree ----------------------------------------

class _Session:
    """A scripted evaluator for proposal mode, with the outputs of `_tau_multi`."""

    is_speculative = True

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        return "ok"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        outputs = {
            tau_defs.USER_POLICY_STREAM_INDEX: "1",
            tau_defs.CONSENSUS_FEE_STREAM_INDEX: "0",
        }
        return outputs if multi else ""

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        pass


def _block_txs():
    return [
        _transfer(ALICE, SK_ALICE, [[ALICE, CAROL, "100"]], tx_id="genuine"),
        _transfer(MALLORY, SK_MALLORY, [[ALICE, MALLORY, "500"]], tx_id="steal"),
        _offer(INVALID_PUBKEYS[1][1], tx_id="bad-offer", seq=1),
    ]


def _apply_block(*, proposal_mode):
    lm = ConsensusLifecycleManager(active_validators=[PROPOSER])
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always ( o0[t]=1 ).",
        metadata={
            "balances": {ALICE: 1000, CAROL: 0, MALLORY: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(target_height=HEIGHT, consensus_rules="",
                               active_validators=[bytes.fromhex(PROPOSER)])
    block = Block.create(block_number=HEIGHT, previous_hash="0" * 64,
                         transactions=_block_txs(), proposer_pubkey=PROPOSER,
                         timestamp=1_700_000_000)
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_tau_multi(0)), \
         patch("tau_manager.communicate_with_tau", return_value="ok"):
        ready.is_set.return_value = True
        if proposal_mode:
            session = _Session()
            plan = tr.plan_representation(candidate_rules=[])
            proposal = tp.ProposalContext(
                session=session,
                journal=tj.Journal(authoritative=False),
                allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                          label="proposal"),
                plan=plan, lifecycle=lm,
            )
            result = engine.apply_block(view, block, parent, session=session,
                                        proposal=proposal)
        else:
            result = engine.apply_block(view, block, parent)
    sealed = Block.create(block_number=HEIGHT, previous_hash="0" * 64,
                          transactions=_block_txs(), proposer_pubkey=PROPOSER,
                          timestamp=1_700_000_000,
                          state_hash=result.next_snapshot.state_hash)
    return result, sealed


def test_proposal_and_direct_apply_give_the_same_block_hash(monkeypatch, temp_database):
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False, raising=False)
    proposed, proposed_block = _apply_block(proposal_mode=True)
    direct, direct_block = _apply_block(proposal_mode=False)

    for result in (proposed, direct):
        assert result.accepted_tx_ids == ["genuine"]
        assert sorted(result.invalid_tx_ids) == ["bad-offer", "steal"]
        assert sorted(o.reason for o in result.outcomes if o.reason) == [
            APPLY_REASON_RECIPIENT_KEY, APPLY_REASON_TRANSFER]
        assert result.next_snapshot.metadata["balances"] == {
            ALICE: 900, CAROL: 100, MALLORY: 0}
    assert proposed.next_snapshot.state_hash == direct.next_snapshot.state_hash
    assert proposed_block.block_hash == direct_block.block_hash
