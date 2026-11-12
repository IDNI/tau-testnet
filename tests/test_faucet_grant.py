"""The genesis faucet: one grant per account, at the first touch.

Each block runs on the production path (a proposal) and on the test-mode path
(no proposal). Both paths must give the same balances and the same state hash.
"""
import copy
import json
import subprocess
import types
from pathlib import Path
from unittest.mock import patch

import pytest

import chain_state
import config
import tau_defs
from block import Block
from bls_keys import sign_payload
from consensus import faucet
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.retractable import KIND_HEIGHT, RetractableEntry
from consensus.state import TauStateSnapshot
from errors import BlockchainBug
from test_retractable_apply import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, SK_BOB, TS, park_tx, spend_tx,
)
from test_retractable_apply_proposal import _Session, _engine, _proposal, _view

GRANT = 100000
PATHS = ["proposal", "plain"]


def _lifecycle(grant=GRANT):
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.faucet_amount = grant
    return lm


def _parent(balances, sequences=None, lm=None):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always ( o0[t]=1 ).",
        metadata={
            "balances": dict(balances),
            "sequence_numbers": dict(sequences or {}),
            "last_transfer_ts": {},
            "lifecycle_manager": lm if lm is not None else _lifecycle(),
            "consensus_rules_state": "",
            "active_consensus_id": "",
        },
    )


def _block(txs, height=HEIGHT):
    return Block.create(
        block_number=height, previous_hash="0" * 64, transactions=txs,
        proposer_pubkey=PROPOSER, timestamp=TS,
    )


def _run(path, txs, parent, fee="0", view=None, session=None, height=HEIGHT):
    view = view or _view()
    if path == "proposal":
        session = session or _Session(fee=fee)
        with patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            return _engine().apply_block(
                view, _block(txs, height), parent, session=session,
                proposal=_proposal(session),
            )

    def multi(**kwargs):
        if session is not None:
            return session.evaluate(kwargs.get("input_stream_values") or {}, multi=True)
        return {tau_defs.USER_POLICY_STREAM_INDEX: "1",
                tau_defs.CONSENSUS_FEE_STREAM_INDEX: fee}

    # The live chain state differs from the parent on purpose: the test-mode
    # path must read the parent, never the node's head.
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", return_value="T"), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=multi), \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch.dict(chain_state._balances, {BOB: 7, CAROL: 7}, clear=True), \
         patch.dict(chain_state._sequence_numbers, {}, clear=True):
        ready.is_set.return_value = True
        return TauConsensusEngine().apply_block(view, _block(txs, height), parent)


def _bal(result):
    return result.next_snapshot.metadata["balances"]


def _supply(result):
    return sum(_bal(result).values())


@pytest.mark.parametrize("path", PATHS)
def test_a_new_recipient_keeps_the_grant(temp_database, path):
    tx = spend_tx(ALICE, BOB, 5001, 0, fee_limit="10")
    result = _run(path, [tx], _parent({ALICE: 200000}), fee="10")
    assert result.accepted_tx_ids == [tx["tx_id"]]
    assert _bal(result)[BOB] == GRANT + 5001
    assert _bal(result)[ALICE] == 200000 - 5001 - 10
    # The proposer is a new record too: its first fee carries its grant.
    assert _bal(result)[PROPOSER] == GRANT + 10
    assert _supply(result) == 200000 + 2 * GRANT


def test_both_paths_give_the_same_state(temp_database):
    tx = spend_tx(ALICE, BOB, 5001, 0, fee_limit="10")
    prod = _run("proposal", [tx], _parent({ALICE: 200000}), fee="10")
    plain = _run("plain", [tx], _parent({ALICE: 200000}), fee="10")
    assert _bal(prod) == _bal(plain)
    assert prod.next_snapshot.state_hash == plain.next_snapshot.state_hash


@pytest.mark.parametrize("path", PATHS)
def test_a_new_sender_spends_its_grant(temp_database, path):
    tx = spend_tx(BOB, CAROL, 5000, 0, fee_limit="10")
    result = _run(path, [tx], _parent({ALICE: 200000, PROPOSER: 0}), fee="10")
    assert result.accepted_tx_ids == [tx["tx_id"]]
    assert _bal(result)[BOB] == GRANT - 5000 - 10
    assert _bal(result)[CAROL] == GRANT + 5000


@pytest.mark.parametrize("path", PATHS)
def test_an_account_at_zero_gets_no_second_grant(temp_database, path):
    tx = spend_tx(BOB, CAROL, 5000, 0, fee_limit="10")
    result = _run(path, [tx], _parent({BOB: 0, PROPOSER: 0}), fee="10")
    assert result.accepted_tx_ids == []
    assert _bal(result)[BOB] == 0
    assert CAROL not in _bal(result)


@pytest.mark.parametrize("path", PATHS)
def test_a_sequence_record_has_no_pending_grant(temp_database, path):
    tx = spend_tx(BOB, CAROL, 5000, 3, fee_limit="10")
    parent = _parent({ALICE: 10, PROPOSER: 0}, sequences={ALICE: 1, BOB: 3})
    result = _run(path, [tx], parent, fee="10")
    assert result.accepted_tx_ids == []
    assert BOB not in _bal(result)


@pytest.mark.parametrize("path", PATHS)
def test_a_record_made_by_the_nonce_alone_gets_the_grant(temp_database, path):
    no_transfer = spend_tx(BOB, CAROL, 1, 0, fee_limit="0")
    no_transfer["operations"] = {"100": "42"}
    sign_payload(no_transfer, SK_BOB)
    result = _run(path, [no_transfer], _parent({ALICE: 1000}))
    assert result.accepted_tx_ids == [no_transfer["tx_id"]]
    assert result.next_snapshot.metadata["sequence_numbers"][BOB] == 1
    assert _bal(result)[BOB] == GRANT
    assert _supply(result) == 1000 + GRANT


@pytest.mark.parametrize("path", PATHS)
def test_i2_shows_the_pending_grant_and_never_a_second_one(temp_database, path):
    seen = {}

    class _Recording(_Session):
        def evaluate(self, inputs, *, multi=False, **kwargs):
            seen.setdefault(str(inputs.get(12, inputs.get("12", ""))), str(inputs.get(2, inputs.get("2"))))
            return super().evaluate(inputs, multi=multi, **kwargs)

    fresh = spend_tx(BOB, ALICE, 1, 0, fee_limit="10")
    zero = spend_tx(CAROL, ALICE, 1, 0, fee_limit="10")
    _run(path, [fresh, zero], _parent({ALICE: 10, CAROL: 0, PROPOSER: 0}),
         session=_Recording(fee="10"))
    by_sender = {k: v for k, v in seen.items() if k}
    assert any(BOB in k and v == str(GRANT) for k, v in by_sender.items()), by_sender
    assert any(CAROL in k and v == "0" for k, v in by_sender.items()), by_sender


def test_the_node_environment_does_not_change_the_state_hash(temp_database, monkeypatch):
    assert "TAU_AUTO_FAUCET" not in config._ENV_VALUE_CASTERS
    assert not hasattr(config.settings.authority, "auto_faucet")
    tx = spend_tx(BOB, CAROL, 5000, 0, fee_limit="10")
    hashes = []
    for env in ({"TAU_AUTO_FAUCET": "true", "TAU_AUTO_FAUCET_AMOUNT": "7"},
                {"TAU_AUTO_FAUCET": "false"}):
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        result = _run("proposal", [tx], _parent({ALICE: 200000}), fee="10")
        assert result.accepted_tx_ids == [tx["tx_id"]]
        hashes.append(result.next_snapshot.state_hash)
    assert hashes[0] == hashes[1]


def test_the_genesis_amount_is_part_of_the_state_hash(temp_database):
    tx = spend_tx(ALICE, BOB, 5001, 0, fee_limit="10")
    on = _run("proposal", [tx], _parent({ALICE: 200000}, lm=_lifecycle(GRANT)), fee="10")
    off = _run("proposal", [tx], _parent({ALICE: 200000}, lm=_lifecycle(0)), fee="10")
    assert _bal(off)[BOB] == 5001
    assert on.next_snapshot.state_hash != off.next_snapshot.state_hash


@pytest.mark.parametrize("path", PATHS)
def test_the_supply_check_finds_an_injected_mint(temp_database, monkeypatch, path):
    import consensus.engine as eng
    orig = eng._release_due_retractables

    def mint(lm, balances, sequences, height, timestamp):
        balances[ALICE] = int(balances.get(ALICE, 0)) + 7
        return orig(lm, balances, sequences, height, timestamp)

    tx = spend_tx(ALICE, BOB, 5001, 0, fee_limit="10")
    ok = _run(path, [tx], _parent({ALICE: 200000}), fee="10")
    assert _supply(ok) == 200000 + 2 * GRANT
    monkeypatch.setattr(eng, "_release_due_retractables", mint)
    with pytest.raises(BlockchainBug):
        _run(path, [tx], _parent({ALICE: 200000}), fee="10")


@pytest.mark.parametrize("path", PATHS)
def test_a_park_from_a_new_sender_and_a_release_to_a_new_recipient(temp_database, path):
    lm = _lifecycle()
    lm.activate_approval_slots()
    tx = park_tx(amount=100, seq=0, at_height=HEIGHT + 5)
    park = _run(path, [tx], _parent({CAROL: 1, PROPOSER: 0}, lm=lm), fee="3")
    assert park.accepted_tx_ids == [tx["tx_id"]]
    assert _bal(park)[ALICE] == GRANT - 100 - 3

    lm2 = _lifecycle()
    lm2.activate_approval_slots()
    lm2.retractable_transfers.submit(RetractableEntry(ALICE, BOB, 300, 0, KIND_HEIGHT, HEIGHT))
    release = _run(path, [], _parent({ALICE: 1000}, {ALICE: 1}, lm=lm2))
    assert _bal(release)[BOB] == GRANT + 300
    assert _supply(release) == 1000 + GRANT + 300


class _TierSession(_Session):
    """Scripted Tau: an amount over 1000 is blocked unless slot 18 holds the approver."""

    def __init__(self, approver, fee="10"):
        super().__init__(fee=fee)
        self.approver = approver

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        amount = int(str(inputs.get(1, "0")) or 0)
        blocked = amount > 1000 and self.approver not in str(inputs.get(18, "0"))
        out = {1: str(amount), tau_defs.USER_POLICY_STREAM_INDEX: "0" if blocked else "1",
               tau_defs.CONSENSUS_FEE_STREAM_INDEX: self.fee}
        return out if multi else ""


def test_an_approved_transfer_to_a_new_recipient_keeps_the_grant(temp_database):
    """A parks 5001 for new B, and B approves: B ends at the grant plus 5001."""
    import test_approval_apply as ta
    from consensus.approvals import STATUS_EXECUTED
    req = ta.ApprovalRequest(
        sender_pubkey=ta.ALICE, recipient_pubkey=ta.AUTH, amount=5001, sequence_number=0,
        expire_at_height=ta.EXPIRE, approvers={18: ta.AUTH}, custom_inputs={})
    view = ActiveConsensusView(
        target_height=HEIGHT, consensus_rules="", active_validators=[bytes.fromhex(ALICE)],
        mechanism_specific_metadata={"approval_slots_active": True})
    lm = _lifecycle()
    lm.activate_approval_slots()
    parked = _run("proposal", [ta.request_tx(req)], _parent({ta.ALICE: 100000, PROPOSER: 0}, lm=lm),
                  view=view, session=_TierSession(ta.AUTH))
    assert parked.accepted_tx_ids
    voted = _run("proposal", [ta.vote_tx(req)], parked.next_snapshot,
                 view=view, session=_TierSession(ta.AUTH, fee="0"))
    status = voted.next_snapshot.metadata["lifecycle_manager"].approval_requests.terminal_status
    assert status[req.request_id] == STATUS_EXECUTED
    assert _bal(voted)[ta.AUTH] == GRANT + 5001


def test_get_balance_uses_the_same_rule(monkeypatch):
    monkeypatch.setattr(chain_state._lifecycle_manager, "faucet_amount", GRANT)
    with patch.dict(chain_state._balances, {ALICE: 10, CAROL: 0}, clear=True), \
         patch.dict(chain_state._sequence_numbers, {ALICE: 1, BOB: 3}, clear=True):
        assert chain_state.get_balance(ALICE) == 10
        assert chain_state.get_balance(BOB) == 0
        assert chain_state.get_balance(CAROL) == 0
        assert chain_state.get_balance(PROPOSER) == GRANT


def test_a_restart_gives_the_same_balances(temp_database, monkeypatch):
    monkeypatch.setattr(chain_state, "_genesis_faucet_amount", GRANT)
    monkeypatch.setattr(chain_state, "_lifecycle_manager", _lifecycle())
    with patch.dict(chain_state._balances, {ALICE: 10}, clear=True), \
         patch.dict(chain_state._sequence_numbers, {ALICE: 1, BOB: 3}, clear=True):
        live = {a: chain_state.get_balance(a) for a in (ALICE, BOB, CAROL)}
        chain_state.commit_state_to_db("ab" * 32, 1)
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state.load_state_from_db()
        restarted = {a: chain_state.get_balance(a) for a in (ALICE, BOB, CAROL)}
    assert live == {ALICE: 10, BOB: 0, CAROL: GRANT}
    assert restarted == live


def test_granted_counts_each_new_record_once():
    assert faucet.granted({ALICE: 1}, {BOB: 2}, {ALICE: 1, CAROL: 5}, {BOB: 3, CAROL: 1}, 10) == 10
    assert faucet.granted({ALICE: 1}, {}, {ALICE: 1, CAROL: 5}, {}, 0) == 0


def test_admission_judges_the_same_spendable_balance(temp_database, monkeypatch):
    """A new sender is funded by its pending grant; a recorded 0 is not."""
    import importlib
    import json
    from commands import checktx, sendtx
    import test_checktx as tc
    importlib.reload(sendtx)
    monkeypatch.setattr(chain_state, "_balances", {})
    monkeypatch.setattr(chain_state, "_sequence_numbers", {})
    chain_state.load_genesis("data/genesis.json")
    monkeypatch.setattr(chain_state._lifecycle_manager, "faucet_amount", GRANT)
    monkeypatch.setattr(sendtx.tau_manager, "communicate_with_tau_multi", tc._mock_tau_multi_ok)
    case = tc.TestChecktx()
    chain_state._balances.pop(tc.SENDER, None)
    chain_state._sequence_numbers.pop(tc.SENDER, None)
    fresh = json.loads(checktx.execute(f"checktx {json.dumps(case._tx())}", None))
    chain_state._balances[tc.SENDER] = 0
    zero = json.loads(checktx.execute(f"checktx {json.dumps(case._tx())}", None))
    assert fresh["status"] == "ok" and fresh["data"]["admissible"] is True, fresh
    assert zero["status"] != "ok", zero


class _NoFaucetField:
    pass


class _Faucet:
    def __init__(self, value):
        self.faucet_amount = value


def test_amount_gives_a_valid_value():
    assert faucet.amount(_Faucet(GRANT)) == GRANT
    assert faucet.amount(_Faucet(0)) == 0
    assert faucet.amount(ConsensusLifecycleManager()) == 0


def test_amount_refuses_a_missing_value():
    with pytest.raises(BlockchainBug, match="no faucet_amount"):
        faucet.amount(_NoFaucetField())
    with pytest.raises(BlockchainBug, match="no faucet_amount"):
        faucet.amount(None)


@pytest.mark.parametrize("value", ["100000", None, True, -1, tau_defs.MAX_TRANSFER_VALUE + 1, 1.5])
def test_amount_refuses_a_bad_value(value):
    with pytest.raises(BlockchainBug, match="faucet_amount"):
        faucet.amount(_Faucet(value))


def _committed_genesis_files():
    repo = Path(__file__).resolve().parent.parent
    out = subprocess.run(["git", "ls-files", "*genesis*.json"], cwd=repo,
                         capture_output=True, text=True, check=True).stdout
    return [repo / name for name in out.split()]


def test_the_repo_ships_a_genesis_file():
    assert _committed_genesis_files()


@pytest.mark.parametrize("path", _committed_genesis_files(), ids=lambda p: p.parent.name)
def test_each_committed_genesis_still_loads(temp_database, monkeypatch, path):
    for name, value in list(vars(chain_state).items()):
        if name.startswith("_") and not name.startswith("__") and not callable(value) \
                and not isinstance(value, types.ModuleType):
            fresh = copy.copy(value) if isinstance(value, (dict, list, set)) else value
            monkeypatch.setattr(chain_state, name, fresh)
    meta = json.loads(path.read_text())["consensus_meta"]
    pinned = meta.get("mechanism_specific_metadata", {}).get("faucet_amount", 0)
    chain_state.load_genesis(str(path))
    assert faucet.amount(chain_state._lifecycle_manager) == pinned


@pytest.mark.parametrize("path", PATHS)
def test_no_parent_lifecycle_on_a_faucet_network_is_a_bug(temp_database, monkeypatch, path):
    parent = _parent({ALICE: 200000})
    del parent.metadata["lifecycle_manager"]
    tx = spend_tx(ALICE, BOB, 5001, 0, fee_limit="10")
    monkeypatch.setattr(chain_state, "_genesis_faucet_amount", GRANT)
    with pytest.raises(BlockchainBug, match="genesis faucet"):
        _run(path, [tx], parent, fee="10")
    monkeypatch.setattr(chain_state, "_genesis_faucet_amount", 0)
    assert _run(path, [tx], parent, fee="10").accepted_tx_ids == [tx["tx_id"]]


@pytest.mark.parametrize("path", PATHS)
def test_a_fee_credit_is_the_first_touch_of_the_proposer(temp_database, path):
    tx = spend_tx(ALICE, BOB, 100, 0, fee_limit="10")
    result = _run(path, [tx], _parent({ALICE: 200000, BOB: 50}), fee="10")
    assert result.accepted_tx_ids == [tx["tx_id"]]
    assert _bal(result)[BOB] == 150
    assert _bal(result)[PROPOSER] == GRANT + 10
    assert _supply(result) == 200050 + GRANT


def test_both_paths_agree_on_a_fee_credit_first_touch(temp_database):
    tx = spend_tx(ALICE, BOB, 100, 0, fee_limit="10")
    prod = _run("proposal", [tx], _parent({ALICE: 200000, BOB: 50}), fee="10")
    plain = _run("plain", [tx], _parent({ALICE: 200000, BOB: 50}), fee="10")
    assert prod.next_snapshot.state_hash == plain.next_snapshot.state_hash


@pytest.mark.parametrize("path", PATHS)
def test_a_rule_offer_from_a_new_sender_pays_its_fee_from_the_grant(temp_database, path):
    from bls_keys import SK_CAROL as SK_NEW, pubkey_hex
    from consensus.rule_offers import RuleOffer
    new = pubkey_hex(SK_NEW)
    offer = RuleOffer(offerer_pubkey=new, recipient_pubkey=ALICE,
                      rule_text="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).",
                      expire_at_height=HEIGHT + 100)
    tx = sign_payload({
        "tx_id": "offer-from-new",
        "tx_type": "rule_offer",
        "sender_pubkey": new,
        "sequence_number": 0,
        "expiration_time": TS + 10_000,
        "recipient_pubkey": ALICE,
        "rule_text": offer.rule_text,
        "expire_at_height": offer.expire_at_height,
        "fee_limit": "10",
    }, SK_NEW)
    result = _run(path, [tx], _parent({ALICE: 1000, PROPOSER: 0}), fee="10")
    assert result.accepted_tx_ids == [tx["tx_id"]]
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    assert bytes.fromhex(offer.offer_id_hex) in lm.rule_offers.offered
    assert _bal(result)[new] == GRANT - 10
    assert result.next_snapshot.metadata["sequence_numbers"][new] == 1
    assert _bal(result)[PROPOSER] == 10
    assert _supply(result) == 1000 + GRANT
