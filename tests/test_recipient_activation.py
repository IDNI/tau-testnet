"""Recipient controls use a canonical flag shared by admission, apply and wallets."""
import json
import subprocess
import sys
from types import SimpleNamespace

import pytest

import chain_state
import db
from commands import getgovernance
from consensus.admission import _check_host_contract_patch
from consensus.approvals import recipient_controls_active
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate, ConsensusRuleVote


VALIDATOR = 'ab' * 48
FLAG = 'recipient_controls_active'


def generate_genesis(tmp_path, enabled):
    path = tmp_path / ('active.json' if enabled else 'legacy.json')
    argv = [sys.executable, 'scripts/gen_genesis.py', '--validator-key', VALIDATOR, '--out', str(path)]
    if enabled:
        argv.append('--recipient-controls')
    subprocess.run(argv, check=True)
    return path


def assert_discovery(enabled):
    assert recipient_controls_active(TipAdmissionView()) is enabled
    container = SimpleNamespace(chain_state=chain_state, db=db)
    response = json.loads(getgovernance.execute('getgovernance', container))
    assert response['data'][FLAG] is enabled


@pytest.mark.parametrize('at_genesis', [False, True])
def test_genesis_and_voted_activation_persist(temp_database, tmp_path, monkeypatch, at_genesis):
    # load_genesis also sets the baseline used by later replays in this process.
    monkeypatch.setattr(chain_state, '_genesis_recipient_controls_active', False)
    path = generate_genesis(tmp_path, at_genesis)
    artifact = json.loads(path.read_text())
    metadata = artifact['consensus_meta']['mechanism_specific_metadata']
    assert (FLAG in metadata) is at_genesis
    chain_state.load_genesis(str(path))
    assert_discovery(at_genesis)

    lm = chain_state._lifecycle_manager
    initial = lm.consensus_meta_hash()
    if not at_genesis:
        patch = {FLAG: True}
        assert _check_host_contract_patch(patch, [VALIDATOR]) is None
        update = ConsensusRuleUpdate(['T.'], 10, patch)
        lm.submit_update(update)
        lm.submit_vote(ConsensusRuleVote(update.update_id, True), VALIDATOR)
        lm.process_height_transitions(9)
        assert_discovery(False)
        lm.process_height_transitions(10)
        assert_discovery(True)
        assert lm.consensus_meta_hash() != initial
    else:
        other = json.loads(generate_genesis(tmp_path, False).read_text())
        assert artifact['block_0']['hash'] != other['block_0']['hash']

    chain_state.commit_state_to_db(db.get_genesis_hash(), 0)
    chain_state._lifecycle_manager = ConsensusLifecycleManager()
    assert chain_state.load_state_from_db()
    assert_discovery(True)


@pytest.mark.parametrize('value', [False, 1, 'true', None])
def test_activation_cannot_be_spelled_as_other_values_or_downgraded(value):
    lm = ConsensusLifecycleManager(active_validators=[VALIDATOR])
    lm.apply_host_contract_patch({FLAG: True})
    active_hash = lm.consensus_meta_hash()
    assert _check_host_contract_patch({FLAG: value}, [VALIDATOR])
    with pytest.raises(ValueError, match=FLAG):
        lm.apply_host_contract_patch({FLAG: value})
    assert lm.consensus_meta_hash() == active_hash
    assert lm.recipient_controls_active is True


def test_reorg_replays_genesis_flag_and_publishes_the_same_state_hash(
    temp_database, tmp_path, monkeypatch,
):
    from block import Block
    from consensus.engine import TauConsensusEngine
    import tau_manager

    monkeypatch.setattr(chain_state, '_genesis_recipient_controls_active', False)
    path = generate_genesis(tmp_path, True)
    chain_state.load_genesis(str(path))
    genesis = db.get_genesis_hash()
    monkeypatch.setattr(TauConsensusEngine, 'verify_block_header', lambda *args, **kwargs: True)
    monkeypatch.setattr(tau_manager.tau_ready, 'wait', lambda *args, **kwargs: False)
    header = dict(block_number=1, previous_hash=genesis, transactions=[],
                  proposer_pubkey=VALIDATOR, timestamp=1_700_000_001)
    candidate = Block.create(**header, state_hash=None)
    candidate.header.state_hash = ''
    assert chain_state.process_new_block(candidate)
    state_hash = chain_state._tau_engine_state_hash
    assert state_hash
    stored = Block.create(**header, state_hash=state_hash)
    db.add_block(stored)
    assert chain_state.reorg_to(stored.block_hash)
    assert chain_state._tau_engine_state_hash == state_hash
    assert db.get_canonical_head()['block_hash'] == stored.block_hash
    assert db.get_chain_state_value(FLAG) == '1'
    assert_discovery(True)
