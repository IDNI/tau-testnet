"""The clause registry: mapping behaviour, incremental root, copies and storage."""
import copy
import random
import struct

import pytest
from blake3 import blake3

import db
import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from consensus import sender_policy
from consensus.clause_registry import ClauseRegistry
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import RuleOfferLifecycleManager, clause_body_v1
from consensus.serialization import (
    CLAUSE_LANES,
    clause_entry_vector,
    clause_root_from_state,
    compute_clause_registry_root,
    encode_clause_entry,
)

import test_approval_apply as ap

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
EMPTY_ROOT = compute_clause_registry_root({})


def account(i):
    return format(i + 1, "096x")


def body(i):
    return f"(o5[t]:bv[24] = {{ #x{i % 0xFFFFFF:06x} }}:bv[24])"


def make(n, offset=0):
    return {(account(i + offset), STREAM): body(i + offset) for i in range(n)}


def random_ops(rng, steps, universe):
    """(op, key, body) triples over a small key universe, so keys collide."""
    for _ in range(steps):
        key = (account(rng.randrange(universe)), rng.choice((5, 6)))
        roll = rng.random()
        if roll < 0.5:
            yield "set", key, body(rng.randrange(6))
        elif roll < 0.8:
            yield "del", key, None
        else:
            yield "get", key, None


def apply_op(target, shadow, op, key, text):
    if op == "set":
        target[key] = text
        shadow[key] = text
    elif op == "del":
        if key in shadow:
            del target[key]
            del shadow[key]
        else:
            with pytest.raises(KeyError):
                del target[key]
    else:
        assert target.get(key) == shadow.get(key)
        assert (key in target) == (key in shadow)


@pytest.fixture
def small_fold(monkeypatch):
    monkeypatch.setattr(ClauseRegistry, "FOLD_AT", 7)


# --- mapping behaviour -------------------------------------------------------

@pytest.mark.parametrize("seed", [1, 2, 3])
def test_registry_behaves_like_a_dict(seed, small_fold):
    rng = random.Random(seed)
    registry, shadow = ClauseRegistry(), {}
    for op, key, text in random_ops(rng, 1500, universe=40):
        apply_op(registry, shadow, op, key, text)
        assert len(registry) == len(shadow)
    assert dict(registry.items()) == shadow
    assert registry == shadow
    assert set(registry) == set(shadow)
    assert sorted(registry.values()) == sorted(shadow.values())


def test_missing_key_and_identical_write(small_fold):
    registry = ClauseRegistry(make(3))
    key = (account(0), STREAM)
    with pytest.raises(KeyError):
        registry[(account(99), STREAM)]
    registry._token = "t"
    registry[key] = registry[key]
    assert registry._changed == set() and registry._version == 0


def test_constructor_accepts_a_plain_mapping():
    registry = ClauseRegistry(make(5))
    assert len(registry) == 5 and registry == make(5)
    assert registry.root() == compute_clause_registry_root(make(5))


# --- root --------------------------------------------------------------------

@pytest.mark.parametrize("seed", [4, 5])
def test_incremental_root_equals_the_reference_after_every_step(seed, small_fold):
    rng = random.Random(seed)
    registry, shadow = ClauseRegistry(), {}
    for op, key, text in random_ops(rng, 500, universe=25):
        apply_op(registry, shadow, op, key, text)
        assert registry.root() == compute_clause_registry_root(shadow)


def test_root_depends_on_content_only(monkeypatch):
    items = list(make(60).items())
    reference = compute_clause_registry_root(dict(items))

    roots = []
    for seed, fold in ((1, 3), (2, 11), (3, 1024)):
        monkeypatch.setattr(ClauseRegistry, "FOLD_AT", fold)
        rng = random.Random(seed)
        order = items[:]
        rng.shuffle(order)
        registry = ClauseRegistry()
        for key, text in order:
            registry[key] = "(o5[t]:bv[24] = { #x0000aa }:bv[24])"
            registry[key] = text
        for key, _ in order[:10]:
            registry[key] = body(777)
        for key, text in order[:10]:
            registry[key] = text
        extra = (account(900), STREAM)
        registry[extra] = body(1)
        del registry[extra]
        roots.append(registry.root())
    assert roots == [reference] * 3


def test_root_changes_with_account_stream_or_body():
    key = (account(1), 5)
    baseline = ClauseRegistry({key: body(1)}).root()
    assert ClauseRegistry({(account(2), 5): body(1)}).root() != baseline
    assert ClauseRegistry({(account(1), 6): body(1)}).root() != baseline
    assert ClauseRegistry({key: body(2)}).root() != baseline
    assert ClauseRegistry({key: body(1), (account(2), 5): body(1)}).root() != baseline


def test_an_emptied_registry_has_the_empty_root(small_fold):
    registry = ClauseRegistry(make(30))
    for key in list(registry):
        del registry[key]
    assert len(registry) == 0
    assert registry.root() == ClauseRegistry().root() == EMPTY_ROOT


def test_root_matches_a_lane_by_lane_reference():
    entries = list(make(40).items())
    lanes = [0] * CLAUSE_LANES
    for (acct, stream), text in entries:
        digest = blake3(encode_clause_entry(acct, stream, text)).digest(length=4096)
        words = struct.unpack("<1024I", digest)
        for i, word in enumerate(words):
            lanes[i] = (lanes[i] + (word & 0xFFFF)) % 65536
    removed = entries[7]
    digest = blake3(encode_clause_entry(removed[0][0], removed[0][1], removed[1])).digest(
        length=4096)
    for i, word in enumerate(struct.unpack("<1024I", digest)):
        lanes[i] = (lanes[i] - (word & 0xFFFF)) % 65536
    state_bytes = b"".join(struct.pack("<I", lane) for lane in lanes)
    expected = blake3(
        b"tau.clause.root.v1" + (len(entries) - 1).to_bytes(8, "big") + state_bytes
    ).digest()

    registry = ClauseRegistry(dict(entries))
    del registry[removed[0]]
    assert registry.root() == expected
    assert clause_root_from_state(len(entries) - 1, int.from_bytes(state_bytes, "little")) \
        == expected
    assert clause_entry_vector(*removed[0], removed[1]) < 1 << (32 * CLAUSE_LANES)


# --- copies ------------------------------------------------------------------

def test_copies_are_isolated_across_folds(small_fold):
    source = ClauseRegistry(make(20))
    source[(account(0), STREAM)] = body(500)
    left = copy.deepcopy(source)
    right = copy.copy(source)
    frozen = dict(source)

    for i in range(30):
        left[(account(100 + i), STREAM)] = body(i)
    for key in list(right)[:12]:
        del right[key]

    assert dict(source) == frozen
    assert len(left) == 50 and len(right) == 8
    assert all((account(100 + i), STREAM) not in right for i in range(30))
    assert all(key in left for key in frozen)

    for i in range(30):
        source[(account(200 + i), STREAM)] = body(i)
    assert not any((account(200 + i), STREAM) in left for i in range(30))
    assert source.root() == compute_clause_registry_root(dict(source))
    assert left.root() == compute_clause_registry_root(dict(left))
    assert right.root() == compute_clause_registry_root(dict(right))


def test_a_copy_shares_the_base_and_copies_the_delta():
    registry = ClauseRegistry(make(50_000))
    registry[(account(0), STREAM)] = body(900_000)
    del registry[(account(1), STREAM)]
    clone = copy.deepcopy(registry)
    assert clone._base is registry._base
    assert clone._delta == registry._delta and clone._delta is not registry._delta
    assert len(clone._delta) == 2
    clone[(account(60_000), STREAM)] = body(1)
    assert (account(60_000), STREAM) not in registry
    assert len(registry) == 49_999 and len(clone) == 50_000


def test_the_manager_copy_goes_through_the_registry_hook():
    manager = RuleOfferLifecycleManager(accepted_clauses=make(10))
    clone = copy.deepcopy(manager)
    assert clone.accepted_clauses._base is manager.accepted_clauses._base
    clone.accepted_clauses[(account(50), STREAM)] = body(1)
    assert len(manager.accepted_clauses) == 10
    assert manager.clauses_root() != clone.clauses_root()


def test_assigning_a_plain_mapping_wraps_it():
    manager = RuleOfferLifecycleManager()
    manager.accepted_clauses = make(4)
    assert isinstance(manager.accepted_clauses, ClauseRegistry)
    assert manager.clauses_root() == compute_clause_registry_root(make(4))


# --- storage -----------------------------------------------------------------

def _save(registry, head="h", number=1):
    plan = registry.storage_plan()
    db.save_canonical_state_atomically(
        head, number, {}, {}, "", "", "", [], [], [], [], rule_clauses=plan)
    return plan


def _table():
    return {(r["acceptor_pubkey"], r["target_stream"]): r["clause_body"]
            for r in db.load_rule_clauses()}


class _Statements:
    def __init__(self):
        self.seen = []

    def __enter__(self):
        db._db_conn.set_trace_callback(self.seen.append)
        return self

    def __exit__(self, *exc):
        db._db_conn.set_trace_callback(None)

    def writes(self):
        return [s for s in self.seen if "rule_clauses_v1" in s
                and s.lstrip().upper().startswith(("INSERT", "DELETE"))]

    def full_rewrites(self):
        return [s for s in self.writes() if s.strip().endswith("FROM rule_clauses_v1")]


@pytest.fixture
def stored(temp_database):
    registry = ClauseRegistry(make(5000))
    _save(registry)
    return registry


def test_the_first_save_rewrites_the_table_and_pairs_the_registry(stored):
    assert _table() == dict(stored)
    assert stored._token == db.load_rule_clauses_token() is not None
    assert stored._changed == set()


def test_a_save_after_three_changes_writes_three_rows(stored):
    stored[(account(1), STREAM)] = body(10_001)
    stored[(account(2), STREAM)] = body(10_002)
    del stored[(account(3), STREAM)]
    stored[(account(9000), STREAM)] = body(5)
    stored[(account(9000), STREAM)] = body(6)
    with _Statements() as spy:
        _save(stored, number=2)
    assert len(spy.writes()) == 4
    assert spy.full_rewrites() == []
    assert _table() == dict(stored)
    assert stored._changed == set()


def test_a_removed_clause_row_is_deleted(stored):
    key = (account(7), STREAM)
    del stored[key]
    _save(stored, number=2)
    assert key not in _table() and len(_table()) == 4999


def test_reload_gives_an_equal_registry_and_root(stored):
    stored[(account(4), STREAM)] = body(31337)
    _save(stored, number=2)
    reloaded = ClauseRegistry(_table())
    reloaded.adopt_stored_token(db.load_rule_clauses_token())
    assert reloaded == stored and reloaded.root() == stored.root()
    reloaded[(account(5), STREAM)] = body(5000)
    with _Statements() as spy:
        _save(reloaded, number=3)
    assert len(spy.writes()) == 1 and spy.full_rewrites() == []
    assert _table() == dict(reloaded)


def test_a_divergent_copy_falls_back_to_the_full_rewrite(stored):
    sibling = copy.deepcopy(stored)
    stored[(account(1), STREAM)] = body(999)
    _save(stored, number=2)

    sibling[(account(2), STREAM)] = body(2)
    with _Statements() as spy:
        _save(sibling, number=3)
    assert len(spy.full_rewrites()) == 1
    assert _table() == dict(sibling)
    assert (account(1), STREAM) in _table() and _table()[(account(1), STREAM)] == body(1)


def test_a_registry_never_saved_before_takes_the_full_rewrite(temp_database):
    registry = ClauseRegistry(make(20))
    with _Statements() as spy:
        _save(registry)
    assert len(spy.full_rewrites()) == 1
    assert _table() == make(20)


def test_a_list_of_rows_rewrites_the_table(stored):
    rows = [{"acceptor_pubkey": account(1), "target_stream": 5, "clause_body": body(1)}]
    db.save_canonical_state_atomically(
        "h", 2, {}, {}, "", "", "", [], [], [], [], rule_clauses=rows)
    assert _table() == {(account(1), 5): body(1)}
    assert db.load_rule_clauses_token() is None
    stored[(account(2), STREAM)] = body(2)
    _save(stored, number=3)
    assert _table() == dict(stored)


def test_a_failed_save_leaves_token_and_changes_and_the_next_save_is_correct(stored):
    token = stored._token
    stored[(account(1), STREAM)] = body(11)
    del stored[(account(2), STREAM)]
    changed = set(stored._changed)
    plan = stored.storage_plan()
    with _Statements() as spy, pytest.raises(Exception):
        db.save_canonical_state_atomically(
            "h", 2, {}, {}, "", "", "", [], [], [], [],
            rule_clauses=plan, approval_requests=[{}])
    assert len(spy.writes()) == 2, "the clause rows were written before the failure"
    assert stored._token == token and stored._changed == changed
    assert db.load_rule_clauses_token() == token
    assert len(_table()) == 5000 and (account(2), STREAM) in _table()

    _save(stored, number=2)
    assert _table() == dict(stored)


def test_a_change_after_the_plan_keeps_the_registry_unconfirmed(stored):
    stored[(account(1), STREAM)] = body(11)
    plan = stored.storage_plan()
    stored[(account(2), STREAM)] = body(12)
    db.save_canonical_state_atomically(
        "h", 2, {}, {}, "", "", "", [], [], [], [], rule_clauses=plan)
    assert stored._token != db.load_rule_clauses_token()
    with _Statements() as spy:
        _save(stored, number=3)
    assert len(spy.full_rewrites()) == 1
    assert _table() == dict(stored)


def test_a_registry_with_too_many_unsaved_changes_stops_tracking(stored, monkeypatch):
    monkeypatch.setattr(ClauseRegistry, "CHANGED_CAP", 5)
    for i in range(6):
        stored[(account(i), STREAM)] = body(20_000 + i)
    assert stored._token is None and stored._changed == set()
    with _Statements() as spy:
        _save(stored, number=2)
    assert len(spy.full_rewrites()) == 1
    assert _table() == dict(stored)


# --- through the block-apply and proposal paths --------------------------------

@pytest.fixture
def apply_evaluator():
    sender_policy.set_evaluator("apply", MockPolicyEvaluator(pool="apply"))
    yield
    sender_policy.set_evaluator("apply", None)


RULE = "always ( (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
NEUTRAL = ap.NEUTRAL_RULE


def test_block_apply_shares_the_registry_base_with_its_parent(apply_evaluator):
    lm = ap._lm()
    lm.rule_offers.accepted_clauses = make(3000, offset=10)
    parent_base = lm.rule_offers.accepted_clauses._base

    _result, post, _calls = ap._apply([ap.rule_tx(RULE)], lm=lm)

    registry = post.rule_offers.accepted_clauses
    assert registry._base is parent_base
    assert registry[(ap.ALICE, STREAM)] == clause_body_v1(RULE)
    assert len(registry) == 3001 and len(lm.rule_offers.accepted_clauses) == 3000
    assert registry.root() == compute_clause_registry_root(dict(registry))


def test_the_meta_root_moves_on_registration_and_returns_on_revocation(apply_evaluator):
    lm = ap._lm()
    before = lm.consensus_meta_hash()

    _r, registered, _c = ap._apply([ap.rule_tx(RULE)], lm=lm)
    during = registered.consensus_meta_hash()
    assert during != before
    assert registered.rule_offers.clauses_root() != EMPTY_ROOT

    _r, revoked, _c = ap._apply([ap.rule_tx(NEUTRAL, seq=0)], lm=registered)
    assert revoked.rule_offers.clauses_root() == EMPTY_ROOT
    assert revoked.consensus_meta_hash() == before


def _proposal(lm):
    plan = tr.plan_representation(candidate_rules=[RULE])
    return tp.ProposalContext(
        session=None,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width, label="proposal"),
        plan=plan,
        lifecycle=lm,
    )


def test_a_transaction_copy_shares_the_base_and_a_rejection_leaves_no_trace(temp_database):
    lm = ap._lm()
    lm.rule_offers.accepted_clauses = make(3000)
    registry = lm.rule_offers.accepted_clauses
    _save(registry)
    base = registry._base
    proposal = _proposal(lm)

    rejected = proposal.transaction("rejected")
    branch_registry = rejected.lifecycle.rule_offers.accepted_clauses
    assert branch_registry._base is base
    branch_registry[(account(5000), STREAM)] = body(1)
    del branch_registry[(account(0), STREAM)]
    rejected.reject("no")
    assert proposal.lifecycle.rule_offers.accepted_clauses is registry
    assert registry == make(3000) and registry._changed == set()

    accepted = proposal.transaction("accepted")
    accepted.lifecycle.rule_offers.accepted_clauses[(account(6000), STREAM)] = body(2)
    accepted.accept()
    final = proposal.lifecycle.rule_offers.accepted_clauses
    assert (account(6000), STREAM) in final and (account(5000), STREAM) not in final
    assert final._base is base
    plan = final.storage_plan()
    assert [key for key, _ in plan.changes] == [(account(6000), STREAM)]

    with _Statements() as spy:
        _save(final, number=2)
    assert len(spy.writes()) == 1 and spy.full_rewrites() == []
    stored = _table()
    assert (account(6000), STREAM) in stored
    assert (account(5000), STREAM) not in stored and (account(0), STREAM) in stored


# --- the activation audit's corpus is built only when an audit runs -----------

class _Tripwire(ClauseRegistry):
    walks = 0

    def __iter__(self):
        type(self).walks += 1
        return super().__iter__()


def _lm_with_registry(registry_cls, items):
    lm = ap._lm(active=False)
    lm.rule_offers.accepted_clauses = registry_cls(items)
    return lm


def _schedule_activation(lm, height=ap.HEIGHT):
    from consensus.governance import ConsensusRuleUpdate

    update = ConsensusRuleUpdate(
        rule_revisions=[], activate_at_height=height,
        host_contract_patch={"approval_slots_active": True})
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates.append((height, update.update_id))


def test_a_block_with_no_activation_due_does_not_walk_the_registry(apply_evaluator):
    _Tripwire.walks = 0
    lm = _lm_with_registry(_Tripwire, make(500, offset=10))
    result, post, _calls = ap._apply([ap.rule_tx(RULE)], lm=lm)
    assert not result.invalid_tx_ids
    assert isinstance(post.rule_offers.accepted_clauses, _Tripwire)
    assert (ap.ALICE, STREAM) in post.rule_offers.accepted_clauses
    assert _Tripwire.walks == 0


COLLIDING_CLAUSE = (
    "((i18[t]:bv[24] = { #x01 }:bv[24]) -> (o5[t]:bv[24] = { #x000000 }:bv[24]))")


def test_an_activation_audit_reads_the_registered_clauses(apply_evaluator):
    _Tripwire.walks = 0
    clean = _lm_with_registry(_Tripwire, make(5, offset=10))
    _schedule_activation(clean)
    _r, post, _c = ap._apply([], lm=clean)
    assert post.approval_slots_active is True
    assert _Tripwire.walks >= 1

    colliding = _lm_with_registry(
        _Tripwire, {**make(5, offset=10), (account(99), STREAM): COLLIDING_CLAUSE})
    _schedule_activation(colliding)
    _r, post, _c = ap._apply([], lm=colliding)
    assert post.approval_slots_active is False


# --- consecutive blocks through the real commit functions ----------------------

def _commit_prepared(canonical, tip, parent):
    return db.commit_prepared_block(
        execution_id=f"exec-{tip}", tip=tip, parent=parent, journal_entries=[],
        expected_journal_seq=0, allocation_delta={},
        expected_epoch=db.shrink_mapping_epoch(), journal_head=None,
        allocator_digest="d", plan_id="p", canonical=canonical,
    )


def _commit_block_and_state(canonical, tip, parent):
    from block import Block

    block = Block.create(
        block_number=canonical["head_num"], previous_hash=parent, transactions=[],
        proposer_pubkey=ap.ALICE, timestamp=1234567890,
    )
    db.commit_block_and_canonical_state(block, canonical)


@pytest.mark.parametrize("commit", [_commit_prepared, _commit_block_and_state],
                         ids=["prepared", "block-and-state"])
def test_consecutive_blocks_write_only_their_changed_clause_rows(
        temp_database, isolated_chain_state, apply_evaluator, commit):
    import chain_state
    from types import SimpleNamespace

    seed = ap._lm()
    seed.rule_offers.accepted_clauses = make(3000, offset=10)
    chain_state._lifecycle_manager = seed

    def mine(tx, tip, parent, number):
        result, _post, _calls = ap._apply([tx], lm=chain_state._lifecycle_manager,
                                          height=number)
        assert not result.invalid_tx_ids
        snapshot = result.next_snapshot
        canonical = chain_state._canonical_state_kwargs(
            snapshot, head_hash=tip, head_num=number)
        with _Statements() as spy:
            commit(canonical, tip, parent)
        chain_state._swap_in_memory_state(snapshot, SimpleNamespace(block_hash=tip))
        return spy

    def check_in_sync():
        registry = chain_state._lifecycle_manager.rule_offers.accepted_clauses
        assert registry._token == db.load_rule_clauses_token() is not None
        assert registry._changed == set()
        reloaded = ClauseRegistry(_table())
        assert reloaded == registry and reloaded.root() == registry.root()

    mine(ap.rule_tx(RULE), "a" * 64, "0" * 64, 21)
    check_in_sync()

    second = mine(ap.rule_tx(RULE, sk=ap.SK_AUTH, sender=ap.AUTH), "b" * 64, "a" * 64, 22)
    assert second.full_rewrites() == []
    assert len(second.writes()) == 1
    check_in_sync()

    third = mine(ap.rule_tx(NEUTRAL), "c" * 64, "b" * 64, 23)
    assert third.full_rewrites() == []
    assert len(third.writes()) == 1
    check_in_sync()
    assert (ap.ALICE, STREAM) not in _table() and (ap.AUTH, STREAM) in _table()
