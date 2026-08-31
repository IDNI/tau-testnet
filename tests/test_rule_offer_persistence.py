"""Rule-offer state survives a restart with a byte-identical meta hash.

The offer book and clause registry are bound into `consensus_meta_hash`. If
either fails to round-trip through `commit_state_to_db` / `load_state_from_db`,
a restarted node computes a different state hash than a peer replaying from
genesis, and the first block it mines afterwards is rejected by everyone --
the mine-vs-replay divergence shape of the Phase 9B/9C bugs.

The last test is the counterpart: `rule_text` and `status` are node-local
durability for the RPC surface and must NOT affect the hash, exactly as
governance update payloads do not.
"""
import chain_state
from consensus.governance import ConsensusLifecycleManager, DEFAULT_MAX_RULE_TXS_PER_BLOCK
from consensus.rule_offers import (
    STATUS_ACCEPTED,
    STATUS_EXPIRED,
    STATUS_OFFERED,
    STATUS_REJECTED,
    RuleOffer,
    RuleOfferDecision,
    clause_body_v1,
)

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
TARGET = 5


def _seed_state(lm):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances["acct"] = 1
    chain_state._sequence_numbers["acct"] = 0
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    return lm


def _offer(offerer=A, recipient=B, text=BLOCK_RULE, expire=500):
    return RuleOffer(offerer_pubkey=offerer, recipient_pubkey=recipient,
                     rule_text=text, expire_at_height=expire)


def _reload():
    """Commit, clobber the manager as a restart would, then reload."""
    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


def test_outstanding_offer_round_trips(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    offer = _offer()
    lm.rule_offers.submit_offer(offer)
    before = lm.consensus_meta_hash()

    reloaded = _reload()

    entry = reloaded.rule_offers.get_offer(offer.offer_id)
    assert entry is not None, "outstanding offer was lost across restart"
    assert entry.offerer_pubkey == A
    assert entry.recipient_pubkey == B
    assert entry.expire_at_height == 500
    assert reloaded.consensus_meta_hash() == before
    # Node-local payload restored too, so the RPC surface can still show it.
    assert reloaded.rule_offers.offer_payloads[offer.offer_id] == BLOCK_RULE
    assert reloaded.rule_offers.terminal_status[offer.offer_id] == STATUS_OFFERED


def test_accepted_clause_round_trips(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    offer = _offer()
    lm.rule_offers.submit_offer(offer)
    lm.rule_offers.submit_decision(RuleOfferDecision(
        offer_id=offer.offer_id, actor_pubkey=B, accept=True, rule_text=BLOCK_RULE))
    before = lm.consensus_meta_hash()
    composite_before = lm.rule_offers.composite_for_stream(TARGET)

    reloaded = _reload()

    assert reloaded.rule_offers.clause_for(B, TARGET) == clause_body_v1(BLOCK_RULE)
    assert offer.offer_id in reloaded.rule_offers.resolved
    assert reloaded.consensus_meta_hash() == before
    # The emitted rule text must be identical, or the live spec diverges.
    assert reloaded.rule_offers.composite_for_stream(TARGET) == composite_before


def test_multiple_acceptors_round_trip(temp_database):
    """Each acceptor keeps its own clause across a restart."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    for recipient, expire in ((B, 500), (C, 501)):
        offer = _offer(recipient=recipient, expire=expire)
        lm.rule_offers.submit_offer(offer)
        lm.rule_offers.submit_decision(RuleOfferDecision(
            offer_id=offer.offer_id, actor_pubkey=recipient, accept=True,
            rule_text=BLOCK_RULE))
    before = lm.consensus_meta_hash()

    reloaded = _reload()

    assert reloaded.rule_offers.clause_for(B, TARGET) is not None
    assert reloaded.rule_offers.clause_for(C, TARGET) is not None
    assert reloaded.consensus_meta_hash() == before


def test_rejected_and_expired_round_trip(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    rejected = _offer(recipient=B, expire=500)
    expiring = _offer(recipient=C, expire=30)
    lm.rule_offers.submit_offer(rejected)
    lm.rule_offers.submit_offer(expiring)
    lm.rule_offers.submit_decision(RuleOfferDecision(
        offer_id=rejected.offer_id, actor_pubkey=B, accept=False))
    lm.rule_offers.expire_at_height(30)
    before = lm.consensus_meta_hash()

    reloaded = _reload()

    assert reloaded.rule_offers.resolved == {rejected.offer_id, expiring.offer_id}
    assert not reloaded.rule_offers.offered
    assert reloaded.rule_offers.terminal_status[rejected.offer_id] == STATUS_REJECTED
    assert reloaded.rule_offers.terminal_status[expiring.offer_id] == STATUS_EXPIRED
    assert reloaded.consensus_meta_hash() == before
    # Never prunes back to empty -- that would revert to the legacy preimage.
    assert not reloaded.rule_offers.is_empty()


def test_empty_book_round_trips_as_empty(temp_database):
    """A chain with no rule sharing must reload with an empty book, so its
    meta hash stays on the pre-feature preimage."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    assert lm.rule_offers.is_empty()
    before = lm.consensus_meta_hash()

    reloaded = _reload()

    assert reloaded.rule_offers.is_empty()
    assert reloaded.consensus_meta_hash() == before


def test_block_budget_round_trips(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    lm.max_rule_txs_per_block = 3
    before = lm.consensus_meta_hash()

    reloaded = _reload()

    assert reloaded.max_rule_txs_per_block == 3
    assert reloaded.consensus_meta_hash() == before


def test_default_block_budget_round_trips(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.max_rule_txs_per_block == DEFAULT_MAX_RULE_TXS_PER_BLOCK
    assert reloaded.consensus_meta_hash() == before


def test_lost_rule_text_does_not_change_the_meta_hash(temp_database):
    """`rule_text` is node-local. A reload that loses it must still hash the
    same, which is what makes acceptance validate from hashed state alone."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    offer = _offer()
    lm.rule_offers.submit_offer(offer)
    expected = lm.consensus_meta_hash()

    chain_state.commit_state_to_db("head-hash", 20)

    # Simulate a node that has the consensus-bound row but not the payload.
    import db as db_module
    with db_module.get_db_connection() as conn:
        conn.execute("UPDATE rule_offers_v1 SET rule_text = ''")

    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager

    assert reloaded.rule_offers.get_offer(offer.offer_id) is not None
    assert reloaded.rule_offers.offer_payloads.get(offer.offer_id) is None
    assert reloaded.consensus_meta_hash() == expected


def test_malformed_offer_rows_are_skipped(temp_database):
    """A corrupt row must not take the node down on startup."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    offer = _offer()
    lm.rule_offers.submit_offer(offer)
    chain_state.commit_state_to_db("head-hash", 20)

    import db as db_module
    with db_module.get_db_connection() as conn:
        conn.execute(
            "INSERT INTO rule_offers_v1 (offer_id, offerer_pubkey, recipient_pubkey, "
            "rule_text, expire_at_height, status) VALUES (?, ?, ?, ?, ?, ?)",
            ("not-hex", A, B, "x", 1, STATUS_OFFERED))
        conn.execute(
            "INSERT INTO rule_offers_v1 (offer_id, offerer_pubkey, recipient_pubkey, "
            "rule_text, expire_at_height, status) VALUES (?, ?, ?, ?, ?, ?)",
            ("ab" * 8, A, B, "x", 1, STATUS_OFFERED))

    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager

    assert list(reloaded.rule_offers.offered) == [offer.offer_id]


def test_every_commit_site_persists_rule_offers():
    """Static audit: each `save_canonical_state_atomically` call in chain_state
    must pass the rule-sharing arguments.

    There are three commit paths (block apply, commit_state_to_db, reorg
    rebuild). A path that omits them leaves the offer/clause tables holding an
    older block's rows, so a restart rehydrates a stale book and computes a
    state hash no peer agrees with. This is a source audit rather than a
    behavioural test because the failure only shows up after a restart on one
    specific path, which is exactly how the Phase 9B/9C bugs escaped.
    """
    import ast
    import inspect

    source = inspect.getsource(chain_state)
    tree = ast.parse(source)

    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "save_canonical_state_atomically":
            calls.append(node)

    assert len(calls) == 3, (
        f"expected 3 commit sites in chain_state, found {len(calls)}; a new one "
        "must also pass every hash-bound snapshot argument"
    )
    required = {
        "rule_offers", "rule_clauses", "max_rule_txs_per_block",
        # Co-signature approvals: the request book root (including which
        # approvers have voted) is bound into consensus_meta_hash, so a path
        # that omits it rehydrates a stale book after a restart.
        "approval_requests", "approval_slots_active",
    }
    for call in calls:
        kwargs = {kw.arg for kw in call.keywords}
        missing = required - kwargs
        assert not missing, (
            f"chain_state.py:{call.lineno} omits {sorted(missing)} when persisting "
            "canonical state; a restart would rehydrate a stale rule-offer book"
        )


def test_composites_are_derived_not_accumulated(temp_database):
    """The application-rules accumulation must NOT grow with acceptances.

    `save_effective_tau_spec` only dedups EXACT units, so appending each
    regenerated composite left every earlier one in place: the stream ended up
    with several composites whose net effect depended on replay order, and the
    spec grew with every accept -- straight into the interpreter-rebuild cost.
    A real-node run showed three composites for o5 after three acceptances.

    The clause registry is the consensus-bound source of truth, so the composite
    is rebuilt from it by the restore plan instead.
    """
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    chain_state._application_rules_state = "always ( o1[t]:bv[24] = i1[t]:bv[24] )."
    baseline_units = len(chain_state._application_rules_state.split("\n"))

    for recipient, expire in ((B, 500), (C, 501)):
        offer = _offer(recipient=recipient, expire=expire)
        lm.rule_offers.submit_offer(offer)
        lm.rule_offers.submit_decision(RuleOfferDecision(
            offer_id=offer.offer_id, actor_pubkey=recipient, accept=True,
            rule_text=BLOCK_RULE))

    # Two acceptances, and the accumulation is untouched.
    assert len(chain_state._application_rules_state.split("\n")) == baseline_units
    assert "i12" not in chain_state._application_rules_state

    # The restore plan supplies exactly ONE composite for the stream, carrying
    # both acceptors.
    plan = chain_state.get_tau_restore_plan()
    composites = [e for e in plan if str(e["label"]).startswith("rule_composite_")]
    assert len(composites) == 1, [e["label"] for e in plan]
    assert composites[0]["label"] == f"rule_composite_o{TARGET}"
    assert B in composites[0]["text"] and C in composites[0]["text"]
    assert composites[0]["text"].count("always") == 1


def test_no_composite_entry_when_nothing_is_accepted(temp_database):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    plan = chain_state.get_tau_restore_plan()
    assert not [e for e in plan if str(e["label"]).startswith("rule_composite_")]


def test_derived_composite_survives_a_reload(temp_database):
    """After a restart the composite must be rebuilt identically from the
    persisted registry, since it is no longer stored as text anywhere."""
    lm = _seed_state(ConsensusLifecycleManager(active_validators=[A]))
    offer = _offer()
    lm.rule_offers.submit_offer(offer)
    lm.rule_offers.submit_decision(RuleOfferDecision(
        offer_id=offer.offer_id, actor_pubkey=B, accept=True, rule_text=BLOCK_RULE))
    before = [e["text"] for e in chain_state.get_tau_restore_plan()
              if str(e["label"]).startswith("rule_composite_")]

    reloaded = _reload()
    after = [e["text"] for e in chain_state.get_tau_restore_plan()
             if str(e["label"]).startswith("rule_composite_")]

    assert before and after == before
    assert reloaded.rule_offers.clause_for(B, TARGET) is not None
