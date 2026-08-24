"""Rule-offer shape validation, composite emission, and lifecycle transitions.

The canonicalization and composition functions determine the exact text
appended to the application-rules state, which is hashed into the block state
hash. Byte-stability tests here are consensus tests, not cosmetics.
"""
import pytest

from consensus.rule_offers import (
    ALLOWED_TARGET_STREAMS,
    MAX_ACCEPTORS_PER_STREAM,
    MAX_OFFER_RULE_BYTES,
    MAX_OFFER_WINDOW_BLOCKS,
    MAX_PENDING_OFFERS_PER_OFFERER,
    MAX_PENDING_OFFERS_PER_RECIPIENT,
    STATUS_ACCEPTED,
    STATUS_EXPIRED,
    STATUS_REJECTED,
    RuleOffer,
    RuleOfferDecision,
    RuleOfferLifecycleManager,
    RuleOfferShapeError,
    canonicalize_clause_v1,
    clause_body_v1,
    clause_output_streams,
    compose_stream_rule,
    normalize_acceptor_pubkey,
    normalize_offer_rule_text,
    parse_rule_offer,
    parse_rule_offer_accept,
    parse_rule_offer_reject,
    validate_clause_target,
)

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
ALLOW_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
TARGET = 5


def _pk(byte):
    return (byte * 2) * 48


# --- canonicalization -------------------------------------------------------

def test_canonicalize_collapses_and_terminates():
    assert canonicalize_clause_v1("always (\n  o5[t] = 1\n)  .") == "always ( o5[t] = 1 ) ."


def test_canonicalize_is_stable_across_cosmetic_variants():
    """Whitespace, comments and directives must not change the hashed text."""
    variants = [
        BLOCK_RULE,
        "  always (   o5[t]:bv[24]   =   { #x000000 }:bv[24]   )  .  ",
        "# my policy\nalways ( o5[t]:bv[24] = { #x000000 }:bv[24] ).",
        "always ( o5[t]:bv[24] = { #x000000 }:bv[24] ). # trailing note",
        "#tau some directive\nalways ( o5[t]:bv[24] = { #x000000 }:bv[24] ).",
        "always (\n  o5[t]:bv[24] = { #x000000 }:bv[24]\n).",
    ]
    bodies = {clause_body_v1(v) for v in variants}
    assert len(bodies) == 1, bodies


def test_canonicalize_preserves_hex_literals():
    """'#x' is a bitvector literal, not a comment marker."""
    assert "#x000000" in canonicalize_clause_v1(BLOCK_RULE)


@pytest.mark.parametrize("text", ["", "   ", "\n\n", "# only a comment", None, 5])
def test_canonicalize_rejects_empty(text):
    with pytest.raises(RuleOfferShapeError):
        canonicalize_clause_v1(text)


# --- shape rejection --------------------------------------------------------

def test_two_units_are_rejected():
    """The greedy `.*` in the unit regex matches "a). always (b", which would
    smuggle a second, UNGUARDED unit into the composite."""
    with pytest.raises(RuleOfferShapeError, match="unbalanced|one rule unit"):
        clause_body_v1("always ( o5[t] = 1 ). always ( o1[t] = 2 ).")


@pytest.mark.parametrize("text,match", [
    ("o5[t] = 1.", "always"),
    ("sometimes ( o5[t] = 1 ).", "always"),
    ("always ( o5[t] = 1 ) ) .", "unbalanced"),
    ("always ( ( o5[t] = 1 .", "always"),
    ("always ( always ( o5[t] = 1 ) ).", "temporal"),
    ("always ( sometimes ( o5[t] = 1 ) ).", "temporal"),
    ("always (  ).", "empty"),
    ("always ( i12[t] = { #xaa }:bv[384] && o5[t] = 1 ).", "i12"),
])
def test_bad_shapes_rejected(text, match):
    with pytest.raises(RuleOfferShapeError, match=match):
        clause_body_v1(text)


def test_i12_in_a_comment_is_allowed():
    """The screen runs after comment stripping, so a mention in prose is fine."""
    assert clause_body_v1("# scoped to i12 by the node\n" + BLOCK_RULE)


# --- target stream ----------------------------------------------------------

def test_output_stream_extraction_is_word_exact():
    assert clause_output_streams("o5[t] = 1 && o51[t] = 2") == [5, 51]
    assert clause_output_streams("# o9[t] = 1\no5[t] = 2") == [5]


@pytest.mark.parametrize("body,match", [
    ("i1[t] = 1", "no output stream"),
    ("o5[t] = 1 && o12[t] = 2", "exactly one output stream"),
    ("o9[t] = 1", "reserved"),
    ("o7[t] = 1", "reserved"),
    ("o0[t] = 1", "reserved"),
    ("o12[t] = 1", "not an accepted target stream"),
])
def test_target_validation(body, match):
    with pytest.raises(RuleOfferShapeError, match=match):
        validate_clause_target(body)


def test_supported_target_accepted():
    body, target = normalize_offer_rule_text(BLOCK_RULE)
    assert target == TARGET
    assert body == "o5[t]:bv[24] = { #x000000 }:bv[24]"


# --- composite emitter ------------------------------------------------------

def test_empty_registry_emits_nothing():
    """No clauses must mean the stream is never mentioned. Mentioning it would
    materialize it for every sender with an arbitrary witness (observed 0,
    i.e. BLOCK) -- see tests/test_rule_scoping_native.py."""
    assert compose_stream_rule(TARGET, {}) is None


def test_composite_is_order_independent():
    body, _ = normalize_offer_rule_text(BLOCK_RULE)
    forward = compose_stream_rule(TARGET, {A: body, B: body})
    reverse = compose_stream_rule(TARGET, {B: body, A: body})
    assert forward == reverse


def test_composite_orders_by_key_bytes():
    body, _ = normalize_offer_rule_text(BLOCK_RULE)
    out = compose_stream_rule(TARGET, {C: body, A: body, B: body})
    assert out.index(A) < out.index(B) < out.index(C)


def test_composite_ends_in_the_neutral_value():
    """The innermost else-branch is what every uncovered sender gets. For o5
    that must be ALLOW, or accepting one user's rule blocks the network."""
    body, _ = normalize_offer_rule_text(BLOCK_RULE)
    out = compose_stream_rule(TARGET, {A: body})
    neutral = ALLOWED_TARGET_STREAMS[TARGET]["neutral"]
    assert out.rstrip().endswith(
        f"(o5[t]:bv[24] = {{ #x{neutral:06x} }}:bv[24])) )."
    ), out


def test_composite_is_a_single_always_unit():
    body, _ = normalize_offer_rule_text(BLOCK_RULE)
    out = compose_stream_rule(TARGET, {A: body, B: body, C: body})
    assert out.startswith("always ( ")
    assert out.endswith(" ).")
    assert out.count("always") == 1
    assert out.count("(") == out.count(")")


def test_composite_case_normalizes_pubkeys():
    body, _ = normalize_offer_rule_text(BLOCK_RULE)
    upper = compose_stream_rule(TARGET, {A.upper(): body})
    lower = compose_stream_rule(TARGET, {A: body})
    assert upper == lower


def test_composite_respects_the_acceptor_cap():
    body, _ = normalize_offer_rule_text(BLOCK_RULE)
    clauses = {format(i, "096x"): body for i in range(MAX_ACCEPTORS_PER_STREAM + 1)}
    with pytest.raises(RuleOfferShapeError, match="limit"):
        compose_stream_rule(TARGET, clauses)


def test_composite_rejects_unsupported_stream():
    with pytest.raises(RuleOfferShapeError):
        compose_stream_rule(12, {A: "o12[t] = 1"})


@pytest.mark.parametrize("bad", ["", "zz" * 48, "aa" * 47, 5, None])
def test_pubkey_normalization_rejects_junk(bad):
    with pytest.raises(RuleOfferShapeError):
        normalize_acceptor_pubkey(bad)


# --- parsers ----------------------------------------------------------------

def _offer_tx(**over):
    tx = {
        "tx_type": "rule_offer",
        "sender_pubkey": A,
        "recipient_pubkey": B,
        "rule_text": BLOCK_RULE,
        "expire_at_height": 500,
    }
    tx.update(over)
    return tx


def test_parse_offer_roundtrip():
    offer = parse_rule_offer(_offer_tx())
    assert offer is not None
    assert offer.offerer_pubkey == A and offer.recipient_pubkey == B
    assert offer.expire_at_height == 500
    assert len(offer.offer_id) == 32
    assert offer.offer_id_hex == offer.offer_id.hex()


def test_parse_offer_accepts_nested_payload():
    tx = {"tx_type": "rule_offer", "sender_pubkey": A, "payload": {
        "recipient_pubkey": B, "rule_text": BLOCK_RULE, "expire_at_height": 7}}
    offer = parse_rule_offer(tx)
    assert offer is not None and offer.expire_at_height == 7


def test_offer_id_depends_on_every_bound_field():
    base = parse_rule_offer(_offer_tx()).offer_id
    assert parse_rule_offer(_offer_tx(recipient_pubkey=C)).offer_id != base
    assert parse_rule_offer(_offer_tx(sender_pubkey=C)).offer_id != base
    assert parse_rule_offer(_offer_tx(expire_at_height=501)).offer_id != base
    assert parse_rule_offer(_offer_tx(rule_text=ALLOW_RULE)).offer_id != base
    # ...and NOT on transaction envelope fields.
    assert parse_rule_offer(_offer_tx(sequence_number=9, fee_limit="4")).offer_id == base


@pytest.mark.parametrize("over", [
    {"tx_type": "user_tx"},
    {"recipient_pubkey": None},
    {"recipient_pubkey": "short"},
    {"rule_text": 5},
    {"expire_at_height": "500"},
    {"expire_at_height": True},
    {"sender_pubkey": None},
])
def test_parse_offer_rejects_bad_payloads(over):
    assert parse_rule_offer(_offer_tx(**over)) is None


def test_parse_decisions():
    offer_id = parse_rule_offer(_offer_tx()).offer_id
    accept = parse_rule_offer_accept({
        "tx_type": "rule_offer_accept", "sender_pubkey": B,
        "offer_id": offer_id.hex(), "rule_text": BLOCK_RULE})
    assert accept is not None and accept.accept and accept.rule_text == BLOCK_RULE

    reject = parse_rule_offer_reject({
        "tx_type": "rule_offer_reject", "sender_pubkey": B,
        "offer_id": offer_id.hex()})
    assert reject is not None and not reject.accept and reject.rule_text is None

    # An accept without the text cannot be validated against the digest.
    assert parse_rule_offer_accept({
        "tx_type": "rule_offer_accept", "sender_pubkey": B,
        "offer_id": offer_id.hex()}) is None
    # Wrong id width.
    assert parse_rule_offer_reject({
        "tx_type": "rule_offer_reject", "sender_pubkey": B,
        "offer_id": "ab" * 8}) is None
    # Cross-type parsing never succeeds.
    assert parse_rule_offer_accept({
        "tx_type": "rule_offer_reject", "sender_pubkey": B,
        "offer_id": offer_id.hex()}) is None


# --- lifecycle --------------------------------------------------------------

@pytest.fixture
def mgr():
    return RuleOfferLifecycleManager()


def _offer(offerer=A, recipient=B, text=BLOCK_RULE, expire=500):
    return RuleOffer(offerer_pubkey=offerer, recipient_pubkey=recipient,
                     rule_text=text, expire_at_height=expire)


def test_offer_admission_and_submission(mgr):
    offer = _offer()
    ok, reason = mgr.can_admit_offer(offer, next_height=10)
    assert ok, reason
    assert mgr.submit_offer(offer)
    assert mgr.knows_offer(offer.offer_id)
    assert mgr.pending_count_for_recipient(B) == 1
    assert mgr.pending_count_for_offerer(A) == 1
    # Duplicates are refused at both layers.
    assert mgr.can_admit_offer(offer, next_height=10)[0] is False
    assert mgr.submit_offer(offer) is False


@pytest.mark.parametrize("offer,height,match", [
    (_offer(recipient=A), 10, "differ"),
    (_offer(expire=10), 10, "future"),
    (_offer(expire=5), 10, "future"),
    (_offer(expire=10 + MAX_OFFER_WINDOW_BLOCKS + 1), 10, "blocks ahead"),
    (_offer(text="always ( o9[t] = 1 )."), 10, "reserved"),
    (_offer(text="not a rule"), 10, "always"),
    (_offer(text="always ( o5[t] = 1 ). always ( o5[t] = 0 )."), 10, "unbalanced"),
])
def test_offer_admission_rejections(offer, height, match):
    mgr = RuleOfferLifecycleManager()
    ok, reason = mgr.can_admit_offer(offer, next_height=height)
    assert not ok
    assert match in reason, reason


def test_oversized_rule_text_rejected(mgr):
    big = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] && " + ("o5[t] = o5[t] && " * 900) + "o5[t] = o5[t] )."
    assert len(big.encode()) > MAX_OFFER_RULE_BYTES
    ok, reason = mgr.can_admit_offer(_offer(text=big), next_height=1)
    assert not ok and "bytes" in reason


def test_recipient_inbox_cap(mgr):
    for i in range(MAX_PENDING_OFFERS_PER_RECIPIENT):
        # Vary the offerer so the per-offerer cap is not what trips first.
        offerer = format(i + 1, "096x")
        assert mgr.submit_offer(_offer(offerer=offerer, expire=500 + i))
    ok, reason = mgr.can_admit_offer(
        _offer(offerer=format(999, "096x"), expire=9000), next_height=1)
    assert not ok and "recipient" in reason


def test_offerer_outbox_cap(mgr):
    for i in range(MAX_PENDING_OFFERS_PER_OFFERER):
        recipient = format(i + 1, "096x")
        assert mgr.submit_offer(_offer(recipient=recipient, expire=500 + i))
    ok, reason = mgr.can_admit_offer(
        _offer(recipient=format(999, "096x"), expire=9000), next_height=1)
    assert not ok and "offerer" in reason


def test_accept_registers_clause_and_composite(mgr):
    offer = _offer()
    mgr.submit_offer(offer)
    decision = RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=B,
                                 accept=True, rule_text=BLOCK_RULE)
    ok, reason = mgr.can_admit_decision(decision)
    assert ok, reason
    assert mgr.submit_decision(decision) == TARGET

    assert mgr.terminal_status[offer.offer_id] == STATUS_ACCEPTED
    assert offer.offer_id in mgr.resolved
    assert offer.offer_id not in mgr.offered
    body, _ = normalize_offer_rule_text(BLOCK_RULE)
    assert mgr.clause_for(B, TARGET) == body
    composite = mgr.composite_for_stream(TARGET)
    assert composite and B in composite


def test_reject_resolves_without_a_clause(mgr):
    offer = _offer()
    mgr.submit_offer(offer)
    decision = RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=B, accept=False)
    assert mgr.can_admit_decision(decision)[0]
    assert mgr.submit_decision(decision) is None
    assert mgr.terminal_status[offer.offer_id] == STATUS_REJECTED
    assert mgr.clause_for(B, TARGET) is None
    assert mgr.composite_for_stream(TARGET) is None


def test_only_the_recipient_may_decide(mgr):
    offer = _offer()
    mgr.submit_offer(offer)
    for actor in (A, C):
        ok, reason = mgr.can_admit_decision(
            RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=actor, accept=False))
        assert not ok and "recipient" in reason


def test_accept_text_must_match_the_digest(mgr):
    offer = _offer()
    mgr.submit_offer(offer)
    ok, reason = mgr.can_admit_decision(RuleOfferDecision(
        offer_id=offer.offer_id, actor_pubkey=B, accept=True, rule_text=ALLOW_RULE))
    assert not ok and "digest" in reason


def test_accept_tolerates_cosmetic_text_variation_only_if_digest_matches(mgr):
    """The digest is over the RAW offered text, so reformatting breaks it. This
    is deliberate: it keeps offer_id a function of exactly what was signed."""
    offer = _offer()
    mgr.submit_offer(offer)
    reformatted = "always (\n  o5[t]:bv[24] = { #x000000 }:bv[24]\n)."
    assert clause_body_v1(reformatted) == clause_body_v1(BLOCK_RULE)
    ok, _ = mgr.can_admit_decision(RuleOfferDecision(
        offer_id=offer.offer_id, actor_pubkey=B, accept=True, rule_text=reformatted))
    assert not ok


def test_decisions_on_unknown_and_resolved_offers(mgr):
    offer = _offer()
    unknown = RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=B, accept=False)
    ok, reason = mgr.can_admit_decision(unknown)
    assert not ok and "unknown" in reason

    mgr.submit_offer(offer)
    mgr.submit_decision(unknown)
    ok, reason = mgr.can_admit_decision(unknown)
    assert not ok and "already resolved" in reason
    # Replaying it is a no-op rather than a second resolution.
    assert mgr.submit_decision(unknown) is None


def test_accepting_a_second_offer_replaces_the_acceptor_clause(mgr):
    """One clause per (acceptor, stream). Accepting again replaces it -- this is
    the only way to change an accepted rule, since there is no retraction."""
    first = _offer(text=BLOCK_RULE, expire=500)
    second = _offer(text=ALLOW_RULE, expire=501)
    mgr.submit_offer(first)
    mgr.submit_offer(second)

    mgr.submit_decision(RuleOfferDecision(
        offer_id=first.offer_id, actor_pubkey=B, accept=True, rule_text=BLOCK_RULE))
    assert mgr.clause_for(B, TARGET) == clause_body_v1(BLOCK_RULE)

    mgr.submit_decision(RuleOfferDecision(
        offer_id=second.offer_id, actor_pubkey=B, accept=True, rule_text=ALLOW_RULE))
    assert mgr.clause_for(B, TARGET) == clause_body_v1(ALLOW_RULE)
    assert len(mgr.clauses_for_stream(TARGET)) == 1


def test_two_acceptors_both_keep_their_clauses(mgr):
    """The regression the composite design exists to prevent: a second
    acceptance must not disable the first acceptor's policy."""
    first = _offer(recipient=B, text=BLOCK_RULE, expire=500)
    second = _offer(recipient=C, text=BLOCK_RULE, expire=501)
    mgr.submit_offer(first)
    mgr.submit_offer(second)
    mgr.submit_decision(RuleOfferDecision(
        offer_id=first.offer_id, actor_pubkey=B, accept=True, rule_text=BLOCK_RULE))
    mgr.submit_decision(RuleOfferDecision(
        offer_id=second.offer_id, actor_pubkey=C, accept=True, rule_text=BLOCK_RULE))

    assert mgr.clause_for(B, TARGET) is not None
    assert mgr.clause_for(C, TARGET) is not None
    composite = mgr.composite_for_stream(TARGET)
    assert B in composite and C in composite


def test_expiry_resolves_only_closed_windows(mgr):
    early = _offer(recipient=B, expire=10)
    late = _offer(recipient=C, expire=20)
    mgr.submit_offer(early)
    mgr.submit_offer(late)

    assert mgr.expire_at_height(9) == []
    assert mgr.expire_at_height(10) == [early.offer_id]
    assert mgr.terminal_status[early.offer_id] == STATUS_EXPIRED
    assert early.offer_id in mgr.resolved
    assert late.offer_id in mgr.offered
    # Idempotent.
    assert mgr.expire_at_height(10) == []


def test_snapshots_cover_offered_and_resolved(mgr):
    offer = _offer()
    mgr.submit_offer(offer)
    rows = mgr.snapshot_offers()
    assert len(rows) == 1 and rows[0]["status"] == "offered"
    assert rows[0]["rule_text"] == BLOCK_RULE

    mgr.submit_decision(RuleOfferDecision(
        offer_id=offer.offer_id, actor_pubkey=B, accept=True, rule_text=BLOCK_RULE))
    rows = mgr.snapshot_offers()
    assert len(rows) == 1 and rows[0]["status"] == STATUS_ACCEPTED
    clauses = mgr.snapshot_clauses()
    assert clauses == [{"acceptor_pubkey": B, "target_stream": TARGET,
                        "clause_body": clause_body_v1(BLOCK_RULE)}]
