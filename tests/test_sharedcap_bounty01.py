"""Bounty 01, FIX 8: shared caps for payout rules — the mock-level suite.

The native counterpart (tests/test_sharedcap_native.py) proves the same
cases against real Tau clauses; this file proves the bookkeeping at
book, parse/signing, admission and request-path level with the mock
policy evaluator.

The gap (differential audit vs #178 @ 0df68c2): clHODL's rules can draw
on ONE shared limit via shared_cap_id + shared_cap_amount. FIX 7's book
gave every rule its own caps only, with no borrowing across rules. FIX 8
closes the gap: a rule may name a shared cap — both fields signed and
inside the rule id — and every rule of the same owner naming the same id
draws on that one amount per period, on top of its own caps. Usage is
counted from current book membership and current period totals only, so
a rule leaving the book frees its room, and the FIX 5C replacement
carry keeps a superseding member's usage inside the group.
"""
import itertools

import pytest

import tau_defs
from bls_keys import FAR_FUTURE, SK_ALICE, sign_tx
from consensus import sender_policy
from consensus.admission import (
    validate_execute_payout_rule_payload,
    validate_install_payout_rule_payload,
)
from consensus.facade import TipAdmissionView
from consensus.approvals import STATUS_EXECUTED, STATUS_OPEN, payout_payload_text
from consensus.payout_rules import (
    FORM_TAU_RULE,
    LEG_FIXED,
    PayoutRuleBook,
    PayoutRuleEntry,
    PayoutLeg,
    parse_install_payout_rule,
    payout_rule_capabilities,
    validate_payout_rule_shape,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.tx_signing import signing_message_bytes

from test_rule_change_release import Chain
from test_rule_change_requests import (
    ALICE,
    BOB,
    GUARD_BODY,
    _lm,
    _request,
    _tx,
)
from test_rule_change_payout_standing_bounty01 import (
    _LmView,
    _payout_entry,
    _vote,
)

OWNER = ALICE
OTHER = "d" * 96
ARTIST = "b" * 96
WORKER = "c" * 96

ANCHOR = 1_700_000_000
WEEK = 604_800
TS = ANCHOR + 1000

GROUP = "royalty-pool"
GROUP_AMOUNT = 250

_IDS = itertools.count()

KIND_SET_PAYOUT = tau_defs.RULE_CHANGE_KIND_SET_PAYOUT
KIND_REVOKE_PAYOUT = tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT


@pytest.fixture(autouse=True)
def evaluators():
    """The seeded guard allows a change only once slot i18 holds a pubkey
    (the FIX 5B harness fixture, restated so this file is self-contained)."""
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        evs[pool].set_verdict(
            GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _sid(n):
    return bytes([n]) * 32


def rule(index=0, *, owner=OWNER, amount=100, version=1, max_period=0,
         max_exec=0, recipient=ARTIST, shared=None,
         shared_amount=GROUP_AMOUNT, anchor=ANCHOR):
    return PayoutRuleEntry(
        owner_pubkey=owner,
        recipients=(recipient,),
        legs=(PayoutLeg(recipient, LEG_FIXED, amount),),
        max_per_execution=max_exec,
        max_per_period=max_period,
        period_seconds=WEEK,
        period_anchor_ts=anchor,
        version=version,
        rule_index=index,
        shared_cap_id=shared or "",
        shared_cap_amount=shared_amount if shared else 0,
    )


def group_book():
    """Two rules of one owner sharing one cap of 250; a third rule of the
    same owner outside the group; all in their first period at TS."""
    book = PayoutRuleBook()
    a = rule(0, amount=100, shared=GROUP)
    b = rule(1, amount=150, shared=GROUP, recipient=WORKER)
    solo = rule(2, amount=100)
    for entry in (a, b, solo):
        book.install(entry, TS)
    return book, a, b, solo


# --- Parsing, shape, identity ------------------------------------------------------


def test_parse_reads_the_shared_terms_and_defaults_to_none():
    base = {
        "sender_pubkey": OWNER,
        "payout_recipients": [ARTIST],
        "payout_legs": [[ARTIST, LEG_FIXED, 100]],
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": ANCHOR,
    }
    plain = parse_install_payout_rule(base)
    assert plain.shared_cap_id == "" and plain.shared_cap_amount == 0
    named = parse_install_payout_rule({
        **base,
        "payout_shared_cap_id": GROUP,
        "payout_shared_cap_amount": GROUP_AMOUNT,
    })
    assert named.shared_cap_id == GROUP
    assert named.shared_cap_amount == GROUP_AMOUNT


def test_shape_refuses_malformed_shared_terms():
    # An amount with no id names no cap.
    orphan = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, LEG_FIXED, 100),),
        max_per_execution=0, max_per_period=0, period_seconds=WEEK,
        period_anchor_ts=ANCHOR, version=1,
        shared_cap_id="", shared_cap_amount=100)
    assert validate_payout_rule_shape(orphan, TS) is not None
    bad = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, LEG_FIXED, 100),),
        max_per_execution=0, max_per_period=0, period_seconds=WEEK,
        period_anchor_ts=ANCHOR, version=1,
        shared_cap_id=GROUP, shared_cap_amount=0)
    assert validate_payout_rule_shape(bad, TS) is not None
    # Charset and length are pinned.
    for bad_id in ("Has Upper", "has space", "x" * 33, "dot.name"):
        entry = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(ARTIST,),
            legs=(PayoutLeg(ARTIST, LEG_FIXED, 100),),
            max_per_execution=0, max_per_period=0, period_seconds=WEEK,
            period_anchor_ts=ANCHOR, version=1,
            shared_cap_id=bad_id, shared_cap_amount=100)
        assert validate_payout_rule_shape(entry, TS) is not None, bad_id
    # A well-formed naming is fine.
    assert validate_payout_rule_shape(rule(0, shared=GROUP), TS) is None


def test_the_shared_terms_are_inside_the_rule_id():
    plain = rule(0)
    named = rule(0, shared=GROUP)
    other_amount = rule(0, shared=GROUP, shared_amount=GROUP_AMOUNT + 1)
    other_group = rule(0, shared="other-pool")
    ids = {plain.rule_id, named.rule_id, other_amount.rule_id,
           other_group.rule_id}
    assert len(ids) == 4
    # The Tau form binds them the same way, under its own domain.
    tau_plain = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,), legs=(),
        max_per_execution=0, max_per_period=0, period_seconds=WEEK,
        period_anchor_ts=ANCHOR, version=1, form=FORM_TAU_RULE,
        clause_text="(o30[t]:bv[64] = { 1 }:bv[64])")
    tau_named = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,), legs=(),
        max_per_execution=0, max_per_period=0, period_seconds=WEEK,
        period_anchor_ts=ANCHOR, version=1, form=FORM_TAU_RULE,
        clause_text="(o30[t]:bv[64] = { 1 }:bv[64])",
        shared_cap_id=GROUP, shared_cap_amount=GROUP_AMOUNT)
    assert tau_plain.rule_id != tau_named.rule_id
    assert tau_named.rule_id != named.rule_id  # different domains


def test_the_shared_terms_are_inside_the_install_and_remove_signatures():
    common = {
        "sender_pubkey": OWNER, "sequence_number": 0,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100",
    }
    install = {
        **common, "tx_type": "install_payout_rule",
        "payout_recipients": [ARTIST],
        "payout_legs": [[ARTIST, LEG_FIXED, 100]],
        "payout_period_seconds": WEEK, "payout_period_anchor_ts": ANCHOR,
        "payout_version": 1,
        "payout_shared_cap_id": GROUP,
        "payout_shared_cap_amount": GROUP_AMOUNT,
    }
    # Rewriting the group or the amount under the owner's signature
    # changes the signed message: the signature no longer covers it.
    assert signing_message_bytes(install) != signing_message_bytes(
        {**install, "payout_shared_cap_id": "other-pool"})
    assert signing_message_bytes(install) != signing_message_bytes(
        {**install, "payout_shared_cap_amount": GROUP_AMOUNT + 1})
    assert signing_message_bytes(install) != signing_message_bytes(
        {k: v for k, v in install.items()
         if k not in ("payout_shared_cap_id", "payout_shared_cap_amount")})
    remove = {
        **common, "tx_type": "remove_payout_rule",
        "payout_shared_cap_id": GROUP,
        "payout_shared_cap_amount": GROUP_AMOUNT,
    }
    assert signing_message_bytes(remove) != signing_message_bytes(
        {**remove, "payout_shared_cap_id": "other-pool"})
    assert signing_message_bytes(remove) != signing_message_bytes(
        {**remove, "payout_shared_cap_amount": 1})


# --- The group ceiling ---------------------------------------------------------------


def test_two_rules_share_one_cap_and_stop_exactly_at_it():
    book, a, b, solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed  # 100
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed  # 150
    # The group has now paid exactly its shared amount of 250.
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250
    assert book.shared_cap_left(a, TS) == 0
    # Any further draw by EITHER member is refused by the shared cap...
    for entry in (a, b):
        decision = book.execute(entry.rule_id, _sid(3), 1, TS, 10_000)
        assert not decision.executed
        assert "shared cap" in decision.reason
    # ...while the owner's rule outside the group is untouched by it.
    assert book.execute(solo.rule_id, _sid(4), 1, TS, 10_000).executed
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250


def test_the_per_slot_cap_binds_first_when_it_is_smaller():
    book = PayoutRuleBook()
    a = rule(0, amount=100, max_period=100, shared=GROUP)
    b = rule(1, amount=150, shared=GROUP, recipient=WORKER)
    book.install(a, TS)
    book.install(b, TS)
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed
    # A is at its OWN per-period cap of 100: refused by that cap, with
    # group room (150 of 250) still standing.
    decision = book.execute(a.rule_id, _sid(2), 1, TS, 10_000)
    assert not decision.executed
    assert "shared cap" not in decision.reason
    assert "max per period" in decision.reason
    # B can still draw the group's remaining 150, exactly.
    assert book.execute(b.rule_id, _sid(3), 1, TS, 10_000).executed
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250


def test_a_refused_execution_settles_nothing_and_leaves_no_debt():
    book, a, b, _solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed  # 100
    # B's 150 fits; a second B execution of 150 would take the group to
    # 400 > 250 and is refused whole.
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed  # 150
    refused = book.execute(b.rule_id, _sid(3), 1, TS, 10_000)
    assert not refused.executed and refused.total == 0 and refused.legs == ()
    # Nothing was recorded: no settlement, no period movement, no debt.
    assert not book.is_settled(b.rule_id, _sid(3))
    assert book.period_total(b.rule_id, 0) == 150
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250
    # The same settlement id is still usable by a fitting execution in a
    # later period — the refusal was not a completion in disguise.
    later = TS + WEEK
    retried = book.execute(b.rule_id, _sid(3), 1, later, 10_000)
    assert retried.executed and retried.total == 150


def test_a_new_period_restores_the_group_room():
    book, a, b, _solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed
    assert book.shared_cap_left(a, TS) == 0
    later = TS + WEEK  # both rules roll into their second period
    assert book.shared_cap_usage(OWNER, GROUP, later) == 0
    assert book.execute(a.rule_id, _sid(3), 1, later, 10_000).executed
    assert book.execute(b.rule_id, _sid(4), 1, later, 10_000).executed
    assert book.shared_cap_usage(OWNER, GROUP, later) == 250


# --- Membership: room frees, groups never cross owners -------------------------------


def test_room_frees_when_a_member_leaves_the_book():
    book, a, b, _solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed  # 100
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed  # 150
    assert book.shared_cap_left(a, TS) == 0
    # Revoking B takes its 150 out of the group's usage at once.
    book.remove(OWNER, TS, 1)
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 100
    assert book.shared_cap_left(a, TS) == 150
    # A alone may now draw right up to the shared amount.
    assert book.execute(a.rule_id, _sid(3), 1, TS, 10_000).executed  # +100
    decision = book.execute(a.rule_id, _sid(4), 1, TS, 10_000)
    assert not decision.executed and "shared cap" in decision.reason


def test_superseding_out_of_the_group_frees_its_usage():
    book, a, b, _solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250
    # B is replaced by a version that names NO shared cap: its carried
    # period total (150, FIX 5C) now stands outside the group.
    b2 = rule(1, amount=150, version=2, recipient=WORKER)
    book.install(b2, TS)
    assert book.period_total(b2.rule_id, 0) == 150  # the carry itself
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 100
    assert book.shared_cap_left(a, TS) == 150


def test_superseding_inside_the_group_keeps_the_usage_counted():
    book, a, b, _solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed
    # B's replacement stays in the group: the FIX 5C carry moves B's 150
    # into the new version's first period, still inside the group — a
    # replacement cannot launder usage out of the shared cap.
    b2 = rule(1, amount=150, version=2, shared=GROUP, recipient=WORKER)
    book.install(b2, TS)
    assert book.period_total(b2.rule_id, 0) == 150
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250
    assert book.shared_cap_left(a, TS) == 0
    decision = book.execute(b2.rule_id, _sid(3), 1, TS, 10_000)
    assert not decision.executed and "shared cap" in decision.reason


def test_groups_never_cross_owners():
    book = PayoutRuleBook()
    mine = rule(0, amount=100, shared=GROUP)
    theirs = rule(0, owner=OTHER, amount=200, shared=GROUP,
                  recipient=WORKER)
    book.install(mine, TS)
    book.install(theirs, TS)
    assert book.execute(mine.rule_id, _sid(1), 1, TS, 10_000).executed
    assert book.execute(theirs.rule_id, _sid(2), 1, TS, 10_000).executed
    # Same id, different owners: two independent groups of 250 each.
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 100
    assert book.shared_cap_usage(OTHER, GROUP, TS) == 200
    # The other owner's 200 does not eat into my remaining 150.
    assert book.shared_cap_left(mine, TS) == 150
    assert book.execute(mine.rule_id, _sid(3), 1, TS, 10_000).executed
    assert book.shared_cap_left(mine, TS) == 50


# --- Signed updates and the FIX 5C carry ----------------------------------------------


def test_a_signed_mid_period_amount_update_respects_the_draws():
    book, a, b, _solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed  # 100
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed  # 150
    # The owner signs a mid-period update of A lowering the shared amount
    # to 220: the 250 already drawn stands OVER the new amount — nothing
    # is clawed back, and the room is simply gone (left = max(0, ...)).
    a2 = rule(0, amount=100, version=2, shared=GROUP, shared_amount=220)
    book.install(a2, TS)
    assert book.shared_cap_left(a2, TS) == 0
    decision = book.execute(a2.rule_id, _sid(3), 1, TS, 10_000)
    assert not decision.executed and "shared cap" in decision.reason
    # Raising it again (another signed update) frees exactly the
    # difference: at 300 the group has 50 of room, no more.
    a3 = rule(0, amount=100, version=3, shared=GROUP, shared_amount=300)
    book.install(a3, TS)
    assert book.shared_cap_left(a3, TS) == 50
    small = rule(0, amount=50, version=4, shared=GROUP, shared_amount=300)
    book.install(small, TS)
    assert book.execute(small.rule_id, _sid(4), 1, TS, 10_000).executed
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 300


def test_the_fix5c_carry_and_the_shared_cap_compose():
    # One rule alone in its group, replaced mid-period: the carry moves
    # its spend into the replacement, and the shared cap charges it.
    book = PayoutRuleBook()
    a = rule(0, amount=200, shared=GROUP)
    book.install(a, TS)
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed  # 200
    a2 = rule(0, amount=200, version=2, shared=GROUP)
    book.install(a2, TS)
    assert book.period_total(a2.rule_id, 0) == 200  # FIX 5C carry
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 200
    # Only 50 of group room remains although the new version's own
    # per-period cap is uncapped and its own total started at the carry.
    decision = book.execute(a2.rule_id, _sid(2), 1, TS, 10_000)
    assert not decision.executed and "shared cap" in decision.reason
    assert book.period_total(a2.rule_id, 0) == 200


# --- Restore ---------------------------------------------------------------------------


def test_restore_round_trips_the_shared_terms():
    book, a, b, solo = group_book()
    assert book.execute(a.rule_id, _sid(1), 1, TS, 10_000).executed
    assert book.execute(b.rule_id, _sid(2), 1, TS, 10_000).executed
    clone = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert clone.root() == book.root()
    assert clone.get(OWNER, 0).shared_cap_id == GROUP
    assert clone.get(OWNER, 0).shared_cap_amount == GROUP_AMOUNT
    assert clone.get(OWNER, 2).shared_cap_id == ""
    assert clone.shared_cap_usage(OWNER, GROUP, TS) == 250
    assert clone.shared_cap_left(clone.get(OWNER, 0), TS) == 0


def test_restore_refuses_a_row_whose_shared_terms_were_rewritten():
    book, a, _b, _solo = group_book()
    rows = book.rows()
    forged = [list(r) for r in rows]
    # Rewriting the stored shared amount (or id) breaks the row's id:
    # the terms are inside it, so the forgery does not recompute.
    forged[0][14] = GROUP_AMOUNT * 4
    with pytest.raises(ValueError):
        PayoutRuleBook.restore([tuple(r) for r in forged],
                               book.settlement_rows())
    forged = [list(r) for r in rows]
    forged[0][13] = "other-pool"
    with pytest.raises(ValueError):
        PayoutRuleBook.restore([tuple(r) for r in forged],
                               book.settlement_rows())


def test_a_pre_fix8_row_restores_with_no_shared_cap():
    book = PayoutRuleBook()
    plain = rule(0)
    book.install(plain, TS)
    legacy_row = book.rows()[0][:13]  # no shared-cap terms, as pre-FIX8
    clone = PayoutRuleBook.restore([legacy_row], [])
    restored = clone.get(OWNER, 0)
    assert restored.rule_id == plain.rule_id
    assert restored.shared_cap_id == "" and restored.shared_cap_amount == 0
    # But truncating a row whose rule DOES name a shared cap refuses:
    # its stored id was computed with the terms inside.
    book2, _a, _b, _solo = group_book()
    shared_row = next(r for r in book2.rows() if r[13] == GROUP)
    with pytest.raises(ValueError):
        PayoutRuleBook.restore([shared_row[:13]], [])


def test_capabilities_report_the_shared_cap():
    caps = payout_rule_capabilities()
    assert "shared_cap" in caps
    assert "payout_shared_cap_id" in caps["shared_cap"]


# --- Admission sees the whole group ------------------------------------------------------


class _BookView(TipAdmissionView):
    """The real facade view over an injected book, at this file's TS.

    (test_payout_rules_engine_bounty01's _TipView is the same shape at
    that file's own timestamp; the facade answers — rows, views,
    balances — are the production ones either way.)
    """

    def __init__(self, book, balances):
        self._book = book
        self._balances = balances

    @property
    def next_block_timestamp(self):
        return TS

    def _tip_payout_book(self):
        return self._book

    def clause_for(self, acceptor_pubkey, target_stream):
        return None

    def get_balance(self, pubkey):
        return self._balances.get(pubkey, 0)


def _execute_tx(rule_id, settlement_id, base=1):
    return {
        "tx_type": "execute_payout_rule",
        "sender_pubkey": WORKER,
        "payout_rule_id": rule_id.hex(),
        "payout_settlement_id": settlement_id.hex(),
        "payout_base_amount": base,
    }


def test_admission_judges_an_execution_against_the_whole_group():
    book, a, b, _solo = group_book()
    view = _BookView(book, {OWNER: 100_000})
    # A draws 100 at the tip's book state: admitted.
    due = validate_execute_payout_rule_payload(
        _execute_tx(a.rule_id, _sid(1)), view)
    assert due.is_valid, due.error
    book.execute(a.rule_id, _sid(1), 1, TS, 100_000)
    book.execute(b.rule_id, _sid(2), 1, TS, 100_000)
    # The group is full (250): admission now refuses a further execution
    # of EITHER member — it rebuilds the owner's whole book, not the
    # target's row alone, so it cannot miss the other member's draws.
    for entry in (a, b):
        refused = validate_execute_payout_rule_payload(
            _execute_tx(entry.rule_id, _sid(3)), view)
        assert not refused.is_valid
        assert "shared cap" in (refused.error or "")


# --- The guard request path ----------------------------------------------------------------


def _install_tx(seq, **over):
    from test_rule_change_payout_standing_bounty01 import _payout_fields

    fields = _payout_fields(**over)
    fields.pop("sender_pubkey")
    return sign_tx({
        "tx_id": f"sharedcap-{next(_IDS)}", "tx_type": "install_payout_rule",
        "sender_pubkey": ALICE, "sequence_number": seq,
        "expiration_time": FAR_FUTURE, "expire_at_height": 5000,
        "fee_limit": "100", **fields,
    }, SK_ALICE)


def test_a_direct_install_carries_the_shared_terms():
    chain = Chain(_lm())
    tx = _install_tx(0, payout_shared_cap_id=GROUP,
                     payout_shared_cap_amount=GROUP_AMOUNT)
    result = validate_install_payout_rule_payload(tx, _LmView(chain.lm))
    assert result.is_valid, result.error
    chain.block(tx)
    entry = chain.lm.payout_rules.get(ALICE, 0)
    assert entry is not None
    assert entry.shared_cap_id == GROUP
    assert entry.shared_cap_amount == GROUP_AMOUNT


def test_kind7_body_binds_the_shared_cap_and_kind9_frees_the_room():
    chain = Chain(_lm(guard=True))
    entries = []
    for slot in (0, 1):
        entry = _payout_entry(
            payout_rule_index=slot,
            payout_shared_cap_id=GROUP,
            payout_shared_cap_amount=GROUP_AMOUNT,
            payout_legs=[[BOB, 2, 10000]],  # 100% of base
        )
        entries.append(entry)
        req = _request(KIND_SET_PAYOUT, text=payout_payload_text(entry),
                       seq=slot, expire=3000)
        chain.block(_tx(req))
        assert chain.entry(req).status == STATUS_OPEN
        chain.block(_vote(req.request_id, seq=slot))
        assert chain.entry(req).status == STATUS_EXECUTED
    book = chain.lm.payout_rules
    # The canonical body carried the shared terms into the installed rule.
    assert book.get(ALICE, 0).shared_cap_id == GROUP
    assert book.get(ALICE, 1).shared_cap_amount == GROUP_AMOUNT
    # Fill the group at book level: 100 + 150 against the cap of 250.
    assert book.execute(entries[0].rule_id, _sid(1), 100, TS, 10_000).executed
    assert book.execute(entries[1].rule_id, _sid(2), 150, TS, 10_000).executed
    assert book.shared_cap_usage(ALICE, GROUP, TS) == 250
    # A kind 9 request naming slot 1's rule id revokes exactly that rule
    # — and its 150 of group usage leaves with it.
    target = book.get(ALICE, 1)
    req = _request(KIND_REVOKE_PAYOUT, seq=2,
                   offer_id=target.rule_id.hex(), expire=3000)
    chain.block(_tx(req))
    assert chain.entry(req).status == STATUS_OPEN
    chain.block(_vote(req.request_id, seq=2))
    assert chain.entry(req).status == STATUS_EXECUTED
    book = chain.lm.payout_rules
    assert book.get(ALICE, 1) is None
    assert book.get(ALICE, 0) is not None
    assert book.shared_cap_usage(ALICE, GROUP, TS) == 100
