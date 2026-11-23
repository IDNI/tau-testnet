"""Payout triggers: stage 1 in rules form (Bounty 01, #34/#35).

The clock trigger makes a standing payment a payout rule whose
signed terms carry its schedule and one end condition; the arrival
trigger makes a receive route a payout rule settled by the credit
itself. Both settle through the #63 book path -- same caps, same
settlement-id idempotency -- so this file carries gmikeyg's five
named cases (his 20 Nov comment on #34) against the trigger paths,
plus the book-level trigger semantics.
"""

import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from block import Block
from consensus import periods
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.payouts import (
    PAYOUT_STREAM_INDEX,
    TEMPLATE_PERCENTAGE_ROUTE_CLAUSE,
    TEMPLATE_ROYALTY_5PCT_CLAUSE,
    TEMPLATE_STANDING_PAYMENT_CLAUSE,
    PayoutBook,
    PayoutShapeError,
    PayoutTerms,
    arrival_settlement_id,
    clock_due_period,
    clock_settlement_id,
    parse_payout_install,
    validate_payout_shape,
)
from consensus.serialization import canonical_json
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

FAR = 9_999_999_999
WEEK = 604800


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


NOW = _ts(2026, 1, 15, 12)
JAN1 = _ts(2026, 1, 1)


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_MALLORY, MALLORY = _key(66666)
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


# --- book-level trigger semantics -------------------------------------------


def _terms(**kw):
    base = dict(
        owner=ALICE, max_per_execution=1000, max_per_period=1500,
        recipients=(BOB, CAROL), period_kind=periods.PERIOD_WEEK,
        anchor_ts=JAN1, sequence_number=1,
    )
    base.update(kw)
    return PayoutTerms(**base)


def test_trigger_terms_extend_rule_id_and_legacy_id_is_unchanged():
    legacy = _terms()
    payload = {
        "owner": legacy.owner,
        "max_per_execution": legacy.max_per_execution,
        "max_per_period": legacy.max_per_period,
        "recipients": list(legacy.recipients),
        "period_kind": legacy.period_kind,
        "anchor_ts": legacy.anchor_ts,
        "sequence_number": legacy.sequence_number,
    }
    expected = hashlib.sha256(canonical_json(payload)).hexdigest()
    assert legacy.rule_id == expected
    # A triggered rule hashes its trigger terms in; the end
    # condition is part of the signed identity.
    clocked = _terms(due=True, max_fires=4)
    assert clocked.rule_id != legacy.rule_id
    assert _terms(due=True, max_fires=5).rule_id != clocked.rule_id
    assert _terms(on_arrival=True).rule_id != legacy.rule_id


def test_clock_rule_requires_exactly_one_end_condition():
    validate_payout_shape(_terms(due=True, max_fires=4), now_ts=JAN1)
    validate_payout_shape(_terms(due=True, end_period_index=11), now_ts=JAN1)
    validate_payout_shape(_terms(due=True, max_total=4000), now_ts=JAN1)
    validate_payout_shape(_terms(on_arrival=True), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(due=True), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(
            _terms(due=True, max_fires=4, max_total=4000), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(max_fires=4), now_ts=JAN1)
    with pytest.raises(PayoutShapeError):
        validate_payout_shape(_terms(due=True, max_fires=0), now_ts=JAN1)


def test_clock_due_period_skips_missed_periods():
    book = PayoutBook()
    state = book.install(_terms(due=True, max_fires=10))
    assert clock_due_period(state, JAN1 - 1) is None
    assert clock_due_period(state, JAN1) == 0
    book.settle_clock(ALICE, clock_settlement_id(state.terms.rule_id, 0),
                      100, ts=JAN1)
    assert clock_due_period(state, JAN1) is None
    # No block landed in period 1: at period 2 the rule fires for
    # period 2 only -- period 1 is skipped, never caught up.
    assert clock_due_period(state, JAN1 + 2 * WEEK + 60) == 2


def test_clock_end_conditions_stop_the_rule():
    book = PayoutBook()
    by_fires = book.install(_terms(due=True, max_fires=1))
    assert clock_due_period(by_fires, JAN1) == 0
    book.settle_clock(ALICE, clock_settlement_id(by_fires.terms.rule_id, 0),
                      100, ts=JAN1)
    assert clock_due_period(by_fires, JAN1 + WEEK) is None

    book2 = PayoutBook()
    by_period = book2.install(_terms(due=True, end_period_index=0))
    assert clock_due_period(by_period, JAN1) == 0
    assert clock_due_period(by_period, JAN1 + WEEK) is None

    book3 = PayoutBook()
    by_total = book3.install(_terms(due=True, max_total=100))
    book3.settle_clock(ALICE, clock_settlement_id(by_total.terms.rule_id, 0),
                       100, ts=JAN1)
    assert clock_due_period(by_total, JAN1 + WEEK) is None


def test_clock_settlement_accounting_and_snapshot_round_trip():
    book = PayoutBook()
    book.install(_terms(due=True, max_fires=4))
    total = book.check_execution(
        ALICE, clock_settlement_id(book.get(ALICE).terms.rule_id, 0),
        [(BOB, 500)], ts=JAN1)
    book.settle_clock(
        ALICE, clock_settlement_id(book.get(ALICE).terms.rule_id, 0),
        total, ts=JAN1)
    state = book.get(ALICE)
    assert state.fires == 1
    assert state.total_spent == 500
    assert state.spent_in_period == 500
    restored = PayoutBook.restore(book.snapshot_rows())
    assert restored.root() == book.root()
    rstate = restored.get(ALICE)
    assert rstate.fires == 1
    assert rstate.total_spent == 500
    assert rstate.terms.due is True
    assert rstate.terms.max_fires == 4


def test_trigger_settlement_id_formats():
    assert clock_settlement_id("ab" * 32, 3) == f"clock:{'ab' * 32}:3"
    assert arrival_settlement_id("tx-9") == "arrival:tx-9"


def test_parse_install_trigger_fields():
    data = {
        "sender_pubkey": ALICE, "max_per_execution": 1000,
        "max_per_period": 1500, "recipients": [BOB],
        "due": True, "max_total": 4000,
    }
    terms = parse_payout_install(data)
    assert terms.due is True
    assert terms.on_arrival is False
    assert terms.max_total == 4000
    assert terms.max_fires is None
    plain = parse_payout_install({
        "sender_pubkey": ALICE, "max_per_execution": 1000,
        "max_per_period": 1500, "recipients": [BOB]})
    assert plain.has_trigger is False


def test_clause_templates_carry_their_stated_semantics():
    # Fixed standing leg of 500 (0x1f4) to recipient index 0.
    assert "#x0001f4" in TEMPLATE_STANDING_PAYMENT_CLAUSE
    assert "o21" in TEMPLATE_STANDING_PAYMENT_CLAUSE
    # 20% route: (i1 * 0x14) / 0x64, floored by Tau division.
    assert "i1" in TEMPLATE_PERCENTAGE_ROUTE_CLAUSE
    assert "#x000014" in TEMPLATE_PERCENTAGE_ROUTE_CLAUSE
    assert "#x000064" in TEMPLATE_PERCENTAGE_ROUTE_CLAUSE
    # 5% royalty: (i1 * 0x05) / 0x64.
    assert "#x000005" in TEMPLATE_ROYALTY_5PCT_CLAUSE
    assert "#x000064" in TEMPLATE_ROYALTY_5PCT_CLAUSE


# --- apply-level harness ------------------------------------------------------


def install_tx(owner=ALICE, sk=SK_ALICE, seq=0, extra=None, **kw):
    tx = {
        "tx_id": f"payout-install-{next(_TX_SEQ)}",
        "tx_type": "payout_rule_install",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "max_per_execution": kw.get("max_per_execution", 1000),
        "max_per_period": kw.get("max_per_period", 1500),
        "recipients": kw.get("recipients", [BOB, CAROL]),
        "period_kind": kw.get("period_kind", 2),
        "anchor_ts": kw.get("anchor_ts", JAN1),
    }
    tx.update(extra or {})
    return _sign(tx, sk)


def transfer_tx(to, amount, sk, *, sender, seq=0, tx_id=None):
    tx = {
        "tx_id": tx_id or f"transfer-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[sender, to, str(amount)]]},
    }
    return _sign(tx, sk)


class Chain:
    """The test_payouts_apply harness, plus a legs function: the
    scripted evaluator plays the installed clause's role, computing
    legs from the fed inputs (i1 gross) exactly as the clause
    templates state -- the same discipline as the grants harness
    computing its canonical clause's verdict from the draw facts."""

    def __init__(self, balances, *, fee=0):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.fee = fee
        self.legs = {}
        self.legs_fn = None
        self.last = None

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        out = {1: str(vals.get(1, "0")), 8: "0", 9: str(self.fee), 5: "1"}
        marker = vals.get(3)
        if isinstance(marker, str) and marker.startswith("{ #x"):
            out.update(self.legs_fn(vals) if self.legs_fn else self.legs)
        return out

    def block(self, txs, height=20, ts=NOW):
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.bal),
                "sequence_numbers": dict(self.seq),
                "last_transfer_ts": dict(self.lts),
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ALICE)],
            mechanism_specific_metadata={"poa": True},
        )
        blk = Block.create(
            block_number=height, previous_hash="00" * 32, transactions=txs,
            proposer_pubkey=PROPOSER, timestamp=ts,
        )
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=self._multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, blk, parent)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.last = result
        return result

    @property
    def book(self):
        return self.lm.payout_rules

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids

    def receipt(self, tx):
        for outcome in self.last.outcomes:
            if outcome.tx_id == tx["tx_id"]:
                return {"logs": outcome.receipt_logs, "reason": outcome.reason}
        raise KeyError(tx["tx_id"])

    def install_rule(self, owner, sk, *, height, ts=NOW, seq=0, **kw):
        self.lm.rule_offers.accepted_clauses[(owner, PAYOUT_STREAM_INDEX)] = (
            "always (o20[t] = 1)."
        )
        tx = install_tx(owner=owner, sk=sk, seq=seq, **kw)
        self.block([tx], height=height, ts=ts)
        assert self.accepted(tx), self.receipt(tx)
        assert self.book.get(owner) is not None
        return parse_payout_install(tx)


def _pct(pct):
    """Legs for a template clause paying pct% of the gross (i1),
    floored, to declared recipient index 0."""
    def legs(vals):
        gross = int(vals.get(1, 0))
        return {20: "1", 21: str(gross * pct // 100), 22: "0"}
    return legs


# --- gmikeyg's named cases, on the trigger paths ------------------------------


def test_101_routed_at_20_percent_gives_20_and_81_with_one_fee():
    # Maintainer case 1: BOB's receive route forwards 20% of a 101
    # credit to CAROL; 81 stays with BOB; the only fee in the block
    # is the crediting transfer's own -- a route settlement is not a
    # transaction and charges no second fee.
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, MALLORY: 0,
                PROPOSER: 0}, fee=7)
    ch.install_rule(BOB, SK_BOB, height=20, recipients=[CAROL],
                    extra={"on_arrival": True})
    ch.legs_fn = _pct(20)
    proposer_before = ch.bal[PROPOSER]
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=21, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 20
    assert ch.bal[BOB] == 1_000 - 7 + 101 - 20
    assert ch.bal[PROPOSER] - proposer_before == 7
    state = ch.book.get(BOB)
    assert state.settlements == [arrival_settlement_id(tx["tx_id"])]


def test_a_5_percent_royalty_on_101_pays_5_once():
    # Maintainer case 2, arrival form: the royalty settles under
    # the crediting transaction's id, so the same credit replayed
    # under the same id pays nothing the second time -- the credit
    # itself still lands; only the settlement is idempotent.
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0})
    ch.install_rule(BOB, SK_BOB, height=20, recipients=[CAROL],
                    extra={"on_arrival": True})
    ch.legs_fn = _pct(5)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0,
                     tx_id="credit-101")
    ch.block([tx], height=21, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 5
    assert ch.bal[BOB] == 101 - 5

    replay = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=1,
                         tx_id="credit-101")
    ch.block([replay], height=22, ts=NOW)
    assert ch.accepted(replay), ch.receipt(replay)
    assert ch.bal[CAROL] == 5
    assert ch.bal[BOB] == 101 - 5 + 101
    assert ch.book.get(BOB).settlements == ["arrival:credit-101"]


def test_a_routed_share_never_triggers_another_route():
    # Maintainer case 3: BOB routes 20% of his credits to CAROL, and
    # CAROL routes 20% of hers to MALLORY. The 20 that lands on
    # CAROL as a payout leg is payout-class: CAROL's route does NOT
    # fire on it. A direct credit to CAROL fires her route normally,
    # proving the guard is about the credit's class, not the rule.
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0})
    ch.install_rule(BOB, SK_BOB, height=20, recipients=[CAROL],
                    extra={"on_arrival": True})
    ch.install_rule(CAROL, SK_CAROL, height=21, recipients=[MALLORY],
                    extra={"on_arrival": True})
    ch.legs_fn = _pct(20)
    tx = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([tx], height=22, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.bal[CAROL] == 20
    assert ch.bal[MALLORY] == 0
    assert ch.book.get(CAROL).settlements == []

    direct = transfer_tx(CAROL, 50, SK_ALICE, sender=ALICE, seq=1)
    ch.block([direct], height=23, ts=NOW)
    assert ch.accepted(direct), ch.receipt(direct)
    assert ch.bal[MALLORY] == 10
    assert ch.bal[CAROL] == 20 + 50 - 10


def test_arrival_without_clause_settles_nothing():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0})
    tx = install_tx(owner=BOB, sk=SK_BOB, seq=0, recipients=[CAROL],
                    extra={"on_arrival": True})
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    credit = transfer_tx(BOB, 101, SK_ALICE, sender=ALICE, seq=0)
    ch.block([credit], height=21, ts=NOW)
    assert ch.accepted(credit), ch.receipt(credit)
    assert ch.bal[BOB] == 101
    assert ch.bal[CAROL] == 0
    assert ch.book.get(BOB).settlements == []


def test_a_monthly_payment_on_the_31st_runs_on_the_last_day_of_a_shorter_month():
    # Maintainer case 4: a standing payment anchored on the 31st,
    # in clock-trigger clause form (the standing-payment template's
    # fixed 500 leg). February has no 31st: the period-1 firing
    # lands on Feb 28, the last day of the shorter month, and the
    # schedule returns to the 31st in March -- no drift.
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0})
    terms = ch.install_rule(
        ALICE, SK_ALICE, height=20, ts=_ts(2026, 1, 15),
        recipients=[BOB], anchor_ts=_ts(2026, 1, 31),
        extra={"due": True, "max_fires": 3})
    ch.legs = {20: "1", 21: "500", 22: "0"}

    ch.block([], height=21, ts=_ts(2026, 2, 28))
    assert ch.bal[BOB] == 500
    state = ch.book.get(ALICE)
    assert state.fires == 1
    assert state.settlements == [clock_settlement_id(terms.rule_id, 1)]

    # March's period starts on the 31st, not the 30th: no firing yet.
    ch.block([], height=22, ts=_ts(2026, 3, 30))
    assert ch.bal[BOB] == 500
    assert ch.book.get(ALICE).fires == 1

    ch.block([], height=23, ts=_ts(2026, 3, 31))
    assert ch.bal[BOB] == 1000
    assert ch.bal[ALICE] == 10_000 - 1000
    state = ch.book.get(ALICE)
    assert state.fires == 2
    assert state.settlements == [
        clock_settlement_id(terms.rule_id, 1),
        clock_settlement_id(terms.rule_id, 2),
    ]


def test_the_5000_grant_500_a_week_from_1_december_returns_the_right_remainder():
    # Maintainer case 5, re-run on this branch: the #63 grant path
    # is untouched by the trigger extension -- 5,000 escrowed, the
    # 500/week cap binds, and the deadline sweep refunds the exact
    # remainder (the full scenario lives in test_grants_apply.py;
    # this re-runs its harness end to end).
    from test_grants_apply import (
        DEC1, WEEK, Chain as GrantChain,
        create_tx as grant_create_tx, draw_tx as grant_draw_tx,
    )
    from consensus.grants import parse_grant_create

    ch = GrantChain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    create = grant_create_tx()
    ch.block([create], height=20, ts=DEC1 - 60)
    assert ch.accepted(create), ch.receipt(create)
    grant_id = parse_grant_create(create).grant_id
    assert ch.bal[ALICE] == 5_000

    d1 = grant_draw_tx(grant_id, 500, seq=0)
    ch.block([d1], height=21, ts=DEC1 + 60)
    assert ch.accepted(d1), ch.receipt(d1)
    d2 = grant_draw_tx(grant_id, 500, seq=1)
    ch.block([d2], height=22, ts=DEC1 + WEEK + 60)
    assert ch.accepted(d2), ch.receipt(d2)
    assert ch.bal[BOB] == 1000

    from test_grants_apply import DEADLINE
    ch.block([], height=23, ts=DEADLINE)
    state = ch.book.get(grant_id)
    assert state.refunded is True
    assert ch.bal[ALICE] == 5_000 + 4_000
    assert ch.bal[BOB] == 1000
