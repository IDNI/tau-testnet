"""Bounty 01, stages 2-5: grants at the engine seam (mock Tau).

Slice 6 of DESIGN-01-TAKEOVER.md: the grant book is wired into block
apply. Creation validates through the book's own can_create and custodies
the total through the transfer seam with escrow=True — the funder's o5 is
re-checked on the real beneficiary and amount, the fee is measured on the
real inputs, and only the debit is staged — while the book records the
custody at the post-settlement site, so a fee-rejected creation holds
nothing. A draw is decided by the book's evaluate_draw and credits the
beneficiary directly (a grant_draw credit: it never enters the seam, so a
receive route never splits it); the expiry refund is the end-of-block
sweep's — fee-free, the full remainder, never routed.

Named case 5 is proven here end-to-end with the program page's numbers:
a 5,000 grant releasing 500/week from Dec 1; Bob draws 500 in each of
three weeks (1,500 spent); at the deadline the sweep returns exactly
3,500 to the funder.
"""
import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.grants import (
    GrantBook,
    grant_capabilities,
    parse_create_grant,
    parse_set_grant_shared_cap,
)
from consensus.receive_routes import ReceiveRouteEntry
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
FEE = 7
WEEK = 604_800
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
DEADLINE = DEC1 + 8 * WEEK


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator / fee beneficiary
SK_FUNDER, FUNDER = _key(22222)      # the grant's funder (Alice of the example)
SK_BOB, BOB = _key(33333)            # the beneficiary (Bob of the example)
SK_CAROL, CAROL = _key(44444)        # a second beneficiary
SK_EXECUTOR, EXECUTOR = _key(55555)  # any third party may submit a draw
SK_RDEST, RDEST = _key(66666)        # receive-route destination

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

    Mirrors the slice-5 payout harness; `allow=False` makes the scripted
    evaluator's o5 refuse every transfer, and `block_amount=N` refuses
    only the transfer of exactly N.
    """

    def __init__(self, balances, lm=None, ts=DEC1 - 100):
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


def _create_tx(funder, sk, seq, fee_limit="100", **kw):
    return _sign({
        "tx_id": f"grant-create-{next(_TX_SEQ)}",
        "tx_type": "create_grant",
        "sender_pubkey": funder,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "grant_beneficiary_pubkey": kw.get("beneficiary", BOB),
        "grant_total_amount": kw.get("total", 5000),
        "grant_release_per_period": kw.get("release", 500),
        "grant_schedule": kw.get("schedule", "weekly"),
        "grant_signed_day": kw.get("signed_day", 0),
        "grant_start_ts": kw.get("start_ts", DEC1),
        "grant_deadline_ts": kw.get("deadline_ts", DEADLINE),
        "grant_locked_until_ts": kw.get("locked_until_ts", 0),
        "grant_window_start_ts": kw.get("window_start_ts", 0),
        "grant_window_end_ts": kw.get("window_end_ts", 0),
        "grant_inactivity_seconds": kw.get("inactivity_seconds", 0),
        "grant_version": kw.get("version", 1),
    }, sk)


def _draw_tx(sender, sk, grant_id, amount, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"grant-draw-{next(_TX_SEQ)}",
        "tx_type": "draw_grant",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "grant_id": grant_id.hex(),
        "grant_draw_amount": amount,
    }, sk)


def _cap_tx(funder, sk, seq, fee_limit="100", **kw):
    return _sign({
        "tx_id": f"grant-cap-{next(_TX_SEQ)}",
        "tx_type": "set_grant_shared_cap",
        "sender_pubkey": funder,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "grant_shared_cap_amount": kw.get("amount", 500),
        "grant_shared_cap_period_seconds": kw.get("period_seconds", WEEK),
        "grant_shared_cap_anchor_ts": kw.get("anchor_ts", DEC1),
        "grant_shared_cap_version": kw.get("version", 1),
    }, sk)


def _grant_id(create_tx):
    return parse_create_grant(create_tx).grant_id


def _funded_chain():
    return _Chain({
        ALICE: 0, FUNDER: 100000, BOB: 0, CAROL: 0, EXECUTOR: 1000, RDEST: 0,
    })


def _created_chain(**kw):
    chain = _funded_chain()
    create = _create_tx(FUNDER, SK_FUNDER, seq=0, **kw)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    return chain, _grant_id(create)


def _book(chain):
    return chain.lm.grants


# --- named case 5, end-to-end -----------------------------------------------------


def test_named_case_5_end_to_end():
    """5000 from Dec 1, 500/week; Bob spends 1500; 3500 returns at deadline."""
    chain, grant_id = _created_chain()
    # Creation custodied the total through the seam: funder down by the
    # total plus exactly one fee; Bob untouched; the book holds 5000.
    assert chain.balances[FUNDER] == 100000 - 5000 - FEE
    assert chain.balances[BOB] == 0
    assert _book(chain).held_total() == 5000

    # Week 1: 501 is refused (only 500 released); 500 draws.
    chain.ts = DEC1 + 10
    over = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 501, seq=0)
    result = chain.apply([over])
    assert over["tx_id"] in result.invalid_tx_ids
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    assert chain.balances[BOB] == 500
    (event,) = result.next_snapshot.metadata["grant_events"]
    assert event["action"] == "drawn" and event["amount"] == 500

    # Weeks 2 and 3: one 500 draw each. Bob has spent 1500 in total.
    chain.ts = DEC1 + WEEK + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=1)
    assert draw["tx_id"] in chain.apply([draw]).accepted_tx_ids
    chain.ts = DEC1 + 2 * WEEK + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=2)
    assert draw["tx_id"] in chain.apply([draw]).accepted_tx_ids
    assert chain.balances[BOB] == 1500
    assert _book(chain).accounting(grant_id)["drawn"] == 1500

    # The deadline block carries no transaction at all: the sweep refunds
    # exactly 3500 to the funder, fee-free (the delta is the remainder
    # itself, to the unit).
    chain.ts = DEADLINE
    funder_before = chain.balances[FUNDER]
    result = chain.apply([])
    assert chain.balances[FUNDER] - funder_before == 3500
    assert _book(chain).held_total() == 0
    assert _book(chain).accounting(grant_id) == {
        "principal": 5000, "drawn": 1500, "held": 0, "refunded": 3500,
    }
    (event,) = result.next_snapshot.metadata["grant_events"]
    assert event["action"] == "refunded" and event["amount"] == 3500
    assert event["funder_pubkey"] == FUNDER
    assert result.governance_changes["grant_events"] == [event]

    # Nothing is drawable after the refund.
    chain.ts = DEADLINE + 10
    late = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 1, seq=3)
    result = chain.apply([late])
    assert late["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 1500


def test_creation_event_and_custody():
    chain = _funded_chain()
    create = _create_tx(FUNDER, SK_FUNDER, seq=0)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    grant_id = _grant_id(create)
    (event,) = result.next_snapshot.metadata["grant_events"]
    assert event["action"] == "created" and event["grant_id"] == grant_id.hex()
    assert event["total_amount"] == 5000
    assert result.governance_changes["grant_events"] == [event]
    assert _book(chain).held(grant_id) == 5000


# --- deferred mutation ----------------------------------------------------------------


def test_create_with_unpaid_fee_creates_nothing():
    """The deferred commit: a fee-rejected creation custodies nothing."""
    chain = _funded_chain()
    broke = _create_tx(FUNDER, SK_FUNDER, seq=0, fee_limit="0")
    result = chain.apply([broke])
    assert broke["tx_id"] in result.invalid_tx_ids
    assert _book(chain).is_empty()
    assert chain.balances[FUNDER] == 100000

    honest = _create_tx(FUNDER, SK_FUNDER, seq=0)
    result = chain.apply([honest])
    assert honest["tx_id"] in result.accepted_tx_ids
    assert not _book(chain).is_empty()


def test_create_policy_block_on_the_amount_creates_nothing():
    """The funder's o5 is re-checked on the real beneficiary and amount:
    a policy refusing a 5000 transfer refuses the creation's escrow."""
    chain = _funded_chain()
    create = _create_tx(FUNDER, SK_FUNDER, seq=0)
    result = chain.apply([create], block_amount=5000)
    assert create["tx_id"] in result.invalid_tx_ids
    assert _book(chain).is_empty()
    assert chain.balances[FUNDER] == 100000


def test_draw_with_unpaid_fee_draws_nothing():
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 10
    broke = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0, fee_limit="0")
    result = chain.apply([broke])
    assert broke["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 0
    assert _book(chain).accounting(grant_id)["drawn"] == 0


# --- credit classes: grant credits never route -------------------------------------------


def test_draw_is_never_split_by_a_route_on_the_beneficiary():
    """The design's credit-class table: draws carry the grant_draw class."""
    chain, grant_id = _created_chain()
    chain.lm.receive_routes.install(ReceiveRouteEntry(
        owner_pubkey=BOB, destination_pubkey=RDEST, bps=5000,
        min_amount=0, activation_ts=0, expiry_ts=0, locked_until_ts=0,
        version=1,
    ), DEC1 - 100)
    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    assert chain.balances[BOB] == 500  # whole, not split
    assert chain.balances[RDEST] == 0
    assert result.next_snapshot.metadata["routing_events"] == []


def test_refund_is_never_split_by_a_route_on_the_funder():
    """The refund is a sweep credit of the refund class: it never routes."""
    chain, grant_id = _created_chain(
        total=1000, release=1000, deadline_ts=DEC1 + WEEK)
    chain.lm.receive_routes.install(ReceiveRouteEntry(
        owner_pubkey=FUNDER, destination_pubkey=RDEST, bps=5000,
        min_amount=0, activation_ts=0, expiry_ts=0, locked_until_ts=0,
        version=1,
    ), DEC1 - 100)
    chain.ts = DEC1 + WEEK
    funder_before = chain.balances[FUNDER]
    result = chain.apply([])
    assert chain.balances[FUNDER] - funder_before == 1000
    assert chain.balances[RDEST] == 0
    assert result.next_snapshot.metadata["routing_events"] == []


# --- the shared cap at engine level ---------------------------------------------------------


def test_shared_cap_binds_across_two_grants():
    chain = _funded_chain()
    cap = _cap_tx(FUNDER, SK_FUNDER, seq=0, amount=500)
    assert cap["tx_id"] in chain.apply([cap]).accepted_tx_ids

    g1 = _create_tx(FUNDER, SK_FUNDER, seq=1, total=2000, release=2000)
    assert g1["tx_id"] in chain.apply([g1]).accepted_tx_ids
    g2 = _create_tx(FUNDER, SK_FUNDER, seq=2, beneficiary=CAROL,
                    total=2000, release=2000)
    assert g2["tx_id"] in chain.apply([g2]).accepted_tx_ids

    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, _grant_id(g1), 400, seq=0)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    (event,) = result.next_snapshot.metadata["grant_events"]
    assert event["shared_total_after"] == 400

    # 400 + 200 would pass the shared cap of 500: refused...
    over = _draw_tx(EXECUTOR, SK_EXECUTOR, _grant_id(g2), 200, seq=1)
    result = chain.apply([over])
    assert over["tx_id"] in result.invalid_tx_ids
    assert chain.balances[CAROL] == 0
    # ...and exactly the remaining 100 fits, counted once.
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, _grant_id(g2), 100, seq=1)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    (event,) = result.next_snapshot.metadata["grant_events"]
    assert event["shared_total_after"] == 500
    assert chain.balances[BOB] == 400 and chain.balances[CAROL] == 100
    assert _book(chain).shared_period_total(FUNDER, 0) == 500


# --- time conditions at engine level ---------------------------------------------------------


def test_draw_on_a_locked_grant_is_refused_until_the_lock_lifts():
    chain, grant_id = _created_chain(locked_until_ts=DEC1 + WEEK)
    chain.ts = DEC1 + 10
    early = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([early])
    assert early["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 0
    assert _book(chain).accounting(grant_id)["drawn"] == 0
    # At the unlock time the same draw settles (1000 released by then).
    chain.ts = DEC1 + WEEK + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    assert chain.balances[BOB] == 500


def test_draw_outside_the_scheduled_window_is_refused():
    chain, grant_id = _created_chain(
        window_start_ts=DEC1 + 2 * WEEK, window_end_ts=DEC1 + 3 * WEEK)
    chain.ts = DEC1 + WEEK + 10
    early = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([early])
    assert early["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 0
    # Inside the window the draw settles.
    chain.ts = DEC1 + 2 * WEEK + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    result = chain.apply([draw])
    assert draw["tx_id"] in result.accepted_tx_ids
    assert chain.balances[BOB] == 500
    # At the window's end the next draw is refused again.
    chain.ts = DEC1 + 3 * WEEK + 10
    late = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=1)
    result = chain.apply([late])
    assert late["tx_id"] in result.invalid_tx_ids
    assert chain.balances[BOB] == 500


# --- capability record + facade ----------------------------------------------------------------


def test_capability_record_matches_the_book():
    caps = grant_capabilities()
    assert caps["supported"] is True
    assert caps["draw_credit_class"] == "grant_draw"
    assert caps["refund_credit_class"] == "refund"


class _TipView(TipAdmissionView):
    """The real facade view over an injected book, at a fixed timestamp."""

    def __init__(self, book, balances, ts=DEC1 + 10):
        self._book = book
        self._balances = balances
        self._ts = ts

    @property
    def next_block_timestamp(self):
        return self._ts

    def _tip_grant_book(self):
        return self._book

    def get_balance(self, pubkey):
        return self._balances.get(pubkey, 0)


def test_grant_view_readable_via_the_facade():
    chain, grant_id = _created_chain()
    chain.ts = DEC1 + 10
    draw = _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0)
    chain.apply([draw])

    view = _TipView(_book(chain), dict(chain.balances))
    got = view.get_grant(grant_id)
    assert got is not None and got["grant_id"] == grant_id.hex()
    assert got["funder_pubkey"] == FUNDER and got["beneficiary_pubkey"] == BOB
    assert got["total_spent"] == 500 and got["released"] == 500
    assert got["spendable"] == 0 and got["held"] == 4500
    assert got["status"] == "active" and got["shared_cap"] is None
    assert view.get_grant(b"\x09" * 32) is None
    assert view.get_shared_cap(FUNDER) is None


def test_meta_hash_moves_only_once_a_grant_exists():
    lm = _lm()
    before = lm.consensus_meta_hash()
    chain = _Chain({ALICE: 0, FUNDER: 100000}, lm=lm)
    create = _create_tx(FUNDER, SK_FUNDER, seq=0)
    chain.apply([create])
    assert chain.lm.consensus_meta_hash() != before


# --- admission and apply agree ---------------------------------------------------------------------


def test_admission_agrees_with_apply():
    from consensus.admission import (
        validate_create_grant_payload,
        validate_draw_grant_payload,
        validate_set_grant_shared_cap_payload,
    )

    empty = _TipView(GrantBook(), {FUNDER: 100000})

    good = _create_tx(FUNDER, SK_FUNDER, seq=0)
    assert validate_create_grant_payload(good, empty).is_valid

    # A grant to oneself, and a never-drawable lock: the book refuses, so
    # admission does.
    own = _create_tx(FUNDER, SK_FUNDER, seq=0, beneficiary=FUNDER)
    assert not validate_create_grant_payload(own, empty).is_valid
    locked = _create_tx(FUNDER, SK_FUNDER, seq=0, locked_until_ts=DEADLINE)
    assert not validate_create_grant_payload(locked, empty).is_valid

    # Draws and caps against a tip that knows no grant and no cap.
    grant_id = _grant_id(good)
    assert not validate_draw_grant_payload(
        _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0), empty).is_valid
    assert validate_set_grant_shared_cap_payload(
        _cap_tx(FUNDER, SK_FUNDER, seq=0), empty).is_valid

    # With the grant live at the tip: a draw is admitted exactly when the
    # book would settle it.
    book = GrantBook()
    book.create(parse_create_grant(good), DEC1 - 100)
    live = _TipView(book, {FUNDER: 100000})
    due = validate_draw_grant_payload(
        _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 500, seq=0), live)
    assert due.is_valid and due.data["amount"] == 500
    assert not validate_draw_grant_payload(
        _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 501, seq=0), live).is_valid

    # After the draw settles in the book, the same admission refuses the
    # next unit: admission and apply read the same book state.
    book.draw(grant_id, 500, DEC1 + 10)
    assert not validate_draw_grant_payload(
        _draw_tx(EXECUTOR, SK_EXECUTOR, grant_id, 1, seq=0), live).is_valid

    # The duplicate creation is refused once the grant exists at the tip.
    assert not validate_create_grant_payload(good, live).is_valid

    # Shared-cap replacement: next version, same shape — or nothing.
    book.set_shared_cap(parse_set_grant_shared_cap(
        _cap_tx(FUNDER, SK_FUNDER, seq=0)), DEC1 - 100)
    assert validate_set_grant_shared_cap_payload(
        _cap_tx(FUNDER, SK_FUNDER, seq=0, version=2), live).is_valid
    assert not validate_set_grant_shared_cap_payload(
        _cap_tx(FUNDER, SK_FUNDER, seq=0, version=2, period_seconds=86400),
        live).is_valid
    assert not validate_set_grant_shared_cap_payload(
        _cap_tx(FUNDER, SK_FUNDER, seq=0, version=3), live).is_valid
