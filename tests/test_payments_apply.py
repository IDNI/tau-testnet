"""Block-apply semantics for programmable payments (Bounty 01).

Every scenario runs through the real ``apply_block`` in the idiom of
test_retractable_apply.py, with the Tau engine scripted: the multi-step
evaluation answers o5 (allow unless scripted to block), o9 (the consensus
fee) and o8 (no custom fee). That scripted evaluator stands behind the
engine's REAL facilities -- the fee-era measurement step and the sender
policy evaluation -- which are exactly what the payment books'
PolicyGate/FeeOracle seams are adapted to here. The native Tau bindings
are not built in this sandbox; the engine harness itself needs no native
code beyond those two patched entry points, same as the retractable
suite.
"""
import hashlib
import itertools
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.payments import (
    FEE_SINK_PUBKEY,
    GRANT_ESCROW_PUBKEY,
    PayoutTerms,
    StandingTerms,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_700_000_000
WEEK = 604_800
FAR = 9_999_999_999
GENESIS_HASH = "ab" * 32

SK_ALICE, ALICE = 11111, G2Basic.SkToPk(11111).hex()
SK_BOB, BOB = 44444, G2Basic.SkToPk(44444).hex()
SK_CAROL, CAROL = 55555, G2Basic.SkToPk(55555).hex()
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _base(tx_type, sender, seq):
    return {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
    }


def standing_create_tx(seq=0, payer=ALICE, payee=BOB, sk=SK_ALICE):
    tx = _base("standing_authorization_create", payer, seq)
    tx.update({
        "payer": payer, "payee": payee, "amount": 100,
        "period_kind": "week", "start_ts": TS,
        "end_kind": "count", "end_value": 2,
        "max_fee_per_execution": 10, "genesis_hash": GENESIS_HASH,
        "max_catch_up": 0,
    })
    return _sign(tx, sk)


def standing_cancel_tx(seq):
    tx = _base("standing_authorization_cancel", ALICE, seq)
    tx["authorization_id"] = standing_terms().auth_id.hex()
    return _sign(tx, SK_ALICE)


def standing_terms():
    return StandingTerms(
        payer=ALICE, payee=BOB, amount=100, period_kind="week",
        start_ts=TS, end_kind="count", end_value=2,
        max_fee_per_execution=10, genesis_hash=GENESIS_HASH,
        max_catch_up=0, sequence_number=0,
    )


def payout_terms():
    return PayoutTerms(
        owner=ALICE, candidates=((BOB, 500), (CAROL, 500)),
        max_per_execution=1000, max_per_period=1000,
        period_kind="week", anchor_ts=TS, sequence_number=0,
    )


class Chain:
    """One chain advanced block by block through the real apply path."""

    def __init__(self, balances, *, fee=3, block_o5=False):
        self.fee = fee
        self.block_o5 = block_o5
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.lm.activate_approval_slots()

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = str(vals.get(1, "0"))
        return {1: amount, 8: "0", 9: str(self.fee),
                5: "0" if self.block_o5 else "1"}

    def block(self, txs, height, ts, *, fee=None, block_o5=None):
        if fee is not None:
            self.fee = fee
        if block_o5 is not None:
            self.block_o5 = block_o5
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.bal),
                "sequence_numbers": dict(self.seq),
                "last_transfer_ts": dict(self.lts),
                "lifecycle_manager": self.lm,
                "consensus_rules_state":
                    "always (o6[t]:bv[16] = i10[t]:bv[16]).",
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
            block_number=height,
            previous_hash="00" * 32,
            transactions=txs,
            proposer_pubkey=PROPOSER,
            timestamp=ts,
        )
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
                patch("tau_manager.communicate_with_tau_multi",
                      side_effect=self._multi), \
                patch("chain_state.get_application_rules_state",
                      return_value=""), \
                patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, blk, parent)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        return result

    def books(self):
        return self.lm.programmable_payments


# --- standing authorizations: the required end-to-end scenario --------------

def test_standing_authorization_settles_once_per_period_at_apply():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})

    # Alice installs the authorization; the same block's sweep settles
    # period 0: amount 100 to Bob, execution fee 3 to the fee sink, and
    # the create tx's own fee-query step pays 3 to the proposer.
    result = ch.block([standing_create_tx()], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    auth_id = next(iter(ch.books().standing.authorizations))
    assert result.governance_changes["payment_settlements"] == [
        (auth_id.hex(), 0, 100, 3)
    ]
    assert ch.bal[BOB] == 100
    assert ch.bal[ALICE] == 10_000 - 3 - 103
    assert ch.bal[FEE_SINK_PUBKEY] == 3
    assert ch.bal[PROPOSER] == 3
    state = ch.books().standing.authorizations[auth_id]
    assert set(state.settled) == {0} and state.cumulative_spent == 100

    # One period later the sweep settles period 1 -- the end count (2)
    # completes the authorization.
    ch.block([], HEIGHT + 1, TS + WEEK)
    assert ch.bal[BOB] == 200
    assert ch.bal[ALICE] == 10_000 - 3 - 206
    assert ch.bal[FEE_SINK_PUBKEY] == 6
    state = ch.books().standing.authorizations[auth_id]
    assert set(state.settled) == {0, 1} and state.status == "completed"

    # Later blocks settle nothing more: each period paid exactly once.
    ch.block([], HEIGHT + 2, TS + 2 * WEEK)
    assert ch.bal[BOB] == 200
    assert ch.bal[ALICE] == 10_000 - 3 - 206


def test_standing_cancel_stops_later_settlements():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    ch.block([standing_create_tx()], HEIGHT, TS)
    assert ch.bal[BOB] == 100

    result = ch.block([standing_cancel_tx(1)], HEIGHT + 1, TS + WEEK)
    assert result.outcomes[0].status == "applied"
    auth_id = standing_terms().auth_id
    state = ch.books().standing.authorizations[auth_id]
    assert state.status == "cancelled"
    # The sweep ran in the cancel block too, but a cancelled authorization
    # settles nothing.
    assert ch.bal[BOB] == 100


def test_policy_block_defers_and_a_missed_period_without_catch_up_skips():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    # The create itself measures only the fee; the sweep's debit is what
    # the payer's policy refuses, so period 0 stays unsettled.
    ch.block([standing_create_tx()], HEIGHT, TS, block_o5=True)
    assert ch.bal[BOB] == 0
    assert ch.bal[ALICE] == 10_000 - 3

    # A week later the policy allows again. Period 0 is missed and the
    # signed terms carry max_catch_up = 0 (skip), so only period 1 pays.
    ch.block([], HEIGHT + 1, TS + WEEK, block_o5=False)
    auth_id = standing_terms().auth_id
    state = ch.books().standing.authorizations[auth_id]
    assert state.skipped == {0} and set(state.settled) == {1}
    assert ch.bal[BOB] == 100


def test_standing_create_signed_by_a_non_payer_is_refused():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    # Bob signs a create naming Alice as payer: signature is valid for
    # the sender, but the payer did not sign.
    tx = standing_create_tx(payer=BOB, payee=CAROL, sk=SK_BOB)
    tx["payer"] = ALICE
    result = ch.block([tx], HEIGHT, TS)
    assert result.outcomes[0].status == "invalid"
    assert not ch.books().standing.authorizations
    assert ch.bal[CAROL] == 0


# --- payout rules ------------------------------------------------------------

def test_payout_install_and_execute_pays_each_event_exactly_once():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    terms = payout_terms()

    install = _base("payout_rule_install", ALICE, 0)
    install.update({
        "owner": ALICE,
        "candidates": [[pub, cap] for pub, cap in terms.candidates],
        "max_per_execution": 1000, "max_per_period": 1000,
        "period_kind": "week", "anchor_ts": TS,
    })
    result = ch.block([_sign(install, SK_ALICE)], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    assert ch.bal[ALICE] == 10_000 - 3

    execute = _base("payout_rule_execute", ALICE, 1)
    execute.update({
        "payout_rule_id": terms.rule_id.hex(),
        "event_id": "sale-1",
        "legs": [[0, 200], [1, 300]],
    })
    result = ch.block([_sign(execute, SK_ALICE)], HEIGHT + 1, TS + 10)
    assert result.outcomes[0].status == "applied"
    rule_state = ch.books().payouts.rules[terms.rule_id]
    assert set(rule_state.settled_events) == {"sale-1"}
    assert ch.bal[BOB] == 200 and ch.bal[CAROL] == 300
    assert ch.bal[ALICE] == 10_000 - 3 - 500

    # The same event submitted again is refused at the shared check: the
    # rule already settled it, so nobody is paid twice.
    replay = _base("payout_rule_execute", ALICE, 2)
    replay.update({
        "payout_rule_id": terms.rule_id.hex(),
        "event_id": "sale-1",
        "legs": [[0, 200], [1, 300]],
    })
    result = ch.block([_sign(replay, SK_ALICE)], HEIGHT + 2, TS + 20)
    assert result.outcomes[0].status == "invalid"
    assert result.outcomes[0].reason == "payment_not_applied"
    assert ch.bal[BOB] == 200 and ch.bal[CAROL] == 300


# --- grants ------------------------------------------------------------------

def test_grant_create_draw_and_refund_claim_at_apply():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})

    create = _base("payment_grant_create", ALICE, 0)
    create.update({
        "grantor": ALICE, "grantee": BOB, "principal": 1000,
        "period_cap": 500, "period_kind": "week", "start_ts": TS,
        "expires_ts": TS + 2 * WEEK, "max_fee_per_execution": 10,
    })
    result = ch.block([_sign(create, SK_ALICE)], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    assert ch.bal[ALICE] == 10_000 - 3 - 1000
    assert ch.bal[GRANT_ESCROW_PUBKEY] == 1000
    grant_id = next(iter(ch.books().grants.grants))

    draw = _base("payment_grant_draw", BOB, 0)
    draw.update({"grant_id": grant_id.hex(), "amount": 400})
    result = ch.block([_sign(draw, SK_BOB)], HEIGHT + 1, TS + 10)
    assert result.outcomes[0].status == "applied"
    assert ch.bal[BOB] == 400
    assert ch.bal[GRANT_ESCROW_PUBKEY] == 600

    # Anyone may trigger the refund after the deadline; Carol does. The
    # remainder returns to the grantor less the measured fee, and the
    # same block's sweep does not refund a second time.
    claim = _base("payment_grant_refund_claim", CAROL, 0)
    claim["grant_id"] = grant_id.hex()
    result = ch.block([_sign(claim, SK_CAROL)], HEIGHT + 2, TS + 2 * WEEK)
    assert result.outcomes[0].status == "applied"
    assert result.governance_changes["payment_refunds"] == []
    assert ch.bal[ALICE] == 10_000 - 3 - 1000 + 600 - 3
    assert ch.bal[GRANT_ESCROW_PUBKEY] == 0
    assert ch.bal[FEE_SINK_PUBKEY] == 3
    state = ch.books().grants.grants[grant_id]
    assert state.status == "closed" and state.refunded == 600

    ch.block([], HEIGHT + 3, TS + 3 * WEEK)
    assert ch.bal[ALICE] == 10_000 - 3 - 1000 + 600 - 3


# --- routes ------------------------------------------------------------------

def test_route_install_update_remove_at_apply():
    ch = Chain({ALICE: 0, BOB: 10_000, CAROL: 0, PROPOSER: 0})

    install = _base("payment_route_install", BOB, 0)
    install.update({"owner": BOB, "destinations": [[CAROL, 2000]]})
    result = ch.block([_sign(install, SK_BOB)], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    assert ch.books().routes.get(BOB).destinations == ((CAROL, 2000),)

    update = _base("payment_route_update", BOB, 1)
    update.update({"owner": BOB, "destinations": [[CAROL, 5000]]})
    result = ch.block([_sign(update, SK_BOB)], HEIGHT + 1, TS + 10)
    assert result.outcomes[0].status == "applied"
    assert ch.books().routes.get(BOB).destinations == ((CAROL, 5000),)

    remove = _base("payment_route_remove", BOB, 2)
    remove["owner"] = BOB
    result = ch.block([_sign(remove, SK_BOB)], HEIGHT + 2, TS + 20)
    assert result.outcomes[0].status == "applied"
    assert ch.books().routes.get(BOB) is None
    # Install and update are fee-bearing; removal is not.
    assert ch.bal[BOB] == 10_000 - 6
