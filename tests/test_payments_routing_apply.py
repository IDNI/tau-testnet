"""Route enforcement on live credits (Bounty 01, #35 — wiring W1 closure).

Book-level routing (test_payments_routes.py) proved the split arithmetic;
these tests prove the ENGINE routes real credits through the recipient's
route, in the same scripted-Tau apply_block idiom as
test_payments_apply.py:

- an ordinary user_tx transfer to a routed account splits at apply —
  recipient keeps the net, legs land as final credits, and the transfer
  pays exactly ONE fee (the fee-era step fee; the split charges none);
- a routed leg never triggers the destination's own route;
- a standing-payment settlement credit is NOT routed (the design's v1
  credit classes: plain transfers and claimed/released payments route;
  standing and payout credits do not);
- a retractable RELEASE to a routed account splits (the claimed class);
- replaying a routed transfer's block reproduces identical balances;
- a transfer to an account with no route is untouched.
"""
import hashlib
import itertools
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.payments import FEE_SINK_PUBKEY
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
SK_DAVE, DAVE = 66666, G2Basic.SkToPk(66666).hex()
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()
_SKS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, DAVE: SK_DAVE}


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


def route_install_tx(owner, destinations, seq):
    tx = _base("payment_route_install", owner, seq)
    tx.update({"owner": owner, "destinations": destinations})
    return _sign(tx, _SKS[owner])


def spend_tx(sender, to, amount, seq):
    tx = _base("user_tx", sender, seq)
    tx["operations"] = {"1": [[sender, to, amount]]}
    return _sign(tx, _SKS[sender])


def standing_create_tx(seq=0):
    tx = _base("standing_authorization_create", ALICE, seq)
    tx.update({
        "payer": ALICE, "payee": BOB, "amount": 100,
        "period_kind": "week", "start_ts": TS,
        "end_kind": "count", "end_value": 2,
        "max_fee_per_execution": 10, "genesis_hash": GENESIS_HASH,
        "max_catch_up": 0,
    })
    return _sign(tx, SK_ALICE)


def park_tx(seq, release_at_height, amount=100):
    tx = _base("retractable_transfer", ALICE, seq)
    tx.update({
        "recipient_pubkey": BOB, "amount": amount,
        "release_at_height": release_at_height,
    })
    return _sign(tx, SK_ALICE)


class Chain:
    """One chain advanced block by block through the real apply path."""

    def __init__(self, balances, *, fee=3):
        self.fee = fee
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        from consensus.governance import ConsensusLifecycleManager
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.lm.activate_approval_slots()

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = str(vals.get(1, "0"))
        return {1: amount, 8: "0", 9: str(self.fee), 5: "1"}

    def block(self, txs, height, ts, *, replay=False):
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
            result = engine.apply_block(view, blk, parent, replay_mode=replay)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        return result

    def books(self):
        return self.lm.programmable_payments


def _logs(result, i=0):
    return " | ".join(result.outcomes[i].receipt_logs or [])


# --- (a) the ordinary transfer splits, with exactly one fee -----------------

def test_transfer_to_routed_recipient_splits_with_one_fee():
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, PROPOSER: 0})
    result = ch.block([route_install_tx(BOB, [[CAROL, 2000]], 0)], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    assert ch.bal[BOB] == 1_000 - 3  # the install's own fee

    result = ch.block([spend_tx(ALICE, BOB, 101, 0)], HEIGHT + 1, TS + 10)
    assert result.outcomes[0].status == "applied"
    # 101 at 20%: 20 routed to Carol, 81 kept by Bob (the design's case 1).
    assert ch.bal[CAROL] == 20
    assert ch.bal[BOB] == 1_000 - 3 + 81
    # Exactly ONE fee for the whole credit: Alice paid 101 + the single
    # fee-era step fee of 3, which went to the proposer. The split charged
    # nothing — in particular nothing reached the payments fee sink.
    assert ch.bal[ALICE] == 10_000 - 101 - 3
    assert ch.bal[PROPOSER] == 3 + 3
    assert ch.bal.get(FEE_SINK_PUBKEY, 0) == 0
    assert "Transfer routed" in _logs(result)


# --- (b) a routed leg never re-routes ---------------------------------------

def test_routed_leg_does_not_trigger_destinations_own_route():
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 1_000, DAVE: 0,
                PROPOSER: 0})
    ch.block([route_install_tx(BOB, [[CAROL, 2000]], 0)], HEIGHT, TS)
    ch.block([route_install_tx(CAROL, [[DAVE, 5000]], 0)], HEIGHT + 1, TS + 10)

    result = ch.block([spend_tx(ALICE, BOB, 101, 0)], HEIGHT + 2, TS + 20)
    assert result.outcomes[0].status == "applied"
    # Carol's leg is a FINAL credit: her own 50% route does not split it.
    assert ch.bal[CAROL] == 1_000 - 3 + 20
    assert ch.bal[DAVE] == 0
    assert ch.bal[BOB] == 1_000 - 3 + 81


# --- (c) standing settlements are not routed (design's v1 classes) ----------

def test_standing_settlement_to_routed_recipient_is_not_routed():
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, PROPOSER: 0})
    ch.block([route_install_tx(BOB, [[CAROL, 2000]], 0)], HEIGHT, TS)

    result = ch.block([standing_create_tx()], HEIGHT + 1, TS)
    assert result.outcomes[0].status == "applied"
    # The create block's sweep settles period 0: Bob is credited the full
    # 100 — a standing-payment credit is not a routable class in v1, so
    # Bob's route does not split it and Carol gets nothing.
    assert ch.bal[BOB] == 1_000 - 3 + 100
    assert ch.bal[CAROL] == 0
    assert ch.bal[FEE_SINK_PUBKEY] == 3  # the settlement's execution fee


# --- (d) replay determinism ---------------------------------------------------

def test_routed_transfer_replays_to_identical_balances():
    def run(replay_transfer):
        ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, PROPOSER: 0})
        ch.block([route_install_tx(BOB, [[CAROL, 2000]], 0)], HEIGHT, TS)
        ch.block([spend_tx(ALICE, BOB, 101, 0)], HEIGHT + 1, TS + 10,
                 replay=replay_transfer)
        return ch.bal

    live = run(False)
    replayed = run(True)
    assert replayed == live
    assert live[BOB] == 1_000 - 3 + 81 and live[CAROL] == 20


# --- (e) no route: the transfer is untouched ---------------------------------

def test_transfer_without_route_is_untouched():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    result = ch.block([spend_tx(ALICE, BOB, 101, 0)], HEIGHT, TS)
    assert result.outcomes[0].status == "applied"
    # The pristine outcome, exactly: full credit, one step fee.
    assert ch.bal[BOB] == 101
    assert ch.bal[ALICE] == 10_000 - 101 - 3
    assert ch.bal[PROPOSER] == 3
    assert "Transfer routed" not in _logs(result)


# --- (f) a retractable release splits (the claimed class) ---------------------

def test_retractable_release_to_routed_recipient_splits():
    ch = Chain({ALICE: 10_000, BOB: 1_000, CAROL: 0, PROPOSER: 0})
    ch.block([route_install_tx(BOB, [[CAROL, 2000]], 0)], HEIGHT, TS)

    result = ch.block([park_tx(0, HEIGHT + 3)], HEIGHT + 1, TS + 10)
    assert result.outcomes[0].status == "applied"
    # Parked: the gross sits in the retractable book's escrow; the park
    # paid its one fee. Nobody has been credited yet.
    assert ch.bal[ALICE] == 10_000 - 100 - 3
    assert ch.bal[BOB] == 1_000 - 3 and ch.bal[CAROL] == 0

    result = ch.block([], HEIGHT + 3, TS + 30)
    # The release is a claimed (released) payment — a routable class in
    # v1: Bob keeps 80, Carol's final leg is 20, and the release itself
    # charges no fee (Alice's balance does not move in this block).
    assert ch.bal[BOB] == 1_000 - 3 + 80
    assert ch.bal[CAROL] == 20
    assert ch.bal[ALICE] == 10_000 - 100 - 3
