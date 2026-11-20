"""Block-apply semantics for recipient-controlled receive routes (issue #35).

Every scenario runs the real `apply_block` with a scripted evaluator, then
compares the FULL balance map against amounts worked out by hand, so a credit
that goes to the wrong place, twice, or nowhere shows up as a mismatch. The
engine's own supply check runs on every block too.

The numbered acceptance criteria of the issue are named in the test names.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from block import Block
from consensus.approvals import STATUS_EXECUTED, STATUS_FAILED, parse_rule_change_request
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.receive_routes import (
    LOCK_NOTICE_SECONDS,
    MAX_ROUTE_BPS,
    ReceiveRoute,
    ReceiveRouteBook,
    compute_split,
    route_spec_text,
)
from consensus.retractable import parse_retractable_transfer
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_700_000_000
FAR = 9_999_999_999
# When a locked route installed at TS starts to route and bind.
BINDS = TS + LOCK_NOTICE_SECONDS


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_DAVE, DAVE = _key(77777)
SK_MALLORY, MALLORY = _key(66666)
PROPOSER = "d4" * 48
SK = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, DAVE: SK_DAVE, MALLORY: SK_MALLORY}

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def _base(sender, seq, tx_type, fee_limit="100"):
    return {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
    }


def route_tx(owner, dest, bps, seq, *, min_amount=None, active_from=None,
             expires_at=None, locked=None, signer=None, extra=None):
    tx = _base(owner, seq, "receive_route_set")
    tx["destination_pubkey"] = dest
    tx["route_bps"] = bps
    if min_amount is not None:
        tx["min_amount"] = min_amount
    if active_from is not None:
        tx["active_from_time"] = active_from
    if expires_at is not None:
        tx["expires_at_time"] = expires_at
    if locked is not None:
        tx["locked"] = locked
    tx.update(extra or {})
    return _sign(tx, SK[signer or owner])


def clear_tx(signer, owner, seq):
    tx = _base(signer, seq, "receive_route_clear")
    tx["route_owner_pubkey"] = owner
    return _sign(tx, SK[signer])


def spend_tx(sender, legs, seq, fee_limit="100"):
    if isinstance(legs, tuple):
        legs = [legs]
    tx = _base(sender, seq, "user_tx", fee_limit)
    tx["operations"] = {"1": [[sender, to, amount] for to, amount in legs]}
    return _sign(tx, SK[sender])


def park_tx(sender, to, amount, seq, at_height):
    tx = _base(sender, seq, "retractable_transfer")
    tx.update(recipient_pubkey=to, amount=amount, release_at_height=at_height,
              expire_at_height=at_height)
    return _sign(tx, SK[sender])


class Chain:
    def __init__(self, balances, *, fee=0, active=True):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        if active:
            self.lm.activate_receive_routes()
        self.fee = fee
        self.blocks = []    # (txs, height, ts) for replay
        self.hashes = []
        self.last = None
        self._genesis = (dict(balances), ConsensusLifecycleManager(active_validators=[ALICE]))

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        return {1: str(vals.get(1, "0")), 8: "0", 9: str(self.fee), 5: "1"}

    def block(self, txs, height=None, ts=TS, *, replay=False):
        height = HEIGHT + len(self.blocks) if height is None else height
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
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=self._multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = TauConsensusEngine().apply_block(view, blk, parent, replay_mode=replay)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.blocks.append((txs, height, ts))
        self.hashes.append(result.next_snapshot.state_hash)
        self.last = result
        return result

    @property
    def routes(self) -> ReceiveRouteBook:
        return self.lm.receive_routes

    def nonzero(self):
        return {k: v for k, v in self.bal.items() if v}

    def receipt(self, tx):
        return self.last_receipts().get(tx["tx_id"], {})

    def last_receipts(self):
        return {o.tx_id: o for o in self.last.outcomes}


def _balances():
    return {ALICE: 10_000, BOB: 0, CAROL: 0, DAVE: 0, PROPOSER: 0}


def _events(result, kind=None):
    events = result.governance_changes["receive_route_events"]
    return [e for e in events if kind is None or e["kind"] == kind]


def _status(result, tx):
    for outcome in result.outcomes:
        if outcome.tx_id == tx["tx_id"]:
            return outcome.status, outcome.reason
    raise AssertionError("tx not in block")


# --- AC1: canonical split ------------------------------------------------------

def test_ac1_twenty_percent_route_splits_by_floor_rounding():
    ch = Chain(_balances())
    ch.block([route_tx(BOB, CAROL, 2000, 0)])
    ch.block([spend_tx(ALICE, (BOB, 101), 0)])
    # 101 * 20% = 20.2 -> 20 routed, 81 net.
    assert ch.bal[BOB] == 81
    assert ch.bal[CAROL] == 20
    assert ch.bal[ALICE] == 10_000 - 101


@pytest.mark.parametrize("gross,bps,routed", [
    (100, 2000, 20), (101, 2000, 20), (4, 2500, 1), (3, 2500, 0),
    (16_777_215, 9000, 15_099_493), (1, 9000, 0), (10_000, 1, 1), (9_999, 1, 0),
])
def test_ac1_rounding_rule_is_floor_of_gross(gross, bps, routed):
    route = ReceiveRoute(BOB, CAROL, bps)
    split = compute_split(route, gross, "transfer")
    if routed == 0:
        assert split is None
    else:
        assert (split.routed, split.net) == (routed, gross - routed)
        assert split.net + split.routed == gross


def test_an_install_the_owner_cannot_pay_for_is_rejected():
    ch = Chain(_balances(), fee=7)
    tx = route_tx(BOB, CAROL, 2000, 0)
    result = ch.block([tx])
    assert _status(result, tx) == ("invalid", "insufficient_funds_for_fee")
    assert ch.routes.is_empty()


def test_ac1_sender_fee_is_separate_and_routing_adds_none():
    ch = Chain({**_balances(), BOB: 50}, fee=7)
    ch.block([route_tx(BOB, CAROL, 2000, 0)])
    assert ch.bal[BOB] == 43 and ch.bal[PROPOSER] == 7
    result = ch.block([spend_tx(ALICE, (BOB, 1000), 0)])
    assert ch.bal[ALICE] == 10_000 - 1000 - 7
    assert ch.bal[BOB] == 43 + 800
    assert ch.bal[CAROL] == 200
    assert ch.bal[PROPOSER] == 14
    (split,) = _events(result, "split")
    assert split["fee_charged"] == 7 and split["routing_fee"] == 0


def test_min_amount_leaves_small_credits_whole():
    ch = Chain(_balances())
    ch.block([route_tx(BOB, CAROL, 5000, 0, min_amount=100)])
    ch.block([spend_tx(ALICE, [(BOB, 99), (BOB, 100)], 0)])
    assert ch.bal[BOB] == 99 + 50
    assert ch.bal[CAROL] == 50


# --- AC2: recipient online or offline ------------------------------------------

def test_ac2_same_result_whether_the_recipient_is_active_or_not():
    def run(recipient_active: bool):
        ch = Chain({**_balances(), BOB: 500})
        ch.block([route_tx(BOB, CAROL, 2500, 0)])
        txs = [spend_tx(ALICE, (BOB, 400), 0)]
        if recipient_active:
            # The recipient is online and sending in the same block.
            txs.append(spend_tx(BOB, (DAVE, 10), 1))
        ch.block(txs)
        return ch

    offline = run(False)
    online = run(True)
    assert offline.bal[CAROL] == online.bal[CAROL] == 100
    assert offline.bal[BOB] == 500 + 300
    assert online.bal[BOB] == 500 + 300 - 10
    # The recipient signed nothing in the offline run, yet the split happened.
    assert offline.seq.get(BOB) == 1


# --- AC3: no bypass -------------------------------------------------------------

def test_ac3_every_ordinary_transfer_form_is_routed():
    ch = Chain({**_balances(), DAVE: 1000})
    ch.block([route_tx(BOB, CAROL, 1000, 0)])
    # Multi-leg transfer, a second sender, and the destination itself paying in.
    ch.block([
        spend_tx(ALICE, [(BOB, 100), (DAVE, 5), (BOB, 200)], 0),
        spend_tx(DAVE, (BOB, 1000), 0),
    ])
    assert ch.bal[BOB] == 90 + 180 + 900
    assert ch.bal[CAROL] == 10 + 20 + 100
    ch.block([spend_tx(CAROL, (BOB, 100), 0)])
    # The destination's own payment to the owner is split too: 10% comes back.
    assert ch.bal[BOB] == 90 + 180 + 900 + 90
    assert ch.bal[CAROL] == 130 - 100 + 10


def test_ac3_a_claimed_payment_release_is_routed():
    ch = Chain(_balances())
    ch.block([route_tx(BOB, CAROL, 2000, 0)], height=HEIGHT)
    park = park_tx(ALICE, BOB, 500, 0, at_height=HEIGHT + 3)
    ch.block([park], height=HEIGHT + 1)
    assert ch.bal[BOB] == 0
    result = ch.block([], height=HEIGHT + 3)
    assert ch.bal[BOB] == 400 and ch.bal[CAROL] == 100
    (split,) = _events(result, "split")
    rid = parse_retractable_transfer(park).retractable_id.hex()
    assert split["source"] == f"retractable:{rid}"
    assert split["credit_class"] == "claimed_payment"


def test_excluded_credits_are_not_routed_fee_and_retract_refund():
    # The proposer installs a route; fees it earns are not split.
    ch = Chain({**_balances(), PROPOSER: 100}, fee=5)
    ch.lm.receive_routes.install(ReceiveRoute(PROPOSER, CAROL, 5000))
    ch.block([spend_tx(ALICE, (DAVE, 10), 0)])
    assert ch.bal[PROPOSER] == 105 and ch.bal[CAROL] == 0
    # A retract refund to a routed sender is not split.
    ch = Chain(_balances())
    ch.lm.receive_routes.install(ReceiveRoute(ALICE, CAROL, 5000))
    park = park_tx(ALICE, BOB, 500, 0, at_height=HEIGHT + 10)
    ch.block([park])
    rid = parse_retractable_transfer(park).retractable_id.hex()
    retract = _sign({**_base(ALICE, 1, "retract_transfer", "0"), "retractable_id": rid}, SK_ALICE)
    ch.block([retract])
    assert ch.bal[ALICE] == 10_000 and ch.bal[CAROL] == 0


def test_routed_amount_does_not_count_as_the_recipients_spend():
    ch = Chain({**_balances(), BOB: 10})
    ch.block([route_tx(BOB, CAROL, 2000, 0)])
    lts_after_install = dict(ch.lts)
    ch.block([spend_tx(ALICE, (BOB, 1000), 0)])
    # Only the sender's last-transfer stamp moved.
    assert ch.lts.get(BOB) == lts_after_install.get(BOB)
    assert ch.lts[ALICE] == TS


# --- AC4: rejected routes -------------------------------------------------------

@pytest.mark.parametrize("name,factory,reason", [
    ("self_route", lambda: route_tx(BOB, BOB, 2000, 0), "receive_route_not_applied"),
    ("zero_bps", lambda: route_tx(BOB, CAROL, 0, 0), "receive_route_not_applied"),
    ("over_cap", lambda: route_tx(BOB, CAROL, MAX_ROUTE_BPS + 1, 0), "receive_route_not_applied"),
    ("hundred_percent", lambda: route_tx(BOB, CAROL, 10_000, 0), "receive_route_not_applied"),
    ("invalid_key", lambda: route_tx(BOB, "ab" * 48, 2000, 0), "invalid_recipient_key"),
    ("malformed_key", lambda: route_tx(BOB, "xyz", 2000, 0), "invalid_recipient_key"),
    ("locked_no_expiry", lambda: route_tx(BOB, CAROL, 2000, 0, locked=True), "receive_route_not_applied"),
    ("expiry_past", lambda: route_tx(BOB, CAROL, 2000, 0, expires_at=TS), "receive_route_not_applied"),
    ("bad_locked_type", lambda: route_tx(BOB, CAROL, 2000, 0, locked="yes"), "receive_route_not_applied"),
    ("forged", lambda: route_tx(BOB, CAROL, 2000, 0, signer=MALLORY), "invalid_signature"),
])
def test_ac4_bad_routes_are_rejected_and_change_nothing(name, factory, reason):
    ch = Chain({**_balances(), BOB: 100})
    before = (ch.nonzero(), ch.routes.root(), ch.lm.consensus_meta_hash())
    tx = factory()
    result = ch.block([tx])
    status, got_reason = _status(result, tx)
    assert status == "invalid"
    assert got_reason == reason
    assert ch.routes.is_empty()
    assert (ch.nonzero(), ch.routes.root(), ch.lm.consensus_meta_hash()) == before
    # A transfer to BOB afterwards is credited whole.
    ch.block([spend_tx(ALICE, (BOB, 100), 0)])
    assert ch.bal[BOB] == 200


def test_ac4_routing_is_single_hop():
    ch = Chain({**_balances(), BOB: 10, CAROL: 10})
    ch.block([route_tx(BOB, CAROL, 5000, 0), route_tx(CAROL, DAVE, 5000, 0)])
    ch.block([spend_tx(ALICE, (BOB, 1000), 0)])
    # CAROL's route does not fire on the share routed to her.
    assert (ch.bal[BOB], ch.bal[CAROL], ch.bal[DAVE]) == (510, 510, 0)
    # A cycle (CAROL -> BOB while BOB -> CAROL) is still one hop per credit.
    ch.block([route_tx(CAROL, BOB, 5000, 1)])
    ch.block([spend_tx(ALICE, (CAROL, 100), 1)])
    assert (ch.bal[BOB], ch.bal[CAROL]) == (560, 560)


def test_ac4_supply_is_conserved_across_route_traffic():
    ch = Chain({**_balances(), BOB: 100, CAROL: 100}, fee=3)
    total = sum(ch.bal.values())
    ch.block([route_tx(BOB, CAROL, 3333, 0), route_tx(CAROL, DAVE, 9000, 0)])
    ch.block([spend_tx(ALICE, [(BOB, 997), (CAROL, 13), (DAVE, 1)], 0)])
    ch.block([spend_tx(BOB, (CAROL, 7), 1), clear_tx(CAROL, BOB, 1)])
    assert sum(ch.bal.values()) == total
    assert min(ch.bal.values()) >= 0


def test_a_new_destination_account_gets_the_routed_share_as_a_new_record():
    ch = Chain({ALICE: 10_000, BOB: 10, PROPOSER: 0})
    ch.block([route_tx(BOB, CAROL, 2000, 0)])
    ch.block([spend_tx(ALICE, (BOB, 100), 0)])
    assert ch.bal[CAROL] == 20


# --- AC5: protected administration ----------------------------------------------

def test_replace_and_owner_clear_of_an_unlocked_route():
    ch = Chain({**_balances(), BOB: 100})
    ch.block([route_tx(BOB, CAROL, 2000, 0)])
    result = ch.block([route_tx(BOB, DAVE, 1000, 1)])
    assert ch.routes.get(BOB).destination_pubkey == DAVE
    assert _events(result)[0]["kind"] == "replaced"
    ch.block([spend_tx(ALICE, (BOB, 100), 0)])
    assert ch.bal[DAVE] == 10 and ch.bal[CAROL] == 0
    result = ch.block([clear_tx(BOB, BOB, 2)])
    assert ch.routes.is_empty()
    (event,) = _events(result)
    assert event["kind"] == "cleared" and event["cleared_by"] == "owner"


def test_ac5_a_locked_route_cannot_be_redirected_or_dropped_by_the_owner():
    ch = Chain({**_balances(), BOB: 100})
    ch.block([route_tx(BOB, CAROL, 2000, 0, locked=True, expires_at=BINDS + 1000)])
    for attempt in (route_tx(BOB, MALLORY, 9000, 1), clear_tx(BOB, BOB, 1)):
        result = ch.block([attempt], ts=BINDS)
        assert _status(result, attempt) == ("invalid", "receive_route_not_applied")
        assert ch.routes.get(BOB).destination_pubkey == CAROL
    # Strangers cannot clear it either.
    stranger = clear_tx(MALLORY, BOB, 0)
    result = ch.block([stranger], ts=BINDS)
    assert _status(result, stranger)[0] == "invalid"


def test_a_locked_route_neither_routes_nor_binds_during_its_notice_period():
    """A stolen key can install a locked route, but the owner has the notice
    period to see it and take it back before it routes anything."""
    ch = Chain({**_balances(), BOB: 100})
    result = ch.block([route_tx(BOB, MALLORY, 9000, 0, locked=True, expires_at=BINDS + 1000)])
    (installed,) = _events(result)
    assert installed["installed_at_time"] == TS and installed["binds_from_time"] == BINDS
    ch.block([spend_tx(ALICE, (BOB, 100), 0)], ts=BINDS - 1)
    assert ch.bal.get(MALLORY, 0) == 0 and ch.bal[BOB] == 200, "nothing routed during notice"
    assert ch.routes.get(BOB).status(BINDS - 1) == "scheduled"
    result = ch.block([clear_tx(BOB, BOB, 1)], ts=BINDS - 1)
    assert ch.routes.is_empty()
    assert _events(result)[0]["cleared_by"] == "owner"


def test_a_replaced_locked_route_starts_a_new_notice_period():
    ch = Chain({**_balances(), BOB: 100})
    ch.block([route_tx(BOB, CAROL, 2000, 0, locked=True, expires_at=BINDS + 9000)])
    later = TS + 100
    ch.block([route_tx(BOB, DAVE, 1000, 1, locked=True, expires_at=BINDS + 9000)], ts=later)
    assert ch.routes.get(BOB).starts_at() == later + LOCK_NOTICE_SECONDS


def test_a_lock_shorter_than_its_notice_period_is_refused():
    ch = Chain({**_balances(), BOB: 100})
    tx = route_tx(BOB, CAROL, 2000, 0, locked=True, expires_at=BINDS)
    result = ch.block([tx])
    assert _status(result, tx) == ("invalid", "receive_route_not_applied")
    assert ch.routes.is_empty()


def test_ac5_the_destination_may_release_a_locked_route():
    ch = Chain({**_balances(), BOB: 100})
    ch.block([route_tx(BOB, CAROL, 2000, 0, locked=True, expires_at=BINDS + 1000)])
    result = ch.block([clear_tx(CAROL, BOB, 0)], ts=BINDS)
    assert ch.routes.is_empty()
    assert _events(result)[0]["cleared_by"] == "destination"


def test_ac5_a_locked_route_ends_at_expiry_and_the_owner_regains_control():
    ch = Chain({**_balances(), BOB: 100})
    ch.block([route_tx(BOB, CAROL, 2000, 0, locked=True, expires_at=BINDS + 100)])
    ch.block([spend_tx(ALICE, (BOB, 100), 0)], ts=BINDS + 99)
    assert ch.bal[CAROL] == 20
    result = ch.block([spend_tx(ALICE, (BOB, 100), 1)], ts=BINDS + 100)
    # Expired at BINDS + 100: that credit is whole and the sweep drops the route.
    assert ch.bal[CAROL] == 20 and ch.bal[BOB] == 100 + 80 + 100
    assert ch.routes.is_empty()
    assert _events(result, "cleared")[0]["cleared_by"] == "expiry"
    ch.block([route_tx(BOB, DAVE, 1000, 1)], ts=BINDS + 101)
    assert ch.routes.get(BOB).destination_pubkey == DAVE


def test_ac5_rule_change_guard_gates_route_changes_by_the_owner():
    ch = Chain({**_balances(), BOB: 100})
    ch.block([route_tx(BOB, CAROL, 2000, 0)])
    ch.lm.rule_offers.accepted_clauses[(BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = "guard"
    seen = []

    def guard(body, values, **kwargs):
        seen.append(values)
        return True, "0"

    with patch("consensus.sender_policy.clause_blocks", side_effect=guard):
        for attempt in (route_tx(BOB, MALLORY, 9000, 1), clear_tx(BOB, BOB, 1)):
            result = ch.block([attempt])
            assert _status(result, attempt) == ("invalid", "rule_change_needs_approval")
        assert ch.routes.get(BOB).destination_pubkey == CAROL
        # The guard saw the route kinds on i1.
        kinds = [str(v.get("i1")) for v in seen]
        assert kinds == [str(tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE),
                         str(tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE)]
        # The destination giving up its share is not a change the owner's guard owns.
        ch.block([clear_tx(CAROL, BOB, 0)])
        assert ch.routes.is_empty()


def test_ac5_a_guard_that_allows_lets_the_change_through():
    ch = Chain({**_balances(), BOB: 100})
    ch.lm.rule_offers.accepted_clauses[(BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = "guard"
    with patch("consensus.sender_policy.clause_blocks", return_value=(False, "1")):
        ch.block([route_tx(BOB, CAROL, 2000, 0)])
    assert ch.routes.get(BOB) is not None


# --- scheduling -------------------------------------------------------------------

def test_a_scheduled_route_starts_at_its_activation_time():
    ch = Chain({**_balances(), BOB: 10})
    ch.block([route_tx(BOB, CAROL, 5000, 0, active_from=TS + 50)])
    ch.block([spend_tx(ALICE, (BOB, 100), 0)], ts=TS + 49)
    assert ch.bal[CAROL] == 0
    ch.block([spend_tx(ALICE, (BOB, 100), 1)], ts=TS + 50)
    assert ch.bal[CAROL] == 50


# --- AC6: receipts ----------------------------------------------------------------

def test_ac6_receipts_and_block_events_show_gross_net_routed_and_fee():
    ch = Chain({**_balances(), BOB: 50}, fee=4)
    result = ch.block([route_tx(BOB, CAROL, 2500, 0)])
    (installed,) = _events(result)
    assert installed["kind"] == "installed"
    assert installed["owner_pubkey"] == BOB and installed["bps"] == 2500
    assert installed["fee_charged"] == 4
    send = spend_tx(ALICE, (BOB, 400), 0)
    result = ch.block([send])
    (split,) = _events(result, "split")
    assert split == {
        "kind": "split", "tx_index": 0, "source": "transfer",
        "recipient_pubkey": BOB, "destination_pubkey": CAROL,
        "gross": 400, "net": 300, "routed": 100, "bps": 2500,
        "route_version": 0, "credit_class": "transfer",
        "fee_charged": 4, "routing_fee": 0,
    }
    assert result.next_snapshot.metadata["receive_route_events"] == _events(result)
    assert any("Receive route: 400" in log for log in ch.last_receipts()[send["tx_id"]].receipt_logs)


# --- AC7: determinism ------------------------------------------------------------

def _scenario():
    ch = Chain({**_balances(), BOB: 100, CAROL: 100}, fee=2)
    ch.block([route_tx(BOB, CAROL, 2000, 0), route_tx(CAROL, DAVE, 300, 0, expires_at=TS + 30)])
    ch.block([spend_tx(ALICE, [(BOB, 777), (CAROL, 55)], 0)], ts=TS + 10)
    ch.block([park_tx(ALICE, BOB, 333, 1, at_height=HEIGHT + 4)], ts=TS + 20)
    ch.block([spend_tx(BOB, (CAROL, 9), 1)], ts=TS + 30)
    ch.block([], ts=TS + 40)
    ch.block([route_tx(BOB, DAVE, 9000, 2, locked=True, expires_at=BINDS + 500)], ts=TS + 50)
    ch.block([spend_tx(ALICE, (BOB, 1001), 2)], ts=TS + 60)
    return ch


def test_ac7_the_same_blocks_give_the_same_state_every_time():
    first, second = _scenario(), _scenario()
    assert first.hashes == second.hashes
    assert first.bal == second.bal
    assert first.routes.root() == second.routes.root()


def test_ac7_replay_mode_reproduces_the_mined_chain():
    mined = _scenario()
    replay = Chain({**_balances(), BOB: 100, CAROL: 100}, fee=2)
    for txs, height, ts in mined.blocks:
        replay.block(txs, height=height, ts=ts, replay=True)
    assert replay.hashes == mined.hashes
    assert replay.bal == mined.bal


def test_ac7_restoring_the_book_from_rows_keeps_the_meta_hash():
    ch = _scenario()
    rows = [
        (r["owner_pubkey"], r["destination_pubkey"], r["bps"], r["min_amount"],
         r["active_from"], r["expires_at"], r["locked"], r["version"], r["installed_at"])
        for r in ch.routes.snapshot_rows()
    ]
    before = ch.lm.consensus_meta_hash()
    ch.lm.receive_routes = ReceiveRouteBook.restore(rows)
    assert ch.lm.consensus_meta_hash() == before


def test_the_route_book_joins_the_meta_hash_only_while_non_empty():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    empty = lm.consensus_meta_hash()
    del lm.receive_routes  # a manager from before the field existed
    assert lm.consensus_meta_hash() == empty
    lm.receive_routes = ReceiveRouteBook()
    lm.receive_routes.install(ReceiveRoute(BOB, CAROL, 100))
    installed = lm.consensus_meta_hash()
    assert installed != empty
    lm.receive_routes.install(ReceiveRoute(BOB, CAROL, 101))
    assert lm.consensus_meta_hash() not in (empty, installed)
    lm.receive_routes.clear(BOB)
    assert lm.consensus_meta_hash() == empty


# --- same block ---------------------------------------------------------------------

def test_a_route_installed_earlier_in_a_block_splits_a_later_transfer_in_it():
    ch = Chain({**_balances(), BOB: 10})
    result = ch.block([route_tx(BOB, CAROL, 2000, 0), spend_tx(ALICE, (BOB, 100), 0)])
    assert (ch.bal[BOB], ch.bal[CAROL]) == (10 + 80, 20)
    assert [e["kind"] for e in _events(result)] == ["installed", "split"]


def test_an_explicit_null_lock_installs_like_an_absent_one():
    ch = Chain({**_balances(), BOB: 10})
    tx = route_tx(BOB, CAROL, 2000, 0, extra={"locked": None})
    ch.block([tx])
    assert ch.routes.get(BOB).locked is False


# --- guarded changes parked as rule_change_request kinds 6 and 7 ------------------

KIND_SET_ROUTE = tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE
KIND_CLEAR_ROUTE = tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE


def request_tx(owner, kind, seq, rule_text="", *, expire_at=HEIGHT + 2500):
    tx = _base(owner, seq, "rule_change_request")
    tx["expire_at_height"] = expire_at
    tx["kind"] = kind
    tx["approvers"] = {}
    if rule_text:
        tx["rule_text"] = rule_text
    return _sign(tx, SK[owner])


def _guard(ch, owner):
    ch.lm.rule_offers.accepted_clauses[(owner, tau_defs.RULE_CHANGE_GUARD_INDEX)] = "guard"


def test_an_unguarded_parked_install_is_released_in_its_own_block():
    ch = Chain({**_balances(), BOB: 10})
    tx = request_tx(BOB, KIND_SET_ROUTE, 0, route_spec_text(CAROL, 2000, min_amount=5))
    result = ch.block([tx])
    route = ch.routes.get(BOB)
    assert (route.destination_pubkey, route.bps, route.min_amount, route.version) == \
        (CAROL, 2000, 5, 0)
    (event,) = _events(result)
    rid = parse_rule_change_request(tx).request_id.hex()
    assert event["kind"] == "installed" and event["source"] == f"rule_change:{rid}"
    ch.block([spend_tx(ALICE, (BOB, 100), 0)])
    assert ch.bal[CAROL] == 20


def test_a_guard_blocked_route_change_is_parked_and_released_by_the_time_escape():
    ch = Chain({**_balances(), BOB: 10})
    _guard(ch, BOB)
    with patch("consensus.sender_policy.clause_blocks", return_value=(True, "0")):
        direct = route_tx(BOB, CAROL, 2000, 0)
        result = ch.block([direct], height=HEIGHT)
        assert _status(result, direct) == ("invalid", "rule_change_needs_approval")
        parked = request_tx(BOB, KIND_SET_ROUTE, 0, route_spec_text(CAROL, 2000))
        ch.block([parked], height=HEIGHT + 1)
        assert ch.routes.is_empty(), "the guard blocks it until approvals or the delay"
        result = ch.block([], height=HEIGHT + 1 + tau_defs.RULE_CHANGE_DELAY_BLOCKS)
    assert ch.routes.get(BOB).destination_pubkey == CAROL
    assert _events(result)[0]["kind"] == "installed"
    rid = parse_rule_change_request(parked).request_id
    assert ch.lm.approval_requests.get_rule_change(rid).status == STATUS_EXECUTED


def test_a_parked_clear_removes_the_owners_route():
    ch = Chain({**_balances(), BOB: 10})
    ch.block([route_tx(BOB, CAROL, 2000, 0)])
    result = ch.block([request_tx(BOB, KIND_CLEAR_ROUTE, 1)])
    assert ch.routes.is_empty()
    (event,) = _events(result)
    assert event["kind"] == "cleared" and event["cleared_by"] == "owner"


def test_a_parked_change_that_cannot_be_written_at_release_fails_and_changes_nothing():
    ch = Chain({**_balances(), BOB: 10})
    _guard(ch, BOB)
    with patch("consensus.sender_policy.clause_blocks", return_value=(True, "0")):
        parked = request_tx(BOB, KIND_SET_ROUTE, 0,
                            route_spec_text(CAROL, 2000, expires_at_time=TS + 10))
        ch.block([parked], height=HEIGHT, ts=TS)
        # By the time the delay passes, the route's expiry is in the past.
        result = ch.block([], height=HEIGHT + tau_defs.RULE_CHANGE_DELAY_BLOCKS, ts=TS + 20)
    assert ch.routes.is_empty()
    assert _events(result) == []
    rid = parse_rule_change_request(parked).request_id
    assert ch.lm.approval_requests.get_rule_change(rid).status == STATUS_FAILED


def test_a_parked_install_refused_while_the_current_route_is_locked():
    ch = Chain({**_balances(), BOB: 10})
    ch.block([route_tx(BOB, CAROL, 2000, 0, locked=True, expires_at=BINDS + 1000)])
    tx = request_tx(BOB, KIND_SET_ROUTE, 1, route_spec_text(DAVE, 9000))
    result = ch.block([tx], ts=BINDS)
    assert _status(result, tx)[0] == "invalid"
    assert ch.routes.get(BOB).destination_pubkey == CAROL


def test_a_parked_locked_install_starts_its_notice_period_at_release():
    ch = Chain({**_balances(), BOB: 10})
    released_at = TS + 30
    spec = route_spec_text(CAROL, 2000, expires_at_time=TS + 2 * LOCK_NOTICE_SECONDS,
                           locked=True)
    ch.block([request_tx(BOB, KIND_SET_ROUTE, 0, spec)], ts=released_at)
    route = ch.routes.get(BOB)
    assert route.installed_at == released_at
    assert route.starts_at() == released_at + LOCK_NOTICE_SECONDS


# --- activation ---------------------------------------------------------------------

def test_before_activation_every_route_change_is_refused_and_nothing_is_split():
    ch = Chain({**_balances(), BOB: 10}, active=False)
    direct = route_tx(BOB, CAROL, 2000, 0)
    parked = request_tx(BOB, KIND_SET_ROUTE, 0, route_spec_text(CAROL, 2000))
    before = ch.lm.consensus_meta_hash()
    for tx in (direct, parked):
        result = ch.block([tx])
        assert _status(result, tx)[0] == "invalid"
    assert ch.routes.is_empty()
    assert ch.lm.consensus_meta_hash() == before
    ch.block([spend_tx(ALICE, (BOB, 100), 0)])
    assert ch.bal[BOB] == 110


def test_activation_is_a_one_way_governance_patch_bound_into_the_meta_hash():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    off = lm.consensus_meta_hash()
    with pytest.raises(ValueError):
        lm.apply_host_contract_patch({"receive_routes_active": False})
    assert lm.receive_routes_active is False
    lm.apply_host_contract_patch({"receive_routes_active": True})
    assert lm.receive_routes_active is True
    on = lm.consensus_meta_hash()
    assert on != off
    lm.apply_host_contract_patch({"receive_routes_active": True})   # idempotent
    assert lm.consensus_meta_hash() == on
