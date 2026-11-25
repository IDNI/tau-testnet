"""Bounty 01, issue #35: receive routes at the engine seam (mock Tau).

Slice 3 of DESIGN-01-TAKEOVER.md: the route book is wired into
`_execute_fee_era_transfer`, so an ordinary credit to an opted-in account is
split in the same staged write set as the credit itself. These tests drive
the real block-apply path with a scripted evaluator (the
test_approval_apply pattern): o5 always allows, o9 prices every evaluation
at a fixed fee, so fee accounting is exact.

Covered here: named cases 1 and 3 end-to-end at engine level, the route-level
5% split (the payout slice owns named case 2's settlement-idempotency form),
#35-5 (install/remove administration incl. the locked-route binding), #35-6
(the routing receipt), #35-8 (capability record), and the no-route
regression: accounts without routes behave exactly as before the seam
existed.
"""
import hashlib
import itertools
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus import receive_routes
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.receive_routes import (
    ReceiveRouteEntry,
    remove_authorization_message,
    route_capabilities,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)   # proposer / sole validator / fee beneficiary
SK_BOB, BOB = _key(44444)       # sender
SK_CAROL, CAROL = _key(77777)   # routed recipient
SK_DAVE, DAVE = _key(88888)     # route destination
SK_EVE, EVE = _key(99999)       # unrouted recipient / second-hop destination

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
    """Threads apply_block results into the next block's parent snapshot."""

    def __init__(self, balances, lm=None, ts=TS):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT

    def apply(self, txs, fee=FEE):
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
            return {1: str(amount), 8: "0", 9: str(fee), 5: "1"}

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


def _logs(result):
    out = []
    for outcome in result.outcomes:
        out.extend(outcome.receipt_logs or [])
    return " | ".join(str(x) for x in out)


def _transfer(sender, sk, to, amount, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"tr-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "operations": {"1": [[sender, to, str(amount)]]},
    }, sk)


def _install_tx(owner, sk, destination, bps, seq, fee_limit="100", **kw):
    tx = {
        "tx_id": f"route-{next(_TX_SEQ)}",
        "tx_type": "install_receive_route",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "route_destination_pubkey": destination,
        "route_bps": bps,
        "route_min_amount": kw.get("min_amount", 0),
        "route_activation_ts": kw.get("activation_ts", 0),
        "route_expiry_ts": kw.get("expiry_ts", 0),
        "route_locked_until_ts": kw.get("locked_until_ts", 0),
        "route_version": kw.get("version", 1),
    }
    return _sign(tx, sk)


def _remove_tx(owner, sk, seq, fee_limit="100", destination_signature=None):
    tx = {
        "tx_id": f"unroute-{next(_TX_SEQ)}",
        "tx_type": "remove_receive_route",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
    }
    if destination_signature is not None:
        tx["route_destination_signature"] = destination_signature
    return _sign(tx, sk)


def _destination_signature(route_entry, sk):
    digest = hashlib.sha256(
        remove_authorization_message(route_entry.owner_pubkey, route_entry.route_id)
    ).digest()
    return G2Basic.Sign(sk, digest).hex()


def _route(owner, destination, bps, **kw):
    return ReceiveRouteEntry(
        owner_pubkey=owner, destination_pubkey=destination, bps=bps,
        min_amount=kw.get("min_amount", 0),
        activation_ts=kw.get("activation_ts", 0),
        expiry_ts=kw.get("expiry_ts", 0),
        locked_until_ts=kw.get("locked_until_ts", 0),
        version=kw.get("version", 1),
    )


def _funded_chain():
    return _Chain({ALICE: 0, BOB: 100000, CAROL: 1000, DAVE: 0, EVE: 0})


# --- named case 1: 101 at 20% gives 20 and 81, one fee -------------------------

def test_route_101_at_20pct_gives_20_and_81_one_fee():
    chain = _funded_chain()
    install = _install_tx(CAROL, SK_CAROL, DAVE, 2000, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    assert chain.lm.receive_routes.get(CAROL) is not None
    carol_after_install = chain.balances[CAROL]
    assert carol_after_install == 1000 - FEE  # the install paid exactly one fee

    tx = _transfer(BOB, SK_BOB, CAROL, 101, seq=0)
    result = chain.apply([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert chain.balances[CAROL] == carol_after_install + 81
    assert chain.balances[DAVE] == 20
    # One fee total: the sender's debit is amount + one fee, exactly as the
    # unrouted control below; the split added no second fee event.
    assert chain.balances[BOB] == 100000 - 101 - FEE
    assert chain.balances[ALICE] == 2 * FEE  # install fee + transfer fee

    (event,) = result.next_snapshot.metadata["routing_events"]
    assert event["gross"] == 101 and event["routed"] == 20 and event["net"] == 81
    assert event["owner_pubkey"] == CAROL and event["destination_pubkey"] == DAVE
    assert "Routing: gross 101 -> net 81" in _logs(result)


def test_unrouted_control_pays_the_same_single_fee():
    """The control half of named case 1: no route, same fee, whole credit."""
    chain = _funded_chain()
    tx = _transfer(BOB, SK_BOB, EVE, 101, seq=0)
    result = chain.apply([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert chain.balances[EVE] == 101
    assert chain.balances[BOB] == 100000 - 101 - FEE
    assert chain.balances[ALICE] == FEE
    assert result.next_snapshot.metadata["routing_events"] == []


# --- named case 3: a routed share never triggers another route -----------------

def test_routed_share_never_triggers_another_route():
    chain = _funded_chain()
    chain.lm.receive_routes.install(_route(CAROL, DAVE, 2000), TS)
    chain.lm.receive_routes.install(_route(DAVE, EVE, 5000), TS)

    tx = _transfer(BOB, SK_BOB, CAROL, 101, seq=0)
    result = chain.apply([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert chain.balances[CAROL] == 1000 + 81
    assert chain.balances[DAVE] == 20
    # DAVE's own 50% route would have sent 10 onward had the routed share
    # re-entered the seam as a credit. It did not: single hop by class.
    assert chain.balances[EVE] == 0
    assert len(result.next_snapshot.metadata["routing_events"]) == 1


# --- the 5% split, once per credit (route level of the royalty numbers) --------

def test_route_5pct_on_101_pays_5_once_per_credit():
    chain = _funded_chain()
    chain.lm.receive_routes.install(_route(CAROL, DAVE, 500), TS)

    first = _transfer(BOB, SK_BOB, CAROL, 101, seq=0)
    result = chain.apply([first])
    assert chain.balances[DAVE] == 5
    assert chain.balances[CAROL] == 1000 + 96
    assert len(result.next_snapshot.metadata["routing_events"]) == 1

    second = _transfer(BOB, SK_BOB, CAROL, 101, seq=1)
    result = chain.apply([second])
    # Each credit splits exactly once: a second, separate credit pays 5 again
    # — never 10 for one credit, never 0 for the next.
    assert chain.balances[DAVE] == 10
    assert len(result.next_snapshot.metadata["routing_events"]) == 1


# --- #35-5: administration at apply — versions, locks, destination signature ---

def test_locked_route_binds_owner_until_destination_authorizes():
    chain = _funded_chain()
    install = _install_tx(
        CAROL, SK_CAROL, DAVE, 2000, seq=0,
        locked_until_ts=TS + 10000, expiry_ts=TS + 20000,
    )
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    entry = chain.lm.receive_routes.get(CAROL)
    assert entry is not None and entry.locked_until_ts == TS + 10000

    # The owner alone cannot remove it during the lock.
    remove = _remove_tx(CAROL, SK_CAROL, seq=1)
    result = chain.apply([remove])
    assert remove["tx_id"] in result.invalid_tx_ids
    assert chain.lm.receive_routes.get(CAROL) is not None

    # Nor replace it with a new version during the lock.
    replace = _install_tx(CAROL, SK_CAROL, EVE, 1000, seq=1, version=2)
    result = chain.apply([replace])
    assert replace["tx_id"] in result.invalid_tx_ids
    assert chain.lm.receive_routes.get(CAROL).destination_pubkey == DAVE

    # The destination's signature releases it (the maintainer's #35 addition).
    signed_remove = _remove_tx(
        CAROL, SK_CAROL, seq=1,
        destination_signature=_destination_signature(entry, SK_DAVE),
    )
    result = chain.apply([signed_remove])
    assert signed_remove["tx_id"] in result.accepted_tx_ids
    assert chain.lm.receive_routes.get(CAROL) is None


def test_route_replacement_must_be_the_next_version():
    chain = _funded_chain()
    chain.apply([_install_tx(CAROL, SK_CAROL, DAVE, 2000, seq=0)])

    skipping = _install_tx(CAROL, SK_CAROL, EVE, 1000, seq=1, version=3)
    result = chain.apply([skipping])
    assert skipping["tx_id"] in result.invalid_tx_ids
    assert chain.lm.receive_routes.get(CAROL).bps == 2000

    proper = _install_tx(CAROL, SK_CAROL, EVE, 1000, seq=1, version=2)
    result = chain.apply([proper])
    assert proper["tx_id"] in result.accepted_tx_ids
    entry = chain.lm.receive_routes.get(CAROL)
    assert entry.bps == 1000 and entry.destination_pubkey == EVE


def test_install_with_unpaid_fee_leaves_no_route():
    """The deferred commit: a fee-rejected install must not survive."""
    chain = _funded_chain()
    broke = _install_tx(CAROL, SK_CAROL, DAVE, 2000, seq=0, fee_limit="0")
    result = chain.apply([broke])
    assert broke["tx_id"] in result.invalid_tx_ids
    assert chain.lm.receive_routes.get(CAROL) is None

    # The sequence was not consumed, so the honest retry at seq 0 lands.
    honest = _install_tx(CAROL, SK_CAROL, DAVE, 2000, seq=0)
    result = chain.apply([honest])
    assert honest["tx_id"] in result.accepted_tx_ids
    assert chain.lm.receive_routes.get(CAROL) is not None


def test_forged_install_is_rejected_and_installs_nothing():
    chain = _funded_chain()
    forged = _install_tx(CAROL, SK_CAROL, DAVE, 2000, seq=0)
    forged["signature"] = G2Basic.Sign(
        SK_BOB, hashlib.sha256(signing_message_bytes(forged)).digest()
    ).hex()
    result = chain.apply([forged])
    assert forged["tx_id"] in result.invalid_tx_ids
    assert chain.lm.receive_routes.get(CAROL) is None


# --- inactive / below-minimum routes: the credit lands whole -------------------

def test_route_not_yet_active_or_below_minimum_credits_whole():
    chain = _funded_chain()
    chain.lm.receive_routes.install(
        _route(CAROL, DAVE, 2000, activation_ts=TS + 5000), TS)
    tx = _transfer(BOB, SK_BOB, CAROL, 101, seq=0)
    result = chain.apply([tx])
    assert chain.balances[CAROL] == 1000 + 101
    assert chain.balances[DAVE] == 0
    assert result.next_snapshot.metadata["routing_events"] == []

    chain2 = _funded_chain()
    chain2.lm.receive_routes.install(_route(CAROL, DAVE, 2000, min_amount=200), TS)
    tx2 = _transfer(BOB, SK_BOB, CAROL, 101, seq=0)
    result2 = chain2.apply([tx2])
    assert chain2.balances[CAROL] == 1000 + 101
    assert chain2.balances[DAVE] == 0
    assert result2.next_snapshot.metadata["routing_events"] == []


# --- #35-8: the capability record matches the book's real constants ------------

def test_capability_reports_route_semantics():
    caps = route_capabilities()
    assert caps["supported"] is True
    assert set(caps["trigger_credit_classes"]) == set(
        receive_routes.ROUTE_TRIGGER_CREDIT_CLASSES)
    assert caps["trigger_credit_classes"] == ["claimed_payment", "ordinary_transfer"]
    assert caps["rounding"] == "floor"
    assert caps["product_cap_bps"] == receive_routes.PRODUCT_CAP_BPS < 10000
    assert caps["max_bps"] == receive_routes.MAX_ROUTE_BPS
    assert "one original transfer fee" in caps["fee"]


# --- admission mirrors apply -----------------------------------------------------

class _TipView:
    def __init__(self, route_row=None):
        self._row = route_row
        self.next_block_timestamp = TS

    def get_receive_route(self, owner):
        return self._row

    def clause_for(self, who, idx):
        # FIX 11: route admission also asks for the owner's rule-change
        # guard; this fixture's accounts have none registered.
        return None


def test_admission_agrees_with_apply_on_install_and_remove():
    from consensus.admission import (
        validate_install_receive_route_payload,
        validate_remove_receive_route_payload,
    )

    good = _install_tx(CAROL, SK_CAROL, DAVE, 2000, seq=0)
    assert validate_install_receive_route_payload(good, _TipView()).is_valid

    # Locked without an expiry: the book refuses it, so admission does too.
    bad = _install_tx(CAROL, SK_CAROL, DAVE, 2000, seq=0, locked_until_ts=TS + 5)
    assert not validate_install_receive_route_payload(bad, _TipView()).is_valid

    # Removal of a route that does not exist at the tip.
    remove = _remove_tx(CAROL, SK_CAROL, seq=0)
    assert not validate_remove_receive_route_payload(remove, _TipView()).is_valid
