"""Tests for Stage 4 receive routes (consensus/routes.py + wiring).

Book, parse/shape and admission tests live here; engine tests (the route
hook in _execute_fee_era_transfer and the standing-payment credit path)
are in the TestEngineRouteHook class below and mirror the grant/standing
engine harness.
"""
import pytest

from consensus.credits import (
    CREDIT_FAUCET,
    CREDIT_ROUTE_OUTPUT,
    CREDIT_STANDING_PAYMENT,
    CREDIT_TRANSFER,
)
from consensus.routes import (
    MAX_BPS,
    MIN_BPS,
    TX_TYPE_ROUTE_REMOVE,
    TX_TYPE_ROUTE_SET,
    RouteBook,
    RouteEntry,
    RouteShapeError,
    parse_route_remove,
    parse_route_set,
    validate_route_shape,
)

ALICE = "aa" * 48
BOB = "bb" * 48
CAROL = "cc" * 48
CHAIN_ID = "ab" * 32

T0 = 1_700_000_000  # a fixed "now" for shape/admission tests


def make_route(**overrides):
    fields = {
        "account_pubkey": BOB,
        "destination_pubkey": CAROL,
        "bps": 2500,
        "min_incoming": 0,
        "activate_at": T0,
        "expires_at": T0 + 30 * 86400,
        "locked_until": None,
        "sequence_number": 1,
    }
    fields.update(overrides)
    return RouteEntry(**fields)


def make_tx(**overrides):
    tx = {
        "tx_type": TX_TYPE_ROUTE_SET,
        "sender_pubkey": BOB,
        "destination_pubkey": CAROL,
        "bps": 2500,
        "min_incoming": 0,
        "activate_at": T0,
        "expires_at": T0 + 30 * 86400,
        "locked_until": None,
        "sequence_number": 1,
        "chain_id": CHAIN_ID,
    }
    tx.update(overrides)
    return tx


# --------------------------------------------------------------------------
# Parse + shape
# --------------------------------------------------------------------------
class TestParseAndShape:
    def test_parse_route_set_roundtrip(self):
        entry = parse_route_set(make_tx())
        assert entry.account_pubkey == BOB
        assert entry.destination_pubkey == CAROL
        assert entry.bps == 2500
        assert entry.min_incoming == 0
        assert entry.locked_until is None

    def test_parse_route_set_rejects_bad_pubkey(self):
        with pytest.raises(RouteShapeError):
            parse_route_set(make_tx(destination_pubkey="zz"))
        with pytest.raises(RouteShapeError):
            parse_route_set(make_tx(sender_pubkey="zz"))

    def test_parse_route_set_rejects_bad_bps_type(self):
        with pytest.raises(RouteShapeError):
            parse_route_set(make_tx(bps="2500"))
        with pytest.raises(RouteShapeError):
            parse_route_set(make_tx(bps=-1))

    def test_parse_route_remove(self):
        req = parse_route_remove(
            {"tx_type": TX_TYPE_ROUTE_REMOVE, "sender_pubkey": BOB}
        )
        assert req.account_pubkey == BOB

    def test_shape_bps_bounds(self):
        assert validate_route_shape(make_route(bps=MIN_BPS), 0, T0) is None
        assert validate_route_shape(make_route(bps=MAX_BPS), 0, T0) is None
        assert validate_route_shape(make_route(bps=0), 0, T0) is not None
        assert validate_route_shape(make_route(bps=MAX_BPS + 1), 0, T0) is not None

    def test_shape_rejects_self_route(self):
        assert (
            validate_route_shape(
                make_route(destination_pubkey=BOB), 0, T0
            )
            is not None
        )

    def test_shape_requires_window(self):
        assert (
            validate_route_shape(
                make_route(activate_at=T0 + 100, expires_at=T0 + 100), 0, T0
            )
            is not None
        )
        assert (
            validate_route_shape(
                make_route(activate_at=T0 + 100, expires_at=T0 + 50), 0, T0
            )
            is not None
        )

    def test_shape_lock_must_be_future_and_within_window(self):
        assert (
            validate_route_shape(make_route(locked_until=T0 - 1), 0, T0)
            is not None
        )
        assert (
            validate_route_shape(
                make_route(locked_until=T0 + 31 * 86400), 0, T0
            )
            is not None
        )
        assert (
            validate_route_shape(make_route(locked_until=T0 + 1000), 0, T0)
            is None
        )


# --------------------------------------------------------------------------
# Book + the split
# --------------------------------------------------------------------------
class TestRouteBook:
    def test_submit_get_remove(self):
        book = RouteBook()
        assert book.is_empty()
        book.submit(make_route())
        assert not book.is_empty()
        assert book.open_count() == 1
        assert book.get(BOB).destination_pubkey == CAROL
        book.remove(BOB)
        assert book.is_empty()
        assert book.get(BOB) is None
        assert book.resolved_state()[0] == 1  # removed folds into resolved

    def test_one_route_per_account_replace(self):
        book = RouteBook()
        book.submit(make_route(bps=2500))
        book.submit(make_route(bps=5000))
        assert book.open_count() == 1
        assert book.get(BOB).bps == 5000

    def test_apply_route_split_floor(self):
        book = RouteBook()
        book.submit(make_route(bps=2500))
        # 1000 * 2500 / 10000 = 250 routed, 750 net.
        assert book.apply_route(BOB, 1000, CREDIT_TRANSFER, T0) == (750, 250, CAROL)
        # Floor: 101 * 2500 / 10000 = 25 (25.25 floored).
        assert book.apply_route(BOB, 101, CREDIT_TRANSFER, T0) == (76, 25, CAROL)
        # 9000 bps: 1000 -> 900 routed, 100 net.
        book.submit(make_route(bps=9000))
        assert book.apply_route(BOB, 1000, CREDIT_TRANSFER, T0) == (100, 900, CAROL)

    def test_apply_route_standing_payment_is_routable(self):
        book = RouteBook()
        book.submit(make_route(bps=5000))
        assert book.apply_route(BOB, 100, CREDIT_STANDING_PAYMENT, T0) == (
            50,
            50,
            CAROL,
        )

    def test_apply_route_non_routable_class_passes_through(self):
        book = RouteBook()
        book.submit(make_route(bps=5000))
        assert book.apply_route(BOB, 100, CREDIT_FAUCET, T0) is None
        # A route output is never re-routed: single hop by construction.
        assert book.apply_route(BOB, 100, CREDIT_ROUTE_OUTPUT, T0) is None

    def test_apply_route_window_and_min_incoming(self):
        book = RouteBook()
        book.submit(make_route(min_incoming=500))
        assert book.apply_route(BOB, 499, CREDIT_TRANSFER, T0) is None
        assert book.apply_route(BOB, 500, CREDIT_TRANSFER, T0) is not None
        assert book.apply_route(BOB, 1000, CREDIT_TRANSFER, T0 - 1) is None
        assert (
            book.apply_route(BOB, 1000, CREDIT_TRANSFER, T0 + 30 * 86400)
            is None
        )

    def test_apply_route_dust_splits_nothing(self):
        # 1 * 2500 / 10000 = 0 routed: no split, the whole credit stays.
        book = RouteBook()
        book.submit(make_route(bps=2500))
        assert book.apply_route(BOB, 1, CREDIT_TRANSFER, T0) is None
        assert book.apply_route(BOB, 3, CREDIT_TRANSFER, T0) is None

    def test_apply_route_unknown_account(self):
        book = RouteBook()
        assert book.apply_route(ALICE, 1000, CREDIT_TRANSFER, T0) is None

    def test_locked_route_cannot_be_replaced_or_removed(self):
        book = RouteBook()
        book.submit(make_route(locked_until=T0 + 10000))
        ok, reason = book.can_admit_set(make_route(bps=5000), 0, T0)
        assert not ok and "locked" in reason
        ok, reason = book.can_admit_remove(BOB, BOB, 0, T0)
        assert not ok and "locked" in reason
        # After the lock lifts, both are allowed again.
        ok, _ = book.can_admit_set(make_route(bps=5000), 0, T0 + 10000)
        assert ok
        ok, _ = book.can_admit_remove(BOB, BOB, 0, T0 + 10000)
        assert ok

    def test_remove_requires_owner(self):
        book = RouteBook()
        book.submit(make_route())
        ok, _ = book.can_admit_remove(BOB, ALICE, 0, T0)
        assert not ok
        ok, _ = book.can_admit_remove(BOB, BOB, 0, T0)
        assert ok

    def test_snapshot_restore_roundtrip(self):
        book = RouteBook()
        book.submit(make_route())
        book.submit(make_route(account_pubkey=ALICE, destination_pubkey=BOB,
                               bps=1000, sequence_number=2))
        book.remove(ALICE)
        count, acc = book.resolved_state()
        rows = book.snapshot_rows()
        restored = RouteBook.restore(rows, count, acc)
        assert restored.open_count() == 1
        assert restored.get(BOB).bps == 2500
        assert restored.resolved_state() == (count, acc)
        assert restored.root() == book.root()

    def test_root_is_deterministic_and_changes_on_mutation(self):
        a = RouteBook()
        a.submit(make_route())
        b = RouteBook()
        b.submit(make_route())
        assert a.root() == b.root()
        b.submit(make_route(bps=5000))
        assert a.root() != b.root()

    def test_restore_rejects_corrupt_row(self):
        book = RouteBook()
        book.submit(make_route(bps=0))  # bypasses admission, corrupt shape
        rows = book.snapshot_rows()
        with pytest.raises(ValueError):
            RouteBook.restore(rows, 0, bytes(32))


# --------------------------------------------------------------------------
# Admission
# --------------------------------------------------------------------------
class _FakeTipView:
    """Minimal TipAdmissionView stand-in (mirrors test_standing.py)."""

    def __init__(self, book=None, timestamp=T0, height=20):
        self._book = book or RouteBook()
        self.next_block_timestamp = timestamp
        self.next_block_height = height
        self.genesis_hash = CHAIN_ID

    def get_route(self, account_pubkey):
        entry = self._book.get(account_pubkey)
        if entry is None:
            return None
        return {
            "account_pubkey": entry.account_pubkey,
            "destination_pubkey": entry.destination_pubkey,
            "bps": entry.bps,
            "min_incoming": entry.min_incoming,
            "activate_at": entry.activate_at,
            "expires_at": entry.expires_at,
            "locked_until": entry.locked_until,
            "sequence_number": entry.sequence_number,
        }

    def open_route_count(self):
        return self._book.open_count()


class TestAdmission:
    def test_set_accepted(self):
        from consensus.admission import validate_route_set_payload

        view = _FakeTipView()
        result = validate_route_set_payload(make_tx(), view)
        assert result.is_valid

    def test_set_wrong_chain_rejected(self):
        from consensus.admission import validate_route_set_payload

        view = _FakeTipView()
        result = validate_route_set_payload(
            make_tx(chain_id="ff" * 32), view
        )
        assert not result.is_valid

    def test_set_bad_bps_rejected(self):
        from consensus.admission import validate_route_set_payload

        view = _FakeTipView()
        result = validate_route_set_payload(make_tx(bps=9001), view)
        assert not result.is_valid

    def test_set_locked_route_rejected(self):
        from consensus.admission import validate_route_set_payload

        book = RouteBook()
        book.submit(make_route(locked_until=T0 + 10000))
        view = _FakeTipView(book=book)
        result = validate_route_set_payload(make_tx(bps=5000), view)
        assert not result.is_valid

    def test_remove_accepted_and_unknown_rejected(self):
        from consensus.admission import validate_route_remove_payload

        book = RouteBook()
        book.submit(make_route())
        view = _FakeTipView(book=book)
        tx = {
            "tx_type": TX_TYPE_ROUTE_REMOVE,
            "sender_pubkey": BOB,
            "chain_id": CHAIN_ID,
        }
        assert validate_route_remove_payload(tx, view).is_valid
        empty = _FakeTipView()
        assert not validate_route_remove_payload(tx, empty).is_valid

    def test_remove_wrong_sender_rejected(self):
        from consensus.admission import validate_route_remove_payload

        book = RouteBook()
        book.submit(make_route())
        view = _FakeTipView(book=book)
        tx = {
            "tx_type": TX_TYPE_ROUTE_REMOVE,
            "sender_pubkey": ALICE,
            "chain_id": CHAIN_ID,
        }
        assert not validate_route_remove_payload(tx, view).is_valid


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------
def test_demo_bob_routes_25_percent_to_carol():
    """Bob routes 25% of every incoming transfer to Carol."""
    book = RouteBook()
    book.submit(make_route(bps=2500))
    assert book.apply_route(BOB, 1000, CREDIT_TRANSFER, T0) == (750, 250, CAROL)
    # A faucet grant is not routable: Bob keeps the whole 1000.
    assert book.apply_route(BOB, 1000, CREDIT_FAUCET, T0) is None


# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# Engine tests (route hook in _execute_fee_era_transfer).
# Harness mirrors tests/test_standing.py exactly (BLS keys, TauStateSnapshot,
# ActiveConsensusView, mocked Tau fee = 7).
# --------------------------------------------------------------------------
import hashlib
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

E_HEIGHT = 20
E_FEE = 7
E_TS = 1234567890

E_SK_ALICE = 11111
E_ALICE = G2Basic.SkToPk(E_SK_ALICE).hex()
E_SK_BOB = 44444
E_BOB = G2Basic.SkToPk(E_SK_BOB).hex()
E_SK_CAROL = 77777
E_CAROL = G2Basic.SkToPk(E_SK_CAROL).hex()


def _e_sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _e_snapshot(lm, balances, sequences=None):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": dict(balances),
            "sequence_numbers": dict(sequences or {}),
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )


def _e_apply_block(txs, parent, height=E_HEIGHT, timestamp=E_TS, fee=E_FEE):
    lm = parent.metadata["lifecycle_manager"]
    lm.activate_approval_slots()
    active_view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(E_ALICE)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block_obj = Block.create(
        block_number=height, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=E_ALICE, timestamp=timestamp,
    )

    def _fake_multi(**kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        return {1: str(amount), 5: "1", 8: "0", 9: str(fee)}

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", return_value="T"), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        return engine.apply_block(active_view, block_obj, parent)


def _e_fresh_parent():
    lm = ConsensusLifecycleManager(active_validators=[E_ALICE])
    lm.genesis_hash = CHAIN_ID
    # Bob and Carol are funded so they can pay route_set fees.
    return _e_snapshot(lm, {E_ALICE: 100000, E_BOB: 10000, E_CAROL: 10000})


def _e_route_set_tx(destination=E_CAROL, bps=2500, seq=0, sender=E_BOB,
                    sk=E_SK_BOB, min_incoming=0, activate_at=E_TS,
                    expires_at=E_TS + 30 * 86400, locked_until=None):
    tx = {
        "tx_id": f"route-set-{seq}",
        "tx_type": TX_TYPE_ROUTE_SET,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "destination_pubkey": destination,
        "bps": bps,
        "min_incoming": min_incoming,
        "activate_at": activate_at,
        "expires_at": expires_at,
        "locked_until": locked_until,
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, sk)


def _e_route_remove_tx(seq=1, sender=E_BOB, sk=E_SK_BOB):
    tx = {
        "tx_id": f"route-remove-{seq}",
        "tx_type": TX_TYPE_ROUTE_REMOVE,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, sk)


def _e_user_tx(sender, recipient, amount, seq=0, sk=E_SK_ALICE):
    tx = {
        "tx_id": f"user-tx-{seq}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "operations": {"1": [[sender, recipient, str(amount)]]},
    }
    return _e_sign(tx, sk)


class TestEngineRouteHook:
    def test_route_set_lands(self):
        result = _e_apply_block([_e_route_set_tx()], _e_fresh_parent())
        assert result.accepted_tx_ids == ["route-set-0"]
        lm = result.next_snapshot.metadata["lifecycle_manager"]
        route = lm.routes.get(E_BOB)
        assert route is not None
        assert route.destination_pubkey == E_CAROL and route.bps == 2500

    def test_transfer_splits_to_route(self):
        first = _e_apply_block([_e_route_set_tx()], _e_fresh_parent())
        second = _e_apply_block(
            [_e_user_tx(E_ALICE, E_BOB, 1000, seq=0)], first.next_snapshot,
            height=E_HEIGHT + 1, timestamp=E_TS + 10,
        )
        assert second.accepted_tx_ids == ["user-tx-0"]
        balances = second.next_snapshot.metadata["balances"]
        # Bob's route_set fee (7) went to Alice (proposer); Alice then pays
        # 1000 + 7 fee and gets the 7 back as proposer.
        # Alice 100000 + 7 - 1000 = 99007; Bob 10000 - 7 + 750 = 10743.
        assert balances[E_ALICE] == 99007
        assert balances[E_BOB] == 10743
        assert balances[E_CAROL] == 10250
        got = {(r.recipient_pubkey, r.amount, r.credit_class)
               for r in second.credits}
        assert (E_BOB, 750, CREDIT_TRANSFER) in got
        assert (E_CAROL, 250, CREDIT_ROUTE_OUTPUT) in got

    def test_transfer_without_route_is_whole(self):
        result = _e_apply_block(
            [_e_user_tx(E_ALICE, E_BOB, 1000, seq=0)], _e_fresh_parent()
        )
        assert result.accepted_tx_ids == ["user-tx-0"]
        balances = result.next_snapshot.metadata["balances"]
        assert balances[E_BOB] == 11000
        assert balances[E_CAROL] == 10000

    def test_route_is_single_hop(self):
        # Carol also routes 50% to Alice. The 250 routed to Carol must NOT
        # split again: Carol keeps the whole 250.
        first = _e_apply_block([_e_route_set_tx()], _e_fresh_parent())
        second = _e_apply_block(
            [_e_route_set_tx(destination=E_ALICE, bps=5000, seq=0,
                             sender=E_CAROL, sk=E_SK_CAROL)],
            first.next_snapshot, height=E_HEIGHT + 1, timestamp=E_TS + 10,
        )
        third = _e_apply_block(
            [_e_user_tx(E_ALICE, E_BOB, 1000, seq=0)], second.next_snapshot,
            height=E_HEIGHT + 2, timestamp=E_TS + 20,
        )
        balances = third.next_snapshot.metadata["balances"]
        assert balances[E_BOB] == 10000 - 7 + 750  # Bob's fee + net
        assert balances[E_CAROL] == 10000 - 7 + 250  # Carol's fee + routed
        got = {(r.recipient_pubkey, r.amount, r.credit_class)
               for r in third.credits}
        assert (E_CAROL, 250, CREDIT_ROUTE_OUTPUT) in got
        assert not any(
            r.recipient_pubkey == E_ALICE
            and r.credit_class == CREDIT_ROUTE_OUTPUT
            for r in third.credits
        )

    def test_route_min_incoming_blocks_small_transfer(self):
        first = _e_apply_block(
            [_e_route_set_tx(min_incoming=2000)], _e_fresh_parent()
        )
        second = _e_apply_block(
            [_e_user_tx(E_ALICE, E_BOB, 1000, seq=0)], first.next_snapshot,
            height=E_HEIGHT + 1, timestamp=E_TS + 10,
        )
        balances = second.next_snapshot.metadata["balances"]
        assert balances[E_BOB] == 10000 - 7 + 1000  # below min: no split
        assert balances[E_CAROL] == 10000

    def test_route_window_blocks_expired_route(self):
        first = _e_apply_block(
            [_e_route_set_tx(expires_at=E_TS + 100)], _e_fresh_parent()
        )
        second = _e_apply_block(
            [_e_user_tx(E_ALICE, E_BOB, 1000, seq=0)], first.next_snapshot,
            height=E_HEIGHT + 1, timestamp=E_TS + 200,
        )
        balances = second.next_snapshot.metadata["balances"]
        assert balances[E_BOB] == 10000 - 7 + 1000  # expired: no split
        assert balances[E_CAROL] == 10000

    def test_route_remove_stops_split(self):
        first = _e_apply_block([_e_route_set_tx()], _e_fresh_parent())
        second = _e_apply_block(
            [_e_route_remove_tx(seq=1)], first.next_snapshot,
            height=E_HEIGHT + 1, timestamp=E_TS + 10,
        )
        assert second.accepted_tx_ids == ["route-remove-1"]
        lm = second.next_snapshot.metadata["lifecycle_manager"]
        assert lm.routes.get(E_BOB) is None
        third = _e_apply_block(
            [_e_user_tx(E_ALICE, E_BOB, 1000, seq=0)], second.next_snapshot,
            height=E_HEIGHT + 2, timestamp=E_TS + 20,
        )
        balances = third.next_snapshot.metadata["balances"]
        assert balances[E_BOB] == 10000 - 7 + 1000
        assert balances[E_CAROL] == 10000
