"""Every transaction carries a height at which it expires.

`expiration_time` is a wall-clock stamp, and the consensus-side recheck compares
it against the block TIMESTAMP -- which the proposer picks, within the clock
tolerance. A height cannot be chosen that way: a proposer who wants to revive an
expired transaction, or bury a live one, has to move the block itself.
"""
import json
from unittest.mock import MagicMock

import pytest

import tau_defs
from consensus.admission import (
    AdmissionResult,
    TipAdmissionView,
    validate_expire_at_height,
)
from consensus.tx_signing import signing_message_bytes


NEXT_HEIGHT = 50


@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    return view


def _tx(tx_type="user_tx", **extra):
    payload = {
        "tx_type": tx_type,
        "sender_pubkey": "a" * 96,
        "sequence_number": 1,
        "expiration_time": 9_999_999_999,
        "fee_limit": "0",
        "expire_at_height": NEXT_HEIGHT + 10,
    }
    payload.update(extra)
    return payload


# --------------------------------------------------------------------------- #
# the field is signed
# --------------------------------------------------------------------------- #

def test_height_is_covered_by_the_signature():
    """Unsigned, a proposer could strip the field and revive a dead tx."""
    with_height = _tx(operations={})
    without = {k: v for k, v in with_height.items() if k != "expire_at_height"}
    assert b'"expire_at_height":60' in signing_message_bytes(with_height)
    assert signing_message_bytes(with_height) != signing_message_bytes(without)


def test_changing_the_height_changes_the_message():
    a = signing_message_bytes(_tx(operations={}))
    b = signing_message_bytes(_tx(operations={}, expire_at_height=NEXT_HEIGHT + 11))
    assert a != b


def test_a_payload_without_a_height_signs_exactly_as_it_used_to():
    """Transactions written before heights existed still verify: the field is
    added to the signed dict only when present."""
    legacy = {
        "sender_pubkey": "aa", "sequence_number": 1, "expiration_time": 9,
        "fee_limit": "10", "tx_type": "user_tx", "operations": {},
    }
    assert signing_message_bytes(legacy) == (
        b'{"expiration_time":9,"fee_limit":"10","operations":{},'
        b'"sender_pubkey":"aa","sequence_number":1,"tx_type":"user_tx"}'
    )


def test_approval_request_signs_one_height_not_two():
    """That type already signed the field; the general rule must not double it."""
    tx = _tx("approval_request", recipient_pubkey="b" * 96, amount=5,
             approvers={}, custom_inputs={})
    assert signing_message_bytes(tx).count(b'"expire_at_height"') == 1


# --------------------------------------------------------------------------- #
# admission
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", [None, "60", 60.0, True])
def test_a_missing_or_non_integer_height_is_refused(tip_view, bad):
    tx = _tx(operations={})
    if bad is None:
        tx.pop("expire_at_height")
    else:
        tx["expire_at_height"] = bad
    result = validate_expire_at_height(tx, tip_view)
    assert isinstance(result, AdmissionResult) and not result.is_valid
    assert "expire_at_height" in result.error


@pytest.mark.parametrize("height", [NEXT_HEIGHT, NEXT_HEIGHT - 1, 1])
def test_a_height_at_or_before_the_next_block_is_expired(tip_view, height):
    """At the next height the transaction can no longer be included, so it is
    already dead -- not merely close to it."""
    result = validate_expire_at_height(_tx(operations={}, expire_at_height=height),
                                       tip_view)
    assert not result.is_valid
    assert result.code == "TX_EXPIRED"


def test_the_next_height_plus_one_is_still_alive(tip_view):
    assert validate_expire_at_height(
        _tx(operations={}, expire_at_height=NEXT_HEIGHT + 1), tip_view) is None


def test_a_height_beyond_the_window_is_refused(tip_view):
    """Without a ceiling a sender could park a transaction in every mempool
    indefinitely."""
    too_far = NEXT_HEIGHT + tau_defs.TX_EXPIRY_MAX_WINDOW_BLOCKS + 1
    result = validate_expire_at_height(_tx(operations={}, expire_at_height=too_far),
                                       tip_view)
    assert not result.is_valid
    assert str(tau_defs.TX_EXPIRY_MAX_WINDOW_BLOCKS) in result.error


def test_the_window_edge_is_accepted(tip_view):
    edge = NEXT_HEIGHT + tau_defs.TX_EXPIRY_MAX_WINDOW_BLOCKS
    assert validate_expire_at_height(_tx(operations={}, expire_at_height=edge),
                                     tip_view) is None


def test_rule_offers_keep_their_own_wider_window(tip_view):
    """rule_offer allowed 100,000 blocks before this was general, and its
    senders still do; the generic ceiling must not silently shrink it."""
    from consensus.rule_offers import MAX_OFFER_WINDOW_BLOCKS

    far = NEXT_HEIGHT + MAX_OFFER_WINDOW_BLOCKS
    assert far > NEXT_HEIGHT + tau_defs.TX_EXPIRY_MAX_WINDOW_BLOCKS
    assert validate_expire_at_height(
        _tx("rule_offer", expire_at_height=far), tip_view) is None
    # ... and the same height on any other type is refused.
    assert validate_expire_at_height(
        _tx("user_tx", operations={}, expire_at_height=far), tip_view) is not None


def test_every_known_tx_type_goes_through_the_check():
    """A type added later must not be able to skip it: the orchestrator runs
    the check before it dispatches, so this is a guard on that ordering."""
    import inspect

    from consensus import admission

    source = inspect.getsource(admission.validate_mempool_admission)
    before_dispatch = source.split("if tx_type ==")[0]
    assert "validate_expire_at_height" in before_dispatch


# --------------------------------------------------------------------------- #
# builders
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad", [None, "500", True, 0, -1])
def test_builders_refuse_an_unusable_height(bad):
    from tau_testnet_cli import tx as tx_mod

    with pytest.raises((ValueError, TypeError)):
        tx_mod.build_user_tx(sender_pubkey="a" * 96, sequence_number=1,
                             expiration_time=1, expire_at_height=bad,
                             operations={"1": []})


def test_every_builder_emits_the_field():
    from tau_testnet_cli import tx as tx_mod

    common = dict(sender_pubkey="a" * 96, sequence_number=1,
                  expiration_time=1, expire_at_height=500)
    built = [
        tx_mod.build_user_tx(operations={"1": []}, **common),
        tx_mod.build_consensus_rule_update_tx(rule_revisions=["x"],
                                              activate_at_height=9, **common),
        tx_mod.build_consensus_rule_vote_tx(update_id="b" * 64, **common),
        tx_mod.build_rule_offer_accept_tx(offer_id="c" * 64, rule_text="always(o1[t]=1).",
                                          **common),
        tx_mod.build_rule_offer_reject_tx(offer_id="c" * 64, **common),
        tx_mod.build_transfer_vote_tx(request_id="d" * 64, **common),
    ]
    for payload in built:
        assert payload["expire_at_height"] == 500, payload["tx_type"]


# --------------------------------------------------------------------------- #
# block apply -- the gate a proposer cannot talk its way past
# --------------------------------------------------------------------------- #

class TestApplyRejectsAnExpiredHeight:
    """`expiration_time` is rechecked at apply against the block TIMESTAMP,
    which the proposer sets. The height gate is the one it cannot move."""

    SENDER = "a" * 96
    RECIPIENT = "b" * 96

    @pytest.fixture(autouse=True)
    def engine(self):
        from unittest.mock import MagicMock, patch

        from consensus.engine import TauConsensusEngine
        from consensus.state import TauStateSnapshot

        # Same shape as tests/test_fee_model.py's harness: the engine asks Tau
        # for the fee, and "Tau unavailable" is a hard error by design.
        ready = patch("tau_manager.tau_ready")
        mock_ready = ready.start()
        mock_ready.is_set.return_value = True
        multi = patch("tau_manager.communicate_with_tau_multi", return_value={1: "1", 9: "0"})
        multi.start()
        comm = patch("tau_manager.communicate_with_tau", return_value="ok")
        comm.start()

        store = MagicMock()
        store.commit.side_effect = lambda snap: snap
        self.engine = TauConsensusEngine(state_store=store)
        self.snapshot = TauStateSnapshot(b"hash", b"rules", {})
        yield
        for patcher in (comm, multi, ready):
            patcher.stop()

    def _tx(self, **extra):
        tx = {
            "tx_id": "tx1",
            "tx_type": "user_tx",
            "sender_pubkey": self.SENDER,
            "sequence_number": 0,
            "expiration_time": 9_999_999_999,
            "fee_limit": "0",
            "operations": {"1": [[self.SENDER, self.RECIPIENT, 100]]},
        }
        tx.update(extra)
        return tx

    def _apply(self, tx, height, replay_mode=False):
        balances = {self.SENDER: 1000}
        result = self.engine.apply(
            self.snapshot, [tx], 1_700_000_000,
            target_balances=balances,
            target_sequences={},
            replay_mode=replay_mode,
            proposer_pubkey="c" * 96,
            block_height=height,
        )
        return result, balances

    def test_a_live_transaction_is_applied(self):
        result, balances = self._apply(self._tx(expire_at_height=100), height=99)
        assert result.accepted_transactions and not result.rejected_transactions
        assert balances[self.RECIPIENT] == 100

    def test_the_expiry_height_itself_is_too_late(self):
        """expire_at_height is the first height at which the transaction can no
        longer be included -- the same boundary admission enforces."""
        result, balances = self._apply(self._tx(expire_at_height=100), height=100)
        assert not result.accepted_transactions
        assert self.RECIPIENT not in balances

    def test_a_block_past_the_expiry_rejects_it(self):
        result, _ = self._apply(self._tx(expire_at_height=100), height=101)
        assert not result.accepted_transactions
        receipt = next(iter(result.receipts.values()))
        assert any("expired at height 100" in line for line in receipt["logs"])

    def test_a_transaction_without_a_height_still_applies(self):
        """Blocks written before heights existed must keep replaying, or a
        restarted node diverges from a running one."""
        result, balances = self._apply(self._tx(), height=10_000)
        assert result.accepted_transactions
        assert balances[self.RECIPIENT] == 100

    def test_a_non_integer_height_does_not_crash_apply(self):
        result, balances = self._apply(self._tx(expire_at_height="100"), height=101)
        assert result.accepted_transactions
        assert balances[self.RECIPIENT] == 100


# --------------------------------------------------------------------------- #
# the mempool drops what can no longer be included
# --------------------------------------------------------------------------- #

class TestMempoolPrunesByHeight:
    """A transaction whose height has passed will be refused by every block
    from here on, so holding it only costs a mempool slot."""

    A = "aa" * 48
    B = "bb" * 48
    FAR_FUTURE = 9_999_999_999

    def _payload(self, expire_at_height, seq=0):
        return json.dumps({
            "tx_type": "user_tx",
            "sender_pubkey": self.A,
            "sequence_number": seq,
            "expiration_time": self.FAR_FUTURE,
            "expire_at_height": expire_at_height,
            "fee_limit": "10",
            "operations": {"1": [[self.A, self.B, 1]]},
        })

    def _head_at(self, db, height):
        """Put a canonical head at `height` so the prune has a tip to read."""
        block = {"header": {"block_number": height, "block_hash": "h" * 64},
                 "transactions": []}
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO blocks "
                "(block_hash, block_number, previous_hash, timestamp, block_data) "
                "VALUES (?, ?, ?, ?, ?)",
                ("h" * 64, height, "0" * 64, 1_700_000_000, json.dumps(block)),
            )
            cur.execute(
                "INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)",
                ("canonical_head_hash", "h" * 64),
            )
            db._db_conn.commit()

    def test_a_passed_height_is_pruned_and_a_live_one_is_kept(self, temp_database):
        import db

        self._head_at(db, 100)
        # Pruning happens on insert, so the survivor goes in last and the rows
        # already there are judged against the tip.
        db.add_mempool_tx(self._payload(expire_at_height=50), "dead1", 1, fee_limit=10)
        db.add_mempool_tx(self._payload(expire_at_height=101, seq=1), "dead2", 2, fee_limit=10)
        db.add_mempool_tx(self._payload(expire_at_height=500, seq=2), "alive", 3, fee_limit=10)

        left = {row["tx_hash"] for row in db.get_mempool_entries()}
        # 101 is the next block's own height: the block being built cannot
        # include it either.
        assert "dead1" not in left and "dead2" not in left
        assert "alive" in left

    def test_a_row_without_a_height_survives_the_height_prune(self, temp_database):
        """Rows written before heights existed have no field to judge."""
        import db

        self._head_at(db, 100)
        legacy = json.loads(self._payload(expire_at_height=1))
        legacy.pop("expire_at_height")
        db.add_mempool_tx(json.dumps(legacy), "legacy", 1, fee_limit=10)
        db.add_mempool_tx(self._payload(expire_at_height=500, seq=1), "alive", 2, fee_limit=10)

        left = {row["tx_hash"] for row in db.get_mempool_entries()}
        assert left == {"legacy", "alive"}

    def test_a_pruned_row_is_reported_as_expired(self, temp_database):
        """gettxstatus must be able to say what happened to it."""
        import db

        self._head_at(db, 100)
        db.add_mempool_tx(self._payload(expire_at_height=50), "dead", 1, fee_limit=10)
        db.add_mempool_tx(self._payload(expire_at_height=500, seq=1), "alive", 2, fee_limit=10)
        assert db.get_dropped_tx("dead") is not None


# --------------------------------------------------------------------------- #
# the CLI's deadline resolution
# --------------------------------------------------------------------------- #

class TestResolveExpireAtHeight:
    """`getsequence` carries the tip, but a node too old to report one answers
    0 -- and a deadline measured from 0 on a live chain is already past."""

    class Args:
        host, port, timeout = "127.0.0.1", 1, 1.0
        expire_at_height = None
        expire_in = None

    def test_an_explicit_height_wins(self, monkeypatch):
        from tau_testnet_cli import cli

        args = self.Args()
        args.expire_at_height = 4242
        monkeypatch.setattr(cli, "_tip_height", lambda a: pytest.fail("asked the node"))
        assert cli._resolve_expire_at_height(args, tip=10) == 4242

    def test_the_passed_tip_is_used_without_a_round_trip(self, monkeypatch):
        from tau_testnet_cli import cli

        monkeypatch.setattr(cli, "_tip_height", lambda a: pytest.fail("asked the node"))
        assert cli._resolve_expire_at_height(self.Args(), tip=300) == 300 + 1 + 1000

    def test_a_zero_tip_falls_back_to_asking_the_chain(self, monkeypatch):
        from tau_testnet_cli import cli

        monkeypatch.setattr(cli, "_tip_height", lambda a: 5_000)
        assert cli._resolve_expire_at_height(self.Args(), tip=0) == 5_000 + 1 + 1000

    def test_expire_in_is_honoured(self, monkeypatch):
        from tau_testnet_cli import cli

        args = self.Args()
        args.expire_in = 7
        assert cli._resolve_expire_at_height(args, tip=100) == 108

    def test_expire_in_one_clears_admission(self):
        """Admission refuses expire_at_height <= tip + 1: the smallest window
        must still be one block the transaction can land in."""
        from tau_testnet_cli import cli

        args = self.Args()
        args.expire_in = 1
        tip = 100
        assert cli._resolve_expire_at_height(args, tip=tip) > tip + 1

    def test_expire_in_zero_is_refused_not_defaulted(self):
        from tau_testnet_cli import cli

        args = self.Args()
        args.expire_in = 0
        with pytest.raises(ValueError):
            cli._resolve_expire_at_height(args, tip=100)
