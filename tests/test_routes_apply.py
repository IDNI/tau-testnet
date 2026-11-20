"""Block-apply semantics for receive routes (Bounty 01, issue #35).

Runs through the real `apply_block` with a scripted evaluator,
mirroring tests/test_standing_apply.py. The named tests are the
engine-level half of the design's case -> test mapping for #35: the
book-level half lives in tests/test_routes.py.
"""

import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.routes import parse_route_install, unlock_message_bytes
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

FAR = 9_999_999_999


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


NOW = _ts(2026, 1, 15, 12)


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_MALLORY, MALLORY = _key(66666)
PROPOSER = "d4" * 48
_KEYS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, MALLORY: SK_MALLORY}

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def install_tx(owner=BOB, sk=SK_BOB, destination=CAROL, bps=2000, seq=0,
               fee_limit="100", extra=None):
    tx = {
        "tx_id": f"route-install-{next(_TX_SEQ)}",
        "tx_type": "receive_route_install",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "destination_pubkey": destination,
        "bps": bps,
        "min_incoming": 0,
        "activation_timestamp": 0,
        "expiry_timestamp": 0,
        "locked": False,
    }
    tx.update(extra or {})
    return _sign(tx, sk)


def remove_tx(route_id_hex, owner=BOB, sk=SK_BOB, seq=1, extra=None):
    tx = {
        "tx_id": f"route-remove-{next(_TX_SEQ)}",
        "tx_type": "receive_route_remove",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "route_id": route_id_hex,
    }
    tx.update(extra or {})
    return _sign(tx, sk)


def unlock_sig(route_terms, sk):
    digest = hashlib.sha256(unlock_message_bytes(route_terms)).digest()
    return G2Basic.Sign(sk, digest).hex()


def spend_tx(sender, to, amount, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"spend-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "operations": {"1": [[sender, to, amount]]},
    }, _KEYS[sender])


class Chain:
    def __init__(self, balances, *, fee=0):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.fee = fee
        self.last = None

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = str(vals.get(1, "0"))
        return {1: amount, 8: "0", 9: str(self.fee), 5: "1"}

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
        return self.lm.receive_routes

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids

    def receipt(self, tx):
        for outcome in self.last.outcomes:
            if outcome.tx_id == tx["tx_id"]:
                return {"logs": outcome.receipt_logs, "reason": outcome.reason}
        raise KeyError(tx["tx_id"])

    def splits(self):
        return self.last.next_snapshot.metadata.get("route_splits", [])


def _balances():
    return {ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0}


def _routed_chain(fee=0, **install_kwargs):
    ch = Chain(_balances(), fee=fee)
    tx = install_tx(**install_kwargs)
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.book.get(BOB) is not None
    return ch, parse_route_install(tx)


# -- the named cases ---------------------------------------------------------

def test_route_101_at_20pct_gives_20_and_81_one_fee():
    ch, _terms = _routed_chain(fee=0)
    ch.fee = 7  # the fee era starts after the route is installed
    spend = spend_tx(ALICE, BOB, 101, seq=0)
    ch.block([spend], height=21, ts=NOW)
    assert ch.accepted(spend)
    assert ch.bal[BOB] == 81
    assert ch.bal[CAROL] == 20
    # One fee, on the whole transfer, paid by the sender as usual.
    assert ch.bal[ALICE] == 10_000 - 101 - 7
    assert ch.bal[PROPOSER] == 7


def test_normal_transfer_cannot_bypass_route():
    # Every ordinary transfer to the routed account is split, whoever
    # sends it. CAROL starts funded here so she can be a sender too.
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 1_000, MALLORY: 0, PROPOSER: 0})
    tx = install_tx()
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx)
    ch.block([spend_tx(ALICE, BOB, 50, seq=0)], height=21, ts=NOW)
    assert ch.bal[BOB] == 40 and ch.bal[CAROL] == 1_010
    ch.block([spend_tx(CAROL, BOB, 200, seq=0)], height=22, ts=NOW)
    # 200 gross: 160 net to BOB, 40 routed back to CAROL (destination).
    assert ch.bal[BOB] == 200
    assert ch.bal[CAROL] == 1_010 - 200 + 40


def test_route_applies_identically_online_or_offline():
    # The checktx preview and the apply seam share RouteTerms.split;
    # here the apply half: two identical transfers at different heights
    # split identically.
    ch, terms = _routed_chain()
    ch.block([spend_tx(ALICE, BOB, 101, seq=0)], height=21, ts=NOW)
    first = (ch.bal[BOB], ch.bal[CAROL])
    ch.block([spend_tx(ALICE, BOB, 101, seq=1)], height=22, ts=NOW)
    assert (ch.bal[BOB] - first[0], ch.bal[CAROL] - first[1]) == first
    assert terms.split(101) == 20


def test_routed_share_never_triggers_another_route():
    ch, _terms = _routed_chain()
    # CAROL (the destination) installs her own route to MALLORY at 50%.
    carol_route = install_tx(owner=CAROL, sk=SK_CAROL, destination=MALLORY,
                             bps=5000, seq=0)
    ch.block([carol_route], height=21, ts=NOW)
    assert ch.accepted(carol_route)
    ch.block([spend_tx(ALICE, BOB, 101, seq=0)], height=22, ts=NOW)
    assert ch.bal[BOB] == 81
    assert ch.bal[CAROL] == 20  # the routed share stays whole
    assert ch.bal[MALLORY] == 0  # and never triggers CAROL's route
    # But an ordinary transfer TO CAROL routes normally.
    ch.block([spend_tx(ALICE, CAROL, 100, seq=1)], height=23, ts=NOW)
    assert ch.bal[MALLORY] == 50


def test_invalid_and_recursive_route_sets_rejected_safely():
    ch = Chain(_balances())
    self_route = install_tx(owner=BOB, sk=SK_BOB, destination=BOB)
    ch.block([self_route], height=20, ts=NOW)
    assert not ch.accepted(self_route)
    full = install_tx(bps=10_000)
    ch.block([full], height=21, ts=NOW)
    assert not ch.accepted(full)
    assert ch.book.is_empty()
    # A cycle (BOB -> CAROL, CAROL -> BOB) installs fine and still
    # routes exactly once, by the credit-class rule.
    ch2, _ = _routed_chain()
    back = install_tx(owner=CAROL, sk=SK_CAROL, destination=BOB, bps=5000, seq=0)
    ch2.block([back], height=21, ts=NOW)
    assert ch2.accepted(back)
    ch2.block([spend_tx(ALICE, BOB, 100, seq=0)], height=22, ts=NOW)
    assert ch2.bal[BOB] == 80 and ch2.bal[CAROL] == 20


def test_route_admin_follows_protected_policy_rules():
    expiry = NOW + 1000
    ch = Chain(_balances())
    tx = install_tx(extra={"locked": True, "expiry_timestamp": expiry})
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx)
    terms = parse_route_install(tx)
    rid = terms.route_id.hex()
    # Removal without the destination's signature is refused.
    bad = remove_tx(rid, seq=1)
    ch.block([bad], height=21, ts=NOW)
    assert not ch.accepted(bad)
    assert ch.book.get(BOB) is not None
    # With the destination's unlock signature it goes through.
    good = remove_tx(rid, seq=1, extra={
        "destination_signature": unlock_sig(terms, SK_CAROL),
    })
    ch.block([good], height=22, ts=NOW)
    assert ch.accepted(good)
    assert ch.book.get(BOB) is None


def test_locked_route_removable_by_owner_alone_after_expiry():
    expiry = NOW + 1000
    ch = Chain(_balances())
    tx = install_tx(extra={"locked": True, "expiry_timestamp": expiry})
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx)
    rid = parse_route_install(tx).route_id.hex()
    late = remove_tx(rid, seq=1)
    ch.block([late], height=21, ts=expiry + 1)
    assert ch.accepted(late)
    assert ch.book.get(BOB) is None


def test_route_amounts_visible_in_receipt_and_history():
    ch, terms = _routed_chain()
    spend = spend_tx(ALICE, BOB, 101, seq=0)
    ch.block([spend], height=21, ts=NOW)
    splits = ch.splits()
    assert len(splits) == 1
    split = splits[0]
    assert split["gross"] == 101
    assert split["routed"] == 20
    assert split["net"] == 81
    assert split["destination"] == CAROL
    assert split["route_id"] == terms.route_id.hex()
    # And the split is in the transaction's own receipt logs, the
    # history surface every block carries.
    logs = " ".join(ch.receipt(spend)["logs"])
    assert "Receive route: 20 of 101" in logs


def test_route_replay_and_snapshot_restore_preserve_balances():
    from consensus.routes import RouteBook

    ch, _terms = _routed_chain()
    spend = spend_tx(ALICE, BOB, 101, seq=0)
    result1 = ch.block([spend], height=21, ts=NOW)
    balances1 = dict(ch.bal)
    root1 = ch.book.root()
    restored = RouteBook.restore(ch.book.snapshot_rows())
    assert restored.root() == root1
    # Re-apply the same block from the same parent state: the split is
    # a pure function of the book and the gross, so balances repeat.
    ch2, _ = _routed_chain()
    ch2.block([spend_tx(ALICE, BOB, 101, seq=0)], height=21, ts=NOW)
    assert ch2.bal == balances1


def test_inactive_route_does_not_split():
    ch = Chain(_balances())
    tx = install_tx(extra={"activation_timestamp": NOW + 500})
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx)
    ch.block([spend_tx(ALICE, BOB, 101, seq=0)], height=21, ts=NOW)
    assert ch.bal[BOB] == 101 and ch.bal[CAROL] == 0
    ch.block([spend_tx(ALICE, BOB, 101, seq=1)], height=22, ts=NOW + 500)
    assert ch.bal[BOB] == 101 + 81 and ch.bal[CAROL] == 20


def test_capability_reports_route_semantics():
    from commands.getroutes import SEMANTICS

    assert SEMANTICS["supported"] is True
    assert SEMANTICS["rounding"] == "floor_on_gross"
    assert SEMANTICS["credit_classes"] == "ordinary_transfers_only"
    assert SEMANTICS["fee"] == "single_fee_on_gross_charged_to_sender"
