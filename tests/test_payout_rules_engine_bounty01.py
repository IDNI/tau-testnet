"""Bounty 01, issue #63: payout rules at the engine seam (mock Tau).

Slice 5 of DESIGN-01-TAKEOVER.md: the payout-rule book is wired into block
apply. Install/remove validate through the book's own can_install/can_remove
and mutate only at the post-settlement site (a fee-rejected install leaves
no rule); an execution is decided by the book's evaluate_execution — the
node computes the legs from the stored program and the submitted inputs —
and every leg settles through the ordinary transfer seam, so the owner's
o5 is re-checked on every real recipient and amount, each credit carries
the payout-leg class (a receive route never splits it, per the design's
credit-class table), and the settlement is recorded only once every leg is
known to stay in the block.

Covered here: all six #63 rows at engine level, including named case 2 in
its settlement form — a 5% royalty on a 101 base pays exactly 5, exactly
once, and a repeat execution carrying the same settlement id (a replay or a
fresh transaction) settles nothing.
"""
import hashlib
import itertools
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus import payout_rules
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.payout_rules import (
    LEG_BPS_OF_BASE,
    LEG_FIXED,
    PayoutRuleBook,
    parse_install_payout_rule,
    payout_rule_capabilities,
)
from consensus.receive_routes import ReceiveRouteEntry
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7
WEEK = 604_800

SID_1 = "11" * 32
SID_2 = "22" * 32
SID_3 = "33" * 32


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator / fee beneficiary
SK_OWNER, OWNER = _key(22222)        # the payout rule's owner
SK_ARTIST, ARTIST = _key(33333)      # the royalty recipient
SK_WORKER, WORKER = _key(44444)      # a fixed-leg recipient
SK_EXECUTOR, EXECUTOR = _key(55555)  # any third party may submit an execution
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

    Mirrors the slice-4 standing-payments harness; `allow=False` makes the
    scripted evaluator's o5 refuse every transfer, and `block_amount=N`
    refuses only the transfer of exactly N (how a policy block on one leg
    of a multi-leg payout presents).
    """

    def __init__(self, balances, lm=None, ts=TS):
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


def _logs(result):
    out = []
    for outcome in result.outcomes:
        out.extend(outcome.receipt_logs or [])
    return " | ".join(str(x) for x in out)


def _install_tx(owner, sk, seq, fee_limit="100", **kw):
    return _sign({
        "tx_id": f"payout-install-{next(_TX_SEQ)}",
        "tx_type": "install_payout_rule",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "payout_recipients": kw.get("recipients", [ARTIST]),
        "payout_legs": kw.get("legs", [[ARTIST, LEG_BPS_OF_BASE, 500]]),
        "payout_max_per_execution": kw.get("max_per_execution", 0),
        "payout_max_per_period": kw.get("max_per_period", 0),
        "payout_period_seconds": kw.get("period_seconds", WEEK),
        "payout_period_anchor_ts": kw.get("anchor_ts", TS - 100),
        "payout_version": kw.get("version", 1),
    }, sk)


def _remove_tx(sender, sk, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"payout-remove-{next(_TX_SEQ)}",
        "tx_type": "remove_payout_rule",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
    }, sk)


def _execute_tx(sender, sk, rule_id, settlement_id, base, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"payout-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_payout_rule",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "payout_rule_id": rule_id.hex(),
        "payout_settlement_id": settlement_id,
        "payout_base_amount": base,
    }, sk)


def _rule_id(install_tx):
    return parse_install_payout_rule(install_tx).rule_id


def _funded_chain():
    return _Chain({
        ALICE: 0, OWNER: 100000, ARTIST: 1000, WORKER: 0,
        EXECUTOR: 1000, RDEST: 0,
    })


def _installed_chain(**kw):
    """A chain with the royalty rule live (OWNER pays ARTIST 5% of base)."""
    chain = _funded_chain()
    install = _install_tx(OWNER, SK_OWNER, seq=0, **kw)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    return chain, _rule_id(install)


def _book(chain):
    return chain.lm.payout_rules


# --- install / remove administration -------------------------------------------


def test_install_lands_and_event_in_block_metadata():
    chain = _funded_chain()
    install = _install_tx(OWNER, SK_OWNER, seq=0)
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    rule_id = _rule_id(install)
    entry = _book(chain).get(OWNER)
    assert entry is not None and entry.rule_id == rule_id
    assert chain.balances[OWNER] == 100000 - FEE  # exactly one install fee
    (event,) = result.next_snapshot.metadata["payout_events"]
    assert event["action"] == "installed" and event["rule_id"] == rule_id.hex()
    assert result.governance_changes["payout_events"] == [event]


def test_install_with_unpaid_fee_installs_nothing():
    """The deferred commit: a fee-rejected install leaves no rule."""
    chain = _funded_chain()
    broke = _install_tx(OWNER, SK_OWNER, seq=0, fee_limit="0")
    result = chain.apply([broke])
    assert broke["tx_id"] in result.invalid_tx_ids
    assert _book(chain).is_empty()

    # The sequence was not consumed, so the honest retry at seq 0 lands.
    honest = _install_tx(OWNER, SK_OWNER, seq=0)
    result = chain.apply([honest])
    assert honest["tx_id"] in result.accepted_tx_ids
    assert not _book(chain).is_empty()


def test_install_version_rules_bind_at_engine_level():
    chain = _funded_chain()
    future = _install_tx(OWNER, SK_OWNER, seq=0, version=2)
    result = chain.apply([future])
    assert future["tx_id"] in result.invalid_tx_ids
    assert _book(chain).is_empty()

    chain, rule_id = _installed_chain()
    duplicate = _install_tx(OWNER, SK_OWNER, seq=1)
    result = chain.apply([duplicate])
    assert duplicate["tx_id"] in result.invalid_tx_ids
    assert _book(chain).get(OWNER).rule_id == rule_id


def test_remove_blocks_execution_and_only_the_owner_removes():
    chain, rule_id = _installed_chain()
    # A stranger's removal names the stranger's own (nonexistent) rule.
    stranger = _remove_tx(EXECUTOR, SK_EXECUTOR, seq=0)
    result = chain.apply([stranger])
    assert stranger["tx_id"] in result.invalid_tx_ids
    assert _book(chain).get(OWNER) is not None

    remove = _remove_tx(OWNER, SK_OWNER, seq=1)
    result = chain.apply([remove])
    assert remove["tx_id"] in result.accepted_tx_ids
    (event,) = result.next_snapshot.metadata["payout_events"]
    assert event["action"] == "removed" and event["rule_id"] == rule_id.hex()
    assert _book(chain).get(OWNER) is None

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000


# --- named case 2: the 5% royalty on 101 pays 5, once ----------------------------


def test_royalty_5pct_on_101_pays_5_once():
    chain, rule_id = _installed_chain()
    owner_after_install = chain.balances[OWNER]

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 5
    assert chain.balances[OWNER] == owner_after_install - 5
    # One leg through the seam: the submitter pays exactly one fee.
    assert chain.balances[EXECUTOR] == 1000 - FEE
    (event,) = result.next_snapshot.metadata["payout_events"]
    assert event["action"] == "executed" and event["total"] == 5
    assert event["settlement_id"] == SID_1
    assert event["legs"] == [{"recipient_pubkey": ARTIST, "amount": 5}]
    assert "Payout rule executed" in _logs(result)
    book = _book(chain)
    assert book.is_settled(rule_id, bytes.fromhex(SID_1))
    assert book.period_total(rule_id, 0) == 5

    # A repeat execution carrying the same settlement id — a fresh
    # transaction, not a replay of the block — settles nothing.
    again = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=1)
    result = chain.apply([again])
    assert again["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000 + 5
    assert chain.balances[OWNER] == owner_after_install - 5

    # A different settlement is a different payment and settles normally.
    other = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_2, 101, seq=1)
    result = chain.apply([other])
    assert other["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 10


# --- #63 rows at the seam ---------------------------------------------------------


def test_payout_rule_outputs_checked_against_declared_caps():
    """Row 1: the node computes the legs; the declared cap binds the total."""
    chain, rule_id = _installed_chain(
        recipients=[ARTIST, WORKER],
        legs=[[WORKER, LEG_FIXED, 700], [ARTIST, LEG_BPS_OF_BASE, 500]],
        max_per_execution=705,
    )
    owner_after_install = chain.balances[OWNER]
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[WORKER] == 700
    assert chain.balances[ARTIST] == 1000 + 5
    assert chain.balances[OWNER] == owner_after_install - 705
    # Two legs through the seam: one measured fee per leg, charged once.
    assert chain.balances[EXECUTOR] == 1000 - 2 * FEE

    # A base whose computed total (700 + 500) exceeds the declared cap
    # settles nothing — the cap is checked against the computed legs, not
    # against anything the submitter claims.
    over = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_2, 10000, seq=1)
    result = chain.apply([over])
    assert over["tx_id"] in result.invalid_tx_ids
    assert chain.balances[WORKER] == 700
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_2))


def test_payout_all_legs_atomic_or_none():
    """Row 2: a policy block on the second leg undoes the first."""
    chain, rule_id = _installed_chain(
        recipients=[ARTIST, WORKER],
        legs=[[WORKER, LEG_FIXED, 700], [ARTIST, LEG_BPS_OF_BASE, 500]],
    )
    owner_after_install = chain.balances[OWNER]
    blocked = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([blocked], block_amount=5)
    assert blocked["tx_id"] in result.invalid_tx_ids
    # The first leg staged but never committed: nothing moved anywhere.
    assert chain.balances[WORKER] == 0
    assert chain.balances[ARTIST] == 1000
    assert chain.balances[OWNER] == owner_after_install
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))
    assert _book(chain).period_total(rule_id, 0) == 0

    allowed = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([allowed])
    assert allowed["tx_id"] in result.accepted_tx_ids
    assert chain.balances[WORKER] == 700 and chain.balances[ARTIST] == 1005


def test_payout_cannot_pay_undeclared_recipient():
    """Row 4: a program paying outside the declared set never installs."""
    chain = _funded_chain()
    bad = _install_tx(
        OWNER, SK_OWNER, seq=0,
        recipients=[ARTIST], legs=[[WORKER, LEG_FIXED, 10]],
    )
    result = chain.apply([bad])
    assert bad["tx_id"] in result.invalid_tx_ids
    assert _book(chain).is_empty()
    assert chain.balances[WORKER] == 0


def test_payout_period_cap_binds_across_executions():
    """Row 5: the per-period cap binds across separate executions."""
    chain, rule_id = _installed_chain(max_per_period=12)
    for seq, sid in ((0, SID_1), (1, SID_2)):
        execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, sid, 101, seq=seq)
        result = chain.apply([execute])
        assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 10

    third = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_3, 101, seq=2)
    result = chain.apply([third])
    assert third["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000 + 10
    assert _book(chain).period_total(rule_id, 0) == 10


def test_o5_blocked_execution_settles_nothing_then_settles_once():
    """Every leg passes the owner's own o5 gate (the design's fee/o5 section)."""
    chain, rule_id = _installed_chain()
    owner_after_install = chain.balances[OWNER]
    blocked = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([blocked], allow=False)
    assert blocked["tx_id"] in result.invalid_tx_ids
    assert chain.balances[OWNER] == owner_after_install
    assert chain.balances[ARTIST] == 1000
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))

    allowed = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([allowed])
    assert allowed["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1005


def test_insufficient_funds_execution_settles_nothing():
    chain = _Chain({
        ALICE: 0, OWNER: 100, ARTIST: 0, WORKER: 0, EXECUTOR: 1000, RDEST: 0,
    })
    install = _install_tx(
        OWNER, SK_OWNER, seq=0,
        recipients=[ARTIST, WORKER],
        legs=[[WORKER, LEG_FIXED, 700], [ARTIST, LEG_BPS_OF_BASE, 500]],
    )
    result = chain.apply([install])
    assert install["tx_id"] in result.accepted_tx_ids
    rule_id = _rule_id(install)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert chain.balances[WORKER] == 0 and chain.balances[ARTIST] == 0
    assert not _book(chain).is_settled(rule_id, bytes.fromhex(SID_1))


def test_execution_of_unknown_rule_is_refused():
    chain = _funded_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, b"\x07" * 32, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert chain.balances[ARTIST] == 1000


def test_payout_leg_is_never_split_by_a_receive_route():
    """The design's credit-class table: payout legs carry the payout class."""
    chain, rule_id = _installed_chain()
    chain.lm.receive_routes.install(ReceiveRouteEntry(
        owner_pubkey=ARTIST, destination_pubkey=RDEST, bps=5000,
        min_amount=0, activation_ts=0, expiry_ts=0, locked_until_ts=0,
        version=1,
    ), TS)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[ARTIST] == 1000 + 5  # whole, not split
    assert chain.balances[RDEST] == 0
    assert result.next_snapshot.metadata["routing_events"] == []


# --- capability record + facade -----------------------------------------------------


def test_capability_record_matches_the_book():
    caps = payout_rule_capabilities()
    assert caps["supported"] is True
    assert caps["leg_modes"] == {
        "fixed": payout_rules.LEG_FIXED,
        "bps_of_base": payout_rules.LEG_BPS_OF_BASE,
    }
    assert caps["credit_class"] == "payout_leg"
    assert caps["max_legs"] == payout_rules.MAX_LEGS
    assert caps["max_recipients"] == payout_rules.MAX_RECIPIENTS


class _TipView(TipAdmissionView):
    """The real facade view over an injected book, at a fixed timestamp."""

    def __init__(self, book, balances):
        self._book = book
        self._balances = balances

    @property
    def next_block_timestamp(self):
        return TS

    def _tip_payout_book(self):
        return self._book

    def get_balance(self, pubkey):
        return self._balances.get(pubkey, 0)


def test_rule_view_readable_via_the_facade():
    chain, rule_id = _installed_chain()
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, rule_id, SID_1, 101, seq=0)
    chain.apply([execute])

    view = _TipView(_book(chain), dict(chain.balances))
    got = view.get_payout_rule_for_owner(OWNER)
    assert got is not None and got["rule_id"] == rule_id.hex()
    assert got["recipients"] == [ARTIST]
    assert got["current_period_total"] == 5
    (settlement,) = got["settlements"]
    assert settlement["settlement_id"] == SID_1 and settlement["total"] == 5
    assert view.get_payout_rule(rule_id)["owner_pubkey"] == OWNER
    assert view.get_payout_rule(b"\x09" * 32) is None
    assert view.get_payout_rule_for_owner(EXECUTOR) is None


# --- admission and apply agree --------------------------------------------------------


def test_admission_agrees_with_apply():
    from consensus.admission import (
        validate_execute_payout_rule_payload,
        validate_install_payout_rule_payload,
        validate_remove_payout_rule_payload,
    )

    empty = _TipView(PayoutRuleBook(), {OWNER: 100000})

    good = _install_tx(OWNER, SK_OWNER, seq=0)
    assert validate_install_payout_rule_payload(good, empty).is_valid

    # A program paying an undeclared recipient: the book refuses, so
    # admission does.
    bad = _install_tx(OWNER, SK_OWNER, seq=0,
                      recipients=[ARTIST], legs=[[WORKER, LEG_FIXED, 10]])
    assert not validate_install_payout_rule_payload(bad, empty).is_valid

    # Execute/remove against a tip that knows no such rule.
    unknown = b"\x07" * 32
    assert not validate_execute_payout_rule_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, unknown, SID_1, 101, seq=0),
        empty).is_valid
    assert not validate_remove_payout_rule_payload(
        _remove_tx(OWNER, SK_OWNER, seq=0), empty).is_valid

    # With the rule live at the tip: removal is the owner's alone, and an
    # execution is admitted exactly when the book would settle it.
    book = PayoutRuleBook()
    entry = parse_install_payout_rule(good)
    book.install(entry, TS)
    live = _TipView(book, {OWNER: 100000})
    assert not validate_remove_payout_rule_payload(
        _remove_tx(EXECUTOR, SK_EXECUTOR, seq=0), live).is_valid
    assert validate_remove_payout_rule_payload(
        _remove_tx(OWNER, SK_OWNER, seq=0), live).is_valid
    due = validate_execute_payout_rule_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, entry.rule_id, SID_1, 101, seq=0),
        live)
    assert due.is_valid and due.data["total"] == 5

    # After the settlement lands, the same execution is refused: it has
    # paid, once — admission and apply read the same book state.
    book.execute(entry.rule_id, bytes.fromhex(SID_1), 101, TS, 100000)
    assert not validate_execute_payout_rule_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, entry.rule_id, SID_1, 101, seq=0),
        live).is_valid
