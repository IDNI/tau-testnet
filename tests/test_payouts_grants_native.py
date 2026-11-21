"""Native-evidence wave, Bounty 01 stage 3 (issues #35/#63), PR #156.

Lands at tau-b01s3/tests/test_payouts_grants_native.py and is
registered in the native-tau-tests CI job (see
native-prep/CI-REGISTRATION.md).

Stage 3 carries the last two of the maintainer's five named cases:
  case 2 — a 5% royalty on a 101 transfer pays the owner 5, once;
  case 5 — a 5,000 grant at 500/week from Dec 1 returns exactly 3,800
           to the grantor after 1,200 drawn;
plus the shared per-period cap across grants in a cap group (the
stage-3 headline addition, commit 3210e55). All three exist on the
mock path (tests/test_payouts_apply.py, tests/test_grants_apply.py)
where the Tau evaluator is scripted. This file reuses those suites'
Chain / tx builders, installs a real tau_native.TauInterface behind
tau_manager (the seam consensus/engine.py steps through via
tau_session.InProcessSession), and patches nothing on the Tau path.

Honest scope, stated up front (also for the PR comment):
  - Case 5's grant book is Python (consensus/grants.py); the native
    run proves the full apply path — escrow, capped draws, the
    shared cap, the deadline refund sweep — with the real engine
    stepping every block's Tau outputs.
  - Case 2: the owner's payout clause is a real Tau unit seeded into
    the real interpreter's spec, and the engine's payout seam reads
    its real outputs via consensus/payouts.py (legs_from_outputs).
    The clause used here pays a FIXED leg of 5. A proportional clause
    (o21 = (i1 * 5) / 100) is expressible in the tau grammar — the
    repo's own probe carries the pattern
    (tests/test_o9_arithmetic_probe_native.py, PCT5_RULE) — but that
    probe has no green run in this repo (it is not registered in CI
    and skips in this VM), so this file does not claim a proportional
    royalty. See native-prep/STAGE3-TODO-RESOLUTIONS-2026-11-21.md
    item #3 for the swap that strengthens the claim once a CI run
    proves the probe in the payout seam.

Gate: idiom A (native-prep/INFRA-MAP.md §3). Locally every test skips;
the native CI job's preflight hard-fails if the module is missing.

Landing-day resolutions — the TODO-VERIFY items that touched this
file (full text: native-prep/STAGE3-TODO-RESOLUTIONS-2026-11-21.md)
----------------------------------------------------------------------
Genesis seeding: as in the landed stage-2 file — the native CI job
generates data/genesis.json in the same docker run before pytest
starts, and the fixture's read is safe as written.

Application-rules state: pinned to "" through the production setter
for each test and restored afterwards, as in stage 2. The payout
clause seed (below) persists the clause into that accumulation for
the duration of the royalty test — the state a landed rule produces
on a live node — and the teardown restore contains it.

Payout legs record (#4): stage 3's engine writes no route_splits-
style leg record. The record asserted here is the one the engine
does write: next_snapshot.metadata["payout_events"] carries
(settlement_id, "executed") for an executed payout, and the
PayoutBook state (settlements, spent_in_period) is the authoritative
"paid exactly once" record — a replayed settlement id is refused by
check_execution ("settlement id already settled").

Payout clause seeding (#5): the engine's payout gate is the Python
registry (rule_offers.clause_for) and its step is the main session's
evaluate — the clause must be in BOTH the registry and the
interpreter's spec. The production offer-accept path writes only
the registry (rule_offers.submit_decision); it never feeds the body
to the interpreter, so driving an offer block through apply would
leave the execute to refuse with "the rule produced no legs".
_install_payout_clause therefore writes the registry entry exactly
as submit_decision does AND seeds the same text through
tau_manager.communicate_with_tau(apply_rules_update=True) — the
mechanism by which any rule enters the main interpreter's spec.

Fees (#6): payout_rule_install, payout_execute, grant_create and
grant_draw are all fee-bearing (engine FEE_BEARING_TX_TYPES). The
real genesis program charges its flat base fee (10 per stage-1/2
evidence) to the tx SENDER, credited to the block proposer (this
Chain's lifecycle manager names no fee beneficiary). Every fee in
these tests is measured off the proposer's balance, never assumed:
  - the payout executor (CAROL) pays the execute fee, so she opens
    funded — at 0 she would be hard-rejected
    (insufficient_funds_for_fee) because an execute stages her no
    credit;
  - a draw's fee is read against the draw's own staged credit, so
    BOB can draw from 0 and nets amount − fee per draw;
  - the deadline refund is a block-level sweep, not a tx: the test
    asserts the grantor's gain across the empty deadline block is
    exactly 3,800 AND the proposer's gain across it is exactly 0;
  - a refused draw/execution pays nothing: the refusing actor's and
    the proposer's balances are asserted unchanged across the
    refusal block.
Recipient-side and book-side numbers (5 paid once, remaining 3,800,
refund 3,800, the shared cap) are fee-independent and asserted
exactly.
"""
import hashlib
import itertools
import os
from datetime import datetime, timezone

import pytest
from py_ecc.bls import G2Basic

import tau_manager
from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.grants import parse_grant_create
from consensus.payouts import PAYOUT_STREAM_INDEX
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENESIS_TAU = os.path.join(REPO_ROOT, "genesis.tau")
TRANSFER_RULE = os.path.join(REPO_ROOT, "rules", "04_handle_valid_transfer.tau")


def _native_available():
    try:
        import tau_native

        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built"
)


@pytest.fixture(autouse=True)
def live_tau():
    """Real engine behind tau_manager; seeding mirrors
    tests/test_fee_model_native.py (transfer rule + genesis consensus
    rules from data/genesis.json, which the CI native job generates
    before pytest runs — see the module docstring). The
    application-rules global is pinned to the mock suites' "" via the
    production setter for the duration of each test and restored
    afterwards (module docstring)."""
    import json

    import chain_state
    import tau_native

    iface = tau_native.TauInterface(GENESIS_TAU)
    old_iface = tau_manager.tau_direct_interface
    old_mode = tau_manager.tau_test_mode
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_test_mode = False
    tau_manager.tau_ready.set()
    prev_rules_state = chain_state.get_application_rules_state()
    chain_state.save_application_rules_state("")
    with open(TRANSFER_RULE) as fh:
        tau_manager.communicate_with_tau(
            rule_text=fh.read(), target_output_stream_index=0,
            apply_rules_update=False, source="seed-transfer-rule",
        )
    with open(os.path.join(REPO_ROOT, "data", "genesis.json")) as fh:
        consensus_rules = json.load(fh)["consensus_rules"]
    tau_manager.communicate_with_tau(
        rule_text=chain_state._preprocess_tau_spec_text(consensus_rules),
        target_output_stream_index=0,
        apply_rules_update=False, source="seed-genesis-consensus",
    )
    yield iface
    tau_manager.tau_direct_interface = old_iface
    tau_manager.tau_test_mode = old_mode
    tau_manager.tau_ready.clear()
    chain_state.save_application_rules_state(prev_rules_state)


# --- tx builders: copied from tests/test_payouts_apply.py and
# --- tests/test_grants_apply.py ---------------------------------------------

FAR = 9_999_999_999
WEEK = 604800


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


NOW = _ts(2026, 1, 15, 12)
JAN1 = _ts(2026, 1, 1)
DEC1 = _ts(2025, 12, 1)
DEADLINE = DEC1 + 4 * WEEK


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


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


def execute_tx(owner=ALICE, executor=CAROL, sk=SK_CAROL, seq=0,
               settlement_id="s1", gross=101, extra=None):
    tx = {
        "tx_id": f"payout-exec-{next(_TX_SEQ)}",
        "tx_type": "payout_execute",
        "sender_pubkey": executor,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "owner": owner,
        "settlement_id": settlement_id,
        "gross": gross,
    }
    tx.update(extra or {})
    return _sign(tx, sk)


def create_tx(seq=0, total=5000, cap=500, extra=None):
    tx = {
        "tx_id": f"grant-create-{next(_TX_SEQ)}",
        "tx_type": "grant_create",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "recipient_pubkey": BOB,
        "total": total,
        "cap_per_period": cap,
        "opens_at": DEC1,
        "deadline": DEADLINE,
    }
    tx.update(extra or {})
    return _sign(tx, SK_ALICE)


def draw_tx(grant_id, amount, seq=0, sk=SK_BOB, sender=BOB, extra=None):
    tx = {
        "tx_id": f"grant-draw-{next(_TX_SEQ)}",
        "tx_type": "grant_draw",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "grant_id": grant_id,
        "amount": amount,
    }
    tx.update(extra or {})
    return _sign(tx, sk)


class Chain:
    """The stage-3 mock suites' Chain with the scripted evaluator
    removed; balances are carried in snapshot metadata as there."""

    def __init__(self, balances):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.last = None

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
        # NO patches on the Tau path (see module docstring).
        # chain_state.get_application_rules_state is not patched
        # either: the live_tau fixture pins the underlying global to
        # "" via the production setter for each test.
        result = engine.apply_block(view, blk, parent)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.last = result
        return result

    @property
    def payout_book(self):
        return self.lm.payout_rules

    @property
    def grant_book(self):
        return self.lm.grants

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids

    def receipt(self, tx):
        for outcome in self.last.outcomes:
            if outcome.tx_id == tx["tx_id"]:
                return {"logs": outcome.receipt_logs, "reason": outcome.reason}
        raise KeyError(tx["tx_id"])

    def payout_events(self):
        return self.last.next_snapshot.metadata.get("payout_events", [])

    def grant_events(self):
        return self.last.next_snapshot.metadata.get("grant_events", [])


def _install_payout_clause(ch: Chain, clause: str):
    """Register ALICE's payout clause the two ways the production
    state holds it (module docstring, resolution #5): the registry
    entry, written exactly as rule_offers.submit_decision writes it,
    and the clause unit in the interpreter's spec, seeded through
    tau_manager with the rules update on — the mechanism by which
    any rule enters the main interpreter's spec on a live node."""
    ch.lm.rule_offers.accepted_clauses[(ALICE, PAYOUT_STREAM_INDEX)] = clause
    tau_manager.communicate_with_tau(
        rule_text=clause, target_output_stream_index=0,
        apply_rules_update=True, source="native-payout-clause",
    )


# --- the named cases ---------------------------------------------------------

# A real clause paying one leg of 5 to declared recipient index 0
# (stream o21 amount, o22 destination index). Fixed-amount by
# construction; see the module docstring's honest-scope note.
ROYALTY_CLAUSE_FIXED5 = (
    "always (o20[t]:bv[24] = { #x000001 }:bv[24]"
    " && o21[t]:bv[24] = { #x000005 }:bv[24]"
    " && o22[t]:bv[24] = { #x000000 }:bv[24])."
)


def test_five_percent_royalty_on_101_pays_five_once_native():
    """Maintainer case 2 (#35): executing ALICE's payout rule over a
    gross of 101 credits the declared recipient exactly 5, exactly
    once — the leg outputs (o20 = 1 leg, o21 = 5, o22 = index 0)
    come from a real Tau clause stepped by the real engine, not from
    a scripted evaluator, and the settlement record proves the
    "once": a replay with the same settlement id settles nothing."""
    # CAROL (the executor) opens funded: she pays the execute fee
    # under the real program (module docstring, "Fees").
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 1_000, PROPOSER: 0})
    _install_payout_clause(ch, ROYALTY_CLAUSE_FIXED5)
    install = install_tx()
    ch.block([install], height=20, ts=NOW)
    assert ch.accepted(install), ch.receipt(install)
    assert ch.payout_book.get(ALICE) is not None
    # The install was a fee-bearing tx under the real program: ALICE
    # paid one fee, credited to the proposer. Measured, not assumed.
    install_fee = ch.bal[PROPOSER]
    assert install_fee > 0
    assert ch.bal[ALICE] == 10_000 - install_fee

    ex = execute_tx(settlement_id="royalty-101", gross=101)
    ch.block([ex], height=21, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    # The leg moved exactly 5 from the owner to recipient index 0.
    assert ch.bal[BOB] == 5
    assert ch.bal[ALICE] == 10_000 - install_fee - 5
    # The executor paid the execute fee — the same flat genesis fee
    # the install paid, each measured independently in this run.
    exec_fee = ch.bal[PROPOSER] - install_fee
    assert exec_fee == install_fee
    assert ch.bal[CAROL] == 1_000 - exec_fee
    # The record (resolution #4): one executed event in the block's
    # snapshot metadata, and the book holds the settlement exactly
    # once with 5 spent in the period.
    assert ch.payout_events() == [("royalty-101", "executed")]
    state = ch.payout_book.get(ALICE)
    assert state.settlements == ["royalty-101"]
    assert state.spent_in_period == 5

    # Replay: the same settlement id settles nothing, pays nothing,
    # and is refused for the settlement reason specifically.
    replay = execute_tx(seq=1, settlement_id="royalty-101", gross=101)
    ch.block([replay], height=22, ts=NOW)
    assert not ch.accepted(replay)
    assert "already settled" in " ".join(ch.receipt(replay)["logs"])
    assert ch.bal[BOB] == 5
    assert ch.bal[ALICE] == 10_000 - install_fee - 5
    assert ch.bal[CAROL] == 1_000 - exec_fee
    assert ch.bal[PROPOSER] == install_fee + exec_fee
    assert ch.payout_events() == []
    assert ch.payout_book.get(ALICE).settlements == ["royalty-101"]
    assert ch.payout_book.get(ALICE).spent_in_period == 5


def test_grant_5000_returns_3800_after_1200_drawn_native():
    """Maintainer case 5 (#35/#63): a 5,000 grant, 500/week cap from
    Dec 1, draws of 500 + 500 + 200 across three weeks, and exactly
    3,800 returned to the grantor by the deadline sweep — the full
    apply path with the real engine stepping every block. The refund
    is fee-free: the grantor's gain across the sweep block is the
    full 3,800 and the proposer's gain across it is zero."""
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    create = create_tx()
    ch.block([create], height=20, ts=DEC1 - 60)
    assert ch.accepted(create), ch.receipt(create)
    grant_id = parse_grant_create(create).grant_id
    # Creation escrows the full 5,000; the sender also pays the real
    # fee, measured off the proposer.
    create_fee = ch.bal[PROPOSER]
    assert create_fee > 0
    assert ch.bal[ALICE] == 10_000 - 5_000 - create_fee
    assert ch.grant_book.get(grant_id).remaining == 5000

    # Three draws across three weeks. Each draw's fee is the
    # proposer's gain across that draw's block; BOB nets the drawn
    # amount minus his own draw fees (module docstring, "Fees").
    fees = []
    for seq, amount, ts in (
        (0, 500, DEC1 + 60),
        (1, 500, DEC1 + WEEK + 60),
        (2, 200, DEC1 + 2 * WEEK + 60),
    ):
        before = ch.bal[PROPOSER]
        draw = draw_tx(grant_id, amount, seq=seq)
        ch.block([draw], height=21 + seq, ts=ts)
        assert ch.accepted(draw), ch.receipt(draw)
        fees.append(ch.bal[PROPOSER] - before)
    assert fees[0] > 0 and fees[0] == fees[1] == fees[2] == create_fee
    assert ch.bal[BOB] == 1200 - sum(fees)
    assert ch.grant_book.get(grant_id).remaining == 3800

    # An empty block at the deadline runs the sweep.
    alice_before = ch.bal[ALICE]
    proposer_before = ch.bal[PROPOSER]
    ch.block([], height=24, ts=DEADLINE)
    assert ch.bal[ALICE] - alice_before == 3800
    assert ch.bal[PROPOSER] - proposer_before == 0  # the sweep is fee-free
    state = ch.grant_book.get(grant_id)
    assert state.remaining == 0
    assert state.refunded is True
    assert (grant_id, "refunded") in ch.grant_events()


def test_grant_shared_cap_binds_across_grants_native():
    """Stage-3 headline addition: two grants in one cap group, each
    with its own 500/week cap, may together draw at most 600/week.
    BOB's 500 leaves only 100 of the shared budget: CAROL's 101 draw
    is refused (and pays nothing), her 100 draw lands — the full
    apply path with the real engine stepping every block."""
    ch = Chain({ALICE: 20_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    group = {"cap_group": "team-budget", "cap_group_cap": 600}
    c1 = create_tx(seq=0, total=5000, cap=500, extra=group)
    ch.block([c1], height=20, ts=DEC1 - 60)
    assert ch.accepted(c1), ch.receipt(c1)
    c2 = create_tx(seq=1, total=5000, cap=500,
                   extra={**group, "recipient_pubkey": CAROL})
    ch.block([c2], height=21, ts=DEC1 - 60)
    assert ch.accepted(c2), ch.receipt(c2)
    g1 = parse_grant_create(c1).grant_id
    g2 = parse_grant_create(c2).grant_id

    before = ch.bal[PROPOSER]
    d1 = draw_tx(g1, 500, seq=0)
    ch.block([d1], height=22, ts=DEC1 + 60)
    assert ch.accepted(d1), ch.receipt(d1)
    bob_fee = ch.bal[PROPOSER] - before
    assert bob_fee > 0
    assert ch.bal[BOB] == 500 - bob_fee

    # The shared budget has only 100 left this week: 101 is refused,
    # and a refused draw pays nothing and moves nothing.
    over = draw_tx(g2, 101, seq=0, sk=SK_CAROL, sender=CAROL)
    ch.block([over], height=23, ts=DEC1 + 120)
    assert not ch.accepted(over)
    assert ch.bal[CAROL] == 0
    assert ch.bal[PROPOSER] == before + bob_fee
    assert ch.grant_book.get(g2).remaining == 5000

    before = ch.bal[PROPOSER]
    d2 = draw_tx(g2, 100, seq=0, sk=SK_CAROL, sender=CAROL)
    ch.block([d2], height=24, ts=DEC1 + 180)
    assert ch.accepted(d2), ch.receipt(d2)
    carol_fee = ch.bal[PROPOSER] - before
    assert carol_fee == bob_fee
    assert ch.bal[CAROL] == 100 - carol_fee
    # The group's own counter agrees: 500 + 100 drawn in this window.
    assert ch.grant_book.group_drawn_in_period(
        ch.grant_book.get(g2), ts=DEC1 + 180) == 600
