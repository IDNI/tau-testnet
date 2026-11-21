"""Native-evidence wave, Bounty 01 stage 2 (issue #35), PR #154.

Landed at tau-b01s2/tests/test_routes_native.py and registered in the
native-tau-tests CI job (see native-prep/CI-REGISTRATION.md).

Stage 2 carries two of the maintainer's five named cases:
  case 1 — 101 routed at 20% gives 20 and 81, with one fee;
  case 3 — a routed share never triggers another route.
Both exist on the mock path in tests/test_routes_apply.py, where the
evaluator is scripted ({1: amount, 8: "0", 9: fee, 5: "1"}). This file
reuses that suite's Chain / tx builders, installs a real
tau_native.TauInterface behind tau_manager (the seam
consensus/engine.py steps through via tau_session.InProcessSession),
and patches nothing on the Tau path.

The split itself is Python (consensus/routes.py RouteTerms.split); what
native evidence adds is that the split, the fee charge and the
no-retrigger property hold when the block's Tau steps — policy (o5),
fee (o9), validation (o1) — are produced by the real genesis program
instead of a script that always says yes.

Gate: idiom A (native-prep/INFRA-MAP.md §3). Locally every test skips;
the native CI job's preflight hard-fails if the module is missing.

Landing-day resolutions — the TODO-VERIFY items that touched this file
----------------------------------------------------------------------
Genesis seeding: the native CI job generates data/genesis.json in the
same docker run, before pytest starts (.github/workflows/ci.yml, "Run
real-Tau consensus suite": gen_genesis.py --out data/genesis.json
precedes the pytest invocation), and tests/test_fee_model_native.py
already reads json.load(open("data/genesis.json"))["consensus_rules"]
the same way in that job. The fixture's read below is therefore safe
as written; no genesis_consensus.tau fallback is needed.

Application-rules state: chain_state.get_application_rules_state reads
a process-global (chain_state.py, initialised to ""). The mock suite
patches it to ""; left live it can carry state across files in one CI
process — chain_state.load_genesis sets it to the genesis application
rules, and tests/test_fee_model_native.py, which runs earlier in the
native job, calls load_genesis in its setUp. Route install/apply never
installs application rules, so nothing in this file writes the global;
the fixture below pins it to "" through the production setter
(chain_state.save_application_rules_state) for the duration of each
test and restores the previous value afterwards — the same condition
the mock suite runs under, with no patch.

Fees: the mock suite scripts o9 (0 while the route installs, then 7 —
"the fee era starts after the route is installed"). The real genesis
program has no fee era switch: scripts/gen_genesis.py's --base-fee
default of 10 is injected into the consensus rules as
o9[t]:bv[24] = { #x00000a }:bv[24] (confirmed in the CI-generated
data/genesis.json), o8 = 0 (no user fee rule is installed), and
consensus/engine.py's fee settlement charges o9 + o8 to the sender of
every fee-bearing tx, capped by its signed fee_limit, credited to the
fee beneficiary or, failing that, the block proposer; this Chain's
ConsensusLifecycleManager sets no beneficiary
(consensus/governance.py: fee_beneficiary = "" and
DEFAULT_FEE_BENEFICIARY = ""), so the sink is the proposer.
receive_route_install is fee-bearing (engine.py FEE_BEARING_TX_TYPES),
and settlement hard-rejects a tx whose sender cannot cover the fee
("insufficient_funds_for_fee") — so the mock suite's opening balances,
which leave the route owners at 0, cannot install a route under the
real program at all. The builders below therefore fund both owners
(1_000 each; the mock suite itself funds CAROL 1_000 in
test_normal_transfer_cannot_bypass_route so she can send), and the
tests measure each fee event off the proposer's balance — the install
fee is the proposer's balance after the install block, the spend's fee
is the proposer's gain across the spend block — instead of assuming an
amount. Every named-case number (20 routed, 81 kept, exactly one split
event, no retrigger, 50 on the ordinary transfer) is asserted exactly,
net of the measured fees.
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
from consensus.routes import parse_route_install
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
    application-rules global is pinned to the mock suite's "" via the
    production setter for the same reason (module docstring)."""
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


# --- tx builders: copied from tests/test_routes_apply.py --------------------

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
    }
    tx.update(extra or {})
    return _sign(tx, sk)


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
    """tests/test_routes_apply.py's Chain with the scripted evaluator
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
        # chain_state.get_application_rules_state is not patched either:
        # the live_tau fixture pins the underlying global to "" via the
        # production setter for each test (module docstring).
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
    # The mock suite opens BOB and CAROL at 0 because its scripted fee
    # is 0 while a route installs. Under the real genesis program the
    # install itself is charged (module docstring, "Fees"), and a
    # sender who cannot cover the fee is rejected — so both route
    # owners open funded here. MALLORY never sends and stays at 0.
    return {ALICE: 10_000, BOB: 1_000, CAROL: 1_000, MALLORY: 0, PROPOSER: 0}


def _routed_chain(**install_kwargs):
    ch = Chain(_balances())
    tx = install_tx(**install_kwargs)
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.book.get(BOB) is not None
    return ch, parse_route_install(tx)


# --- the named cases ---------------------------------------------------------

def test_route_101_at_20pct_gives_20_and_81_one_fee_native():
    """Maintainer case 1 (#35): a 101 transfer to a 20% route credits
    the destination 20 and the recipient 81, and charges exactly one
    fee — with the real engine producing the block's Tau outputs."""
    ch, _terms = _routed_chain()
    # The install was a fee-bearing tx under the real program: BOB paid
    # one fee, credited to the proposer. Measured, not assumed — the
    # proposer's whole balance at this point is that fee.
    install_fee = ch.bal[PROPOSER]
    assert install_fee > 0
    assert ch.bal[BOB] == 1_000 - install_fee
    spend = spend_tx(ALICE, BOB, 101, seq=0)
    ch.block([spend], height=21, ts=NOW)
    assert ch.accepted(spend)
    assert ch.bal[BOB] == 1_000 - install_fee + 81
    assert ch.bal[CAROL] == 1_000 + 20
    # One fee, on the whole transfer, paid by the sender: the
    # proposer's gain across the spend block is that fee — the same
    # flat genesis fee the install paid, each measured independently
    # in this run — and Alice's debit is exactly 101 + that fee.
    fee = ch.bal[PROPOSER] - install_fee
    assert fee == install_fee
    assert ch.bal[ALICE] == 10_000 - 101 - fee
    splits = ch.splits()
    assert len(splits) == 1  # exactly one split event for the transfer


def test_routed_share_never_triggers_another_route_native():
    """Maintainer case 3 (#35): the routed share arriving at CAROL does
    not trigger CAROL's own 50% route to MALLORY; an ordinary transfer
    to CAROL routes normally — real engine throughout."""
    ch, _terms = _routed_chain()
    bob_install_fee = ch.bal[PROPOSER]
    carol_route = install_tx(owner=CAROL, sk=SK_CAROL, destination=MALLORY,
                             bps=5000, seq=0)
    ch.block([carol_route], height=21, ts=NOW)
    assert ch.accepted(carol_route)
    # CAROL's install paid the same flat fee (measured as the
    # proposer's gain across her install block).
    carol_install_fee = ch.bal[PROPOSER] - bob_install_fee
    assert carol_install_fee == bob_install_fee
    ch.block([spend_tx(ALICE, BOB, 101, seq=0)], height=22, ts=NOW)
    assert ch.bal[BOB] == 1_000 - bob_install_fee + 81
    assert ch.bal[CAROL] == 1_000 - carol_install_fee + 20  # routed share stays whole
    assert ch.bal[MALLORY] == 0  # and never triggers CAROL's route
    # But an ordinary transfer TO CAROL routes normally.
    ch.block([spend_tx(ALICE, CAROL, 100, seq=1)], height=23, ts=NOW)
    assert ch.bal[MALLORY] == 50
