"""Native-evidence wave, Bounty 01 stage 1 (issue #34), PR #152.

Landed at tau-b01/tests/test_standing_native.py and registered in the
native-tau-tests CI job (see native-prep/CI-REGISTRATION.md).

What this proves, and what it does not
--------------------------------------
Stage 1's named maintainer case is case 4 of the five: "a monthly
payment on the 31st runs on the last day of a shorter month". The
schedule arithmetic itself is Python (consensus/periods.py +
consensus/standing.py) and does not change with the evaluator. What the
mock suite (tests/test_standing_apply.py) does NOT prove is that the
case survives the real Tau engine in the loop: there, every
`apply_block` runs with tau_manager.communicate_with_tau[_multi] patched
to a scripted evaluator that hard-codes o5 = 1 and the fee.

This file reuses that suite's Chain / tx builders byte-for-byte, but
installs a real tau_native.TauInterface as tau_manager.tau_direct_interface
(the seam consensus/engine.py steps through via
tau_session.InProcessSession) and patches nothing on the Tau path.
Cases 1/3 live in stage 2's native file, cases 2/5 in stage 3's; this
file also carries stage 1's two supporting proofs (anyone may execute,
money moves once; the readable paid_for_period fact after a native
execution).

Gate: idiom A (native-prep/INFRA-MAP.md §3). Locally every test skips;
the native CI job's preflight hard-fails if the module is missing.

Landing-day resolutions — the TODO-VERIFY items that touched this file
----------------------------------------------------------------------
#2 (seed texts): the native CI job generates data/genesis.json in the
same docker run, before pytest starts (.github/workflows/ci.yml, "Run
real-Tau consensus suite": gen_genesis.py --out data/genesis.json
precedes the pytest invocation), and tests/test_fee_model_native.py
already reads json.load(open("data/genesis.json"))["consensus_rules"]
the same way in that job. The fixture's read below is therefore safe
as written; no genesis_consensus.tau fallback is needed.

#6 (fees): the mock suite scripts o9 (0 / 5 / 7). The real genesis
program charges a flat o9 = 10 per accepted user tx
(scripts/gen_genesis.py: --base-fee default 10, injected into the
consensus rules as o9[t]:bv[24] = { #x00000a }:bv[24]); o8 = 0 here
(no user fee rule is installed). consensus/engine.py's fee settlement
charges o9 + o8 to the tx's sender and credits the fee beneficiary
or, failing that, the block proposer; this Chain's
ConsensusLifecycleManager sets no beneficiary
(consensus/governance.py: fee_beneficiary = "" and
DEFAULT_FEE_BENEFICIARY = ""), so the sink is the proposer. The
transfer itself debits the payer exactly the amount and credits the
recipient in full — the shape the mock suite proves in
test_executor_pays_the_fee_not_the_payer (fee = 7: BOB == 1_000
exactly, the fee out of the executor) — so the named-case numbers
(1_000 / 2_000 to BOB) stay exact, and the tests below additionally
assert where the fee lands: sender balances and the proposer sink.

#7 (application-rules state): chain_state.get_application_rules_state
reads a process-global (chain_state.py, initialised to ""). The mock
suite patches it to ""; left live it can carry state across files in
one CI process — chain_state.load_genesis sets it to the genesis
application rules, and tests/test_fee_model_native.py, which runs
earlier in the native job, calls load_genesis in its setUp. Standing
create/execute blocks never install rules, so nothing in this file
writes the global; the fixture below pins it to "" through the
production setter (chain_state.save_application_rules_state) for the
duration of each test and restores the previous value afterwards —
the same condition the mock suite runs under, with no patch.
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
from consensus.periods import PERIOD_MONTH, SECONDS_PER_DAY
from consensus.standing import parse_standing_create
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
    """Install the real engine behind tau_manager for every test here.

    Mirrors tests/test_fee_model_native.py's setUp: a TauInterface on
    the real genesis program, seeded with the transfer rule and the
    genesis consensus rules the same way production seeds them.
    """
    import tau_native

    import chain_state

    iface = tau_native.TauInterface(GENESIS_TAU)
    old_iface = tau_manager.tau_direct_interface
    old_mode = tau_manager.tau_test_mode
    tau_manager.tau_direct_interface = iface
    tau_manager.tau_test_mode = False
    tau_manager.tau_ready.set()
    # TODO-VERIFY #7 resolution (module docstring): pin the
    # process-global application-rules state to the mock suite's ""
    # via the production setter; restored on teardown below.
    prev_rules_state = chain_state.get_application_rules_state()
    chain_state.save_application_rules_state("")
    # Seed texts, as in test_fee_model_native: the transfer rule and
    # the preprocessed consensus_rules from data/genesis.json, which
    # the CI native job generates before pytest runs (TODO-VERIFY #2,
    # module docstring).
    import json

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


# --- tx builders: copied verbatim from tests/test_standing_apply.py --------

FAR = 9_999_999_999


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


ANCHOR = _ts(2026, 1, 31, 12)  # monthly, anchored on the 31st
BEFORE = _ts(2026, 1, 30, 12)
DUE_JAN = _ts(2026, 1, 31, 13)  # inside the January window
DUE_FEB = _ts(2026, 2, 28, 12)  # February window (clamped to the 28th)


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


def create_tx(sk=SK_ALICE, sender=ALICE, recipient=BOB, amount=1000, seq=0,
              fee_limit="100", signer_sk=None, extra=None, drop=()):
    tx = {
        "tx_id": f"standing-create-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_create",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient,
        "amount": amount,
        "period_kind": PERIOD_MONTH,
        "anchor_timestamp": ANCHOR,
        "window_start_offset": 0,
        "window_end_offset": SECONDS_PER_DAY,
        "max_occurrences": 12,
    }
    for key in drop:
        tx.pop(key, None)
    tx.update(extra or {})
    return _sign(tx, signer_sk if signer_sk is not None else sk)


def execute_tx(standing_id_hex, sk=SK_CAROL, sender=CAROL, seq=0, fee_limit="100"):
    tx = {
        "tx_id": f"standing-execute-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_execute",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "standing_id": standing_id_hex,
    }
    return _sign(tx, sk)


class Chain:
    """tests/test_standing_apply.py's Chain with the scripted evaluator
    removed: apply_block steps the real engine via the live_tau fixture.
    Balances/sequences/last_transfer_ts/lifecycle are carried in the
    snapshot metadata exactly as in the mock suite."""

    def __init__(self, balances):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.last = None

    def block(self, txs, height=20, ts=BEFORE):
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
        # NO patches on the Tau path: the engine's InProcessSession calls
        # tau_manager.communicate_with_tau_multi, which delegates to the
        # real TauInterface installed by the live_tau fixture.
        # chain_state.get_application_rules_state is not patched either:
        # the live_tau fixture pins the underlying global to "" via the
        # production setter for each test (TODO-VERIFY #7, module
        # docstring).
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
        return self.lm.standing_payments

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids


def _balances():
    return {ALICE: 10_000, BOB: 0, CAROL: 100, MALLORY: 100, PROPOSER: 0}


def _created_chain():
    ch = Chain(_balances())
    tx = create_tx()
    ch.block([tx], height=20, ts=BEFORE)
    assert ch.accepted(tx)
    sid = parse_standing_create(tx).standing_id
    assert ch.book.get(sid) is not None
    return ch, sid


# --- the named case ---------------------------------------------------------

def test_monthly_on_31st_runs_on_last_day_of_short_month_native():
    """Maintainer case 4 (#34): a monthly payment anchored on the 31st
    executes in January, and its February occurrence runs on the last
    day of the shorter month (Feb 28) — with the real Tau engine
    stepping every block."""
    ch, sid = _created_chain()
    ch.block([execute_tx(sid.hex())], height=21, ts=DUE_JAN)
    ex = execute_tx(sid.hex(), seq=1)
    ch.block([ex], height=22, ts=DUE_FEB)
    assert ch.accepted(ex)
    # Fees (TODO-VERIFY #6, module docstring): the mock suite asserts
    # BOB == 2_000 with a scripted fee of 0. Under the real engine the
    # recipient credit is still exactly the amount — the genesis flat
    # fee (o9 = 10 per accepted tx) is charged to each tx's sender and
    # credited to the proposer, never taken out of the transfer. So
    # the case number stands, and the fee landing is asserted too:
    # Alice paid the create fee, Carol both execution fees.
    assert ch.bal[BOB] == 2_000
    assert ch.book.paid_for_period(sid, 1)
    assert ch.bal[ALICE] == 10_000 - 10 - 2_000
    assert ch.bal[CAROL] == 100 - 2 * 10
    assert ch.bal[PROPOSER] == 3 * 10


def test_create_then_anyone_executes_and_money_moves_once_native():
    """Supporting proof: a third party (neither payer nor recipient)
    executes the January occurrence through the real engine; the money
    moves exactly once and the period fact is set."""
    ch, sid = _created_chain()
    ex = execute_tx(sid.hex())  # Carol executes; she is neither party.
    ch.block([ex], height=21, ts=DUE_JAN)
    assert ch.accepted(ex)
    assert ch.bal[BOB] == 1_000
    assert ch.book.paid_for_period(sid, 0)
    # The genesis flat fee (10 per accepted tx) landed on the senders
    # and the proposer sink, not on the recipient (TODO-VERIFY #6).
    assert ch.bal[ALICE] == 10_000 - 10 - 1_000
    assert ch.bal[CAROL] == 100 - 10
    assert ch.bal[PROPOSER] == 2 * 10
    # A second execution in the same period is refused by apply.
    ex2 = execute_tx(sid.hex(), seq=1)
    ch.block([ex2], height=22, ts=DUE_JAN + 3600)
    assert not ch.accepted(ex2)
    assert ch.bal[BOB] == 1_000
