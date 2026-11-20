"""Block-apply semantics for standing payments (Bounty 01, issue #34).

Runs through the real `apply_block` with a scripted evaluator, mirroring
tests/test_retractable_apply.py. The named tests are the engine-level
half of the design's case -> test mapping for #34: the book-level half
lives in tests/test_standing.py.
"""

import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.periods import PERIOD_MONTH, SECONDS_PER_DAY
from consensus.standing import parse_standing_create
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

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


def cancel_tx(standing_id_hex, sk=SK_ALICE, sender=ALICE, seq=1, fee_limit="100"):
    tx = {
        "tx_id": f"standing-cancel-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_cancel",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "standing_id": standing_id_hex,
    }
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
        return self.lm.standing_payments

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids


def _balances():
    return {ALICE: 10_000, BOB: 0, CAROL: 100, MALLORY: 100, PROPOSER: 0}


def _created_chain(fee=0):
    ch = Chain(_balances(), fee=fee)
    tx = create_tx()
    ch.block([tx], height=20, ts=BEFORE)
    assert ch.accepted(tx)
    sid = parse_standing_create(tx).standing_id
    assert ch.book.get(sid) is not None
    return ch, sid


def test_create_then_anyone_executes_and_money_moves_once():
    ch, sid = _created_chain()
    ex = execute_tx(sid.hex())  # Carol executes; she is neither party.
    ch.block([ex], height=21, ts=DUE_JAN)
    assert ch.accepted(ex)
    assert ch.bal[ALICE] == 9_000
    assert ch.bal[BOB] == 1_000
    assert ch.book.paid_for_period(sid, 0)


def test_second_execution_in_same_period_is_rejected():
    ch, sid = _created_chain()
    ch.block([execute_tx(sid.hex())], height=21, ts=DUE_JAN)
    ex2 = execute_tx(sid.hex(), seq=1)
    ch.block([ex2], height=22, ts=DUE_JAN + 3600)
    assert not ch.accepted(ex2)
    assert ch.bal[ALICE] == 9_000
    assert ch.bal[BOB] == 1_000


def test_execution_outside_the_window_is_rejected():
    ch, sid = _created_chain()
    ex = execute_tx(sid.hex())
    ch.block([ex], height=21, ts=BEFORE)  # a day before the first window
    assert not ch.accepted(ex)
    assert ch.bal[BOB] == 0


def test_february_execution_uses_the_clamped_day():
    ch, sid = _created_chain()
    ch.block([execute_tx(sid.hex())], height=21, ts=DUE_JAN)
    ex = execute_tx(sid.hex(), seq=1)
    ch.block([ex], height=22, ts=DUE_FEB)
    assert ch.accepted(ex)
    assert ch.bal[BOB] == 2_000
    assert ch.book.paid_for_period(sid, 1)


def test_cancel_prevents_all_later_executions():
    ch, sid = _created_chain()
    cx = cancel_tx(sid.hex())
    ch.block([cx], height=21, ts=BEFORE + 3600)
    assert ch.accepted(cx)
    ex = execute_tx(sid.hex())
    ch.block([ex], height=22, ts=DUE_JAN)
    assert not ch.accepted(ex)
    assert ch.bal[BOB] == 0


def test_only_the_payer_can_cancel():
    ch, sid = _created_chain()
    cx = cancel_tx(sid.hex(), sk=SK_MALLORY, sender=MALLORY, seq=0)
    ch.block([cx], height=21, ts=BEFORE + 3600)
    assert not ch.accepted(cx)
    assert ch.book.get(sid) is not None


def test_insufficient_funds_execution_leaves_the_marker_untouched():
    ch = Chain({ALICE: 500, BOB: 0, CAROL: 5_000, MALLORY: 0, PROPOSER: 0})
    tx = create_tx()
    ch.block([tx], height=20, ts=BEFORE)
    sid = parse_standing_create(tx).standing_id
    ex = execute_tx(sid.hex())
    ch.block([ex], height=21, ts=DUE_JAN)
    assert not ch.accepted(ex)  # Alice has 500 < 1000 due
    assert not ch.book.paid_for_period(sid, 0)
    # Carol tops Alice up inside the same window; execution now succeeds.
    top = spend_tx(CAROL, ALICE, 600, seq=0)
    ch.block([top], height=22, ts=DUE_JAN + 600)
    ex2 = execute_tx(sid.hex(), seq=1)
    ch.block([ex2], height=23, ts=DUE_JAN + 1200)
    assert ch.accepted(ex2)
    assert ch.bal[BOB] == 1_000
    assert ch.book.paid_for_period(sid, 0)


def test_create_without_exactly_one_end_condition_is_rejected():
    ch = Chain(_balances())
    two = create_tx(extra={"max_total": 12_000})
    ch.block([two], height=20, ts=BEFORE)
    assert not ch.accepted(two)
    none = create_tx(drop=("max_occurrences",))
    ch.block([none], height=21, ts=BEFORE)
    assert not ch.accepted(none)
    assert ch.book.is_empty()


def test_executor_pays_the_fee_not_the_payer():
    ch, sid = _created_chain(fee=7)
    # Creation was transfer-less: its signer (Alice) paid the fee step.
    assert ch.bal[ALICE] == 10_000 - 7
    ex = execute_tx(sid.hex())
    ch.block([ex], height=21, ts=DUE_JAN)
    assert ch.accepted(ex)
    # The transfer debited the payer exactly the amount; the execution
    # fee (7) came out of the executor, Carol.
    assert ch.bal[ALICE] == 10_000 - 7 - 1_000
    assert ch.bal[BOB] == 1_000
    assert ch.bal[CAROL] == 100 - 7


# -- admission/apply agreement + exactly-once clock ---------------------------


class _ChainTipView:
    """Admission view backed by a chain's live standing book.

    Rows are the book's own snapshot rows -- the same dicts the
    persisted-tip facade serves -- so admission screens exactly the
    state block apply will see.
    """

    def __init__(self, chain, ts):
        from consensus.standing import StandingTerms

        self._rows = {}
        for row in chain.book.snapshot_rows():
            terms = StandingTerms(
                payer=row["payer_pubkey"],
                recipient=row["recipient_pubkey"],
                amount=row["amount"],
                kind=row["period_kind"],
                anchor_ts=row["anchor_timestamp"],
                window_start_offset=row["window_start_offset"],
                window_end_offset=row["window_end_offset"],
                end_kind=row["end_kind"],
                end_value=row["end_value"],
                sequence_number=row["sequence_number"],
                supersedes=(
                    bytes.fromhex(row["supersedes_id"])
                    if row.get("supersedes_id")
                    else None
                ),
            )
            self._rows[terms.standing_id.hex()] = row
        self.next_block_timestamp = ts
        self.next_block_height = 50

    def get_standing(self, standing_id):
        return self._rows.get(bytes(standing_id).hex())


def test_admission_and_apply_agree_on_the_same_book_and_order():
    """Same execute payloads, two gates, one verdict.

    Each payload is screened by mempool admission against the chain's
    own tip book and then applied in a block at the same timestamp;
    the verdicts must agree across the matrix: early, due, twice in
    one period, late (the period's window has lapsed), a later period
    due on its own window while the lapsed one stays unsettled (our
    execute names no period, so there is no period argument to get
    wrong -- the book derives the due period at both gates), and after
    cancel. Admission and apply share the book's `due_period`, which
    is what makes the agreement structural rather than coincidental.
    Funds are sufficient throughout, so apply's balance screen -- the
    one check admission cannot mirror -- never fires.
    """
    from consensus.admission import validate_standing_execute_payload

    ch, sid = _created_chain()
    carol_next_seq = [0]

    def attempt(ts, height):
        tx = execute_tx(sid.hex(), seq=carol_next_seq[0])
        admitted = validate_standing_execute_payload(
            tx, _ChainTipView(ch, ts)
        ).is_valid
        ch.block([tx], height=height, ts=ts)
        applied = ch.accepted(tx)
        if applied:
            carol_next_seq[0] += 1
        assert admitted == applied, (ts, admitted, applied)
        return applied

    assert not attempt(BEFORE, 21)  # early: before the first window
    assert attempt(DUE_JAN, 22)  # due: inside the January window
    assert not attempt(DUE_JAN + 3600, 23)  # twice in the same period
    assert not attempt(_ts(2026, 2, 2, 12), 24)  # late: window lapsed
    # February's window passes with no execution, so period 1 lapses
    # unsettled. March is due on its own window and settles period 2;
    # period 1 stays unsettled forever (no catch-up), and both gates
    # agree on that too.
    assert attempt(_ts(2026, 3, 31, 13), 25)
    assert ch.book.paid_for_period(sid, 2)
    assert not ch.book.paid_for_period(sid, 1)
    # After the payer cancels, both gates refuse every later execute.
    cx = cancel_tx(sid.hex())
    ch.block([cx], height=26, ts=_ts(2026, 4, 2, 12))
    assert ch.accepted(cx)
    assert not attempt(_ts(2026, 4, 30, 13), 27)


def test_execution_moves_only_the_payers_clock_never_the_executors():
    """Exactly once, per authorization -- and only the payer's clock.

    Carol executes Alice's standing payment: the settled-period clock
    that moves belongs to Alice's authorization. Carol, the executor,
    acquires no cooldown of her own: her own standing payment (Carol
    as payer) is untouched by the execution and still executes in the
    very same period, while nobody -- Carol included -- can execute
    Alice's a second time in that period.
    """
    ch = Chain(_balances())
    create_a = create_tx()  # Alice -> Bob, 1000
    ch.block([create_a], height=20, ts=BEFORE)
    sid_a = parse_standing_create(create_a).standing_id
    create_c = create_tx(sk=SK_CAROL, sender=CAROL, amount=50, seq=0)
    ch.block([create_c], height=21, ts=BEFORE)
    sid_c = parse_standing_create(create_c).standing_id

    ex = execute_tx(sid_a.hex(), seq=1)  # Carol executes Alice's
    ch.block([ex], height=22, ts=DUE_JAN)
    assert ch.accepted(ex)
    assert ch.book.paid_for_period(sid_a, 0)
    # The executor's own authorization did not move.
    rec_c = ch.book.get(sid_c)
    assert rec_c.executed_count == 0
    assert rec_c.last_executed_period == -1
    assert not ch.book.paid_for_period(sid_c, 0)
    # Nobody can execute Alice's a second time in the period.
    ex2 = execute_tx(sid_a.hex(), sk=SK_MALLORY, sender=MALLORY, seq=0)
    ch.block([ex2], height=23, ts=DUE_JAN + 3600)
    assert not ch.accepted(ex2)
    # Carol's own payment still executes in the same period: executing
    # for Alice gave her no cooldown.
    ex3 = execute_tx(sid_c.hex(), sk=SK_ALICE, sender=ALICE, seq=1)
    ch.block([ex3], height=24, ts=DUE_JAN + 7200)
    assert ch.accepted(ex3)
    assert ch.book.paid_for_period(sid_c, 0)
    assert ch.bal[BOB] == 1_050
    assert ch.bal[CAROL] == 100 - 50
