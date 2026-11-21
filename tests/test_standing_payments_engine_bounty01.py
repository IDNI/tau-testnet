"""Bounty 01, issue #34: standing payments at the engine seam (mock Tau).

Slice 4 of DESIGN-01-TAKEOVER.md: the standing-payment book (slice 2) is
wired into block apply. Create/cancel validate through the book's own
can_create/can_cancel and mutate only at the post-settlement site (a
fee-rejected create installs nothing); an execution is decided by the
book's execution_due and settled through the ordinary transfer seam, so
the payer's o5 is re-checked on the real recipient and amount, exactly one
fee is measured on the real transfer inputs, and the credit carries the
standing-execution class — a receive route never splits it (the design's
credit-class table, slice 1).

Covered here: #34-7 at engine level (an o5-blocked execution settles
nothing and advances no marker; totals settle exactly once), #34-8
(admission and apply reach the same verdicts), #34-9 (the capability
record matches the book's constants), the end conditions binding at
engine level (occurrence cap, final_ts), the paid-for-period fact read
back through the facade, and the signed fee_limit semantics (submitter
pays by default; the payer funds a third-party execution up to the limit;
a payer-self execution above the limit is refused).
"""
import hashlib
import itertools
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus import standing_payments
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.receive_routes import ReceiveRouteEntry
from consensus.standing_payments import (
    SCHEDULE_DAILY,
    StandingPaymentBook,
    parse_create_standing_payment,
    standing_payment_capabilities,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_800_000_000
FEE = 7
AMOUNT = 250


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)        # proposer / sole validator / fee beneficiary
SK_PAYER, PAYER = _key(22222)        # the standing payment's payer
SK_RECIPIENT, RECIPIENT = _key(33333)
SK_EXECUTOR, EXECUTOR = _key(55555)  # any third party may trigger execution
SK_DEST, DEST = _key(66666)          # receive-route destination

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

    Mirrors the slice-3 routes harness; `allow=False` makes the scripted
    evaluator's o5 refuse, which is how a payer policy block presents.
    """

    def __init__(self, balances, lm=None, ts=TS):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT

    def apply(self, txs, fee=FEE, allow=True):
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
            return {1: str(amount), 8: "0", 9: str(fee), 5: "1" if allow else "0"}

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


def _create_tx(payer, sk, recipient, amount, seq, fee_limit="100", **kw):
    return _sign({
        "tx_id": f"standing-{next(_TX_SEQ)}",
        "tx_type": "create_standing_payment",
        "sender_pubkey": payer,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "standing_recipient_pubkey": recipient,
        "standing_amount": amount,
        "standing_schedule": kw.get("schedule", "daily"),
        "standing_signed_day": kw.get("signed_day", 0),
        "standing_anchor_ts": kw.get("anchor_ts", TS - 100),
        "standing_window_seconds": kw.get("window_seconds", 3600),
        "standing_final_ts": kw.get("final_ts", 0),
        "standing_max_occurrences": kw.get("max_occurrences", 0),
        "standing_max_total": kw.get("max_total", 0),
        "standing_fee_limit": kw.get("standing_fee_limit", 0),
        "standing_policy_version_ref": kw.get("policy_version_ref", 0),
        "standing_allow_catch_up": kw.get("allow_catch_up", 0),
        "standing_version": kw.get("version", 1),
    }, sk)


def _cancel_tx(sender, sk, auth_id, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"standing-cancel-{next(_TX_SEQ)}",
        "tx_type": "cancel_standing_payment",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "standing_auth_id": auth_id.hex(),
    }, sk)


def _execute_tx(sender, sk, auth_id, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"standing-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_standing_payment",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
        "standing_auth_id": auth_id.hex(),
    }, sk)


def _auth_id(create_tx):
    return parse_create_standing_payment(create_tx).auth_id


def _funded_chain():
    return _Chain({ALICE: 0, PAYER: 100000, RECIPIENT: 1000, EXECUTOR: 1000, DEST: 0})


def _created_chain(**kw):
    """A chain with one live authorization (PAYER -> RECIPIENT, daily).

    Defaults to a max_total end condition (the book requires one) unless
    the caller pins a different end condition.
    """
    if not any(k in kw for k in ("final_ts", "max_occurrences", "max_total")):
        kw["max_total"] = 100000
    chain = _funded_chain()
    create = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0, **kw)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    return chain, _auth_id(create)


def _book(chain):
    return chain.lm.standing_payments


# --- create / update / cancel administration ------------------------------------

def test_create_lands_and_is_due_immediately():
    chain, auth_id = _created_chain()
    entry = _book(chain).get(auth_id)
    assert entry is not None and entry.amount == AMOUNT
    assert chain.balances[PAYER] == 100000 - FEE  # exactly one create fee
    assert _book(chain).status(auth_id, TS) == "active"
    assert _book(chain).next_due_ts(auth_id, TS) == TS - 100


def test_create_event_in_block_metadata():
    chain = _funded_chain()
    create = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0, max_total=100000)
    result = chain.apply([create])
    (event,) = result.next_snapshot.metadata["standing_payment_events"]
    assert event["action"] == "created"
    assert event["auth_id"] == _auth_id(create).hex()
    assert event["payer_pubkey"] == PAYER and event["amount"] == AMOUNT
    assert result.governance_changes["standing_payment_events"] == [event]


def test_create_with_unpaid_fee_installs_nothing():
    """The deferred commit: a fee-rejected create leaves no authorization."""
    chain = _funded_chain()
    broke = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0,
                       fee_limit="0", max_total=100000)
    result = chain.apply([broke])
    assert broke["tx_id"] in result.invalid_tx_ids
    assert _book(chain).is_empty()

    # The sequence was not consumed, so the honest retry at seq 0 lands.
    honest = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0,
                        max_total=100000)
    result = chain.apply([honest])
    assert honest["tx_id"] in result.accepted_tx_ids
    assert not _book(chain).is_empty()


def test_open_ended_create_is_refused_by_the_book():
    """The maintainer's #34 addition: an end condition is required."""
    chain = _funded_chain()
    # _create_tx's defaults carry no end condition (all three zero).
    create = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0)
    result = chain.apply([create])
    assert create["tx_id"] in result.invalid_tx_ids
    assert _book(chain).is_empty()


def test_update_must_be_the_next_version():
    chain, auth_id = _created_chain(max_total=100000)
    skipping = _create_tx(
        PAYER, SK_PAYER, RECIPIENT, 300, seq=1, version=3, max_total=100000)
    result = chain.apply([skipping])
    assert skipping["tx_id"] in result.invalid_tx_ids
    assert _book(chain).get(auth_id).amount == AMOUNT

    proper = _create_tx(
        PAYER, SK_PAYER, RECIPIENT, 300, seq=1, version=2, max_total=100000)
    result = chain.apply([proper])
    assert proper["tx_id"] in result.accepted_tx_ids
    new_entry = _book(chain).get(_auth_id(proper))
    assert new_entry.amount == 300 and new_entry.version == 2
    # Supersession is wholesale (the slice-2 book's semantics): the old
    # version's entry is replaced, and the new one is the live term.
    assert _book(chain).get(auth_id) is None
    assert _book(chain).status(new_entry.auth_id, TS) == "active"


def test_cancel_by_payer_blocks_execution_and_cancel_by_stranger_fails():
    chain, auth_id = _created_chain(max_total=100000)

    stranger = _cancel_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([stranger])
    assert stranger["tx_id"] in result.invalid_tx_ids
    assert _book(chain).status(auth_id, TS) == "active"

    cancel = _cancel_tx(PAYER, SK_PAYER, auth_id, seq=1)
    result = chain.apply([cancel])
    assert cancel["tx_id"] in result.accepted_tx_ids
    assert _book(chain).status(auth_id, TS) == "cancelled"
    (event,) = result.next_snapshot.metadata["standing_payment_events"]
    assert event["action"] == "cancelled"

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert _book(chain).total_executed(auth_id) == (0, 0)


def test_cancel_of_unknown_id_is_refused():
    chain = _funded_chain()
    cancel = _cancel_tx(PAYER, SK_PAYER, b"\x07" * 32, seq=0)
    result = chain.apply([cancel])
    assert cancel["tx_id"] in result.invalid_tx_ids


# --- execution: settle exactly once through the seam ------------------------------

def test_third_party_execution_settles_once_with_one_fee():
    chain, auth_id = _created_chain(max_total=100000)
    payer_after_create = chain.balances[PAYER]

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT
    assert chain.balances[PAYER] == payer_after_create - AMOUNT
    # The submitter pays exactly one fee, measured on the real transfer.
    assert chain.balances[EXECUTOR] == 1000 - FEE
    assert chain.balances[ALICE] == 2 * FEE  # create fee + execution fee

    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    (fact,) = _book(chain).facts_for(auth_id)
    assert fact.period_index == 0 and fact.amount == AMOUNT
    (event,) = result.next_snapshot.metadata["standing_payment_events"]
    assert event["action"] == "executed" and event["amount"] == AMOUNT
    assert event["periods_collected"] == 1 and event["total_paid"] == AMOUNT
    assert "Standing payment executed" in _logs(result)

    # The same period cannot settle twice.
    again = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    result = chain.apply([again])
    assert again["tx_id"] in result.invalid_tx_ids
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT


def test_execution_credit_is_never_split_by_a_receive_route():
    """The design's credit-class table: standing credits do not route."""
    chain, auth_id = _created_chain(max_total=100000)
    chain.lm.receive_routes.install(ReceiveRouteEntry(
        owner_pubkey=RECIPIENT, destination_pubkey=DEST, bps=2000,
        min_amount=0, activation_ts=0, expiry_ts=0, locked_until_ts=0,
        version=1,
    ), TS)

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT  # whole, not 200
    assert chain.balances[DEST] == 0
    assert result.next_snapshot.metadata["routing_events"] == []


def test_o5_blocked_execution_settles_nothing_then_settles_once():
    """#34-7: the payer's policy re-check gates the execution itself."""
    chain, auth_id = _created_chain(max_total=100000)
    payer_after_create = chain.balances[PAYER]

    blocked = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([blocked], allow=False)
    assert blocked["tx_id"] in result.invalid_tx_ids
    assert chain.balances[PAYER] == payer_after_create
    assert chain.balances[RECIPIENT] == 1000
    assert _book(chain).total_executed(auth_id) == (0, 0)
    assert _book(chain).facts_for(auth_id) == []

    allowed = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([allowed])
    assert allowed["tx_id"] in result.accepted_tx_ids
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    assert chain.balances[RECIPIENT] == 1000 + AMOUNT


def test_insufficient_funds_execution_settles_nothing():
    chain = _Chain({ALICE: 0, PAYER: 100, RECIPIENT: 0, EXECUTOR: 1000, DEST: 0})
    create = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0, max_total=100000)
    result = chain.apply([create])
    assert create["tx_id"] in result.accepted_tx_ids
    auth_id = _auth_id(create)

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.invalid_tx_ids
    assert _book(chain).total_executed(auth_id) == (0, 0)
    assert _book(chain).facts_for(auth_id) == []


# --- end conditions bind at engine level -------------------------------------------

def test_occurrence_cap_ends_the_authorization():
    chain, auth_id = _created_chain(max_occurrences=1)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert _book(chain).status(auth_id, TS) == "ended"

    chain.ts = TS + 86400  # the next period would be due but for the cap
    again = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    result = chain.apply([again])
    assert again["tx_id"] in result.invalid_tx_ids
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)


def test_final_ts_ends_the_authorization():
    chain, auth_id = _created_chain(final_ts=TS + 1000)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids

    chain.ts = TS + 86400  # period 1 starts after final_ts
    again = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=1)
    result = chain.apply([again])
    assert again["tx_id"] in result.invalid_tx_ids
    assert _book(chain).total_executed(auth_id) == (1, AMOUNT)
    assert _book(chain).status(auth_id, chain.ts) == "ended"


# --- the signed fee_limit -----------------------------------------------------------

def test_payer_funded_fee_reimburses_the_executor_up_to_the_limit():
    chain, auth_id = _created_chain(max_total=100000, standing_fee_limit=10)
    payer_after_create = chain.balances[PAYER]

    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    # Executor: fee charged, then reimbursed in full (7 <= limit 10).
    assert chain.balances[EXECUTOR] == 1000
    # Payer: the amount plus the funded fee.
    assert chain.balances[PAYER] == payer_after_create - AMOUNT - FEE
    (event,) = result.next_snapshot.metadata["standing_payment_events"]
    assert event["fee_reimbursed"] == FEE


def test_no_fee_limit_means_the_submitter_pays():
    chain, auth_id = _created_chain(max_total=100000)  # standing_fee_limit = 0
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([execute])
    assert execute["tx_id"] in result.accepted_tx_ids
    assert chain.balances[EXECUTOR] == 1000 - FEE
    (event,) = result.next_snapshot.metadata["standing_payment_events"]
    assert "fee_reimbursed" not in event


def test_payer_self_execution_above_the_fee_limit_is_refused():
    chain, auth_id = _created_chain(max_total=100000, standing_fee_limit=3)
    payer_after_create = chain.balances[PAYER]

    own = _execute_tx(PAYER, SK_PAYER, auth_id, seq=1)
    result = chain.apply([own])
    assert own["tx_id"] in result.invalid_tx_ids
    assert chain.balances[PAYER] == payer_after_create  # nothing moved, no fee
    assert _book(chain).total_executed(auth_id) == (0, 0)

    # A third party can still execute; the payer funds only up to 3 of the 7.
    other = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    result = chain.apply([other])
    assert other["tx_id"] in result.accepted_tx_ids
    assert chain.balances[EXECUTOR] == 1000 - (FEE - 3)
    assert chain.balances[PAYER] == payer_after_create - AMOUNT - 3
    (event,) = result.next_snapshot.metadata["standing_payment_events"]
    assert event["fee_reimbursed"] == 3


# --- #34-9: the capability record -----------------------------------------------------

def test_capability_record_matches_the_book():
    caps = standing_payment_capabilities()
    assert caps["supported"] is True
    assert caps["schedules"] == ["daily", "monthly", "weekly"]
    assert caps["max_window_seconds"]["daily"] == (
        standing_payments.MAX_WINDOW_SECONDS[SCHEDULE_DAILY])
    assert caps["end_condition"] == (
        "required: a final period, an occurrence limit, or a maximum total")
    assert caps["paid_for_period_fact"] is True
    assert "signed terms cannot be altered" in caps["execution"]


# --- the paid-for-period fact through the facade ---------------------------------------

class _TipView(TipAdmissionView):
    """The real facade view over an injected book, at a fixed timestamp."""

    def __init__(self, book, balances):
        self._book = book
        self._balances = balances

    @property
    def next_block_timestamp(self):
        return TS

    def _tip_standing_book(self):
        return self._book

    def get_balance(self, pubkey):
        return self._balances.get(pubkey, 0)


def test_paid_for_period_fact_is_readable_via_the_facade():
    chain, auth_id = _created_chain(max_occurrences=1)
    execute = _execute_tx(EXECUTOR, SK_EXECUTOR, auth_id, seq=0)
    chain.apply([execute])

    view = _TipView(_book(chain), dict(chain.balances))
    got = view.get_standing_payment(auth_id)
    assert got is not None
    assert got["status"] == "ended"
    assert got["occurrences_executed"] == 1 and got["total_executed"] == AMOUNT
    (fact,) = got["paid_facts"]
    assert fact["period_index"] == 0 and fact["amount"] == AMOUNT
    assert fact["period_start_ts"] == TS - 100
    assert view.get_standing_payment(b"\x09" * 32) is None


# --- #34-8: admission and apply agree ---------------------------------------------------

def test_admission_agrees_with_apply():
    from consensus.admission import (
        validate_cancel_standing_payment_payload,
        validate_create_standing_payment_payload,
        validate_execute_standing_payment_payload,
    )

    empty = _TipView(StandingPaymentBook(), {PAYER: 100000})

    good = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0, max_total=100000)
    assert validate_create_standing_payment_payload(good, empty).is_valid

    # Open-ended: no end condition — the book refuses, so admission does.
    open_ended = _create_tx(PAYER, SK_PAYER, RECIPIENT, AMOUNT, seq=0)
    assert not validate_create_standing_payment_payload(open_ended, empty).is_valid

    # A create the book itself refuses (a payer paying themselves).
    self_pay = _create_tx(PAYER, SK_PAYER, PAYER, AMOUNT, seq=0, max_total=100000)
    assert not validate_create_standing_payment_payload(self_pay, empty).is_valid

    # Cancel/execute of an authorization the tip does not know.
    unknown = b"\x07" * 32
    assert not validate_cancel_standing_payment_payload(
        _cancel_tx(PAYER, SK_PAYER, unknown, seq=0), empty).is_valid
    assert not validate_execute_standing_payment_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, unknown, seq=0), empty).is_valid

    # With the authorization live at the tip: cancel is the payer's alone,
    # and execution is due exactly when the book says it is.
    book = StandingPaymentBook()
    entry = parse_create_standing_payment(good)
    book.create(entry, TS)
    live = _TipView(book, {PAYER: 100000})
    assert not validate_cancel_standing_payment_payload(
        _cancel_tx(EXECUTOR, SK_EXECUTOR, entry.auth_id, seq=0), live).is_valid
    assert validate_cancel_standing_payment_payload(
        _cancel_tx(PAYER, SK_PAYER, entry.auth_id, seq=0), live).is_valid
    due = validate_execute_standing_payment_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, entry.auth_id, seq=0), live)
    assert due.is_valid and due.data["amount"] == AMOUNT

    # After cancellation the same execution is refused.
    book.cancel(entry.auth_id, TS)
    assert not validate_execute_standing_payment_payload(
        _execute_tx(EXECUTOR, SK_EXECUTOR, entry.auth_id, seq=0), live).is_valid
