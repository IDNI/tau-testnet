"""Envelopes outside block apply: parsing, admission, signing, the meta hash,
persistence, RPC (the capability report and history), gettxstatus, gossip, the
command line and the book's own arithmetic (spending limits).

The admission tests end with a corpus judged by BOTH the admission validator and
the book apply consults: they must accept and reject the same envelopes, or a
proposer and the mempool disagree about what can land.
"""
import argparse
import copy
import json
import types
from unittest.mock import MagicMock

import pytest

import chain_state
import db
import tau_defs
from commands import checktx, getenvelope, getenvelopes, gettxstatus, sendtx
from consensus.admission import (
    TipAdmissionView,
    validate_envelope_release_payload,
    validate_envelope_send_payload,
    validate_envelope_spend_payload,
    validate_mempool_admission,
)
from consensus.envelope import (
    KIND_BLOCKS,
    KIND_SECONDS,
    MAX_CAPS,
    MAX_LIFETIME_BLOCKS,
    MAX_LIFETIME_SECONDS,
    MAX_OPEN_ENVELOPES_PER_SENDER,
    MAX_PERIOD_BLOCKS,
    MAX_PERIOD_SECONDS,
    OUTCOME_ENDED,
    EnvelopeBook,
    EnvelopeRefused,
    EnvelopeShapeError,
    EnvelopeSpend,
    EnvelopeState,
    EnvelopeTerms,
    parse_envelope_release,
    parse_envelope_send,
    parse_envelope_spend,
)
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.lanes import LANE_FAST, TAU_EVALUATING_TX_TYPES, classify_lane
from consensus.receive_route import ROUTED_CLASSES
from consensus.network_binding import chain_genesis_hash
from consensus.tx_checks import apply_tx_error
from consensus.tx_signing import signing_message_bytes
from errors import DatabaseError
from network.service import _SNAPSHOT_TX_TYPES, NetworkService

from bls_keys import pubkey_hex

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
C = pubkey_hex(0x3C)
NEXT_HEIGHT = 50
TS = 1_767_225_600
FAR = 9_999_999_999
KEY = "envelopes_root"


def send(**over):
    tx = {
        "tx_type": "envelope_send", "sender_pubkey": A, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
        "recipient_pubkey": B, "amount": 1000, "caps": [100], "period_blocks": 10,
        "recurring": True, "expires_at": NEXT_HEIGHT + 500, "genesis_hash": chain_genesis_hash(),
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def spend(eid, amount=50, signer=B, to=C):
    return {"tx_type": "envelope_spend", "sender_pubkey": signer, "sequence_number": 0,
            "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
            "envelope_id": eid, "to_pubkey": to, "amount": amount,
            "genesis_hash": chain_genesis_hash()}


def release(eid, signer=A):
    return {"tx_type": "envelope_release", "sender_pubkey": signer, "sequence_number": 2,
            "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "0",
            "envelope_id": eid, "genesis_hash": chain_genesis_hash()}


@pytest.fixture
def book():
    return EnvelopeBook()


@pytest.fixture
def tip_view(book):
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = TS
    view.next_block_timestamp = TS
    view.envelope_book.return_value = book
    view.clause_for.return_value = None
    return view


def _opened(book, height=NEXT_HEIGHT - 5, **over):
    terms = parse_envelope_send(send(**over))
    book.send(terms, height, TS)
    return terms


# --- the limit arithmetic --------------------------------------------------------------

def _terms(caps, recurring, period=10):
    return EnvelopeTerms(A, 0, B, 10_000, tuple(caps), KIND_BLOCKS, period, recurring, 10**6)


@pytest.mark.parametrize("caps, recurring, expected", [
    ((100,), True, [100, 100, 100, 100]),
    ((100,), False, [100, None, None, None]),
    ((300, 100), False, [300, 100, None, None]),
    ((300, 100), True, [300, 100, 100, 100]),
    ((5, 6, 7), True, [5, 6, 7, 7]),
])
def test_the_cap_of_each_period(caps, recurring, expected):
    assert [_terms(caps, recurring).cap_for(n) for n in range(4)] == expected


def test_periods_count_from_the_anchor_and_nothing_carries_over():
    terms = _terms((100,), True)
    state = EnvelopeState(anchor=40, remaining=900, period_index=0, spent_in_period=100,
                          spends=1, last_height=41)
    assert [state.period_at(terms, c) for c in (40, 49, 50, 69, 70)] == [0, 0, 1, 2, 3]
    assert state.left_at(terms, 49) == 0
    assert state.left_at(terms, 50) == 100          # a new period, not 200
    assert state.next_reset(terms, 45) == 50
    assert state.next_reset(_terms((100,), False), 55) is None


def test_what_is_left_never_exceeds_what_the_envelope_holds():
    terms = _terms((1_000,), True)
    state = EnvelopeState(anchor=0, remaining=30, spends=1)
    assert state.left_at(terms, 3) == 30
    assert EnvelopeState(anchor=0, remaining=30, spends=1).left_at(_terms((5,), False), 30) == 30


# --- parsing and ids ----------------------------------------------------------------------

@pytest.mark.parametrize("over, why", [
    ({"recipient_pubkey": "xyz"}, "recipient_pubkey"),
    ({"recipient_pubkey": B.upper()}, "recipient_pubkey"),
    ({"caps": None}, "caps"),
    ({"caps": []}, "caps"),
    ({"caps": [1] * (MAX_CAPS + 1)}, "caps"),
    ({"caps": ["5"]}, r"caps\[0\]"),
    ({"caps": [True]}, r"caps\[0\]"),
    ({"period_blocks": None}, "exactly one"),
    ({"period_seconds": 60}, "exactly one"),
    ({"recurring": "yes"}, "recurring"),
    ({"amount": -1}, "amount"),
    ({"expires_at": 2**64}, "expires_at"),
])
def test_malformed_sends(over, why):
    with pytest.raises(EnvelopeShapeError, match=why):
        parse_envelope_send(send(**over))


def test_every_term_changes_the_envelope_id():
    base = parse_envelope_send(send()).envelope_id
    for over in ({"sequence_number": 2}, {"recipient_pubkey": C}, {"amount": 1001},
                 {"caps": [101]}, {"caps": [100, 100]}, {"period_blocks": 11},
                 {"period_blocks": None, "period_seconds": 10}, {"recurring": False},
                 {"expires_at": NEXT_HEIGHT + 501}, {"sender_pubkey": C}):
        assert parse_envelope_send(send(**over)).envelope_id != base, over


def test_recurring_may_be_left_out():
    assert parse_envelope_send(send(recurring=None)).recurring is False


def test_spend_and_release_parse():
    sp = parse_envelope_spend(spend("ab" * 32, 7))
    assert sp == EnvelopeSpend(B, bytes.fromhex("ab" * 32), C, 7)
    for bad in ({"amount": 0}, {"amount": tau_defs.MAX_TRANSFER_VALUE + 1},
                {"envelope_id": "AB" * 32}, {"to_pubkey": "z"}):
        with pytest.raises(EnvelopeShapeError):
            parse_envelope_spend({**spend("ab" * 32), **bad})
    assert parse_envelope_release(release("cd" * 32)).envelope_id == bytes.fromhex("cd" * 32)


# --- admission -------------------------------------------------------------------------------

def test_a_valid_send_is_admitted_with_its_id_and_room(tip_view):
    result = validate_envelope_send_payload(send(), tip_view)
    assert result.is_valid, result.error
    data = result.data
    assert data["envelope_id"] == parse_envelope_send(send()).envelope_id.hex()
    assert (data["cap_this_period"], data["left_this_period"], data["next_reset"]) == \
        (100, 100, NEXT_HEIGHT + 10)
    assert data["recipient_pubkey"] == B and data["amount"] == 1000


@pytest.mark.parametrize("over, code", [
    ({"recipient_pubkey": A}, "INVALID_ENVELOPE"),
    ({"recipient_pubkey": "ab" * 48}, "INVALID_ENVELOPE"),
    ({"caps": [0]}, "INVALID_ENVELOPE"),
    ({"amount": 0}, "INVALID_ENVELOPE"),
    ({"period_blocks": 0}, "INVALID_ENVELOPE"),
    ({"expires_at": NEXT_HEIGHT}, "INVALID_ENVELOPE"),
    ({"caps": "x"}, "INVALID_ENVELOPE"),
])
def test_send_refusals_carry_a_code(tip_view, over, code):
    assert validate_envelope_send_payload(send(**over), tip_view).code == code


def test_duplicate_too_many_and_full(tip_view, book, monkeypatch):
    _opened(book)
    assert validate_envelope_send_payload(send(), tip_view).code == "DUPLICATE_ENVELOPE"
    for k in range(2, MAX_OPEN_ENVELOPES_PER_SENDER + 1):
        _opened(book, sequence_number=k)
    assert validate_envelope_send_payload(send(sequence_number=99), tip_view).code == \
        "TOO_MANY_ENVELOPES"
    import consensus.envelope as envelope

    monkeypatch.setattr(envelope, "MAX_OPEN_ENVELOPES_TOTAL", book.open_count())
    assert validate_envelope_send_payload(send(sender_pubkey=C), tip_view).code == \
        "ENVELOPE_BOOK_FULL"


def test_spend_admission(tip_view, book):
    eid = _opened(book).envelope_id.hex()
    ok = validate_envelope_spend_payload(spend(eid, 60), tip_view)
    assert ok.is_valid, ok.error
    assert ok.data == {"envelope_id": eid, "to_pubkey": C, "amount": 60,
                       "remaining_after": 940, "left_this_period_after": 40}
    for tx, code in [
        (spend("cd" * 32), "NO_ENVELOPE"),
        (spend(eid, signer=C), "NOT_ENVELOPE_RECIPIENT"),
        (spend(eid, signer=A), "NOT_ENVELOPE_RECIPIENT"),
        (spend(eid, 101), "ENVELOPE_LIMIT"),
        (spend(eid, to="ab" * 48), "INVALID_ENVELOPE"),
        (spend(eid, 0), "INVALID_ENVELOPE"),
    ]:
        assert validate_envelope_spend_payload(tx, tip_view).code == code, tx


def test_spend_admission_after_the_end_and_beyond_the_balance(tip_view, book):
    eid = _opened(book, amount=30, caps=[1000], expires_at=NEXT_HEIGHT + 1).envelope_id.hex()
    assert validate_envelope_spend_payload(spend(eid, 31), tip_view).code == \
        "ENVELOPE_INSUFFICIENT"
    tip_view.next_block_height = NEXT_HEIGHT + 1
    assert validate_envelope_spend_payload(spend(eid, 5), tip_view).code == "ENVELOPE_ENDED"


def test_release_admission(tip_view, book):
    eid = _opened(book).envelope_id.hex()
    ok = validate_envelope_release_payload(release(eid), tip_view)
    assert ok.is_valid and ok.data == {"envelope_id": eid, "released": 1000,
                                       "recipient_pubkey": B}
    assert validate_envelope_release_payload(release(eid, signer=B), tip_view).code == \
        "NOT_ENVELOPE_SENDER"
    assert validate_envelope_release_payload(release("ee" * 32), tip_view).code == \
        "NO_ENVELOPE"


def test_the_dispatcher_routes_all_three_types(tip_view, book):
    assert validate_mempool_admission(send(), tip_view).is_valid
    eid = _opened(book).envelope_id.hex()
    assert validate_mempool_admission(spend(eid), tip_view).is_valid
    assert validate_mempool_admission(release(eid), tip_view).is_valid


CORPUS = [
    send(), send(recipient_pubkey=A), send(amount=0), send(amount=1),
    send(amount=tau_defs.MAX_TRANSFER_VALUE), send(amount=tau_defs.MAX_TRANSFER_VALUE + 1),
    send(caps=[0]), send(caps=[tau_defs.MAX_TRANSFER_VALUE + 1]), send(caps=[1] * MAX_CAPS),
    send(period_blocks=MAX_PERIOD_BLOCKS), send(period_blocks=MAX_PERIOD_BLOCKS + 1),
    send(expires_at=NEXT_HEIGHT), send(expires_at=NEXT_HEIGHT + 1),
    send(expires_at=NEXT_HEIGHT + MAX_LIFETIME_BLOCKS),
    send(expires_at=NEXT_HEIGHT + MAX_LIFETIME_BLOCKS + 1),
    send(period_blocks=None, period_seconds=MAX_PERIOD_SECONDS, expires_at=TS + 5),
    send(period_blocks=None, period_seconds=MAX_PERIOD_SECONDS + 1, expires_at=TS + 5),
    send(period_blocks=None, period_seconds=60, expires_at=TS),
    send(period_blocks=None, period_seconds=60, expires_at=TS + MAX_LIFETIME_SECONDS),
    send(period_blocks=None, period_seconds=60, expires_at=TS + MAX_LIFETIME_SECONDS + 1),
]


@pytest.mark.parametrize("tx", CORPUS)
def test_admission_and_apply_agree_on_every_send(tip_view, tx):
    admitted = validate_envelope_send_payload(tx, tip_view)
    applied, reason = EnvelopeBook().can_admit_send(parse_envelope_send(tx), NEXT_HEIGHT, TS)
    assert admitted.is_valid == applied, (admitted.error, reason)


# --- signing and shared checks -------------------------------------------------------------

@pytest.mark.parametrize("field, value", [
    ("recipient_pubkey", C), ("amount", 1001), ("caps", [100, 50]), ("caps", [101]),
    ("period_blocks", 11), ("period_seconds", 10), ("recurring", False),
    ("expires_at", 7), ("fee_limit", "11"),
])
def test_every_term_of_a_send_is_signed(field, value):
    assert signing_message_bytes(send(**{field: value})) != signing_message_bytes(send())


@pytest.mark.parametrize("field, value", [
    ("envelope_id", "11" * 32), ("to_pubkey", A), ("amount", 51)])
def test_every_part_of_a_spend_is_signed(field, value):
    base = spend("00" * 32)
    assert signing_message_bytes({**base, field: value}) != signing_message_bytes(base)


def test_a_release_signs_its_envelope():
    base = release("00" * 32)
    assert signing_message_bytes({**base, "envelope_id": "11" * 32}) != \
        signing_message_bytes(base)


def test_apply_refuses_keys_that_are_not_keys():
    assert apply_tx_error(send(recipient_pubkey="ab" * 48))[0] == "invalid_recipient_key"
    assert apply_tx_error(spend("00" * 32, to="ab" * 48))[0] == "invalid_recipient_key"
    assert apply_tx_error(send()) is None and apply_tx_error(spend("00" * 32)) is None


def test_lanes_tau_needs_and_fees():
    from consensus import engine

    for tx in (send(), spend("00" * 32), release("00" * 32)):
        assert classify_lane(tx) == LANE_FAST
    assert {"envelope_send", "envelope_spend"} <= TAU_EVALUATING_TX_TYPES
    assert "envelope_release" not in TAU_EVALUATING_TX_TYPES
    assert engine.FEE_BEARING_TX_TYPES == sendtx.FEE_BEARING_TX_TYPES
    assert {"envelope_send", "envelope_spend"} <= sendtx.FEE_BEARING_TX_TYPES
    assert "envelope_release" not in sendtx.FEE_BEARING_TX_TYPES
    assert {"envelope_send", "envelope_spend", "envelope_release"} <= sendtx.KNOWN_TX_TYPES


def test_spends_and_releases_are_routed_credit_classes():
    assert {"envelope_spend", "envelope_release"} <= set(ROUTED_CLASSES)


# --- the book and the meta hash ----------------------------------------------------------

def test_an_unused_book_leaves_the_meta_hash_as_it_was():
    lm = ConsensusLifecycleManager()
    assert KEY not in build_mechanism_metadata("supermajority")
    before = lm.consensus_meta_hash()
    lm.envelopes = EnvelopeBook()
    assert lm.consensus_meta_hash() == before


def test_the_book_is_bound_once_used_and_every_change_moves_it():
    lm = ConsensusLifecycleManager()
    hashes = [lm.consensus_meta_hash()]
    terms = _opened(lm.envelopes)
    hashes.append(lm.consensus_meta_hash())
    lm.envelopes.record_spend(terms.envelope_id, 10, NEXT_HEIGHT, TS)
    hashes.append(lm.consensus_meta_hash())
    lm.envelopes.release(terms.envelope_id)
    hashes.append(lm.consensus_meta_hash())
    assert len(set(hashes)) == 4
    assert lm.envelopes.open_count() == 0 and not lm.envelopes.is_empty()


def test_the_outcome_is_part_of_the_commitment():
    def closed(how):
        book = EnvelopeBook()
        terms = _opened(book, amount=10, caps=[10])
        if how == "emptied":
            book.record_spend(terms.envelope_id, 10, NEXT_HEIGHT, TS)
        elif how == "released":
            book.record_spend(terms.envelope_id, 9, NEXT_HEIGHT, TS)
            book.release(terms.envelope_id)
        else:
            book.record_spend(terms.envelope_id, 9, NEXT_HEIGHT, TS)
            book.end_due(10**9, 10**12)
        return book.root()

    assert len({closed("emptied"), closed("released"), closed("ended")}) == 3


def test_a_copy_does_not_leak_into_its_original(book):
    terms = _opened(book)
    clone = copy.deepcopy(book)
    clone.record_spend(terms.envelope_id, 10, NEXT_HEIGHT, TS)
    clone.release(terms.envelope_id)
    assert book.state_of(terms.envelope_id).remaining == 1000
    assert book.escrow_total() == 1000 and clone.escrow_total() == 0
    assert book.root() != clone.root()


def test_ends_close_in_order_on_each_clock(book):
    t1 = _opened(book, expires_at=NEXT_HEIGHT + 9)
    t2 = _opened(book, sequence_number=2, expires_at=NEXT_HEIGHT + 5)
    t3 = _opened(book, sequence_number=3, period_blocks=None, period_seconds=60,
                 expires_at=TS + 100)
    assert not book.has_ending(NEXT_HEIGHT + 4, TS + 99)
    gone = book.end_due(NEXT_HEIGHT + 9, TS + 99)
    assert [t.envelope_id for t, _, _ in gone] == [t2.envelope_id, t1.envelope_id]
    assert [outcome for _, _, outcome in gone] == [OUTCOME_ENDED, OUTCOME_ENDED]
    assert book.get(t3.envelope_id) is not None
    assert [t.envelope_id for t, _, _ in book.end_due(0, TS + 100)] == [t3.envelope_id]


def test_check_spend_reasons(book):
    terms = _opened(book)
    eid = terms.envelope_id
    with pytest.raises(EnvelopeRefused, match="no open envelope"):
        book.check_spend(EnvelopeSpend(B, b"\x01" * 32, C, 1), NEXT_HEIGHT, TS)
    with pytest.raises(EnvelopeRefused, match="the cap 100 leaves 100"):
        book.check_spend(EnvelopeSpend(B, eid, C, 101), NEXT_HEIGHT, TS)
    book.record_spend(eid, 100, NEXT_HEIGHT, TS)
    with pytest.raises(EnvelopeRefused, match="with 100 spent this period"):
        book.check_spend(EnvelopeSpend(B, eid, C, 1), NEXT_HEIGHT + 4, TS)
    assert book.check_spend(EnvelopeSpend(B, eid, C, 100), NEXT_HEIGHT + 5, TS)


# --- persistence -------------------------------------------------------------------------------

def _seed():
    lm = ConsensusLifecycleManager(active_validators=[A])
    # Run on the loaded genesis, as the restarted node will: other modules may
    # leave a genesis faucet grant or slot flag set, and a restart reads both.
    lm.faucet_amount = chain_state._genesis_faucet_amount
    if chain_state._genesis_approval_slots_active:
        lm.activate_approval_slots()
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 5000, B: 7})
    chain_state._sequence_numbers.update({A: 3})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    book = lm.envelopes
    first = _opened(book, caps=[300, 100])
    book.record_spend(first.envelope_id, 250, NEXT_HEIGHT, TS)
    _opened(book, sequence_number=2, recipient_pubkey=C, period_blocks=None,
            period_seconds=3600, expires_at=TS + 86_400)
    gone = _opened(book, sequence_number=3, amount=40, caps=[40])
    book.record_spend(gone.envelope_id, 40, NEXT_HEIGHT, TS)
    return lm, first


def _reload():
    chain_state.commit_state_to_db("head-hash", 60)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_book_round_trips(temp_database):
    """A node that restarts holds the same envelopes, progress and commitment."""
    lm, _ = _seed()
    meta = lm.consensus_meta_hash()
    book = lm.envelopes
    reloaded = _reload().envelopes
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded.resolved_state() == book.resolved_state()
    assert reloaded.escrow_total() == book.escrow_total() == 1000 - 250 + 1000
    assert reloaded._due == book._due
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


@pytest.mark.usefixtures("isolated_chain_state")
@pytest.mark.parametrize("column, value", [
    ("amount", 1001), ("caps_json", "[301, 100]"), ("expires_at", 1), ("recurring", 0),
    ("remaining", 1001), ("spent_in_period", 301), ("spends", 0), ("period_kind", 7),
])
def test_a_tampered_row_refuses_to_load(temp_database, column, value):
    _, first = _seed()
    chain_state.commit_state_to_db("head-hash", 60)
    with db._db_conn as conn:
        conn.execute(f"UPDATE envelopes_v1 SET {column} = ? WHERE envelope_id = ?",
                     (value, first.envelope_id.hex()))
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="envelope"):
        chain_state.load_state_from_db()


def test_restore_refuses_impossible_rows():
    good = EnvelopeTerms(A, 0, B, 100, (10,), KIND_BLOCKS, 5, True, 99)
    row = (good.envelope_id, A, 0, B, 100, (10,), KIND_BLOCKS, 5, True, 99, 1, 100, 0, 0, 0, 0)
    assert EnvelopeBook.restore([row], 0, bytes(32)).get(good.envelope_id) == good
    with pytest.raises(ValueError, match="twice"):
        EnvelopeBook.restore([row, row], 0, bytes(32))
    selfish = EnvelopeTerms(A, 0, A, 100, (10,), KIND_BLOCKS, 5, True, 99)
    with pytest.raises(ValueError, match="impossible"):
        EnvelopeBook.restore([(selfish.envelope_id, A, 0, A) + row[4:]], 0, bytes(32))
    zero = EnvelopeTerms(A, 0, B, 100, (10,), KIND_SECONDS, 0, True, 99)
    with pytest.raises(ValueError, match="impossible"):
        EnvelopeBook.restore([(zero.envelope_id, A, 0, B, 100, (10,), KIND_SECONDS, 0)
                              + row[8:]], 0, bytes(32))
    with pytest.raises(ValueError, match="inconsistent"):
        EnvelopeBook.restore([row[:11] + (0,) + row[12:]], 0, bytes(32))
    with pytest.raises(ValueError, match="32 bytes"):
        EnvelopeBook.restore([], 0, b"x")


# --- RPC: the capability report, history, tx status ------------------------------------------

@pytest.fixture
def container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def call(module, line, container):
    return json.loads(module.execute(line, container))


def test_the_capability_report():
    sem = getenvelope.semantics()
    assert sem["supported"] is True and sem["version"] == 4
    assert sem["conditions"][0] == "spending_limit"
    assert "nothing carries over" in sem["spending_limit"]
    assert sem["clocks"] == ["blocks", "seconds"]
    assert sem["fee_by_tx_type"]["envelope_release"] == "fee-free"
    assert sem["limits"]["open_per_sender"] == MAX_OPEN_ENVELOPES_PER_SENDER
    assert sorted(sem["tx_types"]) == ["envelope_release", "envelope_send", "envelope_spend"]


def _events_for(eid, sent_block="blk"):
    db.record_envelope_events(sent_block, NEXT_HEIGHT, [
        {"outcome": "sent", "envelope_id": eid, "sender_pubkey": A, "recipient_pubkey": B,
         "amount": 1000, "tx_id": "t1"}])
    db.record_envelope_events("blk2", NEXT_HEIGHT + 1, [
        {"outcome": "spend", "envelope_id": eid, "sender_pubkey": A, "recipient_pubkey": B,
         "to_pubkey": C, "amount": 60, "remaining": 940, "period_index": 0,
         "spent_in_period": 60, "tx_id": "t2"}])


@pytest.mark.usefixtures("isolated_chain_state")
def test_getenvelope_shows_an_open_envelope_and_its_history(temp_database, container,
                                                            monkeypatch):
    book = EnvelopeBook()
    terms = _opened(book)
    book.record_spend(terms.envelope_id, 60, NEXT_HEIGHT + 1, TS)
    eid = terms.envelope_id.hex()
    monkeypatch.setattr(getenvelope, "tip",
                        lambda: ("head", book, NEXT_HEIGHT + 2, TS))
    _events_for(eid)
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (True, 1))
    data = call(getenvelope, f"getenvelope {eid}", container)["data"]
    assert data["open"] is True
    env = data["envelope"]
    assert (env["remaining"], env["spent_this_period"], env["left_this_period"],
            env["status"]) == (940, 60, 40, "open")
    assert [e["outcome"] for e in data["history"]] == ["spend", "sent"]
    assert data["history"][0]["to_pubkey"] == C


@pytest.mark.usefixtures("isolated_chain_state")
def test_getenvelope_tells_how_a_closed_envelope_closed(temp_database, container,
                                                       monkeypatch):
    eid = "ab" * 32
    monkeypatch.setattr(getenvelope, "tip", lambda: ("head", EnvelopeBook(), 9, TS))
    _events_for(eid)
    db.record_envelope_events("blk3", NEXT_HEIGHT + 2, [
        {"outcome": "released", "envelope_id": eid, "sender_pubkey": A,
         "recipient_pubkey": B, "paid_out": 940, "paid_to": "recipient", "tx_id": "t3"}])
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (h != "blk3x", 1))
    data = call(getenvelope, f"getenvelope {eid}", container)["data"]
    assert data["open"] is False and data["closed"] == "released"
    assert call(getenvelope, f"getenvelope {'cd' * 32}", container)["error"]["code"] == \
        "NOT_FOUND"


@pytest.mark.usefixtures("isolated_chain_state")
def test_getenvelopes_lists_in_and_out(temp_database, container, monkeypatch):
    book = EnvelopeBook()
    to_b = _opened(book)
    to_a = _opened(book, sender_pubkey=C, recipient_pubkey=A, amount=70)
    monkeypatch.setattr(getenvelope, "tip", lambda: ("head", book, NEXT_HEIGHT, TS))
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (True, 1))
    _events_for(to_b.envelope_id.hex())
    out = call(getenvelopes, f"getenvelopes {A} out", container)["data"]
    assert [e["envelope_id"] for e in out["envelopes"]] == [to_b.envelope_id.hex()]
    assert out["held_in_envelopes"] == 70
    held = call(getenvelopes, f"getenvelopes {A} in", container)["data"]
    assert [e["envelope_id"] for e in held["envelopes"]] == [to_a.envelope_id.hex()]
    both = call(getenvelopes, f"getenvelopes {A}", container)["data"]
    assert len(both["envelopes"]) == 2 and both["role"] == "all"
    assert [e["outcome"] for e in both["history"]] == ["spend", "sent"]


def test_bad_rpc_arguments(container):
    for module, line in ((getenvelope, "getenvelope"), (getenvelope, "getenvelope xyz"),
                         (getenvelopes, "getenvelopes"), (getenvelopes, "getenvelopes xyz"),
                         (getenvelopes, f"getenvelopes {A} sideways")):
        assert call(module, line, container)["error"]["code"] == "INVALID_PARAMS", line


@pytest.mark.usefixtures("isolated_chain_state")
def test_gettxstatus_shows_what_a_transaction_did_to_envelopes(temp_database, monkeypatch):
    eid = "ab" * 32
    _events_for(eid)
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (True, 1))
    sent = gettxstatus._envelope_fields(db, "t1", "blk")["envelopes"]
    assert sent[0]["outcome"] == "sent" and sent[0]["status"] == "open"
    db.record_envelope_events("blk3", NEXT_HEIGHT + 2, [
        {"outcome": "ended", "envelope_id": eid, "sender_pubkey": A,
         "recipient_pubkey": B, "paid_out": 940, "paid_to": "recipient"}])
    assert gettxstatus._envelope_fields(db, "t1", "blk")["envelopes"][0]["status"] == "ended"
    spent = gettxstatus._envelope_fields(db, "t2", "blk2")["envelopes"]
    assert (spent[0]["amount"], spent[0]["to_pubkey"]) == (60, C)
    assert gettxstatus._envelope_fields(db, "zz", "blk") == {}


def test_sendtx_and_checktx_hand_the_envelope_back(monkeypatch):
    summary = {"envelope_id": "ab" * 32, "left_this_period": 100}
    monkeypatch.setattr(sendtx, "queue_transaction",
                        lambda *a, **k: {"ok": True, "tx_hash": "h", "tx_type": "envelope_send",
                                         "envelope": summary})
    assert json.loads(sendtx.execute("sendtx {}", None))["data"]["envelope"] == summary
    assert json.loads(checktx.execute("checktx {}", None))["data"]["envelope"] == summary


# --- gossip and the command line -----------------------------------------------------------

def test_gossip_routes_and_snapshots_all_three_types():
    for t in ("envelope_send", "envelope_spend", "envelope_release"):
        assert NetworkService.topic_for_tx_type(t) == "tau/envelopes/1.0.0"
        assert t in _SNAPSHOT_TX_TYPES


def test_the_cli_builders_make_what_the_node_parses():
    from tau_testnet_cli import tx as tx_mod

    built = tx_mod.build_envelope_send_tx(
        sender_pubkey=A, sequence_number=1, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, recipient_pubkey=B.upper(), amount=1000,
        caps=[300, 100], period_seconds=604_800, recurring=True, expires_at=TS + 9)
    terms = parse_envelope_send(built)
    assert (terms.recipient_pubkey, terms.caps, terms.kind, terms.recurring) == \
        (B, (300, 100), KIND_SECONDS, True)
    plain = tx_mod.build_envelope_send_tx(
        sender_pubkey=A, sequence_number=1, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, recipient_pubkey=B, amount=5, caps=[5],
        period_blocks=10, expires_at=NEXT_HEIGHT + 9)
    assert "recurring" not in plain and "period_seconds" not in plain
    with pytest.raises(ValueError, match="exactly one"):
        tx_mod.build_envelope_send_tx(
            sender_pubkey=A, sequence_number=1, expiration_time=FAR,
            expire_at_height=NEXT_HEIGHT + 5, recipient_pubkey=B, amount=5, caps=[5],
            period_blocks=10, period_seconds=10, expires_at=9)
    sp = tx_mod.build_envelope_spend_tx(
        sender_pubkey=B, sequence_number=0, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, envelope_id=terms.envelope_id.hex().upper(),
        to_pubkey=C, amount=40)
    assert parse_envelope_spend(sp) == EnvelopeSpend(B, terms.envelope_id, C, 40)
    rel = tx_mod.build_envelope_release_tx(
        sender_pubkey=A, sequence_number=2, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, envelope_id=terms.envelope_id.hex())
    assert parse_envelope_release(rel).envelope_id == terms.envelope_id


def test_the_cli_parses_the_envelope_commands():
    from tau_testnet_cli.cli import (
        _PayloadError, _duration_seconds, _envelope_caps, _envelope_terms, build_parser,
    )

    def _envelope_clock(args, tip, now):
        terms = _envelope_terms(args, tip, now)
        return {k: terms[k] for k in ("period_seconds", "period_blocks", "expires_at")
                if k in terms}

    parser = build_parser()
    args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount", "3000",
                              "--cap", "1000,500", "--cap", "250", "--recurring",
                              "--period", "7d", "--ends-in", "12w"])
    assert _envelope_caps(args.cap) == [1000, 500, 250] and args.recurring
    assert _envelope_clock(args, tip=10, now=TS) == {"period_seconds": 604_800,
                                                     "expires_at": TS + 12 * 604_800}
    args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount", "9",
                              "--cap", "3", "--period-blocks", "100",
                              "--ends-in-blocks", "1000"])
    assert _envelope_clock(args, tip=10, now=TS) == {"period_blocks": 100,
                                                     "expires_at": 10 + 1 + 1000}
    args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount", "9",
                              "--cap", "3", "--period-blocks", "100", "--ends-in", "1h"])
    with pytest.raises(_PayloadError, match="one envelope, one clock.*--period-blocks"):
        _envelope_clock(args, tip=10, now=TS)
    with pytest.raises(_PayloadError, match="whole amounts"):
        _envelope_caps(["1.5"])
    assert [_duration_seconds(x) for x in ("90", "90s", "15m", "12h", "7d", "2w")] == \
        [90, 90, 900, 43_200, 604_800, 1_209_600]
    for bad in ("", "0", "7x", "-5", "d"):
        with pytest.raises(argparse.ArgumentTypeError):
            _duration_seconds(bad)
    eid = "ab" * 32
    sp = parser.parse_args(["envelope", "spend", "--key", "k", eid, "--to", "self",
                            "--amount", "5"])
    assert (sp.envelope_id, sp.to, sp.amount) == (eid, "self", 5)
    assert parser.parse_args(["envelope", "release", "--key", "k", eid]).envelope_id == eid
    assert parser.parse_args(["envelope", "show", eid]).envelope_id == eid
    assert parser.parse_args(["envelope", "list", A, "--role", "in"]).role == "in"


# --- the account view and the pending view --------------------------------------------------

@pytest.mark.usefixtures("isolated_chain_state")
def test_getaccountstate_reports_envelopes_both_ways(temp_database, container, monkeypatch):
    from commands import getaccountstate

    book = EnvelopeBook()
    first = _opened(book)
    book.record_spend(first.envelope_id, 60, NEXT_HEIGHT, TS)
    _opened(book, sequence_number=2, amount=25, caps=[25])
    monkeypatch.setattr(TipAdmissionView, "envelope_book", lambda self: book)
    chain_state._balances[A] = 500
    sender = call(getaccountstate, f"getaccountstate {A}", container)["data"]
    recipient = call(getaccountstate, f"getaccountstate {B}", container)["data"]
    assert (sender["envelopes_out"], sender["envelopes_in"]) == ("965", "0")
    assert (recipient["envelopes_out"], recipient["envelopes_in"]) == ("0", "965")
    assert sender["chain_balance"] == "500"


@pytest.mark.usefixtures("isolated_chain_state")
def test_queued_envelope_transactions_in_the_pending_view(temp_database):
    import hashlib

    for k, tx in enumerate((send(), spend("ab" * 32, 40))):
        blob = json.dumps(tx, sort_keys=True)
        db.add_mempool_tx(blob, hashlib.sha256(blob.encode()).hexdigest(), 1000 + k)
    out = {t["tx_type"]: (t["amount_out"], t["amount_in"])
           for t in db.get_mempool_txs_for_address(A)}
    assert out == {"envelope_send": (1000, 0)}
    assert {t["tx_type"]: (t["amount_out"], t["amount_in"])
            for t in db.get_mempool_txs_for_address(B)} == {"envelope_spend": (0, 0)}
    assert {t["tx_type"]: (t["amount_out"], t["amount_in"])
            for t in db.get_mempool_txs_for_address(C)} == {"envelope_spend": (0, 40)}
