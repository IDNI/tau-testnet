"""Block apply verifies EVERY transaction's signature, whatever its type.

sender_pubkey is only a claim until the signature proves it, and every
account-scoped rule trusts it: balances, sequence numbers, policy clauses, offers,
approvals. A proposer that could include a transaction in anyone's name could
drain an account, split one theft into many small transfers that each fit under a
tier policy, or forge a rule offer, a vote or a governance update.

The single check sits at the top of the apply loop. A bad signature hard-rejects
only that transaction (receipt reason `invalid_signature`); the block stays valid,
the rejected transaction leaves no trace, and replay reaches the same verdict
because the state hash binds the transaction as rejected.

Mock Tau throughout. Every signature is a real BLS signature: a forgery is signed
by a different real key, or tampered after signing.
"""
import copy
import itertools
import json
from collections import namedtuple
from unittest.mock import MagicMock, patch

import pytest

import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from block import Block
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_payload
from consensus.approvals import STATUS_FAILED, ApprovalRequest
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate
from consensus.retractable import KIND_HEIGHT, RetractableEntry
from consensus.rule_offers import STATUS_REJECTED, RuleOffer
from consensus.state import TauStateSnapshot
from consensus.tx_signing import verify_tx_signature

HEIGHT = 20
TIER_1 = 1000          # the fake policy blocks above this without approval slot 18
FAR = 9999999999
FEE = 5                # o9 fee the fake Tau charges every fee-bearing transaction

SK_AUTH = 0xA07A       # ALICE's approver
SK_STRANGER = 0x57A57A  # signs the forgeries

ALICE = pubkey_hex(SK_ALICE)      # the victim
BOB = pubkey_hex(SK_BOB)          # recipient
CAROL = pubkey_hex(SK_CAROL)
MALLORY = pubkey_hex(SK_MALLORY)  # block proposer and thief
AUTH = pubkey_hex(SK_AUTH)

NEUTRAL_RULE = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
ALLOW_OFFER_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
GUARDED_RULE = (
    "always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
GOV_RULE = "always ( o6[t]:bv[16] = { 0 }:bv[16] )."

_TX_SEQ = itertools.count()


def tier_body(approver):
    return (
        "( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && "
        "!(i18[t]:bv[384] = { #x" + approver + " }:bv[384])) "
        "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )"
    )


# --- transaction builders ------------------------------------------------------

def _envelope(tx_type, sender, seq, *, fee_limit="100", **fields):
    tx = {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 5000,
        "fee_limit": fee_limit,
    }
    tx.update(fields)
    return tx


def rule_tx(rule, sk, *, sender=ALICE, seq=0):
    return sign_payload(_envelope("user_tx", sender, seq, operations={"0": rule}), sk)


def transfer_tx(to, amount, sk, *, sender=ALICE, seq=0):
    tx = _envelope("user_tx", sender, seq,
                   operations={"1": [[sender, to, str(amount)]]})
    return sign_payload(tx, sk)


def offer_tx(offer, sk, *, seq=0):
    tx = _envelope("rule_offer", offer.offerer_pubkey, seq,
                   recipient_pubkey=offer.recipient_pubkey, rule_text=offer.rule_text)
    tx["expire_at_height"] = offer.expire_at_height
    return sign_payload(tx, sk)


def accept_tx(offer, sk, *, sender=ALICE, seq=0):
    tx = _envelope("rule_offer_accept", sender, seq,
                   offer_id=offer.offer_id_hex, rule_text=offer.rule_text)
    return sign_payload(tx, sk)


def reject_tx(offer, sk, *, sender=ALICE, seq=0):
    tx = _envelope("rule_offer_reject", sender, seq, offer_id=offer.offer_id_hex)
    return sign_payload(tx, sk)


def request_tx(request, sk, *, seq=0):
    tx = _envelope(
        "approval_request", request.sender_pubkey, seq,
        recipient_pubkey=request.recipient_pubkey, amount=request.amount,
        approvers={str(k): v for k, v in request.approvers.items()}, custom_inputs={},
    )
    tx["expire_at_height"] = request.expire_at_height
    return sign_payload(tx, sk)


def vote_tx(request, sk, *, voter=AUTH, seq=0):
    tx = _envelope("transfer_vote", voter, seq, fee_limit="0",
                   request_id=request.request_id_hex, approve=True)
    return sign_payload(tx, sk)


def park_tx(sk, *, sender=ALICE, seq=0):
    tx = _envelope("retractable_transfer", sender, seq, recipient_pubkey=BOB,
                   amount=100, release_at_height=HEIGHT + 10)
    return sign_payload(tx, sk)


def retract_tx(entry, sk, *, sender=ALICE, seq=0):
    tx = _envelope("retract_transfer", sender, seq, fee_limit="0",
                   retractable_id=entry.retractable_id.hex())
    return sign_payload(tx, sk)


def update_tx(sk, *, sender=ALICE, seq=0):
    tx = _envelope("consensus_rule_update", sender, seq, fee_limit="0",
                   rule_revisions=[GOV_RULE], activate_at_height=100)
    return sign_payload(tx, sk)


def gov_vote_tx(update, sk, *, sender=ALICE, seq=0):
    tx = _envelope("consensus_rule_vote", sender, seq, fee_limit="0",
                   update_id=update.update_id_hex, approve=True)
    return sign_payload(tx, sk)


# --- the engine under a fake Tau --------------------------------------------------

Applied = namedtuple("Applied", "result lifecycle multi_calls single_calls")


def _lifecycle(*, active=True, clause=False, request=None, retractable=None,
               update=None, validators=(MALLORY, ALICE)):
    lm = ConsensusLifecycleManager(active_validators=list(validators))
    if active:
        lm.activate_approval_slots()
    if clause:
        lm.rule_offers.accepted_clauses[(ALICE, 5)] = tier_body(AUTH)
    if request is not None:
        assert lm.approval_requests.submit_request(request)
    if retractable is not None:
        lm.retractable_transfers.submit(retractable)
    if update is not None:
        assert lm.submit_update(update)
    return lm


def _apply(txs, lm, *, replay_mode=False, fee=FEE):
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: 100000, AUTH: 10, BOB: 0, CAROL: 100, MALLORY: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block = Block.create(block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
                         proposer_pubkey=MALLORY, timestamp=1234567890)

    # The live o5 composite: seeded from the registry, then whatever the block feeds.
    fed = [lm.rule_offers.composite_for_stream(5) or ""]
    persisted = []
    multi_calls = []
    single_calls = []

    def _single(**kw):
        single_calls.append(kw)
        text = str(kw.get("rule_text") or "")
        if "always" in text:
            fed.append(text)
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def _multi(**kw):
        multi_calls.append(kw)
        vals = kw.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        guarded = ALICE in str(vals.get(12, "")) and ALICE in fed[-1]
        blocked = guarded and amount > TIER_1 and AUTH not in str(vals.get(18, "0"))
        return {1: str(amount), 8: "0", 9: str(fee), 5: "0" if blocked else "1"}

    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = TauConsensusEngine().apply_block(
            view, block, parent, replay_mode=replay_mode)
    return Applied(result, result.next_snapshot.metadata["lifecycle_manager"],
                   multi_calls, single_calls)


def _fingerprint(applied):
    """Everything a transaction could change that the chain keeps."""
    meta = applied.result.next_snapshot.metadata
    lm = applied.lifecycle
    return copy.deepcopy({
        "state_hash": applied.result.next_snapshot.state_hash,
        "tau_bytes": applied.result.next_snapshot.tau_bytes,
        "balances": meta["balances"],
        "sequences": meta["sequence_numbers"],
        "last_transfer_ts": meta["last_transfer_ts"],
        "meta_hash": lm.consensus_meta_hash(),
        "clauses": lm.rule_offers.accepted_clauses,
        "offers": (lm.rule_offers.offered, lm.rule_offers.resolved,
                   lm.rule_offers.terminal_status),
        "approvals": (lm.approval_requests.open_requests, lm.approval_requests.resolved,
                      lm.approval_requests.terminal_status),
        "retractable": (lm.retractable_transfers.snapshot_rows(),
                        lm.retractable_transfers.escrow_total()),
        "governance": (lm.pending_updates, lm.votes),
    })


def _outcome(result, tx_id):
    return next(o for o in result.outcomes if o.tx_id == tx_id)


def _logs(result, tx_id):
    return " | ".join(str(line) for line in _outcome(result, tx_id).receipt_logs)


# --- one scenario per transaction family ----------------------------------------------

Scenario = namedtuple("Scenario", "name lifecycle prefix tx owner_sk")


def _offer_to_alice():
    return RuleOffer(offerer_pubkey=CAROL, recipient_pubkey=ALICE,
                     rule_text=ALLOW_OFFER_RULE, expire_at_height=500)


def _request():
    return ApprovalRequest(sender_pubkey=ALICE, recipient_pubkey=BOB, amount=5000,
                           sequence_number=0, expire_at_height=500,
                           approvers={18: AUTH}, custom_inputs={})


_ESCROWED = RetractableEntry(ALICE, BOB, 300, 0, KIND_HEIGHT, HEIGHT + 50)
_UPDATE = ConsensusRuleUpdate(rule_revisions=[GOV_RULE], activate_at_height=100,
                              proposer_pubkey=ALICE)


def _genuine_offer():
    return [offer_tx(_offer_to_alice(), SK_CAROL)]


SCENARIOS = [
    Scenario(
        "transfer-no-policy-active",
        lambda: _lifecycle(),
        lambda: [],
        lambda sk: transfer_tx(MALLORY, 99000, sk),
        SK_ALICE,
    ),
    Scenario(
        "transfer-no-policy-inactive",
        lambda: _lifecycle(active=False),
        lambda: [],
        lambda sk: transfer_tx(MALLORY, 99000, sk),
        SK_ALICE,
    ),
    Scenario(
        "transfer-at-tier",
        lambda: _lifecycle(clause=True),
        lambda: [],
        lambda sk: transfer_tx(MALLORY, TIER_1, sk),
        SK_ALICE,
    ),
    Scenario(
        "rule-offer",
        lambda: _lifecycle(),
        lambda: [],
        lambda sk: offer_tx(RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=AUTH,
                                      rule_text=ALLOW_OFFER_RULE, expire_at_height=500),
                            sk),
        SK_ALICE,
    ),
    Scenario(
        "rule-offer-reject",
        lambda: _lifecycle(clause=True),
        _genuine_offer,
        lambda sk: reject_tx(_offer_to_alice(), sk),
        SK_ALICE,
    ),
    Scenario(
        "rule-offer-accept",
        lambda: _lifecycle(clause=True),
        _genuine_offer,
        lambda sk: accept_tx(_offer_to_alice(), sk),
        SK_ALICE,
    ),
    Scenario(
        "approval-request",
        lambda: _lifecycle(clause=True),
        lambda: [],
        lambda sk: request_tx(_request(), sk),
        SK_ALICE,
    ),
    Scenario(
        "transfer-vote",
        lambda: _lifecycle(clause=True, request=_request()),
        lambda: [],
        lambda sk: vote_tx(_request(), sk),
        SK_AUTH,
    ),
    Scenario(
        "retractable-transfer",
        lambda: _lifecycle(),
        lambda: [],
        lambda sk: park_tx(sk),
        SK_ALICE,
    ),
    Scenario(
        "retract-transfer",
        lambda: _lifecycle(retractable=_ESCROWED),
        lambda: [],
        lambda sk: retract_tx(_ESCROWED, sk),
        SK_ALICE,
    ),
    Scenario(
        "consensus-rule-update",
        lambda: _lifecycle(),
        lambda: [],
        lambda sk: update_tx(sk),
        SK_ALICE,
    ),
    Scenario(
        "consensus-rule-vote",
        lambda: _lifecycle(update=_UPDATE),
        lambda: [],
        lambda sk: gov_vote_tx(_UPDATE, sk),
        SK_ALICE,
    ),
    Scenario(
        "routed-o5-revoke",
        lambda: _lifecycle(clause=True, request=_request()),
        lambda: [],
        lambda sk: rule_tx(NEUTRAL_RULE, sk),
        SK_ALICE,
    ),
    Scenario(
        "routed-o5-register",
        lambda: _lifecycle(clause=True),
        lambda: [],
        lambda sk: rule_tx("always ( %s )." % tier_body(AUTH), sk, sender=CAROL),
        SK_CAROL,
    ),
    Scenario(
        "routed-o5-replace",
        lambda: _lifecycle(clause=True, request=_request()),
        lambda: [],
        lambda sk: rule_tx("always ( %s )." % tier_body(BOB), sk),
        SK_ALICE,
    ),
    Scenario(
        "rule-offer-accept-before-activation",
        lambda: _lifecycle(active=False),
        _genuine_offer,
        lambda sk: accept_tx(_offer_to_alice(), sk),
        SK_ALICE,
    ),
    Scenario(
        "rule-before-activation",
        lambda: _lifecycle(active=False),
        lambda: [],
        lambda sk: rule_tx(GUARDED_RULE, sk),
        SK_ALICE,
    ),
]
_IDS = [s.name for s in SCENARIOS]


@pytest.mark.parametrize("replay_mode", [False, True], ids=["live", "replay"])
@pytest.mark.parametrize("scenario", SCENARIOS, ids=_IDS)
def test_a_forgery_is_rejected_and_leaves_no_trace(scenario, replay_mode):
    prefix = scenario.prefix()
    forged = scenario.tx(SK_STRANGER)

    alone = _apply(prefix, scenario.lifecycle(), replay_mode=replay_mode)
    attacked = _apply(prefix + [forged], scenario.lifecycle(), replay_mode=replay_mode)

    result = attacked.result
    assert forged["tx_id"] in result.invalid_tx_ids
    assert forged["tx_id"] not in result.accepted_tx_ids + result.skipped_tx_ids
    assert _outcome(result, forged["tx_id"]).reason == "invalid_signature"
    assert "signature" in _logs(result, forged["tx_id"])
    assert result.invalid_tx_ids == [forged["tx_id"]]
    assert result.accepted_tx_ids == alone.result.accepted_tx_ids
    assert _fingerprint(attacked) == _fingerprint(alone)
    assert attacked.multi_calls == alone.multi_calls
    assert attacked.single_calls == alone.single_calls


@pytest.mark.parametrize("replay_mode", [False, True], ids=["live", "replay"])
@pytest.mark.parametrize("scenario", SCENARIOS, ids=_IDS)
def test_the_genuine_version_still_applies(scenario, replay_mode):
    prefix = scenario.prefix()
    genuine = scenario.tx(scenario.owner_sk)

    alone = _apply(prefix, scenario.lifecycle(), replay_mode=replay_mode)
    applied = _apply(prefix + [genuine], scenario.lifecycle(), replay_mode=replay_mode)

    result = applied.result
    assert result.invalid_tx_ids == []
    assert genuine["tx_id"] in result.accepted_tx_ids + result.skipped_tx_ids
    assert _fingerprint(applied) != _fingerprint(alone)


# --- what each forgery would have done, spelled out -----------------------------------

def test_a_forged_transfer_cannot_drain_a_victim_with_no_policy():
    for active in (True, False):
        forged = transfer_tx(MALLORY, 99000, SK_STRANGER)
        applied = _apply([forged], _lifecycle(active=active))
        balances = applied.result.next_snapshot.metadata["balances"]
        assert (balances[ALICE], balances[MALLORY]) == (100000, 0)
        assert applied.result.next_snapshot.metadata["sequence_numbers"] == {}


def test_a_genuine_transfer_moves_funds_pays_the_fee_and_bumps_the_nonce():
    applied = _apply([transfer_tx(MALLORY, 99000, SK_ALICE)], _lifecycle())
    meta = applied.result.next_snapshot.metadata
    assert meta["balances"][ALICE] == 100000 - 99000 - FEE
    assert meta["balances"][MALLORY] == 99000 + FEE
    assert meta["sequence_numbers"] == {ALICE: 1}


def test_a_split_forged_theft_is_rejected_whole():
    # i2 and i16 are frozen at the parent for the whole block, so 100 transfers
    # that each fit the tier would all pass the policy; only the signature stops them.
    forged = [transfer_tx(MALLORY, TIER_1, SK_STRANGER, seq=n) for n in range(100)]
    lm = _lifecycle(clause=True)
    alone = _apply([], lm)
    attacked = _apply(forged, lm)
    assert sorted(attacked.result.invalid_tx_ids) == sorted(tx["tx_id"] for tx in forged)
    assert attacked.result.accepted_tx_ids == []
    balances = attacked.result.next_snapshot.metadata["balances"]
    assert (balances[ALICE], balances[MALLORY]) == (100000, 0)
    assert _fingerprint(attacked) == _fingerprint(alone)
    assert attacked.multi_calls == []


def test_the_same_hundred_transfers_signed_by_the_owner_all_apply():
    genuine = [transfer_tx(MALLORY, 900, SK_ALICE, seq=n) for n in range(100)]
    applied = _apply(genuine, _lifecycle(clause=True), fee=0)
    assert applied.result.invalid_tx_ids == []
    meta = applied.result.next_snapshot.metadata
    assert meta["balances"][MALLORY] == 90000
    assert meta["sequence_numbers"] == {ALICE: 100}


def test_a_forged_revoke_does_not_unlock_a_forged_transfer():
    lm = _lifecycle(clause=True, request=_request())
    revoke = rule_tx(NEUTRAL_RULE, SK_STRANGER, seq=0)
    steal = transfer_tx(MALLORY, 50000, SK_STRANGER, seq=0)
    applied = _apply([revoke, steal], lm)
    assert sorted(applied.result.invalid_tx_ids) == sorted([revoke["tx_id"], steal["tx_id"]])
    assert applied.lifecycle.rule_offers.accepted_clauses == {(ALICE, 5): tier_body(AUTH)}
    assert _request().request_id in applied.lifecycle.approval_requests.open_requests
    balances = applied.result.next_snapshot.metadata["balances"]
    assert (balances[ALICE], balances[MALLORY]) == (100000, 0)


def test_a_genuine_revoke_fails_the_open_request_and_unlocks_the_policy():
    applied = _apply([rule_tx(NEUTRAL_RULE, SK_ALICE)],
                     _lifecycle(clause=True, request=_request()))
    assert applied.lifecycle.rule_offers.clause_for(ALICE, 5) is None
    assert (applied.lifecycle.approval_requests.terminal_status[_request().request_id]
            == STATUS_FAILED)


def test_a_forged_vote_releases_nothing():
    lm = _lifecycle(clause=True, request=_request())
    applied = _apply([vote_tx(_request(), SK_STRANGER)], lm)
    assert _request().request_id in applied.lifecycle.approval_requests.open_requests
    assert applied.result.next_snapshot.metadata["balances"][BOB] == 0


def test_a_genuine_vote_releases_the_parked_transfer():
    applied = _apply([vote_tx(_request(), SK_AUTH)],
                     _lifecycle(clause=True, request=_request()))
    assert applied.result.next_snapshot.metadata["balances"][BOB] == 5000


def test_a_forged_retract_does_not_refund_the_escrow():
    forged = retract_tx(_ESCROWED, SK_STRANGER)
    applied = _apply([forged], _lifecycle(retractable=_ESCROWED))
    assert _ESCROWED.retractable_id in applied.lifecycle.retractable_transfers.open
    assert applied.result.next_snapshot.metadata["balances"][ALICE] == 100000


def test_a_forged_offer_reject_does_not_kill_a_genuine_offer():
    offer = _offer_to_alice()
    applied = _apply([offer_tx(offer, SK_CAROL), reject_tx(offer, SK_STRANGER)],
                     _lifecycle(clause=True))
    assert offer.offer_id in applied.lifecycle.rule_offers.offered
    assert offer.offer_id not in applied.lifecycle.rule_offers.resolved
    assert applied.lifecycle.rule_offers.terminal_status[offer.offer_id] != STATUS_REJECTED


def test_a_forged_accept_leaves_the_acceptors_clause_alone():
    offer = _offer_to_alice()
    applied = _apply([offer_tx(offer, SK_CAROL), accept_tx(offer, SK_STRANGER)],
                     _lifecycle(clause=True, request=_request()))
    assert applied.lifecycle.rule_offers.accepted_clauses == {(ALICE, 5): tier_body(AUTH)}
    assert _request().request_id in applied.lifecycle.approval_requests.open_requests


def test_a_forged_rule_leaves_the_application_rules_alone():
    forged = rule_tx(GUARDED_RULE, SK_STRANGER)
    applied = _apply([forged], _lifecycle(active=False))
    assert applied.single_calls == []
    assert applied.result.next_snapshot.tau_bytes == b"always (o0[t]=1)."


def test_a_forged_governance_update_is_not_recorded():
    applied = _apply([update_tx(SK_STRANGER)], _lifecycle())
    assert applied.lifecycle.pending_updates == set()
    assert applied.lifecycle.update_payloads == {}


def test_a_forged_governance_vote_is_not_counted():
    applied = _apply([gov_vote_tx(_UPDATE, SK_STRANGER)], _lifecycle(update=_UPDATE))
    assert applied.lifecycle.votes[_UPDATE.update_id] == set()


# --- garbage signatures ------------------------------------------------------------------

def _tamper(field, value):
    def mutate(tx):
        tx[field] = value
        return tx
    return mutate


def _drop(field):
    def mutate(tx):
        tx.pop(field, None)
        return tx
    return mutate


def _amount_changed_after_signing(tx):
    tx["operations"] = {"1": [[ALICE, MALLORY, "99001"]]}
    return tx


def _signed_by_another_real_key(tx):
    return sign_payload(tx, SK_BOB)


GARBAGE = {
    "empty-signature": _tamper("signature", ""),
    "short-signature": _tamper("signature", "ab" * 95),
    "long-signature": _tamper("signature", "ab" * 97),
    "non-hex-signature": _tamper("signature", "zz" * 96),
    "odd-length-signature": _tamper("signature", "a" * 191),
    "infinity-signature": _tamper("signature", "c0" + "00" * 95),
    "all-zero-signature": _tamper("signature", "00" * 96),
    "missing-signature": _drop("signature"),
    "null-signature": _tamper("signature", None),
    "integer-signature": _tamper("signature", 7),
    "list-signature": _tamper("signature", ["ab" * 96]),
    "missing-sender": _drop("sender_pubkey"),
    "null-sender": _tamper("sender_pubkey", None),
    "list-sender": _tamper("sender_pubkey", [ALICE]),
    "dict-sender": _tamper("sender_pubkey", {"k": ALICE}),
    "integer-sender": _tamper("sender_pubkey", 7),
    "non-hex-sender": _tamper("sender_pubkey", "alice"),
    "short-sender": _tamper("sender_pubkey", ALICE[:-2]),
    "infinity-sender": _tamper("sender_pubkey", "c0" + "00" * 47),
    "missing-fee-limit": _drop("fee_limit"),
    "missing-expiration": _drop("expiration_time"),
    "other-real-key": _signed_by_another_real_key,
    "tampered-after-signing": _amount_changed_after_signing,
}


@pytest.mark.parametrize("replay_mode", [False, True], ids=["live", "replay"])
@pytest.mark.parametrize("shape", sorted(GARBAGE))
def test_a_malformed_signature_rejects_without_raising(shape, replay_mode):
    lm = _lifecycle()
    alone = _apply([], lm, replay_mode=replay_mode)
    tx = GARBAGE[shape](transfer_tx(MALLORY, 99000, SK_ALICE))
    attacked = _apply([tx], lm, replay_mode=replay_mode)

    assert attacked.result.invalid_tx_ids == [tx["tx_id"]]
    assert _outcome(attacked.result, tx["tx_id"]).reason == "invalid_signature"
    assert _fingerprint(attacked) == _fingerprint(alone)
    assert attacked.multi_calls == []


@pytest.mark.parametrize("tx_type_builder", [
    lambda sk: offer_tx(_offer_to_alice(), sk),
    lambda sk: vote_tx(_request(), sk),
    lambda sk: park_tx(sk),
    lambda sk: update_tx(sk),
], ids=["offer", "vote", "park", "update"])
def test_a_signature_naming_no_key_rejects_every_type(tx_type_builder):
    tx = tx_type_builder(SK_ALICE)
    tx["signature"] = "not hex at all"
    applied = _apply([tx], _lifecycle(clause=True, request=_request()))
    assert applied.result.invalid_tx_ids == [tx["tx_id"]]
    assert _outcome(applied.result, tx["tx_id"]).reason == "invalid_signature"


def test_a_malformed_fee_limit_on_a_forgery_keeps_the_signature_reason():
    tx = transfer_tx(MALLORY, 99000, SK_STRANGER)
    tx["fee_limit"] = "not-a-number"
    sign_payload(tx, SK_STRANGER)
    applied = _apply([tx], _lifecycle())
    assert _outcome(applied.result, tx["tx_id"]).reason == "invalid_signature"


def test_a_reserved_operation_key_on_a_forgery_keeps_the_signature_reason():
    tx = _envelope("user_tx", ALICE, 0, operations={"12": "1"})
    sign_payload(tx, SK_STRANGER)
    applied = _apply([tx], _lifecycle())
    assert _outcome(applied.result, tx["tx_id"]).reason == "invalid_signature"


def test_a_forgery_with_a_stale_sequence_is_still_rejected_without_a_trace():
    forged = transfer_tx(MALLORY, 99000, SK_STRANGER, seq=7)
    lm = _lifecycle()
    attacked = _apply([forged], lm)
    assert attacked.result.invalid_tx_ids == [forged["tx_id"]]
    assert _fingerprint(attacked) == _fingerprint(_apply([], lm))


def test_the_signature_is_checked_once_per_transaction():
    txs = [transfer_tx(BOB, 10, SK_ALICE, seq=n) for n in range(3)]
    with patch("consensus.engine.verify_tx_signature", wraps=verify_tx_signature) as spy:
        _apply(txs, _lifecycle())
    assert spy.call_count == 3


# --- proposal mode ----------------------------------------------------------------------

class _Session:
    """A scripted evaluator that counts every step it is asked to take."""

    is_speculative = True

    def __init__(self):
        self.evaluations = 0
        self.rules = []
        self.allocation = None
        self.journal = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        self.rules.append(rule_text)
        return "ok"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        self.evaluations += 1
        outputs = {
            tau_defs.USER_POLICY_STREAM_INDEX: "1",
            tau_defs.CONSENSUS_FEE_STREAM_INDEX: str(FEE),
        }
        return outputs if multi else ""

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        pass


def _proposal(session, lifecycle):
    plan = tr.plan_representation(candidate_rules=[ALLOW_OFFER_RULE])
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan, lifecycle=lifecycle,
    )


def _propose(txs, lm):
    session = _Session()
    proposal = _proposal(session, lm)
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always ( o0[t]=1 ).",
        metadata={
            "balances": {ALICE: 100000, AUTH: 10, BOB: 0, MALLORY: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=HEIGHT, consensus_rules="",
        active_validators=[bytes.fromhex(MALLORY)],
    )
    block = Block.create(block_number=HEIGHT, previous_hash="0" * 64, transactions=txs,
                         proposer_pubkey=MALLORY, timestamp=1234567890)
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply_block(view, block, parent, session=session,
                                    proposal=proposal)
    return proposal, session, result


def _forgeries():
    offer = _offer_to_alice()
    return [
        transfer_tx(MALLORY, 99000, SK_STRANGER),
        rule_tx(GUARDED_RULE, SK_STRANGER, sender=BOB),
        rule_tx("always ( %s )." % tier_body(BOB), SK_STRANGER, sender=CAROL),
        offer_tx(RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=AUTH,
                           rule_text=ALLOW_OFFER_RULE, expire_at_height=500), SK_STRANGER),
        accept_tx(offer, SK_STRANGER),
        request_tx(_request(), SK_STRANGER),
        park_tx(SK_STRANGER),
    ]


def test_a_forged_tx_never_reaches_the_evaluator_in_proposal_mode(temp_database):
    forged = _forgeries()
    proposal, session, result = _propose(forged, _lifecycle(clause=True))

    assert sorted(result.invalid_tx_ids) == sorted(tx["tx_id"] for tx in forged)
    assert {o.reason for o in result.outcomes} == {"invalid_signature"}
    assert session.evaluations == 0
    assert session.rules == []
    # Rejecting a transaction that never stepped the evaluator must not force a rebuild.
    assert proposal.dirty is False
    meta = result.next_snapshot.metadata
    assert meta["balances"] == {ALICE: 100000, AUTH: 10, BOB: 0, MALLORY: 0}
    assert meta["sequence_numbers"] == {}


def test_forged_and_genuine_txs_share_a_proposal(temp_database):
    genuine = transfer_tx(BOB, 100, SK_ALICE)
    forged = transfer_tx(MALLORY, 99000, SK_STRANGER, seq=1)
    later = transfer_tx(BOB, 50, SK_ALICE, seq=1)

    _, solo_session, solo = _propose([genuine, later], _lifecycle())
    proposal, session, result = _propose([genuine, forged, later], _lifecycle())

    assert result.invalid_tx_ids == [forged["tx_id"]]
    assert result.accepted_tx_ids == solo.accepted_tx_ids
    assert session.evaluations == solo_session.evaluations
    assert (result.next_snapshot.state_hash == solo.next_snapshot.state_hash)
    meta = result.next_snapshot.metadata
    assert meta["balances"][BOB] == 150
    assert meta["sequence_numbers"] == {ALICE: 2}
    assert meta["balances"][MALLORY] == 2 * FEE


def test_a_forged_offer_leaves_the_proposal_lifecycle_untouched(temp_database):
    lm = _lifecycle(clause=True)
    before = lm.consensus_meta_hash()
    forged = offer_tx(RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=AUTH,
                                rule_text=ALLOW_OFFER_RULE, expire_at_height=500),
                      SK_STRANGER)
    proposal, _, result = _propose([forged], lm)
    assert proposal.lifecycle.consensus_meta_hash() == before
    assert result.invalid_tx_ids == [forged["tx_id"]]


# --- a pinned post-state, and admission ----------------------------------------------------

def _golden_block():
    lm = _lifecycle(clause=True, request=_request())
    offer = RuleOffer(offerer_pubkey=MALLORY, recipient_pubkey=CAROL,
                      rule_text="always ( %s )." % tier_body(AUTH), expire_at_height=500)
    txs = {
        "bob-clause": rule_tx("always ( %s )." % tier_body(AUTH), SK_BOB, sender=BOB),
        "alice-revoke": rule_tx(NEUTRAL_RULE, SK_ALICE),
        "offer": offer_tx(offer, SK_MALLORY),
        "carol-accept": accept_tx(offer, SK_CAROL, sender=CAROL),
        "small-transfer": transfer_tx(BOB, 500, SK_ALICE, seq=1),
    }
    return lm, txs


GOLDEN_STATE_HASH = "dc94e9ac7a10ea8928575836a993dbc69bc6d2dc462fb3265a0678dcf62adab8"


def test_a_block_of_genuine_policy_txs_reaches_the_pinned_state():
    lm, txs = _golden_block()
    applied = _apply(list(txs.values()), lm, fee=0)
    result = applied.result

    assert result.invalid_tx_ids == []
    assert sorted(result.accepted_tx_ids) == sorted(tx["tx_id"] for tx in txs.values())
    post = applied.lifecycle
    assert post.rule_offers.accepted_clauses == {
        (BOB, 5): tier_body(AUTH), (CAROL, 5): tier_body(AUTH)}
    assert sorted(post.rule_offers.terminal_status.values()) == ["accepted"]
    assert post.approval_requests.terminal_status[_request().request_id] == STATUS_FAILED
    balances = result.next_snapshot.metadata["balances"]
    assert (balances[ALICE], balances[BOB], balances[MALLORY]) == (99500, 500, 0)
    assert result.next_snapshot.state_hash == GOLDEN_STATE_HASH


def test_the_pinned_state_is_the_same_on_replay():
    lm, txs = _golden_block()
    live = _apply(list(txs.values()), lm, fee=0)
    lm, txs = _golden_block()
    replayed = _apply(list(txs.values()), lm, fee=0, replay_mode=True)
    assert replayed.result.next_snapshot.state_hash == live.result.next_snapshot.state_hash


def test_admission_refuses_the_same_forgeries():
    from commands import sendtx

    forgeries = [
        rule_tx(NEUTRAL_RULE, SK_STRANGER),
        accept_tx(_offer_to_alice(), SK_STRANGER),
        transfer_tx(MALLORY, 99000, SK_STRANGER),
        offer_tx(_offer_to_alice(), SK_STRANGER),
    ]
    for forged in forgeries:
        response = sendtx.queue_transaction(json.dumps(forged))
        assert response["code"] == "INVALID_SIGNATURE", response
