"""Recipient controls: the #47 policy gate and the #76 park hold cap.

The gate lives in the fee-era transfer closure, so it is driven here at
block apply with a scripted Tau (owner-aware on i12), and at admission
through checktx's dry run of sendtx with an owner-aware admission
worker. The recipient evaluation must see the counterparty on i3, the
amount on i1, its own balance on i2, the height on i6 and -- for a park
only -- the absolute release pair on i17.
"""
import itertools
import json
from collections import namedtuple
from unittest.mock import PropertyMock, patch

import pytest

import chain_state
import tau_admission
import tau_defs
from block import Block
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_payload
from commands import checktx
from consensus import recipient_gate, sender_policy
from consensus.admission import (
    TipAdmissionView,
    _check_host_contract_patch,
    screen_user_rule_text,
    validate_rule_offer_payload,
)
from consensus.approvals import ApprovalRequest
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import parse_retractable_transfer
from consensus.rule_offers import RuleOffer
from consensus.state import TauStateSnapshot

HEIGHT = 20
FAR = 9999999999
FEE = 5
BLOCK_TS = 1234567890

SK_AUTH = 0xA07A
ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)
MALLORY = pubkey_hex(SK_MALLORY)
AUTH = pubkey_hex(SK_AUTH)

_TX_SEQ = itertools.count()


# --- the shared helpers, unit level -------------------------------------------

def test_release_pair_packs_both_units():
    pair = recipient_gate.pack_release_pair(release_ts=1700000000, release_height=0)
    assert pair >> 32 == 1700000000 and pair & 0xFFFFFFFF == 0
    pair = recipient_gate.pack_release_pair(release_ts=0, release_height=12345)
    assert pair == 12345
    assert recipient_gate.pack_release_pair() == 0


def test_recipient_values_change_only_the_owner_streams():
    base = {1: "100", 2: "900", 3: "S", 4: "R", 5: "777", 12: "S", 26: "x"}
    values = recipient_gate.recipient_values(base, "RECIP", 500, 77, release_pair=5)
    assert values[1] == "100" and values[3] == "S" and values[26] == "x"
    assert values[2] == "500"
    assert values[12] == "{ #xRECIP }:bv[384]"
    assert values[6] == "77"
    assert values[17] == "5"
    assert base[12] == "S"  # the sender's map is not mutated


def test_policy_blocked_mirrors_the_sender_parse():
    parse = lambda raw: int(str(raw))
    assert recipient_gate.policy_blocked({5: "0"}, parse) is True
    assert recipient_gate.policy_blocked({5: "1"}, parse) is False
    assert recipient_gate.policy_blocked({}, parse) is False


def test_hold_cap_reads_o10_and_fails_closed():
    parse = lambda raw: int(str(raw)) if str(raw).isdigit() else 0
    assert recipient_gate.hold_cap({10: "86400"}, parse) == 86400
    assert recipient_gate.hold_cap({}, parse) is None
    assert recipient_gate.hold_cap({10: "garbage"}, parse) == 0


# --- block apply, scripted Tau --------------------------------------------------

Applied = namedtuple("Applied", "result lifecycle multi_calls")


def _owner_of(vals):
    raw = str(vals.get(12, ""))
    if "#x" in raw:
        return raw.split("#x", 1)[1].split(" ", 1)[0].strip()
    return raw


def _lifecycle(*, clause=None, request=None):
    lm = ConsensusLifecycleManager(active_validators=[MALLORY, ALICE])
    lm.activate_approval_slots()
    # The gate tests run in the ACTIVE configuration: the recipient
    # gate is governance-activated, exactly as approval slots are
    # activated one line above. The inactive configuration has its
    # own tests at the bottom of this file.
    lm.activate_recipient_gate()
    if clause is not None:
        lm.rule_offers.accepted_clauses[(BOB, tau_defs.USER_POLICY_STREAM_INDEX)] = clause
    if request is not None:
        assert lm.approval_requests.submit_request(request)
    return lm


def _parent(lm, balances=None):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": balances or {ALICE: 100000, AUTH: 10, BOB: 0, CAROL: 100000, MALLORY: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )


def _apply(txs, lm, *, parent=None, height=HEIGHT, blocked=frozenset(),
           caps=None, decide=None, clause_decide=None, recipient_policy=False):
    # The gate is clause-triggered: a recipient the script gives a
    # policy (blocked, recipient_policy) or a cap (caps) is a recipient
    # who published one, modelled by registering the trigger clauses
    # for BOB -- unless the test registered its own clause already.
    if blocked or recipient_policy:
        lm.rule_offers.accepted_clauses.setdefault(
            (BOB, tau_defs.USER_POLICY_STREAM_INDEX),
            "always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")
    if caps:
        lm.rule_offers.accepted_clauses.setdefault(
            (BOB, tau_defs.RECIPIENT_HOLD_CAP_STREAM_INDEX),
            "always ( o10[t]:bv[24] = { #x000000 }:bv[24] ).")
    if parent is None:
        parent = _parent(lm)
    view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block = Block.create(block_number=height, previous_hash="00" * 32,
                         transactions=txs, proposer_pubkey=MALLORY,
                         timestamp=BLOCK_TS)
    persisted = []
    multi_calls = []

    def _single(**kw):
        text = str(kw.get("rule_text") or "")
        if text and kw.get("apply_rules_update"):
            persisted.append(text.strip())
        return "T"

    def _multi(**kw):
        vals = kw.get("input_stream_values") or {}
        multi_calls.append(dict(vals))
        amount = int(str(vals.get(1, "0")) or 0)
        out = {1: str(amount), 8: "0", 9: str(FEE), 5: "1"}
        if decide is not None:
            out.update(decide(vals) or {})
        owner = _owner_of(vals)
        if owner in blocked:
            out[5] = "0"
        if caps and owner in caps:
            out[10] = str(caps[owner])
        return out

    sender_policy.set_evaluator(
        "apply", MockPolicyEvaluator(decide=clause_decide or (lambda body, inputs: None)))
    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("chain_state.get_application_rules_state",
               side_effect=lambda: "\n".join(persisted)), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        try:
            result = TauConsensusEngine().apply_block(view, block, parent)
        finally:
            sender_policy.set_evaluator("apply", None)
    return Applied(result, result.next_snapshot.metadata["lifecycle_manager"], multi_calls)


def _envelope(tx_type, sender, seq, *, fee_limit="100000", **fields):
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


def _transfer(to, amount, sk, *, sender=ALICE, seq=0):
    return sign_payload(_envelope(
        "user_tx", sender, seq,
        operations={"1": [[sender, to, str(amount)]]}), sk)


def _outcome(applied, tx_id):
    return next(o for o in applied.result.outcomes if o.tx_id == tx_id)


def _balances(applied):
    return applied.result.next_snapshot.metadata["balances"]


# --- #47 at apply ---------------------------------------------------------------

def test_recipient_policy_refusal_has_distinct_reason():
    lm = _lifecycle()
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm, blocked={BOB})
    outcome = _outcome(applied, tx["tx_id"])
    assert outcome.reason == recipient_gate.REASON_POLICY_BLOCK
    assert outcome.reason != "user_policy_block"
    assert tx["tx_id"] not in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 0
    assert _balances(applied)[ALICE] == 100000


def test_recipient_rule_reads_counterparty_and_amount():
    def decide(vals):
        # BOB's rule, as the node would evaluate it: refuse CAROL above 500.
        if _owner_of(vals) == BOB and _owner_of({12: vals.get(3)}) == CAROL \
                and int(str(vals.get(1, "0")) or 0) > 500:
            return {5: "0"}
        return {}

    lm = _lifecycle()
    big = _transfer(BOB, 600, SK_CAROL, sender=CAROL)
    applied = _apply([big], lm, decide=decide, recipient_policy=True)
    assert _outcome(applied, big["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK

    lm = _lifecycle()
    small = _transfer(BOB, 400, SK_CAROL, sender=CAROL)
    applied = _apply([small], lm, decide=decide, recipient_policy=True)
    assert small["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 400 - FEE or _balances(applied)[BOB] == 400

    lm = _lifecycle()
    other_sender = _transfer(BOB, 600, SK_ALICE)
    applied = _apply([other_sender], lm, decide=decide, recipient_policy=True)
    assert other_sender["tx_id"] in applied.result.accepted_tx_ids


def test_one_refused_output_fails_the_whole_batch():
    lm = _lifecycle()
    tx = sign_payload(_envelope(
        "user_tx", ALICE, 0,
        operations={"1": [[ALICE, CAROL, "100"], [ALICE, BOB, "100"]]}), SK_ALICE)
    applied = _apply([tx], lm, blocked={BOB})
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[CAROL] == 100000  # the good leg did not move either
    assert _balances(applied)[BOB] == 0


def test_recipient_without_policy_allows_all():
    lm = _lifecycle()
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100


def test_outbound_only_clause_does_not_block_inbound():
    # BOB's only clause is his SEND whitelist: it reads i4 (where a
    # transfer is going) and never mentions i3 or i17. Written purely
    # for outbound transfers, it must not veto money arriving -- the
    # neutral default DESIGN section 1 promises ("a policy that does
    # not mention incoming transfers allows everything"). Judged on
    # the recipient map the clause would see i4 = BOB himself, who is
    # not on his own send whitelist, so an unscreened gate refuses
    # the payment for a reason the clause was never written to give.
    clause = (
        "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
        "&& i4[t]:bv[384] = { #x" + CAROL + " }:bv[384] )."
    )

    def whitelist(body, inputs):
        if body != clause:
            return None
        # The whitelist's own semantics: allow only sends to CAROL.
        return "1" if inputs.get("i4") == "#x" + CAROL else "0"

    lm = _lifecycle(clause=clause)
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm, clause_decide=whitelist)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100


def test_comment_mentioning_i4_does_not_screen_out_an_inbound_clause():
    # PoC (comment-only reference): BOB's clause is an inbound rule
    # -- refuse incoming above 500, reading i1 only -- and its only
    # mention of i4 is inside a '#' comment recalling the old send
    # whitelist. A raw-text screen would see i4 and suppress the
    # verdict, admitting a payment the clause refuses. The screen
    # strips comments first, so the verdict stands.
    clause = (
        "always ( o5[t]:bv[24] = { #x000001 }:bv[24] ). "
        "# see also the old send whitelist on i4[t]"
    )

    def amount_rule(body, inputs):
        if body != clause:
            return None
        return "0" if int(inputs.get("i1", "0")) > 500 else "1"

    lm = _lifecycle(clause=clause)
    big = _transfer(BOB, 600, SK_CAROL, sender=CAROL)
    applied = _apply([big], lm, clause_decide=amount_rule)
    assert _outcome(applied, big["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[BOB] == 0

    lm = _lifecycle(clause=clause)
    small = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([small], lm, clause_decide=amount_rule)
    assert small["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100


def test_comment_mentioning_i3_does_not_rescue_an_outbound_clause():
    # PoC (comment-only reference, mirrored): BOB's clause is the
    # outbound whitelist -- reads i4 in its body, never i3/i17, no
    # o10 -- and its only mention of i3 is inside a '#' comment.
    # A raw-text screen would see i3 and enforce the verdict,
    # refusing a payment the clause was never written about. The
    # screen strips comments first, so the outbound verdict stays
    # unenforced against the inbound transfer.
    clause = (
        "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
        "&& i4[t]:bv[384] = { #x" + CAROL + " }:bv[384] ). "
        "# inbound note: i3[t] is the sender on this map"
    )

    def whitelist(body, inputs):
        if body != clause:
            return None
        return "1" if inputs.get("i4") == "#x" + CAROL else "0"

    lm = _lifecycle(clause=clause)
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm, clause_decide=whitelist)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100


def test_one_unit_carries_inbound_and_outbound_rules():
    # #47 case 4: BOB's ONE policy unit carries both directions -- an
    # inbound rule (reads the counterparty on i3: refuse CAROL) and
    # the outbound whitelist (reads the destination on i4: send only
    # to CAROL). Both halves must enforce, each under its own reason.
    unit = (
        "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
        "&& (i3[t]:bv[384] = { #x" + ALICE + " }:bv[384] "
        "|| i4[t]:bv[384] = { #x" + CAROL + " }:bv[384]) )."
    )

    def unit_decide(body, inputs):
        if body != unit or inputs.get("i12") != "#x" + BOB:
            return None
        if inputs.get("i4") == "#x" + BOB:
            # Inbound half: BOB is being paid; refuse CAROL.
            return "0" if inputs.get("i3") == "#x" + CAROL else "1"
        # Outbound half: BOB is sending; only CAROL may receive.
        return "1" if inputs.get("i4") == "#x" + CAROL else "0"

    # The inbound half enforces under the recipient reason.
    lm = _lifecycle(clause=unit)
    bad = _transfer(BOB, 100, SK_CAROL, sender=CAROL)
    applied = _apply([bad], lm, clause_decide=unit_decide)
    assert _outcome(applied, bad["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[BOB] == 0

    lm = _lifecycle(clause=unit)
    good = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([good], lm, clause_decide=unit_decide)
    assert good["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100

    # The outbound half enforces under the sender reason.
    funded = {ALICE: 100000, AUTH: 10, BOB: 1000, CAROL: 100000, MALLORY: 0}
    lm = _lifecycle(clause=unit)
    out_bad = _transfer(MALLORY, 100, SK_BOB, sender=BOB)
    applied = _apply([out_bad], lm, parent=_parent(lm, balances=dict(funded)),
                     clause_decide=unit_decide)
    assert _outcome(applied, out_bad["tx_id"]).reason == "user_policy_block"
    assert _balances(applied)[MALLORY] == 0

    lm = _lifecycle(clause=unit)
    out_good = _transfer(CAROL, 100, SK_BOB, sender=BOB)
    applied = _apply([out_good], lm, parent=_parent(lm, balances=dict(funded)),
                     clause_decide=unit_decide)
    assert out_good["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[CAROL] == 100000 + 100


def test_guarded_unit_can_refuse_inbound():
    # Guarded mode (#47): BOB's unit lives in the spec itself, guarded
    # on i12 = BOB -- "always ((i12 = BOB) ? <body> : o5 = allow)" --
    # and is NOT an accepted clause. The isolated clause evaluator
    # below allows everything, so a refusal can only come from the
    # guarded unit firing on the gate's second pass, the one that
    # feeds i12 = recipient. BOB's unit: only ALICE may pay him.
    def spec_decide(vals):
        if _owner_of(vals) == BOB \
                and _owner_of({12: vals.get(3)}) != ALICE:
            return {5: "0"}
        return {}

    lm = _lifecycle()
    tx = _transfer(BOB, 100, SK_CAROL, sender=CAROL)
    applied = _apply([tx], lm, decide=spec_decide, recipient_policy=True,
                     clause_decide=lambda body, inputs: "1")
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[BOB] == 0
    # The gate's second pass ran with the recipient as policy owner --
    # the only way the guard on i12 = BOB can match.
    assert any(_owner_of(c) == BOB for c in applied.multi_calls)

    # Control: the approved sender passes the same guarded unit.
    lm = _lifecycle()
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm, decide=spec_decide, recipient_policy=True,
                     clause_decide=lambda body, inputs: "1")
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100


def test_recipient_clause_alone_can_block():
    clause = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
    lm = _lifecycle(clause=clause)
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm,
                     clause_decide=lambda body, inputs: "0" if body == clause else None)
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[BOB] == 0


def test_rule_offers_are_not_recipient_gated():
    lm = _lifecycle()
    offer = RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=BOB,
                      rule_text="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).",
                      expire_at_height=HEIGHT + 100)
    tx = sign_payload(_envelope(
        "rule_offer", ALICE, 0, fee_limit="100000",
        recipient_pubkey=offer.recipient_pubkey, rule_text=offer.rule_text,
        expire_at_height=offer.expire_at_height), SK_ALICE)
    applied = _apply([tx], lm, blocked={BOB})
    assert tx["tx_id"] in applied.result.accepted_tx_ids


def test_approval_completion_refused_by_recipient_policy():
    request = ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=500,
        sequence_number=0, expire_at_height=500,
        approvers={18: AUTH}, custom_inputs={},
    )
    lm = _lifecycle(request=request)
    vote = sign_payload(_envelope(
        "transfer_vote", AUTH, 0, fee_limit="0",
        request_id=request.request_id_hex, approve=True), SK_AUTH)
    applied = _apply([vote], lm, blocked={BOB})
    # The vote itself stands; the completion it triggered is refused by
    # the recipient's policy, so the request fails unexecuted -- the same
    # terminal shape a sender-policy block gives a completion.
    logs = " | ".join(str(x) for x in _outcome(applied, vote["tx_id"]).receipt_logs)
    assert "recipient policy" in logs
    assert _balances(applied)[BOB] == 0
    assert request.request_id not in applied.lifecycle.approval_requests.open_requests
    assert applied.lifecycle.approval_requests.terminal_status.get(
        request.request_id) is not None

    # Control: unblocked, the same vote pays the recipient.
    lm = _lifecycle(request=request)
    vote = sign_payload(_envelope(
        "transfer_vote", AUTH, 0, fee_limit="0",
        request_id=request.request_id_hex, approve=True), SK_AUTH)
    applied = _apply([vote], lm)
    assert _balances(applied)[BOB] == 500


def test_recipient_refusal_at_apply_charges_like_a_sender_block():
    # DESIGN section 4.4: a recipient refusal at apply behaves like a
    # sender-policy block at apply. The harness observes the charge
    # through the sender's resulting balance (outcomes carry no fee
    # field): both refusals must cost the sender exactly the same,
    # and strictly less than an applied transfer, which pays the
    # amount plus the measured step fee. (The admission half of the
    # documented behaviour -- a refusal there is free -- is a dry
    # run: it moves no balance by construction, and its refusal
    # envelope is pinned by the admission tests below.)
    clause = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."

    # A sender-policy block: ALICE's own clause refuses her send.
    lm = _lifecycle()
    lm.rule_offers.accepted_clauses[(ALICE, tau_defs.USER_POLICY_STREAM_INDEX)] = clause
    tx = _transfer(CAROL, 100, SK_ALICE)
    applied = _apply([tx], lm,
                     clause_decide=lambda body, inputs: "0" if body == clause else None)
    assert _outcome(applied, tx["tx_id"]).reason == "user_policy_block"
    sender_block_balance = _balances(applied)[ALICE]

    # A recipient-policy block of the same transfer shape.
    lm = _lifecycle()
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm, blocked={BOB})
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    recipient_block_balance = _balances(applied)[ALICE]

    # Control: the same payment applied pays amount + measured fee.
    lm = _lifecycle()
    tx = _transfer(CAROL, 100, SK_ALICE)
    applied = _apply([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[ALICE] == 100000 - 100 - FEE

    assert recipient_block_balance == sender_block_balance


# --- #76 at apply ---------------------------------------------------------------

def _park(sk, *, sender=ALICE, seq=0, release_at_height=HEIGHT + 10, amount=100):
    return sign_payload(_envelope(
        "retractable_transfer", sender, seq, recipient_pubkey=BOB,
        amount=amount, release_at_height=release_at_height), sk)


def test_park_within_recipient_cap_is_admitted():
    lm = _lifecycle()
    tx = _park(SK_ALICE)
    applied = _apply([tx], lm, caps={BOB: 20})
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert applied.lifecycle.retractable_transfers.escrow_total() == 100
    # The recipient evaluation of the park carried the absolute pair on i17.
    park_evals = [c for c in applied.multi_calls
                  if _owner_of(c) == BOB and str(c.get(17, "0")) != "0"]
    assert park_evals and int(park_evals[0][17]) == HEIGHT + 10


def test_park_beyond_recipient_cap_refused_with_cap():
    lm = _lifecycle()
    tx = _park(SK_ALICE)
    applied = _apply([tx], lm, caps={BOB: 5})
    outcome = _outcome(applied, tx["tx_id"])
    assert outcome.reason == recipient_gate.REASON_HOLD_CAP
    assert "cap=5" in " | ".join(str(x) for x in outcome.receipt_logs)
    assert applied.lifecycle.retractable_transfers.escrow_total() == 0
    assert _balances(applied)[ALICE] == 100000


def test_recipient_cap_zero_allows_instant_only():
    lm = _lifecycle()
    tx = _park(SK_ALICE)
    applied = _apply([tx], lm, caps={BOB: 0})
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_HOLD_CAP

    lm = _lifecycle()
    plain = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([plain], lm, caps={BOB: 0})
    assert plain["tx_id"] in applied.result.accepted_tx_ids


def test_release_and_retract_are_never_gated():
    lm = _lifecycle()
    tx = _park(SK_ALICE)
    applied = _apply([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    entry = parse_retractable_transfer(tx)

    retract = sign_payload(_envelope(
        "retract_transfer", ALICE, 1, fee_limit="0",
        retractable_id=entry.retractable_id.hex()), SK_ALICE)
    applied2 = _apply([retract], applied.lifecycle,
                      parent=applied.result.next_snapshot, blocked={BOB})
    assert retract["tx_id"] in applied2.result.accepted_tx_ids
    assert _balances(applied2)[ALICE] == 100000 - FEE  # escrow refunded, park fee paid


def test_park_release_is_never_gated():
    # The release leg of #76's "never gated", driven rather than
    # named: the park matures in a block where the recipient's
    # policy refuses every inbound transfer (blocked below), and
    # the sweep still pays the recipient in full. A release is the
    # recipient's own escrowed money leaving; gating it could trap
    # funds behind a policy published after the park was created.
    lm = _lifecycle()
    tx = _park(SK_ALICE)  # releases at HEIGHT + 10
    applied = _apply([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    entry = parse_retractable_transfer(tx)

    applied2 = _apply([], applied.lifecycle,
                      parent=applied.result.next_snapshot,
                      height=HEIGHT + 10, blocked={BOB})
    assert entry.retractable_id.hex() in \
        applied2.result.governance_changes["released_retractables"]
    assert _balances(applied2)[BOB] == 100
    assert applied2.lifecycle.retractable_transfers.escrow_total() == 0


def test_recipient_without_cap_allows_any_hold():
    lm = _lifecycle()
    tx = _park(SK_ALICE, release_at_height=HEIGHT + 100000)
    applied = _apply([tx], lm)
    assert tx["tx_id"] in applied.result.accepted_tx_ids


def test_absolute_deadline_cap_refuses_short_park():
    # BOB's rule: nothing may release after height 100, whatever the
    # hold length. A delta feed cannot state this; the absolute pair
    # on i17 can. The park below holds only 10 blocks -- inside any
    # reasonable length cap -- but releases at 110, past the deadline.
    deadline = 100

    def decide(vals):
        if _owner_of(vals) == BOB:
            pair = int(str(vals.get(17, "0")) or 0)
            release_height = pair & 0xFFFFFFFF
            if release_height and release_height > deadline:
                return {5: "0"}
        return {}

    lm = _lifecycle()
    tx = _park(SK_ALICE, release_at_height=110)
    applied = _apply([tx], lm, decide=decide, caps={BOB: 20})
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK

    # The same hold length releasing before the deadline is admitted.
    lm = _lifecycle()
    tx = _park(SK_ALICE, release_at_height=30)
    applied = _apply([tx], lm, decide=decide, caps={BOB: 20})
    assert tx["tx_id"] in applied.result.accepted_tx_ids


# --- admission (checktx dry run of sendtx) ---------------------------------------

NEXT_HEIGHT = 50
TIP_TS = 1_700_000_000


class _AdmissionSession:
    """Owner-aware admission worker: o5 by i12, o10 caps by i12."""

    def __init__(self, script):
        self.script = script

    def evaluate(self, inputs, *, multi, record):
        self.script["steps"].append(dict(inputs))
        out = {1: str(inputs.get(1, "0")), 5: "1", 8: "0", 9: "10"}
        owner = _owner_of(inputs)
        if owner in self.script["blocked"]:
            out[5] = "0"
        if owner in self.script["caps"]:
            out[10] = str(self.script["caps"][owner])
        return out

    def apply_rule(self, rule_text, *, target, record):
        pass

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        pass


class _Standby:
    enabled = True

    def take(self, **kwargs):
        return None

    def refill(self, **kwargs):
        pass


@pytest.fixture
def admission_node(temp_database, mock_policy_evaluators, monkeypatch):
    script = {"steps": [], "blocked": set(), "caps": {}}

    def build(**kwargs):
        return _AdmissionSession(script), {"journal_head": "h", "journal_sequence": 0,
                                           "epoch": 0, "high_water": 0}, None

    patches = [
        patch("tau_admission.enabled", return_value=True),
        patch("tau_admission._build", side_effect=build),
        patch("tau_admission._standby", _Standby()),
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau_multi",
              side_effect=AssertionError("the in-process evaluator was used")),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch("tau_native.compile_revisions_isolated_subprocess", return_value=None),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
        patch.object(TipAdmissionView, "next_block_height",
                     new_callable=PropertyMock, return_value=NEXT_HEIGHT),
        patch.object(TipAdmissionView, "tip_timestamp",
                     new_callable=PropertyMock, return_value=TIP_TS),
        patch.object(TipAdmissionView, "approval_slots_active",
                     new_callable=PropertyMock, return_value=True),
        patch.object(TipAdmissionView, "recipient_gate_active",
                     new_callable=PropertyMock, return_value=True),
        patch.object(TipAdmissionView, "get_offer", return_value=None),
        patch.object(TipAdmissionView, "clause_for",
                     side_effect=lambda pk, stream: (
                         "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
                         if pk == BOB and (
                             BOB in script["blocked"] or BOB in script["caps"])
                         else None)),
    ]
    mocks = [p.start() for p in patches]
    mocks[3].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, ALICE, 1_000_000)
    monkeypatch.setitem(chain_state._balances, BOB, 1_000_000)
    yield script
    for p in reversed(patches):
        p.stop()


def _draft(tx):
    return "checktx estimate " + json.dumps(tx)


def _signed_draft(tx_type, sender, sk, **fields):
    tx = {"tx_type": tx_type, "sender_pubkey": sender, "sequence_number": 1,
          "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 200,
          "fee_limit": "100000"}
    tx.update(fields)
    return sign_payload(tx, sk)


def test_admission_recipient_refusal_names_the_recipient_reason(admission_node):
    admission_node["blocked"] = {BOB}
    tx = _signed_draft("user_tx", ALICE, SK_ALICE,
                       operations={"1": [[ALICE, BOB, "100"]]})
    result = json.loads(checktx.execute(_draft(tx), None))
    assert result["status"] == "error"
    assert result["error"]["details"]["reason"] == recipient_gate.REASON_POLICY_BLOCK


def test_recipient_cap_admission_matches_apply(admission_node):
    # Hold of NEXT_HEIGHT+10 - NEXT_HEIGHT = 10 blocks: refused at cap 5,
    # admitted at cap 20 -- the same numbers the apply tests above use.
    tx = _signed_draft("retractable_transfer", ALICE, SK_ALICE,
                       recipient_pubkey=BOB, amount=100,
                       release_at_height=NEXT_HEIGHT + 10,
                       expire_at_height=NEXT_HEIGHT + 10)
    admission_node["caps"] = {BOB: 5}
    result = json.loads(checktx.execute(_draft(tx), None))
    assert result["status"] == "error"
    assert result["error"]["details"]["reason"] == recipient_gate.REASON_HOLD_CAP
    assert result["error"]["details"]["recipient_hold_cap"] == 5

    admission_node["caps"] = {BOB: 20}
    result = json.loads(checktx.execute(_draft(tx), None))
    assert result["status"] == "ok"
    assert result["data"]["recipient_hold_cap"] == "enforced"


def test_checktx_reports_recipient_capabilities_enforced(admission_node):
    # #47 case 5 / #76 case 6, the reporting half: checktx's capability
    # surface names both features as enforced on this node, so a
    # wallet can detect the gate before offering an inbound rule.
    tx = _signed_draft("user_tx", ALICE, SK_ALICE,
                       operations={"1": [[ALICE, BOB, "100"]]})
    result = json.loads(checktx.execute(_draft(tx), None))
    assert result["status"] == "ok"
    assert result["data"]["recipient_policy_gate"] == "enforced"
    assert result["data"]["recipient_hold_cap"] == "enforced"


# --- activation: the gate is governance-activated (#47 case 5 / #76 case 6) -----
#
# Until a host-contract patch sets recipient_gate_active, the gate does
# not run and a clause that would deploy the feature is refused at
# deploy -- the behaviour DESIGN section 3.3 promises a pre-feature
# deployment. The tests above run in the active configuration (the
# harness activates, like it does for approval slots); these pin the
# inactive one and the activation path itself.

_I17_CLAUSE = (
    "always ( o5[t]:bv[24] = { #x000001 }:bv[24] "
    "&& i17[t]:bv[64] = { 0 }:bv[64] )."
)
_PLAIN_CLAUSE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."


def _lifecycle_inactive():
    lm = ConsensusLifecycleManager(active_validators=[MALLORY, ALICE])
    lm.activate_approval_slots()
    return lm


class _TipStub:
    """The slice of the tip view validate_rule_offer_payload reads."""

    def __init__(self, *, gate):
        self.recipient_gate_active = gate
        self.next_block_height = HEIGHT

    def get_offer_lifecycle_state(self, offer_id_hex):
        return None

    def pending_offers_for_recipient(self, pubkey):
        return 0

    def pending_offers_for_offerer(self, pubkey):
        return 0


def _offer_tx(rule_text):
    return sign_payload(_envelope(
        "rule_offer", ALICE, 0, fee_limit="100000",
        recipient_pubkey=BOB, rule_text=rule_text,
        expire_at_height=HEIGHT + 100), SK_ALICE)


def test_feature_detection_reads_only_the_features_own_streams():
    uses = recipient_gate.clause_uses_recipient_feature
    assert uses(_I17_CLAUSE) is True
    assert uses("always ( o10[t]:bv[64] = { 3600 }:bv[64] ).") is True
    assert uses(_PLAIN_CLAUSE, target_stream=10) is True
    assert uses(_PLAIN_CLAUSE) is False
    assert uses(_PLAIN_CLAUSE, target_stream=5) is False
    # A stream named only in a comment is not a reference the clause
    # makes -- the same flaw class as the prescreen PoCs above.
    assert uses(_PLAIN_CLAUSE + " # park pair on i17[t]") is False
    assert uses("") is False
    assert uses(None) is False


def test_deploy_refused_while_gate_inactive():
    # A clause reading i17 deploys the recipient feature: refused at
    # admission while the gate is off, with the inactive error that
    # names the governance patch -- not silently admitted and never
    # enforced.
    result = validate_rule_offer_payload(
        _offer_tx(_I17_CLAUSE), _TipStub(gate=False))
    assert not result.is_valid
    assert result.code == "FEATURE_INACTIVE"
    assert "recipient_gate_active" in result.error

    # An ordinary o5 clause is a sender policy the chain already
    # enforces; it deploys exactly as it always has.
    result = validate_rule_offer_payload(
        _offer_tx(_PLAIN_CLAUSE), _TipStub(gate=False))
    assert result.is_valid

    # Once active, the same recipient clause deploys.
    result = validate_rule_offer_payload(
        _offer_tx(_I17_CLAUSE), _TipStub(gate=True))
    assert result.is_valid


def test_spec_units_are_not_deploy_refused():
    # The boundary of the deploy refusal, pinned deliberately: the
    # refusal covers the surfaces that REGISTER recipient policy (the
    # clause registry), not accumulated spec units. o10 is a free
    # output stream for user rules -- the codebase's own suite pins
    # that (test_approval_admission.py's free-output-streams test,
    # test_launch_hardening.py's word-boundary test) -- so a guarded
    # unit writing o10 is admitted exactly as it was before the
    # feature, whatever the gate's state. A first version of this
    # activation refused such units; those two tests failed, and the
    # refusal was removed rather than the contract broken.
    unit = (
        "always ( (i12[t]:bv[384] = { #x" + BOB + " }:bv[384]) "
        "-> o10[t]:bv[64] = { 3600 }:bv[64] )."
    )
    assert screen_user_rule_text(unit, "", True) is None


def test_gate_inactive_at_apply():
    # The offer is refused in the block too, under the named reason,
    # so a proposer cannot include what admission refused.
    lm = _lifecycle_inactive()
    tx = _offer_tx(_I17_CLAUSE)
    applied = _apply([tx], lm)
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_GATE_INACTIVE
    assert tx["tx_id"] not in applied.result.accepted_tx_ids

    # And the gate itself does not run: BOB's registered clause --
    # modelled here as deployed before the feature existed -- judges
    # nobody, and the transfer lands exactly as it did pre-feature.
    lm = _lifecycle_inactive()
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm, blocked={BOB})
    assert tx["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 100


def test_governance_patch_activates_the_gate():
    lm = _lifecycle_inactive()
    assert lm.recipient_gate_active is False
    hash_before = lm.consensus_meta_hash()

    # The flag enters the mechanism metadata only once active, so the
    # pre-activation hash is the pre-feature hash.
    assert "recipient_gate_active" not in build_mechanism_metadata("supermajority")
    assert build_mechanism_metadata(
        "supermajority", recipient_gate_active=True)["recipient_gate_active"] is True

    # Admission screens the patch value; apply enforces it again --
    # deactivation is not a legal value on either path.
    err = _check_host_contract_patch({"recipient_gate_active": False})
    assert err is not None and "recipient_gate_active" in err
    assert _check_host_contract_patch({"recipient_gate_active": True}) is None
    with pytest.raises(ValueError, match="recipient_gate_active"):
        lm.apply_host_contract_patch({"recipient_gate_active": False})
    assert lm.recipient_gate_active is False

    # The activation path itself: one governance patch, one-way.
    lm.apply_host_contract_patch({"recipient_gate_active": True})
    assert lm.recipient_gate_active is True
    assert lm.consensus_meta_hash() != hash_before

    # From the next block the gate enforces, unchanged: the same
    # transfer the inactive test above let through is now refused
    # under the recipient reason.
    tx = _transfer(BOB, 100, SK_ALICE)
    applied = _apply([tx], lm, blocked={BOB})
    assert _outcome(applied, tx["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK
    assert _balances(applied)[BOB] == 0


def test_checktx_reports_inactive_and_judges_nobody_when_gate_off(admission_node):
    # The reporting half, inactive side: the capability surface says
    # "inactive", and the dry run admits a transfer to a recipient
    # whose policy would refuse it on an activated chain.
    admission_node["blocked"] = {BOB}
    tx = _signed_draft("user_tx", ALICE, SK_ALICE,
                       operations={"1": [[ALICE, BOB, "100"]]})
    with patch.object(TipAdmissionView, "recipient_gate_active",
                      new_callable=PropertyMock, return_value=False):
        result = json.loads(checktx.execute(_draft(tx), None))
    assert result["status"] == "ok"
    assert result["data"]["recipient_policy_gate"] == "inactive"
    assert result["data"]["recipient_hold_cap"] == "inactive"
