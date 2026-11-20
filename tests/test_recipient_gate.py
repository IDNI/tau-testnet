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
from consensus.admission import TipAdmissionView
from consensus.approvals import ApprovalRequest
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
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
           caps=None, decide=None, clause_decide=None):
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
    applied = _apply([big], lm, decide=decide)
    assert _outcome(applied, big["tx_id"]).reason == recipient_gate.REASON_POLICY_BLOCK

    lm = _lifecycle()
    small = _transfer(BOB, 400, SK_CAROL, sender=CAROL)
    applied = _apply([small], lm, decide=decide)
    assert small["tx_id"] in applied.result.accepted_tx_ids
    assert _balances(applied)[BOB] == 400 - FEE or _balances(applied)[BOB] == 400

    lm = _lifecycle()
    other_sender = _transfer(BOB, 600, SK_ALICE)
    applied = _apply([other_sender], lm, decide=decide)
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
        patch.object(TipAdmissionView, "get_offer", return_value=None),
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
