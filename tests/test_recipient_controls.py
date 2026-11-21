"""Recipient controls (issues #47/#76): the recipient's o5 clause as a gate.

The gate lives inside the shared transfer closure, so these tests drive
every payment path through real block apply with a scripted policy
evaluator:

  * ordinary transfers and batches (atomic on a recipient refusal),
  * approval-request settlement -- the sharpest path, because the payment
    never appears as a transfer output of the vote transaction,
  * escrow parks, judged on the hold they carry at park time,
  * retract and release, which are never recipient-gated,
  * clause registration timing within and across blocks.

Plus unit tests for the verdict module (cap measurement by re-evaluation,
never by parsing rule text), the deploy screens, and the plain-language
templates the CLI installs.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from block import Block
from consensus import recipient_policy, sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import KIND_HEIGHT, KIND_TIME, RetractableEntry
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_700_000_000
FAR = 9_999_999_999


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)     # sender
SK_AUTH, AUTH = _key(22222)       # approver
SK_SCAN, SCAN = _key(33333)       # approver 2
SK_BOB, BOB = _key(44444)         # recipient
SK_CAROL, CAROL = _key(55555)     # second recipient / listed sender
SK_STRANGER, STRANGER = _key(66666)

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


# --- the mock evaluator's reading of a clause body ---------------------------
# The mock cannot run Tau, so each registered body gets a `decide` callable
# that implements exactly the semantics the real body has. Inputs are the
# bare clause inputs: i3/i4 are "#x<96 hex>", i1 the amount, i17/i27 holds.

def decide_for(owner, allowed_senders=(), max_hold_seconds=None,
               max_hold_blocks=None):
    """Semantics of recipient_policy.recipient_clause_body with these args."""
    allowed = {"#x" + s for s in allowed_senders}
    if max_hold_seconds is None and max_hold_blocks is None:
        cap_s = cap_b = None
    else:
        cap_s = 0 if max_hold_seconds is None else max_hold_seconds
        cap_b = 0 if max_hold_blocks is None else max_hold_blocks

    def decide(inputs):
        if inputs.get("i4") != "#x" + owner:
            return None                     # recipient guard false -> allow
        if allowed and inputs.get("i3") not in allowed:
            return 0
        if cap_s is not None and int(inputs.get("i17", "0")) > cap_s:
            return 0
        if cap_b is not None and int(inputs.get("i27", "0")) > cap_b:
            return 0
        return None
    return decide


@pytest.fixture(autouse=True)
def _evaluators():
    ev = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", ev)
    yield ev
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)


def _install(ev, owner, body, **semantics):
    """Register `body` for `owner` in a fresh lifecycle manager's registry
    is the caller's job; this binds the mock's semantics for the body."""
    ev.set_verdict(body, decide_for(owner, **semantics))


# --- apply harness (after tests/test_approval_apply.py) ----------------------

def _lm(active=True):
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    if active:
        lm.activate_approval_slots()
    return lm


def _apply(txs, lm=None, height=HEIGHT, ts=TS, balances=None, replay=False,
           sequences=None):
    lm = lm if lm is not None else _lm()
    bal = balances if balances is not None else {
        ALICE: 100000, AUTH: 10, SCAN: 10, BOB: 0, CAROL: 0, STRANGER: 100000,
    }
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": dict(bal),
            "sequence_numbers": dict(sequences or {}),
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(ALICE)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block_obj = Block.create(
        block_number=height, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=ALICE, timestamp=ts,
    )

    def _fake_multi(**kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        slot18 = str(vals.get(18, "0"))
        # Tier policy for approval requests: >1000 needs AUTH's slot vote.
        blocked = amount > 1000 and AUTH not in slot18
        return {1: str(amount), 8: "0", 9: "0", 5: "0" if blocked else "1"}

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", return_value="T"), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply_block(view, block_obj, parent, replay_mode=replay)
    return result, result.next_snapshot.metadata["lifecycle_manager"]


def _logs(result):
    out = []
    for outcome in result.outcomes:
        out.extend(outcome.receipt_logs or [])
    return " | ".join(str(x) for x in out)


def _balances(result):
    return result.next_snapshot.metadata["balances"]


def _outcome(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome


def _transfer_tx(sender, sk, transfers, seq=0):
    return _sign({
        "tx_id": f"tx-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": transfers},
    }, sk)


def _rule_tx(body, sender, sk, seq=0):
    return _sign({
        "tx_id": f"rule-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"0": "always ( %s )." % body},
    }, sk)


def _with_clause(lm, owner, body):
    lm.rule_offers.accepted_clauses[(owner, 5)] = body
    return lm


# --- #47: the allow-list gate on ordinary transfers --------------------------

def test_listed_sender_may_pay_the_recipient(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [ALICE])
    _install(_evaluators, BOB, body, allowed_senders=[ALICE])
    lm = _with_clause(_lm(), BOB, body)
    tx = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "500"]])
    result, _ = _apply([tx], lm=lm)
    assert tx["tx_id"] in result.accepted_tx_ids
    assert _balances(result)[BOB] == 500


def test_unlisted_sender_is_refused_by_the_recipient(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    lm = _with_clause(_lm(), BOB, body)
    tx = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "500"]])
    result, _ = _apply([tx], lm=lm)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, tx).reason == tau_defs.REASON_RECIPIENT_POLICY_BLOCK
    assert _balances(result)[ALICE] == 100000
    assert _balances(result)[BOB] == 0
    assert "recipient's policy" in _logs(result)


def test_recipient_without_a_clause_accepts_everyone(_evaluators):
    tx = _transfer_tx(STRANGER, SK_STRANGER, [[STRANGER, BOB, "500"]])
    result, _ = _apply([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert _balances(result)[BOB] == 500


def test_batch_fails_atomically_when_one_recipient_refuses(_evaluators):
    body = recipient_policy.allowlist_clause_body(CAROL, [STRANGER])
    _install(_evaluators, CAROL, body, allowed_senders=[STRANGER])
    lm = _with_clause(_lm(), CAROL, body)
    tx = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "100"], [ALICE, CAROL, "100"]])
    result, _ = _apply([tx], lm=lm)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, tx).reason == tau_defs.REASON_RECIPIENT_POLICY_BLOCK
    bals = _balances(result)
    assert bals[BOB] == 0, "the willing recipient must not be credited either"
    assert bals[ALICE] == 100000


def test_inbound_and_outbound_conditions_coexist_in_one_clause(_evaluators):
    """One unit, both directions enforced (acceptance case #47.5)."""
    body = "(combined body: outbound cap + inbound allow-list)"

    def decide(inputs):
        if inputs.get("i3") == "#x" + BOB:      # BOB sending: cap 1000
            return 0 if int(inputs.get("i1", "0")) > 1000 else None
        if inputs.get("i4") == "#x" + BOB:      # BOB receiving: listed only
            return None if inputs.get("i3") == "#x" + CAROL else 0
        return None

    _evaluators.set_verdict(body, decide)
    lm = _with_clause(_lm(), BOB, body)

    big_send = _transfer_tx(BOB, SK_BOB, [[BOB, ALICE, "2000"]])
    result, _ = _apply([big_send], lm=lm, balances={ALICE: 0, BOB: 5000})
    assert big_send["tx_id"] in result.invalid_tx_ids, "outbound cap must fire"

    listed = _transfer_tx(CAROL, SK_CAROL, [[CAROL, BOB, "100"]])
    result, _ = _apply([listed], lm=lm, balances={CAROL: 1000, BOB: 0})
    assert listed["tx_id"] in result.accepted_tx_ids, "inbound allow-list must pass"

    unlisted = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "100"]])
    result, _ = _apply([unlisted], lm=lm)
    assert unlisted["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, unlisted).reason == tau_defs.REASON_RECIPIENT_POLICY_BLOCK


def test_a_recipient_clause_that_does_not_build_blocks_fail_closed(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    _evaluators.fail_build(body)
    lm = _with_clause(_lm(), BOB, body)
    tx = _transfer_tx(CAROL, SK_CAROL, [[CAROL, BOB, "100"]],
                      )
    result, _ = _apply([tx], lm=lm, balances={CAROL: 1000, BOB: 0})
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, tx).reason == tau_defs.REASON_RECIPIENT_POLICY_BLOCK


def test_recipient_gate_verdict_is_the_same_in_replay(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    lm = _with_clause(_lm(), BOB, body)
    tx = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "500"]])
    result, _ = _apply([tx], lm=lm, replay=True)
    assert _balances(result)[BOB] == 0
    assert _balances(result)[ALICE] == 100000


def test_self_transfer_is_never_recipient_gated(_evaluators):
    """The engine refuses self-transfers before the closure, so the skip is
    pinned here at the verdict level: sender == recipient is allowed
    without the evaluator ever being consulted."""
    body = recipient_policy.allowlist_clause_body(ALICE, [BOB])
    _install(_evaluators, ALICE, body, allowed_senders=[BOB])
    verdict = recipient_policy.recipient_verdict(
        _clause_for({(ALICE, 5): body}), ALICE,
        _values(sender=ALICE, recipient=ALICE),
        pool="apply", timeout=None, sender=ALICE,
    )
    assert not verdict.blocked
    assert _evaluators.verdict_calls == []


# --- policy-change timing -----------------------------------------------------

def test_clause_registered_earlier_in_the_block_gates_the_next_transfer(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    rule = _rule_tx(body, BOB, SK_BOB, seq=0)
    tx = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "100"]], seq=0)
    result, lm = _apply([rule, tx])
    assert lm.rule_offers.clause_for(BOB, 5) == body
    assert tx["tx_id"] in result.invalid_tx_ids


def test_transfer_before_the_clause_in_the_block_is_not_gated(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    tx = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "100"]], seq=0)
    rule = _rule_tx(body, BOB, SK_BOB, seq=0)
    result, _ = _apply([tx, rule])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert _balances(result)[BOB] == 100


# --- the approval-settlement path ---------------------------------------------

def _request_tx(sender=ALICE, sk=SK_ALICE, recipient=BOB, amount=5000, seq=0):
    from consensus.approvals import ApprovalRequest
    req = ApprovalRequest(
        sender_pubkey=sender, recipient_pubkey=recipient, amount=amount,
        sequence_number=seq, expire_at_height=500,
        approvers={18: AUTH}, custom_inputs={},
    )
    tx = {
        "tx_id": f"req-{next(_TX_SEQ)}",
        "tx_type": "approval_request",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "fee_limit": "100",
        "recipient_pubkey": recipient,
        "amount": amount,
        "expire_at_height": 500,
        "approvers": {"18": AUTH},
        "custom_inputs": {},
    }
    return _sign(tx, sk), req


def _vote_tx(req, voter=AUTH, sk=SK_AUTH, seq=0):
    return _sign({
        "tx_id": f"vote-{next(_TX_SEQ)}",
        "tx_type": "transfer_vote",
        "sender_pubkey": voter,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 5000,
        "fee_limit": "0",
        "request_id": req.request_id_hex,
        "approve": True,
    }, sk)


def test_approval_request_creation_is_not_recipient_gated(_evaluators):
    """Creating a request moves no money; only settlement is gated."""
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    lm = _with_clause(_lm(), BOB, body)
    tx, req = _request_tx()
    result, post = _apply([tx], lm=lm)
    assert post.approval_requests.get_request(req.request_id) is not None


def test_approval_settlement_refused_by_recipient_policy(_evaluators):
    """The bypass that matters: the settlement payment is not an output of
    the vote tx, so only a gate inside the shared closure can see it."""
    from consensus.approvals import STATUS_FAILED
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    lm = _with_clause(_lm(), BOB, body)
    req_tx, req = _request_tx()
    vote = _vote_tx(req)
    result, post = _apply([req_tx, vote], lm=lm)
    assert vote["tx_id"] in result.accepted_tx_ids, "the vote itself stands"
    assert post.approval_requests.terminal_status[req.request_id] == STATUS_FAILED
    assert "Parked transfer could not be executed" in _logs(result)
    bals = _balances(result)
    assert bals[BOB] == 0
    assert bals[ALICE] == 100000


def test_approval_settlement_allowed_recipient_is_paid(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [ALICE])
    _install(_evaluators, BOB, body, allowed_senders=[ALICE])
    lm = _with_clause(_lm(), BOB, body)
    req_tx, req = _request_tx()
    vote = _vote_tx(req)
    result, post = _apply([req_tx, vote], lm=lm)
    assert _balances(result)[BOB] == 5000


# --- escrow parks: the hold cap (issue #76) -----------------------------------

def _park_tx(sender=ALICE, sk=SK_ALICE, recipient=BOB, amount=100, seq=0,
             at_time=None, at_height=None):
    tx = {
        "tx_id": f"park-{next(_TX_SEQ)}",
        "tx_type": "retractable_transfer",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "recipient_pubkey": recipient,
        "amount": amount,
    }
    if at_time is not None:
        tx["release_at_time"] = at_time
    else:
        tx["release_at_height"] = HEIGHT + 10 if at_height is None else at_height
    return _sign(tx, sk)


def _retract_tx(rid_hex, sender=ALICE, sk=SK_ALICE, seq=1):
    return _sign({
        "tx_id": f"retract-{next(_TX_SEQ)}",
        "tx_type": "retract_transfer",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "0",
        "retractable_id": rid_hex,
    }, sk)


def _rid(tx):
    from consensus.retractable import parse_retractable_transfer
    return parse_retractable_transfer(tx).retractable_id.hex()


def test_park_refused_by_recipient_allowlist(_evaluators):
    body = recipient_policy.allowlist_clause_body(BOB, [CAROL])
    _install(_evaluators, BOB, body, allowed_senders=[CAROL])
    lm = _with_clause(_lm(), BOB, body)
    tx = _park_tx(at_time=TS + 600)
    result, post = _apply([tx], lm=lm)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, tx).reason == tau_defs.REASON_RECIPIENT_POLICY_BLOCK
    assert post.retractable_transfers.open_count() == 0
    assert _balances(result)[ALICE] == 100000


def test_park_at_the_cap_is_accepted_and_releases(_evaluators):
    body = recipient_policy.max_hold_clause_body(BOB, seconds=600)
    _install(_evaluators, BOB, body, max_hold_seconds=600)
    lm = _with_clause(_lm(), BOB, body)
    tx = _park_tx(at_time=TS + 600)
    result, post = _apply([tx], lm=lm)
    assert tx["tx_id"] in result.accepted_tx_ids
    assert post.retractable_transfers.open_count() == 1
    # Next block at the release time: the release pays without re-judging.
    result2, post2 = _apply(
        [], lm=post, height=HEIGHT + 1, ts=TS + 600,
        balances=_balances(result),
        sequences=result.next_snapshot.metadata["sequence_numbers"])
    assert _balances(result2)[BOB] == 100
    assert post2.retractable_transfers.open_count() == 0


def test_park_over_the_cap_is_refused_with_the_measured_cap(_evaluators):
    body = recipient_policy.max_hold_clause_body(BOB, seconds=600)
    _install(_evaluators, BOB, body, max_hold_seconds=600)
    lm = _with_clause(_lm(), BOB, body)
    tx = _park_tx(at_time=TS + 3600)
    result, post = _apply([tx], lm=lm)
    assert tx["tx_id"] in result.invalid_tx_ids
    outcome = _outcome(result, tx)
    assert outcome.reason == tau_defs.REASON_RECIPIENT_MAX_HOLD
    assert post.retractable_transfers.open_count() == 0
    assert _balances(result)[ALICE] == 100000


def test_height_park_fails_closed_against_a_seconds_only_cap(_evaluators):
    """Unit trick: a seconds cap must not read a height park as 0 seconds."""
    body = recipient_policy.max_hold_clause_body(BOB, seconds=600)
    _install(_evaluators, BOB, body, max_hold_seconds=600)
    lm = _with_clause(_lm(), BOB, body)
    tx = _park_tx(at_height=HEIGHT + 5)
    result, post = _apply([tx], lm=lm)
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, tx).reason == tau_defs.REASON_RECIPIENT_MAX_HOLD
    assert post.retractable_transfers.open_count() == 0


def test_instant_only_recipient_refuses_parks_but_accepts_transfers(_evaluators):
    body = recipient_policy.instant_only_clause_body(BOB)
    _install(_evaluators, BOB, body, max_hold_seconds=0, max_hold_blocks=0)
    lm = _with_clause(_lm(), BOB, body)
    park = _park_tx(at_time=TS + 60)
    result, post = _apply([park], lm=lm)
    assert park["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, park).reason == tau_defs.REASON_RECIPIENT_MAX_HOLD

    plain = _transfer_tx(ALICE, SK_ALICE, [[ALICE, BOB, "100"]])
    result2, _ = _apply([plain], lm=lm)
    assert plain["tx_id"] in result2.accepted_tx_ids
    assert _balances(result2)[BOB] == 100


def test_retract_is_never_recipient_gated(_evaluators):
    park = _park_tx(at_time=TS + 600)
    result, post = _apply([park])
    assert post.retractable_transfers.open_count() == 1
    # The recipient installs an instant-only clause AFTER the park landed.
    body = recipient_policy.instant_only_clause_body(BOB)
    _install(_evaluators, BOB, body, max_hold_seconds=0, max_hold_blocks=0)
    post.rule_offers.accepted_clauses[(BOB, 5)] = body
    retract = _retract_tx(_rid(park))
    result2, post2 = _apply(
        [retract], lm=post, balances=_balances(result),
        sequences=result.next_snapshot.metadata["sequence_numbers"])
    assert retract["tx_id"] in result2.accepted_tx_ids
    assert post2.retractable_transfers.open_count() == 0
    assert _balances(result2)[ALICE] == 100000


def test_release_is_not_rechecked_against_a_later_cap(_evaluators):
    """Documented #76 boundary: authorisation happens at park time."""
    park = _park_tx(at_time=TS + 600)
    result, post = _apply([park])
    assert post.retractable_transfers.open_count() == 1
    body = recipient_policy.instant_only_clause_body(BOB)
    _install(_evaluators, BOB, body, max_hold_seconds=0, max_hold_blocks=0)
    post.rule_offers.accepted_clauses[(BOB, 5)] = body
    result2, post2 = _apply(
        [], lm=post, height=HEIGHT + 1, ts=TS + 600,
        balances=_balances(result),
        sequences=result.next_snapshot.metadata["sequence_numbers"])
    assert _balances(result2)[BOB] == 100, "a due release pays in full"
    assert post2.retractable_transfers.open_count() == 0


# --- unit tests: the verdict module -------------------------------------------

def _clause_for(mapping):
    return lambda pubkey, stream: mapping.get((pubkey, stream))


def _values(sender=ALICE, recipient=BOB, amount="100"):
    return {
        1: amount,
        2: "100000",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        12: "{ #x" + sender + " }:bv[384]",
        5: str(TS),
    }


def test_verdict_measures_the_cap_by_reevaluation(_evaluators):
    body = recipient_policy.max_hold_clause_body(BOB, seconds=600)
    _install(_evaluators, BOB, body, max_hold_seconds=600)
    verdict = recipient_policy.recipient_verdict(
        _clause_for({(BOB, 5): body}), BOB, _values(),
        pool="apply", timeout=None, hold_seconds=3600, sender=ALICE,
    )
    assert verdict.blocked
    assert verdict.reason == tau_defs.REASON_RECIPIENT_MAX_HOLD
    assert verdict.cap == 600 and verdict.cap_unit == "seconds"
    assert verdict.max_hold == {"max_hold_seconds": 600}
    # More than the initial + zeroed probes: a binary search ran.
    assert len(_evaluators.verdict_calls) > 3


def test_verdict_reports_a_plain_block_when_zeroing_the_hold_still_blocks(_evaluators):
    body = recipient_policy.recipient_clause_body(
        BOB, allowed_senders=[CAROL], max_hold_seconds=600)
    _evaluators.set_verdict(body, decide_for(
        BOB, allowed_senders=[CAROL], max_hold_seconds=600))
    verdict = recipient_policy.recipient_verdict(
        _clause_for({(BOB, 5): body}), BOB, _values(),
        pool="apply", timeout=None, hold_seconds=3600, sender=ALICE,
    )
    assert verdict.blocked
    assert verdict.reason == tau_defs.REASON_RECIPIENT_POLICY_BLOCK
    assert verdict.cap is None


def test_verdict_allows_when_there_is_no_clause(_evaluators):
    verdict = recipient_policy.recipient_verdict(
        _clause_for({}), BOB, _values(), pool="apply", timeout=None,
        sender=ALICE,
    )
    assert not verdict.blocked


def test_with_hold_overrides_sender_supplied_streams():
    values = {17: "999999", 27: "5", 1: "100"}
    out = recipient_policy.with_hold(values, 10, 0)
    assert out[17] == "10" and out[27] == "0" and out[1] == "100"
    assert values[17] == "999999", "the caller's map is not mutated"


def test_park_hold_units_and_saturation():
    time_park = RetractableEntry(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=1,
        sequence_number=0, kind=KIND_TIME, release_at=TS + 600)
    assert recipient_policy.park_hold(time_park, HEIGHT, TS) == (600, 0)
    height_park = RetractableEntry(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=1,
        sequence_number=0, kind=KIND_HEIGHT, release_at=HEIGHT + 7)
    assert recipient_policy.park_hold(height_park, HEIGHT, TS) == (0, 7)
    past = RetractableEntry(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=1,
        sequence_number=0, kind=KIND_TIME, release_at=TS - 5)
    assert recipient_policy.park_hold(past, HEIGHT, TS) == (0, 0)


# --- deploy screens and templates ----------------------------------------------

def test_templates_pass_the_clause_screens():
    from consensus.admission import _screen_clause_domains
    from consensus.rule_offers import clause_body_v1
    bodies = [
        recipient_policy.allowlist_clause_body(BOB, [ALICE, CAROL]),
        recipient_policy.instant_only_clause_body(BOB),
        recipient_policy.max_hold_clause_body(BOB, seconds=600),
        recipient_policy.max_hold_clause_body(BOB, blocks=100),
        recipient_policy.recipient_clause_body(
            BOB, allowed_senders=[ALICE], max_hold_seconds=60),
    ]
    for body in bodies:
        assert clause_body_v1("always ( %s )." % body) == body
        assert _screen_clause_domains(body) is None


def test_deploy_screen_refuses_hold_rules_when_the_feature_is_off(monkeypatch):
    from consensus.admission import _screen_clause_domains
    body = recipient_policy.max_hold_clause_body(BOB, seconds=600)
    monkeypatch.setattr(tau_defs, "RECIPIENT_POLICY_ACTIVE", False)
    error = _screen_clause_domains(body)
    assert error is not None and "not supported by this node" in error


def test_deploy_screen_refuses_untyped_hold_streams():
    from consensus.admission import _screen_clause_domains
    body = "(i17[t] > { #x10 }:bv[64] ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]))"
    error = _screen_clause_domains(body)
    assert error is not None and "bv[64]" in error


# --- the CLI surface ------------------------------------------------------------

def test_cli_receive_set_print_only_prints_the_template(capsys):
    from tau_testnet_cli import cli
    args = cli.build_parser().parse_args([
        "policy", "receive", "set",
        "--privkey", str(SK_ALICE),
        "--sender", CAROL,
        "--max-hold-seconds", "600",
        "--print-only",
    ])
    assert args.func(args) == 0
    printed = capsys.readouterr().out.strip()
    assert printed == recipient_policy.recipient_clause_body(
        ALICE, allowed_senders=[CAROL], max_hold_seconds=600)


def test_cli_receive_instant_prints_the_instant_only_template(capsys):
    from tau_testnet_cli import cli
    args = cli.build_parser().parse_args([
        "policy", "receive", "set",
        "--privkey", str(SK_ALICE), "--instant", "--print-only",
    ])
    assert args.func(args) == 0
    assert capsys.readouterr().out.strip() == \
        recipient_policy.instant_only_clause_body(ALICE)


def test_cli_receive_set_refuses_contradictory_and_empty_options():
    from tau_testnet_cli import cli
    for argv in (
        ["--instant", "--max-hold-seconds", "5"],   # instant already caps at 0
        [],                                          # nothing to install
        ["--sender", "not-a-pubkey"],                # malformed pubkey
    ):
        args = cli.build_parser().parse_args(
            ["policy", "receive", "set", "--privkey", str(SK_ALICE),
             "--print-only"] + argv)
        assert args.func(args) == cli.EXIT_LOCAL, argv


def test_sendtx_recipient_helper_blocks_and_reports_the_cap():
    from commands.sendtx import _recipient_clause_verdict

    class _Tip:
        def clause_for(self, pubkey, stream):
            return BODY if pubkey == BOB else None

    BODY = recipient_policy.max_hold_clause_body(BOB, seconds=600)
    ev = MockPolicyEvaluator(pool="admission")
    ev.set_verdict(BODY, decide_for(BOB, max_hold_seconds=600))
    sender_policy.set_evaluator("admission", ev)
    try:
        verdict = _recipient_clause_verdict(
            _Tip(), ALICE, BOB, _values(), None, hold_seconds=3600)
    finally:
        sender_policy.set_evaluator("admission", None)
    assert verdict.blocked
    assert verdict.reason == tau_defs.REASON_RECIPIENT_MAX_HOLD
    assert verdict.max_hold == {"max_hold_seconds": 600}
