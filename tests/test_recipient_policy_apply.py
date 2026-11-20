"""Recipient-side policy (issues #47 inbound allow-list, #76 maximum hold time).

Block-apply semantics, with the per-account o5 clauses served by the mock policy
evaluator. The mock decides from the same inputs the real worker gets: i3 is the
sender's key, i17 says which side the evaluation is for (0 = the account's own
outgoing transfer, 1 + hold seconds = an incoming payment).

What these tests pin down:

- The recipient's clause is consulted only when recipient policy is active AND
  the clause reads i17, so an outbound-only clause never judges incoming money.
- A refusal fails the whole transaction, as a sender-side o5 block does: a batch
  is all or nothing and nothing moves.
- Parks are judged with their hold; retracts are never gated and releases are
  not re-checked. A park released by height reports the longest window.
- Routed shares (#35), faucet grants and refunds are not transfers to the
  destination and are not gated.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

import tau_defs
from block import Block
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import MAX_RELEASE_WINDOW_SECONDS, parse_retractable_transfer
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_700_000_000
FAR = 9_999_999_999


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)      # pays
SK_BOB, BOB = _key(44444)          # pays too
SK_RITA, RITA = _key(55555)        # the recipient with a policy
SK_SAM, SAM = _key(77777)          # a second recipient
SK_DEST, DEST = _key(66666)        # a receive-route destination
PROPOSER = "d4" * 48
SK = {ALICE: SK_ALICE, BOB: SK_BOB, RITA: SK_RITA, SAM: SK_SAM, DEST: SK_DEST}

_TX_SEQ = itertools.count()

# Clause bodies: the text only has to read i17 (or not) and be distinct; the
# mock decides the verdict from the inputs, as the real engine would from the rule.
ONLY_FROM_ALICE = "o5[t]:bv[24] = i17[t]:bv[64] /* inbound: only from ALICE */"
INSTANT_ONLY = "o5[t]:bv[24] = i17[t]:bv[64] /* inbound: hold must be 0 */"
CAP_600 = "o5[t]:bv[24] = i17[t]:bv[64] /* inbound: hold at most 600 s */"
OUTBOUND_WHITELIST = "o5[t]:bv[24] = i4[t]:bv[384] /* outbound: only to SAM */"
BOTH = "o5[t]:bv[24] = i17[t]:bv[64] /* outbound to SAM only, inbound from ALICE only */"


def _key_of(value: str) -> str:
    return str(value).lower().removeprefix("#x")


def _verdicts():
    """The mock's stand-in for each clause, deciding from the worker inputs."""
    def only_from_alice(inputs):
        inbound = int(inputs["i17"]) > 0
        return "0" if inbound and _key_of(inputs["i3"]) != ALICE else "1"

    def instant_only(inputs):
        return "0" if int(inputs["i17"]) > 1 else "1"

    def cap_600(inputs):
        return "0" if int(inputs["i17"]) > 601 else "1"

    def outbound_whitelist(inputs):
        # An outbound-only rule: it never looks at i17, so if it were consulted
        # for an incoming payment it would see i4 = its owner and block.
        return "1" if _key_of(inputs["i4"]) == SAM else "0"

    def both(inputs):
        if int(inputs["i17"]) > 0:
            return only_from_alice(inputs)
        return outbound_whitelist(inputs)

    return {
        ONLY_FROM_ALICE: only_from_alice,
        INSTANT_ONLY: instant_only,
        CAP_600: cap_600,
        OUTBOUND_WHITELIST: outbound_whitelist,
        BOTH: both,
    }


@pytest.fixture(autouse=True)
def evaluator():
    mock = MockPolicyEvaluator(pool="apply")
    for body, decide in _verdicts().items():
        mock.set_verdict(body, decide)
    admission = MockPolicyEvaluator(pool="admission")
    for body, decide in _verdicts().items():
        admission.set_verdict(body, decide)
    sender_policy.set_evaluator("apply", mock)
    sender_policy.set_evaluator("admission", admission)
    yield mock
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def _base(sender, seq, tx_type, fee_limit="100", expiration_time=FAR):
    return {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": expiration_time,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
    }


def spend_tx(sender, legs, seq, *, extra_ops=None):
    if isinstance(legs, tuple):
        legs = [legs]
    tx = _base(sender, seq, "user_tx")
    tx["operations"] = {"1": [[sender, to, amount] for to, amount in legs]}
    tx["operations"].update(extra_ops or {})
    return _sign(tx, SK[sender])


def park_tx(sender, to, amount, seq, *, hold=None, at_height=None):
    """A retractable transfer released `hold` seconds after TS, or at a height."""
    if hold is not None:
        tx = _base(sender, seq, "retractable_transfer", expiration_time=TS + max(1, hold // 2))
        tx["release_at_time"] = TS + hold
    else:
        tx = _base(sender, seq, "retractable_transfer")
        tx["release_at_height"] = at_height
        tx["expire_at_height"] = at_height
    tx.update(recipient_pubkey=to, amount=amount)
    return _sign(tx, SK[sender])


def retract_tx(park, seq):
    tx = _base(park["sender_pubkey"], seq, "retract_transfer", fee_limit="0")
    tx["retractable_id"] = parse_retractable_transfer(park).retractable_id.hex()
    return _sign(tx, SK[park["sender_pubkey"]])


def route_tx(owner, dest, bps, seq):
    tx = _base(owner, seq, "receive_route_set")
    tx["destination_pubkey"] = dest
    tx["route_bps"] = bps
    return _sign(tx, SK[owner])


class Chain:
    def __init__(self, balances=None, *, active=True, routes=False):
        self.bal = dict(balances or {ALICE: 10_000, BOB: 10_000, RITA: 1_000,
                                     SAM: 0, DEST: 0, PROPOSER: 0})
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        if active:
            self.lm.activate_recipient_policy()
        if routes:
            self.lm.activate_receive_routes()
        self.last = None

    def clause(self, owner, body):
        clauses = dict(self.lm.rule_offers.accepted_clauses.items())
        if body is None:
            clauses.pop((owner, tau_defs.USER_POLICY_STREAM_INDEX), None)
        else:
            clauses[(owner, tau_defs.USER_POLICY_STREAM_INDEX)] = body
        self.lm.rule_offers.accepted_clauses = clauses

    def block(self, txs, ts=TS, height=None):
        height = HEIGHT if height is None else height
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

        def _multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            return {1: str(vals.get(1, "0")), 8: "0", 9: "0", 5: "1"}

        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = TauConsensusEngine().apply_block(view, blk, parent)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.last = result
        return result


def _status(result, tx):
    for outcome in result.outcomes:
        if outcome.tx_id == tx["tx_id"]:
            return outcome.status, outcome.reason
    raise AssertionError("tx not in block")


def _logs(result, tx):
    for outcome in result.outcomes:
        if outcome.tx_id == tx["tx_id"]:
            return " | ".join(str(x) for x in (outcome.receipt_logs or []))
    return ""


def _applied(result, tx):
    return _status(result, tx)[0] == "applied"


# --- #47 acceptance cases --------------------------------------------------------

def test_47_ac1_only_the_allowed_sender_can_pay_and_the_allowed_senders_own_policy_is_untouched(evaluator):
    ch = Chain()
    ch.clause(RITA, ONLY_FROM_ALICE)
    ok, refused = spend_tx(ALICE, (RITA, 100), 0), spend_tx(BOB, (RITA, 100), 0)
    result = ch.block([ok, refused])

    assert _applied(result, ok)
    assert _status(result, refused) == ("invalid", "recipient_policy_block")
    assert "recipient's policy" in _logs(result, refused)
    assert ch.bal[RITA] == 1_100 and ch.bal[BOB] == 10_000
    # ALICE has no clause: her own outgoing transfers are unaffected.
    result = ch.block([spend_tx(ALICE, (SAM, 5), 1)])
    assert ch.bal[SAM] == 5


def test_47_ac2_no_policy_means_everyone_can_pay():
    ch = Chain()
    a, b = spend_tx(ALICE, (RITA, 10), 0), spend_tx(BOB, (RITA, 20), 0)
    result = ch.block([a, b])
    assert _applied(result, a) and _applied(result, b)
    assert ch.bal[RITA] == 1_030


def test_47_ac3_a_batch_with_one_refused_output_fails_as_a_whole():
    ch = Chain()
    ch.clause(SAM, ONLY_FROM_ALICE)               # SAM refuses BOB; RITA takes anyone
    batch = spend_tx(BOB, [(RITA, 100), (SAM, 50)], 0)
    result = ch.block([batch])

    assert _status(result, batch) == ("invalid", "recipient_policy_block")
    assert ch.bal[BOB] == 10_000 and ch.bal[RITA] == 1_000 and ch.bal[SAM] == 0
    assert ch.seq.get(BOB, 0) == 0


def test_47_ac4_one_clause_holds_the_outbound_whitelist_and_the_inbound_rule():
    ch = Chain()
    ch.clause(RITA, BOTH)
    to_sam = spend_tx(RITA, (SAM, 10), 0)
    to_alice = spend_tx(RITA, (ALICE, 10), 0)
    result = ch.block([to_sam, to_alice])
    assert _applied(result, to_sam)
    assert _status(result, to_alice)[0] == "invalid"     # outbound whitelist

    from_alice, from_bob = spend_tx(ALICE, (RITA, 7), 0), spend_tx(BOB, (RITA, 7), 0)
    result = ch.block([from_alice, from_bob])
    assert _applied(result, from_alice)
    assert _status(result, from_bob) == ("invalid", "recipient_policy_block")


def test_47_an_outbound_only_clause_never_judges_incoming_payments(evaluator):
    """The clause does not read i17, so it is not consulted for RITA's receipts,
    although evaluated on them it would block (i4 = RITA is not SAM)."""
    ch = Chain()
    ch.clause(RITA, OUTBOUND_WHITELIST)
    pay = spend_tx(BOB, (RITA, 40), 0)
    result = ch.block([pay])
    assert _applied(result, pay)
    assert ch.bal[RITA] == 1_040
    assert not any(body == OUTBOUND_WHITELIST for body, _ in evaluator.verdict_calls)


def test_47_nothing_is_consulted_before_activation(evaluator):
    ch = Chain(active=False)
    ch.clause(RITA, ONLY_FROM_ALICE)
    pay = spend_tx(BOB, (RITA, 40), 0)
    assert _applied(ch.block([pay]), pay)
    assert evaluator.verdict_calls == []


def test_47_the_sides_are_told_apart_by_i17(evaluator):
    ch = Chain()
    ch.clause(RITA, BOTH)
    ch.block([spend_tx(RITA, (SAM, 1), 0), spend_tx(ALICE, (RITA, 1), 0)])
    seen = [inputs["i17"] for body, inputs in evaluator.verdict_calls if body == BOTH]
    assert seen == ["0", "1"]


def test_47_a_routed_share_is_not_gated_by_the_destinations_policy():
    """DEST only accepts ALICE, but a share routed to it from RITA's receipts is
    RITA's money moving by RITA's own rule, not a transfer to DEST."""
    ch = Chain(routes=True)
    ch.block([route_tx(RITA, DEST, 2000, 0)])
    ch.clause(DEST, ONLY_FROM_ALICE)
    pay = spend_tx(BOB, (RITA, 100), 0)
    result = ch.block([pay])
    assert _applied(result, pay)
    assert ch.bal[DEST] == 20


# --- #76 acceptance cases --------------------------------------------------------

def test_76_ac1_a_zero_cap_takes_plain_transfers_and_refuses_every_park():
    ch = Chain()
    ch.clause(RITA, INSTANT_ONLY)
    plain = spend_tx(ALICE, (RITA, 10), 0)
    short = park_tx(BOB, RITA, 10, 0, hold=60)
    result = ch.block([plain, short])
    assert _applied(result, plain)
    assert _status(result, short) == ("invalid", "recipient_policy_block")
    assert ch.bal[BOB] == 10_000          # nothing escrowed, nothing charged
    # BOB has no clause: his own sending is unaffected elsewhere.
    elsewhere = park_tx(BOB, SAM, 10, 0, hold=60)
    assert _applied(ch.block([elsewhere]), elsewhere)


def test_76_ac2_a_600_second_cap_takes_ten_minutes_and_refuses_an_hour():
    ch = Chain()
    ch.clause(RITA, CAP_600)
    ten_min = park_tx(ALICE, RITA, 10, 0, hold=600)
    an_hour = park_tx(BOB, RITA, 10, 0, hold=3600)
    result = ch.block([ten_min, an_hour])
    assert _applied(result, ten_min)
    assert _status(result, an_hour) == ("invalid", "recipient_policy_block")


def test_76_ac3_no_policy_takes_parks_of_any_length():
    ch = Chain()
    long_one = park_tx(ALICE, RITA, 10, 0, hold=7 * 86_400)
    by_height = park_tx(BOB, RITA, 10, 0, at_height=HEIGHT + 50)
    result = ch.block([long_one, by_height])
    assert _applied(result, long_one) and _applied(result, by_height)


def test_76_ac4_a_retract_is_never_gated_by_the_cap():
    ch = Chain()
    park = park_tx(ALICE, RITA, 10, 0, hold=3600)
    assert _applied(ch.block([park]), park)
    ch.clause(RITA, INSTANT_ONLY)                 # cap set after the park
    retract = retract_tx(park, 1)
    result = ch.block([retract])
    assert _applied(result, retract)
    assert ch.bal[ALICE] == 10_000


def test_76_a_release_is_not_re_checked():
    ch = Chain()
    park = park_tx(ALICE, RITA, 10, 0, hold=600)
    assert _applied(ch.block([park]), park)
    ch.clause(RITA, INSTANT_ONLY)
    ch.block([], ts=TS + 601, height=HEIGHT + 1)  # the release sweep
    assert ch.bal[RITA] == 1_010


def test_76_a_park_released_by_height_reports_the_longest_window(evaluator):
    ch = Chain()
    ch.clause(RITA, CAP_600)
    by_height = park_tx(ALICE, RITA, 10, 0, at_height=HEIGHT + 1)
    result = ch.block([by_height])
    assert _status(result, by_height) == ("invalid", "recipient_policy_block")
    seen = [inputs["i17"] for body, inputs in evaluator.verdict_calls if body == CAP_600]
    assert seen == [str(1 + MAX_RELEASE_WINDOW_SECONDS)]


def test_76_the_hold_the_clause_sees_is_the_window_from_the_block_time(evaluator):
    ch = Chain()
    ch.clause(RITA, CAP_600)
    ch.block([park_tx(ALICE, RITA, 10, 0, hold=599)])
    seen = [inputs["i17"] for body, inputs in evaluator.verdict_calls if body == CAP_600]
    assert seen == ["600"]


# --- refusal reasons at admission (#47 distinct reason, #76 AC5 cap in message) ---

class _Tip:
    def __init__(self, clauses, active=True):
        self._clauses = clauses
        self.recipient_policy_active = active

    def clause_for(self, owner, stream):
        return self._clauses.get((owner, stream))


def _values(sender, recipient, amount=10):
    return {1: str(amount), 3: "{ #x" + sender + " }:bv[384]",
            4: "{ #x" + recipient + " }:bv[384]", 5: str(TS)}


def test_admission_names_the_recipients_policy_as_the_refusing_side():
    from commands.sendtx import _recipient_refusal

    tip = _Tip({(RITA, 5): ONLY_FROM_ALICE})
    refusal = _recipient_refusal(tip, RITA, _values(BOB, RITA), 0, None, 1, "BOB->RITA")
    assert refusal["code"] == "RECIPIENT_POLICY_BLOCK"
    assert "recipient's policy" in refusal["message"]
    assert refusal["details"]["recipient"] == RITA
    assert _recipient_refusal(tip, RITA, _values(ALICE, RITA), 0, None, 1, "x") is None


@pytest.mark.parametrize("body,hold,cap", [(CAP_600, 3600, 600), (INSTANT_ONLY, 60, 0)])
def test_76_ac5_a_hold_refusal_carries_the_recipients_cap(body, hold, cap):
    from commands.sendtx import _recipient_refusal

    tip = _Tip({(RITA, 5): body})
    refusal = _recipient_refusal(tip, RITA, _values(ALICE, RITA), hold, None, 1, "x")
    assert refusal["code"] == "RECIPIENT_MAX_HOLD"
    assert refusal["details"]["max_hold_seconds"] == cap
    assert refusal["details"]["hold_seconds"] == hold
    assert f"at most {cap} seconds" in refusal["message"]


def test_a_park_refused_for_the_sender_not_the_hold_is_a_policy_block():
    from commands.sendtx import _recipient_refusal

    tip = _Tip({(RITA, 5): ONLY_FROM_ALICE})
    refusal = _recipient_refusal(tip, RITA, _values(BOB, RITA), 600, None, 1, "x")
    assert refusal["code"] == "RECIPIENT_POLICY_BLOCK"


def test_admission_hold_is_the_parks_window_or_the_longest_one():
    from commands.sendtx import _admission_hold_seconds
    from consensus.retractable import KIND_HEIGHT, KIND_TIME

    assert _admission_hold_seconds("user_tx", {}, TS) == 0
    assert _admission_hold_seconds(
        "retractable_transfer", {"release_kind": KIND_TIME, "release_at": TS + 90}, TS) == 90
    assert _admission_hold_seconds(
        "retractable_transfer", {"release_kind": KIND_HEIGHT, "release_at": 99}, TS
    ) == MAX_RELEASE_WINDOW_SECONDS


# --- activation, reservation and screens (#47 AC5, #76 AC6) ------------------------

def test_activation_is_one_way_and_refused_while_the_spec_already_reads_i17():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.apply_host_contract_patch(
        {"recipient_policy_active": True},
        effective_spec_texts=[("application_rules", "always (o13[t] = i17[t]).")],
    )
    assert lm.recipient_policy_active is False
    lm.apply_host_contract_patch(
        {"recipient_policy_active": True},
        effective_spec_texts=[("application_rules", "always (o13[t] = i13[t]).")],
    )
    assert lm.recipient_policy_active is True
    with pytest.raises(ValueError):
        lm.apply_host_contract_patch({"recipient_policy_active": False})


def test_the_flag_enters_the_meta_hash_only_once_set():
    off = build_mechanism_metadata("majority", recipient_policy_active=False)
    on = build_mechanism_metadata("majority", recipient_policy_active=True)
    assert "recipient_policy_active" not in off
    assert on["recipient_policy_active"] is True


def test_i17_is_write_reserved_only_once_active():
    assert 17 not in tau_defs.reserved_operation_keys()
    assert 17 in tau_defs.reserved_operation_keys(recipient_policy_active=True)
    assert "i17" not in tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE, recipient_policy_active=True)
    assert "i17" in tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_USER, recipient_policy_active=True)


def test_a_sender_cannot_write_i17_once_active():
    ch = Chain()
    forged = spend_tx(BOB, (RITA, 10), 0, extra_ops={"17": "0"})
    result = ch.block([forged])
    assert _status(result, forged)[0] == "invalid"
    assert ch.bal[RITA] == 1_000


@pytest.mark.parametrize("body,ok", [
    ("o5[t]:bv[24] = i17[t]:bv[64]", True),
    ("o5[t]:bv[24] = i17[t]:bv[8]", False),
    ("o5[t]:bv[24] = i17[t]", False),
])
def test_i17_must_be_typed_bv64_once_active(body, ok):
    from consensus.admission import _screen_clause_domains
    from consensus.approvals import screen_recipient_policy_width

    assert (screen_recipient_policy_width(body) is None) is ok
    # Inactive: i17 is still an ordinary custom stream, screened as before.
    as_custom = _screen_clause_domains(body.replace("i17", "i26"))
    assert _screen_clause_domains(body) == (
        as_custom.replace("i26", "i17") if as_custom else None)
    from consensus.admission import screen_o5_clause

    assert (screen_o5_clause(body, True) is None) is (ok and _screen_clause_domains(body) is None)
    assert screen_o5_clause(body, False) == _screen_clause_domains(body)


def test_checktx_refuses_an_inbound_rule_while_the_feature_is_off():
    import json

    from commands import checktx

    tx = {"tx_type": "rule_change_request", "kind": 1,
          "rule_text": "always ( o5[t]:bv[24] = i17[t]:bv[64] )."}
    with patch.object(checktx, "_recipient_policy_active", return_value=False):
        out = json.loads(checktx.execute("checktx " + json.dumps(tx), None))
    assert out["status"] == "error"
    assert out["error"]["code"] == "RECIPIENT_POLICY_INACTIVE"
    with patch.object(checktx, "_recipient_policy_active", return_value=True):
        assert checktx._inbound_rule_refusal(json.dumps(tx)) is None
    plain = dict(tx, rule_text="always ( o5[t]:bv[24] = i4[t]:bv[384] ).")
    with patch.object(checktx, "_recipient_policy_active", return_value=False):
        assert checktx._inbound_rule_refusal(json.dumps(plain)) is None


def test_an_inbound_clause_deployed_early_does_not_block_activation():
    """A correctly typed o5 clause reading i17 is the feature's own use; a guard,
    a raw rule or a clause typing i17 at another width still blocks."""
    from consensus.approvals import audit_recipient_policy_collisions

    good = ("clause_aaaaaaaaaa_o5", "o5[t]:bv[24] = i17[t]:bv[64]")
    assert audit_recipient_policy_collisions([good]) == []
    for bad in [
        ("clause_aaaaaaaaaa_o5", "o5[t]:bv[24] = i17[t]:bv[8]"),
        ("clause_aaaaaaaaaa_o4294967295", "o5[t]:bv[24] = i17[t]:bv[64]"),
        ("application_rules", "always (o13[t] = i17[t]:bv[64])."),
    ]:
        assert audit_recipient_policy_collisions([bad]), bad
